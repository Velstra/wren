//! # The central router loop
//!
//! Wren's equivalent of FRR's *zebra*: a single owner of the [`Rib`] and the
//! forwarding plane. Protocol engines never touch the RIB directly — they run in
//! their own tasks and send [`RouteUpdate`]s down a channel, and this loop is the
//! only place that calls [`Rib::update`]/[`Rib::withdraw`] and drains the
//! resulting [`FibChange`]s into the [`Fib`]. That keeps best-path selection and
//! FIB programming single-threaded and serialized, however many protocols feed it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use wren_core::{FibChange, Prefix, Protocol, Rib, Route};
use wren_filter::{Decision, Filter};

use crate::fib::FibHandle;

/// How often the router re-tries prefixes whose last FIB write failed. A transient
/// kernel error (ENOBUFS/EINTR — see the netlink backend's own bounded retry) can
/// still exhaust its retries and leave a best-path route out of the kernel FIB; on
/// each tick the router re-derives the desired state for those prefixes from the RIB
/// and re-applies it, so a dropped route self-heals within one interval instead of
/// lingering until its next independent change (review finding M8).
const FIB_RECONCILE_INTERVAL: Duration = Duration::from_secs(15);

/// Upper bound on how many queued protocol updates the router folds into the RIB
/// before it programs the forwarding plane. During a flap storm many updates for the
/// same prefixes pile up in the channel; draining them into the RIB first and then
/// writing only the *net* best-path change per prefix once collapses N blocking
/// netlink round-trips into one (review finding M7). The bound caps worst-case
/// latency: anything beyond it is programmed on the next loop iteration.
const MAX_COALESCE_BATCH: usize = 1024;

/// Per-protocol import filters: applied to each route a protocol announces before
/// it enters the RIB. A protocol with no entry imports everything unchanged.
pub type ImportFilters = HashMap<Protocol, Filter>;

/// Exact post-export routes successfully installed before the router starts.
pub type ExportedRoutes = BTreeMap<(u32, Prefix), Route>;

/// Completion refers only to routing policy/static FIB reconciliation, not to
/// protocol adjacency establishment. A pending generation is never cancelled by
/// a control client's timeout or disconnection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadStatus {
    pub generation: u64,
    pub state: &'static str,
    pub pending_prefixes: usize,
    pub detail: Option<String>,
    /// Internal admission barrier; not part of the public receipt grammar.
    pub in_flight: bool,
}

impl ReloadStatus {
    pub fn startup() -> Self {
        Self {
            generation: 0,
            state: "converged",
            pending_prefixes: 0,
            detail: None,
            in_flight: false,
        }
    }

    pub fn render(&self) -> String {
        let mut text = format!(
            "scope routing\ngeneration {}\nstate {}\npending-prefixes {}\n",
            self.generation, self.state, self.pending_prefixes
        );
        if let Some(detail) = &self.detail {
            // Details are fixed diagnostics, never configuration contents.
            let _ = writeln!(text, "detail {}", detail.replace(['\n', '\r'], " "));
        }
        text
    }
}

/// One admitted generation: policy and statics must never arrive independently.
#[derive(Debug)]
pub struct RouterReload {
    pub generation: u64,
    pub statics: Vec<Route>,
    pub imports: ImportFilters,
    pub fib_export: Option<Filter>,
    pub vrf_exports: HashMap<u32, Filter>,
}

/// Seed admitted statics into the RIB, then program only its final best paths.
/// Export decisions never remove candidates from the RIB. The returned cache is
/// evidence of successful writes, not a reconstruction from configured routes.
/// Startup callers must propagate errors before exposing a healthy daemon.
pub async fn seed_startup_routes(
    rib: &mut Rib,
    fib: &FibHandle,
    statics: &[Route],
    vrf_exports: &HashMap<u32, Filter>,
    fib_export: Option<&Filter>,
) -> anyhow::Result<ExportedRoutes> {
    for route in statics {
        rib.update(route.clone());
    }
    let mut exported = ExportedRoutes::new();
    for best in rib.iter_best() {
        let Some(route) = export_route(best, vrf_exports.get(&best.table)) else {
            continue;
        };
        let Some(route) = export_route(&route, fib_export) else {
            continue;
        };
        fib.apply(FibChange::Install(route.clone()))
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        exported.insert((route.table, route.prefix), route);
    }
    let observed = fib
        .owned_routes()
        .await
        .map_err(|error| anyhow::anyhow!(error))?;
    anyhow::ensure!(
        observed.len() == exported.len()
            && exported
                .values()
                .all(|want| observed.iter().any(|have| same_forwarding(want, have))),
        "startup forwarding-plane readback does not match exported routes"
    );
    Ok(exported)
}

/// Connected routes belong to the kernel. Each export boundary transforms an
/// accepted route exactly once; rejection is not an empty successful install.
fn export_route(route: &Route, filter: Option<&Filter>) -> Option<Route> {
    if route.protocol == Protocol::Connected {
        return None;
    }
    match filter.map(|filter| filter.apply(route)) {
        Some(Decision::Reject) => None,
        Some(Decision::Accept(route)) => Some(route),
        None => Some(route.clone()),
    }
}

/// A route the router pushes *out* to a protocol engine for redistribution: the
/// engine re-originates it in its own protocol (e.g. a connected or static route
/// announced into BGP). The mirror image of [`RouteUpdate`], which flows *in*.
#[derive(Debug, Clone)]
pub enum Redistribution {
    /// Redistribute this RIB best-path route (re-originate it).
    Announce(Route),
    /// Stop redistributing this prefix (withdraw any prior origination).
    Withdraw(Prefix),
}

/// A protocol engine that wants RIB best-path routes pushed to it for
/// redistribution. The router consults each target on every best-path change and,
/// for routes whose origin protocol is in `sources` (never the target's own
/// protocol — that would loop), runs them through `filter` and sends the result
/// down `tx`.
pub struct RedistTarget {
    /// The consuming protocol — excluded from its own `sources` to avoid a loop.
    pub protocol: Protocol,
    /// The origin protocols whose routes this target redistributes.
    pub sources: HashSet<Protocol>,
    /// An optional export filter applied to each redistributed route (reusing the
    /// same `wren-filter` engine as import/kernel-export).
    pub filter: Option<Filter>,
    /// The channel to the consuming protocol's task.
    pub tx: mpsc::Sender<Redistribution>,
}

/// A best-path change the router fans out to its redistribution targets, derived
/// from the [`FibChange`] the RIB produced (independently of the kernel export
/// filter — redistribution gates protocol origination, not the FIB).
enum RedistEvent {
    /// `prefix`'s best path appeared or changed to this route.
    Changed(Route),
    /// `prefix`'s best path disappeared.
    Gone(Prefix),
}

/// A route change announced by a protocol engine for the router to reconcile.
#[derive(Debug)]
pub enum RouteUpdate {
    /// A protocol's best route to a prefix appeared or changed — offer it to the
    /// RIB as a candidate (replacing any prior route with the same
    /// `(protocol, source)`).
    Announce(Route),
    /// A protocol withdrew its route to a prefix — remove that candidate.
    Withdraw {
        /// The VRF (kernel table) the route was in — [`wren_core::RT_TABLE_MAIN`] for
        /// a protocol in the default VRF.
        table: u32,
        /// The destination whose route is gone.
        prefix: Prefix,
        /// The protocol that owned it.
        protocol: Protocol,
        /// The source discriminator within that protocol.
        source: u64,
    },
}

/// A read-only question for the router about its current state, posed over the
/// control socket and answered from the RIB the router owns — so operational
/// `show` commands never need shared access to the RIB.
#[derive(Debug)]
pub enum Query {
    /// Show the best routes, optionally filtered to one protocol.
    Routes {
        /// Restrict to this protocol, or `None` for every route.
        protocol: Option<Protocol>,
    },
    /// Render the RIB's Prometheus metrics (`show metrics`): best-route counts by
    /// origin protocol.
    Metrics,
    /// List the configured VRFs and the number of best routes in each (`show vrf`).
    Vrfs,
}

/// A configured VRF, as the router needs it to answer `show vrf`: its name, kernel
/// routing table and (optional) Route Distinguisher identity.
#[derive(Debug, Clone)]
pub struct VrfInfo {
    /// The VRF's name.
    pub name: String,
    /// Its kernel routing table.
    pub table: u32,
    /// Its Route Distinguisher, rendered (RFC 4364), if configured.
    pub rd: Option<String>,
}

/// A [`Query`] paired with the channel to deliver its rendered answer on.
pub type QueryRequest = crate::query::QueryRequest<Query>;

/// A change to the routes Wren is forwarding, streamed to a route-export
/// subscriber over the control socket (`wren monitor routes`). The stream mirrors
/// the FIB: a subscriber sees exactly the best-path routes the router programs
/// into the forwarding plane — first a snapshot of every current route (one
/// [`Update`](RouteEvent::Update) each, terminated by
/// [`EndOfDump`](RouteEvent::EndOfDump)), then live
/// [`Update`](RouteEvent::Update)/[`Withdraw`](RouteEvent::Withdraw) events as the
/// RIB changes. This is the model an external forwarding plane (e.g. the Velstra
/// eBPF datapath) consumes to mirror Wren's routing decisions — Wren's equivalent
/// of FRR zebra's Forwarding Plane Manager (FPM).
#[derive(Debug, Clone)]
pub enum RouteEvent {
    /// A best-path route appeared or changed — forward to this destination.
    Update(Route),
    /// A route was withdrawn — stop forwarding this `(table, prefix)`.
    Withdraw {
        /// The VRF (kernel table) the route was in.
        table: u32,
        /// The destination whose route is gone.
        prefix: Prefix,
    },
    /// Marks the end of the initial snapshot: every route that existed when the
    /// subscription opened has now been sent; subsequent events are live.
    EndOfDump,
}

/// A request to subscribe to the route-export stream, carrying the channel the
/// router pushes [`RouteEvent`]s down. The router replays the current forwarding
/// table as [`Update`](RouteEvent::Update)s followed by an
/// [`EndOfDump`](RouteEvent::EndOfDump), then retains the sender to deliver live
/// changes until the subscriber disconnects.
#[derive(Debug)]
pub struct RouteSubscribe {
    /// Where to deliver the snapshot and subsequent live events. Bounded: a
    /// subscriber that stops reading must not let the router queue events for it
    /// without limit. The initial snapshot is delivered with backpressure (so it
    /// is never truncated); subsequent live events use `try_send`, and a
    /// subscriber whose buffer fills is dropped (it can reconnect and re-snapshot).
    pub events: mpsc::Sender<RouteEvent>,
}

/// Capacity of each route-export subscriber channel. Bounds the memory a single
/// slow/stuck `monitor routes` client can cause the router to hold.
pub(crate) const SUBSCRIBER_CAP: usize = 1024;

/// Run the router until the update channel closes (every sender dropped).
///
/// Borrows the `rib` and `fib` so the caller can keep them (e.g. to race this
/// against a shutdown signal in `tokio::select!`). Besides protocol `updates`, the
/// loop also answers read-only `queries` from the control socket out of the RIB it
/// owns — keeping best-path, FIB programming and `show` all single-threaded.
#[allow(clippy::too_many_arguments)] // the router wires together every cross-cutting input
pub async fn run(
    rib: &mut Rib,
    fib: &FibHandle,
    mut updates: mpsc::Receiver<RouteUpdate>,
    imports: &ImportFilters,
    fib_export: Option<&Filter>,
    redist: &[RedistTarget],
    vrfs: &[VrfInfo],
    mut queries: mpsc::Receiver<QueryRequest>,
    mut subscribes: mpsc::Receiver<RouteSubscribe>,
    statics: &[Route],
    mut exported: ExportedRoutes,
    mut reloads: mpsc::Receiver<RouterReload>,
    status: watch::Sender<ReloadStatus>,
    vrf_exports: &HashMap<u32, Filter>,
) {
    // Policy and admitted statics change together in the reload arm.
    let mut imports = imports.clone();
    let mut fib_export = fib_export.cloned();
    let mut vrf_exports = vrf_exports.clone();
    let mut generation = 0;
    let mut managed: BTreeSet<(u32, Prefix)> = exported.keys().copied().collect();
    // The static routes the running configuration defines, keyed by (vrf, prefix) —
    // the pre-export baseline a SIGHUP reload diffs against. Keep it separate from
    // the exact successful startup writes passed in `exported`: an export-denied
    // static is still configured, but must never enter snapshots or FIB repair.
    let mut current_statics: BTreeMap<(u32, Prefix), Route> = BTreeMap::new();
    for route in statics {
        let key = (route.table, route.prefix);
        current_statics.insert(key, route.clone());
    }
    // Prefixes whose last FIB write (install or remove) errored — retried on the
    // periodic reconcile tick below until they succeed (review finding M8).
    let mut failed: BTreeSet<(u32, Prefix)> = BTreeSet::new();
    // Open route-export subscriptions (`wren monitor routes`); each receives live
    // RouteEvents. Closed ones are pruned lazily on the next fan-out.
    let mut subscribers: Vec<mpsc::Sender<RouteEvent>> = Vec::new();
    let mut monitor_valid = true;
    // Periodic FIB reconciliation. The first `tick()` completes immediately, so
    // consume it up front — there is nothing to reconcile before the loop runs.
    let mut reconcile = tokio::time::interval(FIB_RECONCILE_INTERVAL);
    reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reconcile.tick().await;
    loop {
        tokio::select! {
            update = updates.recv(), if status.borrow().generation == generation => match update {
                Some(first) => {
                    // Coalesce a burst: fold this update and every other one already
                    // waiting in the channel into the RIB, keeping only the net
                    // best-path change per prefix (last write wins — each RIB change
                    // carries the absolute new best, so the last one is the desired
                    // state). Then program the forwarding plane once per prefix. In
                    // steady state `try_recv` returns empty immediately, so a lone
                    // update behaves exactly as before with no added latency.
                    let mut coalesced: BTreeMap<(u32, Prefix), FibChange> = BTreeMap::new();
                    if let Some(change) = ingest(rib, first, &imports) {
                        coalesced.insert(fib_key(&change), change);
                    }
                    let mut drained = 0;
                    while drained < MAX_COALESCE_BATCH {
                        match updates.try_recv() {
                            Ok(u) => {
                                drained += 1;
                                if let Some(change) = ingest(rib, u, &imports) {
                                    coalesced.insert(fib_key(&change), change);
                                }
                            }
                            Err(_) => break, // channel empty (or closed — recv() catches close)
                        }
                    }
                    if coalesced.is_empty() { continue; }
                    begin_attempt(&status, generation);
                    managed.extend(coalesced.keys().copied());
                    let changed: BTreeSet<_> = coalesced.keys().chain(failed.iter()).copied().collect();
                    let desired: ExportedRoutes = changed.iter().filter_map(|(table, prefix)| {
                        rib.best_in(*table, prefix).and_then(|route| export_route(route, vrf_exports.get(table)))
                            .and_then(|route| export_route(&route, fib_export.as_ref()))
                            .map(|route| ((route.table, route.prefix), route))
                    }).collect();
                    let converged = reconcile_selected(&desired, fib,
                        &mut exported, &mut subscribers, &mut failed, &changed, &mut monitor_valid).await;
                    for change in coalesced.values() {
                        redistribute(redist, &redist_event(change)).await;
                    }
                    publish_completion(&status, generation, &failed, converged);
                    managed.retain(|key| failed.contains(key) || exported.contains_key(key));
                }
                None => break, // every protocol sender dropped — shut the router down
            },
            Some(req) = queries.recv() => {
                let _ = req.respond.send(answer_query(rib, vrfs, &req.query));
            }
            Some(sub) = subscribes.recv() => {
                if monitor_valid {
                    subscribe_routes(&exported, &mut subscribers, sub).await;
                }
                // Unknown or ambiguous FIB state: drop without EndOfDump. A
                // reconnect must not mistake uncertainty for a clean empty FIB.
            }
            Some(reload) = reloads.recv() => {
                // Stage all RIB changes before adopting the generation. Learned
                // candidates remain intact; admission already rejected import
                // changes which would require replaying their raw inputs.
                let mut staged = rib.clone();
                let next: BTreeMap<_, _> = reload.statics.into_iter()
                    .map(|route| ((route.table, route.prefix), route)).collect();
                managed.extend(current_statics.keys().copied());
                managed.extend(next.keys().copied());
                let mut changes = BTreeMap::new();
                for (key, old) in &current_statics {
                    if next.get(key) != Some(old) {
                        if let Some(change) = staged.withdraw(key.0, key.1, Protocol::Static, old.source) {
                            changes.insert(*key, change);
                        }
                    }
                }
                for (key, route) in &next {
                    if current_statics.get(key) != Some(route) {
                        if let Some(change) = staged.update(route.clone()) {
                            changes.insert(*key, change);
                        }
                    }
                }
                *rib = staged;
                current_statics = next;
                imports = reload.imports;
                fib_export = reload.fib_export;
                vrf_exports = reload.vrf_exports;
                generation = reload.generation;
                let converged = reconcile_desired_checked(rib, fib, &vrf_exports, fib_export.as_ref(),
                    &mut exported, &mut subscribers, &mut failed, &managed, &mut monitor_valid).await;
                for change in changes.values() {
                    redistribute(redist, &redist_event(change)).await;
                }
                publish_completion(&status, generation, &failed, converged);
                managed.retain(|key| failed.contains(key) || exported.contains_key(key));
            }
            _ = reconcile.tick(), if status.borrow().generation == generation => {
                begin_attempt(&status, generation);
                let converged = reconcile_desired_checked(rib, fib, &vrf_exports, fib_export.as_ref(),
                    &mut exported, &mut subscribers, &mut failed, &managed, &mut monitor_valid).await;
                publish_completion(&status, generation, &failed, converged);
                managed.retain(|key| failed.contains(key) || exported.contains_key(key));
            }
        }
    }
}

fn begin_attempt(status: &watch::Sender<ReloadStatus>, generation: u64) {
    status.send_modify(|current| {
        if current.generation == generation {
            current.in_flight = true;
        }
    });
}

fn publish_completion(
    status: &watch::Sender<ReloadStatus>,
    generation: u64,
    failed: &BTreeSet<(u32, Prefix)>,
    converged: bool,
) {
    status.send_modify(|current| {
        // An older in-flight generation must not overwrite a newer admission.
        if current.generation == generation && current.state != "rejected" {
            current.in_flight = false;
            current.state = if converged { "converged" } else { "pending" };
            current.pending_prefixes = failed.len();
            current.detail = (!converged)
                .then(|| "forwarding-plane reconciliation incomplete; retry scheduled".into());
        }
    });
}

/// Kernel dumps canonicalize inferred interface and single-path weight. Do not
/// compare RIB-only source/distance fields which the kernel cannot represent.
fn same_forwarding(want: &Route, have: &Route) -> bool {
    want.table == have.table
        && want.prefix == have.prefix
        && want.protocol == have.protocol
        && want.metric == have.metric
        && want.nexthops.len() == have.nexthops.len()
        && want
            .nexthops
            .iter()
            .zip(&have.nexthops)
            .all(|(want_hop, have_hop)| {
                want_hop.gateway == have_hop.gateway
                    && want_hop
                        .iface
                        .as_ref()
                        .map_or(true, |iface| Some(iface) == have_hop.iface.as_ref())
                    && (want.nexthops.len() == 1
                        || want_hop.weight.clamp(1, 256) == have_hop.weight)
            })
}

fn inventory_index(observed: &[Route]) -> BTreeMap<(u32, Prefix), Vec<&Route>> {
    let mut index = BTreeMap::<_, Vec<_>>::new();
    for route in observed {
        index
            .entry((route.table, route.prefix))
            .or_default()
            .push(route);
    }
    index
}

fn observed_exports(
    desired: &ExportedRoutes,
    observed: &[Route],
    keys: &BTreeSet<(u32, Prefix)>,
    exported: &mut ExportedRoutes,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
) -> bool {
    let mut confirmed: ExportedRoutes = exported
        .iter()
        .filter(|(key, _)| !keys.contains(key))
        .map(|(key, route)| (*key, route.clone()))
        .collect();
    let index = inventory_index(observed);
    for key in keys {
        if let Some(routes) = index.get(key) {
            if routes.len() != 1 {
                // This wire protocol has one route per prefix. Do not present
                // an arbitrary sibling as the complete forwarding inventory.
                subscribers.clear();
                return false;
            }
            let observed = routes[0];
            let route = desired
                .get(key)
                .filter(|want| same_forwarding(want, observed))
                .or_else(|| {
                    exported
                        .get(key)
                        .filter(|old| same_forwarding(old, observed))
                })
                .unwrap_or(observed);
            confirmed.insert(*key, route.clone());
        }
    }
    for key in exported.keys().filter(|key| !confirmed.contains_key(key)) {
        fanout(
            subscribers,
            RouteEvent::Withdraw {
                table: key.0,
                prefix: key.1,
            },
        );
    }
    for (key, route) in &confirmed {
        if exported.get(key) != Some(route) {
            fanout(subscribers, RouteEvent::Update(route.clone()));
        }
    }
    *exported = confirmed;
    true
}

/// Reconcile against actual owned identities, not the success cache. An install
/// may have reached the kernel even when its ACK failed. All restrictive removals
/// and a complete readback precede expansions; no prefix-wide deletes are used.
#[allow(clippy::too_many_arguments)]
async fn reconcile_desired_checked(
    rib: &Rib,
    fib: &FibHandle,
    vrf_exports: &HashMap<u32, Filter>,
    fib_export: Option<&Filter>,
    exported: &mut ExportedRoutes,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    failed: &mut BTreeSet<(u32, Prefix)>,
    managed: &BTreeSet<(u32, Prefix)>,
    monitor_valid: &mut bool,
) -> bool {
    let desired: ExportedRoutes = rib
        .iter_best()
        .filter_map(|route| {
            export_route(route, vrf_exports.get(&route.table))
                .and_then(|route| export_route(&route, fib_export))
                .map(|route| ((route.table, route.prefix), route))
        })
        .collect();
    let keys: BTreeSet<_> = managed
        .iter()
        .chain(desired.keys())
        .chain(exported.keys())
        .chain(failed.iter())
        .copied()
        .chain(rib.iter_best().map(|route| (route.table, route.prefix)))
        .collect();
    reconcile_selected(
        &desired,
        fib,
        exported,
        subscribers,
        failed,
        &keys,
        monitor_valid,
    )
    .await
}

async fn reconcile_selected(
    desired: &ExportedRoutes,
    fib: &FibHandle,
    exported: &mut ExportedRoutes,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    failed: &mut BTreeSet<(u32, Prefix)>,
    keys: &BTreeSet<(u32, Prefix)>,
    monitor_valid: &mut bool,
) -> bool {
    *monitor_valid = false;
    failed.extend(keys.iter().copied());
    let obsolete = |have: &Route| {
        let key = (have.table, have.prefix);
        keys.contains(&key)
            && !desired
                .get(&key)
                .is_some_and(|want| same_forwarding(want, have))
    };
    let observed = match fib.owned_routes().await {
        Ok(routes) => routes,
        Err(error) => {
            subscribers.clear();
            warn!(%error, "routing reconciliation inventory failed");
            return false;
        }
    };
    let mut writes_ok = true;
    let mut removed = false;
    for route in observed.iter().filter(|route| obsolete(route)) {
        removed = true;
        if let Err(error) = fib.remove_owned(route.clone()).await {
            writes_ok = false;
            warn!(%error, prefix = %route.prefix, "exact route withdrawal pending");
        }
    }
    let after_removals = if removed {
        match fib.owned_routes().await {
            Ok(routes) => routes,
            Err(error) => {
                subscribers.clear();
                warn!(%error, "route withdrawal readback failed");
                return false;
            }
        }
    } else {
        observed
    };
    *monitor_valid = observed_exports(desired, &after_removals, keys, exported, subscribers);
    if !writes_ok || after_removals.iter().any(obsolete) {
        return false;
    }
    let index = inventory_index(&after_removals);
    let mut installed = false;
    for (key, route) in desired {
        if !index
            .get(key)
            .is_some_and(|routes| routes.iter().any(|have| same_forwarding(route, have)))
        {
            installed = true;
            if let Err(error) = fib.apply(FibChange::Install(route.clone())).await {
                writes_ok = false;
                warn!(%error, prefix = %route.prefix, "route installation pending");
            }
        }
    }
    let final_routes = if installed {
        match fib.owned_routes().await {
            Ok(routes) => routes,
            Err(error) => {
                *monitor_valid = false;
                subscribers.clear();
                warn!(%error, "route installation readback failed");
                return false;
            }
        }
    } else {
        after_removals
    };
    *monitor_valid = observed_exports(desired, &final_routes, keys, exported, subscribers);
    let index = inventory_index(&final_routes);
    failed.retain(|key| {
        if !keys.contains(key) {
            return true;
        }
        let actual = index.get(key).map_or(&[][..], Vec::as_slice);
        match desired.get(key) {
            Some(want) => actual.len() != 1 || !same_forwarding(want, actual[0]),
            None => !actual.is_empty(),
        }
    });
    writes_ok && failed.is_empty() && *monitor_valid
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn reconcile_desired(
    rib: &Rib,
    fib: &FibHandle,
    vrf_exports: &HashMap<u32, Filter>,
    fib_export: Option<&Filter>,
    exported: &mut ExportedRoutes,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    failed: &mut BTreeSet<(u32, Prefix)>,
    managed: &BTreeSet<(u32, Prefix)>,
) -> bool {
    reconcile_desired_checked(
        rib,
        fib,
        vrf_exports,
        fib_export,
        exported,
        subscribers,
        failed,
        managed,
        &mut true,
    )
    .await
}

/// A successful install is not permanent: Linux removes gateway routes when a
/// link goes down. Read back owned routes, not our cached RIB, and restore only
/// successfully exported routes. Never flush another daemon's routes, refresh
/// connected routes or resurrect a pending withdrawal/replacement.
#[cfg(test)]
async fn repair_missing_routes(
    fib: &FibHandle,
    exported: &BTreeMap<(u32, Prefix), Route>,
    failed: &BTreeSet<(u32, Prefix)>,
) {
    let mut rib = Rib::new();
    for (key, route) in exported {
        if !failed.contains(key) {
            rib.update(route.clone());
        }
    }
    let mut confirmed = exported.clone();
    let mut pending = failed.clone();
    let keys = exported.keys().copied().collect();
    reconcile_desired(
        &rib,
        fib,
        &HashMap::new(),
        None,
        &mut confirmed,
        &mut Vec::new(),
        &mut pending,
        &keys,
    )
    .await;
}

/// Re-apply the desired forwarding state for every prefix whose last FIB write
/// failed. The desired state is re-derived from the RIB (the single source of
/// truth): a prefix that still has a best path is re-installed; one whose best path
/// has since disappeared is removed. A write that succeeds this time clears the
/// prefix from `failed` (via [`program_fib`]); one that fails again stays queued for
/// the next tick. Called only from the reconcile tick, so a healthy router with no
/// outstanding failures does no work here.
#[cfg(test)]
async fn retry_failed(
    rib: &Rib,
    fib: &FibHandle,
    fib_export: Option<&Filter>,
    exported: &mut BTreeMap<(u32, Prefix), Route>,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    failed: &mut BTreeSet<(u32, Prefix)>,
) {
    let managed = failed.clone();
    reconcile_desired(
        rib,
        fib,
        &HashMap::new(),
        fib_export,
        exported,
        subscribers,
        failed,
        &managed,
    )
    .await;
}

/// Register a new route-export subscriber: replay the current forwarding table as
/// [`RouteEvent::Update`]s — a consistent snapshot, since the single-threaded
/// router processes no route change while this runs — then a terminating
/// [`RouteEvent::EndOfDump`], and finally retain the sender for live events. A
/// subscriber that has already disconnected is simply dropped.
async fn subscribe_routes(
    exported: &BTreeMap<(u32, Prefix), Route>,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    sub: RouteSubscribe,
) {
    // Deliver the snapshot with backpressure (`send().await`) rather than
    // `try_send`, so a large forwarding table (e.g. a full BGP feed) is never
    // truncated when it exceeds the channel capacity. This briefly applies
    // backpressure to the router, but a new subscription is a rare operator
    // action.
    for route in exported.values() {
        if sub
            .events
            .send(RouteEvent::Update(route.clone()))
            .await
            .is_err()
        {
            return;
        }
    }
    if sub.events.send(RouteEvent::EndOfDump).await.is_err() {
        return;
    }
    subscribers.push(sub.events);
}

/// Apply a static-route reload (SIGHUP hot-reload): diff the new desired static set
/// against the one the router currently holds and carry only the delta into the RIB
/// and forwarding plane. A route that is gone from the new set is withdrawn from the
/// RIB; one that is new or whose definition changed is offered to the RIB; one that
/// is byte-for-byte unchanged is left untouched (its RIB entry, and any FIB write, is
/// not disturbed). Each resulting best-path change is programmed through
/// [`program_fib`], so an added route reaches the kernel and streams to `monitor
/// routes` subscribers exactly as a live protocol update would. Dynamically-learned
/// routes are never touched — and since no protocol engine is involved, every session
/// and adjacency stays up across the reload. `current` is replaced with the new set so
/// the next reload diffs against it.
#[allow(clippy::too_many_arguments)] // one delta step: the RIB, the FIB, and every fan-out sink
#[cfg(test)]
async fn reload_statics(
    rib: &mut Rib,
    fib: &FibHandle,
    fib_export: Option<&Filter>,
    exported: &mut BTreeMap<(u32, Prefix), Route>,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    failed: &mut BTreeSet<(u32, Prefix)>,
    current: &mut BTreeMap<(u32, Prefix), Route>,
    new_statics: Vec<Route>,
) {
    let next: BTreeMap<_, _> = new_statics
        .into_iter()
        .map(|route| ((route.table, route.prefix), route))
        .collect();
    let managed = current.keys().chain(next.keys()).copied().collect();
    for (key, route) in current.iter() {
        if next.get(key) != Some(route) {
            rib.withdraw(key.0, key.1, Protocol::Static, route.source);
        }
    }
    for (key, route) in &next {
        if current.get(key) != Some(route) {
            rib.update(route.clone());
        }
    }
    *current = next;
    reconcile_desired(
        rib,
        fib,
        &HashMap::new(),
        fib_export,
        exported,
        subscribers,
        failed,
        &managed,
    )
    .await;
}

/// Fan a route-export event out to every open subscriber. Live events use
/// non-blocking `try_send` so the router never stalls; a subscriber that is
/// closed OR whose bounded buffer has filled (a slow/stuck client) is dropped —
/// it can reconnect and re-snapshot. This bounds the memory any one subscriber
/// can cost the router.
fn fanout(subscribers: &mut Vec<mpsc::Sender<RouteEvent>>, event: RouteEvent) {
    subscribers.retain(|s| s.try_send(event.clone()).is_ok());
}

/// Push the RIB's current best routes to the redistribution targets once at
/// startup. Routes seeded into the RIB before the loop runs (the static routes,
/// installed directly in `main`) never pass through [`apply`], so without this
/// they would not be redistributed until they next change. Subsequent changes
/// flow through [`run`] as usual.
pub async fn redistribute_seed(redist: &[RedistTarget], rib: &Rib) {
    if redist.is_empty() {
        return;
    }
    for route in rib.iter_best() {
        redistribute(redist, &RedistEvent::Changed(route.clone())).await;
    }
}

/// Fan a best-path change out to every redistribution target. For each target,
/// a route whose origin protocol is one of the target's `sources` (and not the
/// target's own protocol) is run through its filter and announced; any other
/// best-path change (a non-source protocol now winning, or the prefix gone) sends
/// a withdraw so a previously-redistributed prefix cannot linger. The consuming
/// engine treats a withdraw for a prefix it never originated as a no-op.
async fn redistribute(targets: &[RedistTarget], event: &RedistEvent) {
    for t in targets {
        let msg = match event {
            RedistEvent::Changed(route) => {
                if route.protocol != t.protocol && t.sources.contains(&route.protocol) {
                    match &t.filter {
                        Some(f) => match f.apply(route) {
                            Decision::Accept(r) => Redistribution::Announce(r),
                            Decision::Reject => Redistribution::Withdraw(route.prefix),
                        },
                        None => Redistribution::Announce(route.clone()),
                    }
                } else {
                    // Best path now held by a protocol this target does not
                    // redistribute (or its own): retract any prior origination.
                    Redistribution::Withdraw(route.prefix)
                }
            }
            RedistEvent::Gone(prefix) => Redistribution::Withdraw(*prefix),
        };
        let _ = t.tx.send(msg).await;
    }
}

/// Render the answer to a [`Query`] as the text the control client prints.
fn answer_query(rib: &Rib, vrfs: &[VrfInfo], query: &Query) -> String {
    match query {
        Query::Routes { protocol } => render_routes(rib, *protocol),
        Query::Metrics => render_router_metrics(rib),
        Query::Vrfs => render_vrfs(rib, vrfs),
    }
}

/// Render `show vrf`: every configured VRF with its table, Route Distinguisher and
/// the number of best routes the RIB currently holds in its table.
pub fn render_vrfs(rib: &Rib, vrfs: &[VrfInfo]) -> String {
    if vrfs.is_empty() {
        return "no vrfs configured\n".to_string();
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<16} {:>8} {:<20} {:>6}",
        "vrf", "table", "rd", "routes"
    );
    for v in vrfs {
        let count = rib.iter_best().filter(|r| r.table == v.table).count();
        let _ = writeln!(
            out,
            "{:<16} {:>8} {:<20} {:>6}",
            v.name,
            v.table,
            v.rd.as_deref().unwrap_or("-"),
            count,
        );
    }
    out
}

/// Render the RIB as Prometheus metrics: the number of best routes by origin
/// protocol (`wren_rib_routes{protocol="…"}`). Because every installed route
/// carries its origin protocol, this single family gives per-protocol visibility
/// for all of them (bgp, ospf, isis, babel, rip, static, connected) from the one
/// task that owns the merged RIB.
pub fn render_router_metrics(rib: &Rib) -> String {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for route in rib.iter_best() {
        *counts.entry(route.protocol.name()).or_default() += 1;
    }
    let mut out = String::new();
    crate::metrics::family(
        &mut out,
        "wren_rib_routes",
        "Best routes in the RIB by origin protocol.",
        "gauge",
    );
    for (proto, n) in &counts {
        crate::metrics::sample(&mut out, "wren_rib_routes", &[("protocol", proto)], n);
    }
    out
}

/// Format the RIB's best routes one per line, à la `ip route`, optionally filtered
/// to a single protocol. Empty output becomes a friendly "no routes" line.
pub fn render_routes(rib: &Rib, protocol: Option<Protocol>) -> String {
    let mut out = String::new();
    for route in rib.iter_best() {
        if protocol.is_some_and(|p| route.protocol != p) {
            continue;
        }
        let _ = write!(out, "{}", route.prefix);
        for (i, nh) in route.nexthops.iter().enumerate() {
            if i > 0 {
                out.push_str(" ,");
            }
            if let Some(gw) = nh.gateway {
                let _ = write!(out, " via {gw}");
            }
            if let Some(dev) = &nh.iface {
                let _ = write!(out, " dev {dev}");
            }
        }
        if route.table != wren_core::RT_TABLE_MAIN {
            let _ = write!(out, " table {}", route.table);
        }
        let _ = writeln!(
            out,
            " proto {} metric {}",
            route.protocol.name(),
            route.metric
        );
    }
    if out.is_empty() {
        match protocol {
            Some(p) => format!("no {} routes\n", p.name()),
            None => "no routes\n".to_string(),
        }
    } else {
        out
    }
}

/// Fold one protocol update into the RIB and, if the best path changed, program
/// the forwarding plane. An announced route is first run through its protocol's
/// import filter (if any): a rejected route is dropped — and any prior candidate
/// for the same `(prefix, protocol, source)` is withdrawn, so re-announcing a
/// now-rejected route cannot leave a stale entry behind. The resulting best-path
/// change is then run through the FIB **export** filter before programming.
/// Fold one protocol update into the RIB, returning the resulting best-path change
/// (or `None` if the installed best route did not change). This is the RIB half of
/// the pipeline, split out from FIB programming so a burst of updates can be folded
/// into the RIB first and programmed once per prefix (see [`run`]'s coalescing).
fn ingest(rib: &mut Rib, update: RouteUpdate, imports: &ImportFilters) -> Option<FibChange> {
    match update {
        RouteUpdate::Announce(route) => {
            let (table, prefix, protocol, source) =
                (route.table, route.prefix, route.protocol, route.source);
            match apply_import(imports, route) {
                Decision::Accept(route) => rib.update(route),
                Decision::Reject => {
                    debug!(%prefix, protocol = protocol.name(), "route rejected by import filter");
                    rib.withdraw(table, prefix, protocol, source)
                }
            }
        }
        // The withdraw names its VRF (the default VRF / main table for a protocol not
        // bound to a VRF).
        RouteUpdate::Withdraw {
            table,
            prefix,
            protocol,
            source,
        } => rib.withdraw(table, prefix, protocol, source),
    }
}

/// The `(table, prefix)` a best-path change is keyed by — the coalescing key.
fn fib_key(change: &FibChange) -> (u32, Prefix) {
    match change {
        FibChange::Install(route) => (route.table, route.prefix),
        FibChange::Remove { table, prefix } => (*table, *prefix),
    }
}

/// The redistribution event a best-path change produces (connected and export-
/// rejected routes are still redistributed even though they are not programmed).
fn redist_event(change: &FibChange) -> RedistEvent {
    match change {
        FibChange::Install(route) => RedistEvent::Changed(route.clone()),
        FibChange::Remove { prefix, .. } => RedistEvent::Gone(*prefix),
    }
}

/// Fold one protocol update into the RIB and, if the best path changed, program the
/// forwarding plane and return the redistribution event. Retained for the unit tests
/// (which drive one update at a time); both paths use the production readback
/// reconciler, while [`run`] additionally coalesces bursts.
#[cfg(test)]
#[allow(clippy::too_many_arguments)] // the router threads every cross-cutting input through
async fn apply(
    rib: &mut Rib,
    fib: &crate::fib::FibHandle,
    update: RouteUpdate,
    imports: &ImportFilters,
    fib_export: Option<&Filter>,
    exported: &mut BTreeMap<(u32, Prefix), Route>,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    failed: &mut BTreeSet<(u32, Prefix)>,
) -> Option<RedistEvent> {
    let change = ingest(rib, update, imports)?;
    let event = redist_event(&change);
    reconcile_desired(
        rib,
        fib,
        &HashMap::new(),
        fib_export,
        exported,
        subscribers,
        failed,
        &BTreeSet::from([fib_key(&change)]),
    )
    .await;
    Some(event)
}

/// Carry the best-path change into the forwarding plane: program a new/changed
/// best route (subject to the FIB export filter and the connected-route special
/// case) or remove a withdrawn one.
#[cfg(test)]
async fn program_fib(
    fib: &FibHandle,
    change: FibChange,
    fib_export: Option<&Filter>,
    exported: &mut BTreeMap<(u32, Prefix), Route>,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    failed: &mut BTreeSet<(u32, Prefix)>,
) {
    let key = fib_key(&change);
    let mut rib = Rib::new();
    // Test adapter only: exercise the production reconciliation machinery.
    // Other exported keys are included to avoid unrelated test fixture deletion.
    for (previous_key, route) in exported.iter() {
        if *previous_key != key {
            rib.update(route.clone());
        }
    }
    if let FibChange::Install(route) = change {
        rib.update(route);
    }
    reconcile_desired(
        &rib,
        fib,
        &HashMap::new(),
        fib_export,
        exported,
        subscribers,
        failed,
        &BTreeSet::from([key]),
    )
    .await;
}

/// Run `route` through its protocol's import filter, if one is configured. With no
/// filter for the protocol the route is accepted unchanged.
pub(crate) fn apply_import(imports: &ImportFilters, route: Route) -> Decision {
    match imports.get(&route.protocol) {
        Some(filter) => filter.apply(&route),
        None => Decision::Accept(route),
    }
}

/// Complete startup readback before any readiness/control endpoint is exposed.
/// An unreadable inventory is unknown, not an empty set of stale routes.
pub async fn reconcile_startup(fib: &FibHandle) -> anyhow::Result<usize> {
    use anyhow::Context;
    let owned = fib
        .owned_routes()
        .await
        .context("reading existing owned routes for startup reconciliation")?;
    reconcile_owned(fib, owned).await
}

/// Reconcile leftover routes at startup: remove every forwarding-plane route this
/// daemon owns (read back via [`Fib::owned_routes`]), even when a new static uses
/// the same prefix: metric/protocol siblings and export-denied routes must not
/// survive by prefix coincidence. Exact owned removal preserves foreign routes.
/// Static routes are synchronously reinstalled before readiness; dynamic routes
/// return as protocols reconverge. Unchanged owned routes briefly withdraw on
/// restart, a deliberate fail-closed tradeoff rather than stale preservation. Returns
/// the number of routes removed. Any failed exact removal prevents startup;
/// partially completed cleanup is retried from a fresh inventory next start.
pub async fn reconcile_owned(fib: &FibHandle, owned: Vec<Route>) -> anyhow::Result<usize> {
    use anyhow::Context;
    let mut removed = 0;
    for route in owned {
        fib.remove_owned(route.clone()).await.with_context(|| {
            format!(
                "removing stale owned route {} in table {}",
                route.prefix, route.table
            )
        })?;
        info!(
            prefix = %route.prefix,
            protocol = route.protocol.name(),
            "removed stale route left by a previous instance",
        );
        removed += 1;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wren_core::{Fib, MemoryFib, NextHop};
    use wren_filter::{Action, Match, Modify, PrefixList, Rule};

    /// A small harness: a RIB + a FIB handle + import/export filters + programmed set.
    struct Harness {
        rib: Rib,
        fib: crate::fib::FibHandle,
        imports: ImportFilters,
        export: Option<Filter>,
        exported: BTreeMap<(u32, Prefix), Route>,
        failed: BTreeSet<(u32, Prefix)>,
    }

    impl Harness {
        fn new() -> Self {
            Harness {
                rib: Rib::new(),
                fib: crate::fib::spawn(Box::new(MemoryFib::default())),
                imports: ImportFilters::new(),
                export: None,
                exported: BTreeMap::new(),
                failed: BTreeSet::new(),
            }
        }

        async fn feed(&mut self, update: RouteUpdate) {
            apply(
                &mut self.rib,
                &self.fib,
                update,
                &self.imports,
                self.export.as_ref(),
                &mut self.exported,
                &mut Vec::new(),
                &mut self.failed,
            )
            .await;
        }

        async fn announce(&mut self, route: Route) {
            self.feed(RouteUpdate::Announce(route)).await;
        }

        /// The route programmed for `prefix` in the main table, read back from the
        /// FIB worker thread (the FIB now lives off-task, so we can't peek a field).
        async fn installed(&self, prefix: &str) -> Option<Route> {
            let key = (wren_core::RT_TABLE_MAIN, prefix.parse().unwrap());
            self.fib
                .owned_routes()
                .await
                .unwrap()
                .into_iter()
                .find(|r| (r.table, r.prefix) == key)
        }

        /// Whether the FIB currently holds any programmed route.
        async fn is_empty(&self) -> bool {
            self.fib.owned_routes().await.unwrap().is_empty()
        }
    }

    fn bgp_route(prefix: &str, metric: u32) -> Route {
        Route::new(
            prefix.parse().unwrap(),
            Protocol::Bgp,
            vec![NextHop::via("192.0.2.1".parse().unwrap())],
            metric,
        )
    }

    #[tokio::test]
    async fn lost_forwarding_routes_are_restored_without_a_protocol_restart() {
        let mut h = Harness::new();
        let expected = bgp_route("203.0.113.0/24", 42);
        h.announce(expected.clone()).await;
        // Simulate the kernel deleting a previously successful gateway route
        // during a link bounce. The RIB and exported cache still hold it.
        h.fib.remove_owned(expected.clone()).await.unwrap();
        assert!(h.installed("203.0.113.0/24").await.is_none());
        let unrelated = bgp_route("192.0.2.0/24", 77);
        h.fib
            .apply(FibChange::Install(unrelated.clone()))
            .await
            .unwrap();
        repair_missing_routes(&h.fib, &h.exported, &h.failed).await;
        assert_eq!(h.installed("203.0.113.0/24").await, Some(expected.clone()));
        assert_eq!(h.installed("192.0.2.0/24").await, Some(unrelated));
        // A failed replacement/withdrawal must not reinstall obsolete intent.
        h.fib.remove_owned(expected.clone()).await.unwrap();
        h.failed.insert((expected.table, expected.prefix));
        repair_missing_routes(&h.fib, &h.exported, &h.failed).await;
        assert!(h.installed("203.0.113.0/24").await.is_none());
    }

    /// A filter rejecting RFC 1918 BGP routes and bumping the metric of the rest.
    fn rfc1918_then_tag() -> Filter {
        Filter {
            rules: vec![
                Rule {
                    matcher: Match::prefix("10.0.0.0/8+".parse::<PrefixList>().unwrap()),
                    modify: Modify::default(),
                    action: Action::Reject,
                },
                Rule {
                    matcher: Match::any(),
                    modify: Modify {
                        add_metric: Some(100),
                        ..Modify::default()
                    },
                    action: Action::Accept,
                },
            ],
            default: Action::Accept,
        }
    }

    /// A connected route is the kernel's, and withdrawing our view of the same
    /// prefix must not delete it.
    ///
    /// Install already refused to reprogram one; Remove did not, and only
    /// skipped unprogrammed prefixes when an export filter happened to exist.
    /// So a protocol that learned the segment it was speaking on, and then
    /// withdrew it, deleted the interface's own route out of the kernel — after
    /// which the box could not reach its own subnet.
    #[tokio::test]
    async fn withdrawing_a_prefix_we_never_installed_leaves_the_kernel_alone() {
        let mut h = Harness::new();
        let connected = Route::new(
            "10.0.0.0/24".parse().unwrap(),
            Protocol::Connected,
            vec![NextHop::dev("eth0")],
            0,
        );
        h.announce(connected.clone()).await;
        // Tracked in the RIB, never programmed: the kernel made it.
        assert!(
            h.is_empty().await,
            "a connected route must not be programmed"
        );

        h.feed(RouteUpdate::Withdraw {
            prefix: "10.0.0.0/24".parse().unwrap(),
            protocol: Protocol::Connected,
            table: wren_core::RT_TABLE_MAIN,
            source: 0,
        })
        .await;
        // And the withdrawal must not have issued a delete for it either.
        assert!(
            !h.failed
                .contains(&(wren_core::RT_TABLE_MAIN, "10.0.0.0/24".parse().unwrap())),
            "removing a route we never installed must not even be attempted"
        );
        assert!(h.is_empty().await);
    }

    #[tokio::test]
    async fn import_filter_rejects_drops_and_accepts_installs_modified() {
        let mut h = Harness::new();
        h.imports.insert(Protocol::Bgp, rfc1918_then_tag());

        // A martian is rejected: nothing reaches the RIB/FIB.
        h.announce(bgp_route("10.1.0.0/16", 1)).await;
        assert!(h.rib.best(&"10.1.0.0/16".parse().unwrap()).is_none());
        assert!(h.is_empty().await);

        // A public route is accepted and installed with the modified metric.
        h.announce(bgp_route("8.8.8.0/24", 1)).await;
        let best = h
            .rib
            .best(&"8.8.8.0/24".parse().unwrap())
            .expect("installed");
        assert_eq!(best.metric, 101); // 1 + add-metric 100
        assert_eq!(h.installed("8.8.8.0/24").await.unwrap().metric, 101);
    }

    #[tokio::test]
    async fn reannouncing_a_now_rejected_route_withdraws_the_prior_one() {
        let mut h = Harness::new();
        // Start with an accept-all filter so the route installs.
        h.imports.insert(Protocol::Bgp, Filter::accept_all());
        h.announce(bgp_route("203.0.113.0/24", 5)).await;
        assert!(h.rib.best(&"203.0.113.0/24".parse().unwrap()).is_some());

        // Now a stricter filter rejects it: re-announcing must withdraw the prior.
        h.imports.insert(Protocol::Bgp, Filter::reject_all());
        h.announce(bgp_route("203.0.113.0/24", 5)).await;
        assert!(h.rib.best(&"203.0.113.0/24".parse().unwrap()).is_none());
    }

    #[tokio::test]
    async fn export_filter_gates_fib_but_not_the_rib() {
        let mut h = Harness::new();
        // Export only public prefixes to the kernel.
        h.export = Some(Filter {
            rules: vec![Rule {
                matcher: Match::prefix("10.0.0.0/8+".parse::<PrefixList>().unwrap()),
                modify: Modify::default(),
                action: Action::Reject,
            }],
            default: Action::Accept,
        });

        // A private route: in the RIB (best-path), but not programmed into the FIB.
        h.announce(bgp_route("10.9.0.0/16", 1)).await;
        assert!(h.rib.best(&"10.9.0.0/16".parse().unwrap()).is_some());
        assert!(h.installed("10.9.0.0/16").await.is_none());

        // A public route: programmed.
        h.announce(bgp_route("8.8.8.0/24", 1)).await;
        assert!(h.installed("8.8.8.0/24").await.is_some());
    }

    #[tokio::test]
    async fn export_filter_modifies_the_programmed_route() {
        let mut h = Harness::new();
        h.export = Some(Filter {
            rules: vec![Rule {
                matcher: Match::any(),
                modify: Modify {
                    set_metric: Some(500),
                    ..Modify::default()
                },
                action: Action::Accept,
            }],
            default: Action::Accept,
        });
        h.announce(bgp_route("8.8.8.0/24", 1)).await;
        // The RIB keeps the original metric; the FIB carries the rewritten one.
        assert_eq!(
            h.rib.best(&"8.8.8.0/24".parse().unwrap()).unwrap().metric,
            1
        );
        assert_eq!(h.installed("8.8.8.0/24").await.unwrap().metric, 500);
    }

    #[test]
    fn render_routes_formats_like_ip_route_and_filters_by_protocol() {
        let mut rib = Rib::new();
        rib.update(Route::new(
            "10.0.0.0/24".parse().unwrap(),
            Protocol::Ospf,
            vec![NextHop::via_dev("192.0.2.1".parse().unwrap(), "eth0")],
            20,
        ));
        rib.update(Route::new(
            "0.0.0.0/0".parse().unwrap(),
            Protocol::Static,
            vec![NextHop::via("192.0.2.254".parse().unwrap())],
            0,
        ));

        let all = render_routes(&rib, None);
        assert!(all.contains("10.0.0.0/24 via 192.0.2.1 dev eth0 proto ospf metric 20"));
        assert!(all.contains("0.0.0.0/0 via 192.0.2.254 proto static metric 0"));

        let only_ospf = render_routes(&rib, Some(Protocol::Ospf));
        assert!(only_ospf.contains("proto ospf"));
        assert!(!only_ospf.contains("proto static"));

        // No matching routes yields the friendly per-protocol message.
        assert_eq!(render_routes(&rib, Some(Protocol::Bgp)), "no bgp routes\n");
    }

    #[tokio::test]
    async fn startup_removes_owned_routes_before_reinstalling_current_ones() {
        let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
        // A previous instance left two routes: a static we still want, and a RIP
        // route the current config no longer covers.
        let still_wanted = "10.0.0.0/24".parse::<Prefix>().unwrap();
        let stale = "10.9.0.0/16".parse::<Prefix>().unwrap();
        fib.apply(FibChange::Install(Route::new(
            still_wanted,
            Protocol::Static,
            vec![NextHop::via("192.0.2.1".parse().unwrap())],
            0,
        )))
        .await
        .unwrap();
        fib.apply(FibChange::Install(Route::new(
            stale,
            Protocol::Rip,
            vec![NextHop::via("192.0.2.2".parse().unwrap())],
            5,
        )))
        .await
        .unwrap();

        let removed = reconcile_startup(&fib).await.unwrap();

        assert_eq!(removed, 2);
        assert!(fib.owned_routes().await.unwrap().is_empty());
        let desired = static_route("10.0.0.0/24");
        fib.apply(FibChange::Install(desired.clone()))
            .await
            .unwrap();
        assert_eq!(fib.owned_routes().await.unwrap(), vec![desired]);
    }

    fn static_route(prefix: &str) -> Route {
        Route::new(
            prefix.parse().unwrap(),
            Protocol::Static,
            vec![NextHop::via("192.0.2.1".parse().unwrap())],
            0,
        )
    }

    #[tokio::test]
    async fn startup_export_rejections_never_reappear_in_repair_or_snapshots() {
        for reject_at_vrf in [false, true] {
            let mut route = static_route("198.51.100.0/24");
            route.table = 100;
            let mut rib = Rib::new();
            let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
            let vrf_exports = if reject_at_vrf {
                HashMap::from([(100, Filter::reject_all())])
            } else {
                HashMap::new()
            };
            let global = (!reject_at_vrf).then(Filter::reject_all);
            let exported = seed_startup_routes(
                &mut rib,
                &fib,
                std::slice::from_ref(&route),
                &vrf_exports,
                global.as_ref(),
            )
            .await
            .unwrap();
            assert_eq!(rib.iter_best().cloned().collect::<Vec<_>>(), vec![route]);
            assert!(exported.is_empty());
            assert!(fib.owned_routes().await.unwrap().is_empty());
            repair_missing_routes(&fib, &exported, &BTreeSet::new()).await;
            assert!(fib.owned_routes().await.unwrap().is_empty());
            let (tx, mut rx) = mpsc::channel(4);
            subscribe_routes(&exported, &mut Vec::new(), RouteSubscribe { events: tx }).await;
            assert!(matches!(rx.recv().await, Some(RouteEvent::EndOfDump)));
            assert!(rx.recv().await.is_none());
        }
    }

    fn rewriting_export(modify: Modify) -> Filter {
        Filter {
            rules: vec![Rule {
                matcher: Match::any(),
                modify,
                action: Action::Accept,
            }],
            default: Action::Reject,
        }
    }

    #[tokio::test]
    async fn startup_export_rewrites_once_in_order_and_preserves_exact_repair_snapshot() {
        let mut route = static_route("198.51.100.0/24");
        route.table = 100;
        let vrf_exports = HashMap::from([(
            100,
            rewriting_export(Modify {
                set_metric: Some(30),
                set_next_hop: Some("192.0.2.2".parse().unwrap()),
                ..Modify::default()
            }),
        )]);
        let global = rewriting_export(Modify {
            add_metric: Some(7),
            ..Modify::default()
        });
        let mut rib = Rib::new();
        let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
        let exported = seed_startup_routes(
            &mut rib,
            &fib,
            std::slice::from_ref(&route),
            &vrf_exports,
            Some(&global),
        )
        .await
        .unwrap();
        let mut expected = route.clone();
        expected.metric = 37;
        expected.nexthops = vec![NextHop::via("192.0.2.2".parse().unwrap())];
        assert_eq!(rib.iter_best().cloned().collect::<Vec<_>>(), vec![route]);
        assert_eq!(
            exported.values().cloned().collect::<Vec<_>>(),
            vec![expected.clone()]
        );
        assert_eq!(fib.owned_routes().await.unwrap(), vec![expected.clone()]);
        fib.remove_owned(expected.clone()).await.unwrap();
        repair_missing_routes(&fib, &exported, &BTreeSet::new()).await;
        assert_eq!(fib.owned_routes().await.unwrap(), vec![expected.clone()]);
        let (tx, mut rx) = mpsc::channel(4);
        subscribe_routes(&exported, &mut Vec::new(), RouteSubscribe { events: tx }).await;
        assert!(matches!(rx.recv().await, Some(RouteEvent::Update(route)) if route == expected));
        assert!(matches!(rx.recv().await, Some(RouteEvent::EndOfDump)));
    }

    struct StartupInstallFib {
        inner: MemoryFib,
        attempts: std::sync::Arc<std::sync::Mutex<Vec<Route>>>,
        fail: bool,
    }

    impl Fib for StartupInstallFib {
        fn apply(&mut self, change: &FibChange) -> Result<(), wren_core::FibError> {
            if let FibChange::Install(route) = change {
                self.attempts.lock().unwrap().push(route.clone());
                if self.fail {
                    return Err(wren_core::FibError(
                        "injected startup install failure".into(),
                    ));
                }
            }
            self.inner.apply(change)
        }

        fn owned_routes(&mut self) -> Result<Vec<Route>, wren_core::FibError> {
            self.inner.owned_routes()
        }
    }

    #[tokio::test]
    async fn startup_exports_final_duplicate_best_only_and_never_connected_routes() {
        let first = static_route("198.51.100.0/24");
        let mut last = first.clone();
        last.metric = 42;
        last.nexthops = vec![NextHop::via("192.0.2.2".parse().unwrap())];
        let mut connected = static_route("192.0.2.0/24");
        connected.protocol = Protocol::Connected;
        let attempts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fib = crate::fib::spawn(Box::new(StartupInstallFib {
            inner: MemoryFib::default(),
            attempts: attempts.clone(),
            fail: false,
        }));
        let mut rib = Rib::new();
        let exported = seed_startup_routes(
            &mut rib,
            &fib,
            &[first, last.clone(), connected],
            &HashMap::new(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(*attempts.lock().unwrap(), vec![last.clone()]);
        assert_eq!(
            exported.values().cloned().collect::<Vec<_>>(),
            vec![last.clone()]
        );
        assert_eq!(fib.owned_routes().await.unwrap(), vec![last]);
        assert_eq!(rib.iter_best().count(), 2);
    }

    #[tokio::test]
    async fn startup_install_failure_is_fatal_not_a_successful_export_cache() {
        let attempts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fib = crate::fib::spawn(Box::new(StartupInstallFib {
            inner: MemoryFib::default(),
            attempts: attempts.clone(),
            fail: true,
        }));
        let mut rib = Rib::new();
        let route = static_route("198.51.100.0/24");
        let error = seed_startup_routes(
            &mut rib,
            &fib,
            std::slice::from_ref(&route),
            &HashMap::new(),
            None,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("injected startup install failure"));
        assert_eq!(*attempts.lock().unwrap(), vec![route]);
        assert!(fib.owned_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn startup_router_loop_uses_successful_exports_not_static_intent() {
        let accepted = static_route("198.51.100.0/24");
        let denied = static_route("203.0.113.0/24");
        let filter = Filter {
            rules: vec![Rule {
                matcher: Match::prefix("198.51.100.0/24".parse::<PrefixList>().unwrap()),
                modify: Modify {
                    add_metric: Some(9),
                    ..Modify::default()
                },
                action: Action::Accept,
            }],
            default: Action::Reject,
        };
        let statics = vec![accepted.clone(), denied];
        let mut rib = Rib::new();
        let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
        let exported =
            seed_startup_routes(&mut rib, &fib, &statics, &HashMap::new(), Some(&filter))
                .await
                .unwrap();
        let (utx, urx) = mpsc::channel(4);
        let (_qtx, qrx) = mpsc::channel(4);
        let (stx, srx) = mpsc::channel(4);
        let (_rtx, rrx) = mpsc::channel(4);
        let (status, _status_rx) = watch::channel(ReloadStatus::startup());
        let vrf_exports = HashMap::new();
        let imports = ImportFilters::new();
        let router = run(
            &mut rib,
            &fib,
            urx,
            &imports,
            Some(&filter),
            &[],
            &[],
            qrx,
            srx,
            &statics,
            exported,
            rrx,
            status,
            &vrf_exports,
        );
        let driver = async move {
            let (tx, mut rx) = mpsc::channel(4);
            stx.send(RouteSubscribe { events: tx }).await.unwrap();
            let event = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap();
            let mut expected = accepted;
            expected.metric = 9;
            assert!(matches!(event, Some(RouteEvent::Update(route)) if route == expected));
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .unwrap(),
                Some(RouteEvent::EndOfDump)
            ));
            // Ending the update stream exits the real central loop.
            drop(utx);
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(router, driver);
        })
        .await
        .unwrap();
    }

    struct StartupFaultFib {
        inner: MemoryFib,
        fail_inventory: bool,
        fail_delete: bool,
        removed: std::sync::Arc<std::sync::Mutex<Vec<Route>>>,
    }

    impl Fib for StartupFaultFib {
        fn apply(&mut self, change: &FibChange) -> Result<(), wren_core::FibError> {
            self.inner.apply(change)
        }

        fn owned_routes(&mut self) -> Result<Vec<Route>, wren_core::FibError> {
            if std::mem::take(&mut self.fail_inventory) {
                return Err(wren_core::FibError("injected inventory failure".into()));
            }
            self.inner.owned_routes()
        }

        fn remove_owned(&mut self, route: &Route) -> Result<(), wren_core::FibError> {
            if std::mem::take(&mut self.fail_delete) {
                return Err(wren_core::FibError("injected exact delete failure".into()));
            }
            self.removed.lock().unwrap().push(route.clone());
            self.inner.remove_owned(route)
        }
    }

    #[tokio::test]
    async fn startup_inventory_failure_is_not_an_empty_healthy_inventory() {
        let stale = static_route("10.8.0.0/16");
        let mut inner = MemoryFib::default();
        inner.apply(&FibChange::Install(stale.clone())).unwrap();
        let removed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fib = crate::fib::spawn(Box::new(StartupFaultFib {
            inner,
            fail_inventory: true,
            fail_delete: false,
            removed: removed.clone(),
        }));
        let error = reconcile_startup(&fib).await.unwrap_err();
        assert!(format!("{error:#}").contains("injected inventory failure"));
        assert!(removed.lock().unwrap().is_empty());
        assert_eq!(fib.owned_routes().await.unwrap(), vec![stale.clone()]);
        // A new start observes the real inventory and completes cleanup.
        assert_eq!(reconcile_startup(&fib).await.unwrap(), 1);
        assert_eq!(*removed.lock().unwrap(), vec![stale]);
        assert!(fib.owned_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn startup_delete_failure_blocks_readiness_until_complete_cleanup() {
        let kept = static_route("10.0.0.0/24");
        let stale = static_route("10.9.0.0/16");
        let mut inner = MemoryFib::default();
        for route in [&kept, &stale] {
            inner.apply(&FibChange::Install(route.clone())).unwrap();
        }
        let removed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fib = crate::fib::spawn(Box::new(StartupFaultFib {
            inner,
            fail_inventory: false,
            fail_delete: true,
            removed: removed.clone(),
        }));
        let error = reconcile_startup(&fib).await.unwrap_err();
        assert!(format!("{error:#}").contains("injected exact delete failure"));
        assert!(removed.lock().unwrap().is_empty());
        assert_eq!(fib.owned_routes().await.unwrap().len(), 2);
        assert_eq!(reconcile_startup(&fib).await.unwrap(), 2);
        assert_eq!(*removed.lock().unwrap(), vec![kept, stale]);
        assert!(fib.owned_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn startup_cleans_metric_protocol_siblings_and_denied_routes_not_foreign_routes() {
        // Model the kernel's multiple identities at one prefix; MemoryFib's
        // one-route-per-prefix map cannot represent this important case.
        struct ExactFib {
            owned: Vec<Route>,
            installed: std::sync::Arc<std::sync::Mutex<Vec<Route>>>,
        }
        impl Fib for ExactFib {
            fn apply(&mut self, _: &FibChange) -> Result<(), wren_core::FibError> {
                panic!("cleanup must use exact owned removal, never broad prefix mutation")
            }
            fn owned_routes(&mut self) -> Result<Vec<Route>, wren_core::FibError> {
                Ok(self.owned.clone())
            }
            fn remove_owned(&mut self, route: &Route) -> Result<(), wren_core::FibError> {
                assert!(
                    self.owned.contains(route),
                    "foreign identity offered for deletion"
                );
                self.installed
                    .lock()
                    .unwrap()
                    .retain(|entry| entry != route);
                self.owned.retain(|entry| entry != route);
                Ok(())
            }
        }
        let old_static = static_route("10.20.0.0/24");
        let mut old_metric = old_static.clone();
        old_metric.metric = 99;
        let mut old_protocol = old_static.clone();
        old_protocol.protocol = Protocol::Bgp;
        let export_denied = static_route("10.30.0.0/24");
        let mut foreign = old_static.clone();
        foreign.metric = 77;
        let owned = vec![old_static, old_metric, old_protocol, export_denied];
        let mut all = owned.clone();
        all.push(foreign.clone());
        let installed = std::sync::Arc::new(std::sync::Mutex::new(all));
        let fib = crate::fib::spawn(Box::new(ExactFib {
            owned,
            installed: installed.clone(),
        }));
        assert_eq!(reconcile_startup(&fib).await.unwrap(), 4);
        assert_eq!(*installed.lock().unwrap(), vec![foreign]);
        assert!(fib.owned_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn render_router_metrics_counts_routes_by_protocol() {
        let mut h = Harness::new();
        h.announce(bgp_route("10.1.0.0/24", 0)).await;
        h.announce(bgp_route("10.2.0.0/24", 0)).await;
        h.announce(static_route("10.3.0.0/24")).await;
        let out = render_router_metrics(&h.rib);
        assert!(out.contains("# TYPE wren_rib_routes gauge"));
        assert!(out.contains("wren_rib_routes{protocol=\"bgp\"} 2"));
        assert!(out.contains("wren_rib_routes{protocol=\"static\"} 1"));
        // An empty RIB still emits the family header, with no samples.
        let empty = render_router_metrics(&Rib::new());
        assert!(empty.contains("# TYPE wren_rib_routes gauge"));
        assert!(!empty.contains("wren_rib_routes{"));
    }

    #[tokio::test]
    async fn redistribution_announces_sources_and_withdraws_others() {
        let (tx, mut rx) = mpsc::channel(16);
        let sources: HashSet<Protocol> = [Protocol::Static, Protocol::Connected]
            .into_iter()
            .collect();
        let targets = vec![RedistTarget {
            protocol: Protocol::Bgp,
            sources,
            filter: None,
            tx,
        }];

        // A static route (a source) is announced verbatim.
        redistribute(&targets, &RedistEvent::Changed(static_route("10.0.0.0/24"))).await;
        match rx.try_recv().unwrap() {
            Redistribution::Announce(r) => assert_eq!(r.prefix.to_string(), "10.0.0.0/24"),
            other => panic!("expected announce, got {other:?}"),
        }

        // A BGP route — the target's own protocol — is never re-announced; the
        // target is told to withdraw instead (loop prevention).
        redistribute(&targets, &RedistEvent::Changed(bgp_route("10.1.0.0/24", 0))).await;
        assert!(matches!(
            rx.try_recv().unwrap(),
            Redistribution::Withdraw(_)
        ));

        // A prefix going away withdraws everywhere.
        redistribute(&targets, &RedistEvent::Gone("10.0.0.0/24".parse().unwrap())).await;
        assert!(matches!(
            rx.try_recv().unwrap(),
            Redistribution::Withdraw(_)
        ));
    }

    #[tokio::test]
    async fn redistribution_export_filter_turns_rejects_into_withdraws() {
        let (tx, mut rx) = mpsc::channel(16);
        let sources: HashSet<Protocol> = [Protocol::Static].into_iter().collect();
        // Reject RFC 1918 10/8, accept everything else.
        let filter = Filter {
            rules: vec![Rule {
                matcher: Match::prefix("10.0.0.0/8+".parse::<PrefixList>().unwrap()),
                modify: Modify::default(),
                action: Action::Reject,
            }],
            default: Action::Accept,
        };
        let targets = vec![RedistTarget {
            protocol: Protocol::Bgp,
            sources,
            filter: Some(filter),
            tx,
        }];

        redistribute(&targets, &RedistEvent::Changed(static_route("10.9.0.0/16"))).await;
        assert!(matches!(
            rx.try_recv().unwrap(),
            Redistribution::Withdraw(_)
        ));

        redistribute(&targets, &RedistEvent::Changed(static_route("8.8.8.0/24"))).await;
        assert!(matches!(
            rx.try_recv().unwrap(),
            Redistribution::Announce(_)
        ));
    }

    #[tokio::test]
    async fn best_path_changing_to_a_rejected_route_withdraws_from_the_fib() {
        let mut h = Harness::new();
        // Reject anything with metric ≥ 100 on export.
        h.export = Some(Filter {
            rules: vec![Rule {
                matcher: Match {
                    metric_ge: Some(100),
                    ..Match::default()
                },
                modify: Modify::default(),
                action: Action::Reject,
            }],
            default: Action::Accept,
        });

        // A good route is installed.
        h.announce(bgp_route("8.8.8.0/24", 1)).await;
        assert!(h.installed("8.8.8.0/24").await.is_some());

        // The same source re-announces with a now-rejected metric: the best path
        // changes, export rejects it, and the prior FIB entry is withdrawn.
        h.announce(bgp_route("8.8.8.0/24", 200)).await;
        assert!(h.rib.best(&"8.8.8.0/24".parse().unwrap()).is_some());
        assert!(h.installed("8.8.8.0/24").await.is_none());
    }

    #[tokio::test]
    async fn route_export_snapshots_then_streams_live_updates_and_withdraws() {
        use std::time::Duration;
        use tokio::time::timeout;

        let (utx, urx) = mpsc::channel(16);
        let (qtx, qrx) = mpsc::channel::<QueryRequest>(16);
        let (stx, srx) = mpsc::channel::<RouteSubscribe>(16);
        let (_rtx, rrx) = mpsc::channel::<RouterReload>(16);
        let (status, _status_rx) = watch::channel(ReloadStatus::startup());

        // `run` borrows a `&mut Rib` for its whole lifetime, so it can't be
        // `tokio::spawn`ed (production runs it in `select!`, not spawned). Drive it
        // and the test interactions concurrently on one task with `join!` instead.
        // The FIB lives on its own worker thread behind the handle; the loop ends
        // when the driver drops every update sender.
        let router = async move {
            let mut rib = Rib::new();
            let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
            let imports = ImportFilters::new();
            run(
                &mut rib,
                &fib,
                urx,
                &imports,
                None,
                &[],
                &[],
                qrx,
                srx,
                &[],
                ExportedRoutes::new(),
                rrx,
                status,
                &HashMap::new(),
            )
            .await;
        };

        let driver = async move {
            // Hold the query/subscribe `_tx` ends so those select arms never see a
            // closed channel while the test runs.
            let _qtx = qtx;
            // A short timeout turns a hang (a missing event) into a test failure.
            async fn next(rx: &mut mpsc::Receiver<RouteEvent>) -> RouteEvent {
                timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
            }

            // Subscribe before any route exists: the snapshot is empty — just
            // EndOfDump.
            let (etx, mut erx) = mpsc::channel(SUBSCRIBER_CAP);
            stx.send(RouteSubscribe { events: etx }).await.unwrap();
            assert!(matches!(next(&mut erx).await, RouteEvent::EndOfDump));

            // A new best route streams live as an Update…
            utx.send(RouteUpdate::Announce(bgp_route("203.0.113.0/24", 10)))
                .await
                .unwrap();
            match next(&mut erx).await {
                RouteEvent::Update(r) => assert_eq!(r.prefix.to_string(), "203.0.113.0/24"),
                other => panic!("expected update, got {other:?}"),
            }

            // …and withdrawing it streams a Withdraw for the same prefix.
            utx.send(RouteUpdate::Withdraw {
                table: wren_core::RT_TABLE_MAIN,
                prefix: "203.0.113.0/24".parse().unwrap(),
                protocol: Protocol::Bgp,
                source: 0,
            })
            .await
            .unwrap();
            match next(&mut erx).await {
                RouteEvent::Withdraw { prefix, .. } => {
                    assert_eq!(prefix.to_string(), "203.0.113.0/24")
                }
                other => panic!("expected withdraw, got {other:?}"),
            }

            // A late subscriber sees the now-current table replayed in its
            // snapshot. Re-announce a route and wait until subscriber #1 sees it
            // live — that confirms the router has processed the announce (so it is
            // in `exported`) before subscriber #2 subscribes, avoiding an
            // announce-vs-subscribe race.
            utx.send(RouteUpdate::Announce(bgp_route("198.51.100.0/24", 5)))
                .await
                .unwrap();
            match next(&mut erx).await {
                RouteEvent::Update(r) => assert_eq!(r.prefix.to_string(), "198.51.100.0/24"),
                other => panic!("expected live update on subscriber #1, got {other:?}"),
            }
            let (etx2, mut erx2) = mpsc::channel(SUBSCRIBER_CAP);
            stx.send(RouteSubscribe { events: etx2 }).await.unwrap();
            match next(&mut erx2).await {
                RouteEvent::Update(r) => assert_eq!(r.prefix.to_string(), "198.51.100.0/24"),
                other => panic!("expected snapshot update, got {other:?}"),
            }
            assert!(matches!(next(&mut erx2).await, RouteEvent::EndOfDump));
            // Dropping utx/stx/_qtx here closes every router input → the loop ends.
        };

        tokio::join!(router, driver);
    }

    #[tokio::test]
    async fn static_reload_applies_delta_and_leaves_learned_routes_untouched() {
        let mut rib = Rib::new();
        let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
        let mut exported: BTreeMap<(u32, Prefix), Route> = BTreeMap::new();
        let mut subs: Vec<mpsc::Sender<RouteEvent>> = Vec::new();
        let mut failed = BTreeSet::new();

        // A learned BGP route and an initial static are already in the RIB/FIB —
        // the state a running daemon holds before a SIGHUP.
        let learned = bgp_route("203.0.113.0/24", 10);
        rib.update(learned.clone());
        fib.apply(FibChange::Install(learned.clone()))
            .await
            .unwrap();
        exported.insert((learned.table, learned.prefix), learned.clone());
        let old_static = static_route("10.0.0.0/24");
        rib.update(old_static.clone());
        fib.apply(FibChange::Install(old_static.clone()))
            .await
            .unwrap();
        exported.insert((old_static.table, old_static.prefix), old_static.clone());

        let mut current: BTreeMap<(u32, Prefix), Route> = BTreeMap::new();
        current.insert((old_static.table, old_static.prefix), old_static.clone());

        // Reload: drop 10.0.0.0/24, add 172.16.0.0/24. The BGP route is not part of
        // the static set, so it must be left exactly in place.
        let new_static = static_route("172.16.0.0/24");
        reload_statics(
            &mut rib,
            &fib,
            None,
            &mut exported,
            &mut subs,
            &mut failed,
            &mut current,
            vec![new_static.clone()],
        )
        .await;

        let owned = fib.owned_routes().await.unwrap();
        // The added static is the best path for its prefix and is programmed.
        assert!(rib.best_in(new_static.table, &new_static.prefix).is_some());
        assert!(owned.iter().any(|r| r.prefix == new_static.prefix));
        // The removed static is gone from both the RIB and the FIB.
        assert!(rib.best_in(old_static.table, &old_static.prefix).is_none());
        assert!(!owned.iter().any(|r| r.prefix == old_static.prefix));
        // The learned BGP route is untouched — same protocol, still in the FIB.
        let b = rib.best(&learned.prefix).expect("bgp route still present");
        assert_eq!(b.protocol, Protocol::Bgp);
        assert!(owned.iter().any(|r| r.prefix == learned.prefix));
        // `current` now reflects the new desired set.
        assert_eq!(current.len(), 1);
        assert!(current.contains_key(&(new_static.table, new_static.prefix)));
    }

    #[tokio::test]
    async fn static_reload_leaves_an_unchanged_route_in_place() {
        // A reload whose static set is identical to the running one must be a no-op
        // for the RIB: the unchanged route keeps its exact RIB entry.
        let mut rib = Rib::new();
        let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
        let mut exported: BTreeMap<(u32, Prefix), Route> = BTreeMap::new();
        let mut subs: Vec<mpsc::Sender<RouteEvent>> = Vec::new();
        let mut failed = BTreeSet::new();

        let kept = static_route("10.0.0.0/24");
        rib.update(kept.clone());
        let mut current: BTreeMap<(u32, Prefix), Route> = BTreeMap::new();
        current.insert((kept.table, kept.prefix), kept.clone());

        reload_statics(
            &mut rib,
            &fib,
            None,
            &mut exported,
            &mut subs,
            &mut failed,
            &mut current,
            vec![kept.clone()],
        )
        .await;

        // Still exactly one static, unchanged, and no route-export churn happened.
        assert_eq!(current.len(), 1);
        assert_eq!(rib.best_in(kept.table, &kept.prefix), Some(&kept));
    }

    /// A [`Fib`] whose first `fail_installs` install attempts return a transient
    /// error, then succeed — modelling an ENOBUFS burst that clears.
    struct FlakyFib {
        inner: MemoryFib,
        fail_installs: u32,
        fail_removes: u32,
    }

    impl Fib for FlakyFib {
        fn remove_owned(&mut self, route: &Route) -> Result<(), wren_core::FibError> {
            if self.fail_removes > 0 {
                self.fail_removes -= 1;
                return Err(wren_core::FibError("transient ENOBUFS on remove".into()));
            }
            self.inner.remove_owned(route)
        }
        fn apply(&mut self, change: &FibChange) -> Result<(), wren_core::FibError> {
            if matches!(change, FibChange::Install(_)) && self.fail_installs > 0 {
                self.fail_installs -= 1;
                return Err(wren_core::FibError("transient ENOBUFS".into()));
            }
            self.inner.apply(change)
        }

        fn owned_routes(&mut self) -> Result<Vec<Route>, wren_core::FibError> {
            self.inner.owned_routes()
        }
    }

    #[tokio::test]
    async fn failed_fib_install_is_queued_and_healed_by_reconcile() {
        // A route whose first install attempt fails: it lands in `failed`, not the
        // FIB, and is not lost.
        let mut rib = Rib::new();
        let fib = crate::fib::spawn(Box::new(FlakyFib {
            inner: MemoryFib::default(),
            fail_installs: 1,
            fail_removes: 0,
        }));
        let mut exported = BTreeMap::new();
        let mut subs = Vec::new();
        let mut failed = BTreeSet::new();

        apply(
            &mut rib,
            &fib,
            RouteUpdate::Announce(bgp_route("198.51.100.0/24", 5)),
            &ImportFilters::new(),
            None,
            &mut exported,
            &mut subs,
            &mut failed,
        )
        .await;
        let key = (wren_core::RT_TABLE_MAIN, "198.51.100.0/24".parse().unwrap());
        assert!(
            fib.owned_routes().await.unwrap().is_empty(),
            "install should have failed"
        );
        assert!(
            failed.contains(&key),
            "failed prefix must be queued for retry"
        );

        // The reconcile tick re-derives the desired state from the RIB and, now that
        // the kernel error has cleared, installs the route and clears the queue.
        retry_failed(&rib, &fib, None, &mut exported, &mut subs, &mut failed).await;
        assert!(
            fib.owned_routes()
                .await
                .unwrap()
                .iter()
                .any(|r| (r.table, r.prefix) == key),
            "route should self-heal"
        );
        assert!(failed.is_empty(), "queue must clear once the write lands");
    }

    #[tokio::test]
    async fn reconcile_removes_a_failed_prefix_whose_best_path_vanished() {
        // A prefix queued as failed whose RIB best path has since disappeared must be
        // reconciled as a removal, not re-installed.
        let rib = Rib::new();
        let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
        let mut exported = BTreeMap::new();
        let mut subs: Vec<mpsc::Sender<RouteEvent>> = Vec::new();
        let mut failed = BTreeSet::new();
        let key = (wren_core::RT_TABLE_MAIN, "203.0.113.0/24".parse().unwrap());
        failed.insert(key);

        // RIB has no best path for the prefix → reconcile issues a remove and clears
        // the queue (MemoryFib remove of an absent key is a no-op success).
        retry_failed(&rib, &fib, None, &mut exported, &mut subs, &mut failed).await;
        assert!(
            failed.is_empty(),
            "vanished prefix must leave the retry queue"
        );
        assert!(fib.owned_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_exact_withdraw_keeps_identity_until_retry_succeeds() {
        let route = bgp_route("203.0.113.0/24", 20);
        let key = (route.table, route.prefix);
        let mut inner = MemoryFib::default();
        inner.apply(&FibChange::Install(route.clone())).unwrap();
        let fib = crate::fib::spawn(Box::new(FlakyFib {
            inner,
            fail_installs: 0,
            fail_removes: 1,
        }));
        let mut exported = BTreeMap::from([(key, route)]);
        let mut failed = BTreeSet::new();
        let (tx, mut rx) = mpsc::channel(2);
        let mut subs = vec![tx];
        program_fib(
            &fib,
            FibChange::Remove {
                table: key.0,
                prefix: key.1,
            },
            None,
            &mut exported,
            &mut subs,
            &mut failed,
        )
        .await;
        assert!(failed.contains(&key));
        assert!(
            exported.contains_key(&key),
            "do not lose exact deletion identity on failure"
        );
        assert_eq!(fib.owned_routes().await.unwrap().len(), 1);
        assert!(
            rx.try_recv().is_err(),
            "do not report a withdrawal that failed"
        );
        retry_failed(
            &Rib::new(),
            &fib,
            None,
            &mut exported,
            &mut subs,
            &mut failed,
        )
        .await;
        assert!(exported.is_empty() && failed.is_empty());
        assert!(fib.owned_routes().await.unwrap().is_empty());
        assert!(
            matches!(rx.try_recv().unwrap(), RouteEvent::Withdraw { table, prefix }
            if (table, prefix) == key)
        );
    }

    #[derive(Default)]
    struct LiveFaultFib {
        routes: Vec<Route>,
        fail_remove: bool,
        error_after_install: bool,
        fail_read_after_install: bool,
        fail_next_read: bool,
        operations: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl Fib for LiveFaultFib {
        fn apply(&mut self, change: &FibChange) -> Result<(), wren_core::FibError> {
            let FibChange::Install(route) = change else {
                panic!("broad deletion forbidden")
            };
            self.operations.lock().unwrap().push("install");
            self.routes.retain(|old| {
                !(old.table == route.table
                    && old.prefix == route.prefix
                    && old.protocol == route.protocol
                    && old.metric == route.metric)
            });
            self.routes.push(route.clone());
            self.fail_next_read = std::mem::take(&mut self.fail_read_after_install);
            if std::mem::take(&mut self.error_after_install) {
                return Err(wren_core::FibError("injected lost ACK after effect".into()));
            }
            Ok(())
        }
        fn remove_owned(&mut self, route: &Route) -> Result<(), wren_core::FibError> {
            self.operations.lock().unwrap().push("remove");
            if std::mem::take(&mut self.fail_remove) {
                return Err(wren_core::FibError("injected failed withdrawal".into()));
            }
            self.routes.retain(|old| old != route);
            Ok(())
        }
        fn owned_routes(&mut self) -> Result<Vec<Route>, wren_core::FibError> {
            self.operations.lock().unwrap().push("read");
            if std::mem::take(&mut self.fail_next_read) {
                return Err(wren_core::FibError("injected failed readback".into()));
            }
            Ok(self.routes.clone())
        }
    }

    #[tokio::test]
    async fn coherent_reload_removes_all_old_identities_before_expanding_and_reports_actual_monitor(
    ) {
        let original = static_route("198.51.100.0/24");
        let key = (original.table, original.prefix);
        let mut sibling = original.clone();
        sibling.metric = 40;
        let mut desired = original.clone();
        desired.metric = 27;
        let foreign_key = bgp_route("203.0.113.0/24", 99);
        let operations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fib = crate::fib::spawn(Box::new(LiveFaultFib {
            routes: vec![original.clone(), sibling, foreign_key.clone()],
            fail_remove: true,
            error_after_install: false,
            operations: operations.clone(),
            ..Default::default()
        }));
        let mut rib = Rib::new();
        rib.update(desired.clone());
        let mut exported = BTreeMap::from([(key, original.clone())]);
        let mut failed = BTreeSet::new();
        let managed = BTreeSet::from([key]);
        let (tx, mut events) = mpsc::channel(10);
        let mut subscribers = vec![tx];
        assert!(
            !reconcile_desired(
                &rib,
                &fib,
                &HashMap::new(),
                None,
                &mut exported,
                &mut subscribers,
                &mut failed,
                &managed
            )
            .await
        );
        assert!(
            !operations.lock().unwrap().contains(&"install"),
            "failed restrictive phase prohibits every expansion"
        );
        assert_eq!(exported.get(&key), Some(&original));
        assert!(events.try_recv().is_err());
        operations.lock().unwrap().clear();
        assert!(
            reconcile_desired(
                &rib,
                &fib,
                &HashMap::new(),
                None,
                &mut exported,
                &mut subscribers,
                &mut failed,
                &managed
            )
            .await
        );
        assert_eq!(
            fib.owned_routes().await.unwrap(),
            vec![foreign_key, desired.clone()]
        );
        assert_eq!(exported.get(&key), Some(&desired));
        let ops = operations.lock().unwrap();
        assert!(
            ops.iter().position(|op| *op == "remove").unwrap()
                < ops.iter().position(|op| *op == "install").unwrap()
        );
        assert!(ops.last() == Some(&"read"));
        assert!(matches!(
            events.try_recv().unwrap(),
            RouteEvent::Withdraw { .. }
        ));
        assert!(
            matches!(events.try_recv().unwrap(), RouteEvent::Update(route) if route == desired)
        );
    }

    #[tokio::test]
    async fn applied_despite_error_is_owned_and_withdrawn_by_subsequent_reject_or_connected_best() {
        for connected in [false, true] {
            let route = static_route("198.51.100.0/24");
            let key = (route.table, route.prefix);
            let fib = crate::fib::spawn(Box::new(LiveFaultFib {
                routes: vec![],
                fail_remove: false,
                error_after_install: true,
                operations: Default::default(),
                ..Default::default()
            }));
            let mut rib = Rib::new();
            rib.update(route.clone());
            let mut exported = BTreeMap::new();
            let mut failed = BTreeSet::new();
            let managed = BTreeSet::from([key]);
            let mut subscribers = vec![];
            assert!(
                !reconcile_desired(
                    &rib,
                    &fib,
                    &HashMap::new(),
                    None,
                    &mut exported,
                    &mut subscribers,
                    &mut failed,
                    &managed
                )
                .await
            );
            assert_eq!(fib.owned_routes().await.unwrap(), vec![route.clone()]);
            let reject = Filter::reject_all();
            if connected {
                let mut local = route;
                local.protocol = Protocol::Connected;
                local.preference = Protocol::Connected.default_preference();
                rib.update(local);
                assert_eq!(
                    rib.best_in(key.0, &key.1).unwrap().protocol,
                    Protocol::Connected
                );
            }
            assert!(
                reconcile_desired(
                    &rib,
                    &fib,
                    &HashMap::new(),
                    (!connected).then_some(&reject),
                    &mut exported,
                    &mut subscribers,
                    &mut failed,
                    &managed
                )
                .await
            );
            assert!(fib.owned_routes().await.unwrap().is_empty());
            assert!(exported.is_empty());
        }
    }

    #[tokio::test]
    async fn lost_ack_and_readback_then_failed_denial_never_produces_a_clean_empty_monitor() {
        let route = static_route("198.51.100.0/24");
        let key = (route.table, route.prefix);
        let fib = crate::fib::spawn(Box::new(LiveFaultFib {
            error_after_install: true,
            fail_read_after_install: true,
            fail_remove: true,
            ..Default::default()
        }));
        let desired = BTreeMap::from([(key, route.clone())]);
        let keys = BTreeSet::from([key]);
        let mut exported = BTreeMap::new();
        let mut failed = BTreeSet::new();
        let (tx, mut rx) = mpsc::channel(10);
        let mut subs = vec![tx];
        let mut valid = true;
        assert!(
            !reconcile_selected(
                &desired,
                &fib,
                &mut exported,
                &mut subs,
                &mut failed,
                &keys,
                &mut valid
            )
            .await
        );
        assert!(!valid && exported.is_empty());
        assert!(
            rx.recv().await.is_none(),
            "unknown inventory closes rather than fabricating an empty dump"
        );
        assert_eq!(fib.owned_routes().await.unwrap(), vec![route.clone()]);
        assert!(
            !reconcile_selected(
                &BTreeMap::new(),
                &fib,
                &mut exported,
                &mut subs,
                &mut failed,
                &keys,
                &mut valid
            )
            .await
        );
        assert!(
            valid,
            "sole observed old route is representable even when never cached"
        );
        assert_eq!(exported.get(&key), Some(&route));
        assert!(
            reconcile_selected(
                &BTreeMap::new(),
                &fib,
                &mut exported,
                &mut subs,
                &mut failed,
                &keys,
                &mut valid
            )
            .await
        );
        assert!(valid && exported.is_empty());
    }

    #[tokio::test]
    async fn ambiguous_sibling_inventory_drops_monitor_until_readback_proves_one_identity() {
        let route = static_route("198.51.100.0/24");
        let key = (route.table, route.prefix);
        let mut sibling = route.clone();
        sibling.metric = 99;
        let fib = crate::fib::spawn(Box::new(LiveFaultFib {
            routes: vec![route.clone(), sibling],
            fail_remove: true,
            ..Default::default()
        }));
        let desired = BTreeMap::from([(key, route.clone())]);
        let keys = BTreeSet::from([key]);
        let mut exported = desired.clone();
        let mut failed = BTreeSet::new();
        let (tx, mut rx) = mpsc::channel(10);
        let mut subs = vec![tx];
        let mut valid = true;
        assert!(
            !reconcile_selected(
                &desired,
                &fib,
                &mut exported,
                &mut subs,
                &mut failed,
                &keys,
                &mut valid
            )
            .await
        );
        assert!(!valid);
        assert!(rx.recv().await.is_none());
        assert!(
            reconcile_selected(
                &desired,
                &fib,
                &mut exported,
                &mut subs,
                &mut failed,
                &keys,
                &mut valid
            )
            .await
        );
        assert!(valid);
        assert_eq!(exported, desired);
    }

    #[tokio::test]
    async fn runtime_vrf_then_global_exports_rewrite_once_in_repair_and_deny_unchanged_static() {
        let mut route = static_route("198.51.100.0/24");
        route.table = 100;
        route.metric = 10;
        let key = (route.table, route.prefix);
        let increment = |amount| Filter {
            rules: vec![Rule {
                matcher: Match::default(),
                modify: Modify {
                    add_metric: Some(amount),
                    ..Modify::default()
                },
                action: Action::Accept,
            }],
            default: Action::Accept,
        };
        let vrf = HashMap::from([(100, increment(7))]);
        let global = increment(10);
        let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
        let mut rib = Rib::new();
        rib.update(route);
        let mut exported = BTreeMap::new();
        let mut failed = BTreeSet::new();
        let mut subs = vec![];
        for _ in 0..3 {
            assert!(
                reconcile_desired(
                    &rib,
                    &fib,
                    &vrf,
                    Some(&global),
                    &mut exported,
                    &mut subs,
                    &mut failed,
                    &BTreeSet::from([key])
                )
                .await
            );
            assert_eq!(exported[&key].metric, 27);
            fib.remove_owned(exported[&key].clone()).await.unwrap();
        }
        // Restore once, then change only policy: static/RIB input is identical.
        assert!(
            reconcile_desired(
                &rib,
                &fib,
                &vrf,
                Some(&global),
                &mut exported,
                &mut subs,
                &mut failed,
                &BTreeSet::from([key])
            )
            .await
        );
        assert!(
            reconcile_desired(
                &rib,
                &fib,
                &HashMap::from([(100, Filter::reject_all())]),
                Some(&global),
                &mut exported,
                &mut subs,
                &mut failed,
                &BTreeSet::from([key])
            )
            .await
        );
        assert!(exported.is_empty());
        assert!(fib.owned_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn full_reconcile_removes_drift_at_current_denied_rib_prefix_without_history() {
        let route = static_route("198.51.100.0/24");
        let mut rib = Rib::new();
        rib.update(route.clone());
        let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
        let reject = Filter::reject_all();
        let mut exported = BTreeMap::new();
        let mut failed = BTreeSet::new();
        let mut subs = vec![];
        assert!(
            reconcile_desired(
                &rib,
                &fib,
                &HashMap::new(),
                Some(&reject),
                &mut exported,
                &mut subs,
                &mut failed,
                &BTreeSet::new()
            )
            .await
        );
        // Both cache and historical keys are empty after confirmed denial.
        fib.apply(FibChange::Install(route)).await.unwrap();
        assert!(
            reconcile_desired(
                &rib,
                &fib,
                &HashMap::new(),
                Some(&reject),
                &mut exported,
                &mut subs,
                &mut failed,
                &BTreeSet::new()
            )
            .await
        );
        assert!(fib.owned_routes().await.unwrap().is_empty());
    }

    #[test]
    fn old_completion_cannot_overwrite_new_generation_and_unknown_empty_inventory_is_not_converged()
    {
        let (status, _) = watch::channel(ReloadStatus {
            generation: 2,
            state: "pending",
            pending_prefixes: 0,
            detail: None,
            in_flight: false,
        });
        publish_completion(&status, 1, &BTreeSet::new(), true);
        assert_eq!(status.borrow().state, "pending");
        publish_completion(&status, 2, &BTreeSet::new(), false);
        assert_eq!(status.borrow().state, "pending");
        publish_completion(&status, 2, &BTreeSet::new(), true);
        assert_eq!(status.borrow().state, "converged");
        assert_eq!(
            ReloadStatus::startup().render(),
            "scope routing\ngeneration 0\nstate converged\npending-prefixes 0\n"
        );
    }

    #[tokio::test]
    async fn real_loop_skips_rejected_updates_commits_duplicate_last_and_forgets_verified_withdrawals(
    ) {
        let operations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fib = crate::fib::spawn(Box::new(LiveFaultFib {
            operations: operations.clone(),
            ..Default::default()
        }));
        let (updates, updates_rx) = mpsc::channel(16);
        let (_queries, queries_rx) = mpsc::channel(4);
        let (subscribe, subscribe_rx) = mpsc::channel(4);
        let (reloads, reload_rx) = mpsc::channel(1);
        let (status, progress) = watch::channel(ReloadStatus::startup());
        let imports = HashMap::from([(Protocol::Bgp, Filter::reject_all())]);
        let router = async {
            run(
                &mut Rib::new(),
                &fib,
                updates_rx,
                &imports,
                None,
                &[],
                &[],
                queries_rx,
                subscribe_rx,
                &[],
                ExportedRoutes::new(),
                reload_rx,
                status.clone(),
                &HashMap::new(),
            )
            .await;
        };
        let driver = async {
            for _ in 0..100 {
                updates
                    .send(RouteUpdate::Announce(bgp_route("203.0.113.0/24", 10)))
                    .await
                    .unwrap();
            }
            // Full capacity proves all updates were received; a rejected batch
            // has no awaiting FIB work after its final recv.
            while updates.capacity() != 16 {
                tokio::task::yield_now().await;
            }
            assert!(
                operations.lock().unwrap().is_empty(),
                "no-op input must not dump or write FIB"
            );
            async fn commit(
                tx: &mpsc::Sender<RouterReload>,
                status: &watch::Sender<ReloadStatus>,
                progress: &mut watch::Receiver<ReloadStatus>,
                generation: u64,
                routes: Vec<Route>,
            ) {
                let mut receipt = ReloadStatus::startup();
                receipt.generation = generation;
                receipt.state = "pending";
                receipt.in_flight = true;
                tx.try_send(RouterReload {
                    generation,
                    statics: routes,
                    imports: HashMap::from([(Protocol::Bgp, Filter::reject_all())]),
                    fib_export: None,
                    vrf_exports: HashMap::new(),
                })
                .unwrap();
                status.send_replace(receipt);
                progress
                    .wait_for(|value| value.generation == generation && value.state == "converged")
                    .await
                    .unwrap();
                assert!(!status.borrow().in_flight);
            }
            let mut progress = progress;
            let first = static_route("198.51.100.0/24");
            let mut last = first.clone();
            last.metric = 27;
            commit(
                &reloads,
                &status,
                &mut progress,
                1,
                vec![first, last.clone()],
            )
            .await;
            assert_eq!(fib.owned_routes().await.unwrap(), vec![last.clone()]);
            let (events, mut stream) = mpsc::channel(4);
            subscribe.send(RouteSubscribe { events }).await.unwrap();
            assert!(
                matches!(stream.recv().await.unwrap(), RouteEvent::Update(route) if route == last)
            );
            assert!(matches!(
                stream.recv().await.unwrap(),
                RouteEvent::EndOfDump
            ));
            commit(&reloads, &status, &mut progress, 2, vec![]).await;
            assert!(fib.owned_routes().await.unwrap().is_empty());
            assert!(matches!(
                stream.recv().await.unwrap(),
                RouteEvent::Withdraw { .. }
            ));
            // A historical prefix no longer configured/failed/exported must not
            // grant this router perpetual ownership over a later writer's route.
            fib.apply(FibChange::Install(last.clone())).await.unwrap();
            let next = static_route("192.0.2.128/25");
            commit(&reloads, &status, &mut progress, 3, vec![next.clone()]).await;
            let routes = fib.owned_routes().await.unwrap();
            assert_eq!(routes.len(), 2);
            assert!(routes.contains(&last) && routes.contains(&next));
            drop(updates);
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(router, driver);
        })
        .await
        .unwrap();
    }

    /// A [`Fib`] that counts install writes — to prove a coalesced burst hits the
    /// forwarding plane once, not once per intermediate best-path change. The count
    /// lives behind a shared `Arc` so the test can read it after the FIB moves onto
    /// its worker thread.
    struct CountingFib {
        inner: MemoryFib,
        installs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Fib for CountingFib {
        fn remove_owned(&mut self, route: &Route) -> Result<(), wren_core::FibError> {
            self.inner.remove_owned(route)
        }
        fn apply(&mut self, change: &FibChange) -> Result<(), wren_core::FibError> {
            if matches!(change, FibChange::Install(_)) {
                self.installs
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            self.inner.apply(change)
        }

        fn owned_routes(&mut self) -> Result<Vec<Route>, wren_core::FibError> {
            self.inner.owned_routes()
        }
    }

    #[tokio::test]
    async fn coalescing_collapses_a_prefix_burst_into_one_fib_write() {
        // Three announces for the same prefix, each strictly better (lower metric):
        // driven one at a time this is three FIB installs; coalesced as run() does,
        // it is a single install of the final best path (M7).
        let mut rib = Rib::new();
        let installs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fib = crate::fib::spawn(Box::new(CountingFib {
            inner: MemoryFib::default(),
            installs: installs.clone(),
        }));
        let mut exported = BTreeMap::new();
        let mut subs = Vec::new();
        let mut failed = BTreeSet::new();
        let imports = ImportFilters::new();

        // Fold the whole burst into the RIB first, keeping the net change per prefix.
        let mut coalesced: BTreeMap<(u32, Prefix), FibChange> = BTreeMap::new();
        for metric in [30, 20, 10] {
            if let Some(change) = ingest(
                &mut rib,
                RouteUpdate::Announce(bgp_route("203.0.113.0/24", metric)),
                &imports,
            ) {
                coalesced.insert(fib_key(&change), change);
            }
        }
        // Each better metric changed the best path, so the RIB produced three changes…
        // …but they collapse onto one prefix key.
        assert_eq!(coalesced.len(), 1, "one prefix → one coalesced change");
        for (_k, change) in coalesced {
            program_fib(&fib, change, None, &mut exported, &mut subs, &mut failed).await;
        }
        assert_eq!(
            installs.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the burst became a single FIB write"
        );
        let key = (wren_core::RT_TABLE_MAIN, "203.0.113.0/24".parse().unwrap());
        let installed = fib.owned_routes().await.unwrap();
        assert_eq!(
            installed
                .iter()
                .find(|r| (r.table, r.prefix) == key)
                .unwrap()
                .metric,
            10,
            "final best path installed"
        );
    }
}
