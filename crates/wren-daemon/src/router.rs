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

use tokio::sync::mpsc;
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

/// A request to reload the router's static routes from a freshly-read configuration
/// (the SIGHUP hot-reload path). Carries the complete new desired static-route set;
/// the router diffs it against the set it currently holds and applies only the delta
/// — installing added routes, removing deleted ones, replacing changed ones —
/// through the same RIB/FIB pipeline as a live protocol update (so a new route is
/// programmed and streamed to `monitor routes` subscribers). Dynamically-learned
/// routes are never touched, and no protocol engine is involved, so every session
/// and adjacency stays up across a reload.
#[derive(Debug)]
pub struct ReloadRoutes {
    /// The complete set of static routes the new configuration defines, already run
    /// through any per-VRF import route-map by the caller (as at startup).
    pub statics: Vec<Route>,
}

/// A request to swap the router's live filter set from a freshly-read configuration
/// (the SIGHUP hot-reload path). Carries the complete new import filters (per-protocol,
/// applied as a route enters the RIB) and FIB export filter (RIB → kernel). The router
/// replaces its working set wholesale; the change takes effect on the next route update
/// each affects — no session or adjacency is disturbed. Withdrawing an already-installed
/// route when a stricter export filter now rejects it is handled the next time that
/// prefix changes; the periodic reconcile does not re-run export policy on its own.
#[derive(Debug)]
pub struct FilterReload {
    /// The new per-protocol import filters (replaces the running set wholesale).
    pub imports: ImportFilters,
    /// The new FIB export filter, or `None` to clear it.
    pub fib_export: Option<Filter>,
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
    mut reloads: mpsc::Receiver<ReloadRoutes>,
    mut filter_reloads: mpsc::Receiver<FilterReload>,
) {
    // Own working copies of the filter set so a SIGHUP hot-reload can swap them live
    // (`filter_reloads` arm below). Seeded from the startup filters the caller resolved.
    let mut imports = imports.clone();
    let mut fib_export = fib_export.cloned();
    // The best-path routes we have actually programmed into the FIB, keyed by
    // (vrf, prefix). Doubles as the route-export snapshot source, and lets the
    // export filter's accept→reject transition withdraw a previously-installed
    // route.
    let mut exported: BTreeMap<(u32, Prefix), Route> = BTreeMap::new();
    // The static routes the running configuration defines, keyed by (vrf, prefix) —
    // the baseline a SIGHUP reload diffs against. `main` seeds (installs) these into
    // the FIB directly before this loop starts, so record them in `exported` too:
    // they are in the forwarding plane, so a new `monitor routes` subscriber should
    // see them in its snapshot, and a reload that removes one must be able to find
    // and withdraw it.
    let mut current_statics: BTreeMap<(u32, Prefix), Route> = BTreeMap::new();
    for route in statics {
        let key = (route.table, route.prefix);
        current_statics.insert(key, route.clone());
        exported.entry(key).or_insert_with(|| route.clone());
    }
    // Prefixes whose last FIB write (install or remove) errored — retried on the
    // periodic reconcile tick below until they succeed (review finding M8).
    let mut failed: BTreeSet<(u32, Prefix)> = BTreeSet::new();
    // Open route-export subscriptions (`wren monitor routes`); each receives live
    // RouteEvents. Closed ones are pruned lazily on the next fan-out.
    let mut subscribers: Vec<mpsc::Sender<RouteEvent>> = Vec::new();
    // Periodic FIB reconciliation. The first `tick()` completes immediately, so
    // consume it up front — there is nothing to reconcile before the loop runs.
    let mut reconcile = tokio::time::interval(FIB_RECONCILE_INTERVAL);
    reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reconcile.tick().await;
    loop {
        tokio::select! {
            update = updates.recv() => match update {
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
                    for (_key, change) in coalesced {
                        let event = redist_event(&change);
                        program_fib(fib, change, fib_export.as_ref(), &mut exported, &mut subscribers, &mut failed).await;
                        redistribute(redist, &event).await;
                    }
                }
                None => break, // every protocol sender dropped — shut the router down
            },
            Some(req) = queries.recv() => {
                let _ = req.respond.send(answer_query(rib, vrfs, &req.query));
            }
            Some(sub) = subscribes.recv() => {
                subscribe_routes(&exported, &mut subscribers, sub).await;
            }
            Some(reload) = reloads.recv() => {
                reload_statics(
                    rib, fib, fib_export.as_ref(), &mut exported, &mut subscribers,
                    &mut failed, &mut current_statics, reload.statics,
                ).await;
            }
            Some(fr) = filter_reloads.recv() => {
                // Swap the live filter set (SIGHUP hot-reload). Re-evaluated on the next
                // route update each filter affects; running sessions are untouched. Report
                // the per-protocol delta (added / removed / changed import filters) so an
                // operator sees exactly what the reload changed.
                let old_named: BTreeMap<&str, &Filter> =
                    imports.iter().map(|(p, f)| (p.name(), f)).collect();
                let new_named: BTreeMap<&str, &Filter> =
                    fr.imports.iter().map(|(p, f)| (p.name(), f)).collect();
                let delta = crate::reload::diff_keyed(&old_named, &new_named);
                imports = fr.imports;
                fib_export = fr.fib_export;
                if delta.is_empty() {
                    info!(fib_export = fib_export.is_some(), "route filters reloaded (import set unchanged)");
                } else {
                    info!(
                        added = ?delta.added,
                        removed = ?delta.removed,
                        changed = ?delta.changed,
                        fib_export = fib_export.is_some(),
                        "route filters reloaded",
                    );
                }
            }
            _ = reconcile.tick() => {
                retry_failed(rib, fib, fib_export.as_ref(), &mut exported, &mut subscribers, &mut failed).await;
            }
        }
    }
}

/// Re-apply the desired forwarding state for every prefix whose last FIB write
/// failed. The desired state is re-derived from the RIB (the single source of
/// truth): a prefix that still has a best path is re-installed; one whose best path
/// has since disappeared is removed. A write that succeeds this time clears the
/// prefix from `failed` (via [`program_fib`]); one that fails again stays queued for
/// the next tick. Called only from the reconcile tick, so a healthy router with no
/// outstanding failures does no work here.
async fn retry_failed(
    rib: &Rib,
    fib: &FibHandle,
    fib_export: Option<&Filter>,
    exported: &mut BTreeMap<(u32, Prefix), Route>,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    failed: &mut BTreeSet<(u32, Prefix)>,
) {
    if failed.is_empty() {
        return;
    }
    // Snapshot the queue: program_fib mutates `failed` as each retry resolves.
    let pending: Vec<(u32, Prefix)> = failed.iter().copied().collect();
    debug!(count = pending.len(), "retrying failed FIB writes");
    for (table, prefix) in pending {
        let change = match rib.best_in(table, &prefix) {
            Some(route) => FibChange::Install(route.clone()),
            None => FibChange::Remove { table, prefix },
        };
        program_fib(fib, change, fib_export, exported, subscribers, failed).await;
    }
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
        if sub.events.send(RouteEvent::Update(route.clone())).await.is_err() {
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
    // Index the new desired set by (table, prefix). A duplicate prefix in the config
    // keeps the last, matching how the RIB's single (Static, source=0) candidate per
    // prefix behaves.
    let mut next: BTreeMap<(u32, Prefix), Route> = BTreeMap::new();
    for route in new_statics {
        next.insert((route.table, route.prefix), route);
    }

    // Removed: present in the old set, absent from the new one — withdraw the static
    // candidate. If another protocol still has a route to that prefix, the RIB's
    // best-path simply changes to it (program_fib installs it); otherwise the prefix
    // is removed from the FIB.
    let removed: Vec<(u32, Prefix, u64)> = current
        .iter()
        .filter(|(key, _)| !next.contains_key(key))
        .map(|((table, prefix), route)| (*table, *prefix, route.source))
        .collect();
    let removed_count = removed.len();
    for (table, prefix, source) in removed {
        if let Some(change) = rib.withdraw(table, prefix, Protocol::Static, source) {
            program_fib(fib, change, fib_export, exported, subscribers, failed).await;
        }
    }

    // Added or changed: absent from the old set, or defined differently — offer to
    // the RIB. An unchanged route is skipped so its RIB entry (and any FIB state) is
    // left exactly as it is.
    let mut changed_count = 0usize;
    for (key, route) in &next {
        if current.get(key) == Some(route) {
            continue;
        }
        changed_count += 1;
        if let Some(change) = rib.update(route.clone()) {
            program_fib(fib, change, fib_export, exported, subscribers, failed).await;
        }
    }

    *current = next;
    info!(
        added_or_changed = changed_count,
        removed = removed_count,
        total = current.len(),
        "static routes reloaded",
    );
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
    let _ = writeln!(out, "{:<16} {:>8} {:<20} {:>6}", "vrf", "table", "rd", "routes");
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
/// (which drive one update at a time); [`run`] uses [`ingest`] + [`program_fib`]
/// directly so it can coalesce a burst.
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
    program_fib(fib, change, fib_export, exported, subscribers, failed).await;
    Some(event)
}

/// Carry the best-path change into the forwarding plane: program a new/changed
/// best route (subject to the FIB export filter and the connected-route special
/// case) or remove a withdrawn one.
async fn program_fib(
    fib: &FibHandle,
    change: FibChange,
    fib_export: Option<&Filter>,
    exported: &mut BTreeMap<(u32, Prefix), Route>,
    subscribers: &mut Vec<mpsc::Sender<RouteEvent>>,
    failed: &mut BTreeSet<(u32, Prefix)>,
) {
    match change {
        FibChange::Install(route) => {
            // Directly-connected networks are created in the kernel FIB by the
            // interface configuration itself; track them in the RIB but never
            // reprogram them, which would fight the kernel. They are likewise not
            // route-exported (the consumer owns its own interface routes).
            if route.protocol == Protocol::Connected {
                info!(prefix = %route.prefix, "connected route (kernel-owned; tracked, not reinstalled)");
                return;
            }
            // Run the route through the FIB export filter, if one is configured.
            let route = match fib_export {
                Some(filter) => match filter.apply(&route) {
                    Decision::Accept(r) => r,
                    Decision::Reject => {
                        debug!(prefix = %route.prefix, "route rejected by FIB export filter");
                        // If we had programmed this (vrf, prefix), withdraw it now —
                        // from the FIB and from every route-export subscriber.
                        if exported.remove(&(route.table, route.prefix)).is_some() {
                            remove_from_fib(fib, route.table, route.prefix, failed).await;
                            fanout(
                                subscribers,
                                RouteEvent::Withdraw { table: route.table, prefix: route.prefix },
                            );
                        }
                        return;
                    }
                },
                None => route,
            };
            let key = (route.table, route.prefix);
            match fib.apply(FibChange::Install(route.clone())).await {
                Ok(()) => {
                    exported.insert(key, route.clone());
                    failed.remove(&key); // a retried write that finally landed
                    info!(
                        prefix = %route.prefix,
                        table = route.table,
                        protocol = route.protocol.name(),
                        metric = route.metric,
                        "route installed",
                    );
                    // Mirror the install to the route-export stream.
                    fanout(subscribers, RouteEvent::Update(route));
                }
                Err(e) => {
                    // A failed install (e.g. transient ENOBUFS) is queued for the
                    // periodic reconcile tick to retry, rather than silently lost.
                    warn!(error = %e, prefix = %route.prefix, "FIB install failed; queued for retry");
                    failed.insert(key);
                }
            }
        }
        FibChange::Remove { table, prefix } => {
            let was_exported = exported.remove(&(table, prefix)).is_some();
            // Skip prefixes we never programmed (e.g. export-rejected ones), so we
            // don't issue spurious kernel deletes or export withdrawals.
            if fib_export.is_some() && !was_exported {
                failed.remove(&(table, prefix));
                return;
            }
            remove_from_fib(fib, table, prefix, failed).await;
            if was_exported {
                fanout(subscribers, RouteEvent::Withdraw { table, prefix });
            }
        }
    }
}

/// Remove `(table, prefix)` from the forwarding plane, logging the outcome. A
/// transient failure is queued in `failed` for the reconcile tick to retry; a
/// success clears any prior queued failure for the prefix.
async fn remove_from_fib(
    fib: &FibHandle,
    table: u32,
    prefix: Prefix,
    failed: &mut BTreeSet<(u32, Prefix)>,
) {
    match fib.apply(FibChange::Remove { table, prefix }).await {
        Ok(()) => {
            info!(%prefix, table, "route removed");
            failed.remove(&(table, prefix));
        }
        Err(e) => {
            warn!(error = %e, %prefix, table, "FIB remove failed; queued for retry");
            failed.insert((table, prefix));
        }
    }
}

/// Run `route` through its protocol's import filter, if one is configured. With no
/// filter for the protocol the route is accepted unchanged.
fn apply_import(imports: &ImportFilters, route: Route) -> Decision {
    match imports.get(&route.protocol) {
        Some(filter) => filter.apply(&route),
        None => Decision::Accept(route),
    }
}

/// Reconcile leftover routes at startup: remove every forwarding-plane route this
/// daemon owns (read back via [`Fib::owned_routes`]) whose prefix the current
/// configuration does **not** program, so a restarted daemon never leaves a stale
/// route behind. `keep` is the set of prefixes the daemon installs up front (its
/// static routes); dynamic protocols re-install theirs as they reconverge. Returns
/// the number of routes removed.
pub async fn reconcile_owned(
    fib: &FibHandle,
    owned: Vec<Route>,
    keep: &HashSet<(u32, Prefix)>,
) -> usize {
    let mut removed = 0;
    for route in owned {
        if keep.contains(&(route.table, route.prefix)) {
            continue;
        }
        match fib.apply(FibChange::Remove { table: route.table, prefix: route.prefix }).await {
            Ok(()) => {
                info!(
                    prefix = %route.prefix,
                    protocol = route.protocol.name(),
                    "removed stale route left by a previous instance",
                );
                removed += 1;
            }
            Err(e) => warn!(error = %e, prefix = %route.prefix, "removing stale route"),
        }
    }
    removed
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
    async fn reconcile_removes_stale_owned_routes_but_keeps_current_ones() {
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

        let owned = fib.owned_routes().await.unwrap();
        let keep: HashSet<(u32, Prefix)> =
            [(wren_core::RT_TABLE_MAIN, still_wanted)].into_iter().collect();
        let removed = reconcile_owned(&fib, owned, &keep).await;

        assert_eq!(removed, 1);
        let remaining = fib.owned_routes().await.unwrap();
        assert!(remaining.iter().any(|r| r.table == wren_core::RT_TABLE_MAIN && r.prefix == still_wanted));
        assert!(!remaining.iter().any(|r| r.table == wren_core::RT_TABLE_MAIN && r.prefix == stale));
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
        let sources: HashSet<Protocol> = [Protocol::Static, Protocol::Connected].into_iter().collect();
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
        assert!(matches!(rx.try_recv().unwrap(), Redistribution::Withdraw(_)));

        // A prefix going away withdraws everywhere.
        redistribute(&targets, &RedistEvent::Gone("10.0.0.0/24".parse().unwrap())).await;
        assert!(matches!(rx.try_recv().unwrap(), Redistribution::Withdraw(_)));
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
        assert!(matches!(rx.try_recv().unwrap(), Redistribution::Withdraw(_)));

        redistribute(&targets, &RedistEvent::Changed(static_route("8.8.8.0/24"))).await;
        assert!(matches!(rx.try_recv().unwrap(), Redistribution::Announce(_)));
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
        let (_rtx, rrx) = mpsc::channel::<ReloadRoutes>(16);
        let (_frtx, frrx) = mpsc::channel::<FilterReload>(16);

        // `run` borrows a `&mut Rib` for its whole lifetime, so it can't be
        // `tokio::spawn`ed (production runs it in `select!`, not spawned). Drive it
        // and the test interactions concurrently on one task with `join!` instead.
        // The FIB lives on its own worker thread behind the handle; the loop ends
        // when the driver drops every update sender.
        let router = async move {
            let mut rib = Rib::new();
            let fib = crate::fib::spawn(Box::new(MemoryFib::default()));
            let imports = ImportFilters::new();
            run(&mut rib, &fib, urx, &imports, None, &[], &[], qrx, srx, &[], rrx, frrx).await;
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
        fib.apply(FibChange::Install(learned.clone())).await.unwrap();
        exported.insert((learned.table, learned.prefix), learned.clone());
        let old_static = static_route("10.0.0.0/24");
        rib.update(old_static.clone());
        fib.apply(FibChange::Install(old_static.clone())).await.unwrap();
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
    }

    impl Fib for FlakyFib {
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
        assert!(fib.owned_routes().await.unwrap().is_empty(), "install should have failed");
        assert!(failed.contains(&key), "failed prefix must be queued for retry");

        // The reconcile tick re-derives the desired state from the RIB and, now that
        // the kernel error has cleared, installs the route and clears the queue.
        retry_failed(&rib, &fib, None, &mut exported, &mut subs, &mut failed).await;
        assert!(
            fib.owned_routes().await.unwrap().iter().any(|r| (r.table, r.prefix) == key),
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
        assert!(failed.is_empty(), "vanished prefix must leave the retry queue");
        assert!(fib.owned_routes().await.unwrap().is_empty());
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
        fn apply(&mut self, change: &FibChange) -> Result<(), wren_core::FibError> {
            if matches!(change, FibChange::Install(_)) {
                self.installs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            if let Some(change) = ingest(&mut rib, RouteUpdate::Announce(bgp_route("203.0.113.0/24", metric)), &imports) {
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
            installed.iter().find(|r| (r.table, r.prefix) == key).unwrap().metric,
            10,
            "final best path installed"
        );
    }
}
