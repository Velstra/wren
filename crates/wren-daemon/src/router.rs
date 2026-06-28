//! # The central router loop
//!
//! Wren's equivalent of FRR's *zebra*: a single owner of the [`Rib`] and the
//! forwarding plane. Protocol engines never touch the RIB directly — they run in
//! their own tasks and send [`RouteUpdate`]s down a channel, and this loop is the
//! only place that calls [`Rib::update`]/[`Rib::withdraw`] and drains the
//! resulting [`FibChange`]s into the [`Fib`]. That keeps best-path selection and
//! FIB programming single-threaded and serialized, however many protocols feed it.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use wren_core::{Fib, FibChange, Prefix, Protocol, Rib, Route};
use wren_filter::{Decision, Filter};

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
}

/// A [`Query`] paired with the channel to deliver its rendered answer on.
#[derive(Debug)]
pub struct QueryRequest {
    /// What is being asked.
    pub query: Query,
    /// Where to send the rendered text answer.
    pub respond: oneshot::Sender<String>,
}

/// Run the router until the update channel closes (every sender dropped).
///
/// Borrows the `rib` and `fib` so the caller can keep them (e.g. to race this
/// against a shutdown signal in `tokio::select!`). Besides protocol `updates`, the
/// loop also answers read-only `queries` from the control socket out of the RIB it
/// owns — keeping best-path, FIB programming and `show` all single-threaded.
pub async fn run(
    rib: &mut Rib,
    fib: &mut dyn Fib,
    mut updates: mpsc::Receiver<RouteUpdate>,
    imports: &ImportFilters,
    fib_export: Option<&Filter>,
    redist: &[RedistTarget],
    mut queries: mpsc::Receiver<QueryRequest>,
) {
    // The prefixes we have actually programmed into the FIB, so the export filter's
    // accept→reject transition can withdraw a previously-installed route.
    let mut programmed: HashSet<Prefix> = HashSet::new();
    loop {
        tokio::select! {
            update = updates.recv() => match update {
                Some(update) => {
                    // Apply the update to the RIB/FIB; if the best path changed,
                    // fan that change out to the redistribution targets.
                    if let Some(event) = apply(rib, fib, update, imports, fib_export, &mut programmed) {
                        redistribute(redist, &event).await;
                    }
                }
                None => break, // every protocol sender dropped — shut the router down
            },
            Some(req) = queries.recv() => {
                let _ = req.respond.send(answer_query(rib, &req.query));
            }
        }
    }
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
fn answer_query(rib: &Rib, query: &Query) -> String {
    match query {
        Query::Routes { protocol } => render_routes(rib, *protocol),
    }
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
fn apply(
    rib: &mut Rib,
    fib: &mut dyn Fib,
    update: RouteUpdate,
    imports: &ImportFilters,
    fib_export: Option<&Filter>,
    programmed: &mut HashSet<Prefix>,
) -> Option<RedistEvent> {
    let change = match update {
        RouteUpdate::Announce(route) => {
            let (prefix, protocol, source) = (route.prefix, route.protocol, route.source);
            match apply_import(imports, route) {
                Decision::Accept(route) => rib.update(route),
                Decision::Reject => {
                    debug!(%prefix, protocol = protocol.name(), "route rejected by import filter");
                    rib.withdraw(prefix, protocol, source)
                }
            }
        }
        RouteUpdate::Withdraw {
            prefix,
            protocol,
            source,
        } => rib.withdraw(prefix, protocol, source),
    };

    let change = change?; // the installed best route did not change

    // Capture the best-path change for redistribution before the FIB side of the
    // story (connected routes and export-rejected routes are still redistributed,
    // even though they are not programmed into the kernel here).
    let event = match &change {
        FibChange::Install(route) => RedistEvent::Changed(route.clone()),
        FibChange::Remove(prefix) => RedistEvent::Gone(*prefix),
    };
    program_fib(fib, change, fib_export, programmed);
    Some(event)
}

/// Carry the best-path change into the forwarding plane: program a new/changed
/// best route (subject to the FIB export filter and the connected-route special
/// case) or remove a withdrawn one.
fn program_fib(
    fib: &mut dyn Fib,
    change: FibChange,
    fib_export: Option<&Filter>,
    programmed: &mut HashSet<Prefix>,
) {
    match change {
        FibChange::Install(route) => {
            // Directly-connected networks are created in the kernel FIB by the
            // interface configuration itself; track them in the RIB but never
            // reprogram them, which would fight the kernel.
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
                        // If we had programmed this prefix, withdraw it now.
                        if programmed.remove(&route.prefix) {
                            remove_from_fib(fib, route.prefix);
                        }
                        return;
                    }
                },
                None => route,
            };
            match fib.apply(&FibChange::Install(route.clone())) {
                Ok(()) => {
                    programmed.insert(route.prefix);
                    info!(
                        prefix = %route.prefix,
                        protocol = route.protocol.name(),
                        metric = route.metric,
                        "route installed",
                    );
                }
                Err(e) => warn!(error = %e, "applying FIB change"),
            }
        }
        FibChange::Remove(prefix) => {
            // Skip prefixes we never programmed (e.g. export-rejected ones), so we
            // don't issue spurious kernel deletes.
            if fib_export.is_some() && !programmed.contains(&prefix) {
                return;
            }
            programmed.remove(&prefix);
            remove_from_fib(fib, prefix);
        }
    }
}

/// Remove `prefix` from the forwarding plane, logging the outcome.
fn remove_from_fib(fib: &mut dyn Fib, prefix: Prefix) {
    match fib.apply(&FibChange::Remove(prefix)) {
        Ok(()) => info!(%prefix, "route removed"),
        Err(e) => warn!(error = %e, "applying FIB change"),
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
pub fn reconcile_owned(fib: &mut dyn Fib, owned: Vec<Route>, keep: &HashSet<Prefix>) -> usize {
    let mut removed = 0;
    for route in owned {
        if keep.contains(&route.prefix) {
            continue;
        }
        match fib.apply(&FibChange::Remove(route.prefix)) {
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
    use wren_core::{MemoryFib, NextHop};
    use wren_filter::{Action, Match, Modify, PrefixList, Rule};

    /// A small harness: a RIB + MemoryFib + import/export filters + programmed set.
    struct Harness {
        rib: Rib,
        fib: MemoryFib,
        imports: ImportFilters,
        export: Option<Filter>,
        programmed: HashSet<Prefix>,
    }

    impl Harness {
        fn new() -> Self {
            Harness {
                rib: Rib::new(),
                fib: MemoryFib::default(),
                imports: ImportFilters::new(),
                export: None,
                programmed: HashSet::new(),
            }
        }

        fn feed(&mut self, update: RouteUpdate) {
            apply(
                &mut self.rib,
                &mut self.fib,
                update,
                &self.imports,
                self.export.as_ref(),
                &mut self.programmed,
            );
        }

        fn announce(&mut self, route: Route) {
            self.feed(RouteUpdate::Announce(route));
        }

        fn installed(&self, prefix: &str) -> Option<&Route> {
            self.fib.installed.get(&prefix.parse().unwrap())
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

    #[test]
    fn import_filter_rejects_drops_and_accepts_installs_modified() {
        let mut h = Harness::new();
        h.imports.insert(Protocol::Bgp, rfc1918_then_tag());

        // A martian is rejected: nothing reaches the RIB/FIB.
        h.announce(bgp_route("10.1.0.0/16", 1));
        assert!(h.rib.best(&"10.1.0.0/16".parse().unwrap()).is_none());
        assert!(h.fib.installed.is_empty());

        // A public route is accepted and installed with the modified metric.
        h.announce(bgp_route("8.8.8.0/24", 1));
        let best = h
            .rib
            .best(&"8.8.8.0/24".parse().unwrap())
            .expect("installed");
        assert_eq!(best.metric, 101); // 1 + add-metric 100
        assert_eq!(h.installed("8.8.8.0/24").unwrap().metric, 101);
    }

    #[test]
    fn reannouncing_a_now_rejected_route_withdraws_the_prior_one() {
        let mut h = Harness::new();
        // Start with an accept-all filter so the route installs.
        h.imports.insert(Protocol::Bgp, Filter::accept_all());
        h.announce(bgp_route("203.0.113.0/24", 5));
        assert!(h.rib.best(&"203.0.113.0/24".parse().unwrap()).is_some());

        // Now a stricter filter rejects it: re-announcing must withdraw the prior.
        h.imports.insert(Protocol::Bgp, Filter::reject_all());
        h.announce(bgp_route("203.0.113.0/24", 5));
        assert!(h.rib.best(&"203.0.113.0/24".parse().unwrap()).is_none());
    }

    #[test]
    fn export_filter_gates_fib_but_not_the_rib() {
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
        h.announce(bgp_route("10.9.0.0/16", 1));
        assert!(h.rib.best(&"10.9.0.0/16".parse().unwrap()).is_some());
        assert!(h.installed("10.9.0.0/16").is_none());

        // A public route: programmed.
        h.announce(bgp_route("8.8.8.0/24", 1));
        assert!(h.installed("8.8.8.0/24").is_some());
    }

    #[test]
    fn export_filter_modifies_the_programmed_route() {
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
        h.announce(bgp_route("8.8.8.0/24", 1));
        // The RIB keeps the original metric; the FIB carries the rewritten one.
        assert_eq!(
            h.rib.best(&"8.8.8.0/24".parse().unwrap()).unwrap().metric,
            1
        );
        assert_eq!(h.installed("8.8.8.0/24").unwrap().metric, 500);
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

    #[test]
    fn reconcile_removes_stale_owned_routes_but_keeps_current_ones() {
        let mut fib = MemoryFib::default();
        // A previous instance left two routes: a static we still want, and a RIP
        // route the current config no longer covers.
        let still_wanted = "10.0.0.0/24".parse::<Prefix>().unwrap();
        let stale = "10.9.0.0/16".parse::<Prefix>().unwrap();
        fib.apply(&FibChange::Install(Route::new(
            still_wanted,
            Protocol::Static,
            vec![NextHop::via("192.0.2.1".parse().unwrap())],
            0,
        )))
        .unwrap();
        fib.apply(&FibChange::Install(Route::new(
            stale,
            Protocol::Rip,
            vec![NextHop::via("192.0.2.2".parse().unwrap())],
            5,
        )))
        .unwrap();

        let owned = fib.owned_routes().unwrap();
        let keep: HashSet<Prefix> = [still_wanted].into_iter().collect();
        let removed = reconcile_owned(&mut fib, owned, &keep);

        assert_eq!(removed, 1);
        assert!(fib.installed.contains_key(&still_wanted));
        assert!(!fib.installed.contains_key(&stale));
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

    #[test]
    fn best_path_changing_to_a_rejected_route_withdraws_from_the_fib() {
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
        h.announce(bgp_route("8.8.8.0/24", 1));
        assert!(h.installed("8.8.8.0/24").is_some());

        // The same source re-announces with a now-rejected metric: the best path
        // changes, export rejects it, and the prior FIB entry is withdrawn.
        h.announce(bgp_route("8.8.8.0/24", 200));
        assert!(h.rib.best(&"8.8.8.0/24".parse().unwrap()).is_some());
        assert!(h.installed("8.8.8.0/24").is_none());
    }
}
