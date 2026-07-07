//! # Full-configuration hot-reload (SIGHUP)
//!
//! Wren re-reads its configuration file on `SIGHUP` and applies the delta to the
//! running daemon *without* a restart. The router already reconciles static routes
//! and route filters live, and the BGP engine reconciles its neighbour set live
//! (see `router::reload_statics`, `router::FilterReload` and `bgp::BgpReconfig`).
//! This module generalises the same idea to the dynamic protocol engines
//! (OSPF/OSPFv3, RIP/RIPng, Babel, IS-IS) and VRRP, which cannot be reconfigured
//! mid-session as cheaply: for those a change is applied by cleanly **stopping and
//! restarting just that engine's task**, leaving every other engine untouched.
//!
//! ## What reconciles live vs restarts-per-engine
//!
//! | Config area              | On SIGHUP                                         |
//! |--------------------------|--------------------------------------------------|
//! | `[[static]]`             | live delta into the RIB/FIB (no engine involved) |
//! | `[[filter]]`/`[import]`  | live filter-set swap in the router               |
//! | BGP `[[neighbor]]`       | live add/remove of neighbours (session preserved)|
//! | OSPF/OSPFv3/RIP/RIPng/…  | **task restart** of that one engine              |
//! | VRRP `[[vrrp]]`          | **task restart** of the VRRP engine              |
//!
//! A restarted engine drops and re-forms its adjacencies (its routes are re-learned
//! as it reconverges); no other engine, session or the daemon process is disturbed.
//!
//! ## Limits of a restarted engine (deferred)
//!
//! An engine the [`Supervisor`] (re)starts on SIGHUP runs with a fresh set of
//! internal channels, so two things a startup-spawned engine has are *not* rewired:
//! its `show <proto>` control-socket route (queries reach only the generation that
//! was spawned at startup) and its `redistribute` registration (a hot-started engine
//! advertises no redistributed routes until the next full restart). BFD for a
//! hot-started protocol likewise assumes BFD was enabled at startup. These are
//! documented deferrals, not silent failures — each is logged when it applies.

use std::any::Any;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// One managed engine's *reload signature*: the parts of its configuration a SIGHUP
/// compares to decide whether the engine must be (re)started. Restricted to what the
/// hot-reload actually acts on — whether the protocol is enabled, and its interface
/// set — so an unrelated edit elsewhere in the file does not needlessly bounce an
/// adjacency. `ifaces` is normalised (sorted, deduplicated) so it compares
/// order-independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sig {
    /// Whether the protocol is enabled in this configuration.
    pub enabled: bool,
    /// The engine's interface set (for VRRP, `"iface/vrid"` keys), normalised.
    pub ifaces: Vec<String>,
}

impl Sig {
    /// Build a signature from an enabled flag and an interface-name iterator,
    /// normalising the set so it compares order-independently.
    pub fn new<I, S>(enabled: bool, ifaces: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut v: Vec<String> = ifaces.into_iter().map(Into::into).collect();
        v.sort();
        v.dedup();
        Sig { enabled, ifaces: v }
    }
}

/// The action a SIGHUP implies for one managed engine, from its previously-running
/// signature (`None` = not running) and the freshly-read one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// No change — leave the engine exactly as it is.
    None,
    /// The protocol became enabled — start it.
    Start,
    /// The protocol became disabled — stop it.
    Stop,
    /// The protocol stayed enabled but its interface set changed — restart it.
    Restart,
}

/// Decide what a SIGHUP must do to one engine: compare the running signature (if any)
/// against the newly-read one. A disabled engine is represented by `running = None`.
pub fn plan_action(running: Option<&Sig>, new: &Sig) -> Action {
    match (running.is_some(), new.enabled) {
        (false, false) => Action::None,
        (false, true) => Action::Start,
        (true, false) => Action::Stop,
        (true, true) => {
            if running == Some(new) {
                Action::None
            } else {
                Action::Restart
            }
        }
    }
}

/// The add/remove/change breakdown of a keyed configuration diff, used for the
/// human-readable reload log lines (and unit-tested against the router's own static
/// and filter reconcilers).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Delta {
    /// Keys present only in the new configuration.
    pub added: Vec<String>,
    /// Keys present only in the old configuration.
    pub removed: Vec<String>,
    /// Keys in both whose value changed.
    pub changed: Vec<String>,
}

impl Delta {
    /// Whether nothing changed at all (all three lists empty).
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Diff two keyed sets into an add/remove/change [`Delta`]. The keys are rendered
/// with `Display` (sorted, so the result is deterministic); values are compared with
/// `PartialEq` to detect an in-place change. This is the shape both the static-route
/// reload (keyed by prefix) and the filter reload (keyed by protocol) take.
pub fn diff_keyed<K, V>(
    old: &std::collections::BTreeMap<K, V>,
    new: &std::collections::BTreeMap<K, V>,
) -> Delta
where
    K: Ord + std::fmt::Display,
    V: PartialEq,
{
    let mut d = Delta::default();
    for (k, v) in new {
        match old.get(k) {
            None => d.added.push(k.to_string()),
            Some(old_v) if old_v != v => d.changed.push(k.to_string()),
            Some(_) => {}
        }
    }
    for k in old.keys() {
        if !new.contains_key(k) {
            d.removed.push(k.to_string());
        }
    }
    d.added.sort();
    d.removed.sort();
    d.changed.sort();
    d
}

/// A sender end of a restarted engine's channel, parked so the channel stays open for
/// the engine's lifetime (a closed control/redist channel would otherwise leave a
/// `select!` arm permanently disabled). Boxed as `Any` because engines differ in their
/// channel value types; the box is only ever held, never downcast.
pub type Parked = Box<dyn Any + Send>;

/// What a respawn closure returns after spawning a fresh engine generation: its task
/// handle and the parked sender ends that keep its fresh channels open.
pub struct SpawnOut {
    /// The spawned engine task.
    pub join: JoinHandle<()>,
    /// Sender ends kept alive for the generation's lifetime.
    pub parked: Vec<Parked>,
}

/// Builds and spawns one fresh generation of an engine from a freshly-read config and
/// a per-engine stop signal. Returns `None` when the protocol is disabled in that
/// config or its configuration failed to resolve (already logged). Defined per
/// protocol in `main` so it can capture that engine's clonable wiring
/// (`updates_tx`, the BFD register/notify senders, the backend, …).
pub type Respawn =
    Box<dyn FnMut(&wren_config::Config, watch::Receiver<bool>) -> Option<SpawnOut> + Send>;

/// Computes an engine's reload signature from a configuration. Defined per protocol in
/// `main` alongside its [`Respawn`].
pub type SigOf = Box<dyn Fn(&wren_config::Config) -> Sig + Send>;

/// One supervised engine's live state within the [`Supervisor`].
struct Slot {
    /// Human name for logs (`"ospf"`, `"vrrp"`, …).
    name: &'static str,
    /// The signature of the running generation, or `None` when the engine is stopped.
    running: Option<Sig>,
    /// Stop signal for the running generation (flip to `true` to end it).
    stop: Option<watch::Sender<bool>>,
    /// Task handle of a generation *this supervisor* spawned (a reload restart). The
    /// startup generation's handle lives in `main`'s `proto_handles` instead, so it is
    /// awaited within the graceful-shutdown window; a reload-spawned generation is
    /// detached and stopped via its `stop` signal on shutdown.
    join: Option<JoinHandle<()>>,
    /// Parked sender ends keeping the running generation's fresh channels open.
    parked: Vec<Parked>,
    /// How to read this engine's signature from a config.
    sig_of: SigOf,
    /// How to (re)spawn this engine from a config.
    respawn: Respawn,
}

/// Supervises the dynamic protocol engines across configuration hot-reloads. Holds a
/// per-engine stop signal and a respawn closure; on [`apply`](Supervisor::apply) it
/// diffs each engine's signature and starts / stops / restarts only the ones that
/// changed, leaving the rest — and every BGP session and static route — untouched.
pub struct Supervisor {
    slots: Vec<Slot>,
    /// The daemon-wide shutdown signal. Each spawned generation gets a per-engine stop
    /// that a small relay flips when this fires, so an engine still emits its protocol
    /// goodbye on Ctrl-C exactly as a startup-spawned one does.
    global: watch::Sender<bool>,
}

impl Supervisor {
    /// Create an empty supervisor tied to the daemon-wide shutdown signal.
    pub fn new(global: watch::Sender<bool>) -> Self {
        Supervisor {
            slots: Vec::new(),
            global,
        }
    }

    fn slot_mut(&mut self, name: &str) -> Option<&mut Slot> {
        self.slots.iter_mut().find(|s| s.name == name)
    }

    /// Register a managed engine's reload behaviour. Called once per protocol at
    /// startup (before the reload loop), whether or not the protocol is enabled, so a
    /// protocol that is off at startup can still be started by a later SIGHUP. If the
    /// engine was already spawned at startup, attach the closures to that live slot via
    /// [`mark_started`](Supervisor::mark_started) first; otherwise this creates a
    /// stopped slot.
    pub fn register(&mut self, name: &'static str, sig_of: SigOf, respawn: Respawn) {
        if let Some(slot) = self.slot_mut(name) {
            slot.sig_of = sig_of;
            slot.respawn = respawn;
        } else {
            self.slots.push(Slot {
                name,
                running: None,
                stop: None,
                join: None,
                parked: Vec::new(),
                sig_of,
                respawn,
            });
        }
    }

    /// Record that a startup-spawned engine is running under `sig`, returning the stop
    /// receiver `main` must hand that engine in place of a direct `shutdown` subscribe.
    /// The returned receiver flips when either the daemon shuts down (relayed here) or a
    /// SIGHUP stops/restarts this engine. The startup generation's `JoinHandle` stays in
    /// `main`'s `proto_handles` for the graceful-shutdown window.
    pub fn mark_started(&mut self, name: &'static str, sig: Sig) -> watch::Receiver<bool> {
        let (stop_tx, stop_rx) = watch::channel(false);
        spawn_shutdown_relay(&self.global, stop_tx.clone());
        if let Some(slot) = self.slot_mut(name) {
            slot.running = Some(sig);
            slot.stop = Some(stop_tx);
        } else {
            // Registered later; park the state in a placeholder slot.
            self.slots.push(Slot {
                name,
                running: Some(sig),
                stop: Some(stop_tx),
                join: None,
                parked: Vec::new(),
                sig_of: Box::new(|_| Sig::new(false, Vec::<String>::new())),
                respawn: Box::new(|_, _| None),
            });
        }
        stop_rx
    }

    /// Apply a freshly-read configuration to every managed engine: start newly-enabled
    /// ones, stop newly-disabled ones, and restart ones whose interface set changed.
    /// Non-blocking — it only signals and spawns; a restarted engine reconverges on its
    /// own. Unaffected engines are left completely untouched.
    pub fn apply(&mut self, cfg: &wren_config::Config) {
        // `global` is cloned out so each slot can be borrowed mutably in the loop while
        // the relay helper still reads the daemon shutdown signal.
        let global = self.global.clone();
        for slot in &mut self.slots {
            let new_sig = (slot.sig_of)(cfg);
            match plan_action(slot.running.as_ref(), &new_sig) {
                Action::None => {}
                Action::Stop => {
                    stop_slot(slot);
                    info!(protocol = slot.name, "stopped (removed from configuration)");
                }
                Action::Start => {
                    if spawn_generation(&global, slot, cfg) {
                        slot.running = Some(new_sig);
                        info!(protocol = slot.name, "started (task spawn)");
                    }
                }
                Action::Restart => {
                    stop_slot(slot);
                    if spawn_generation(&global, slot, cfg) {
                        slot.running = Some(new_sig);
                        info!(protocol = slot.name, "reloaded (task restart)");
                    }
                }
            }
        }
    }

    /// Await every reload-spawned generation's task within the graceful-shutdown
    /// deadline (the daemon-wide shutdown signal has already been flipped, so each has
    /// been asked to stop). Startup generations are awaited by `main` via
    /// `proto_handles`; this covers the ones the supervisor spawned on a later SIGHUP.
    pub async fn join_all(&mut self, deadline: tokio::time::Instant) {
        for slot in &mut self.slots {
            if let Some(join) = slot.join.take() {
                let _ = tokio::time::timeout_at(deadline, join).await;
            }
        }
    }
}

/// Flip a slot's running generation off: signal its stop, drop (detach) its task handle
/// and its parked channels. The task ends on its own once it observes the stop.
fn stop_slot(slot: &mut Slot) {
    if let Some(stop) = slot.stop.take() {
        let _ = stop.send(true);
    }
    slot.join = None;
    slot.parked.clear();
    slot.running = None;
}

/// Spawn a fresh generation for a slot: mint a per-engine stop, relay the daemon
/// shutdown into it, and call the slot's respawn closure. Returns whether a generation
/// actually started (the closure returns `None` when the protocol is disabled or its
/// config failed to resolve — already logged).
fn spawn_generation(global: &watch::Sender<bool>, slot: &mut Slot, cfg: &wren_config::Config) -> bool {
    let (stop_tx, stop_rx) = watch::channel(false);
    spawn_shutdown_relay(global, stop_tx.clone());
    match (slot.respawn)(cfg, stop_rx) {
        Some(out) => {
            slot.stop = Some(stop_tx);
            slot.join = Some(out.join);
            slot.parked = out.parked;
            true
        }
        None => {
            warn!(protocol = slot.name, "not (re)started; keeping it stopped");
            false
        }
    }
}

/// Spawn a tiny task that flips `engine_stop` to `true` when the daemon-wide shutdown
/// signal fires, so an engine watching a per-engine stop still emits its protocol
/// goodbye on Ctrl-C. Ends once shutdown fires (or the engine's stop is dropped).
fn spawn_shutdown_relay(global: &watch::Sender<bool>, engine_stop: watch::Sender<bool>) {
    let mut g = global.subscribe();
    tokio::spawn(async move {
        while g.changed().await.is_ok() {
            if *g.borrow() {
                let _ = engine_stop.send(true);
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // --- protocol enable/disable/restart planning -------------------------------

    #[test]
    fn plan_action_starts_a_newly_enabled_protocol() {
        let new = Sig::new(true, ["veth0"]);
        assert_eq!(plan_action(None, &new), Action::Start);
    }

    #[test]
    fn plan_action_stops_a_newly_disabled_protocol() {
        // The engine was running on veth0; the new config disables it entirely.
        let running = Sig::new(true, ["veth0"]);
        let new = Sig::new(false, Vec::<String>::new());
        assert_eq!(plan_action(Some(&running), &new), Action::Stop);
    }

    #[test]
    fn plan_action_restarts_on_interface_set_change() {
        let running = Sig::new(true, ["veth0"]);
        let new = Sig::new(true, ["veth0", "veth1"]);
        assert_eq!(plan_action(Some(&running), &new), Action::Restart);
    }

    #[test]
    fn plan_action_is_a_noop_when_nothing_changed() {
        // Same enabled state and interface set (order-independent) — no bounce.
        let running = Sig::new(true, ["veth1", "veth0"]);
        let new = Sig::new(true, ["veth0", "veth1"]);
        assert_eq!(plan_action(Some(&running), &new), Action::None);
        // And a protocol that was and stays disabled.
        let off = Sig::new(false, Vec::<String>::new());
        assert_eq!(plan_action(None, &off), Action::None);
    }

    // --- static-route reload delta ---------------------------------------------

    #[test]
    fn static_delta_reports_added_removed_and_changed_prefixes() {
        // Old set: two statics. New set: one unchanged, one with a changed next hop,
        // one dropped, one added. `diff_keyed` must classify each exactly once.
        let mut old: BTreeMap<String, String> = BTreeMap::new();
        old.insert("10.0.0.0/24".into(), "via 10.0.0.1".into());
        old.insert("10.0.1.0/24".into(), "via 10.0.0.1".into());
        old.insert("10.0.2.0/24".into(), "via 10.0.0.1".into());

        let mut new: BTreeMap<String, String> = BTreeMap::new();
        new.insert("10.0.0.0/24".into(), "via 10.0.0.1".into()); // unchanged
        new.insert("10.0.1.0/24".into(), "via 10.0.0.2".into()); // changed next hop
        new.insert("10.0.3.0/24".into(), "via 10.0.0.1".into()); // added
        // 10.0.2.0/24 removed

        let d = diff_keyed(&old, &new);
        assert_eq!(d.added, vec!["10.0.3.0/24".to_string()]);
        assert_eq!(d.removed, vec!["10.0.2.0/24".to_string()]);
        assert_eq!(d.changed, vec!["10.0.1.0/24".to_string()]);
        assert!(!d.is_empty());
    }

    #[test]
    fn static_delta_is_empty_for_an_identical_set() {
        let mut m: BTreeMap<String, String> = BTreeMap::new();
        m.insert("192.168.0.0/24".into(), "via 10.0.0.9".into());
        assert!(diff_keyed(&m, &m).is_empty());
    }

    // --- filter reload delta ----------------------------------------------------

    #[test]
    fn filter_delta_reports_changed_and_added_protocol_filters() {
        use wren_filter::Filter;
        // Model the router's per-protocol import filters keyed by protocol name (as
        // `filter_delta` does in `main`). A flipped default action for BGP is a
        // "changed"; a brand-new OSPF filter is "added".
        let mut old: BTreeMap<String, Filter> = BTreeMap::new();
        old.insert("bgp".into(), Filter::accept_all());
        let mut new: BTreeMap<String, Filter> = BTreeMap::new();
        new.insert("bgp".into(), Filter::reject_all()); // changed default action
        new.insert("ospf".into(), Filter::accept_all()); // added

        let d = diff_keyed(&old, &new);
        assert_eq!(d.added, vec!["ospf".to_string()]);
        assert!(d.removed.is_empty());
        assert_eq!(d.changed, vec!["bgp".to_string()]);
    }
}
