//! Keep a WireGuard successor's wall clock from lagging its predecessor's.
//!
//! Both members of a pair present one WireGuard identity, so a remote peer
//! keeps one handshake replay floor for the pair: the newest TAI64N timestamp
//! it has accepted, which the kernel takes from the initiator's
//! CLOCK_REALTIME. A member whose wall clock lags the previous owner's (a VM
//! that was paused or suspended: its clock stopped with it) sends handshake
//! initiations the peer silently drops as replays. WireGuard retries every
//! REKEY_TIMEOUT (5 s) and succeeds only once the lagging clock passes the
//! floor, so tunnels stall for the lag, rounded up to 5 s. Measured in
//! checks.ha-wireguard-failover: an 8.9 s lag after an 8 s pause, stalls of
//! 6 s to beyond 15 s.
//!
//! A new owner holds its VIPs, and its agent forwards for the new term. Then,
//! before it reconfigures WireGuard and initiates, it compares its clock with
//! the previous owner's. The agent replicates that clock over the
//! authenticated HA state stream and dates it by its own CLOCK_BOOTTIME on
//! receipt. The member steps its clock forward to the peer's, never backward,
//! and only within narrow bounds, because the wall clock also drives TLS
//! validity, one-time passwords, log timestamps and update freshness:
//! - every step is logged with both times;
//! - a step is refused beyond [`MAX_STEP_NS`];
//! - beyond [`MAX_SYNCED_STEP_NS`] when both clocks claim NTP synchronisation;
//! - and whenever this member is synchronised and the peer is not.
//!
//! A refusal promotes anyway and says so.
//!
//! The step itself is not taken by Wren. Wren parses untrusted routing
//! protocols and must not hold CAP_SYS_TIME. It connects to [`SOCKET`], and
//! the `wren-ha-clock-step` helper, which holds that capability and nothing
//! else, runs [`align`]. What Wren can and cannot do through it:
//! - Wren sends nothing. The helper reads the predecessor's clock from
//!   [`PEER`], which the agent publishes in a directory Wren's unit cannot
//!   see, so Wren can neither choose nor forge the reading.
//! - Wren can only trigger a decision on the agent's reading. Requests run
//!   one at a time under a lock, and each re-reads the wall clock under the
//!   lock, so two requests never add the same lag twice.
//! - All steps of a boot together never exceed [`MAX_BOOT_STEP_NS`]. The
//!   helper keeps that budget in [`STATE_DIR`], which Wren also cannot see.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The helper's socket (systemd socket activation, one request at a time).
pub const SOCKET: &str = "/run/velstra-ha-clock.sock";
/// The predecessor's clock as the agent publishes it (velstra
/// `ha::wireguard::publish_clock`), outside Wren's view.
pub const PEER: &str = "/run/velstra/ha-clock/peer.json";
/// The helper's own state: the lock, the per-boot budget and the last
/// decision (read by `sentinel show health`). Outside Wren's view.
pub const STATE_DIR: &str = "/run/velstra-ha-clock-step";
/// All forward steps of one boot together (10 min). /run is per boot.
pub const MAX_BOOT_STEP_NS: u64 = 600_000_000_000;

/// A lag below this is left alone: it is within handshake timing noise.
pub const STEP_THRESHOLD_NS: u64 = 100_000_000;
/// The largest step taken (10 min). Beyond it the clock is wrong for a reason
/// a peer's reading must not paper over; NTP has to correct it.
pub const MAX_STEP_NS: u64 = 600_000_000_000;
/// The largest step when both clocks claim NTP synchronisation (60 s). Two
/// disciplined clocks further apart than that is a fault on one of them, and
/// a peer's "synchronised" is only its own claim; a resumed VM's lag (its
/// kernel still reports synchronised) stays well inside it.
pub const MAX_SYNCED_STEP_NS: u64 = 60_000_000_000;
/// A peer reading older than this (by CLOCK_BOOTTIME) is not used: the owner
/// refreshes it every second, so an older one predates a pause or a broken
/// stream and would carry the same lag as this clock.
pub const MAX_SAMPLE_AGE_NS: u64 = 5_000_000_000;
/// The kernel's ceiling for its admitted clock error, and systemd's threshold
/// for calling a clock synchronised.
const MAX_ERROR_US: libc::c_long = 16_000_000;

/// The previous owner's wall clock as the agent last received it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerClock {
    /// The owner's CLOCK_REALTIME in ns when it sampled it.
    pub wall_ns: u64,
    /// Whether the owner's clock was NTP-disciplined.
    pub synchronised: bool,
    /// This member's CLOCK_BOOTTIME when the sample arrived.
    pub observed_ns: u64,
}

/// What a new owner does about its wall clock before WireGuard promotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Decision {
    /// No usable peer reading; the clock is left alone.
    Unknown { reason: &'static str },
    /// Not behind the peer by more than [`STEP_THRESHOLD_NS`].
    InStep,
    /// Step forward by `behind_ns`.
    Step { behind_ns: u64 },
    /// Behind, but stepping is not safe; promote anyway and warn.
    Refuse {
        behind_ns: u64,
        reason: &'static str,
    },
}

/// Decide from a peer reading and this member's clocks (all in ns).
pub fn decide(
    peer: Option<PeerClock>,
    local_wall_ns: u64,
    local_boot_ns: u64,
    local_synchronised: bool,
) -> Decision {
    let Some(peer) = peer else {
        return Decision::Unknown {
            reason: "no replicated peer clock",
        };
    };
    let Some(age) = local_boot_ns
        .checked_sub(peer.observed_ns)
        .filter(|age| *age <= MAX_SAMPLE_AGE_NS)
    else {
        return Decision::Unknown {
            reason: "the peer clock reading is stale",
        };
    };
    let peer_now = peer.wall_ns.saturating_add(age);
    let behind_ns = peer_now.saturating_sub(local_wall_ns);
    if behind_ns <= STEP_THRESHOLD_NS {
        return Decision::InStep;
    }
    if local_synchronised && !peer.synchronised {
        return Decision::Refuse {
            behind_ns,
            reason: "this member's clock is NTP-synchronised and the peer's is not",
        };
    }
    if local_synchronised && behind_ns > MAX_SYNCED_STEP_NS {
        return Decision::Refuse {
            behind_ns,
            reason: "both clocks are NTP-synchronised and disagree by more than 60 s",
        };
    }
    if behind_ns > MAX_STEP_NS {
        return Decision::Refuse {
            behind_ns,
            reason: "the lag exceeds the 10 min step limit",
        };
    }
    Decision::Step { behind_ns }
}

/// One decision as recorded in the helper's status file and returned to Wren.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// `step`, `in-step`, `refuse` or `unknown`.
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behind_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// CLOCK_REALTIME before and after a step, in ns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stepped: Option<(u64, u64)>,
    /// Why a decided step was not taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether this member's clock was NTP-synchronised when it decided.
    pub local_synchronised: bool,
    /// The latest refusal or failed step that nothing has settled since. A
    /// later unknown decision keeps it; only a step, or an in-step decision on
    /// a fresh reading, clears it. This is what `sentinel show health` reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved: Option<Box<Status>>,
}

impl Status {
    fn of(decision: Decision, local_synchronised: bool) -> Self {
        let (action, behind_ns, reason) = match decision {
            Decision::Unknown { reason } => ("unknown", None, Some(reason)),
            Decision::InStep => ("in-step", None, None),
            Decision::Step { behind_ns } => ("step", Some(behind_ns), None),
            Decision::Refuse { behind_ns, reason } => ("refuse", Some(behind_ns), Some(reason)),
        };
        Self {
            action: action.into(),
            behind_ns,
            reason: reason.map(String::from),
            stepped: None,
            error: None,
            local_synchronised,
            unresolved: None,
        }
    }

    /// Whether this decision left a lag standing (a refusal or a failed step).
    fn leaves_lag(&self) -> bool {
        self.action == "refuse" || (self.action == "step" && self.stepped.is_none())
    }

    /// Carry the outstanding lag forward from the `previous` record.
    fn settle(mut self, previous: Option<Status>) -> Self {
        self.unresolved = if self.leaves_lag() {
            Some(Box::new(Status {
                unresolved: None,
                ..self.clone()
            }))
        } else if self.action == "unknown" {
            previous.and_then(|p| p.unresolved)
        } else {
            None
        };
        self
    }

    /// The helper's reply and record, as JSON.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// The journal line for this decision, or `None` when there is nothing to
    /// say (in step). A step, a refusal, a failed step and an unknown peer
    /// clock are all worth a line on a WireGuard takeover.
    pub fn message(&self) -> Option<String> {
        let behind = self.behind_ns.unwrap_or(0) as f64 / 1e9;
        let reason = self.reason.as_deref().unwrap_or("no reason recorded");
        match (self.action.as_str(), &self.stepped, &self.error) {
            ("step", Some((old, new)), _) => Some(format!(
                "HA takeover: stepped the wall clock forward {behind:.3} s to the previous owner's (from {old} ns to {new} ns) so WireGuard handshakes are not rejected as replays"
            )),
            ("step", _, error) => Some(format!(
                "HA takeover: clock {behind:.3} s behind the previous owner, stepping it failed ({}); WireGuard tunnels may stall until NTP corrects it",
                error.as_deref().unwrap_or("unknown error")
            )),
            ("refuse", _, _) => Some(format!(
                "HA takeover: clock {behind:.3} s behind the previous owner, not stepped: {reason}; WireGuard tunnels may stall until NTP corrects it"
            )),
            ("unknown", _, _) => Some(format!(
                "HA takeover: the previous owner's clock is not known ({reason}); a lagging clock here would stall WireGuard tunnels"
            )),
            _ => None,
        }
    }
}

fn not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// The predecessor's clock as the agent published it; `None` when there is
/// none (the agent removes the file when it has no predecessor's reading).
pub fn read_peer_clock(path: &Path) -> Result<Option<PeerClock>> {
    match crate::read_private::<PeerClock>(path) {
        Ok(clock) => Ok(Some(clock)),
        Err(error) if not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The clocks [`align`] reads and steps; a trait so tests can run it without
/// CAP_SYS_TIME.
pub trait Clocks {
    fn wall_ns(&self) -> Result<u64>;
    fn boot_ns(&self) -> u64;
    fn synchronised(&self) -> bool;
    fn step_forward(&self, behind_ns: u64) -> Result<(u64, u64)>;
}

/// This machine's clocks.
pub struct SystemClocks;
impl Clocks for SystemClocks {
    fn wall_ns(&self) -> Result<u64> {
        wall_ns()
    }
    fn boot_ns(&self) -> u64 {
        crate::now_ns()
    }
    fn synchronised(&self) -> bool {
        synchronised()
    }
    fn step_forward(&self, behind_ns: u64) -> Result<(u64, u64)> {
        step_forward(behind_ns)
    }
}

/// Where [`align`] reads and keeps its state.
pub struct Paths {
    pub peer: PathBuf,
    pub state: PathBuf,
}
impl Default for Paths {
    fn default() -> Self {
        Self {
            peer: PEER.into(),
            state: STATE_DIR.into(),
        }
    }
}
impl Paths {
    pub fn status(&self) -> PathBuf {
        self.state.join("status.json")
    }
    fn budget(&self) -> PathBuf {
        self.state.join("budget.json")
    }
    fn lock(&self) -> PathBuf {
        self.state.join("lock")
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    /// Forward steps taken this boot, in ns.
    spent_ns: u64,
}

/// Hold the helper's lock (flock on a file in its own directory).
fn lock(path: &Path) -> Result<std::fs::File> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    // SAFETY: flock on a descriptor this function owns.
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0,
        "locking the clock-step state failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(file)
}

/// Decide from the agent's published reading and act: step when the rules and
/// the per-boot budget allow it, and record the decision. One request at a
/// time: the decision is taken under the lock, on a wall clock read under it,
/// so a second request sees the first one's step. Never fails: whatever goes
/// wrong is part of the returned status.
pub fn align(paths: &Paths, clocks: &dyn Clocks) -> Status {
    let held = std::fs::create_dir_all(&paths.state)
        .map_err(anyhow::Error::from)
        .and_then(|()| lock(&paths.lock()));
    let _guard = match held {
        Ok(file) => file,
        Err(error) => {
            return Status {
                error: Some(format!("{error:#}")),
                ..Status::of(
                    Decision::Unknown {
                        reason: "the clock-step state is unavailable",
                    },
                    clocks.synchronised(),
                )
            }
        }
    };
    let local_synchronised = clocks.synchronised();
    let decision = match (read_peer_clock(&paths.peer), clocks.wall_ns()) {
        (Ok(peer), Ok(wall)) => decide(peer, wall, clocks.boot_ns(), local_synchronised),
        (Err(_), _) => Decision::Unknown {
            reason: "the replicated peer clock cannot be read",
        },
        (_, Err(_)) => Decision::Unknown {
            reason: "the wall clock cannot be read",
        },
    };
    // A budget that exists but cannot be read counts as spent.
    let budget = match crate::read_private::<Budget>(&paths.budget()) {
        Ok(budget) => Some(budget),
        Err(error) if not_found(&error) => Some(Budget::default()),
        Err(_) => None,
    };
    let decision = match (decision, &budget) {
        (Decision::Step { behind_ns }, Some(b))
            if b.spent_ns.saturating_add(behind_ns) <= MAX_BOOT_STEP_NS =>
        {
            decision
        }
        (Decision::Step { behind_ns }, _) => Decision::Refuse {
            behind_ns,
            reason: "the per-boot step budget (10 min) is spent",
        },
        (other, _) => other,
    };
    let mut result = Status::of(decision, local_synchronised);
    if let Decision::Step { behind_ns } = decision {
        match clocks.step_forward(behind_ns) {
            Ok(times) => {
                result.stepped = Some(times);
                let spent = Budget {
                    spent_ns: budget.map_or(0, |b| b.spent_ns).saturating_add(behind_ns),
                };
                if let Err(error) = crate::write_private(&paths.budget(), &spent, false) {
                    result.error = Some(format!("recording the step budget failed: {error:#}"));
                }
            }
            Err(error) => result.error = Some(format!("{error:#}")),
        }
    }
    let previous = crate::read_private::<Status>(&paths.status()).ok();
    let mut result = result.settle(previous);
    if let Err(error) = crate::write_private(&paths.status(), &result, false) {
        result
            .error
            .get_or_insert(format!("recording the decision failed: {error:#}"));
    }
    result
}
/// This member's CLOCK_REALTIME in ns.
pub fn wall_ns() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes the timespec it is given.
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut time) } == 0,
        "reading the wall clock failed"
    );
    timespec_ns(time)
}

/// Whether the kernel admits an error bound under 16 s (NTP disciplines it).
pub fn synchronised() -> bool {
    // SAFETY: modes = 0 makes adjtimex read-only; the struct is fully owned.
    let mut timex: libc::timex = unsafe { std::mem::zeroed() };
    let state = unsafe { libc::adjtimex(&mut timex) };
    state >= 0 && timex.maxerror < MAX_ERROR_US
}

/// Step CLOCK_REALTIME forward by `behind_ns`, measured from the clock's value
/// now (not when the decision was taken). Returns (old, new) in ns.
pub fn step_forward(behind_ns: u64) -> Result<(u64, u64)> {
    let old = wall_ns()?;
    let new = old
        .checked_add(behind_ns)
        .context("stepped wall clock overflows")?;
    let time = libc::timespec {
        tv_sec: (new / 1_000_000_000) as libc::time_t,
        tv_nsec: (new % 1_000_000_000) as libc::c_long,
    };
    // SAFETY: clock_settime reads the timespec it is given.
    ensure!(
        unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } == 0,
        "stepping the wall clock failed: {}",
        std::io::Error::last_os_error()
    );
    Ok((old, new))
}

fn timespec_ns(time: libc::timespec) -> Result<u64> {
    let seconds = u64::try_from(time.tv_sec).context("wall clock before 1970")?;
    let nanos = u64::try_from(time.tv_nsec).context("invalid wall clock")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(nanos))
        .context("wall clock overflows")
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    fn peer(wall_ns: u64, synchronised: bool, observed_ns: u64) -> Option<PeerClock> {
        Some(PeerClock {
            wall_ns,
            synchronised,
            observed_ns,
        })
    }

    #[test]
    fn a_resumed_member_steps_forward_to_the_peers_clock() {
        // Measured case: the peer read 20.35 s, the resumed member 11.71 s.
        let wall = 1_000 * S + 11_710_000_000;
        let peer_wall = 1_000 * S + 20_350_000_000;
        // The reading arrived 0.5 s ago by this member's CLOCK_BOOTTIME.
        assert_eq!(
            decide(peer(peer_wall, false, 99 * S + S / 2), wall, 100 * S, false),
            Decision::Step {
                behind_ns: 9_140_000_000
            }
        );
    }

    #[test]
    fn a_clock_in_step_or_ahead_is_left_alone() {
        let wall = 1_000 * S;
        assert_eq!(
            decide(
                peer(wall + STEP_THRESHOLD_NS, true, 5 * S),
                wall,
                5 * S,
                true
            ),
            Decision::InStep
        );
        // Never backwards: a member ahead of its peer keeps its clock.
        assert_eq!(
            decide(peer(wall - 30 * S, true, 5 * S), wall, 5 * S, false),
            Decision::InStep
        );
    }

    #[test]
    fn a_synchronised_member_never_follows_an_unsynchronised_peer() {
        let wall = 1_000 * S;
        assert_eq!(
            decide(peer(wall + 9 * S, false, 5 * S), wall, 5 * S, true),
            Decision::Refuse {
                behind_ns: 9 * S,
                reason: "this member's clock is NTP-synchronised and the peer's is not"
            }
        );
        // Both synchronised, or only the peer: the step is taken.
        for local in [true, false] {
            assert_eq!(
                decide(peer(wall + 9 * S, true, 5 * S), wall, 5 * S, local),
                Decision::Step { behind_ns: 9 * S }
            );
        }
    }

    #[test]
    fn two_synchronised_clocks_are_stepped_together_at_most_a_minute() {
        // A synchronised peer's claim is only its own word. Two synchronised
        // clocks a minute or more apart is a fault, not a pause to repair:
        // following it would put the remote peers' replay floor ahead and
        // chrony would step this member back.
        let wall = 1_000_000 * S;
        let both = |behind| decide(peer(wall + behind, true, 5 * S), wall, 5 * S, true);
        // The measured pauses still step: a resumed VM's kernel keeps
        // reporting synchronised for a while.
        assert_eq!(both(9 * S), Decision::Step { behind_ns: 9 * S });
        assert_eq!(
            both(MAX_SYNCED_STEP_NS),
            Decision::Step {
                behind_ns: MAX_SYNCED_STEP_NS
            }
        );
        assert_eq!(
            both(MAX_SYNCED_STEP_NS + 1),
            Decision::Refuse {
                behind_ns: MAX_SYNCED_STEP_NS + 1,
                reason: "both clocks are NTP-synchronised and disagree by more than 60 s"
            }
        );
        assert_eq!(
            both(9 * 60 * S),
            Decision::Refuse {
                behind_ns: 9 * 60 * S,
                reason: "both clocks are NTP-synchronised and disagree by more than 60 s"
            }
        );
        // Without that claim on both sides the 10 min limit applies.
        assert_eq!(
            decide(peer(wall + 9 * 60 * S, true, 5 * S), wall, 5 * S, false),
            Decision::Step {
                behind_ns: 9 * 60 * S
            }
        );
    }

    #[test]
    fn a_lag_beyond_ten_minutes_is_refused_not_stepped() {
        let wall = 1_000_000 * S;
        assert_eq!(
            decide(peer(wall + MAX_STEP_NS, false, 5 * S), wall, 5 * S, false),
            Decision::Step {
                behind_ns: MAX_STEP_NS
            }
        );
        assert_eq!(
            decide(
                peer(wall + MAX_STEP_NS + 1, false, 5 * S),
                wall,
                5 * S,
                false
            ),
            Decision::Refuse {
                behind_ns: MAX_STEP_NS + 1,
                reason: "the lag exceeds the 10 min step limit"
            }
        );
    }

    #[test]
    fn a_missing_stale_or_future_reading_changes_nothing() {
        let wall = 1_000 * S;
        let unknown = |reason| Decision::Unknown { reason };
        assert_eq!(
            decide(None, wall, 5 * S, false),
            unknown("no replicated peer clock")
        );
        // Older than MAX_SAMPLE_AGE_NS: it predates a pause and lags as we do.
        assert_eq!(
            decide(
                peer(wall + 9 * S, false, S),
                wall,
                S + MAX_SAMPLE_AGE_NS + 1,
                false
            ),
            unknown("the peer clock reading is stale")
        );
        // Received "after" now: not a reading of this boot.
        assert_eq!(
            decide(peer(wall + 9 * S, false, 6 * S), wall, 5 * S, false),
            unknown("the peer clock reading is stale")
        );
    }

    #[test]
    fn every_decision_records_its_journal_line_and_the_local_sync_state() {
        let step = Status {
            stepped: Some((1, 2)),
            ..Status::of(Decision::Step { behind_ns: 9 * S }, true)
        };
        assert!(step
            .message()
            .unwrap()
            .contains("stepped the wall clock forward 9.000 s"));
        assert!(step.local_synchronised);
        let failed = Status {
            error: Some("EPERM".into()),
            ..Status::of(Decision::Step { behind_ns: S }, false)
        };
        assert!(failed
            .message()
            .unwrap()
            .contains("stepping it failed (EPERM)"));
        let refused = Status::of(
            Decision::Refuse {
                behind_ns: 61 * S,
                reason: "r",
            },
            true,
        );
        assert!(refused.message().unwrap().contains("not stepped: r"));
        let unknown = Status::of(
            Decision::Unknown {
                reason: "the peer clock reading is stale",
            },
            false,
        );
        assert!(unknown
            .message()
            .unwrap()
            .contains("not known (the peer clock reading is stale)"));
        assert_eq!(Status::of(Decision::InStep, false).message(), None);
        let json = serde_json::to_string(&refused).unwrap();
        assert_eq!(serde_json::from_str::<Status>(&json).unwrap(), refused);
        assert!(
            json.contains(r#""action":"refuse""#) && json.contains(r#""local_synchronised":true"#),
            "{json}"
        );
    }

    /// A clock under test control: the wall clock moves only by its steps
    /// (each read waits `lag`, to widen any race), and every step is counted.
    struct FakeClocks {
        wall: std::sync::Mutex<u64>,
        steps: std::sync::atomic::AtomicUsize,
        boot: u64,
        lag: std::time::Duration,
    }
    impl Clocks for FakeClocks {
        fn wall_ns(&self) -> Result<u64> {
            let wall = *self.wall.lock().unwrap();
            std::thread::sleep(self.lag);
            Ok(wall)
        }
        fn boot_ns(&self) -> u64 {
            self.boot
        }
        fn synchronised(&self) -> bool {
            false
        }
        fn step_forward(&self, behind_ns: u64) -> Result<(u64, u64)> {
            let mut wall = self.wall.lock().unwrap();
            let old = *wall;
            *wall += behind_ns;
            self.steps.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((old, *wall))
        }
    }

    fn fake(wall: u64) -> FakeClocks {
        FakeClocks {
            wall: std::sync::Mutex::new(wall),
            steps: std::sync::atomic::AtomicUsize::new(0),
            boot: 100 * S,
            lag: std::time::Duration::ZERO,
        }
    }

    fn steps(clocks: &FakeClocks) -> usize {
        clocks.steps.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A private directory for one test, holding the agent's reading and the
    /// helper's state the way write_private and read_private require them.
    struct Scratch {
        root: PathBuf,
        paths: Paths,
    }
    impl Scratch {
        fn new(name: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let root =
                std::env::temp_dir().join(format!("wren-clock-{name}-{}", std::process::id()));
            for dir in [root.clone(), root.join("agent"), root.join("state")] {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o700)).unwrap();
            }
            let paths = Paths {
                peer: root.join("agent/peer.json"),
                state: root.join("state"),
            };
            Self { root, paths }
        }
        fn publish(&self, wall_ns: u64, observed_ns: u64) {
            let clock = PeerClock {
                wall_ns,
                synchronised: false,
                observed_ns,
            };
            crate::write_private(&self.paths.peer, &clock, false).unwrap();
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn align_steps_on_the_agents_reading_and_ignores_a_snapshot_wren_can_write() {
        let scratch = Scratch::new("source");
        let clocks = fake(1_000 * S);
        // A peer_clock in Wren's writable /run/velstra/ha/wireguard.json is
        // never read: only the agent's own file counts, and there is none yet.
        crate::write_private(
            &scratch.root.join("wireguard.json"),
            &serde_json::json!({"peer_clock": {"wall_ns": 1_600 * S, "synchronised": true, "observed_ns": 100 * S}}),
            false,
        )
        .unwrap();
        let status = align(&scratch.paths, &clocks);
        assert_eq!(status.action, "unknown", "{status:?}");
        assert_eq!(steps(&clocks), 0);
        // The agent's reading: 9 s ahead, received 0.5 s ago.
        scratch.publish(1_009 * S, 100 * S - S / 2);
        let status = align(&scratch.paths, &clocks);
        assert_eq!(status.action, "step", "{status:?}");
        assert_eq!(status.behind_ns, Some(9 * S + S / 2));
        assert_eq!(*clocks.wall.lock().unwrap(), 1_009 * S + S / 2);
        let recorded: Status = crate::read_private(&scratch.paths.status()).unwrap();
        assert_eq!(recorded, status);
    }

    #[test]
    fn two_concurrent_requests_step_once() {
        let scratch = Scratch::new("concurrent");
        scratch.publish(1_009 * S, 100 * S);
        let clocks = FakeClocks {
            lag: std::time::Duration::from_millis(100),
            ..fake(1_000 * S)
        };
        let statuses: Vec<Status> = std::thread::scope(|scope| {
            let a = scope.spawn(|| align(&scratch.paths, &clocks));
            let b = scope.spawn(|| align(&scratch.paths, &clocks));
            vec![a.join().unwrap(), b.join().unwrap()]
        });
        assert_eq!(steps(&clocks), 1, "{statuses:?}");
        assert_eq!(*clocks.wall.lock().unwrap(), 1_009 * S);
        let mut actions: Vec<_> = statuses.iter().map(|s| s.action.as_str()).collect();
        actions.sort();
        assert_eq!(actions, ["in-step", "step"]);
    }

    #[test]
    fn the_per_boot_budget_refuses_steps_beyond_ten_minutes_in_total() {
        let scratch = Scratch::new("budget");
        let clocks = fake(1_000 * S);
        for round in 0..2u64 {
            let wall = *clocks.wall.lock().unwrap();
            scratch.publish(wall + 5 * 60 * S, 100 * S);
            let status = align(&scratch.paths, &clocks);
            assert_eq!(status.action, "step", "round {round}: {status:?}");
        }
        // 10 min spent: one more second is refused and the clock stays.
        let wall = *clocks.wall.lock().unwrap();
        scratch.publish(wall + S, 100 * S);
        let status = align(&scratch.paths, &clocks);
        assert_eq!(status.action, "refuse", "{status:?}");
        assert_eq!(
            status.reason.as_deref(),
            Some("the per-boot step budget (10 min) is spent")
        );
        assert_eq!(*clocks.wall.lock().unwrap(), wall);
        assert!(status.unresolved.is_some());
        // A budget file that cannot be trusted counts as spent.
        let corrupt = Scratch::new("budget-corrupt");
        crate::write_private(
            &corrupt.paths.state.join("budget.json"),
            &serde_json::json!({"spent": "garbage"}),
            false,
        )
        .unwrap();
        corrupt.publish(1_000 * S + S, 100 * S);
        assert_eq!(align(&corrupt.paths, &fake(1_000 * S)).action, "refuse");
    }

    #[test]
    fn an_unknown_decision_keeps_an_unresolved_refusal_a_fresh_one_clears_it() {
        let scratch = Scratch::new("unresolved");
        let clocks = fake(1_000 * S);
        // 11 min ahead: refused, and left unresolved.
        scratch.publish(1_000 * S + 11 * 60 * S, 100 * S);
        let refused = align(&scratch.paths, &clocks);
        assert_eq!(refused.action, "refuse");
        let outstanding = refused.unresolved.clone().unwrap();
        assert_eq!(
            outstanding.reason.as_deref(),
            Some("the lag exceeds the 10 min step limit")
        );
        // No reading any more: unknown, and the refusal stays recorded.
        std::fs::remove_file(&scratch.paths.peer).unwrap();
        let unknown = align(&scratch.paths, &clocks);
        assert_eq!(unknown.action, "unknown");
        assert_eq!(unknown.unresolved, Some(outstanding));
        let recorded: Status = crate::read_private(&scratch.paths.status()).unwrap();
        assert!(recorded.unresolved.is_some());
        // A fresh reading in step settles it.
        scratch.publish(1_000 * S, 100 * S);
        let settled = align(&scratch.paths, &clocks);
        assert_eq!(settled.action, "in-step");
        assert_eq!(settled.unresolved, None);
    }

    #[test]
    fn the_local_clock_reads_are_plausible() {
        assert!(wall_ns().unwrap() > 1_577_836_800 * S);
        let _ = synchronised();
    }
}
