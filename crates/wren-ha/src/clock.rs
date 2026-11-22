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
//! else, reads the replicated clock itself and runs [`align`]. Wren sends
//! nothing, so the most a compromised Wren can trigger is a step these rules
//! allow.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The helper's socket (systemd socket activation, one instance per request).
pub const SOCKET: &str = "/run/velstra-ha-clock.sock";
/// The agent's replicated WireGuard snapshot, with `peer_clock`.
pub const SNAPSHOT: &str = "/run/velstra/ha/wireguard.json";
/// The last decision, for `sentinel show health`.
pub const STATUS: &str = "/run/velstra/ha/clock.json";

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

/// One decision as recorded in [`STATUS`] and returned to Wren.
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
        }
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

/// The replicated peer clock in the agent's snapshot. Only `peer_clock` is
/// read; the rest of the snapshot is Wren's business.
pub fn read_peer_clock(path: &Path) -> Result<Option<PeerClock>> {
    #[derive(Deserialize)]
    struct Snapshot {
        #[serde(default)]
        peer_clock: Option<PeerClock>,
    }
    Ok(crate::read_private::<Snapshot>(path)?.peer_clock)
}

/// Decide from the replicated clock at `snapshot` and act: step when the rules
/// allow it, and record the decision at `status`. Never fails: whatever goes
/// wrong is part of the returned status.
pub fn align(snapshot: &Path, status: &Path) -> Status {
    let local_synchronised = synchronised();
    let decision = match (read_peer_clock(snapshot), wall_ns()) {
        (Ok(peer), Ok(wall)) => decide(peer, wall, crate::now_ns(), local_synchronised),
        (Err(_), _) => Decision::Unknown {
            reason: "the replicated peer clock cannot be read",
        },
        (_, Err(_)) => Decision::Unknown {
            reason: "the wall clock cannot be read",
        },
    };
    let mut result = Status::of(decision, local_synchronised);
    if let Decision::Step { behind_ns } = decision {
        match step_forward(behind_ns) {
            Ok(times) => result.stepped = Some(times),
            Err(error) => result.error = Some(format!("{error:#}")),
        }
    }
    if let Err(error) = crate::write_private(status, &result, false) {
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

    #[test]
    fn align_reads_the_agents_snapshot_and_records_unknown_when_it_is_missing() {
        let dir = std::env::temp_dir().join(format!("wren-clock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // write_private refuses a group- or world-writable directory.
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let status_path = dir.join("clock.json");
        let status = align(&dir.join("absent.json"), &status_path);
        assert_eq!(status.action, "unknown");
        assert_eq!(
            status.reason.as_deref(),
            Some("the replicated peer clock cannot be read")
        );
        let recorded: Status = crate::read_private(&status_path).unwrap();
        assert_eq!(recorded, status);
        // A snapshot without a peer clock (a cold baseline) is also unknown.
        let snapshot = dir.join("wireguard.json");
        crate::write_private(
            &snapshot,
            &serde_json::json!({"cluster": "c", "endpoints": []}),
            false,
        )
        .unwrap();
        assert_eq!(read_peer_clock(&snapshot).unwrap(), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_local_clock_reads_are_plausible() {
        assert!(wall_ns().unwrap() > 1_577_836_800 * S);
        let _ = synchronised();
    }
}
