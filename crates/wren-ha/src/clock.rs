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
//! Before it initiates, a new owner compares its clock with the previous
//! owner's, which the agent replicates over the authenticated HA state stream
//! and dates by its own CLOCK_BOOTTIME on receipt. It steps its clock forward
//! to the peer's, never backward, and only within narrow bounds: the wall
//! clock also drives TLS validity, one-time passwords, log timestamps and
//! update freshness, so a step is logged with both times, refused beyond
//! [`MAX_STEP_NS`], and refused when this member's clock is NTP-synchronised
//! and the peer's is not. A refusal promotes anyway and says so.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};

/// A lag below this is left alone: it is within handshake timing noise.
pub const STEP_THRESHOLD_NS: u64 = 100_000_000;
/// The largest step taken (10 min). Beyond it the clock is wrong for a reason
/// a peer's reading must not paper over; NTP has to correct it.
pub const MAX_STEP_NS: u64 = 600_000_000_000;
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
    if behind_ns > MAX_STEP_NS {
        return Decision::Refuse {
            behind_ns,
            reason: "the lag exceeds the 10 min step limit",
        };
    }
    Decision::Step { behind_ns }
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
    fn the_local_clock_reads_are_plausible() {
        assert!(wall_ns().unwrap() > 1_577_836_800 * S);
        let _ = synchronised();
    }
}
