//! `wren-ha-clock-step`: the one process allowed to step this member's wall
//! clock for an HA WireGuard takeover (see `wren_ha::clock`).
//!
//! It runs from boot with the listening socket `wren_ha::clock::SOCKET` that
//! systemd passes it (socket activation, `Accept=no`), and serves one
//! connection at a time. A request carries nothing. For each one the helper
//! reads the predecessor's clock that the agent published outside the
//! caller's view, then applies `wren_ha::clock::decide` and the per-boot
//! budget under its lock. It steps when both allow it, records the decision,
//! and answers with it as one JSON document. A caller can trigger a decision
//! on the agent's reading; it can neither supply the reading nor exceed the
//! budget.
//!
//! It stays running rather than being started per request: starting a
//! sandboxed instance cost 0.2-0.4 s, which every WireGuard takeover paid
//! before its first handshake.
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

/// systemd's first passed descriptor (`SD_LISTEN_FDS_START`).
const LISTEN_FD: i32 = 3;
/// A caller that stops reading cannot hold up the next takeover.
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// The listening socket systemd passed, refusing anything else.
fn passed_listener() -> anyhow::Result<UnixListener> {
    let ours = std::env::var("LISTEN_PID")?.parse::<u32>()? == std::process::id();
    let one = std::env::var("LISTEN_FDS")?.parse::<u32>()? == 1;
    anyhow::ensure!(ours && one, "expected exactly one socket from systemd");
    // SAFETY: systemd passed exactly this descriptor to this process, and
    // nothing else in the process owns it.
    Ok(unsafe { UnixListener::from_raw_fd(LISTEN_FD) })
}

fn serve(mut stream: UnixStream) {
    let status = wren_ha::clock::align(
        &wren_ha::clock::Paths::default(),
        &wren_ha::clock::SystemClocks,
    );
    if let Some(message) = status.message() {
        // stderr is this unit's journal.
        eprintln!("{message}");
    }
    let reply = match status.to_json() {
        Ok(reply) => reply,
        Err(error) => {
            eprintln!("encoding the clock decision failed: {error:#}");
            return;
        }
    };
    // The decision is taken and recorded either way. A caller that went away
    // first (a takeover cancelled by a newer one) is only worth a line.
    let sent = stream
        .set_write_timeout(Some(REPLY_TIMEOUT))
        .and_then(|()| stream.write_all(&reply))
        .and_then(|()| stream.flush());
    if let Err(error) = sent {
        eprintln!("the clock-step caller left before the answer: {error}");
    }
}

fn main() -> std::process::ExitCode {
    let listener = match passed_listener() {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("wren-ha-clock-step runs only socket-activated: {error:#}");
            return std::process::ExitCode::FAILURE;
        }
    };
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => serve(stream),
            Err(error) => eprintln!("accepting a clock-step request failed: {error}"),
        }
    }
    std::process::ExitCode::SUCCESS
}
