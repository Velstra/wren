//! `wren-ha-clock-step`: the one process allowed to step this member's wall
//! clock for an HA WireGuard takeover (see `wren_ha::clock`).
//!
//! systemd starts one instance per connection to `wren_ha::clock::SOCKET`
//! (`Accept=yes`), with the connection as stdin and stdout. The request
//! carries nothing: the helper reads the agent's replicated peer clock itself,
//! applies `wren_ha::clock::decide`, steps when the rules allow it, records the
//! decision, answers with it as one JSON document and exits. A caller can
//! therefore trigger at most a step the rules allow, never choose one.
use std::io::Write;
use std::path::Path;

fn main() -> std::process::ExitCode {
    let status = wren_ha::clock::align(
        Path::new(wren_ha::clock::SNAPSHOT),
        Path::new(wren_ha::clock::STATUS),
    );
    if let Some(message) = status.message() {
        // stderr is this unit's journal.
        eprintln!("{message}");
    }
    let reply = match status.to_json() {
        Ok(reply) => reply,
        Err(error) => {
            eprintln!("encoding the clock decision failed: {error:#}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout.write_all(&reply).and_then(|()| stdout.flush()) {
        eprintln!("answering the clock-step request failed: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
