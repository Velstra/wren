//! `wren-ha-clock-step`: the one process allowed to step this member's wall
//! clock for an HA WireGuard takeover (see `wren_ha::clock`).
//!
//! systemd starts one instance per connection to `wren_ha::clock::SOCKET`
//! (`Accept=yes`, one connection at a time), with the connection as stdin and
//! stdout. The request carries nothing. The helper reads the predecessor's
//! clock that the agent published outside the caller's view, then applies
//! `wren_ha::clock::decide` and the per-boot budget under its lock. It steps
//! when both allow it, records the decision, answers with it as one JSON
//! document and exits. A caller can trigger a decision on the agent's
//! reading; it can neither supply the reading nor exceed the budget.
use std::io::Write;

fn main() -> std::process::ExitCode {
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
