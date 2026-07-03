//! Off-runtime forwarding-plane worker (review C7).
//!
//! [`wren_core::Fib`] is a synchronous trait, and the kernel backend
//! ([`wren_netlink::KernelFib`]) implements it with blocking `sendto`/`recv`
//! netlink syscalls (plus short retry sleeps on `ENOBUFS`). Calling that
//! directly from the router's async task blocks a tokio worker thread for the
//! duration of every route install — starving every *other* async task on that
//! worker (BGP/OSPF/… sessions, the control socket, BMP) until the syscall
//! returns. A bounded `SO_RCVTIMEO` turned an unbounded hang into a recoverable
//! error, but the blocking remained.
//!
//! This module moves the whole `Fib` onto a dedicated OS thread and hands the
//! router an **async** [`FibHandle`]. The router `await`s each write; while it
//! waits, the tokio runtime is free to drive every other task. Netlink I/O never
//! runs on — and never stalls — the async runtime again.

use std::sync::mpsc;
use std::thread;

use tokio::sync::oneshot;
use wren_core::{Fib, FibChange, FibError, Route};

/// One unit of work for the FIB thread, carrying a one-shot channel for its reply.
enum FibJob {
    Apply(FibChange, oneshot::Sender<Result<(), FibError>>),
    OwnedRoutes(oneshot::Sender<Result<Vec<Route>, FibError>>),
}

/// An async handle to a [`Fib`] running on its own OS thread. Cheap to clone
/// (both startup and the router loop hold one); the worker thread lives until the
/// last handle is dropped.
#[derive(Clone)]
pub struct FibHandle {
    tx: mpsc::Sender<FibJob>,
}

/// The worker thread stopped (it only stops if it panicked, which it should not).
fn worker_gone() -> FibError {
    FibError("FIB worker thread is not running".to_string())
}

impl FibHandle {
    /// Apply one forwarding-plane change, awaiting the worker's result. Changes
    /// are applied in call order — the worker processes its queue sequentially —
    /// so an install and a later remove of the same prefix never reorder.
    pub async fn apply(&self, change: FibChange) -> Result<(), FibError> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(FibJob::Apply(change, reply)).map_err(|_| worker_gone())?;
        rx.await.unwrap_or_else(|_| Err(worker_gone()))
    }

    /// Read back the routes this daemon owns in the forwarding plane (startup
    /// reconciliation).
    pub async fn owned_routes(&self) -> Result<Vec<Route>, FibError> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(FibJob::OwnedRoutes(reply)).map_err(|_| worker_gone())?;
        rx.await.unwrap_or_else(|_| Err(worker_gone()))
    }
}

/// Move `fib` onto a dedicated OS thread and return an async handle to it.
pub fn spawn(mut fib: Box<dyn Fib + Send>) -> FibHandle {
    let (tx, rx) = mpsc::channel::<FibJob>();
    thread::Builder::new()
        .name("wren-fib".to_string())
        .spawn(move || {
            // Blocking netlink I/O lives here, on its own thread — off the async
            // runtime. The loop ends when the last `FibHandle` (and thus the last
            // sender) is dropped.
            while let Ok(job) = rx.recv() {
                match job {
                    FibJob::Apply(change, reply) => {
                        let _ = reply.send(fib.apply(&change));
                    }
                    FibJob::OwnedRoutes(reply) => {
                        let _ = reply.send(fib.owned_routes());
                    }
                }
            }
        })
        .expect("spawning the FIB worker thread");
    FibHandle { tx }
}
