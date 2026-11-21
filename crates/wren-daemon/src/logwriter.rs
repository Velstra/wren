//! A log writer that never blocks the task that logs.
//!
//! `tracing_subscriber::fmt` writes every event straight to stdout under the
//! stdout lock. Under systemd that is a pipe to journald, and when journald
//! stops reading (synchronous console forwarding, disk pressure, rate
//! limiting) the write blocks: the logging task stalls, and so does every
//! other task that logs, because they queue on the same lock. The HA lease
//! coordinator renews a 250 ms lease every 25 ms and logs on that path; a
//! stalled journal stopped the renewals and the pair failed over with no
//! fault at all.
//!
//! [`LossyStdout`] hands each formatted line to a bounded queue drained by a
//! dedicated writer thread. A full queue drops the line instead of waiting;
//! the drop is counted ([`dropped`], exported as `wren_log_lines_dropped_total`)
//! and reported on the log itself as soon as the output drains again. Losing
//! log lines while the log is not being read is the right trade: losing the
//! lease is not.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing_subscriber::fmt::MakeWriter;

/// Lines held while the output is blocked before new ones are dropped.
pub const QUEUE_LINES: usize = 4096;

/// Log lines dropped because the output was blocked, since start.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Lines dropped since the daemon started (all writers).
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

struct Shared {
    tx: SyncSender<Vec<u8>>,
    /// Lines queued and not yet written, for [`LossyStdout::flush_for`].
    pending: AtomicUsize,
    /// Drops by this writer; the writer thread reports the ones it has not yet.
    dropped: AtomicU64,
}

/// A [`MakeWriter`] whose writers never block: see the module docs.
#[derive(Clone)]
pub struct LossyStdout {
    shared: Arc<Shared>,
}

impl LossyStdout {
    /// A writer for the process's stdout.
    pub fn stdout() -> Self {
        Self::new(io::stdout(), QUEUE_LINES)
    }

    /// A writer that drains into `out` on its own thread, holding at most
    /// `capacity` lines while `out` blocks.
    pub fn new(out: impl Write + Send + 'static, capacity: usize) -> Self {
        let (tx, rx) = sync_channel(capacity.max(1));
        let shared = Arc::new(Shared {
            tx,
            pending: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
        });
        let drain = Arc::clone(&shared);
        // If the thread cannot be spawned the queue fills and every line is
        // counted as dropped: logging degrades, the daemon does not.
        let _ = std::thread::Builder::new()
            .name("wren-log".into())
            .spawn(move || drain_lines(out, rx, &drain));
        Self { shared }
    }

    /// Wait up to `limit` for the queued lines to be written — at shutdown,
    /// so the last lines are not lost. Returns whether the queue drained.
    pub fn flush_for(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while self.shared.pending.load(Ordering::Acquire) > 0 {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }
}

/// Writes out what is still queued when dropped (bounded by
/// [`SHUTDOWN_FLUSH`]): held for the life of `main`, so the last lines of a
/// shutdown, or of an error exit, are not lost with the queue.
pub struct FlushOnExit(pub LossyStdout);

/// How long a daemon exit waits for queued log lines.
pub const SHUTDOWN_FLUSH: Duration = Duration::from_millis(500);

impl Drop for FlushOnExit {
    fn drop(&mut self) {
        self.0.flush_for(SHUTDOWN_FLUSH);
    }
}

/// The writer thread: write each line, first saying how many were dropped
/// since the last report.
fn drain_lines(mut out: impl Write, rx: Receiver<Vec<u8>>, shared: &Shared) {
    let mut reported = 0u64;
    for line in rx {
        let dropped = shared.dropped.load(Ordering::Relaxed);
        if dropped > reported {
            let _ = writeln!(
                out,
                "wren: {} log line(s) dropped while the log output was blocked",
                dropped - reported
            );
            reported = dropped;
        }
        let _ = out.write_all(&line);
        let _ = out.flush();
        shared.pending.fetch_sub(1, Ordering::Release);
    }
}

impl<'a> MakeWriter<'a> for LossyStdout {
    type Writer = LineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LineWriter {
            shared: Arc::clone(&self.shared),
            line: Vec::new(),
        }
    }
}

/// Collects one formatted event and queues it on drop, so a line is never
/// split between events.
pub struct LineWriter {
    shared: Arc<Shared>,
    line: Vec<u8>,
}

impl Write for LineWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.line.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        if self.line.is_empty() {
            return;
        }
        self.shared.pending.fetch_add(1, Ordering::AcqRel);
        match self.shared.tx.try_send(std::mem::take(&mut self.line)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.shared.pending.fetch_sub(1, Ordering::AcqRel);
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Output that blocks every write for `stall` — a journal that has
    /// stopped reading — and records what it eventually receives.
    struct Stalled {
        stall: Duration,
        seen: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Stalled {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::thread::sleep(self.stall);
            self.seen.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn stalled(stall: Duration) -> (Stalled, Arc<Mutex<Vec<u8>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        (
            Stalled {
                stall,
                seen: Arc::clone(&seen),
            },
            seen,
        )
    }

    /// A lease-renewal loop that logs on every 25 ms tick keeps its cadence
    /// while the log output is stalled: the largest gap between renewals
    /// stays far inside the 250 ms lease. With logging written straight to
    /// the stalled output every tick waited out the stall.
    #[test]
    fn renewals_keep_their_cadence_while_the_log_output_is_stalled() {
        let (out, _) = stalled(Duration::from_secs(2));
        let writer = LossyStdout::new(out, 64);
        let subscriber = tracing_subscriber::fmt().with_writer(writer).finish();
        tracing::subscriber::with_default(subscriber, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let worst = runtime.block_on(async {
                let mut tick = tokio::time::interval(Duration::from_millis(25));
                let mut last = Instant::now();
                let mut worst = Duration::ZERO;
                for renewal in 0..40 {
                    tick.tick().await;
                    let now = Instant::now();
                    worst = worst.max(now - last);
                    last = now;
                    // More than one line per tick, as a busy daemon logs.
                    for _ in 0..10 {
                        tracing::info!(renewal, "HA lease renewed");
                    }
                }
                worst
            });
            assert!(
                worst < Duration::from_millis(100),
                "renewal gap {worst:?} under a stalled log"
            );
        });
        assert!(dropped() > 0, "a stalled output must drop and count lines");
    }

    /// Lines dropped while the output was blocked are reported on the output
    /// once it drains, and every line queued before is written whole.
    #[test]
    fn dropped_lines_are_reported_when_the_output_drains() {
        let (out, seen) = stalled(Duration::from_millis(50));
        let writer = LossyStdout::new(out, 2);
        for i in 0..20 {
            let mut line = writer.make_writer();
            writeln!(line, "line {i}").unwrap();
        }
        let mut last = writer.make_writer();
        writeln!(last, "after the stall").unwrap();
        drop(last);
        assert!(writer.flush_for(Duration::from_secs(10)));
        let text = String::from_utf8(seen.lock().unwrap().clone()).unwrap();
        assert!(text.contains("line 0\n"), "{text}");
        assert!(
            text.contains("log line(s) dropped while the log output was blocked"),
            "{text}"
        );
        assert!(text
            .lines()
            .all(|l| l.starts_with("line ") || l.starts_with("wren: ") || l == "after the stall"));
    }

    /// An event written in several pieces reaches the output as one line.
    #[test]
    fn one_event_is_queued_as_one_line() {
        let (out, seen) = stalled(Duration::ZERO);
        let writer = LossyStdout::new(out, 8);
        {
            let mut line = writer.make_writer();
            line.write_all(b"part one, ").unwrap();
            line.write_all(b"part two\n").unwrap();
        }
        assert!(writer.flush_for(Duration::from_secs(5)));
        assert_eq!(seen.lock().unwrap().as_slice(), b"part one, part two\n");
    }
}
