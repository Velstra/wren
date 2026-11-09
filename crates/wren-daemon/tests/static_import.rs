//! Real daemon/CLI regression. Only the in-memory FIB is used; no host route or
//! network interface is changed. Tests startup and SIGHUP, not just filter parsing.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Daemon {
    dir: PathBuf,
    child: Option<Child>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn config(allowed: &str, protocol: &str) -> String {
    format!(
        r#"
[import]
static = "admit"
[[filter]]
name = "admit"
default = "reject"
[[filter.rule]]
prefix = ["{allowed}"]
protocol = "{protocol}"
add-metric = 7
action = "accept"
[[static]]
prefix = "198.51.100.1/32"
via = "192.0.2.1"
metric = 10
[[static]]
prefix = "198.51.100.2/32"
via = "192.0.2.1"
metric = 10
"#
    )
}

impl Daemon {
    fn query(&self) -> Option<String> {
        let output = Command::new(env!("CARGO_BIN_EXE_wren"))
            .arg("--socket")
            .arg(self.dir.join("ctl.sock"))
            .args(["show", "routes", "static"])
            .output()
            .expect("query CLI");
        output
            .status
            .success()
            .then(|| String::from_utf8(output.stdout).unwrap())
    }

    fn wait_for(&mut self, present: &[&str], absent: &[&str]) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "daemon exited"
            );
            if let Some(output) = self.query() {
                if present.iter().all(|p| output.contains(p))
                    && absent.iter().all(|p| !output.contains(p))
                {
                    return output;
                }
                assert!(Instant::now() < deadline, "unexpected routes: {output}");
            }
            assert!(Instant::now() < deadline, "daemon did not converge");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn reload(&self, content: &str) {
        fs::write(self.dir.join("wren.toml"), content).unwrap();
        // Only signal our own live child; never discover a daemon by process name.
        let pid = self.child.as_ref().unwrap().id() as libc::pid_t;
        assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    }
}

#[test]
fn static_import_is_enforced_at_startup_and_reconciled_on_reload() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("wren-static-import-{}-{nonce}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let mut daemon = Daemon { dir, child: None };
    fs::write(
        daemon.dir.join("wren.toml"),
        config("198.51.100.1/32", "static"),
    )
    .unwrap();
    daemon.child = Some(
        Command::new(env!("CARGO_BIN_EXE_wren"))
            .arg("--config")
            .arg(daemon.dir.join("wren.toml"))
            .arg("--socket")
            .arg(daemon.dir.join("ctl.sock"))
            .args(["--backend", "memory"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let first = daemon.wait_for(&["198.51.100.1/32"], &["198.51.100.2/32"]);
    // The static definitions do not change: only their admission policy changes.
    daemon.reload(&config("198.51.100.2/32", "static"));
    daemon.wait_for(&["198.51.100.2/32"], &["198.51.100.1/32"]);
    daemon.reload(&config("198.51.100.2/32", "bgp"));
    daemon.wait_for(
        &["no static routes"],
        &["198.51.100.1/32", "198.51.100.2/32"],
    );
    daemon.reload(&config("198.51.100.1/32", "static"));
    let restored = daemon.wait_for(&["198.51.100.1/32"], &["198.51.100.2/32"]);
    assert_eq!(
        restored, first,
        "import transforms must not accumulate on reload"
    );
    daemon.reload(&config("198.51.100.1/32", "static"));
    assert_eq!(
        daemon.wait_for(&["198.51.100.1/32"], &["198.51.100.2/32"]),
        first
    );
}
