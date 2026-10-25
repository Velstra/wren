//! A single durable witness serializes forwarding authority. Leases expire on
//! CLOCK_BOOTTIME, including suspend; dataplanes must enforce the corresponding
//! absolute local deadline in the kernel. Authentication does not encrypt metadata.
pub mod wireguard;
use anyhow::{ensure, Context, Result};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    time::timeout,
};

pub const ROLE_PATH: &str = "/run/velstra/ha/role.json";
pub const AGENT_PATH: &str = "/run/velstra/ha/agent.json";
pub const TTL_MS: u64 = 250;
pub const MARGIN_MS: u64 = 20;
pub const FRESH_NS: u64 = 100_000_000;
const LIMIT: usize = 4096;
const IO: Duration = Duration::from_millis(80);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub cluster: String,
    pub node: u8,
    pub witness: SocketAddr,
    pub secret: String,
    pub priority: u8,
    #[serde(default)]
    pub preempt: bool,
    #[serde(default)]
    pub wireguard: Vec<String>,
    #[serde(default)]
    pub wireguard_policy: String,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!((1..=2).contains(&self.node), "HA node must be 1 or 2");
        ensure!(
            (16..=128).contains(&self.cluster.len())
                && self
                    .cluster
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "HA cluster must be 16..128 letters, digits or hyphens"
        );
        ensure!(
            self.secret.len() >= 32 && self.secret.len() <= 1024,
            "HA credential must contain 32..1024 bytes"
        );
        ensure!(
            self.priority > 0 && !self.witness.ip().is_unspecified() && self.witness.port() > 0,
            "invalid HA priority/witness"
        );
        ensure!(
            self.wireguard.len() <= 128
                && self.wireguard.iter().all(|n| !n.is_empty()
                    && n.len() < 16
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))),
            "invalid HA WireGuard interfaces"
        );
        ensure!(
            self.wireguard.is_empty()
                || self.wireguard_policy.len() == 64
                    && self.wireguard_policy.bytes().all(|b| b.is_ascii_hexdigit()),
            "HA WireGuard requires a SHA-256 desired-policy digest"
        );
        Ok(())
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessConfig {
    pub cluster: String,
    pub secret: String,
    pub listen: SocketAddr,
    pub state: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub term: u64,
    pub owner: u8,
    pub boot: [u8; 16],
    pub policy: [u8; 32],
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub cluster: String,
    pub node: u8,
    pub boot: [u8; 16],
    pub priority: u8,
    pub preempt: bool,
    pub ready_term: u64,
    pub policy: [u8; 32],
    pub eligible: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub authority: Authority,
    pub remaining_ms: u64,
    pub granted: bool,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub cluster: String,
    pub node: u8,
    pub coordinator_boot: [u8; 16],
    pub authority: Authority,
    pub deadline_ns: u64,
    pub updated_ns: u64,
    pub vips_ready: bool,
    pub vpn_ready: bool,
    /// The ready generation used in the claim, never inferred from a stale role.
    pub claimed_ready_term: u64,
    pub claimed_agent_boot: [u8; 16],
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub cluster: String,
    pub node: u8,
    pub coordinator_boot: [u8; 16],
    pub agent_boot: [u8; 16],
    pub policy: [u8; 32],
    pub ready_term: u64,
    pub forwarding_term: u64,
    pub eligible: bool,
    pub updated_ns: u64,
}

pub fn now_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Failure closes leases, rather than treating a failed clock as time zero.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return u64::MAX;
    }
    (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64)
}
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("HA random source unavailable"))?;
    Ok(bytes)
}
pub fn fresh(updated: u64, now: u64) -> bool {
    updated <= now && now - updated <= FRESH_NS
}

/// Root-owned, exclusively created staging and atomic rename; readers never see
/// partially written roles. Runtime snapshots contain no credential material.
pub fn write_private<T: Serialize>(path: &Path, value: &T, durable: bool) -> Result<()> {
    let parent = path.parent().context("HA state parent missing")?;
    std::fs::create_dir_all(parent)?;
    let metadata = std::fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "untrusted HA state directory"
    );
    let bytes = serde_json::to_vec(value)?;
    let token = random::<16>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let stage = parent.join(format!(".ha-{token}"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&stage)?;
        file.write_all(&bytes)?;
        if durable {
            file.sync_all()?;
        }
        std::fs::rename(&stage, path)?;
        if durable {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(stage);
    result
}
pub fn read_private<T: DeserializeOwned>(path: &Path) -> Result<T> {
    use std::io::Read;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0
            && metadata.len() <= 4_194_304,
        "untrusted HA state file"
    );
    let mut bytes = Vec::new();
    file.take(4_194_305).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4_194_304, "oversized HA state file");
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Durable {
    cluster: String,
    authority: Authority,
}
type ColdVote = ([u8; 16], [u8; 32], u64);
struct Engine {
    cluster: String,
    authority: Authority,
    expiry: u64,
    quarantine: u64,
    owner_priority: u8,
    preferred: Option<(u8, u8, u64)>,
    cold: [Option<ColdVote>; 2],
}
impl Engine {
    fn new(cluster: String, previous: Authority, now: u64) -> Self {
        Self {
            cluster,
            authority: previous,
            expiry: 0,
            quarantine: now.saturating_add((TTL_MS + MARGIN_MS) * 1_000_000),
            owner_priority: 0,
            preferred: None,
            cold: [None, None],
        }
    }
    /// Pure transition: the caller persists a changed authority before sending
    /// its grant. No early release/preemption can overlap an outstanding lease.
    fn request(&mut self, request: &Request, now: u64) -> Result<Reply> {
        ensure!(
            request.cluster == self.cluster
                && (1..=2).contains(&request.node)
                && request.priority > 0,
            "unknown cluster/member"
        );
        if self.preferred.is_some_and(|(_, _, until)| now >= until) {
            self.preferred = None;
        }
        ensure!(now != u64::MAX, "witness clock unavailable");
        let slot = usize::from(request.node - 1);
        self.cold[slot] = if request.eligible && request.ready_term == 0 {
            Some((request.boot, request.policy, now))
        } else {
            None
        };
        let cold_quorum = self.cold.iter().all(|vote| {
            vote.is_some_and(|(_, policy, at)| {
                policy == request.policy && now.saturating_sub(at) < 2 * TTL_MS * 1_000_000
            })
        });
        let current = self.expiry > now;
        let ours = request.node == self.authority.owner && request.boot == self.authority.boot;
        let exact =
            request.policy == self.authority.policy && request.ready_term == self.authority.term;
        // A fresh complete predecessor snapshot remains a valid asynchronous
        // baseline if a just-promoted owner dies before exporting its new term.
        // Preemption of a live owner, however, requires that owner's snapshot.
        let ready = request.policy == self.authority.policy
            && request.ready_term > 0
            && request.ready_term <= self.authority.term;
        let initial = self.authority.term == 0 && request.node == 1 && request.ready_term == 0;
        let eligible = request.eligible && (ready || initial || cold_quorum && request.node == 1);
        if current
            && !ours
            && exact
            && request.eligible
            && request.preempt
            && (request.priority, 3 - request.node)
                > (self.owner_priority, 3 - self.authority.owner)
        {
            self.preferred = Some((
                request.node,
                request.priority,
                now.saturating_add(2 * TTL_MS * 1_000_000),
            ));
        }
        let preferred_us = self
            .preferred
            .map_or(true, |(node, _, _)| node == request.node);
        let mut granted = false;
        if now >= self.quarantine && request.eligible {
            if current
                && ours
                && request.ready_term == self.authority.term
                && (preferred_us || request.policy != self.authority.policy)
            {
                if request.policy != self.authority.policy {
                    self.authority.term = self
                        .authority
                        .term
                        .checked_add(1)
                        .context("HA term exhausted")?;
                    self.authority.policy = request.policy;
                    self.preferred = None;
                }
                // A policy change requires a fully reconciled local table and
                // becomes visible with a fresh authority generation below.
                self.expiry = now.saturating_add(TTL_MS * 1_000_000);
                self.owner_priority = request.priority;
                granted = true;
            } else if !current && eligible && preferred_us {
                self.authority = Authority {
                    term: self
                        .authority
                        .term
                        .checked_add(1)
                        .context("HA term exhausted")?,
                    owner: request.node,
                    boot: request.boot,
                    policy: request.policy,
                };
                self.expiry = now.saturating_add(TTL_MS * 1_000_000);
                self.owner_priority = request.priority;
                self.preferred = None;
                self.cold = [None, None];
                granted = true;
            }
        }
        Ok(Reply {
            authority: self.authority.clone(),
            remaining_ms: self.expiry.saturating_sub(now) / 1_000_000,
            granted,
        })
    }
}

fn mac(key: &[u8], label: &[u8], client: &[u8; 32], server: &[u8; 32]) -> Vec<u8> {
    let mut data = b"Velstra witness v1\0".to_vec();
    data.extend_from_slice(label);
    data.extend_from_slice(client);
    data.extend_from_slice(server);
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &data)
        .as_ref()
        .to_vec()
}
fn check(key: &[u8], label: &[u8], client: &[u8; 32], server: &[u8; 32], tag: &[u8]) -> Result<()> {
    let mut data = b"Velstra witness v1\0".to_vec();
    data.extend_from_slice(label);
    data.extend_from_slice(client);
    data.extend_from_slice(server);
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), &data, tag)
        .map_err(|_| anyhow::anyhow!("witness authentication failed"))
}
async fn handshake(socket: &mut TcpStream, key: &[u8], client_side: bool) -> Result<hmac::Key> {
    let (client, server) = if client_side {
        let client = random()?;
        socket.write_all(&client).await?;
        let mut server = [0; 32];
        let mut tag = [0; 32];
        socket.read_exact(&mut server).await?;
        socket.read_exact(&mut tag).await?;
        check(key, b"server", &client, &server, &tag)?;
        socket
            .write_all(&mac(key, b"client", &client, &server))
            .await?;
        (client, server)
    } else {
        let mut client = [0; 32];
        socket.read_exact(&mut client).await?;
        let server = random()?;
        socket.write_all(&server).await?;
        socket
            .write_all(&mac(key, b"server", &client, &server))
            .await?;
        let mut tag = [0; 32];
        socket.read_exact(&mut tag).await?;
        check(key, b"client", &client, &server, &tag)?;
        (client, server)
    };
    Ok(hmac::Key::new(
        hmac::HMAC_SHA256,
        &mac(key, b"session", &client, &server),
    ))
}
async fn send<T: Serialize>(
    socket: &mut TcpStream,
    key: &hmac::Key,
    label: u8,
    value: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= LIMIT, "oversized witness message");
    let mut authenticated = vec![label];
    authenticated.extend_from_slice(&bytes);
    socket
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .await?;
    socket.write_all(&bytes).await?;
    socket
        .write_all(hmac::sign(key, &authenticated).as_ref())
        .await?;
    Ok(())
}
async fn receive<T: DeserializeOwned>(
    socket: &mut TcpStream,
    key: &hmac::Key,
    label: u8,
) -> Result<T> {
    let mut length = [0; 4];
    socket.read_exact(&mut length).await?;
    let length = u32::from_le_bytes(length) as usize;
    ensure!(length <= LIMIT, "oversized witness message");
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes).await?;
    let mut tag = [0; 32];
    socket.read_exact(&mut tag).await?;
    let mut authenticated = vec![label];
    authenticated.extend_from_slice(&bytes);
    hmac::verify(key, &authenticated, &tag)
        .map_err(|_| anyhow::anyhow!("invalid witness frame"))?;
    Ok(serde_json::from_slice(&bytes)?)
}
/// Returns an absolute conservative local lease deadline. Starting the clock
/// before connect excludes both transit time and server processing from validity.
pub async fn exchange(config: &Config, request: &Request) -> Result<(Reply, u64)> {
    let start = now_ns();
    timeout(IO, async {
        let mut socket = TcpStream::connect(config.witness).await?;
        socket.set_nodelay(true)?;
        let key = handshake(&mut socket, config.secret.as_bytes(), true).await?;
        send(&mut socket, &key, 0, request).await?;
        let reply: Reply = receive(&mut socket, &key, 1).await?;
        ensure!(reply.remaining_ms <= TTL_MS, "invalid witness duration");
        let deadline = if reply.granted {
            start.saturating_add(reply.remaining_ms.saturating_sub(MARGIN_MS) * 1_000_000)
        } else {
            0
        };
        Ok((reply, deadline))
    })
    .await
    .context("witness request deadline")?
}

pub async fn serve(config: WitnessConfig) -> Result<()> {
    Config {
        cluster: config.cluster.clone(),
        node: 1,
        witness: std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            config.listen.port(),
        ),
        secret: config.secret.clone(),
        priority: 200,
        preempt: false,
        wireguard: Vec::new(),
        wireguard_policy: String::new(),
    }
    .validate()?;
    let parent = config.state.parent().context("witness state parent")?;
    std::fs::create_dir_all(parent)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(config.state.with_extension("lock"))?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "witness state is already owned"
    );
    let previous = match read_private::<Durable>(&config.state) {
        Ok(saved) => {
            ensure!(
                saved.cluster == config.cluster,
                "witness cluster differs from durable state"
            );
            saved.authority
        }
        Err(error) => {
            if std::fs::symlink_metadata(&config.state).is_ok() {
                return Err(error);
            }
            Authority::default()
        }
    };
    let engine = Arc::new(Mutex::new(Engine::new(
        config.cluster.clone(),
        previous,
        now_ns(),
    )));
    let permits = Arc::new(Semaphore::new(64));
    let listener = TcpListener::bind(config.listen).await?;
    loop {
        let (mut socket, _) = listener.accept().await?;
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let engine = engine.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = timeout(Duration::from_secs(1), async {
                socket.set_nodelay(true)?;
                let key = handshake(&mut socket, config.secret.as_bytes(), false).await?;
                let request: Request = receive(&mut socket, &key, 0).await?;
                let reply = {
                    let mut engine = engine.lock().await;
                    let previous = engine.authority.clone();
                    let reply = engine.request(&request, now_ns())?;
                    if previous != engine.authority {
                        if let Err(error) = write_private(
                            &config.state,
                            &Durable {
                                cluster: config.cluster.clone(),
                                authority: engine.authority.clone(),
                            },
                            true,
                        ) {
                            engine.expiry = 0;
                            engine.quarantine = u64::MAX;
                            return Err(
                                error.context("persisting witness generation; witness fenced")
                            );
                        }
                    }
                    reply
                };
                send(&mut socket, &key, 1, &reply).await
            })
            .await;
        });
    }
}

impl Config {
    /// A reload key includes every setting without exposing the credential.
    pub fn signature(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        Ok(ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HaConfig")
            .field("cluster", &self.cluster)
            .field("node", &self.node)
            .field("witness", &self.witness)
            .field("priority", &self.priority)
            .field("preempt", &self.preempt)
            .field("wireguard", &self.wireguard)
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(node: u8, term: u64) -> Request {
        Request {
            cluster: "ha-test-cluster-01".into(),
            node,
            boot: [node; 16],
            priority: if node == 1 { 200 } else { 100 },
            preempt: true,
            ready_term: term,
            policy: [7; 32],
            eligible: true,
        }
    }
    #[test]
    fn witness_never_overlaps_leases_and_rejects_cold_stale_or_replayed_owners() {
        let mut engine = Engine::new("ha-test-cluster-01".into(), Authority::default(), 0);
        assert!(!engine.request(&request(1, 0), 1).unwrap().granted);
        let now = (TTL_MS + MARGIN_MS) * 1_000_000;
        let first = engine.request(&request(1, 0), now).unwrap();
        assert!(first.granted);
        assert_eq!(first.authority.term, 1);
        assert!(!engine.request(&request(2, 1), now + 1).unwrap().granted);
        assert!(
            !engine
                .request(&request(2, 0), now + TTL_MS * 1_000_000)
                .unwrap()
                .granted
        );
        let second = engine
            .request(&request(2, 1), now + TTL_MS * 1_000_000)
            .unwrap();
        assert!(second.granted);
        assert_eq!(second.authority.term, 2);
        assert!(
            !engine
                .request(&request(1, 1), now + TTL_MS * 1_000_000 + 1)
                .unwrap()
                .granted
        );
    }
    #[test]
    fn preemption_waits_for_old_lease_and_requires_current_ready_generation() {
        let mut engine = Engine::new("ha-test-cluster-01".into(), Authority::default(), 0);
        let now = 1_000_000_000;
        engine.request(&request(1, 0), now).unwrap();
        let b = engine
            .request(&request(2, 1), now + TTL_MS * 1_000_000)
            .unwrap();
        assert!(b.granted);
        let active = now + TTL_MS * 1_000_000;
        assert!(!engine.request(&request(1, 1), active + 1).unwrap().granted);
        assert!(!engine.request(&request(1, 2), active + 2).unwrap().granted);
        assert!(
            !engine.request(&request(2, 2), active + 3).unwrap().granted,
            "preempted owner renewed"
        );
        assert!(
            !engine
                .request(&request(1, 2), active + TTL_MS * 1_000_000 - 1)
                .unwrap()
                .granted
        );
        assert!(
            engine
                .request(&request(1, 2), active + TTL_MS * 1_000_000)
                .unwrap()
                .granted
        );
    }
    #[test]
    fn restarted_witness_quarantines_before_reissuing_any_lease() {
        let previous = Authority {
            term: 10,
            owner: 2,
            boot: [2; 16],
            policy: [7; 32],
        };
        let mut engine = Engine::new("ha-test-cluster-01".into(), previous, 10);
        assert!(!engine.request(&request(1, 10), 11).unwrap().granted);
        let next = engine
            .request(&request(1, 10), 10 + (TTL_MS + MARGIN_MS) * 1_000_000)
            .unwrap();
        assert!(next.granted);
        assert_eq!(next.authority.term, 11);
    }
    #[test]
    fn two_cold_members_can_recover_but_one_cold_member_cannot_preempt_retained_state() {
        let previous = Authority {
            term: 10,
            owner: 2,
            boot: [2; 16],
            policy: [7; 32],
        };
        let mut engine = Engine::new("ha-test-cluster-01".into(), previous, 0);
        let now = 1_000_000_000;
        assert!(!engine.request(&request(1, 0), now).unwrap().granted);
        assert!(!engine.request(&request(2, 0), now + 1).unwrap().granted);
        let reply = engine.request(&request(1, 0), now + 2).unwrap();
        assert!(reply.granted);
        assert_eq!(reply.authority.term, 11);
        assert!(!engine.request(&request(2, 0), now + 3).unwrap().granted);
    }
    #[test]
    fn live_policy_transition_advances_authority_and_refuses_old_policy_state() {
        let mut engine = Engine::new("ha-test-cluster-01".into(), Authority::default(), 0);
        let now = 1_000_000_000;
        engine.request(&request(1, 0), now).unwrap();
        let mut update = request(1, 1);
        update.policy = [9; 32];
        let reply = engine.request(&update, now + 1).unwrap();
        assert!(reply.granted);
        assert_eq!(reply.authority.term, 2);
        assert!(
            !engine
                .request(&request(2, 2), now + TTL_MS * 1_000_000 + 2)
                .unwrap()
                .granted
        );
        let mut backup = request(2, 2);
        backup.policy = [9; 32];
        assert!(
            engine
                .request(&backup, now + TTL_MS * 1_000_000 + 3)
                .unwrap()
                .granted
        );
    }
    #[tokio::test]
    async fn fresh_mutual_handshake_rejects_wrong_credentials_and_reflection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            handshake(&mut socket, b"correct credential", false).await
        });
        let mut socket = TcpStream::connect(address).await.unwrap();
        assert!(handshake(&mut socket, b"wrong credential", true)
            .await
            .is_err());
        drop(socket);
        assert!(server.await.unwrap().is_err());
        let tag = mac(b"key", b"server", &[1; 32], &[2; 32]);
        assert!(check(b"key", b"client", &[1; 32], &[2; 32], &tag).is_err());
        assert!(check(b"key", b"server", &[1; 32], &[3; 32], &tag).is_err());
    }
}
