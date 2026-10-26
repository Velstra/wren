//! A single durable witness serializes forwarding authority. Leases expire on
//! CLOCK_BOOTTIME, including suspend; dataplanes must enforce the corresponding
//! absolute local deadline in the kernel. Authentication does not encrypt metadata.
//!
//! Timing is a budget, not a set of independent knobs. A member's lease is
//! valid locally from the instant it *started* connecting, minus a margin, so
//! the round trips to the witness are spent out of the lease itself. One
//! exchange costs roughly three round trips (connect, nonce/tag, request/reply)
//! and is abandoned after `io_ms`; the lease must survive one abandoned exchange
//! plus the coordinator's poll before the next one: `2·io + poll + margin ≤
//! lease`. The defaults (250 ms lease, 80 ms I/O) therefore need a witness
//! round trip below roughly 25 ms; a distant witness needs a longer lease and
//! I/O budget, configured identically on both members and the witness.
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
    net::{IpAddr, SocketAddr},
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
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

pub const ROLE_PATH: &str = "/run/velstra/ha/role.json";
pub const AGENT_PATH: &str = "/run/velstra/ha/agent.json";
/// Default lease. Configurable, see [`check_budget`].
pub const TTL_MS: u64 = 250;
pub const MARGIN_MS: u64 = 20;
pub const FRESH_NS: u64 = 100_000_000;
/// Default bound on one complete witness exchange.
pub const IO_MS: u64 = 80;
/// The coordinator's renewal cadence; part of the lease budget.
pub const POLL_MS: u64 = 25;
/// No configuration can make a lost member keep its authority for longer.
pub const MAX_LEASE_MS: u64 = 10_000;
/// How long the witness must have heard nothing from one member before it
/// lets the other, cold member open a new empty epoch alone.
pub const PEER_SILENCE_MS: u64 = 10_000;
/// Concurrent sessions each configured member may hold. The coordinator runs
/// one exchange at a time; the rest absorbs exchanges it abandoned that the
/// witness has not yet timed out.
const MEMBER_PERMITS: usize = 8;
/// Unrestricted (legacy) witnesses share one pool across every source.
const SHARED_PERMITS: usize = 64;
const LIMIT: usize = 4096;
fn default_lease_ms() -> u64 {
    TTL_MS
}
fn default_io_ms() -> u64 {
    IO_MS
}
fn default_peer_silence_ms() -> u64 {
    PEER_SILENCE_MS
}

/// A lease that cannot outlive one abandoned exchange plus the next poll
/// would expire between two healthy renewals: the owner would flap, or never
/// hold authority at all behind a slow witness link.
pub fn check_budget(lease_ms: u64, io_ms: u64) -> Result<()> {
    ensure!(
        (1..=MAX_LEASE_MS).contains(&lease_ms) && io_ms > 0,
        "HA lease must be 1..={MAX_LEASE_MS} ms and the witness I/O budget nonzero"
    );
    ensure!(
        2 * io_ms + POLL_MS + MARGIN_MS <= lease_ms,
        "HA witness I/O budget {io_ms} ms does not fit a {lease_ms} ms lease: \
         2 x I/O + {POLL_MS} ms poll + {MARGIN_MS} ms margin must not exceed the lease \
         (an I/O budget of {io_ms} ms needs a lease of at least {} ms)",
        2 * io_ms + POLL_MS + MARGIN_MS
    );
    Ok(())
}

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
    /// The longest local lease this member honours; a longer witness grant is
    /// cut to it. Set it equal to the witness's lease.
    #[serde(default = "default_lease_ms")]
    pub lease_ms: u64,
    /// Bound on one complete witness exchange, round trips included.
    #[serde(default = "default_io_ms")]
    pub io_ms: u64,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        check_budget(self.lease_ms, self.io_ms)?;
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
    /// The derived witness key, never the members' enrollment credential.
    pub secret: String,
    pub listen: SocketAddr,
    pub state: PathBuf,
    /// The two members' source addresses. Any other source is closed before
    /// it can occupy a session; empty keeps the legacy unrestricted listener.
    #[serde(default)]
    pub members: Vec<IpAddr>,
    #[serde(default = "default_lease_ms")]
    pub lease_ms: u64,
    #[serde(default = "default_peer_silence_ms")]
    pub peer_silence_ms: u64,
}
impl WitnessConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_LEASE_MS).contains(&self.lease_ms) && self.lease_ms > MARGIN_MS,
            "witness lease must be {}..={MAX_LEASE_MS} ms",
            MARGIN_MS + 1
        );
        // Silence only decides when warm state is presumed lost, never who
        // may forward (lease expiry does that), but it must be long enough
        // that a member which merely missed a few renewals is not presumed dead.
        ensure!(
            self.peer_silence_ms >= 1_000 && self.peer_silence_ms >= 4 * self.lease_ms,
            "witness peer silence must be at least 1000 ms and four leases"
        );
        ensure!(
            self.members.is_empty()
                || self.members.len() == 2
                    && canonical(self.members[0]) != canonical(self.members[1])
                    && self.members.iter().all(|m| !m.is_unspecified()),
            "witness members must be the two distinct member addresses"
        );
        Ok(())
    }
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
    pub agent_boot: [u8; 16],
    pub priority: u8,
    pub preempt: bool,
    pub ready_term: u64,
    pub policy: [u8; 32],
    pub eligible: bool,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub ready_term: u64,
    pub agent_boot: [u8; 16],
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub authority: Authority,
    pub claim: Claim,
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
    #[serde(default)]
    claim: Claim,
    /// The lease length this witness grants. A restarted witness quarantines
    /// for the longer of this and its new setting, so shortening the lease
    /// across a restart cannot cut an outstanding grant short.
    #[serde(default = "default_lease_ms")]
    lease_ms: u64,
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
    claim: Claim,
    lease_ns: u64,
    silence_ns: u64,
    /// The last authenticated request from each member, or this witness's own
    /// start: silence it did not observe is never presumed.
    heard: [u64; 2],
}
impl Engine {
    #[cfg(test)]
    fn new(cluster: String, previous: Authority, now: u64) -> Self {
        Self::configured(cluster, previous, TTL_MS, TTL_MS, PEER_SILENCE_MS, now)
    }
    fn configured(
        cluster: String,
        previous: Authority,
        recorded_lease_ms: u64,
        lease_ms: u64,
        silence_ms: u64,
        now: u64,
    ) -> Self {
        let outstanding = recorded_lease_ms.max(lease_ms);
        Self {
            cluster,
            authority: previous,
            expiry: 0,
            quarantine: now.saturating_add((outstanding + MARGIN_MS) * 1_000_000),
            owner_priority: 0,
            preferred: None,
            cold: [None, None],
            claim: Claim::default(),
            lease_ns: lease_ms * 1_000_000,
            silence_ns: silence_ms * 1_000_000,
            heard: [now, now],
        }
    }
    /// Pure transition: the caller persists a changed authority before sending
    /// its grant. No early release/preemption can overlap an outstanding lease.
    fn request(&mut self, request: &Request, now: u64) -> Result<Reply> {
        ensure!(
            request.cluster == self.cluster
                && (1..=2).contains(&request.node)
                && request.priority > 0
                && (!request.eligible || request.agent_boot != [0; 16]),
            "unknown cluster/member"
        );
        if self.preferred.is_some_and(|(_, _, until)| now >= until) {
            self.preferred = None;
        }
        ensure!(now != u64::MAX, "witness clock unavailable");
        let slot = usize::from(request.node - 1);
        self.heard[slot] = now;
        self.cold[slot] = if request.eligible && request.ready_term == 0 {
            Some((request.boot, request.policy, now))
        } else {
            None
        };
        let cold_quorum = self.cold.iter().all(|vote| {
            vote.is_some_and(|(_, policy, at)| {
                policy == request.policy && now.saturating_sub(at) < 2 * self.lease_ns
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
        // Every reply repeats the durable grant's exact baseline and agent.
        // A lost warm or cold ACK cannot strand its still-complete baseline.
        let retry = ours
            && request.policy == self.authority.policy
            && request.ready_term == self.claim.ready_term
            && request.agent_boot == self.claim.agent_boot;
        // A lone survivor. The other member has sent nothing this witness could
        // authenticate for the whole silence interval (counted from this
        // witness's own start, never from before it), so its warm state is
        // presumed lost and a cold vote cannot be outvoted. This rule never
        // decides *whether* authority may move: that is still `!current`
        // below, the witness's own lease expiry, which the silent member's
        // kernel deadline (started before it connected) precedes. A member
        // that is merely slow keeps talking and is never silent; one that
        // returns after this grant holds a superseded generation and must
        // import the survivor's snapshot before it is eligible again. The
        // survivor's policy is taken as is: its table is empty, so nothing is
        // interpreted under a fingerprint it does not hold.
        //
        // Only a cluster that has had an owner has warm state to presume lost.
        // Before the first grant (term 0) node 1 opens the cluster alone
        // (`initial`); a peer that has not reached this witness yet is not
        // dead, it is still enrolling — pairing applies node 2 first, and the
        // witness has typically been up far longer than the silence interval
        // by then — so node 2 must not claim a fresh cluster on its own.
        let lone = self.authority.term > 0
            && request.ready_term == 0
            && now.saturating_sub(self.heard[1 - slot]) >= self.silence_ns;
        let eligible = request.eligible
            && (ready || initial || retry || cold_quorum && request.node == 1 || lone);
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
                now.saturating_add(2 * self.lease_ns),
            ));
        }
        let preferred_us = self
            .preferred
            .map_or(true, |(node, _, _)| node == request.node);
        let mut granted = false;
        if now >= self.quarantine && request.eligible {
            if current
                && ours
                && (request.ready_term == self.authority.term || retry)
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
                self.expiry = now.saturating_add(self.lease_ns);
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
                self.expiry = now.saturating_add(self.lease_ns);
                self.owner_priority = request.priority;
                self.preferred = None;
                self.cold = [None, None];
                granted = true;
            }
        }
        if granted {
            self.claim = Claim {
                ready_term: request.ready_term,
                agent_boot: request.agent_boot,
            };
        }
        Ok(Reply {
            authority: self.authority.clone(),
            claim: self.claim.clone(),
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
/// A grant longer than this member's own lease is cut to it: ending a lease
/// early is always safe, the witness still waits out its own expiry.
pub async fn exchange(config: &Config, request: &Request) -> Result<(Reply, u64)> {
    let start = now_ns();
    timeout(Duration::from_millis(config.io_ms), async {
        let mut socket = TcpStream::connect(config.witness).await?;
        socket.set_nodelay(true)?;
        let key = handshake(&mut socket, config.secret.as_bytes(), true).await?;
        send(&mut socket, &key, 0, request).await?;
        let reply: Reply = receive(&mut socket, &key, 1).await?;
        ensure!(
            reply.remaining_ms <= MAX_LEASE_MS,
            "invalid witness duration"
        );
        let deadline = if reply.granted {
            let valid = reply.remaining_ms.min(config.lease_ms);
            start.saturating_add(valid.saturating_sub(MARGIN_MS) * 1_000_000)
        } else {
            0
        };
        Ok((reply, deadline))
    })
    .await
    .context("witness request deadline")?
}

/// An IPv4 member reaching a dual-stack listener arrives v4-mapped.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        v4 => v4,
    }
}
/// Sessions are admitted per source before any work is done for them. With
/// members configured, a stranger is closed at once and each member draws on
/// its own pool, so neither a third party nor one member's leftovers can hold
/// the sessions the other member needs to renew within its lease.
struct Admission {
    members: Vec<IpAddr>,
    pools: Vec<Arc<Semaphore>>,
}
impl Admission {
    fn new(members: &[IpAddr]) -> Self {
        let members: Vec<_> = members.iter().copied().map(canonical).collect();
        let pools = if members.is_empty() {
            vec![Arc::new(Semaphore::new(SHARED_PERMITS))]
        } else {
            members
                .iter()
                .map(|_| Arc::new(Semaphore::new(MEMBER_PERMITS)))
                .collect()
        };
        Self { members, pools }
    }
    fn admit(&self, source: IpAddr) -> Option<OwnedSemaphorePermit> {
        let pool = if self.members.is_empty() {
            0
        } else {
            let source = canonical(source);
            self.members.iter().position(|m| *m == source)?
        };
        self.pools[pool].clone().try_acquire_owned().ok()
    }
}

pub async fn serve(config: WitnessConfig) -> Result<()> {
    config.validate()?;
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
        lease_ms: TTL_MS,
        io_ms: IO_MS,
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
            (saved.authority, saved.claim, saved.lease_ms)
        }
        Err(error) => {
            if std::fs::symlink_metadata(&config.state).is_ok() {
                return Err(error);
            }
            (Authority::default(), Claim::default(), TTL_MS)
        }
    };
    let mut restored = Engine::configured(
        config.cluster.clone(),
        previous.0,
        previous.2,
        config.lease_ms,
        config.peer_silence_ms,
        now_ns(),
    );
    restored.claim = previous.1;
    let engine = Arc::new(Mutex::new(restored));
    let admission = Admission::new(&config.members);
    // A member abandons an exchange after its I/O budget, which is shorter
    // than the lease; holding a session longer than one lease serves nobody.
    let session = Duration::from_millis(config.lease_ms);
    let listener = TcpListener::bind(config.listen).await?;
    loop {
        let (mut socket, source) = listener.accept().await?;
        let Some(permit) = admission.admit(source.ip()) else {
            continue;
        };
        let engine = engine.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = timeout(session, async {
                socket.set_nodelay(true)?;
                let key = handshake(&mut socket, config.secret.as_bytes(), false).await?;
                let request: Request = receive(&mut socket, &key, 0).await?;
                let reply = {
                    let mut engine = engine.lock().await;
                    let previous = (engine.authority.clone(), engine.claim.clone());
                    let reply = engine.request(&request, now_ns())?;
                    if previous != (engine.authority.clone(), engine.claim.clone()) {
                        if let Err(error) = write_private(
                            &config.state,
                            &Durable {
                                cluster: config.cluster.clone(),
                                authority: engine.authority.clone(),
                                claim: engine.claim.clone(),
                                // Every grant after a restart follows the
                                // quarantine and changes the authority, so the
                                // first one records this run's lease before
                                // any reply carries it.
                                lease_ms: config.lease_ms,
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
            agent_boot: [node + 2; 16],
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
    fn lost_cold_grant_ack_can_retry_only_until_the_same_agent_reports_warm_state() {
        let mut engine = Engine::new("ha-test-cluster-01".into(), Authority::default(), 0);
        let now = 1_000_000_000;
        assert!(engine.request(&request(1, 0), now).unwrap().granted);
        let mut restarted = request(1, 0);
        restarted.agent_boot = [9; 16];
        assert!(!engine.request(&restarted, now + 1).unwrap().granted);
        assert!(
            engine
                .request(&request(1, 0), now + TTL_MS * 1_000_000 + 1)
                .unwrap()
                .granted,
            "lost ACK after expiry must recover without an offline peer"
        );
        assert!(
            engine
                .request(&request(1, 0), now + TTL_MS * 1_000_000 + 2)
                .unwrap()
                .granted
        );
        assert!(
            engine
                .request(&request(1, 2), now + TTL_MS * 1_000_000 + 3)
                .unwrap()
                .granted
        );
        assert!(
            !engine
                .request(&request(1, 0), now + TTL_MS * 1_000_000 + 4)
                .unwrap()
                .granted,
            "an acknowledged warm owner cannot regress to a cold claim"
        );
        assert!(
            !engine
                .request(&restarted, now + 2 * TTL_MS * 1_000_000 + 4)
                .unwrap()
                .granted
        );
    }
    #[test]
    fn lost_warm_ack_retains_exact_claim_across_retries_and_witness_restart() {
        let mut engine = Engine::new("ha-test-cluster-01".into(), Authority::default(), 0);
        let now = 1_000_000_000;
        engine.request(&request(1, 0), now).unwrap();
        engine.request(&request(1, 1), now + 1).unwrap();
        let grant = engine
            .request(&request(2, 1), now + TTL_MS * 1_000_000 + 2)
            .unwrap();
        assert!(grant.granted);
        assert_eq!(grant.claim.ready_term, 1);
        let mut denied = request(2, 1);
        denied.eligible = false;
        let observed = engine
            .request(&denied, now + TTL_MS * 1_000_000 + 3)
            .unwrap();
        assert!(!observed.granted);
        assert_eq!(observed.claim, grant.claim);
        assert!(
            engine
                .request(&request(2, 1), now + TTL_MS * 1_000_000 + 4)
                .unwrap()
                .granted
        );
        let mut wrong_live = request(2, 1);
        wrong_live.agent_boot = [9; 16];
        assert!(
            !engine
                .request(&wrong_live, now + TTL_MS * 1_000_000 + 5)
                .unwrap()
                .granted,
            "a different agent cannot retry the live grant's predecessor baseline"
        );
        let saved = Durable {
            cluster: engine.cluster.clone(),
            authority: engine.authority.clone(),
            claim: engine.claim.clone(),
            lease_ms: TTL_MS,
        };
        let saved: Durable = serde_json::from_slice(&serde_json::to_vec(&saved).unwrap()).unwrap();
        let mut restored =
            Engine::new(saved.cluster, saved.authority, now + 2 * TTL_MS * 1_000_000);
        restored.claim = saved.claim;
        let later = now + 2 * TTL_MS * 1_000_000 + (TTL_MS + MARGIN_MS) * 1_000_000;
        let mut wrong = request(2, 0);
        wrong.agent_boot = [9; 16];
        assert!(!restored.request(&wrong, later).unwrap().granted);
        assert!(restored.request(&request(2, 1), later + 1).unwrap().granted);
        let term = restored.authority.term;
        assert!(
            restored
                .request(&request(2, term), later + 2)
                .unwrap()
                .granted
        );
        assert!(!restored.request(&request(2, 1), later + 3).unwrap().granted);
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
    const SILENCE: u64 = PEER_SILENCE_MS * 1_000_000;
    #[test]
    fn lone_cold_survivor_is_granted_only_after_the_peer_was_silent_for_the_full_interval() {
        // Node 1 owned term 10 and then died for good; node 2's agent restarts
        // cold. Before this rule nothing could ever grant node 2 again.
        let previous = Authority {
            term: 10,
            owner: 1,
            boot: [1; 16],
            policy: [7; 32],
        };
        let start = 1_000_000_000;
        let mut engine = Engine::new("ha-test-cluster-01".into(), previous, start);
        // The witness hears node 1 one last time, then never again.
        let mut last = request(1, 10);
        last.eligible = false;
        engine.request(&last, start + 1).unwrap();
        let cold = request(2, 0);
        assert!(!engine.request(&cold, start + 2).unwrap().granted);
        assert!(
            !engine.request(&cold, start + SILENCE).unwrap().granted,
            "granted before the peer had been silent for the full interval"
        );
        let reply = engine.request(&cold, start + 1 + SILENCE).unwrap();
        assert!(reply.granted, "a lone cold survivor must forward again");
        assert_eq!(reply.authority.term, 11);
        assert_eq!(reply.authority.owner, 2);
        assert_eq!(
            reply.claim.ready_term, 0,
            "the grant names an empty baseline"
        );
    }
    #[test]
    fn lone_cold_survivor_with_a_newer_policy_is_granted_its_own_policy() {
        // The survivor missed (or alone received) the last commit. Its table is
        // empty, so no state is interpreted under the old fingerprint.
        let previous = Authority {
            term: 3,
            owner: 1,
            boot: [1; 16],
            policy: [7; 32],
        };
        let mut engine = Engine::new("ha-test-cluster-01".into(), previous, 0);
        let mut cold = request(2, 0);
        cold.policy = [9; 32];
        let reply = engine.request(&cold, SILENCE).unwrap();
        assert!(reply.granted);
        assert_eq!(reply.authority.policy, [9; 32]);
    }
    #[test]
    fn a_fresh_cluster_is_never_opened_by_node_2_alone() {
        // Pairing applies the secondary first; a witness that has been up for
        // longer than the silence interval has simply never heard the primary
        // yet. That is enrollment, not a lost owner.
        let start = 1_000_000_000;
        let mut engine = Engine::new("ha-test-cluster-01".into(), Authority::default(), start);
        let late = start + 3 * SILENCE;
        assert!(
            !engine.request(&request(2, 0), late).unwrap().granted,
            "node 2 opened a cluster that never had an owner"
        );
        let reply = engine.request(&request(1, 0), late + 1).unwrap();
        assert!(reply.granted, "the primary opens a fresh cluster alone");
        assert_eq!(reply.authority.owner, 1);
        assert_eq!(reply.authority.term, 1);
    }
    #[test]
    fn a_renewing_peer_is_never_silent_and_never_displaced_by_a_lone_cold_member() {
        let mut engine = Engine::new("ha-test-cluster-01".into(), Authority::default(), 0);
        let mut now = (TTL_MS + MARGIN_MS) * 1_000_000;
        assert!(engine.request(&request(1, 0), now).unwrap().granted);
        let term = engine.authority.term;
        let mut restarted = request(2, 0);
        restarted.agent_boot = [9; 16];
        let until = now + 3 * SILENCE;
        while now < until {
            now += 50_000_000;
            assert!(engine.request(&request(1, term), now).unwrap().granted);
            assert!(
                !engine.request(&restarted, now + 1).unwrap().granted,
                "a lone cold member displaced a live owner"
            );
        }
        // An ineligible but talking peer is not silent either.
        let mut idle = request(1, term);
        idle.eligible = false;
        now += TTL_MS * 1_000_000;
        while now < until + 3 * SILENCE {
            now += 50_000_000;
            engine.request(&idle, now).unwrap();
            assert!(!engine.request(&restarted, now + 1).unwrap().granted);
        }
    }
    #[test]
    fn both_cold_members_alive_still_use_the_two_vote_rule() {
        let previous = Authority {
            term: 10,
            owner: 2,
            boot: [2; 16],
            policy: [7; 32],
        };
        let mut engine = Engine::new("ha-test-cluster-01".into(), previous, 0);
        let mut now = 1_000_000_000;
        // Both members keep voting cold; only node 1 may win, by quorum, and
        // node 2 never by the lone rule while node 1 is audible.
        assert!(!engine.request(&request(2, 0), now).unwrap().granted);
        now += 1;
        let reply = engine.request(&request(1, 0), now).unwrap();
        assert!(reply.granted);
        assert_eq!(reply.authority.owner, 1);
        for _ in 0..400 {
            now += 50_000_000;
            assert!(engine.request(&request(1, 0), now).unwrap().granted);
            assert!(!engine.request(&request(2, 0), now + 1).unwrap().granted);
        }
    }
    #[test]
    fn restarted_witness_waits_the_full_silence_interval_from_its_own_start() {
        // After a restart the witness has observed no silence at all: the
        // peer may have been renewing until the moment it stopped.
        let previous = Authority {
            term: 10,
            owner: 1,
            boot: [1; 16],
            policy: [7; 32],
        };
        let start = 50 * SILENCE;
        let mut engine = Engine::new("ha-test-cluster-01".into(), previous, start);
        assert!(
            !engine
                .request(&request(2, 0), start + SILENCE - 1)
                .unwrap()
                .granted
        );
        assert!(
            engine
                .request(&request(2, 0), start + SILENCE)
                .unwrap()
                .granted
        );
    }
    fn witness_fixture(name: &str) -> (WitnessConfig, Config) {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let directory = std::env::temp_dir().join(format!(
            "wren-ha-{name}-{}-{}",
            std::process::id(),
            random::<8>()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let key = "a-derived-witness-key-of-at-least-32-bytes".to_string();
        let witness = WitnessConfig {
            cluster: "ha-test-cluster-01".into(),
            secret: key.clone(),
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            state: directory.join("state.json"),
            members: vec!["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()],
            lease_ms: TTL_MS,
            peer_silence_ms: PEER_SILENCE_MS,
        };
        let member = Config {
            cluster: "ha-test-cluster-01".into(),
            node: 2,
            witness: witness.listen,
            secret: key,
            priority: 100,
            preempt: false,
            wireguard: Vec::new(),
            wireguard_policy: String::new(),
            lease_ms: TTL_MS,
            io_ms: IO_MS,
        };
        (witness, member)
    }
    async fn wait_listening(address: SocketAddr) {
        for _ in 0..200 {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("witness never listened");
    }
    async fn connect_from(source: &str, address: SocketAddr) -> TcpStream {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
        socket.connect(address).await.unwrap()
    }
    #[tokio::test]
    async fn idle_connections_from_one_source_cannot_starve_a_member() {
        let (witness, member) = witness_fixture("flood");
        let address = witness.listen;
        let state = witness.state.clone();
        let server = tokio::spawn(serve(witness));
        wait_listening(address).await;
        // An attacker (or a misbehaving member) holds more idle sessions than
        // the witness has ever had permits for; none sends its nonce.
        let mut flood = Vec::new();
        for _ in 0..80 {
            flood.push(connect_from("127.0.0.2", address).await);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let request = Request {
            cluster: member.cluster.clone(),
            node: 2,
            boot: [2; 16],
            agent_boot: [4; 16],
            priority: 100,
            preempt: false,
            ready_term: 0,
            policy: [7; 32],
            eligible: false,
        };
        let answered = exchange(&member, &request).await;
        server.abort();
        drop(flood);
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
        assert!(
            answered.is_ok(),
            "a flood from one source starved a member's renewal: {:#}",
            answered.err().unwrap()
        );
    }
    #[tokio::test]
    async fn a_connection_from_a_non_member_is_closed_at_once() {
        let (witness, _) = witness_fixture("stranger");
        let address = witness.listen;
        let state = witness.state.clone();
        let server = tokio::spawn(serve(witness));
        wait_listening(address).await;
        let mut stranger = connect_from("127.0.0.3", address).await;
        let mut byte = [0; 1];
        let closed = timeout(Duration::from_millis(200), stranger.read(&mut byte)).await;
        server.abort();
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "a non-member held a witness session open"
        );
    }
    #[test]
    fn strangers_consume_no_permits_and_members_draw_on_separate_pools() {
        let a: IpAddr = "10.3.0.1".parse().unwrap();
        let b: IpAddr = "10.3.0.2".parse().unwrap();
        let admission = Admission::new(&[a, b]);
        for _ in 0..1000 {
            assert!(admission.admit("10.3.0.9".parse().unwrap()).is_none());
        }
        let held: Vec<_> = (0..MEMBER_PERMITS)
            .map(|_| admission.admit(a).expect("member A permit"))
            .collect();
        assert!(admission.admit(a).is_none(), "member A is bounded");
        let b_permits: Vec<_> = (0..MEMBER_PERMITS)
            .map(|_| admission.admit(b).expect("member A cannot starve member B"))
            .collect();
        assert_eq!(b_permits.len(), MEMBER_PERMITS);
        // An IPv4 member reaching a dual-stack listener arrives v4-mapped.
        drop(held);
        assert!(admission
            .admit("::ffff:10.3.0.1".parse().unwrap())
            .is_some());
        // Legacy: no members configured keeps the old shared listener.
        assert!(Admission::new(&[])
            .admit("192.0.2.1".parse().unwrap())
            .is_some());
    }
    #[test]
    fn timing_budget_requires_one_abandoned_exchange_to_fit_the_lease() {
        check_budget(TTL_MS, IO_MS).unwrap();
        // A 50 ms round-trip witness: ~150 ms per exchange.
        let error = check_budget(250, 150).unwrap_err().to_string();
        assert!(error.contains("at least 345 ms"), "{error}");
        check_budget(400, 150).unwrap();
        assert!(check_budget(MAX_LEASE_MS + 1, 80).is_err());
        assert!(check_budget(250, 0).is_err());
        // Configurations written before the budget existed keep its defaults.
        let old: Config = serde_json::from_str(
            r#"{"cluster":"ha-test-cluster-01","node":1,"witness":"10.3.0.3:5440",
                "secret":"a-derived-witness-key-of-at-least-32-bytes","priority":200}"#,
        )
        .unwrap();
        assert_eq!((old.lease_ms, old.io_ms), (TTL_MS, IO_MS));
        old.validate().unwrap();
        let mut slow = old.clone();
        slow.io_ms = 150;
        assert!(slow.validate().is_err());
    }
    #[test]
    fn witness_configuration_bounds_members_lease_and_silence() {
        let (mut witness, _) = witness_fixture("validate");
        witness.validate().unwrap();
        witness.members.pop();
        assert!(witness.validate().is_err(), "one member is not a pair");
        witness.members = vec![
            "10.3.0.1".parse().unwrap(),
            "::ffff:10.3.0.1".parse().unwrap(),
        ];
        assert!(witness.validate().is_err(), "the same member twice");
        witness.members.clear();
        witness.validate().unwrap();
        witness.peer_silence_ms = 3 * witness.lease_ms;
        assert!(witness.validate().is_err());
        let old: WitnessConfig = serde_json::from_str(
            r#"{"cluster":"ha-test-cluster-01","secret":"k","listen":"10.3.0.3:5440","state":"/s"}"#,
        )
        .unwrap();
        assert_eq!(
            (old.members.len(), old.lease_ms, old.peer_silence_ms),
            (0, TTL_MS, PEER_SILENCE_MS)
        );
    }
    #[test]
    fn a_witness_restarted_with_a_shorter_lease_waits_out_the_longer_recorded_one() {
        let mut engine = Engine::configured(
            "ha-test-cluster-01".into(),
            Authority::default(),
            2_000,
            250,
            10_000,
            0,
        );
        assert!(
            !engine
                .request(&request(1, 0), 2_019_999_999)
                .unwrap()
                .granted
        );
        let reply = engine.request(&request(1, 0), 2_020_000_000).unwrap();
        assert!(reply.granted);
        assert_eq!(reply.remaining_ms, 250);
    }
    #[tokio::test]
    async fn a_member_cuts_a_longer_witness_grant_to_its_own_lease() {
        let (mut witness, mut member) = witness_fixture("cut");
        witness.lease_ms = 1_000;
        witness.peer_silence_ms = 4_000;
        member.node = 1;
        member.priority = 200;
        let address = witness.listen;
        let state = witness.state.clone();
        let server = tokio::spawn(serve(witness));
        wait_listening(address).await;
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let mut cold = request(1, 0);
        cold.cluster = member.cluster.clone();
        let before = now_ns();
        let result = exchange(&member, &cold).await;
        server.abort();
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
        let (reply, deadline) = result.unwrap();
        assert!(reply.granted);
        assert!(
            reply.remaining_ms > TTL_MS,
            "the witness granted its own lease"
        );
        assert!(deadline <= before + (TTL_MS - MARGIN_MS) * 1_000_000 + 5_000_000);
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
