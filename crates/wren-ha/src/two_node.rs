//! Authenticated, availability-oriented two-member HA without a witness.
//!
//! This is deliberately not a quorum protocol. If every control path is
//! partitioned, both healthy members can eventually forward. Authentication,
//! local kernel deadlines and state readiness remain mandatory; connectivity
//! restoration deterministically fences the losing member. Deployments needing
//! exclusive ownership through a total partition must use witness mode.

use crate::{fresh, now_ns, Authority, Claim, Config, Mode, Reply, Request, MARGIN_MS, POLL_MS};
use anyhow::{ensure, Context, Result};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::Mutex,
    task::{JoinHandle, JoinSet},
    time::timeout,
};

fn timeout_default() -> u64 {
    1_000
}
fn startup_default() -> u64 {
    3_000
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    #[serde(alias = "heartbeat-listen")]
    pub listen: Vec<SocketAddr>,
    #[serde(alias = "heartbeat-peer")]
    pub peers: Vec<SocketAddr>,
    #[serde(default = "timeout_default", alias = "peer-timeout-ms")]
    pub peer_timeout_ms: u64,
    #[serde(default = "startup_default", alias = "startup-delay-ms")]
    pub startup_delay_ms: u64,
}
impl PeerConfig {
    pub fn validate(&self, lease_ms: u64, io_ms: u64) -> Result<()> {
        ensure!(
            (1..=4).contains(&self.listen.len()) && self.listen.len() == self.peers.len(),
            "two-node HA requires 1..4 matching local/peer paths"
        );
        for (index, (local, peer)) in self.listen.iter().zip(&self.peers).enumerate() {
            ensure!(
                local.is_ipv4() == peer.is_ipv4()
                    && local != peer
                    && local.port() > 0
                    && peer.port() > 0
                    && !local.ip().is_unspecified()
                    && !peer.ip().is_unspecified()
                    && !local.ip().is_multicast()
                    && !peer.ip().is_multicast(),
                "invalid two-node HA path"
            );
            ensure!(
                !self.listen[..index].contains(local) && !self.peers[..index].contains(peer),
                "duplicate two-node HA path"
            );
        }
        // Pinned data-plane replicas expire at 1500 ms. A longer election
        // silently loses warm takeover readiness; reject it rather than opening
        // an empty table under a warm generation.
        ensure!((750..=1_200).contains(&self.peer_timeout_ms)
            && self.peer_timeout_ms >= 4 * lease_ms
            && self.peer_timeout_ms + io_ms + POLL_MS + 2 * MARGIN_MS < 1_500,
            "two-node peer timeout must be 750..1200 ms, at least four leases, and fit the 1500 ms replica readiness budget");
        ensure!(
            self.startup_delay_ms >= 2 * self.peer_timeout_ms && self.startup_delay_ms <= 120_000,
            "two-node startup delay must be at least two peer timeouts and at most 120000 ms"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat {
    sequence: u64,
    request: Request,
    authority: Authority,
    claim: Claim,
    active: bool,
    remaining_ms: u64,
}
#[derive(Clone)]
struct Observation {
    heartbeat: Heartbeat,
    heard_ns: u64,
}

/// Pure election state. All timestamps are local CLOCK_BOOTTIME; peer absolute
/// clocks are never compared. Agent claims come only from the local fresh report.
struct Election {
    authority: Authority,
    claim: Claim,
    deadline_ns: u64,
    started_ns: u64,
    agent_boot: [u8; 16],
    last_owner_ns: u64,
    yield_until_ns: u64,
    highest_term: u64,
    last_step_ns: Option<u64>,
    rejoin_until_ns: u64,
}
impl Election {
    fn new(now: u64) -> Self {
        Self {
            authority: Authority::default(),
            claim: Claim::default(),
            deadline_ns: 0,
            started_ns: now,
            agent_boot: [0; 16],
            last_owner_ns: now,
            yield_until_ns: 0,
            highest_term: 0,
            last_step_ns: None,
            rejoin_until_ns: 0,
        }
    }
    fn adopt(&mut self, heartbeat: &Heartbeat, heard: u64) {
        let changed = self.authority != heartbeat.authority;
        self.authority = heartbeat.authority.clone();
        self.claim = heartbeat.claim.clone();
        self.deadline_ns = 0;
        if heartbeat.active || changed {
            self.last_owner_ns = heard;
        }
    }
    fn step(
        &mut self,
        cfg: &Config,
        local: &Request,
        peer: Option<&Observation>,
        now: u64,
    ) -> Result<(Reply, u64)> {
        ensure!(now != u64::MAX, "two-node HA clock unavailable");
        let paths = cfg.two_node.as_ref().context("missing peer settings")?;
        ensure!(
            local.cluster == cfg.cluster
                && local.node == cfg.node
                && local.boot != [0; 16]
                && local.priority == cfg.priority
                && (!local.eligible || local.agent_boot != [0; 16]),
            "invalid local HA report"
        );
        if self.agent_boot != local.agent_boot && local.agent_boot != [0; 16] {
            if self.agent_boot != [0; 16] {
                self.started_ns = now;
                self.deadline_ns = 0;
            }
            self.agent_boot = local.agent_boot;
        }
        let timeout_ns = paths.peer_timeout_ms * 1_000_000;
        if self.authority.owner == cfg.node
            && self.authority.boot == local.boot
            && self
                .last_step_ns
                .is_some_and(|previous| now.saturating_sub(previous) >= cfg.lease_ms * 1_000_000)
        {
            // A suspended coordinator's kernel lease already expired. Give it
            // time to discover an incumbent before reusing its retained table;
            // a delayed process is not permission to preempt a healthy peer.
            self.rejoin_until_ns = now.saturating_add(timeout_ns);
            self.deadline_ns = 0;
        }
        self.last_step_ns = Some(now);
        let peer = peer.filter(|p| p.heard_ns <= now && now - p.heard_ns < timeout_ns);
        let own_live = local.eligible
            && self.authority.owner == cfg.node
            && self.authority.boot == local.boot
            && self.deadline_ns > now;
        if let Some(peer) = peer {
            let remote = &peer.heartbeat;
            self.highest_term = self.highest_term.max(remote.authority.term);
            if remote.active {
                if !own_live || rank(&remote.request) > rank(local) {
                    // Fence immediately on losing a collision, but never roll
                    // the exported generation backwards. The winning owner
                    // advances beyond both histories on its next observation.
                    if remote.authority.term >= self.authority.term {
                        self.adopt(remote, peer.heard_ns);
                    }
                }
            } else if !own_live && remote.authority.term > self.authority.term {
                self.adopt(remote, peer.heard_ns);
            }
        }
        self.highest_term = self
            .highest_term
            .max(self.authority.term)
            .max(local.ready_term);
        let owner_is_us = self.authority.owner == cfg.node && self.authority.boot == local.boot;
        let retry = owner_is_us
            && local.policy == self.authority.policy
            && local.ready_term == self.claim.ready_term
            && local.agent_boot == self.claim.agent_boot;
        let continuity = owner_is_us
            && (local.ready_term == self.authority.term && local.ready_term > 0 || retry);
        let candidate_preempts = peer.is_some_and(|p| {
            let other = &p.heartbeat.request;
            other.eligible
                && other.preempt
                && other.policy == self.authority.policy
                && other.ready_term == self.authority.term
                && other.ready_term > 0
                && rank(other) > rank(local)
        });
        if owner_is_us && candidate_preempts {
            self.yield_until_ns = now.saturating_add(timeout_ns + cfg.lease_ms * 1_000_000);
        }
        let remote_active = peer.is_some_and(|p| {
            p.heartbeat.active
                && (p.heartbeat.authority.owner != cfg.node
                    || p.heartbeat.authority.boot != local.boot)
        });
        // A total-partition collision is resolved by the same stable ordering
        // on both members. A connected, sole healthy incumbent is not preempted
        // unless the challenger explicitly requests it with its exact snapshot.
        let remote_wins = remote_active
            && (!own_live || peer.is_some_and(|p| rank(&p.heartbeat.request) > rank(local)));
        let mut granted = false;
        if local.eligible
            && !remote_wins
            && now >= self.yield_until_ns
            && now >= self.rejoin_until_ns
        {
            if continuity {
                let collision = peer.is_some_and(|p| {
                    p.heartbeat.active
                        && p.heartbeat.authority != self.authority
                        && p.heartbeat.authority.term >= self.authority.term
                });
                if local.policy != self.authority.policy || collision {
                    self.authority.term = self
                        .highest_term
                        .checked_add(1)
                        .context("HA term exhausted")?;
                    self.authority.policy = local.policy;
                    self.highest_term = self.authority.term;
                }
                granted = true;
            } else {
                let startup_done =
                    now.saturating_sub(self.started_ns) >= paths.startup_delay_ms * 1_000_000;
                let owner_expired = now.saturating_sub(self.last_owner_ns) >= timeout_ns;
                let warm = local.ready_term > 0
                    && (self.authority.term == 0
                        || local.policy == self.authority.policy
                            && local.ready_term <= self.authority.term);
                let cold = local.ready_term == 0
                    && startup_done
                    && peer.map_or(true, |p| {
                        p.heartbeat.request.ready_term == 0
                            && p.heartbeat.request.policy == local.policy
                    });
                let preferred = peer.map_or(true, |p| {
                    let other = &p.heartbeat.request;
                    !other.eligible
                        || other.ready_term == 0 && local.ready_term > 0
                        || (other.ready_term > 0) == (local.ready_term > 0)
                            && rank(local) > rank(other)
                });
                if owner_expired
                    && (self.authority.term > 0 || startup_done)
                    && preferred
                    && (warm || cold)
                {
                    self.authority = Authority {
                        term: self
                            .highest_term
                            .checked_add(1)
                            .context("HA term exhausted")?,
                        owner: cfg.node,
                        boot: local.boot,
                        policy: local.policy,
                    };
                    self.highest_term = self.authority.term;
                    granted = true;
                }
            }
        }
        if granted {
            self.claim = Claim {
                ready_term: local.ready_term,
                agent_boot: local.agent_boot,
            };
            self.deadline_ns =
                now.saturating_add(cfg.lease_ms.saturating_sub(MARGIN_MS) * 1_000_000);
            self.last_owner_ns = now;
        } else {
            self.deadline_ns = 0;
        }
        Ok((
            Reply {
                authority: self.authority.clone(),
                claim: self.claim.clone(),
                remaining_ms: self.deadline_ns.saturating_sub(now) / 1_000_000,
                granted,
            },
            self.deadline_ns,
        ))
    }
}
fn rank(request: &Request) -> (u8, u8) {
    (request.priority, 3 - request.node)
}

struct Shared {
    local: Heartbeat,
    local_updated_ns: u64,
    local_deadline_ns: u64,
    peer: Option<Observation>,
    retired_boots: VecDeque<[u8; 16]>,
}
impl Shared {
    fn observe(&mut self, cfg: &Config, message: Heartbeat, now: u64) -> Result<()> {
        let request = &message.request;
        ensure!(
            request.cluster == cfg.cluster
                && request.node == 3 - cfg.node
                && request.priority > 0
                && request.boot != [0; 16]
                && message.sequence > 0
                && (!request.eligible || request.agent_boot != [0; 16]),
            "invalid two-node member"
        );
        ensure!(
            message.remaining_ms <= cfg.lease_ms
                && (message.authority.term == 0 && message.authority.owner == 0
                    || message.authority.term > 0
                        && (1..=2).contains(&message.authority.owner)
                        && message.authority.boot != [0; 16]),
            "invalid peer authority"
        );
        ensure!(
            !message.active
                || request.eligible
                    && message.remaining_ms > 0
                    && message.authority.owner == request.node
                    && message.authority.boot == request.boot
                    && message.authority.policy == request.policy,
            "invalid active peer"
        );
        ensure!(
            !self.retired_boots.contains(&request.boot),
            "retired peer coordinator epoch"
        );
        if let Some(previous) = &self.peer {
            if previous.heartbeat.request.boot == request.boot {
                // Duplicate multipath replies never extend peer liveness.
                if message.sequence <= previous.heartbeat.sequence {
                    return Ok(());
                }
            } else {
                self.retired_boots
                    .push_back(previous.heartbeat.request.boot);
                if self.retired_boots.len() > 16 {
                    self.retired_boots.pop_front();
                }
            }
        }
        self.peer = Some(Observation {
            heartbeat: message,
            heard_ns: now,
        });
        Ok(())
    }
    fn response(&self, now: u64) -> Heartbeat {
        let mut message = self.local.clone();
        if !fresh(self.local_updated_ns, now) {
            message.request.eligible = false;
            message.active = false;
        }
        message.remaining_ms = self.local_deadline_ns.saturating_sub(now) / 1_000_000;
        message.active &= message.remaining_ms > 0 && message.request.eligible;
        message
    }
}

/// Listener lifetime is bounded by the coordinator object, including every
/// accepted session. No orphan listener survives a configuration reload.
pub struct PeerCoordinator {
    config: Config,
    state: Arc<Mutex<Shared>>,
    election: Election,
    listeners: Vec<JoinHandle<()>>,
    exchanges: JoinSet<Result<Heartbeat>>,
}
impl Drop for PeerCoordinator {
    fn drop(&mut self) {
        for task in &self.listeners {
            task.abort();
        }
    }
}
impl PeerCoordinator {
    pub async fn start(config: Config, boot: [u8; 16]) -> Result<Self> {
        config.validate()?;
        ensure!(
            config.mode == Mode::TwoNode && boot != [0; 16],
            "invalid two-node coordinator"
        );
        let paths = config.two_node.as_ref().context("missing peers")?;
        // Bind everything before starting the quarantine clock or spawning
        // anything. Startup may be retried while networkd restores addresses;
        // unavailable paths must neither start an election nor leak listeners.
        let mut bound = Vec::new();
        for address in &paths.listen {
            bound.push(
                TcpListener::bind(address)
                    .await
                    .with_context(|| format!("binding HA peer control path {address}"))?,
            );
        }
        let now = now_ns();
        ensure!(now != u64::MAX, "HA clock unavailable");
        let state = Arc::new(Mutex::new(Shared {
            local: Heartbeat {
                sequence: 1,
                request: Request {
                    cluster: config.cluster.clone(),
                    node: config.node,
                    boot,
                    agent_boot: [0; 16],
                    priority: config.priority,
                    preempt: config.preempt,
                    ready_term: 0,
                    policy: [0; 32],
                    eligible: false,
                },
                authority: Authority::default(),
                claim: Claim::default(),
                active: false,
                remaining_ms: 0,
            },
            local_updated_ns: now,
            local_deadline_ns: 0,
            peer: None,
            retired_boots: VecDeque::new(),
        }));
        let admission = Arc::new(crate::Admission::new(
            &paths.peers.iter().map(|a| a.ip()).collect::<Vec<_>>(),
        ));
        let mut listeners = Vec::new();
        for listener in bound {
            let state = state.clone();
            let config = config.clone();
            let admission = admission.clone();
            listeners.push(tokio::spawn(async move {
                let mut sessions = JoinSet::new();
                loop {
                    while sessions.try_join_next().is_some() {}
                    tokio::select! {
                        result = listener.accept() => {
                            let Ok((mut stream, source)) = result else { break; };
                            let Some(permit) = admission.admit(source.ip()) else { continue; };
                            let state = state.clone(); let config = config.clone();
                            sessions.spawn(async move {
                                let _permit = permit;
                                let _ = timeout(Duration::from_millis(config.io_ms), async {
                                    stream.set_nodelay(true)?;
                                    let key = peer_key(&config);
                                    let session = crate::handshake(&mut stream, key.as_ref(), false).await?;
                                    let request: Heartbeat = crate::receive(&mut stream, &session, 2).await?;
                                    let response = {
                                        let mut shared = state.lock().await;
                                        let now = now_ns();
                                        shared.observe(&config, request, now)?;
                                        shared.response(now)
                                    };
                                    crate::send(&mut stream, &session, 3, &response).await
                                }).await;
                            });
                        }
                        Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
                    }
                }
            }));
        }
        Ok(Self {
            config,
            state,
            election: Election::new(now),
            listeners,
            exchanges: JoinSet::new(),
        })
    }
    async fn publish(
        &mut self,
        request: &Request,
        actual_deadline: u64,
        vips_ready: bool,
    ) -> Result<Heartbeat> {
        let mut shared = self.state.lock().await;
        let now = now_ns();
        let sequence = shared
            .local
            .sequence
            .checked_add(1)
            .context("HA heartbeat sequence exhausted")?;
        shared.local = Heartbeat {
            sequence,
            request: request.clone(),
            authority: self.election.authority.clone(),
            claim: self.election.claim.clone(),
            active: actual_deadline > now
                && vips_ready
                && request.eligible
                && self.election.authority.owner == self.config.node,
            remaining_ms: actual_deadline.saturating_sub(now) / 1_000_000,
        };
        shared.local_updated_ns = now;
        shared.local_deadline_ns = actual_deadline;
        Ok(shared.response(now))
    }
    /// Renew locally bounded authority, using all control paths concurrently.
    /// `actual_deadline`/`vips_ready` are the previous published kernel role, not
    /// an invented success inferred from our own desired election.
    pub async fn step(
        &mut self,
        request: &Request,
        actual_deadline: u64,
        vips_ready: bool,
    ) -> Result<(Reply, u64)> {
        let heartbeat = self.publish(request, actual_deadline, vips_ready).await?;
        let paths = self.config.two_node.as_ref().context("missing peers")?;
        while let Some(result) = self.exchanges.try_join_next() {
            if let Ok(Ok(message)) = result {
                // A malformed authenticated packet must not suppress healthy
                // paths. It also must never refresh the peer's liveness.
                let _ = self
                    .state
                    .lock()
                    .await
                    .observe(&self.config, message, now_ns());
            }
        }
        // Network timeouts must never stall the coordinator's role refresh:
        // Fabric fences roles older than 100 ms, independent of the lease.
        // One bounded batch runs in the background, at most four exchanges.
        if self.exchanges.is_empty() {
            for (&local, &remote) in paths.listen.iter().zip(&paths.peers) {
                let config = self.config.clone();
                let message = heartbeat.clone();
                self.exchanges
                    .spawn(async move { peer_exchange(&config, local, remote, &message).await });
            }
        }
        let observed = self.state.lock().await.peer.clone();
        let previous = self.election.authority.clone();
        let result = self
            .election
            .step(&self.config, request, observed.as_ref(), now_ns())?;
        self.publish(
            request,
            result.1,
            vips_ready && previous == result.0.authority,
        )
        .await?;
        Ok(result)
    }
}

fn peer_key(config: &Config) -> hmac::Tag {
    let mut domain = b"Velstra two-node control v1\0".to_vec();
    domain.extend_from_slice(config.cluster.as_bytes());
    hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, config.secret.as_bytes()),
        &domain,
    )
}
async fn peer_exchange(
    config: &Config,
    local: SocketAddr,
    remote: SocketAddr,
    heartbeat: &Heartbeat,
) -> Result<Heartbeat> {
    timeout(Duration::from_millis(config.io_ms), async {
        let socket = if local.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(SocketAddr::new(local.ip(), 0))?;
        let mut stream = socket.connect(remote).await?;
        stream.set_nodelay(true)?;
        let key = peer_key(config);
        let session = crate::handshake(&mut stream, key.as_ref(), true).await?;
        crate::send(&mut stream, &session, 2, heartbeat).await?;
        crate::receive::<Heartbeat>(&mut stream, &session, 3).await
    })
    .await
    .context("HA peer exchange deadline")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const MS: u64 = 1_000_000;
    #[tokio::test]
    async fn failed_multipath_bind_releases_earlier_listener_and_preserves_cause() {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_address = first.local_addr().unwrap();
        let conflict = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let conflict_address = conflict.local_addr().unwrap();
        drop(first);
        let mut cfg = config(1);
        cfg.two_node.as_mut().unwrap().listen = vec![first_address, conflict_address];
        cfg.two_node.as_mut().unwrap().peers = vec![
            "127.0.0.2:5441".parse().unwrap(),
            "127.0.0.2:5442".parse().unwrap(),
        ];
        let error = match PeerCoordinator::start(cfg, [1; 16]).await {
            Ok(_) => panic!("occupied path must fail instead of silently dropping a path"),
            Err(error) => error,
        };
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::AddrInUse
        );
        assert!(format!("{error:#}").contains(&conflict_address.to_string()));
        let released = TcpListener::bind(first_address).await.unwrap();
        drop(released);
    }

    fn config(node: u8) -> Config {
        Config {
            cluster: "two-node-test-cluster".into(),
            node,
            mode: Mode::TwoNode,
            witness: None,
            two_node: Some(PeerConfig {
                listen: vec![format!("127.0.0.{node}:5441").parse().unwrap()],
                peers: vec![format!("127.0.0.{}:5441", 3 - node).parse().unwrap()],
                peer_timeout_ms: 1_000,
                startup_delay_ms: 2_000,
            }),
            secret: "synthetic-unit-test-key-not-a-real-credential".into(),
            priority: if node == 1 { 200 } else { 100 },
            preempt: false,
            wireguard: Vec::new(),
            wireguard_policy: String::new(),
            lease_ms: crate::TTL_MS,
            io_ms: crate::IO_MS,
        }
    }
    fn request(cfg: &Config, ready: u64) -> Request {
        Request {
            cluster: cfg.cluster.clone(),
            node: cfg.node,
            boot: [cfg.node; 16],
            agent_boot: [cfg.node + 2; 16],
            priority: cfg.priority,
            preempt: cfg.preempt,
            ready_term: ready,
            policy: [7; 32],
            eligible: true,
        }
    }
    fn authority(node: u8, term: u64) -> Authority {
        Authority {
            term,
            owner: node,
            boot: [node; 16],
            policy: [7; 32],
        }
    }
    fn observation(cfg: &Config, ready: u64, term: u64, active: bool, now: u64) -> Observation {
        Observation {
            heartbeat: Heartbeat {
                sequence: 1,
                request: request(cfg, ready),
                authority: if term > 0 {
                    authority(cfg.node, term)
                } else {
                    Authority::default()
                },
                claim: Claim {
                    ready_term: ready,
                    agent_boot: [cfg.node + 2; 16],
                },
                active,
                remaining_ms: if active { 200 } else { 0 },
            },
            heard_ns: now,
        }
    }
    fn shared(cfg: &Config) -> Shared {
        Shared {
            local: observation(cfg, 0, 0, false, 0).heartbeat,
            local_updated_ns: 0,
            local_deadline_ns: 0,
            peer: None,
            retired_boots: VecDeque::new(),
        }
    }
    fn unused_port(ip: &str) -> SocketAddr {
        std::net::TcpListener::bind(format!("{ip}:0"))
            .unwrap()
            .local_addr()
            .unwrap()
    }
    fn network_pair(paths: usize) -> (Config, Config) {
        let (mut a, mut b) = (config(1), config(2));
        let first: Vec<_> = (0..paths).map(|_| unused_port("127.0.0.1")).collect();
        let second: Vec<_> = (0..paths).map(|_| unused_port("127.0.0.2")).collect();
        a.two_node.as_mut().unwrap().listen = first.clone();
        a.two_node.as_mut().unwrap().peers = second.clone();
        b.two_node.as_mut().unwrap().listen = second;
        b.two_node.as_mut().unwrap().peers = first;
        (a, b)
    }
    #[test]
    fn defaults_preserve_legacy_witness_and_reject_mixed_authority() {
        let mut cfg = config(1);
        cfg.mode = Mode::Witness;
        cfg.witness = Some("127.0.0.1:5440".parse().unwrap());
        cfg.two_node = None;
        let mut value = serde_json::to_value(&cfg).unwrap();
        value.as_object_mut().unwrap().remove("mode");
        let decoded: Config = serde_json::from_value(value).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded.mode, Mode::Witness);
        cfg.two_node = config(1).two_node;
        assert!(cfg.validate().is_err());
        cfg.mode = Mode::TwoNode;
        assert!(cfg.validate().is_err());
        cfg.witness = None;
        cfg.validate().unwrap();
        assert!(!format!("{cfg:?}").contains(&cfg.secret));
    }
    #[test]
    fn invalid_paths_and_readiness_timing_fail_closed() {
        let baseline = config(1);
        baseline.validate().unwrap();
        for invalid in [0, 749, 1_201, 1_500, u64::MAX] {
            let mut cfg = baseline.clone();
            cfg.two_node.as_mut().unwrap().peer_timeout_ms = invalid;
            assert!(cfg.validate().is_err());
        }
        let mut cfg = baseline.clone();
        cfg.two_node.as_mut().unwrap().startup_delay_ms = 1_999;
        assert!(cfg.validate().is_err());
        let mut cfg = baseline.clone();
        let duplicate = cfg.two_node.as_ref().unwrap().listen[0];
        cfg.two_node.as_mut().unwrap().listen.push(duplicate);
        assert!(cfg.validate().is_err());
        let mut cfg = baseline.clone();
        cfg.two_node.as_mut().unwrap().peers[0] = "0.0.0.0:5441".parse().unwrap();
        assert!(cfg.validate().is_err());
        let mut cfg = baseline.clone();
        cfg.io_ms = u64::MAX;
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn cold_start_waits_and_elects_priority_then_node() {
        let a = config(1);
        let b = config(2);
        let mut engine = Election::new(0);
        let peer = observation(&b, 0, 0, false, 2_000 * MS);
        assert!(
            !engine
                .step(&a, &request(&a, 0), None, 1_999 * MS)
                .unwrap()
                .0
                .granted
        );
        let (reply, deadline) = engine
            .step(&a, &request(&a, 0), Some(&peer), 2_000 * MS)
            .unwrap();
        assert!(reply.granted);
        assert_eq!(reply.authority, authority(1, 1));
        assert_eq!(reply.claim.agent_boot, [3; 16]);
        assert!(deadline > 2_000 * MS);
        let mut loser = Election::new(0);
        let peer = observation(&a, 0, 0, false, 2_000 * MS);
        assert!(
            !loser
                .step(&b, &request(&b, 0), Some(&peer), 2_000 * MS)
                .unwrap()
                .0
                .granted
        );
        let mut tie = b.clone();
        tie.priority = 200;
        let peer = observation(&tie, 0, 0, false, 2_000 * MS);
        assert!(
            Election::new(0)
                .step(&a, &request(&a, 0), Some(&peer), 2_000 * MS)
                .unwrap()
                .0
                .granted
        );
    }
    #[test]
    fn missing_or_stale_agent_never_bootstraps_or_takes_over() {
        let cfg = config(2);
        let mut input = request(&cfg, 7);
        input.eligible = false;
        let mut engine = Election::new(0);
        engine.authority = authority(1, 7);
        assert!(
            !engine
                .step(&cfg, &input, None, 9_000 * MS)
                .unwrap()
                .0
                .granted
        );
        input.ready_term = 0;
        assert!(
            !engine
                .step(&cfg, &input, None, 20_000 * MS)
                .unwrap()
                .0
                .granted
        );
        input.eligible = true;
        input.agent_boot = [0; 16];
        assert!(engine.step(&cfg, &input, None, 21_000 * MS).is_err());
    }
    #[test]
    fn warm_failover_requires_matching_policy_and_preserves_claim() {
        let cfg = config(2);
        let peer = observation(&config(1), 7, 7, true, 100 * MS);
        let mut engine = Election::new(0);
        assert!(
            !engine
                .step(&cfg, &request(&cfg, 7), Some(&peer), 100 * MS)
                .unwrap()
                .0
                .granted
        );
        assert!(
            !engine
                .step(&cfg, &request(&cfg, 7), None, 1_099 * MS)
                .unwrap()
                .0
                .granted
        );
        let mut wrong = request(&cfg, 7);
        wrong.policy = [8; 32];
        assert!(
            !engine
                .step(&cfg, &wrong, None, 1_101 * MS)
                .unwrap()
                .0
                .granted
        );
        let (reply, _) = engine
            .step(&cfg, &request(&cfg, 7), None, 1_102 * MS)
            .unwrap();
        assert!(reply.granted);
        assert_eq!(reply.authority, authority(2, 8));
        assert_eq!(reply.claim.ready_term, 7);
        assert_eq!(reply.claim.agent_boot, [4; 16]);
    }
    #[test]
    fn healthy_incumbent_is_not_displaced_without_preemption() {
        let cfg = config(2);
        let mut engine = Election::new(0);
        let mut local = request(&cfg, 0);
        assert!(
            engine
                .step(&cfg, &local, None, 2_000 * MS)
                .unwrap()
                .0
                .granted
        );
        local.ready_term = 1;
        let peer = observation(&config(1), 1, 0, false, 2_050 * MS);
        assert!(
            engine
                .step(&cfg, &local, Some(&peer), 2_050 * MS)
                .unwrap()
                .0
                .granted
        );
        let mut challenger = Election::new(0);
        let active = observation(&cfg, 1, 1, true, 2_050 * MS);
        assert!(
            !challenger
                .step(
                    &config(1),
                    &request(&config(1), 1),
                    Some(&active),
                    2_050 * MS
                )
                .unwrap()
                .0
                .granted
        );
    }
    #[test]
    fn preemption_yields_then_waits_out_owner_before_warm_grant() {
        let owner_cfg = config(2);
        let mut owner = Election::new(0);
        owner
            .step(&owner_cfg, &request(&owner_cfg, 0), None, 2_000 * MS)
            .unwrap();
        let mut cfg = config(1);
        cfg.preempt = true;
        let challenger = request(&cfg, 1);
        let peer = observation(&cfg, 1, 0, false, 2_100 * MS);
        assert!(
            !owner
                .step(&owner_cfg, &request(&owner_cfg, 1), Some(&peer), 2_100 * MS)
                .unwrap()
                .0
                .granted
        );
        let mut backup = Election::new(0);
        let active = observation(&owner_cfg, 1, 1, true, 2_099 * MS);
        backup
            .step(&cfg, &challenger, Some(&active), 2_099 * MS)
            .unwrap();
        let mut yielded = active.clone();
        yielded.heartbeat.active = false;
        yielded.heartbeat.remaining_ms = 0;
        yielded.heard_ns = 3_050 * MS;
        assert!(
            !backup
                .step(&cfg, &challenger, Some(&yielded), 3_050 * MS)
                .unwrap()
                .0
                .granted
        );
        yielded.heard_ns = 3_100 * MS;
        assert!(
            backup
                .step(&cfg, &challenger, Some(&yielded), 3_100 * MS)
                .unwrap()
                .0
                .granted
        );
    }
    #[test]
    fn total_partition_tradeoff_and_deterministic_recovery_are_explicit() {
        let a = config(1);
        let b = config(2);
        let mut first = Election::new(0);
        let mut second = Election::new(0);
        assert!(
            first
                .step(&a, &request(&a, 0), None, 2_000 * MS)
                .unwrap()
                .0
                .granted
        );
        assert!(
            second
                .step(&b, &request(&b, 0), None, 2_000 * MS)
                .unwrap()
                .0
                .granted
        );
        let remote_b = observation(&b, 1, 1, true, 2_050 * MS);
        let remote_a = observation(&a, 1, 1, true, 2_050 * MS);
        assert!(
            first
                .step(&a, &request(&a, 1), Some(&remote_b), 2_050 * MS)
                .unwrap()
                .0
                .granted
        );
        let result = second
            .step(&b, &request(&b, 1), Some(&remote_a), 2_050 * MS)
            .unwrap();
        assert!(!result.0.granted);
        assert_eq!(result.1, 0);
        assert_eq!(result.0.authority.owner, 1);
    }
    #[test]
    fn restarted_agent_cannot_reuse_old_claim_or_cold_promote_immediately() {
        let cfg = config(1);
        let mut engine = Election::new(0);
        let original = request(&cfg, 0);
        engine.step(&cfg, &original, None, 2_000 * MS).unwrap();
        let mut restart = original.clone();
        restart.agent_boot = [42; 16];
        assert!(
            !engine
                .step(&cfg, &restart, None, 2_050 * MS)
                .unwrap()
                .0
                .granted
        );
        for at in (2_075..4_049).step_by(25) {
            assert!(
                !engine
                    .step(&cfg, &restart, None, at * MS)
                    .unwrap()
                    .0
                    .granted
            );
        }
        assert!(
            !engine
                .step(&cfg, &restart, None, 4_049 * MS)
                .unwrap()
                .0
                .granted
        );
        assert!(
            engine
                .step(&cfg, &restart, None, 4_051 * MS)
                .unwrap()
                .0
                .granted
        );
    }
    #[test]
    fn partition_collision_winner_advances_past_both_histories() {
        let a = config(1);
        let b = config(2);
        let mut first = Election::new(0);
        let mut second = Election::new(0);
        first.authority = authority(1, 5);
        first.claim = Claim {
            ready_term: 5,
            agent_boot: [3; 16],
        };
        first.deadline_ns = 3_000 * MS;
        second.authority = authority(2, 9);
        second.claim = Claim {
            ready_term: 9,
            agent_boot: [4; 16],
        };
        second.deadline_ns = 3_000 * MS;
        let old_a = observation(&a, 5, 5, true, 2_050 * MS);
        let newer_b = observation(&b, 9, 9, true, 2_050 * MS);
        let loser = second
            .step(&b, &request(&b, 9), Some(&old_a), 2_050 * MS)
            .unwrap();
        assert!(!loser.0.granted);
        assert_eq!(
            loser.0.authority.term, 9,
            "must not roll the generation backwards"
        );
        let winner = first
            .step(&a, &request(&a, 5), Some(&newer_b), 2_050 * MS)
            .unwrap();
        assert!(winner.0.granted);
        assert_eq!(winner.0.authority, authority(1, 10));
        assert_eq!(winner.0.claim.ready_term, 5);
        let current_a = observation(&a, 10, 10, true, 2_075 * MS);
        let follower = second
            .step(&b, &request(&b, 9), Some(&current_a), 2_075 * MS)
            .unwrap();
        assert!(!follower.0.granted);
        assert_eq!(follower.0.authority, authority(1, 10));
    }
    #[test]
    fn suspended_old_owner_discovers_incumbent_without_implicit_preemption() {
        let cfg = config(1);
        let mut engine = Election::new(0);
        engine
            .step(&cfg, &request(&cfg, 0), None, 2_000 * MS)
            .unwrap();
        assert!(
            !engine
                .step(&cfg, &request(&cfg, 1), None, 5_000 * MS)
                .unwrap()
                .0
                .granted
        );
        let incumbent = observation(&config(2), 2, 2, true, 5_025 * MS);
        let result = engine
            .step(&cfg, &request(&cfg, 1), Some(&incumbent), 5_025 * MS)
            .unwrap();
        assert!(!result.0.granted);
        assert_eq!(result.0.authority, authority(2, 2));
    }
    #[test]
    fn newly_observed_pending_owner_is_not_treated_as_long_dead() {
        let cfg = config(2);
        let mut engine = Election::new(0);
        let pending = observation(&config(1), 0, 1, false, 3_000 * MS);
        assert!(
            !engine
                .step(&cfg, &request(&cfg, 1), Some(&pending), 3_000 * MS)
                .unwrap()
                .0
                .granted
        );
        assert!(
            !engine
                .step(&cfg, &request(&cfg, 1), None, 3_999 * MS)
                .unwrap()
                .0
                .granted
        );
        assert!(
            engine
                .step(&cfg, &request(&cfg, 1), None, 4_001 * MS)
                .unwrap()
                .0
                .granted
        );
    }
    #[test]
    fn restarted_coordinator_cannot_reuse_previous_boot_authority() {
        let cfg = config(1);
        let mut engine = Election::new(0);
        engine.authority = authority(1, 9);
        let mut local = request(&cfg, 0);
        local.boot = [88; 16];
        assert!(!engine.step(&cfg, &local, None, 500 * MS).unwrap().0.granted);
        let result = engine.step(&cfg, &local, None, 2_001 * MS).unwrap().0;
        assert!(result.granted);
        assert_eq!(result.authority.boot, [88; 16]);
        assert_eq!(result.authority.term, 10);
    }
    #[test]
    fn clock_failure_and_term_exhaustion_fail_closed() {
        let cfg = config(1);
        let mut engine = Election::new(0);
        assert!(engine
            .step(&cfg, &request(&cfg, 0), None, u64::MAX)
            .is_err());
        engine.highest_term = u64::MAX;
        assert!(engine
            .step(&cfg, &request(&cfg, 0), None, 3_000 * MS)
            .is_err());
    }
    #[test]
    fn duplicate_sequences_never_refresh_liveness_and_retired_epochs_are_rejected() {
        let cfg = config(1);
        let mut state = shared(&cfg);
        let mut message = observation(&config(2), 0, 0, false, 0).heartbeat;
        state.observe(&cfg, message.clone(), 100).unwrap();
        state.observe(&cfg, message.clone(), 900).unwrap();
        assert_eq!(state.peer.as_ref().unwrap().heard_ns, 100);
        message.sequence = 2;
        state.observe(&cfg, message.clone(), 1_000).unwrap();
        assert_eq!(state.peer.as_ref().unwrap().heard_ns, 1_000);
        let old = message.clone();
        message.request.boot = [99; 16];
        message.sequence = 1;
        state.observe(&cfg, message, 1_100).unwrap();
        assert!(state.observe(&cfg, old, 1_200).is_err());
    }
    #[test]
    fn malformed_authenticated_members_do_not_refresh_liveness() {
        let cfg = config(1);
        let mut state = shared(&cfg);
        let mut message = observation(&config(2), 0, 0, false, 0).heartbeat;
        message.request.node = 1;
        assert!(state.observe(&cfg, message.clone(), 100).is_err());
        message.request.node = 2;
        message.active = true;
        assert!(state.observe(&cfg, message.clone(), 100).is_err());
        message.active = false;
        message.request.cluster = "different-cluster".into();
        assert!(state.observe(&cfg, message, 100).is_err());
        assert!(state.peer.is_none());
    }
    #[tokio::test]
    async fn actual_authenticated_paths_reject_wrong_keys_sources_and_replayed_sessions() {
        let (cfg, other) = network_pair(1);
        let server = PeerCoordinator::start(other.clone(), [2; 16])
            .await
            .unwrap();
        let message = observation(&cfg, 0, 0, false, 0).heartbeat;
        let local = cfg.two_node.as_ref().unwrap().listen[0];
        let remote = cfg.two_node.as_ref().unwrap().peers[0];
        let mut wrong = cfg.clone();
        wrong.secret = "different-test-credential-with-enough-bytes".into();
        assert!(peer_exchange(&wrong, local, remote, &message)
            .await
            .is_err());
        assert!(server.state.lock().await.peer.is_none());
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.3:0".parse().unwrap()).unwrap();
        let mut outsider = socket.connect(remote).await.unwrap();
        assert!(
            crate::handshake(&mut outsider, peer_key(&cfg).as_ref(), true)
                .await
                .is_err()
        );
        assert!(server.state.lock().await.peer.is_none());
        let open = || async {
            let socket = TcpSocket::new_v4().unwrap();
            socket.bind(SocketAddr::new(local.ip(), 0)).unwrap();
            socket.connect(remote).await.unwrap()
        };
        let mut first = open().await;
        let old_key = crate::handshake(&mut first, peer_key(&cfg).as_ref(), true)
            .await
            .unwrap();
        drop(first);
        let mut second = open().await;
        let _new_key = crate::handshake(&mut second, peer_key(&cfg).as_ref(), true)
            .await
            .unwrap();
        let bytes = serde_json::to_vec(&message).unwrap();
        let mut authenticated = vec![2];
        authenticated.extend_from_slice(&bytes);
        second
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .await
            .unwrap();
        second.write_all(&bytes).await.unwrap();
        second
            .write_all(hmac::sign(&old_key, &authenticated).as_ref())
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_millis(200), second.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(server.state.lock().await.peer.is_none());
        peer_exchange(&cfg, local, remote, &message).await.unwrap();
        assert!(server.state.lock().await.peer.is_some());
    }
    #[tokio::test]
    async fn actual_multipath_survives_one_listener_loss_and_warm_owner_shutdown() {
        let (a, b) = network_pair(2);
        let mut first = PeerCoordinator::start(a.clone(), [1; 16]).await.unwrap();
        let mut second = PeerCoordinator::start(b.clone(), [2; 16]).await.unwrap();
        first.listeners[0].abort();
        second.listeners[0].abort();
        let mut req_a = request(&a, 0);
        let mut req_b = request(&b, 0);
        let (mut da, mut db) = (0, 0);
        let (mut va, mut vb) = (false, false);
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut term = 0;
        while tokio::time::Instant::now() < until {
            let (ra, rb) = tokio::join!(first.step(&req_a, da, va), second.step(&req_b, db, vb));
            let (ra, rb) = (ra.unwrap(), rb.unwrap());
            (da, db) = (ra.1, rb.1);
            (va, vb) = (ra.0.granted, rb.0.granted);
            assert!(!(va && vb), "connected multipath pair elected two owners");
            if va && rb.0.authority.owner == 1 {
                term = ra.0.authority.term;
                break;
            }
            if va {
                req_a.ready_term = ra.0.authority.term;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(term > 0, "cold authenticated pair did not elect");
        req_b.ready_term = term;
        drop(first);
        let until = tokio::time::Instant::now() + Duration::from_millis(1_450);
        let mut promoted = false;
        while tokio::time::Instant::now() < until {
            let result = second.step(&req_b, db, vb).await.unwrap();
            db = result.1;
            vb = result.0.granted;
            if vb {
                assert_eq!(result.0.claim.ready_term, term);
                assert_eq!(result.0.claim.agent_boot, req_b.agent_boot);
                assert_eq!(result.0.authority.term, term + 1);
                promoted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            promoted,
            "warm failover missed pinned replica readiness budget"
        );
    }
}
