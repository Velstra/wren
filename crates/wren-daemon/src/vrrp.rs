//! # The VRRP runner (RFC 5798) — dual-stack
//!
//! Drives one or more virtual routers ([`wren_vrrp`]) over the wire: a raw
//! `IPPROTO_VRRP` (112) socket per interface — IPv4 to `224.0.0.18` or IPv6 to
//! `ff02::12`, TTL/hop-limit 255 — sends and receives advertisements, and turns
//! the state machine's [`Action`]s into kernel effects: assigning the virtual IP
//! with netlink ([`wren_netlink::add_address`]) and announcing it when it becomes
//! master — a **gratuitous ARP** for IPv4, an **unsolicited neighbor
//! advertisement** for IPv6 — removing it when it becomes backup.
//!
//! One task owns every instance: per-instance reader tasks parse and validate
//! advertisements into a shared channel, and the central loop runs the FSMs, the
//! two timers (advertisement / master-down) and the `show vrrp` query channel.
//! Each instance is single-family (its virtual addresses are all IPv4 or all
//! IPv6); an IPv6 virtual router sources its advertisements from the interface's
//! link-local address, as the RFC requires.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::FromRawFd;
use std::os::raw::c_void;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use wren_vrrp::packet::{MCAST_V4, MCAST_V6};
use wren_vrrp::{Action, Advertisement, Vrrp, VrrpConfig};

use crate::sockopt::{setsockopt_int, setsockopt_struct};

/// IANA protocol number for VRRP.
const VRRP_PROTO: i32 = 112;
/// The required TTL/hop-limit for VRRP advertisements (RFC 5798 §5.1.1.3) — a
/// receiver MUST drop anything lower, which scopes VRRP to the local link.
const VRRP_TTL: i32 = 255;
/// EtherType for ARP, for the gratuitous-ARP AF_PACKET socket.
const ETH_P_ARP: u16 = 0x0806;
/// The IPv6 all-nodes multicast group, the destination for an unsolicited NA.
const ALL_NODES_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// One virtual router as resolved by `main.rs` from `[[vrrp]]`.
pub struct InstanceConfig {
    /// The interface the virtual router runs on.
    pub interface: String,
    /// Virtual Router ID (1–255).
    pub vrid: u8,
    /// Our priority (1–255; 255 = address owner).
    pub priority: u8,
    /// Advertisement interval in centiseconds.
    pub advert_int_cs: u16,
    /// Whether to preempt a lower-priority master.
    pub preempt: bool,
    /// The virtual IP address(es) — all of one family.
    pub addresses: Vec<IpAddr>,
    /// The prefix length to assign each virtual address with.
    pub prefix_len: u8,
    /// Interfaces to track: while any is down, the effective priority drops by
    /// `priority_decrement` so a healthier peer can take over.
    pub track_interfaces: Vec<String>,
    /// How much to subtract from the base priority while a tracked interface is down.
    pub priority_decrement: u8,
}

/// A read-only `show vrrp` query, answered from the instances the runner owns.
#[derive(Debug)]
pub enum VrrpQuery {
    /// List every virtual router and its state.
    Instances,
}

/// A [`VrrpQuery`] paired with the channel to answer it on.
pub type VrrpQueryRequest = crate::query::QueryRequest<VrrpQuery>;

/// A validated advertisement forwarded from a reader task to the central loop.
struct AdvIn {
    idx: usize,
    priority: u8,
    adver_int_cs: u16,
    src: IpAddr,
}

/// One running virtual router: its FSM, socket, interface facts and timers.
struct Instance {
    fsm: Vrrp,
    ifname: String,
    ifindex: u32,
    primary: IpAddr,
    prefix_len: u8,
    addresses: Vec<IpAddr>,
    ipv6: bool,
    sock: Arc<UdpSocket>,
    mac: [u8; 6],
    /// The configured priority before any tracking penalty.
    base_priority: u8,
    /// Interfaces whose state lowers the effective priority while down.
    track_interfaces: Vec<String>,
    /// The penalty applied while any tracked interface is down.
    priority_decrement: u8,
    /// Whether a tracked interface was down at the last poll (to log transitions).
    tracked_down: bool,
    /// When the next advertisement is due (Master only).
    adver_deadline: Option<Instant>,
    /// When the master is declared down (Backup only).
    master_down_deadline: Option<Instant>,
}

/// Run every configured virtual router until cancelled. `queries` answers
/// `show vrrp`.
pub async fn run(
    configs: Vec<InstanceConfig>,
    mut queries: mpsc::Receiver<VrrpQueryRequest>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let (adv_tx, mut adv_rx) = mpsc::channel::<AdvIn>(256);
    let mut instances: Vec<Instance> = Vec::new();

    for (idx, cfg) in configs.into_iter().enumerate() {
        let ipv6 = cfg.addresses.first().is_some_and(|a| a.is_ipv6());
        let (ifindex, std_sock) = open_vrrp_socket(&cfg.interface, ipv6)
            .with_context(|| format!("opening VRRP socket on {:?}", cfg.interface))?;
        let sock = Arc::new(UdpSocket::from_std(std_sock).context("registering VRRP socket")?);
        let primary = iface_primary(&cfg.interface, ipv6).unwrap_or(if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        });
        let mac = read_mac(&cfg.interface).unwrap_or([0; 6]);
        let fsm = Vrrp::new(VrrpConfig {
            vrid: cfg.vrid,
            priority: cfg.priority,
            advert_int_cs: cfg.advert_int_cs,
            preempt: cfg.preempt,
            local_primary: primary,
            addresses: cfg.addresses.clone(),
        });

        // A reader task validates advertisements into the shared channel.
        let rsock = sock.clone();
        let tx = adv_tx.clone();
        let vrid = cfg.vrid;
        tokio::spawn(async move { read_loop(idx, rsock, vrid, ipv6, tx).await });

        let mut inst = Instance {
            fsm,
            ifname: cfg.interface,
            ifindex,
            primary,
            prefix_len: cfg.prefix_len,
            addresses: cfg.addresses,
            ipv6,
            sock,
            mac,
            base_priority: cfg.priority,
            track_interfaces: cfg.track_interfaces,
            priority_decrement: cfg.priority_decrement,
            tracked_down: false,
            adver_deadline: None,
            master_down_deadline: None,
        };
        info!(
            vrid = inst.fsm.vrid(),
            interface = %inst.ifname,
            priority = inst.fsm.priority(),
            family = if ipv6 { "ipv6" } else { "ipv4" },
            "VRRP virtual router starting",
        );
        let actions = inst.fsm.on_startup();
        apply_actions(&mut inst, actions).await;
        instances.push(inst);
    }
    drop(adv_tx); // the reader tasks hold their own clones

    // Re-evaluate tracked interfaces once a second, adjusting effective priority.
    let mut track_poll = tokio::time::interval(Duration::from_secs(1));

    loop {
        let next = next_deadline(&instances);
        let timer = async {
            match next {
                Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            // Graceful shutdown (M10): relinquish mastership immediately by
            // advertising priority 0 (RFC 5798 §6.4.3) so a Backup takes over
            // now instead of after the master-down interval, then exit.
            _ = shutdown.changed() => {
                info!("VRRP shutting down; releasing mastership (priority 0)");
                for inst in instances.iter_mut() {
                    let actions = inst.fsm.on_shutdown();
                    apply_actions(inst, actions).await;
                }
                return Ok(());
            }
            _ = track_poll.tick() => {
                for inst in instances.iter_mut() {
                    poll_tracking(inst).await;
                }
            }
            Some(adv) = adv_rx.recv() => {
                if let Some(inst) = instances.get_mut(adv.idx) {
                    let actions = inst.fsm.on_advertisement(adv.priority, adv.adver_int_cs, adv.src);
                    apply_actions(inst, actions).await;
                }
            }
            _ = timer => {
                let now = Instant::now();
                for inst in instances.iter_mut() {
                    // Fire whichever timer is due; clear it first so a missing
                    // re-arm cannot busy-loop.
                    if inst.adver_deadline.is_some_and(|d| now >= d) {
                        inst.adver_deadline = None;
                        let actions = inst.fsm.on_adver_timer();
                        apply_actions(inst, actions).await;
                    }
                    if inst.master_down_deadline.is_some_and(|d| now >= d) {
                        inst.master_down_deadline = None;
                        let actions = inst.fsm.on_master_down_timer();
                        apply_actions(inst, actions).await;
                    }
                }
            }
            Some(req) = queries.recv() => {
                let _ = req.respond.send(render_instances(&instances));
            }
        }
    }
}

/// The earliest of all instances' armed timers, or `None` if none is armed.
fn next_deadline(instances: &[Instance]) -> Option<Instant> {
    instances
        .iter()
        .flat_map(|i| [i.adver_deadline, i.master_down_deadline])
        .flatten()
        .min()
}

/// Carry one transition's [`Action`]s into the kernel and timers.
async fn apply_actions(inst: &mut Instance, actions: Vec<Action>) {
    for action in actions {
        match action {
            Action::SendAdvert => send_advert(inst, inst.fsm.priority()).await,
            Action::SendAdvertZero => send_advert(inst, 0).await,
            Action::AssumeVip => assume_vip(inst),
            Action::ReleaseVip => release_vip(inst),
            Action::ArmAdverTimer(cs) => {
                inst.adver_deadline = Some(Instant::now() + cs_to_dur(cs));
                inst.master_down_deadline = None; // mutually exclusive with backup
            }
            Action::ArmMasterDownTimer(cs) => {
                inst.master_down_deadline = Some(Instant::now() + cs_to_dur(cs));
                inst.adver_deadline = None;
            }
            Action::CancelAdverTimer => inst.adver_deadline = None,
            Action::CancelMasterDownTimer => inst.master_down_deadline = None,
        }
    }
}

/// Re-evaluate this instance's tracked interfaces and adjust its effective
/// priority: while any tracked interface is down, subtract `priority_decrement`
/// (clamped to at least 1). A change is pushed into the FSM, which re-advertises
/// if it is master so a healthier peer can preempt.
async fn poll_tracking(inst: &mut Instance) {
    if inst.track_interfaces.is_empty() {
        return;
    }
    let any_down = inst.track_interfaces.iter().any(|i| !iface_running(i));
    if any_down != inst.tracked_down {
        inst.tracked_down = any_down;
        info!(
            vrid = inst.fsm.vrid(),
            interface = %inst.ifname,
            tracked_down = any_down,
            "VRRP tracked-interface state changed",
        );
    }
    let effective = if any_down {
        inst.base_priority.saturating_sub(inst.priority_decrement).max(1)
    } else {
        inst.base_priority
    };
    let actions = inst.fsm.set_priority(effective);
    apply_actions(inst, actions).await;
}

/// The VRRP multicast destination for this instance's family.
fn mcast(ipv6: bool) -> IpAddr {
    if ipv6 {
        IpAddr::V6(MCAST_V6)
    } else {
        IpAddr::V4(MCAST_V4)
    }
}

/// Build and multicast one advertisement with the given priority.
async fn send_advert(inst: &Instance, priority: u8) {
    let dst_ip = mcast(inst.ipv6);
    let adv = Advertisement {
        vrid: inst.fsm.vrid(),
        priority,
        max_adver_int_cs: inst.fsm.advert_int_cs(),
        addresses: inst.addresses.clone(),
    };
    let bytes = adv.encode(inst.primary, dst_ip);
    let dst = match dst_ip {
        IpAddr::V4(a) => SocketAddr::V4(SocketAddrV4::new(a, 0)),
        IpAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(a, 0, 0, inst.ifindex)),
    };
    if let Err(e) = inst.sock.send_to(&bytes, dst).await {
        warn!(vrid = inst.fsm.vrid(), error = %e, "sending VRRP advertisement");
    }
}

/// Assume the virtual IP(s): add each to the interface and announce it (gratuitous
/// ARP for IPv4, unsolicited neighbor advertisement for IPv6).
fn assume_vip(inst: &Instance) {
    info!(vrid = inst.fsm.vrid(), interface = %inst.ifname, "becoming MASTER — assuming virtual IP(s)");
    for vip in &inst.addresses {
        match wren_netlink::add_address(&inst.ifname, *vip, inst.prefix_len) {
            Ok(()) => debug!(%vip, "virtual IP assigned"),
            Err(e) => warn!(%vip, error = %e, "assigning virtual IP"),
        }
        let announced = match vip {
            IpAddr::V4(v4) => send_gratuitous_arp(inst.ifindex, inst.mac, *v4),
            IpAddr::V6(v6) => send_unsolicited_na(inst.ifindex, inst.mac, *v6),
        };
        if let Err(e) = announced {
            debug!(%vip, error = %e, "virtual-IP announcement failed (best-effort)");
        }
    }
}

/// Release the virtual IP(s): remove each from the interface.
fn release_vip(inst: &Instance) {
    info!(vrid = inst.fsm.vrid(), interface = %inst.ifname, "becoming BACKUP — releasing virtual IP(s)");
    for vip in &inst.addresses {
        // A delete of an address we never held (or already lost) is harmless.
        if let Err(e) = wren_netlink::del_address(&inst.ifname, *vip, inst.prefix_len) {
            debug!(%vip, error = %e, "releasing virtual IP (may already be gone)");
        }
    }
}

/// Convert centiseconds to a `Duration`.
fn cs_to_dur(cs: u16) -> Duration {
    Duration::from_millis(cs as u64 * 10)
}

/// Render `show vrrp` as an aligned table.
fn render_instances(instances: &[Instance]) -> String {
    use std::fmt::Write as _;
    if instances.is_empty() {
        return "no vrrp instances\n".to_string();
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<5} {:<10} {:<11} {:>8}  {:<22} virtual-ips",
        "vrid", "interface", "state", "priority", "master"
    );
    for inst in instances {
        let master = match inst.fsm.master_addr() {
            Some(a) => a.to_string(),
            None => "-".to_string(),
        };
        let vips = inst
            .addresses
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "{:<5} {:<10} {:<11} {:>8}  {:<22} {}",
            inst.fsm.vrid(),
            inst.ifname,
            inst.fsm.state().name(),
            inst.fsm.priority(),
            master,
            vips,
        );
    }
    out
}

/// Read, validate and forward advertisements for one instance to the central loop.
async fn read_loop(idx: usize, sock: Arc<UdpSocket>, vrid: u8, ipv6: bool, tx: mpsc::Sender<AdvIn>) {
    let mut buf = [0u8; 1500];
    let dst = mcast(ipv6);
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                debug!(error = %e, "VRRP recv");
                continue;
            }
        };
        let src = peer.ip();
        // An IPv4 raw socket delivers the IP header (skip it by IHL); an IPv6 raw
        // socket delivers the VRRP message directly.
        let payload = if ipv6 {
            &buf[..n]
        } else {
            match ipv4_payload(&buf[..n]) {
                Some(p) => p,
                None => continue,
            }
        };
        // Verify-then-decode in one step: `decode_verified` makes the pseudo-header
        // checksum a precondition of obtaining an Advertisement, so a spoofed advert
        // can never be acted on (a wrong checksum surfaces as DecodeError::Checksum).
        let adv = match Advertisement::decode_verified(payload, ipv6, src, dst) {
            Ok(a) => a,
            Err(e) => {
                debug!(%src, error = %e, "rejected VRRP advertisement");
                continue;
            }
        };
        if adv.vrid != vrid {
            continue; // a different virtual router on the same link
        }
        if tx
            .send(AdvIn {
                idx,
                priority: adv.priority,
                adver_int_cs: adv.max_adver_int_cs,
                src,
            })
            .await
            .is_err()
        {
            return; // central loop gone
        }
    }
}

/// Return the payload of a raw IPv4 datagram (skip the IP header by its IHL).
fn ipv4_payload(buf: &[u8]) -> Option<&[u8]> {
    if buf.is_empty() || (buf[0] >> 4) != 4 {
        return None;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    Some(&buf[ihl..])
}

/// Open a raw `IPPROTO_VRRP` socket bound to `ifname`, joined to the VRRP multicast
/// group (`224.0.0.18` / `ff02::12`) with the egress interface and TTL/hop-limit
/// 255 set. Needs `CAP_NET_RAW`.
fn open_vrrp_socket(ifname: &str, ipv6: bool) -> Result<(u32, std::net::UdpSocket)> {
    let cname = std::ffi::CString::new(ifname).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is valid for the duration of the call.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {ifname:?} not found");
    }
    let family = if ipv6 { libc::AF_INET6 } else { libc::AF_INET };
    // SAFETY: a raw socket; the fd is taken into ownership immediately below.
    let fd = unsafe {
        libc::socket(
            family,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            VRRP_PROTO,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("socket(SOCK_RAW, 112) — needs CAP_NET_RAW");
    }
    // SAFETY: `fd` was just returned by socket() and is owned by nobody else.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    bind_to_device(fd, ifname)?;
    if ipv6 {
        // SAFETY: ipv6_mreq is plain POD; we set the group and interface index.
        let mut mreq: libc::ipv6_mreq = unsafe { mem::zeroed() };
        mreq.ipv6mr_multiaddr.s6_addr = MCAST_V6.octets();
        mreq.ipv6mr_interface = ifindex;
        setsockopt_struct(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &mreq)
            .context("IPV6_ADD_MEMBERSHIP ff02::12")?;
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, ifindex as i32)
            .context("IPV6_MULTICAST_IF")?;
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, 0)?;
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, VRRP_TTL)?;
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, VRRP_TTL)?;
    } else {
        // SAFETY: ip_mreqn is plain POD; we set the group and interface index.
        let mut mreq: libc::ip_mreqn = unsafe { mem::zeroed() };
        mreq.imr_multiaddr.s_addr = u32::from(MCAST_V4).to_be();
        mreq.imr_ifindex = ifindex as libc::c_int;
        setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &mreq)
            .context("IP_ADD_MEMBERSHIP 224.0.0.18")?;
        // SAFETY: ip_mreqn is plain POD; only the interface index matters here.
        let mut ifreq: libc::ip_mreqn = unsafe { mem::zeroed() };
        ifreq.imr_ifindex = ifindex as libc::c_int;
        setsockopt_struct(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &ifreq).context("IP_MULTICAST_IF")?;
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, 0)?;
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, VRRP_TTL)?;
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL, VRRP_TTL)?;
    }

    Ok((ifindex, sock))
}

/// `SO_BINDTODEVICE ifname` on `fd`.
fn bind_to_device(fd: i32, ifname: &str) -> Result<()> {
    // SAFETY: `ifname` bytes + length describe a valid optval buffer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            ifname.as_ptr() as *const c_void,
            ifname.len() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("SO_BINDTODEVICE {ifname:?}"));
    }
    Ok(())
}

/// The primary address of `ifname` for the family: the first global IPv4, or the
/// interface's IPv6 link-local (the source VRRPv3 uses for IPv6 advertisements).
fn iface_primary(ifname: &str, ipv6: bool) -> Option<IpAddr> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list into `head`, freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut result = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let node = unsafe { &*cur };
        if !node.ifa_addr.is_null() {
            // SAFETY: ifa_name is a valid C string; ifa_addr points at a sockaddr.
            let name = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) };
            let fam = unsafe { (*node.ifa_addr).sa_family } as i32;
            if name.to_bytes() == ifname.as_bytes() {
                if !ipv6 && fam == libc::AF_INET {
                    // SAFETY: AF_INET sockaddr is a sockaddr_in.
                    let sin = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in) };
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        result = Some(IpAddr::V4(ip));
                        break;
                    }
                } else if ipv6 && fam == libc::AF_INET6 {
                    // SAFETY: AF_INET6 sockaddr is a sockaddr_in6.
                    let sin6 = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in6) };
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    // VRRPv3 IPv6 advertisements are sourced from the link-local.
                    if (ip.segments()[0] & 0xffc0) == 0xfe80 {
                        result = Some(IpAddr::V6(ip));
                        break;
                    }
                }
            }
        }
        cur = node.ifa_next;
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    result
}

/// Read the MAC of `ifname` via the namespace-aware `SIOCGIFHWADDR` ioctl.
fn read_mac(ifname: &str) -> Option<[u8; 6]> {
    const SIOCGIFHWADDR: libc::c_ulong = 0x8927;
    let name = ifname.as_bytes();
    if name.len() >= libc::IF_NAMESIZE {
        return None;
    }
    // SAFETY: a plain datagram socket to carry the ioctl; closed below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name);
    // SAFETY: `ifr` is a 40-byte `ifreq` buffer; SIOCGIFHWADDR fills it in place.
    let rc = unsafe { libc::ioctl(fd, SIOCGIFHWADDR, ifr.as_mut_ptr()) };
    let mac = if rc == 0 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&ifr[18..24]); // 16 (name) + 2 (sa_family) → sa_data
        Some(m)
    } else {
        None
    };
    // SAFETY: closing the fd we opened.
    unsafe { libc::close(fd) };
    mac
}

/// Whether `ifname` is operationally up (`IFF_UP` && `IFF_RUNNING`), via the
/// namespace-aware `SIOCGIFFLAGS` ioctl. A missing or unreadable interface counts
/// as down.
fn iface_running(ifname: &str) -> bool {
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const IFF_UP: u16 = 0x1;
    const IFF_RUNNING: u16 = 0x40;
    let name = ifname.as_bytes();
    if name.len() >= libc::IF_NAMESIZE {
        return false;
    }
    // SAFETY: a plain datagram socket to carry the ioctl; closed below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return false;
    }
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name);
    // SAFETY: `ifr` is a 40-byte `ifreq` buffer; SIOCGIFFLAGS fills the flags field.
    let rc = unsafe { libc::ioctl(fd, SIOCGIFFLAGS, ifr.as_mut_ptr()) };
    let up = if rc == 0 {
        let flags = u16::from_ne_bytes([ifr[16], ifr[17]]); // ifr_flags after the 16-byte name
        (flags & IFF_UP) != 0 && (flags & IFF_RUNNING) != 0
    } else {
        false
    };
    // SAFETY: closing the fd we opened.
    unsafe { libc::close(fd) };
    up
}

/// Broadcast a gratuitous ARP for `vip` from `mac`, so switches and hosts relearn
/// the virtual IP at this router after a failover. Best-effort.
fn send_gratuitous_arp(ifindex: u32, mac: [u8; 6], vip: Ipv4Addr) -> io::Result<()> {
    // SAFETY: an AF_PACKET datagram socket for ARP; closed below.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            (ETH_P_ARP.to_be()) as i32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // ARP payload: a "request" for our own IP (the canonical gratuitous ARP).
    let mut arp = [0u8; 28];
    arp[0..2].copy_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
    arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
    arp[4] = 6; // hlen
    arp[5] = 4; // plen
    arp[6..8].copy_from_slice(&1u16.to_be_bytes()); // oper: request
    arp[8..14].copy_from_slice(&mac); // sender hardware address
    arp[14..18].copy_from_slice(&vip.octets()); // sender protocol address
    // target hardware address left zero; target protocol address = our VIP.
    arp[24..28].copy_from_slice(&vip.octets());

    // Destination: the broadcast MAC, via sockaddr_ll.
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ETH_P_ARP.to_be();
    sll.sll_ifindex = ifindex as i32;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&[0xff; 6]);

    let rc = sendto_sockaddr(fd, &arp, &sll as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_ll>());
    // SAFETY: closing the fd we opened.
    unsafe { libc::close(fd) };
    rc
}

/// Send an unsolicited ICMPv6 neighbor advertisement for `vip` to the all-nodes
/// group, so IPv6 hosts relearn the virtual IP at this router. Best-effort. The
/// kernel computes the ICMPv6 checksum for a raw IPPROTO_ICMPV6 socket.
fn send_unsolicited_na(ifindex: u32, mac: [u8; 6], vip: Ipv6Addr) -> io::Result<()> {
    // SAFETY: a raw ICMPv6 socket; closed below.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMPV6,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // NDP requires a hop limit of 255; pin egress to the interface.
    let _ = setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, VRRP_TTL);
    let _ = setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, ifindex as i32);

    // Neighbor Advertisement (RFC 4861 §4.4): override flag set, target = the VIP,
    // with a Target Link-Layer Address option carrying our MAC.
    let mut na = [0u8; 32];
    na[0] = 136; // type: Neighbor Advertisement
    na[1] = 0; // code; na[2..4] checksum left zero (kernel fills)
    na[4] = 0x20; // flags: Override
    na[8..24].copy_from_slice(&vip.octets()); // target address
    na[24] = 2; // option: Target Link-Layer Address
    na[25] = 1; // length in 8-octet units
    na[26..32].copy_from_slice(&mac);

    // Destination: ff02::1 (all nodes) on this interface.
    let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as u16;
    sa.sin6_addr.s6_addr = ALL_NODES_V6.octets();
    sa.sin6_scope_id = ifindex;

    let rc = sendto_sockaddr(fd, &na, &sa as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_in6>());
    // SAFETY: closing the fd we opened.
    unsafe { libc::close(fd) };
    rc
}

/// `sendto(fd, buf, 0, addr, addrlen)`, mapping a negative return to an error.
fn sendto_sockaddr(fd: i32, buf: &[u8], addr: *const libc::sockaddr, addrlen: usize) -> io::Result<()> {
    // SAFETY: `buf` and `addr` are valid for the call; `addrlen` matches the struct.
    let sent = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const c_void,
            buf.len(),
            0,
            addr,
            addrlen as libc::socklen_t,
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Parse a control command into a [`VrrpQuery`]: `show vrrp` (the only view).
pub fn parse_vrrp_query(line: &str) -> Option<VrrpQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "vrrp" {
        return None;
    }
    match tokens.next() {
        None | Some("instances") | Some("instance") => {
            if tokens.next().is_some() {
                return None;
            }
            Some(VrrpQuery::Instances)
        }
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_payload_skips_the_header_by_ihl() {
        // A minimal 20-byte IPv4 header (IHL 5) followed by two payload bytes.
        let mut pkt = vec![0x45u8]; // version 4, IHL 5
        pkt.extend_from_slice(&[0u8; 19]);
        pkt.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(ipv4_payload(&pkt), Some(&[0xaa, 0xbb][..]));
        // A non-IPv4 first nibble is rejected.
        assert_eq!(ipv4_payload(&[0x60]), None);
        // Truncated below the claimed header length.
        assert_eq!(ipv4_payload(&[0x46, 0, 0]), None);
    }

    #[test]
    fn parse_vrrp_query_understands_show_vrrp() {
        assert!(matches!(parse_vrrp_query("show vrrp"), Some(VrrpQuery::Instances)));
        assert!(matches!(
            parse_vrrp_query("show vrrp instances"),
            Some(VrrpQuery::Instances)
        ));
        assert!(parse_vrrp_query("show bgp").is_none());
        assert!(parse_vrrp_query("show vrrp nonsense").is_none());
        assert!(parse_vrrp_query("show vrrp instances extra").is_none());
    }
}
