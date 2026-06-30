//! # The VRRP runner (RFC 5798)
//!
//! Drives one or more virtual routers ([`wren_vrrp`]) over the wire: a raw
//! `IPPROTO_VRRP` (112) socket per interface, joined to the VRRP multicast group
//! `224.0.0.18` with TTL 255, sends and receives advertisements, and turns the
//! state machine's [`Action`]s into kernel effects — assigning the virtual IP with
//! netlink ([`wren_netlink::add_address`]) and announcing it with a gratuitous ARP
//! when it becomes master, removing it when it becomes backup.
//!
//! One task owns every instance: per-instance reader tasks parse and validate
//! advertisements into a shared channel, and the central loop runs the FSMs, the
//! two timers (advertisement / master-down) and the `show vrrp` query channel.
//!
//! Scope: IPv4. The codec ([`wren_vrrp::packet`]) and FSM are already dual-stack;
//! the IPv6 runner (multicast `ff02::12`, unsolicited neighbor advertisement
//! instead of gratuitous ARP) is the natural follow-on.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::FromRawFd;
use std::os::raw::c_void;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use wren_vrrp::packet::MCAST_V4;
use wren_vrrp::{Action, Advertisement, Vrrp, VrrpConfig};

use crate::sockopt::{setsockopt_int, setsockopt_struct};

/// IANA protocol number for VRRP.
const VRRP_PROTO: i32 = 112;
/// The required TTL for VRRP advertisements (RFC 5798 §5.1.1.3) — a receiver MUST
/// drop anything lower, which scopes VRRP to the local link.
const VRRP_TTL: i32 = 255;
/// EtherType for ARP, for the gratuitous-ARP AF_PACKET socket.
const ETH_P_ARP: u16 = 0x0806;

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
    /// The virtual IPv4 address(es).
    pub addresses: Vec<Ipv4Addr>,
    /// The prefix length to assign each virtual address with.
    pub prefix_len: u8,
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
    primary: Ipv4Addr,
    prefix_len: u8,
    addresses: Vec<Ipv4Addr>,
    sock: Arc<UdpSocket>,
    mac: [u8; 6],
    /// When the next advertisement is due (Master only).
    adver_deadline: Option<Instant>,
    /// When the master is declared down (Backup only).
    master_down_deadline: Option<Instant>,
}

/// Run every configured virtual router until cancelled. `queries` answers
/// `show vrrp`.
pub async fn run(configs: Vec<InstanceConfig>, mut queries: mpsc::Receiver<VrrpQueryRequest>) -> Result<()> {
    let (adv_tx, mut adv_rx) = mpsc::channel::<AdvIn>(256);
    let mut instances: Vec<Instance> = Vec::new();

    for (idx, cfg) in configs.into_iter().enumerate() {
        let (ifindex, std_sock) = open_vrrp_socket(&cfg.interface)
            .with_context(|| format!("opening VRRP socket on {:?}", cfg.interface))?;
        let sock = Arc::new(UdpSocket::from_std(std_sock).context("registering VRRP socket")?);
        let primary = iface_primary_v4(&cfg.interface).unwrap_or(Ipv4Addr::UNSPECIFIED);
        let mac = read_mac(&cfg.interface).unwrap_or([0; 6]);
        let fsm = Vrrp::new(VrrpConfig {
            vrid: cfg.vrid,
            priority: cfg.priority,
            advert_int_cs: cfg.advert_int_cs,
            preempt: cfg.preempt,
            local_primary: IpAddr::V4(primary),
            addresses: cfg.addresses.iter().map(|a| IpAddr::V4(*a)).collect(),
        });

        // A reader task validates advertisements into the shared channel.
        let rsock = sock.clone();
        let tx = adv_tx.clone();
        let vrid = cfg.vrid;
        tokio::spawn(async move { read_loop(idx, rsock, vrid, tx).await });

        let mut inst = Instance {
            fsm,
            ifname: cfg.interface,
            ifindex,
            primary,
            prefix_len: cfg.prefix_len,
            addresses: cfg.addresses,
            sock,
            mac,
            adver_deadline: None,
            master_down_deadline: None,
        };
        info!(
            vrid = inst.fsm.vrid(),
            interface = %inst.ifname,
            priority = inst.fsm.priority(),
            "VRRP virtual router starting",
        );
        let actions = inst.fsm.on_startup();
        apply_actions(&mut inst, actions).await;
        instances.push(inst);
    }
    drop(adv_tx); // the reader tasks hold their own clones

    loop {
        let next = next_deadline(&instances);
        let timer = async {
            match next {
                Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
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

/// Build and multicast one advertisement with the given priority.
async fn send_advert(inst: &Instance, priority: u8) {
    let adv = Advertisement {
        vrid: inst.fsm.vrid(),
        priority,
        max_adver_int_cs: inst.fsm.advert_int_cs(),
        addresses: inst.addresses.iter().map(|a| IpAddr::V4(*a)).collect(),
    };
    let bytes = adv.encode(IpAddr::V4(inst.primary), IpAddr::V4(MCAST_V4));
    let dst = SocketAddr::V4(SocketAddrV4::new(MCAST_V4, 0));
    if let Err(e) = inst.sock.send_to(&bytes, dst).await {
        warn!(vrid = inst.fsm.vrid(), error = %e, "sending VRRP advertisement");
    }
}

/// Assume the virtual IP(s): add each to the interface and gratuitously ARP it.
fn assume_vip(inst: &Instance) {
    info!(vrid = inst.fsm.vrid(), interface = %inst.ifname, "becoming MASTER — assuming virtual IP(s)");
    for vip in &inst.addresses {
        match wren_netlink::add_address(&inst.ifname, IpAddr::V4(*vip), inst.prefix_len) {
            Ok(()) => debug!(%vip, "virtual IP assigned"),
            Err(e) => warn!(%vip, error = %e, "assigning virtual IP"),
        }
        if let Err(e) = send_gratuitous_arp(inst.ifindex, inst.mac, *vip) {
            debug!(%vip, error = %e, "gratuitous ARP failed (best-effort)");
        }
    }
}

/// Release the virtual IP(s): remove each from the interface.
fn release_vip(inst: &Instance) {
    info!(vrid = inst.fsm.vrid(), interface = %inst.ifname, "becoming BACKUP — releasing virtual IP(s)");
    for vip in &inst.addresses {
        // A delete of an address we never held (or already lost) is harmless.
        if let Err(e) = wren_netlink::del_address(&inst.ifname, IpAddr::V4(*vip), inst.prefix_len) {
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
        "{:<5} {:<10} {:<11} {:>8}  {:<16} virtual-ips",
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
            "{:<5} {:<10} {:<11} {:>8}  {:<16} {}",
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
async fn read_loop(idx: usize, sock: Arc<UdpSocket>, vrid: u8, tx: mpsc::Sender<AdvIn>) {
    let mut buf = [0u8; 1500];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                debug!(error = %e, "VRRP recv");
                continue;
            }
        };
        let src = peer.ip();
        // The raw IPv4 socket delivers the IP header; skip it to reach the VRRP
        // message, then verify the pseudo-header checksum against src/multicast dst.
        let Some(payload) = ipv4_payload(&buf[..n]) else { continue };
        if !Advertisement::verify_checksum(payload, src, IpAddr::V4(MCAST_V4)) {
            debug!(%src, "VRRP advertisement failed checksum");
            continue;
        }
        let adv = match Advertisement::decode(payload, false) {
            Ok(a) => a,
            Err(e) => {
                debug!(%src, error = %e, "malformed VRRP advertisement");
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

/// Open a raw `IPPROTO_VRRP` socket bound to `ifname`, joined to `224.0.0.18` with
/// the egress interface and TTL 255 set. Needs `CAP_NET_RAW`.
fn open_vrrp_socket(ifname: &str) -> Result<(u32, std::net::UdpSocket)> {
    let cname = std::ffi::CString::new(ifname).context("interface name has an interior NUL")?;
    // SAFETY: `cname` is valid for the duration of the call.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("interface {ifname:?} not found");
    }
    // SAFETY: a raw socket; the fd is taken into ownership immediately below.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            VRRP_PROTO,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("socket(AF_INET, SOCK_RAW, 112) — needs CAP_NET_RAW");
    }
    // SAFETY: `fd` was just returned by socket() and is owned by nobody else.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

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

    // Join the VRRP group on this interface and pin multicast egress to it.
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

    Ok((ifindex, sock))
}

/// The primary IPv4 address of `ifname` (the first global one), via `getifaddrs`.
fn iface_primary_v4(ifname: &str) -> Option<Ipv4Addr> {
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
            let sa = unsafe { &*node.ifa_addr };
            if name.to_bytes() == ifname.as_bytes() && sa.sa_family as i32 == libc::AF_INET {
                // SAFETY: AF_INET sockaddr is a sockaddr_in.
                let sin = unsafe { &*(node.ifa_addr as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if !ip.is_loopback() && !ip.is_unspecified() {
                    result = Some(ip);
                    break;
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

/// Broadcast a gratuitous ARP for `vip` from `mac` on the interface, so switches
/// and hosts relearn the virtual IP at this router after a failover. Best-effort.
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

    // SAFETY: `arp` and `sll` are valid for the call; sizes match the structs.
    let sent = unsafe {
        libc::sendto(
            fd,
            arp.as_ptr() as *const c_void,
            arp.len(),
            0,
            &sll as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    // SAFETY: closing the fd we opened.
    unsafe { libc::close(fd) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
