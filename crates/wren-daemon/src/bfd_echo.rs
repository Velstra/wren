//! BFD Echo (RFC 5880 §6.4) — the loopback liveness check that exercises the
//! neighbour's forwarding plane without its BFD software.
//!
//! An Echo packet is sent **out of the wire to the neighbour's MAC** but with an IP
//! destination of *our own* address, so the neighbour's data plane forwards it
//! straight back to us (it never reaches the neighbour's BFD). The payload is a local
//! matter (§6.4): Wren carries a magic, the sending session's discriminator and a
//! sequence number, so each side recognises only its own looped-back packets.
//!
//! Because the looped packet has our own address as both source and destination, the
//! kernel's martian-source/local-delivery filtering would drop it on the way in — so
//! both transmit and receive use a raw `AF_PACKET`/`SOCK_DGRAM` socket, tapping at the
//! link layer below IP. This needs `CAP_NET_RAW`, and the neighbour must have IP
//! forwarding enabled for the loopback to happen at all. IPv4, single-hop only.

use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;

use anyhow::{Context, Result};
use tokio::io::unix::AsyncFd;

/// The BFD Echo UDP port (RFC 5881 §4).
pub const ECHO_PORT: u16 = 3785;
/// A magic tagging Wren Echo payloads (`"WREN"`), so a looped packet is recognised as
/// ours before its discriminator is trusted. The payload format is a local matter.
const ECHO_MAGIC: u32 = 0x5752_454e;
/// `ETH_P_IP` in network byte order's host value — the AF_PACKET protocol for IPv4.
const ETH_P_IP: u16 = 0x0800;
/// `ETH_P_IPV6` — the AF_PACKET protocol for IPv6 (for the IPv6 Echo socket).
const ETH_P_IPV6: u16 = 0x86dd;
/// `PACKET_OUTGOING` (linux/if_packet.h): a frame this socket itself sent, delivered
/// back to packet sockets. We skip these so we only act on the looped-back copy.
const PACKET_OUTGOING: u8 = 4;
/// The fixed Echo payload size: magic(4) + discriminator(4) + sequence(8).
const PAYLOAD_LEN: usize = 16;
/// The IPv6 fixed header length (RFC 8200 §3), no extension headers.
const IPV6_HEADER_LEN: usize = 40;

/// An owned raw fd that closes itself on drop (wrapped by [`AsyncFd`]).
struct RawSock(RawFd);
impl AsRawFd for RawSock {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}
impl Drop for RawSock {
    fn drop(&mut self) {
        // SAFETY: we own this fd exclusively; closing it once is correct.
        unsafe { libc::close(self.0) };
    }
}

/// A non-blocking `AF_PACKET`/`SOCK_DGRAM` socket registered with tokio, shared by every
/// Echo session of one address family: it receives looped-back Echo packets on all
/// interfaces and transmits new ones out a chosen interface to a chosen neighbour MAC.
/// One socket is opened per family — [`EchoSock::open`] for IPv4, [`EchoSock::open_v6`]
/// for IPv6 — since an `AF_PACKET` socket delivers only frames of its bound ethertype.
pub struct EchoSock {
    fd: AsyncFd<RawSock>,
    /// The bound ethertype in network byte order, stamped on every transmit so the
    /// kernel builds the right Ethernet header ([`ETH_P_IP`] or [`ETH_P_IPV6`]).
    proto_be: u16,
}

impl EchoSock {
    /// Open the shared IPv4 Echo socket (`ETH_P_IP`). Needs `CAP_NET_RAW`.
    pub fn open() -> Result<EchoSock> {
        EchoSock::open_proto(ETH_P_IP)
    }

    /// Open the shared IPv6 Echo socket (`ETH_P_IPV6`). Needs `CAP_NET_RAW`.
    pub fn open_v6() -> Result<EchoSock> {
        EchoSock::open_proto(ETH_P_IPV6)
    }

    /// Open a shared Echo socket for one ethertype: `AF_PACKET`/`SOCK_DGRAM` bound to all
    /// interfaces (`sll_ifindex` 0). Needs `CAP_NET_RAW`.
    fn open_proto(eth_p: u16) -> Result<EchoSock> {
        let proto = (eth_p.to_be()) as libc::c_int;
        // SAFETY: a plain socket(2); the fd is checked and owned immediately below.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                proto,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("socket(AF_PACKET, SOCK_DGRAM) for BFD Echo — needs CAP_NET_RAW");
        }
        let guard = RawSock(fd);
        // Bind to all interfaces (ifindex 0) so one socket serves every Echo session.
        // SAFETY: a zeroed sockaddr_ll with family/protocol set is a valid bind addr.
        let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sa.sll_family = libc::AF_PACKET as libc::c_ushort;
        sa.sll_protocol = eth_p.to_be();
        let rc = unsafe {
            libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("bind AF_PACKET for BFD Echo");
        }
        Ok(EchoSock {
            fd: AsyncFd::new(guard).context("registering BFD Echo socket with tokio")?,
            proto_be: eth_p.to_be(),
        })
    }

    /// Receive one IPv4 packet (the network-layer bytes; `SOCK_DGRAM` strips the
    /// Ethernet header). Inbound copies of our own transmissions (`PACKET_OUTGOING`)
    /// are skipped so only the looped-back packet is returned.
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| recvfrom_ip(inner.get_ref().as_raw_fd())) {
                Ok(Ok(Some(pkt))) => return Ok(pkt),
                Ok(Ok(None)) => continue, // an outgoing copy — ignore
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    /// Send one Echo packet `ip` (IPv4 or IPv6 per this socket's family) out of
    /// `ifindex` to neighbour MAC `dst`. The kernel prepends the Ethernet header
    /// (`SOCK_DGRAM`), tagging it with this socket's bound ethertype.
    pub async fn send(&self, ip: &[u8], dst: [u8; 6], ifindex: u32) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            let proto = self.proto_be;
            match guard
                .try_io(|inner| sendto_ip(inner.get_ref().as_raw_fd(), ip, dst, ifindex, proto))
            {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// `recvfrom` one frame, returning its IPv4 payload — or `None` if it was an outgoing
/// copy of one of our own transmissions (which packet sockets are also handed).
fn recvfrom_ip(fd: RawFd) -> io::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; 1500];
    // SAFETY: zeroed sockaddr_ll is a valid receive address buffer.
    let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
    let mut salen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    // SAFETY: buf and sa are valid, sized buffers for the duration of the call.
    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut sa as *mut _ as *mut libc::sockaddr,
            &mut salen,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if sa.sll_pkttype == PACKET_OUTGOING {
        return Ok(None);
    }
    buf.truncate(n as usize);
    Ok(Some(buf))
}

/// `sendto` an IP packet `ip` to `dst` out of `ifindex` with ethertype `proto_be`
/// (network byte order — the kernel builds the Ethernet header from `sll_addr` and
/// `sll_protocol`).
fn sendto_ip(fd: RawFd, ip: &[u8], dst: [u8; 6], ifindex: u32, proto_be: u16) -> io::Result<()> {
    // SAFETY: zeroed sockaddr_ll with the link-layer fields set is a valid dest.
    let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as libc::c_ushort;
    sa.sll_protocol = proto_be;
    sa.sll_ifindex = ifindex as libc::c_int;
    sa.sll_halen = 6;
    sa.sll_addr[..6].copy_from_slice(&dst);
    // SAFETY: ip and sa are valid for the call; sizes match.
    let n = unsafe {
        libc::sendto(
            fd,
            ip.as_ptr() as *const libc::c_void,
            ip.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Build an IPv4/UDP Echo packet from `our` address (used as both source and
/// destination so the neighbour loops it back), carrying our `discr` and `seq`.
pub fn build_echo(our: Ipv4Addr, discr: u32, seq: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.extend_from_slice(&ECHO_MAGIC.to_be_bytes());
    payload.extend_from_slice(&discr.to_be_bytes());
    payload.extend_from_slice(&seq.to_be_bytes());

    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = Vec::with_capacity(total_len);
    // IPv4 header (20 octets, no options).
    pkt.push(0x45); // version 4, IHL 5
    pkt.push(0); // DSCP/ECN
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // identification
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    pkt.push(255); // TTL — survive the one forwarding hop
    pkt.push(17); // protocol UDP
    pkt.extend_from_slice(&0u16.to_be_bytes()); // header checksum (filled below)
    pkt.extend_from_slice(&our.octets());
    pkt.extend_from_slice(&our.octets());
    let ip_csum = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    // UDP header + payload.
    let udp_off = pkt.len();
    pkt.extend_from_slice(&ECHO_PORT.to_be_bytes()); // source port
    pkt.extend_from_slice(&ECHO_PORT.to_be_bytes()); // destination port
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum (filled below)
    pkt.extend_from_slice(&payload);
    let udp_csum = udp_checksum(our, our, &pkt[udp_off..]);
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&udp_csum.to_be_bytes());
    pkt
}

/// Build an IPv6/UDP Echo packet from `our` address (used as both source and
/// destination so the neighbour loops it back), carrying our `discr` and `seq`. The
/// IPv6 header has no checksum, but the UDP checksum is mandatory over IPv6 (RFC 8200).
pub fn build_echo_v6(our: Ipv6Addr, discr: u32, seq: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.extend_from_slice(&ECHO_MAGIC.to_be_bytes());
    payload.extend_from_slice(&discr.to_be_bytes());
    payload.extend_from_slice(&seq.to_be_bytes());

    let udp_len = 8 + payload.len();
    let mut pkt = Vec::with_capacity(IPV6_HEADER_LEN + udp_len);
    // IPv6 header (40 octets, no extension headers).
    pkt.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6, TC 0, flow 0
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes()); // payload length
    pkt.push(17); // next header: UDP
    pkt.push(255); // hop limit — survive the one forwarding hop
    pkt.extend_from_slice(&our.octets()); // source
    pkt.extend_from_slice(&our.octets()); // destination
    // UDP header + payload.
    let udp_off = pkt.len();
    pkt.extend_from_slice(&ECHO_PORT.to_be_bytes()); // source port
    pkt.extend_from_slice(&ECHO_PORT.to_be_bytes()); // destination port
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum (filled below)
    pkt.extend_from_slice(&payload);
    let udp_csum = udp_checksum_v6(our, our, &pkt[udp_off..]);
    pkt[udp_off + 6..udp_off + 8].copy_from_slice(&udp_csum.to_be_bytes());
    pkt
}

/// Parse a received IPv4 or IPv6 packet as one of our Echo packets, returning the
/// carried `(discriminator, sequence)` if it is a UDP packet to [`ECHO_PORT`] with our
/// magic. Handles both families so one receive path serves both Echo sockets.
pub fn parse_echo(ip: &[u8]) -> Option<(u32, u64)> {
    if ip.is_empty() {
        return None;
    }
    let (udp, next_header) = match ip[0] >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = (ip[0] & 0x0f) as usize * 4;
            if ihl < 20 || ip.len() < ihl {
                return None;
            }
            (&ip[ihl..], ip[9])
        }
        6 => {
            if ip.len() < IPV6_HEADER_LEN {
                return None;
            }
            (&ip[IPV6_HEADER_LEN..], ip[6])
        }
        _ => return None,
    };
    if next_header != 17 {
        return None;
    }
    if udp.len() < 8 + PAYLOAD_LEN {
        return None;
    }
    if u16::from_be_bytes([udp[2], udp[3]]) != ECHO_PORT {
        return None;
    }
    let payload = &udp[8..];
    if u32::from_be_bytes(payload[0..4].try_into().ok()?) != ECHO_MAGIC {
        return None;
    }
    let discr = u32::from_be_bytes(payload[4..8].try_into().ok()?);
    let seq = u64::from_be_bytes(payload[8..16].try_into().ok()?);
    Some((discr, seq))
}

/// The internet checksum (RFC 1071) over `data`.
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The UDP checksum over the IPv4 pseudo-header plus the UDP header and payload.
fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + udp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(17); // protocol
    buf.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    buf.extend_from_slice(udp);
    let c = checksum(&buf);
    // A computed UDP checksum of zero is transmitted as all-ones (RFC 768).
    if c == 0 {
        0xffff
    } else {
        c
    }
}

/// The UDP checksum over the IPv6 pseudo-header (RFC 8200 §8.1) plus the UDP header and
/// payload. Unlike IPv4, the UDP checksum is mandatory over IPv6.
fn udp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + udp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&(udp.len() as u32).to_be_bytes()); // upper-layer packet length
    buf.extend_from_slice(&[0, 0, 0]); // zero
    buf.push(17); // next header
    buf.extend_from_slice(udp);
    let c = checksum(&buf);
    if c == 0 {
        0xffff
    } else {
        c
    }
}

/// The egress facts for reaching an IPv4 neighbour on a directly-connected link.
pub struct Egress {
    /// The interface's kernel index (for `sll_ifindex`).
    pub ifindex: u32,
    /// The interface name (for the ARP-table lookup).
    pub ifname: String,
    /// Our IPv4 address on that interface (the Echo source/destination).
    pub our_ip: Ipv4Addr,
}

/// Find the interface toward `peer`: the one whose IPv4 subnet contains it. Returns
/// its index, name and our address on it, or `None` if no connected interface matches.
pub fn egress_for(peer: Ipv4Addr) -> Option<Egress> {
    let target = u32::from(peer);
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs allocates a list into `head`; checked and freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut found: Option<Egress> = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: reading sa_family from a non-null sockaddr is always valid.
        if unsafe { (*ifa.ifa_addr).sa_family } as libc::c_int != libc::AF_INET {
            continue;
        }
        // SAFETY: family is AF_INET, so both are sockaddr_in.
        let addr = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
        let mask = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
        let ip = u32::from_be(addr.sin_addr.s_addr);
        let m = u32::from_be(mask.sin_addr.s_addr);
        if ip == 0 || m == 0 || (ip & m) != (target & m) {
            continue;
        }
        // SAFETY: `ifa_name` is a valid NUL-terminated C string.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        let ifindex = name_to_index(&name);
        if ifindex != 0 {
            found = Some(Egress { ifindex, ifname: name, our_ip: Ipv4Addr::from(ip) });
            break;
        }
    }
    // SAFETY: freeing exactly the list getifaddrs allocated above.
    unsafe { libc::freeifaddrs(head) };
    found
}

/// The egress facts for reaching an IPv6 neighbour on a directly-connected link.
pub struct EgressV6 {
    /// The interface's kernel index (for `sll_ifindex`).
    pub ifindex: u32,
    /// The interface name (for the neighbour-cache lookup).
    pub ifname: String,
    /// Our IPv6 address on that interface (the Echo source/destination).
    pub our_ip: Ipv6Addr,
}

/// Find the interface toward IPv6 `peer`. A link-local peer (`fe80::/10`) is reached on
/// the interface named by `scope` (its `sin6_scope_id`); we source the Echo from our own
/// link-local address there. A global/ULA peer is reached on whichever interface has a
/// matching-prefix (non-link-local) address, which becomes the source. Returns `None`
/// when no connected interface matches.
pub fn egress_for_v6(peer: Ipv6Addr, scope: u32) -> Option<EgressV6> {
    let peer_ll = is_link_local_v6(&peer);
    let target = u128::from(peer);
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs allocates a list into `head`; checked and freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut found: Option<EgressV6> = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: reading sa_family from a non-null sockaddr is always valid.
        if unsafe { (*ifa.ifa_addr).sa_family } as libc::c_int != libc::AF_INET6 {
            continue;
        }
        // SAFETY: family is AF_INET6, so both are sockaddr_in6.
        let addr = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
        let mask = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
        let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
        let addr_ll = is_link_local_v6(&ip);
        // SAFETY: `ifa_name` is a valid NUL-terminated C string.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        let ifindex = name_to_index(&name);
        if ifindex == 0 {
            continue;
        }
        let matches = if peer_ll {
            // Match the scoped interface, sourcing from our link-local there.
            addr_ll && (scope == 0 || ifindex == scope)
        } else {
            // Match by prefix, sourcing from a routable (non-link-local) address.
            let m = u128::from(Ipv6Addr::from(mask.sin6_addr.s6_addr));
            !addr_ll && m != 0 && (u128::from(ip) & m) == (target & m)
        };
        if matches {
            found = Some(EgressV6 { ifindex, ifname: name, our_ip: ip });
            break;
        }
    }
    // SAFETY: freeing exactly the list getifaddrs allocated above.
    unsafe { libc::freeifaddrs(head) };
    found
}

/// Whether an IPv6 address is link-local (`fe80::/10`).
fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    let o = ip.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

/// `if_nametoindex`, or 0 if the name is invalid or unknown.
fn name_to_index(name: &str) -> u32 {
    let Ok(cname) = CString::new(name) else { return 0 };
    // SAFETY: `cname` is a valid NUL-terminated string for the call's duration.
    unsafe { libc::if_nametoindex(cname.as_ptr()) }
}

/// Resolve the neighbour `peer`'s MAC on `ifname` from the kernel ARP table
/// (`/proc/net/arp`, which is network-namespace-aware). Returns `None` until the entry
/// is complete (the BFD Control traffic to the peer keeps it fresh).
pub fn neighbor_mac(ifname: &str, peer: Ipv4Addr) -> Option<[u8; 6]> {
    let table = std::fs::read_to_string("/proc/net/arp").ok()?;
    let want = peer.to_string();
    for line in table.lines().skip(1) {
        // IP address | HW type | Flags | HW address | Mask | Device
        let mut cols = line.split_whitespace();
        let ip = cols.next()?;
        let _hw_type = cols.next()?;
        let flags = cols.next()?;
        let mac = cols.next()?;
        let _mask = cols.next()?;
        let dev = cols.next()?;
        if ip != want || dev != ifname {
            continue;
        }
        // Flag 0x2 = ATF_COM (a complete entry with a usable MAC).
        let flag = u32::from_str_radix(flags.trim_start_matches("0x"), 16).unwrap_or(0);
        if flag & 0x2 == 0 {
            return None;
        }
        return parse_mac(mac);
    }
    None
}

// --- IPv6 neighbour-cache lookup (rtnetlink) -------------------------------
//
// IPv6 has no `/proc/net/arp`; the neighbour (ND) cache is reachable only over
// rtnetlink. These few constants and the small `RTM_GETNEIGH` dump below keep the
// dependency-free, hand-rolled-libc style of the rest of this file.

/// `RTM_GETNEIGH` — request a dump of the kernel neighbour cache.
const RTM_GETNEIGH: u16 = 30;
/// `RTM_NEWNEIGH` — a neighbour-cache entry in the dump reply.
const RTM_NEWNEIGH: u16 = 28;
/// `NLMSG_ERROR` / `NLMSG_DONE` control message types.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// `NLM_F_REQUEST` and a dump's `NLM_F_ROOT | NLM_F_MATCH`.
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x0100 | 0x0200;
/// `NDA_DST` (the neighbour address) and `NDA_LLADDR` (its link-layer address).
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
/// NUD states that carry a usable link-layer address (reachable/stale/delay/probe/
/// permanent/noarp) — an entry in one of these has a MAC we can send an Echo to.
const NUD_USABLE: u16 = 0x02 | 0x04 | 0x08 | 0x10 | 0x80 | 0x40;
/// The `nlmsghdr` length (len, type, flags, seq, pid).
const NLMSGHDR_LEN: usize = 16;
/// The `ndmsg` length (family, pad, ifindex, state, flags, type).
const NDMSG_LEN: usize = 12;

/// Resolve the IPv6 neighbour `peer`'s MAC on the interface indexed `ifindex` from the
/// kernel neighbour cache via an rtnetlink `RTM_GETNEIGH` dump (namespace-aware, since
/// the netlink socket is per-netns). Returns `None` until the entry has a usable
/// link-layer address (the BFD Control traffic to the peer keeps it fresh). This is the
/// IPv6 counterpart to [`neighbor_mac`], which reads `/proc/net/arp` for IPv4.
pub fn neighbor_mac_v6(ifindex: u32, peer: Ipv6Addr) -> Option<[u8; 6]> {
    // SAFETY: a plain netlink socket; the fd is owned by `RawSock` and closed on drop.
    let fd = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE)
    };
    if fd < 0 {
        return None;
    }
    let _guard = RawSock(fd);

    // Request: nlmsghdr + ndmsg{ndm_family = AF_INET6}, asking for the whole table.
    let mut req = [0u8; NLMSGHDR_LEN + NDMSG_LEN];
    let total = req.len() as u32;
    req[0..4].copy_from_slice(&total.to_ne_bytes());
    req[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    req[NLMSGHDR_LEN] = libc::AF_INET6 as u8; // ndm_family

    // SAFETY: sending `req` to the kernel (nl_pid 0) with a zeroed sockaddr_nl.
    let mut dst: libc::sockaddr_nl = unsafe { mem::zeroed() };
    dst.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = unsafe {
        libc::sendto(
            fd,
            req.as_ptr() as *const libc::c_void,
            req.len(),
            0,
            &dst as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return None;
    }

    // Read dump replies until the terminating NLMSG_DONE (or an error / short read).
    let mut buf = vec![0u8; 8192];
    loop {
        // SAFETY: `buf` is a valid, sized buffer for the recv.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            return None;
        }
        let data = &buf[..n as usize];
        let mut off = 0;
        while off + NLMSGHDR_LEN <= data.len() {
            let msg_len = u32::from_ne_bytes(data[off..off + 4].try_into().ok()?) as usize;
            if msg_len < NLMSGHDR_LEN || off + msg_len > data.len() {
                return None;
            }
            let msg_type = u16::from_ne_bytes([data[off + 4], data[off + 5]]);
            match msg_type {
                NLMSG_DONE => return None,
                NLMSG_ERROR => return None,
                RTM_NEWNEIGH => {
                    if let Some(mac) = parse_neigh(&data[off..off + msg_len], ifindex, peer) {
                        return Some(mac);
                    }
                }
                _ => {}
            }
            off += (msg_len + 3) & !3; // NLMSG_ALIGN
        }
    }
}

/// Parse one `RTM_NEWNEIGH` message, returning the link-layer address if it is a usable
/// IPv6 entry on `ifindex` for `peer`.
fn parse_neigh(msg: &[u8], ifindex: u32, peer: Ipv6Addr) -> Option<[u8; 6]> {
    if msg.len() < NLMSGHDR_LEN + NDMSG_LEN {
        return None;
    }
    let nd = &msg[NLMSGHDR_LEN..];
    if nd[0] as libc::c_int != libc::AF_INET6 {
        return None;
    }
    let ndm_ifindex = i32::from_ne_bytes(nd[4..8].try_into().ok()?);
    let ndm_state = u16::from_ne_bytes([nd[8], nd[9]]);
    if ndm_ifindex as u32 != ifindex || ndm_state & NUD_USABLE == 0 {
        return None;
    }
    // Walk the rtattrs after the ndmsg for NDA_DST (must equal `peer`) and NDA_LLADDR.
    let mut off = NLMSGHDR_LEN + NDMSG_LEN;
    let mut dst_ok = false;
    let mut lladdr: Option<[u8; 6]> = None;
    while off + 4 <= msg.len() {
        let rta_len = u16::from_ne_bytes([msg[off], msg[off + 1]]) as usize;
        let rta_type = u16::from_ne_bytes([msg[off + 2], msg[off + 3]]);
        if rta_len < 4 || off + rta_len > msg.len() {
            break;
        }
        let payload = &msg[off + 4..off + rta_len];
        match rta_type {
            NDA_DST if payload.len() == 16 => {
                let a: [u8; 16] = payload.try_into().ok()?;
                dst_ok = Ipv6Addr::from(a) == peer;
            }
            NDA_LLADDR if payload.len() == 6 => {
                lladdr = Some(payload.try_into().ok()?);
            }
            _ => {}
        }
        off += (rta_len + 3) & !3; // RTA_ALIGN
    }
    if dst_ok {
        lladdr
    } else {
        None
    }
}

/// Parse a colon-separated MAC address (`aa:bb:cc:dd:ee:ff`).
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.split(':');
    for b in mac.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_roundtrips_through_build_and_parse() {
        let pkt = build_echo(Ipv4Addr::new(10, 9, 0, 1), 0xdead_beef, 0x0102_0304_0506_0708);
        let (discr, seq) = parse_echo(&pkt).expect("our own packet must parse");
        assert_eq!(discr, 0xdead_beef);
        assert_eq!(seq, 0x0102_0304_0506_0708);
    }

    #[test]
    fn echo_v6_roundtrips_through_build_and_parse() {
        let our: Ipv6Addr = "fe80::1".parse().unwrap();
        let pkt = build_echo_v6(our, 0xcafe_babe, 0x1122_3344_5566_7788);
        assert_eq!(pkt[0] >> 4, 6); // IPv6 version nibble
        assert_eq!(pkt[6], 17); // next header: UDP
        let (discr, seq) = parse_echo(&pkt).expect("our own v6 packet must parse");
        assert_eq!(discr, 0xcafe_babe);
        assert_eq!(seq, 0x1122_3344_5566_7788);
    }

    #[test]
    fn parse_rejects_truncated_v6_and_wrong_version() {
        let pkt = build_echo_v6("2001:db8::1".parse().unwrap(), 1, 1);
        assert!(parse_echo(&pkt[..30]).is_none()); // shorter than the 40-byte header
        let mut bad = pkt.clone();
        bad[0] = 0x50; // version 5 — neither IPv4 nor IPv6
        assert!(parse_echo(&bad).is_none());
    }

    #[test]
    fn v6_udp_checksum_covers_the_pseudo_header() {
        // Two different source/dest addresses must yield different UDP checksums, proving
        // the IPv6 pseudo-header is folded in (a v4-style checksum would ignore them).
        let a = build_echo_v6("2001:db8::1".parse().unwrap(), 1, 1);
        let b = build_echo_v6("2001:db8::2".parse().unwrap(), 1, 1);
        let udp_csum = |p: &[u8]| u16::from_be_bytes([p[IPV6_HEADER_LEN + 6], p[IPV6_HEADER_LEN + 7]]);
        assert_ne!(udp_csum(&a), udp_csum(&b));
    }

    #[test]
    fn is_link_local_v6_classifies_prefixes() {
        assert!(is_link_local_v6(&"fe80::1".parse().unwrap()));
        assert!(is_link_local_v6(&"febf::1".parse().unwrap()));
        assert!(!is_link_local_v6(&"2001:db8::1".parse().unwrap()));
        assert!(!is_link_local_v6(&"fec0::1".parse().unwrap()));
    }

    #[test]
    fn parse_rejects_non_echo() {
        // A UDP packet to a different port is not an Echo.
        let mut pkt = build_echo(Ipv4Addr::LOCALHOST, 1, 1);
        // Corrupt the destination port (offset 20 + 2).
        pkt[22] = 0;
        pkt[23] = 53;
        assert!(parse_echo(&pkt).is_none());
    }

    #[test]
    fn parse_rejects_foreign_magic() {
        let mut pkt = build_echo(Ipv4Addr::LOCALHOST, 1, 1);
        pkt[28] = 0; // first magic byte in the payload (20 IP + 8 UDP)
        assert!(parse_echo(&pkt).is_none());
    }

    #[test]
    fn ipv4_header_checksum_is_valid() {
        let pkt = build_echo(Ipv4Addr::new(192, 0, 2, 1), 7, 7);
        // The checksum over a valid header (including its checksum field) is zero.
        assert_eq!(checksum(&pkt[..20]), 0);
    }

    #[test]
    fn parses_arp_mac() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None);
    }
}
