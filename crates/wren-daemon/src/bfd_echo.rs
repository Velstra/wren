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
use std::net::Ipv4Addr;
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
/// `PACKET_OUTGOING` (linux/if_packet.h): a frame this socket itself sent, delivered
/// back to packet sockets. We skip these so we only act on the looped-back copy.
const PACKET_OUTGOING: u8 = 4;
/// The fixed Echo payload size: magic(4) + discriminator(4) + sequence(8).
const PAYLOAD_LEN: usize = 16;

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

/// A non-blocking `AF_PACKET`/`SOCK_DGRAM` socket (IPv4) registered with tokio, shared
/// by every Echo session: it receives looped-back Echo packets on all interfaces and
/// transmits new ones out a chosen interface to a chosen neighbour MAC.
pub struct EchoSock {
    fd: AsyncFd<RawSock>,
}

impl EchoSock {
    /// Open the shared Echo socket: `AF_PACKET`/`SOCK_DGRAM` for IPv4, bound to all
    /// interfaces (`sll_ifindex` 0). Needs `CAP_NET_RAW`.
    pub fn open() -> Result<EchoSock> {
        let proto = (ETH_P_IP.to_be()) as libc::c_int;
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
        sa.sll_protocol = ETH_P_IP.to_be();
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

    /// Send one IPv4 Echo packet `ip` out of `ifindex` to neighbour MAC `dst`. The
    /// kernel prepends the Ethernet header (`SOCK_DGRAM`).
    pub async fn send(&self, ip: &[u8], dst: [u8; 6], ifindex: u32) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| sendto_ip(inner.get_ref().as_raw_fd(), ip, dst, ifindex)) {
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

/// `sendto` an IPv4 packet `ip` to `dst` out of `ifindex` (the kernel builds the
/// Ethernet header from `sll_addr`/`sll_protocol`).
fn sendto_ip(fd: RawFd, ip: &[u8], dst: [u8; 6], ifindex: u32) -> io::Result<()> {
    // SAFETY: zeroed sockaddr_ll with the link-layer fields set is a valid dest.
    let mut sa: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as libc::c_ushort;
    sa.sll_protocol = ETH_P_IP.to_be();
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

/// Parse a received IPv4 packet as one of our Echo packets, returning the carried
/// `(discriminator, sequence)` if it is a UDP packet to [`ECHO_PORT`] with our magic.
pub fn parse_echo(ip: &[u8]) -> Option<(u32, u64)> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl || ip[9] != 17 {
        return None;
    }
    let udp = &ip[ihl..];
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
