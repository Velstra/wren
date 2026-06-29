//! # wren-netlink — the Linux kernel FIB backend
//!
//! A [`wren_core::Fib`] that installs the RIB's chosen routes into the kernel
//! routing table over **rtnetlink** (`NETLINK_ROUTE`). It is hand-rolled on a raw
//! `AF_NETLINK` socket via `libc`, on purpose:
//!
//! * it stays **synchronous**, matching the [`Fib`] trait, with no async runtime;
//! * it pulls in **no netlink dependency tree** — just `libc`.
//!
//! A route install is an `RTM_NEWROUTE` request with `NLM_F_CREATE|NLM_F_REPLACE`
//! (so a best-path change cleanly overwrites the previous route); a withdraw is
//! an `RTM_DELROUTE` matched on the destination prefix. Each request asks for an
//! ACK (`NLM_F_ACK`) and the reply's error code is surfaced as a [`FibError`].
//!
//! Routes are tagged with the standard rtnetlink protocol id for the source
//! protocol (`proto rip`, `proto ospf`, `proto bgp`, …), so an operator can see —
//! and selectively flush — exactly which daemon owns each route.
//!
//! Requires `CAP_NET_ADMIN` (real root, or root inside a user+network namespace).

use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_void;

use wren_core::{Fib, FibChange, FibError, NextHop, Prefix, Protocol, Route};

// --- rtnetlink constants (stable kernel ABI; not all are in `libc`) ----------

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_REPLACE: u16 = 0x100;
// A dump request is `NLM_F_ROOT | NLM_F_MATCH` (0x100 | 0x200). Those bits mean
// REPLACE/EXCL on a NEW request but ROOT/MATCH on a GET request — context decides.
const NLM_F_DUMP: u16 = 0x0100 | 0x0200;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// The main table id (254); now only referenced by tests (routes carry their own
// table), but kept named for clarity at the call sites.
#[allow(dead_code)]
const RT_TABLE_MAIN: u8 = 254;
/// The "unspecified" table (0): set in `rtm_table` when the real id is carried in the
/// `RTA_TABLE` attribute, for table ids that do not fit the one-octet field (> 255).
const RT_TABLE_UNSPEC: u8 = 0;
const RTN_UNICAST: u8 = 1;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_MULTIPATH: u16 = 9;
/// `RTA_TABLE`: the 32-bit routing-table id, for VRF tables that exceed the one-octet
/// `rtm_table` field (and read back to learn which VRF a dumped route is in).
const RTA_TABLE: u16 = 15;
/// `RTA_VIA` (RFC 5549 in the kernel): a next-hop gateway in a *different* address
/// family from the route's destination — an IPv4 route reached via an IPv6 gateway.
/// Its payload is a `struct rtvia` = a 2-octet family followed by the gateway octets,
/// where a same-family `RTA_GATEWAY` would carry the bare octets.
const RTA_VIA: u16 = 18;

/// Length of the fixed `struct rtnexthop` header inside an `RTA_MULTIPATH`
/// attribute (`rtnh_len` u16 + `rtnh_flags` u8 + `rtnh_hops` u8 + `rtnh_ifindex`
/// i32), before its own nested attributes.
const RTNH_HDR_LEN: usize = 8;

// Standard Linux route-origin protocol ids (`/usr/include/linux/rtnetlink.h`).
const RTPROT_KERNEL: u8 = 2;
const RTPROT_STATIC: u8 = 4;
const RTPROT_BABEL: u8 = 42;
const RTPROT_BGP: u8 = 186;
const RTPROT_ISIS: u8 = 187;
const RTPROT_OSPF: u8 = 188;
const RTPROT_RIP: u8 = 189;

const NLMSGHDR_LEN: usize = 16;
const RTMSG_LEN: usize = 12;

/// Map a [`Protocol`] to its conventional rtnetlink route-origin id, so kernel
/// route dumps attribute each route to the daemon that produced it.
fn rtprot(p: Protocol) -> u8 {
    match p {
        Protocol::Connected | Protocol::Kernel => RTPROT_KERNEL,
        Protocol::Static => RTPROT_STATIC,
        Protocol::Rip => RTPROT_RIP,
        Protocol::Ospf => RTPROT_OSPF,
        Protocol::Isis => RTPROT_ISIS,
        Protocol::Babel => RTPROT_BABEL,
        Protocol::Bgp => RTPROT_BGP,
    }
}

/// The inverse of [`rtprot`]: map a kernel route-origin id back to the Wren
/// [`Protocol`] that owns it, or `None` for ids Wren never installs (kernel,
/// boot, DHCP, RA, …). Connected routes are tagged `RTPROT_KERNEL` on the way out,
/// so they correctly map to `None` here — Wren must never reclaim a kernel route.
fn owned_protocol(rtprot: u8) -> Option<Protocol> {
    Some(match rtprot {
        RTPROT_STATIC => Protocol::Static,
        RTPROT_RIP => Protocol::Rip,
        RTPROT_OSPF => Protocol::Ospf,
        RTPROT_ISIS => Protocol::Isis,
        RTPROT_BABEL => Protocol::Babel,
        RTPROT_BGP => Protocol::Bgp,
        _ => return None,
    })
}

/// Resolve an interface index back to its name, or `None` if it is gone.
fn if_name(idx: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` is `IF_NAMESIZE` bytes, exactly what `if_indextoname` requires.
    let p = unsafe { libc::if_indextoname(idx, buf.as_mut_ptr() as *mut libc::c_char) };
    if p.is_null() {
        return None;
    }
    // SAFETY: on success `p` points at a NUL-terminated name within `buf`.
    let c = unsafe { CStr::from_ptr(p) };
    c.to_str().ok().map(|s| s.to_string())
}

/// Reassemble an [`IpAddr`] from a route attribute's raw octets. A missing
/// destination (`None`) is the unspecified address of `family` — the default route.
fn ip_from_octets(family: u8, octets: Option<&[u8]>) -> Option<IpAddr> {
    match family as i32 {
        libc::AF_INET => match octets {
            None => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some(o) if o.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))),
            _ => None,
        },
        libc::AF_INET6 => match octets {
            None => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Some(o) if o.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(o);
                Some(IpAddr::V6(Ipv6Addr::from(a)))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Build a [`NextHop`] from a route's same-family gateway octets (`gw`, in `family`),
/// an already-decoded cross-family gateway (`cross_gw`, from RTA_VIA, RFC 5549),
/// and/or an out-interface; `None` if it has none of them.
fn nexthop_from_gw(
    family: u8,
    gw: Option<&[u8]>,
    cross_gw: Option<IpAddr>,
    oif: Option<u32>,
) -> Option<NextHop> {
    let gateway = match (cross_gw, gw) {
        (Some(g), _) => Some(g),
        (None, Some(g)) => Some(ip_from_octets(family, Some(g))?),
        (None, None) => None,
    };
    let iface = oif.and_then(if_name);
    if gateway.is_none() && iface.is_none() {
        return None;
    }
    Some(NextHop {
        gateway,
        iface,
        weight: 1,
    })
}

/// Parse one `RTM_NEWROUTE` message (header + rtmsg + rtattrs) into a [`Route`],
/// keeping only **unicast** routes tagged with a protocol id Wren owns
/// ([`owned_protocol`]) — in any table, so a VRF's routes are reconciled too. The
/// route's table (VRF) is recorded in [`Route::table`]. Returns `None` for anything
/// else — a foreign route, or one we cannot represent.
fn parse_route(msg: &[u8]) -> Option<Route> {
    if msg.len() < NLMSGHDR_LEN + RTMSG_LEN {
        return None;
    }
    if u16::from_ne_bytes([msg[4], msg[5]]) != RTM_NEWROUTE {
        return None;
    }
    let family = msg[16];
    let dst_len = msg[17];
    // The one-octet table id; a larger one (a VRF) overrides it from RTA_TABLE below.
    let mut table = msg[20] as u32;
    let protocol = owned_protocol(msg[21])?;
    let rtn_type = msg[23];
    if rtn_type != RTN_UNICAST {
        return None;
    }

    let total = u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
    let end = total.min(msg.len());
    let mut dst: Option<&[u8]> = None;
    let mut gw: Option<&[u8]> = None;
    let mut via: Option<&[u8]> = None;
    let mut oif: Option<u32> = None;
    let mut mp: Option<&[u8]> = None;
    let mut metric: u32 = 0;
    let mut off = NLMSGHDR_LEN + RTMSG_LEN;
    while off + 4 <= end {
        let len = u16::from_ne_bytes([msg[off], msg[off + 1]]) as usize;
        let ty = u16::from_ne_bytes([msg[off + 2], msg[off + 3]]);
        if len < 4 || off + len > end {
            break;
        }
        let data = &msg[off + 4..off + len];
        match ty {
            RTA_DST => dst = Some(data),
            RTA_GATEWAY => gw = Some(data),
            RTA_VIA => via = Some(data),
            RTA_MULTIPATH => mp = Some(data),
            RTA_TABLE if data.len() == 4 => {
                table = u32::from_ne_bytes([data[0], data[1], data[2], data[3]])
            }
            RTA_OIF if data.len() == 4 => {
                oif = Some(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
            }
            RTA_PRIORITY if data.len() == 4 => {
                metric = u32::from_ne_bytes([data[0], data[1], data[2], data[3]])
            }
            _ => {}
        }
        off += align4(len);
    }

    let addr = ip_from_octets(family, dst)?;
    let prefix = Prefix::new(addr, dst_len).ok()?;
    // A multipath route carries its next-hops in RTA_MULTIPATH; otherwise it's the
    // single top-level gateway/oif.
    let nexthops = match mp {
        Some(buf) => parse_multipath(family, buf),
        None => {
            // A cross-family gateway (RFC 5549) arrives in RTA_VIA, decoded by its own
            // embedded family; an ordinary same-family gateway is in RTA_GATEWAY.
            let cross_gw = via.and_then(via_addr);
            match nexthop_from_gw(family, gw, cross_gw, oif) {
                Some(nh) => vec![nh],
                None => Vec::new(),
            }
        }
    };
    if nexthops.is_empty() {
        return None;
    }
    Some(Route {
        prefix,
        table,
        nexthops,
        protocol,
        preference: protocol.default_preference(),
        metric,
        source: 0,
        communities: Vec::new(),
        large_communities: Vec::new(),
        ext_communities: Vec::new(),
    })
}

/// Parse an `RTA_MULTIPATH` payload back into next-hops — the inverse of
/// [`build_multipath`]. Walks each `struct rtnexthop` (advancing by its 4-aligned
/// `rtnh_len`) and reads its weight, out-interface and nested `RTA_GATEWAY`.
fn parse_multipath(family: u8, mut buf: &[u8]) -> Vec<NextHop> {
    let mut out = Vec::new();
    while buf.len() >= RTNH_HDR_LEN {
        let rtnh_len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        if rtnh_len < RTNH_HDR_LEN || rtnh_len > buf.len() {
            break;
        }
        let hops = buf[3];
        let ifindex = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
        // Nested attributes live between the header and rtnh_len.
        let mut gw: Option<&[u8]> = None;
        let mut via: Option<&[u8]> = None;
        let mut off = RTNH_HDR_LEN;
        while off + 4 <= rtnh_len {
            let alen = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
            let aty = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
            if alen < 4 || off + alen > rtnh_len {
                break;
            }
            match aty {
                RTA_GATEWAY => gw = Some(&buf[off + 4..off + alen]),
                RTA_VIA => via = Some(&buf[off + 4..off + alen]),
                _ => {}
            }
            off += align4(alen);
        }
        // A cross-family gateway (RFC 5549) is in RTA_VIA; else the same-family
        // gateway octets in RTA_GATEWAY.
        let gateway = via
            .and_then(via_addr)
            .or_else(|| gw.and_then(|g| ip_from_octets(family, Some(g))));
        let iface = if ifindex > 0 {
            if_name(ifindex as u32)
        } else {
            None
        };
        if gateway.is_some() || iface.is_some() {
            out.push(NextHop {
                gateway,
                iface,
                weight: hops as u16 + 1,
            });
        }
        let advance = align4(rtnh_len);
        if advance == 0 || advance > buf.len() {
            break;
        }
        buf = &buf[advance..];
    }
    out
}

fn af(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    }
}

fn addr_octets(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// Append a next-hop gateway attribute to `buf` for a route whose destination is in
/// `dst_family`: an ordinary `RTA_GATEWAY` (bare octets) when the gateway is the same
/// family, or an `RTA_VIA` (`struct rtvia`: 2-octet family + octets) when it differs —
/// the kernel's RFC 5549 encoding for, e.g., an IPv4 route via an IPv6 gateway.
fn push_gateway(buf: &mut Vec<u8>, dst_family: u8, gw: &IpAddr) {
    let gw_family = af(gw);
    if gw_family == dst_family {
        push_attr(buf, RTA_GATEWAY, &addr_octets(gw));
    } else {
        let mut via = Vec::with_capacity(2 + 16);
        via.extend_from_slice(&(gw_family as u16).to_ne_bytes());
        via.extend_from_slice(&addr_octets(gw));
        push_attr(buf, RTA_VIA, &via);
    }
}

/// Decode an `RTA_VIA` payload (`struct rtvia`: 2-octet family + gateway octets) into
/// an [`IpAddr`] — the cross-family gateway of an RFC 5549 route.
fn via_addr(data: &[u8]) -> Option<IpAddr> {
    if data.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([data[0], data[1]]) as u8;
    ip_from_octets(family, Some(&data[2..]))
}

/// Round `n` up to the next multiple of 4 (netlink alignment).
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Append one rtattr (`len`, `type`, payload) padded to a 4-byte boundary.
fn push_attr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = (4 + payload.len()) as u16; // header + payload, unpadded
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

/// Resolve an interface name to its index, or `None` if it doesn't exist.
fn if_index(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the duration of the call.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

/// Build the payload of an `RTA_MULTIPATH` attribute: one `struct rtnexthop` per
/// next-hop, each carrying its weight (`rtnh_hops` = weight − 1) and out-interface,
/// followed by a nested `RTA_GATEWAY` when it has a gateway. Each entry is padded
/// to a 4-byte boundary, as the kernel's `RTNH_ALIGN` requires.
fn build_multipath(dst_family: u8, nexthops: &[NextHop]) -> Vec<u8> {
    let mut payload = Vec::new();
    for nh in nexthops {
        let start = payload.len();
        payload.extend_from_slice(&0u16.to_ne_bytes()); // rtnh_len — patched below
        payload.push(0); // rtnh_flags
        payload.push(nh.weight.saturating_sub(1).min(u8::MAX as u16) as u8); // rtnh_hops
        let ifindex = nh.iface.as_deref().and_then(if_index).unwrap_or(0) as i32;
        payload.extend_from_slice(&ifindex.to_ne_bytes()); // rtnh_ifindex
        if let Some(gw) = nh.gateway {
            push_gateway(&mut payload, dst_family, &gw);
        }
        // rtnh_len covers the header + nested (4-aligned) attrs, not trailing pad.
        let len = (payload.len() - start) as u16;
        payload[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        while payload.len() % 4 != 0 {
            payload.push(0);
        }
    }
    payload
}

/// Build an `RTM_NEWROUTE`/`RTM_DELROUTE` netlink message for `prefix`.
///
/// When `route` is `Some`, the next-hop attributes (gateway / out-interface /
/// metric) and origin protocol are added — that's an install. When `None`, only
/// the destination is set — enough for the kernel to match and delete it.
fn build_route_msg(
    nlmsg_type: u16,
    flags: u16,
    seq: u32,
    prefix: &Prefix,
    table: u32,
    route: Option<&Route>,
) -> Vec<u8> {
    let mut buf = vec![0u8; NLMSGHDR_LEN + RTMSG_LEN];

    // --- rtmsg (offset 16) ---
    let dst = prefix.addr();
    buf[16] = af(&dst); // rtm_family
    buf[17] = prefix.len(); // rtm_dst_len
                            // 18 rtm_src_len, 19 rtm_tos = 0
    // The VRF's table id: it fits the one-octet rtm_table field up to 255; a larger
    // id sets rtm_table to "unspecified" and travels in the RTA_TABLE attribute below.
    buf[20] = if table <= u8::MAX as u32 {
        table as u8
    } else {
        RT_TABLE_UNSPEC
    };
    buf[21] = route.map(|r| rtprot(r.protocol)).unwrap_or(RTPROT_STATIC); // rtm_protocol
                                                                          // Universe scope if any next-hop has a gateway; link scope for purely
                                                                          // on-link routes (a connected/dev route the kernel forwards directly).
    let any_gateway = route
        .map(|r| r.nexthops.iter().any(|n| n.gateway.is_some()))
        .unwrap_or(false);
    buf[22] = if any_gateway {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    }; // rtm_scope
    buf[23] = RTN_UNICAST; // rtm_type
                           // 24..28 rtm_flags = 0

    // --- attributes ---
    // Destination (omitted for the default route, where dst_len == 0).
    if prefix.len() > 0 {
        push_attr(&mut buf, RTA_DST, &addr_octets(&dst));
    }
    // A VRF table id that did not fit rtm_table travels here.
    if table > u8::MAX as u32 {
        push_attr(&mut buf, RTA_TABLE, &table.to_ne_bytes());
    }
    if let Some(r) = route {
        // A single next-hop goes in the top-level RTA_GATEWAY/RTA_OIF; several
        // become an RTA_MULTIPATH (ECMP) so the kernel installs every path.
        match r.nexthops.as_slice() {
            [] => {}
            [nh] => {
                if let Some(gw) = nh.gateway {
                    push_gateway(&mut buf, af(&dst), &gw);
                }
                if let Some(idx) = nh.iface.as_deref().and_then(if_index) {
                    push_attr(&mut buf, RTA_OIF, &idx.to_ne_bytes());
                }
            }
            nexthops => {
                let mp = build_multipath(af(&dst), nexthops);
                push_attr(&mut buf, RTA_MULTIPATH, &mp);
            }
        }
        if r.metric > 0 {
            push_attr(&mut buf, RTA_PRIORITY, &r.metric.to_ne_bytes());
        }
    }

    // --- fill the nlmsghdr now that the length is known ---
    let total = buf.len() as u32;
    buf[0..4].copy_from_slice(&total.to_ne_bytes()); // nlmsg_len
    buf[4..6].copy_from_slice(&nlmsg_type.to_ne_bytes()); // nlmsg_type
    buf[6..8].copy_from_slice(&flags.to_ne_bytes()); // nlmsg_flags
    buf[8..12].copy_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
                                                     // 12..16 nlmsg_pid = 0 (kernel assigns on bind)
    debug_assert_eq!(buf.len(), align4(buf.len()));
    buf
}

/// A [`Fib`] backed by the Linux kernel routing table via rtnetlink.
pub struct KernelFib {
    fd: i32,
    seq: u32,
}

impl KernelFib {
    /// Open a netlink route socket. Fails without `CAP_NET_ADMIN`.
    pub fn new() -> Result<Self, FibError> {
        // SAFETY: a plain socket(2) call; the returned fd is checked.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(FibError(format!(
                "opening netlink socket: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: a zeroed sockaddr_nl with only the family set is a valid bind
        // address (the kernel auto-assigns the port id).
        let mut sa: libc::sockaddr_nl = unsafe { mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: closing the fd we just opened.
            unsafe { libc::close(fd) };
            return Err(FibError(format!("binding netlink socket: {err}")));
        }
        Ok(Self { fd, seq: 1 })
    }

    /// Send one netlink message to the kernel (nl_pid 0).
    fn send_to_kernel(&self, msg: &[u8]) -> Result<(), FibError> {
        // SAFETY: a zeroed sockaddr_nl with the family set addresses the kernel.
        let mut dst: libc::sockaddr_nl = unsafe { mem::zeroed() };
        dst.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: `msg` is a valid byte slice; `dst` outlives the call.
        let sent = unsafe {
            libc::sendto(
                self.fd,
                msg.as_ptr() as *const c_void,
                msg.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(FibError(format!(
                "sending netlink request: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Send one route request and wait for its ACK.
    fn request(&mut self, msg: &[u8]) -> Result<(), FibError> {
        self.send_to_kernel(msg)?;

        // Read the ACK / error reply.
        let mut buf = [0u8; 4096];
        // SAFETY: `buf` is a valid, sufficiently-large mutable buffer.
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
        if n < 0 {
            return Err(FibError(format!(
                "reading netlink reply: {}",
                io::Error::last_os_error()
            )));
        }
        let n = n as usize;
        if n < NLMSGHDR_LEN {
            return Err(FibError("truncated netlink reply".into()));
        }
        let nlmsg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        if nlmsg_type == NLMSG_ERROR {
            // struct nlmsgerr { __s32 error; struct nlmsghdr msg; } — the error is
            // the first field after the 16-byte header. 0 means a plain ACK.
            if n < NLMSGHDR_LEN + 4 {
                return Err(FibError("short netlink error reply".into()));
            }
            let code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if code != 0 {
                return Err(FibError(format!(
                    "netlink: {}",
                    io::Error::from_raw_os_error(-code)
                )));
            }
        }
        Ok(())
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Dump every routing table and return the routes tagged with one of Wren's own
    /// protocol ids (see [`owned_protocol`]) — the routes a previous Wren instance
    /// installed, in the main table or any VRF table (each route carries its table).
    /// Foreign routes (kernel, DHCP, …) are skipped.
    fn dump_owned(&mut self) -> Result<Vec<Route>, FibError> {
        // An `RTM_GETROUTE` dump request: an rtmsg with `AF_UNSPEC` so the kernel
        // walks both address families.
        let seq = self.next_seq();
        let mut req = vec![0u8; NLMSGHDR_LEN + RTMSG_LEN];
        req[16] = libc::AF_UNSPEC as u8; // rtm_family
        let total = req.len() as u32;
        req[0..4].copy_from_slice(&total.to_ne_bytes());
        req[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
        req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req[8..12].copy_from_slice(&seq.to_ne_bytes());
        self.send_to_kernel(&req)?;

        // Read the multipart reply until `NLMSG_DONE`. Netlink datagrams are
        // message-aligned, so each `recv` yields whole messages.
        let mut routes = Vec::new();
        let mut buf = [0u8; 16384];
        'recv: loop {
            // SAFETY: `buf` is a valid, sufficiently-large mutable buffer.
            let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
            if n < 0 {
                return Err(FibError(format!(
                    "reading netlink dump: {}",
                    io::Error::last_os_error()
                )));
            }
            let n = n as usize;
            let mut off = 0;
            while off + NLMSGHDR_LEN <= n {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                if len < NLMSGHDR_LEN || off + len > n {
                    break;
                }
                let ty = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                if ty == NLMSG_DONE {
                    break 'recv;
                }
                if ty == NLMSG_ERROR {
                    let code = if off + NLMSGHDR_LEN + 4 <= n {
                        i32::from_ne_bytes([
                            buf[off + 16],
                            buf[off + 17],
                            buf[off + 18],
                            buf[off + 19],
                        ])
                    } else {
                        0
                    };
                    if code != 0 {
                        return Err(FibError(format!(
                            "netlink dump: {}",
                            io::Error::from_raw_os_error(-code)
                        )));
                    }
                }
                if ty == RTM_NEWROUTE {
                    if let Some(route) = parse_route(&buf[off..off + len]) {
                        routes.push(route);
                    }
                }
                off += align4(len);
            }
        }
        Ok(routes)
    }
}

impl Fib for KernelFib {
    fn apply(&mut self, change: &FibChange) -> Result<(), FibError> {
        let seq = self.next_seq();
        let msg = match change {
            FibChange::Install(route) => build_route_msg(
                RTM_NEWROUTE,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
                seq,
                &route.prefix,
                route.table,
                Some(route),
            ),
            FibChange::Remove { table, prefix } => build_route_msg(
                RTM_DELROUTE,
                NLM_F_REQUEST | NLM_F_ACK,
                seq,
                prefix,
                *table,
                None,
            ),
        };
        self.request(&msg)
    }

    fn owned_routes(&mut self) -> Result<Vec<Route>, FibError> {
        self.dump_owned()
    }
}

impl Drop for KernelFib {
    fn drop(&mut self) {
        // SAFETY: closing our own socket fd exactly once.
        unsafe { libc::close(self.fd) };
    }
}

/// `NLM_F_EXCL` is exposed for callers that want create-only (fail if present)
/// semantics in a future API; the default install uses create-or-replace.
pub const CREATE_ONLY_FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

#[cfg(test)]
mod tests {
    use super::*;
    use wren_core::NextHop;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    #[test]
    fn install_message_has_header_rtmsg_and_attrs() {
        let route = Route::new(
            p("10.20.0.0/16"),
            Protocol::Static,
            vec![NextHop::via("192.0.2.1".parse().unwrap())],
            7,
        );
        let msg = build_route_msg(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            42,
            &route.prefix,
            route.table,
            Some(&route),
        );

        // nlmsg_len matches the buffer and is 4-aligned.
        assert_eq!(
            u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize,
            msg.len()
        );
        assert_eq!(msg.len() % 4, 0);
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), RTM_NEWROUTE);
        assert_eq!(u32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]), 42); // seq

        // rtmsg: IPv4, /16, main table, static proto, universe scope (has gateway).
        assert_eq!(msg[16], libc::AF_INET as u8);
        assert_eq!(msg[17], 16);
        assert_eq!(msg[20], RT_TABLE_MAIN);
        assert_eq!(msg[21], RTPROT_STATIC);
        assert_eq!(msg[22], RT_SCOPE_UNIVERSE);
        assert_eq!(msg[23], RTN_UNICAST);

        // The destination, gateway and metric attributes are all present.
        assert!(has_attr(&msg, RTA_DST, &[10, 20, 0, 0]));
        assert!(has_attr(&msg, RTA_GATEWAY, &[192, 0, 2, 1]));
        assert!(has_attr(&msg, RTA_PRIORITY, &7u32.to_ne_bytes()));
    }

    #[test]
    fn default_route_omits_dst_and_dev_route_is_link_scoped() {
        let def = Route::new(
            p("0.0.0.0/0"),
            Protocol::Static,
            vec![NextHop::via("192.0.2.1".parse().unwrap())],
            0,
        );
        let msg = build_route_msg(RTM_NEWROUTE, 0, 1, &def.prefix, def.table, Some(&def));
        assert_eq!(msg[17], 0); // dst_len 0
        assert!(!has_attr(&msg, RTA_DST, &[])); // no RTA_DST for the default route

        let onlink = Route::new(
            p("10.0.0.0/24"),
            Protocol::Connected,
            vec![NextHop::dev("eth0")],
            0,
        );
        let msg = build_route_msg(RTM_NEWROUTE, 0, 2, &onlink.prefix, onlink.table, Some(&onlink));
        assert_eq!(msg[22], RT_SCOPE_LINK); // no gateway → link scope
        assert_eq!(msg[21], RTPROT_KERNEL); // connected → kernel proto
    }

    #[test]
    fn delete_message_carries_only_the_destination() {
        let msg = build_route_msg(
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            1,
            &p("10.0.0.0/24"),
            RT_TABLE_MAIN as u32,
            None,
        );
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), RTM_DELROUTE);
        assert!(has_attr(&msg, RTA_DST, &[10, 0, 0, 0]));
        assert!(!has_attr(&msg, RTA_GATEWAY, &[])); // no next-hop on a delete
    }

    #[test]
    fn vrf_table_in_rtm_table_byte_and_rta_table_attr() {
        let nh = || vec![NextHop::via("192.0.2.1".parse().unwrap())];
        // A small VRF table fits the one-octet rtm_table field, no RTA_TABLE.
        let r = Route::new(p("10.0.0.0/24"), Protocol::Static, nh(), 0).with_table(100);
        let msg = build_route_msg(RTM_NEWROUTE, 0, 1, &r.prefix, r.table, Some(&r));
        assert_eq!(msg[20], 100);
        assert!(!has_attr(&msg, RTA_TABLE, &100u32.to_ne_bytes()));
        assert_eq!(parse_route(&msg), Some(r));

        // A large VRF table travels in RTA_TABLE with rtm_table = unspecified.
        let r = Route::new(p("10.0.0.0/24"), Protocol::Static, nh(), 0).with_table(100_000);
        let msg = build_route_msg(RTM_NEWROUTE, 0, 1, &r.prefix, r.table, Some(&r));
        assert_eq!(msg[20], RT_TABLE_UNSPEC);
        assert!(has_attr(&msg, RTA_TABLE, &100_000u32.to_ne_bytes()));
        assert_eq!(parse_route(&msg), Some(r));
    }

    #[test]
    fn parse_route_round_trips_an_owned_ipv4_route() {
        let route = Route::new(
            p("10.20.0.0/16"),
            Protocol::Static,
            vec![NextHop::via("192.0.2.1".parse().unwrap())],
            7,
        );
        let msg = build_route_msg(RTM_NEWROUTE, 0, 1, &route.prefix, route.table, Some(&route));
        // A built message parses straight back to the same route (proto, prefix,
        // gateway, metric all preserved).
        assert_eq!(parse_route(&msg), Some(route));
    }

    #[test]
    fn parse_route_handles_the_default_route() {
        let def = Route::new(
            p("0.0.0.0/0"),
            Protocol::Bgp,
            vec![NextHop::via("192.0.2.1".parse().unwrap())],
            0,
        );
        let msg = build_route_msg(RTM_NEWROUTE, 0, 1, &def.prefix, def.table, Some(&def));
        let got = parse_route(&msg).expect("default route parses");
        assert!(got.prefix.is_default());
        assert_eq!(got.protocol, Protocol::Bgp);
    }

    #[test]
    fn parse_route_round_trips_ipv6() {
        let route = Route::new(
            p("2001:db8::/32"),
            Protocol::Ospf,
            vec![NextHop::via("fe80::1".parse().unwrap())],
            3,
        );
        let msg = build_route_msg(RTM_NEWROUTE, 0, 1, &route.prefix, route.table, Some(&route));
        assert_eq!(parse_route(&msg), Some(route));
    }

    #[test]
    fn ipv4_route_via_ipv6_gateway_uses_rta_via() {
        // RFC 5549: an IPv4 prefix with an IPv6 gateway must encode the gateway as
        // RTA_VIA (struct rtvia: family + octets), not a same-family RTA_GATEWAY, and
        // round-trip back to the same IPv6 gateway.
        let route = Route::new(
            p("10.99.0.0/24"),
            Protocol::Bgp,
            vec![NextHop::via("2001:db8::2".parse().unwrap())],
            0,
        );
        let msg = build_route_msg(RTM_NEWROUTE, 0, 1, &route.prefix, route.table, Some(&route));
        // The cross-family gateway is in RTA_VIA, and there is no top-level RTA_GATEWAY.
        assert!(has_attr(&msg, RTA_VIA, &[]));
        assert!(!has_attr(&msg, RTA_GATEWAY, &[]));
        // The RTA_VIA payload is the family (AF_INET6) followed by the 16 octets.
        let mut via = (libc::AF_INET6 as u16).to_ne_bytes().to_vec();
        via.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert!(has_attr(&msg, RTA_VIA, &via));
        assert_eq!(parse_route(&msg), Some(route));
    }

    /// Kernel-acceptance for the RFC 5549 case the round-trip test can't prove: that
    /// the real kernel accepts an IPv4 route with an IPv6 gateway via RTA_VIA. Needs
    /// `CAP_NET_ADMIN` and an interface carrying `2001:db8::1/64`, so it is `#[ignore]`d:
    ///
    /// ```sh
    /// unshare -Urn sh -c '
    ///   ip link add d0 type dummy; ip addr add 2001:db8::1/64 dev d0; ip link set d0 up
    ///   cargo test -p wren-netlink --ignored ipv4_via_ipv6_kernel_acceptance -- --nocapture'
    /// ```
    #[test]
    #[ignore = "needs CAP_NET_ADMIN + 2001:db8::/64 on an iface; run under unshare -Urn"]
    fn ipv4_via_ipv6_kernel_acceptance() {
        let mut fib = KernelFib::new().expect("open kernel fib");
        let route = Route::new(
            p("10.123.0.0/16"),
            Protocol::Bgp,
            vec![NextHop::via("2001:db8::2".parse().unwrap())],
            0,
        );
        fib.apply(&FibChange::Install(route.clone()))
            .expect("kernel accepts the IPv4-via-IPv6 (RTA_VIA) route");
        let back = fib.owned_routes().expect("dump routes");
        let got = back
            .iter()
            .find(|r| r.prefix == route.prefix)
            .expect("the IPv4-via-IPv6 route is present in the kernel");
        assert_eq!(
            got.nexthops[0].gateway,
            Some("2001:db8::2".parse().unwrap()),
            "the IPv6 gateway survives the kernel round trip"
        );
    }

    /// Kernel-acceptance smoke for ECMP — the one thing the round-trip test can't
    /// prove: that the real kernel accepts our `RTA_MULTIPATH` message. Needs
    /// `CAP_NET_ADMIN` and an interface carrying `192.168.1.0/24`, so it is
    /// `#[ignore]`d; run it under a throwaway namespace:
    ///
    /// ```sh
    /// unshare -Urn sh -c '
    ///   ip link add d0 type dummy; ip addr add 192.168.1.1/24 dev d0; ip link set d0 up
    ///   cargo test -p wren-netlink --ignored ecmp_kernel_acceptance -- --nocapture'
    /// ```
    #[test]
    #[ignore = "needs CAP_NET_ADMIN + 192.168.1.0/24 on an iface; run under unshare -Urn"]
    fn ecmp_kernel_acceptance() {
        let mut fib = KernelFib::new().expect("open kernel fib");
        let route = Route::new(
            p("10.123.0.0/16"),
            Protocol::Ospf,
            vec![
                NextHop::via("192.168.1.2".parse().unwrap()),
                NextHop::via("192.168.1.3".parse().unwrap()),
            ],
            20,
        );
        fib.apply(&FibChange::Install(route.clone()))
            .expect("kernel accepts the ECMP route");
        // Read it back and confirm both next-hops survived the round trip.
        let back = fib.owned_routes().expect("dump routes");
        let got = back
            .iter()
            .find(|r| r.prefix == route.prefix)
            .expect("the ECMP route is present in the kernel");
        assert_eq!(got.nexthops.len(), 2, "both ECMP next-hops installed");
    }

    /// Kernel-acceptance for the BGP-multipath case the daemon actually performs:
    /// a prefix is first installed as a *single* path, then **replaced** by a
    /// multipath route whose two next hops sit on **different interfaces** (the
    /// real eBGP-multipath topology) — `CREATE|REPLACE` over an existing entry,
    /// gateway-only next hops (ifindex 0), metric 1, `proto bgp`. The fresh-install,
    /// single-interface ECMP test covers neither the replace transition nor the
    /// cross-interface gateway resolution. Run it the same way:
    ///
    /// ```sh
    /// unshare -Urn sh -c '
    ///   ip link add d0 type dummy; ip addr add 192.168.1.1/24 dev d0; ip link set d0 up
    ///   ip link add d1 type dummy; ip addr add 192.168.2.1/24 dev d1; ip link set d1 up
    ///   cargo test -p wren-netlink replace_single_path_with_multipath -- --ignored --nocapture'
    /// ```
    #[test]
    #[ignore = "needs CAP_NET_ADMIN + 192.168.{1,2}.0/24 on two ifaces; run under unshare -Urn"]
    fn replace_single_path_with_multipath_acceptance() {
        let mut fib = KernelFib::new().expect("open kernel fib");
        let dst = p("10.123.0.0/16");
        let single =
            Route::new(dst, Protocol::Bgp, vec![NextHop::via("192.168.1.2".parse().unwrap())], 1);
        fib.apply(&FibChange::Install(single)).expect("install the single path");
        let multi = Route::new(
            dst,
            Protocol::Bgp,
            vec![
                NextHop::via("192.168.1.2".parse().unwrap()),
                NextHop::via("192.168.2.2".parse().unwrap()),
            ],
            1,
        );
        fib.apply(&FibChange::Install(multi.clone()))
            .expect("kernel accepts replacing the single path with cross-interface multipath");
        let back = fib.owned_routes().expect("dump routes");
        let got = back.iter().find(|r| r.prefix == dst).expect("the route is present");
        assert_eq!(got.nexthops.len(), 2, "both ECMP next-hops installed after the replace");
    }

    #[test]
    fn build_and_parse_multipath_ecmp_route() {
        let route = Route::new(
            p("10.0.0.0/24"),
            Protocol::Ospf,
            vec![
                NextHop::via("192.0.2.1".parse().unwrap()),
                NextHop::via("192.0.2.2".parse().unwrap()),
            ],
            20,
        );
        let msg = build_route_msg(RTM_NEWROUTE, 0, 1, &route.prefix, route.table, Some(&route));
        // Two next-hops are encoded as RTA_MULTIPATH, not a top-level RTA_GATEWAY.
        assert!(has_attr(&msg, RTA_MULTIPATH, &[]));
        assert!(!has_attr(&msg, RTA_GATEWAY, &[]));
        // …and round-trip back to both gateways.
        let parsed = parse_route(&msg).expect("multipath route parses");
        assert_eq!(parsed, route);
        assert_eq!(parsed.nexthops.len(), 2);
    }

    #[test]
    fn parse_route_skips_foreign_routes() {
        // A connected route is tagged `RTPROT_KERNEL`, which Wren does not own — it
        // must never be reclaimed, so the parser drops it.
        let connected = Route::new(
            p("10.0.0.0/24"),
            Protocol::Connected,
            vec![NextHop::via("192.0.2.1".parse().unwrap())],
            0,
        );
        let msg = build_route_msg(RTM_NEWROUTE, 0, 1, &connected.prefix, connected.table, Some(&connected));
        assert_eq!(parse_route(&msg), None);
    }

    /// Walk the rtattrs after the rtmsg looking for `(attr_type, payload)`.
    fn has_attr(msg: &[u8], attr_type: u16, payload: &[u8]) -> bool {
        let mut off = NLMSGHDR_LEN + RTMSG_LEN;
        while off + 4 <= msg.len() {
            let len = u16::from_ne_bytes([msg[off], msg[off + 1]]) as usize;
            let ty = u16::from_ne_bytes([msg[off + 2], msg[off + 3]]);
            if len < 4 || off + len > msg.len() {
                break;
            }
            let data = &msg[off + 4..off + len];
            if ty == attr_type && (payload.is_empty() || data == payload) {
                return true;
            }
            off += align4(len);
        }
        false
    }
}
