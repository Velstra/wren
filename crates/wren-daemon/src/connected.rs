//! # Connected-route discovery
//!
//! Reads the IPv4 **and** IPv6 networks directly attached to the daemon's
//! interfaces — an interface configured `10.0.0.1/24` is directly connected to
//! `10.0.0.0/24` — so they can be redistributed: announced to the
//! [`Rib`](wren_core::Rib) as [`Protocol::Connected`](wren_core::Protocol::Connected)
//! routes (the highest default preference) and advertised by RIP/RIPng to
//! neighbours.
//!
//! IPv6 link-local prefixes (`fe80::/10`) are skipped: they are not routable and
//! must never be redistributed. It uses `getifaddrs(3)` via `libc`, the same
//! minimal-dependency style as the rest of the daemon's platform glue.

use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

// `IpAddr` and `Prefix` are only used by the connected-network discovery below.
#[cfg(feature = "_connected")]
use std::net::IpAddr;
#[cfg(feature = "_connected")]
use wren_core::Prefix;

/// Convert an IPv4 netmask to a prefix length, or `None` if it is not a contiguous
/// run of high bits. Kept local so this module (used by every protocol runner) does
/// not depend on a protocol crate.
#[cfg(feature = "_connected")]
fn netmask_to_len(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let len = bits.leading_ones();
    let expected = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    (bits == expected).then_some(len as u8)
}

/// A directly-attached network found on one of our interfaces.
#[cfg(feature = "_connected")]
pub struct ConnectedNet {
    /// The interface the network is reached on.
    pub ifname: String,
    /// The attached network (the interface address with host bits cleared).
    pub prefix: Prefix,
}

/// Discover the IPv4/IPv6 networks directly attached to `ifnames`. Interfaces not
/// in the list, non-contiguous netmasks and IPv6 link-local prefixes are skipped.
/// Returns an empty list if the interfaces can't be read.
#[cfg(feature = "_connected")]
pub fn discover(ifnames: &[String]) -> Vec<ConnectedNet> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs allocates a linked list into `head`; we check its result
    // and free the list below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a valid NUL-terminated C string.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if !ifnames.contains(&name) {
            continue;
        }
        if let Some(prefix) = prefix_of(ifa.ifa_addr, ifa.ifa_netmask) {
            out.push(ConnectedNet {
                ifname: name,
                prefix,
            });
        }
    }

    // SAFETY: freeing exactly the list getifaddrs allocated above.
    unsafe { libc::freeifaddrs(head) };
    out
}

/// Resolve the local interface facing a BGP transport whose local IPv4 address is
/// `local_ip`: its name and that interface's IPv6 link-local (`fe80::/10`), if any.
///
/// Used for MP-BGP link-local next hops (RFC 2545): the name pins a received
/// link-local next hop to the right interface, and the link-local is what we
/// advertise as the second next-hop address toward a directly-connected peer.
/// Returns `None` if the address can't be matched or the interface has no
/// link-local.
pub fn resolve_link(local_ip: Ipv4Addr) -> Option<(String, Ipv6Addr)> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs allocates a linked list into `head`; checked and freed.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }

    let mut matched: Option<String> = None;
    let mut link_locals: Vec<(String, Ipv6Addr)> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a valid NUL-terminated C string.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: reading sa_family from a valid sockaddr is always sound.
        match unsafe { (*ifa.ifa_addr).sa_family } as i32 {
            libc::AF_INET if read_sin_addr(ifa.ifa_addr) == local_ip => {
                matched = Some(name);
            }
            libc::AF_INET6 => {
                let a = read_sin6_addr(ifa.ifa_addr);
                if (a.segments()[0] & 0xffc0) == 0xfe80 {
                    link_locals.push((name, a));
                }
            }
            _ => {}
        }
    }

    // SAFETY: freeing exactly the list getifaddrs allocated above.
    unsafe { libc::freeifaddrs(head) };

    let ifname = matched?;
    link_locals.into_iter().find(|(n, _)| *n == ifname)
}

/// Resolve the local interface facing a BGP transport whose local IPv6 address is
/// `local_v6` (an unnumbered / RFC 5549 session): its name and that interface's IPv6
/// link-local (`fe80::/10`), if any. `local_v6` may itself be the link-local.
///
/// Used for RFC 2545 next hops the same way [`resolve_link`] is, but keyed on the
/// IPv6 transport address. Returns `None` if the address can't be matched or the
/// interface has no link-local.
pub fn resolve_link6(local_v6: Ipv6Addr) -> Option<(String, Ipv6Addr)> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs allocates a linked list into `head`; checked and freed.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }

    let mut matched: Option<String> = None;
    let mut link_locals: Vec<(String, Ipv6Addr)> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node in the kernel-provided list.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a valid NUL-terminated C string.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: reading sa_family from a valid sockaddr is always sound.
        if unsafe { (*ifa.ifa_addr).sa_family } as i32 == libc::AF_INET6 {
            let a = read_sin6_addr(ifa.ifa_addr);
            if (a.segments()[0] & 0xffc0) == 0xfe80 {
                link_locals.push((name.clone(), a));
            }
            // Match on either the global or the link-local local address.
            if a == local_v6 {
                matched = Some(name);
            }
        }
    }

    // SAFETY: freeing exactly the list getifaddrs allocated above.
    unsafe { libc::freeifaddrs(head) };

    let ifname = matched?;
    link_locals.into_iter().find(|(n, _)| *n == ifname)
}

/// Build the attached [`Prefix`] from an interface's address + netmask sockaddrs,
/// for AF_INET / AF_INET6. Returns `None` for other families, a non-contiguous
/// mask, or an IPv6 link-local address.
#[cfg(feature = "_connected")]
fn prefix_of(addr: *const libc::sockaddr, netmask: *const libc::sockaddr) -> Option<Prefix> {
    // SAFETY: `addr` points to a sockaddr; reading sa_family is always valid.
    let family = unsafe { (*addr).sa_family } as i32;
    match family {
        libc::AF_INET => {
            let a = read_sin_addr(addr);
            let len = netmask_to_len(read_sin_addr(netmask))?;
            Prefix::new(IpAddr::V4(a), len).ok()
        }
        libc::AF_INET6 => {
            let a = read_sin6_addr(addr);
            // Link-local (fe80::/10) prefixes are not routable; never redistribute.
            if (a.segments()[0] & 0xffc0) == 0xfe80 {
                return None;
            }
            let len = v6_mask_len(read_sin6_addr(netmask))?;
            Prefix::new(IpAddr::V6(a), len).ok()
        }
        _ => None,
    }
}

/// Read the 4-byte IPv4 address out of a `sockaddr` known to be `AF_INET`.
fn read_sin_addr(sa: *const libc::sockaddr) -> Ipv4Addr {
    // SAFETY: the caller only passes pointers whose family is AF_INET, so the
    // sockaddr is really a sockaddr_in. `s_addr` is in network byte order.
    let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
    Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))
}

/// Read the 16-byte IPv6 address out of a `sockaddr` known to be `AF_INET6`.
fn read_sin6_addr(sa: *const libc::sockaddr) -> Ipv6Addr {
    // SAFETY: the caller only passes pointers whose family is AF_INET6, so the
    // sockaddr is really a sockaddr_in6. `s6_addr` is already in byte order.
    let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
    Ipv6Addr::from(sin6.sin6_addr.s6_addr)
}

/// The prefix length implied by a 16-byte IPv6 netmask, or `None` if it is not a
/// contiguous run of one-bits.
#[cfg(feature = "_connected")]
fn v6_mask_len(mask: Ipv6Addr) -> Option<u8> {
    let bits = u128::from(mask);
    let ones = bits.leading_ones();
    let expected = if ones == 0 {
        0
    } else {
        u128::MAX << (128 - ones)
    };
    (bits == expected).then_some(ones as u8)
}
