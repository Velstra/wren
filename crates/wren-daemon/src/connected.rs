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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use wren_core::Prefix;
use wren_rip::netmask_to_len;

/// A directly-attached network found on one of our interfaces.
pub struct ConnectedNet {
    /// The interface the network is reached on.
    pub ifname: String,
    /// The attached network (the interface address with host bits cleared).
    pub prefix: Prefix,
}

/// Discover the IPv4/IPv6 networks directly attached to `ifnames`. Interfaces not
/// in the list, non-contiguous netmasks and IPv6 link-local prefixes are skipped.
/// Returns an empty list if the interfaces can't be read.
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

/// Build the attached [`Prefix`] from an interface's address + netmask sockaddrs,
/// for AF_INET / AF_INET6. Returns `None` for other families, a non-contiguous
/// mask, or an IPv6 link-local address.
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
