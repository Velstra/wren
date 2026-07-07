//! # The kernel multicast forwarding cache writer (Linux `MRT_*`)
//!
//! PIM computes *which* interface a group arrives on and *which* interfaces to
//! replicate it onto; this module applies that to the kernel so packets are actually
//! forwarded, via the Linux multicast routing socket API (`<linux/mroute.h>`, the
//! same `ip mroute` control plane `mrouted`/`pimd` use):
//!
//! * one raw `IPPROTO_IGMP` socket per network namespace becomes *the* multicast
//!   router with `MRT_INIT`; there can be only one, and closing it (`MRT_DONE`, on
//!   `Drop`) tears the kernel forwarding down;
//! * each multicast interface is registered as a numbered *virtual interface* (VIF)
//!   with `MRT_ADD_VIF` (by ifindex, `VIFF_USE_IFINDEX`);
//! * each `(source, group)` forwarding entry is installed with `MRT_ADD_MFC` — its
//!   parent VIF is the incoming interface (the RPF interface / where the packet
//!   arrived) and its per-VIF TTL thresholds mark the outgoing interfaces;
//! * when a multicast packet arrives with no matching entry the kernel queues it and
//!   sends a `NOCACHE` upcall (a `struct igmpmsg`) up this socket — that is how the
//!   router learns a new `(S,G)` flow and installs the entry for it.
//!
//! `libc` does not expose the `MRT_*` constants or the `vifctl`/`mfcctl`/`igmpmsg`
//! structs, so they are defined here against the stable Linux ABI. `#[repr(C)]`
//! reproduces the kernel field layout exactly (checked by `layout_matches_kernel`).

use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::raw::c_void;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

// --- MRT_* setsockopt options (level IPPROTO_IP), from <linux/mroute.h> ----------
const MRT_BASE: libc::c_int = 200;
const MRT_INIT: libc::c_int = MRT_BASE; // 200 — become the multicast router
const MRT_DONE: libc::c_int = MRT_BASE + 1; // 201 — stop being the router
const MRT_ADD_VIF: libc::c_int = MRT_BASE + 2; // 202 — add a virtual interface
const MRT_ADD_MFC: libc::c_int = MRT_BASE + 4; // 204 — add a forwarding entry
const MRT_DEL_MFC: libc::c_int = MRT_BASE + 5; // 205 — delete a forwarding entry

/// `VIFF_USE_IFINDEX` — interpret the VIF's local field as an interface index.
const VIFF_USE_IFINDEX: libc::c_uchar = 0x8;
/// The maximum number of VIFs the kernel supports (`MAXVIFS`), the length of the
/// per-VIF TTL-threshold array in `mfcctl`.
pub const MAXVIFS: usize = 32;

/// `im_msgtype` of a `NOCACHE` upcall: a data packet hit no forwarding entry — the
/// signal to create one (and, at a first-hop DR, to Register it to the RP).
pub const IGMPMSG_NOCACHE: u8 = 1;
/// `im_msgtype` of a `WRONGVIF` upcall: a packet arrived on the wrong (non-RPF)
/// interface — the Assert trigger (deferred; logged, not acted on).
pub const IGMPMSG_WRONGVIF: u8 = 2;
/// `im_msgtype` of a `WHOLEPKT` upcall: the whole packet, for PIM Register at the DR.
pub const IGMPMSG_WHOLEPKT: u8 = 3;

/// The kernel `struct vifctl` — a virtual-interface registration (`<linux/mroute.h>`).
#[repr(C)]
struct Vifctl {
    vifc_vifi: u16,
    vifc_flags: u8,
    vifc_threshold: u8,
    vifc_rate_limit: u32,
    /// Union `{ in_addr vifc_lcl_addr; int vifc_lcl_ifindex; }` — the ifindex here.
    vifc_lcl: u32,
    vifc_rmt_addr: u32,
}

/// The kernel `struct mfcctl` — a multicast forwarding-cache entry (`<linux/mroute.h>`).
#[repr(C)]
struct Mfcctl {
    mfcc_origin: u32,   // in_addr, network order
    mfcc_mcastgrp: u32, // in_addr, network order
    mfcc_parent: u16,   // incoming VIF (the RPF interface)
    mfcc_ttls: [u8; MAXVIFS],
    mfcc_pkt_cnt: u32,
    mfcc_byte_cnt: u32,
    mfcc_wrong_if: u32,
    mfcc_expire: i32,
}

/// A parsed `NOCACHE`/`WRONGVIF`/`WHOLEPKT` upcall the kernel sent up the router
/// socket (the first 20 bytes of the datagram are a `struct igmpmsg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upcall {
    /// `im_msgtype` — one of the `IGMPMSG_*` constants.
    pub msgtype: u8,
    /// The incoming VIF the packet arrived on.
    pub vif: u16,
    /// The source `S`.
    pub source: Ipv4Addr,
    /// The group `G`.
    pub group: Ipv4Addr,
}

/// Parse a datagram read off the router socket as an `igmpmsg` upcall. Returns `None`
/// if it is not an upcall.
///
/// The kernel builds the upcall by *copying the triggering packet's IP header* and
/// then overwriting `im_msgtype` (offset 8), `im_mbz` (9) and `im_vif` (10) — so
/// byte 0 is the copied version/IHL (`0x45`), **not** zero. The reliable
/// discriminator (as `mrouted`/`pimd` use) is `im_mbz == 0`: it overlays the IP
/// protocol byte, which for a real IP+IGMP datagram delivered on this raw socket is
/// `2` (IGMP), never `0`.
pub fn parse_upcall(buf: &[u8]) -> Option<Upcall> {
    if buf.len() < 20 || buf[9] != 0 {
        return None; // too short, or a real IP datagram (protocol byte != 0)
    }
    let msgtype = buf[8];
    if !matches!(msgtype, IGMPMSG_NOCACHE | IGMPMSG_WRONGVIF | IGMPMSG_WHOLEPKT) {
        return None;
    }
    // im_vif at offset 10, im_vif_hi at 11 (a VIF index can exceed 255).
    let vif = buf[10] as u16 | ((buf[11] as u16) << 8);
    let source = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let group = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    Some(Upcall {
        msgtype,
        vif,
        source,
        group,
    })
}

/// The kernel multicast router socket: the one `MRT_INIT` socket for this netns,
/// through which VIFs and MFC entries are programmed and upcalls are read.
pub struct MrouteSocket {
    sock: Arc<UdpSocket>,
}

impl MrouteSocket {
    /// Open a raw `IPPROTO_IGMP` socket and make it the kernel multicast router with
    /// `MRT_INIT`. Fails (needs `CAP_NET_ADMIN`) if another router already owns the
    /// namespace's multicast forwarding, or if multicast routing is not built in.
    pub fn init() -> Result<MrouteSocket> {
        // SAFETY: a raw socket; the fd is taken into ownership immediately below.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::IPPROTO_IGMP,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("socket(SOCK_RAW, IPPROTO_IGMP) for MRT_INIT — needs CAP_NET_RAW");
        }
        // SAFETY: `fd` was just returned by socket() and is owned by nobody else.
        let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        // MRT_INIT takes an int optval of 1.
        setsockopt_val(fd, MRT_INIT, 1i32)
            .context("MRT_INIT — needs CAP_NET_ADMIN and CONFIG_IP_MROUTE")?;
        std_sock.set_nonblocking(true).context("set_nonblocking")?;
        let sock = UdpSocket::from_std(std_sock).context("tokio UdpSocket::from_std")?;
        Ok(MrouteSocket {
            sock: Arc::new(sock),
        })
    }

    /// A clonable handle to the underlying socket, for reading upcalls in the runner's
    /// select loop.
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.sock.clone()
    }

    /// Register interface `ifindex` as virtual interface `vifi` with a TTL threshold
    /// of 1 (link-local multicast never leaves; ordinary streams pass).
    pub fn add_vif(&self, vifi: u16, ifindex: u32) -> Result<()> {
        let vc = Vifctl {
            vifc_vifi: vifi,
            vifc_flags: VIFF_USE_IFINDEX,
            vifc_threshold: 1,
            vifc_rate_limit: 0,
            vifc_lcl: ifindex,
            vifc_rmt_addr: 0,
        };
        setsockopt_struct(self.sock.as_raw_fd(), MRT_ADD_VIF, &vc)
            .with_context(|| format!("MRT_ADD_VIF vif={vifi} ifindex={ifindex}"))
    }

    /// Install (or replace) the forwarding entry for `(source, group)`: `parent` is
    /// the incoming VIF, `oif_vifis` the outgoing VIFs to replicate onto.
    pub fn add_mfc(
        &self,
        source: Ipv4Addr,
        group: Ipv4Addr,
        parent: u16,
        oif_vifis: &[u16],
    ) -> Result<()> {
        let mut ttls = [0u8; MAXVIFS];
        for &v in oif_vifis {
            if (v as usize) < MAXVIFS {
                ttls[v as usize] = 1; // forward on this VIF (min TTL 1)
            }
        }
        let mfc = Mfcctl {
            mfcc_origin: u32::from(source).to_be(),
            mfcc_mcastgrp: u32::from(group).to_be(),
            mfcc_parent: parent,
            mfcc_ttls: ttls,
            mfcc_pkt_cnt: 0,
            mfcc_byte_cnt: 0,
            mfcc_wrong_if: 0,
            mfcc_expire: 0,
        };
        setsockopt_struct(self.sock.as_raw_fd(), MRT_ADD_MFC, &mfc)
            .with_context(|| format!("MRT_ADD_MFC ({source}, {group}) parent={parent}"))
    }

    /// Remove the forwarding entry for `(source, group)`.
    pub fn del_mfc(&self, source: Ipv4Addr, group: Ipv4Addr) -> Result<()> {
        let mut mfc: Mfcctl = unsafe { mem::zeroed() };
        mfc.mfcc_origin = u32::from(source).to_be();
        mfc.mfcc_mcastgrp = u32::from(group).to_be();
        setsockopt_struct(self.sock.as_raw_fd(), MRT_DEL_MFC, &mfc)
            .with_context(|| format!("MRT_DEL_MFC ({source}, {group})"))
    }
}

impl Drop for MrouteSocket {
    fn drop(&mut self) {
        // Relinquish the multicast router role so the kernel tears the forwarding
        // down; ignore errors (we are on the way out).
        let _ = setsockopt_val(self.sock.as_raw_fd(), MRT_DONE, 0i32);
    }
}

/// `setsockopt(IPPROTO_IP, name, &value)` with an `i32` optval.
fn setsockopt_val(fd: i32, name: libc::c_int, value: i32) -> Result<()> {
    // SAFETY: `&value` is a valid optval of the declared size for the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            name,
            &value as *const i32 as *const c_void,
            mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("setsockopt {name}"));
    }
    Ok(())
}

/// `setsockopt(IPPROTO_IP, name, &value)` with a struct optval (`vifctl`/`mfcctl`).
fn setsockopt_struct<T>(fd: i32, name: libc::c_int, value: &T) -> Result<()> {
    // SAFETY: `value` points to a `T` that lives across the call; its size matches.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            name,
            value as *const T as *const c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("setsockopt {name}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_kernel() {
        // The kernel ABI sizes (x86-64 / arm64): vifctl 16 bytes, mfcctl 60 bytes.
        assert_eq!(mem::size_of::<Vifctl>(), 16);
        assert_eq!(mem::size_of::<Mfcctl>(), 60);
    }

    #[test]
    fn parse_upcall_reads_nocache() {
        // A NOCACHE igmpmsg as the kernel builds it: byte 0 is the copied IP
        // version/IHL (0x45), im_msgtype=1 at offset 8, im_mbz=0 at 9, im_vif=2 at 10,
        // im_src=10.0.1.2, im_dst=239.1.1.1.
        let mut buf = [0u8; 28];
        buf[0] = 0x45;
        buf[8] = IGMPMSG_NOCACHE;
        buf[9] = 0; // im_mbz — the upcall discriminator
        buf[10] = 2; // im_vif
        buf[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 1, 2).octets());
        buf[16..20].copy_from_slice(&Ipv4Addr::new(239, 1, 1, 1).octets());
        let up = parse_upcall(&buf).expect("an upcall");
        assert_eq!(up.msgtype, IGMPMSG_NOCACHE);
        assert_eq!(up.vif, 2);
        assert_eq!(up.source, Ipv4Addr::new(10, 0, 1, 2));
        assert_eq!(up.group, Ipv4Addr::new(239, 1, 1, 1));
    }

    #[test]
    fn parse_upcall_rejects_real_ip_packet() {
        // A real IP+IGMP datagram carries the protocol number (2, IGMP) at offset 9,
        // where an upcall has im_mbz = 0 — so it is not mistaken for an upcall.
        let mut buf = [0u8; 28];
        buf[0] = 0x45;
        buf[8] = IGMPMSG_NOCACHE; // coincidental byte
        buf[9] = 2; // IP protocol IGMP → not an upcall
        assert!(parse_upcall(&buf).is_none());
        // Too short.
        assert!(parse_upcall(&[0u8; 8]).is_none());
        // im_mbz = 0 but an unknown msgtype.
        let mut buf = [0u8; 28];
        buf[8] = 9;
        assert!(parse_upcall(&buf).is_none());
    }
}
