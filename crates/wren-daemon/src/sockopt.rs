//! Small `setsockopt` helpers shared by every protocol runner that hand-builds a raw
//! or multicast socket (RIP/RIPng, OSPF/OSPFv3, IS-IS, Babel). Kept in a neutral,
//! always-compiled module so one protocol's build does not pull in another's just to
//! reach these — important now that protocols are behind cargo features.

use std::ffi::c_void;
use std::{io, mem};

use anyhow::{Context, Result};

/// `setsockopt` with an `int` optval.
// Not every protocol subset uses this (IS-IS only needs `setsockopt_struct`), so it can
// be dead in an `--features isis`-only build.
#[allow(dead_code)]
pub(crate) fn setsockopt_int(fd: i32, level: i32, name: i32, value: i32) -> Result<()> {
    let v: libc::c_int = value;
    // SAFETY: `&v` is a valid optval of the declared size for the option's lifetime.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &v as *const _ as *const c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("setsockopt {name}"));
    }
    Ok(())
}

/// `setsockopt` with a struct optval (e.g. `ip_mreqn`).
// Only the multicast IGP runners use this; a BFD-only (`--no-default-features`) build
// reaches `setsockopt_int` but not this, so it can be dead there.
#[allow(dead_code)]
pub(crate) fn setsockopt_struct<T>(fd: i32, level: i32, name: i32, value: &T) -> Result<()> {
    // SAFETY: `value` points to a `T` that lives across the call; its size matches.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
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
