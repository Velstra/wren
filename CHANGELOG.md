# Changelog

All notable changes to Wren are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/) once it reaches `0.1.0`.

## [0.0.1] — 2026-06-28

The first public release. Wren is a small, RFC-correct routing daemon in Rust —
the job of BIRD/FRR, rebuilt with a dependency-free, embeddable core.

### Routing protocols

- **Static** routes and **connected** (direct) networks, tracked in the RIB and
  redistributable.
- **RIPv2** (RFC 2453) and **RIPng** (RFC 2080) over a shared distance-vector
  engine.
- **OSPFv2** (RFC 2328) — point-to-point and broadcast links, multi-area via an
  ABR, AS-external via an ASBR.
- **OSPFv3** (RFC 5340) — OSPF for IPv6, end to end.
- **IS-IS** (ISO/IEC 10589 + RFC 1195) — dual-stack wide metrics, L1/L2, the
  adjacency FSM, DIS election and SPF, over an `AF_PACKET` layer-2 runner.
- **BGP-4** (RFC 4271) — eBGP/iBGP over TCP 179, with **4-octet ASNs** (RFC 6793),
  **communities** (RFC 1997) and **large communities** (RFC 8092).
- **Babel** (RFC 8966) — loop-avoiding distance-vector over IPv6.

### Platform & policy

- **Netlink FIB backend** (Linux rtnetlink) with **ECMP / multipath** and
  startup route reconciliation.
- **Route filters** (BIRD-style import/export policy) with prefix patterns,
  protocol/metric matches, and metric/preference/community rewrites.
- **RIB-based redistribution** into every protocol, with optional per-protocol
  export filters.
- **Management interface**: a Unix control socket answering `wren show routes`,
  `show bgp [routes|neighbors]`, `show ospf [neighbors|interfaces]` and
  `show isis [neighbors|interfaces]`.

### Project

- **Open-core licensing**: the dependency-free `wren-core` is **Apache-2.0**
  (embeddable anywhere); the daemon and every other crate are
  **GPL-2.0-or-later** (like BIRD).
- An **mdBook handbook** under `docs/`, and rootless two-router convergence
  **smoke scripts** under `scripts/` (each runs in a throwaway `unshare -Urn`
  network namespace).

[0.0.1]: https://github.com/velstra/wren/releases/tag/v0.0.1
