# Introduction

**Wren** is a routing daemon written in Rust. It speaks the standard routing
protocols — each implemented to its RFC — and programs the operating system's
forwarding table, the job that [BIRD](https://github.com/CZ-NIC/bird) and
[FRR](https://github.com/FRRouting/frr) do, rebuilt in safe Rust around a small,
dependency-free core.

It is developed with two uses in mind:

1. **A standalone daemon** — run `wren` on a Linux router or host, point it at a
   TOML config, and it learns routes from its neighbours and installs the winners
   into the kernel routing table over netlink.
2. **An embeddable control plane** — the [`wren-core`](core.md) crate carries no
   dependencies, so the route table and best-path logic link directly into other
   programs. The first such consumer is the [Velstra **Sentinel**](https://github.com/velstra)
   appliance, whose eBPF/XDP data plane can consume Wren's chosen routes.

## Status

Wren is **early** (`0.0.x`); the wire formats and configuration may still change.
What works today, end to end and verified between real routers in Linux network
namespaces:

| Capability | RFC | State |
|---|---|---|
| Static routes | — | ✅ |
| Connected (direct) networks | — | ✅ |
| RIPv2 | [2453](https://www.rfc-editor.org/rfc/rfc2453) | ✅ |
| RIPng (IPv6) | [2080](https://www.rfc-editor.org/rfc/rfc2080) | ✅ |
| OSPFv2 (single-area, multi-area, AS-external) | [2328](https://www.rfc-editor.org/rfc/rfc2328) | ✅ |
| BGP-4 (IPv4 unicast, eBGP/iBGP) | [4271](https://www.rfc-editor.org/rfc/rfc4271) | ✅ |
| Netlink kernel FIB backend | — | ✅ |

The [Roadmap](roadmap.md) tracks what is next (OSPFv3, Babel, BGP extensions,
policy filters, VRFs, a management CLI).

## How to read this handbook

- **[Getting Started](getting-started.md)** — build, run and try Wren in a throwaway
  network namespace without root.
- **[Architecture](architecture.md)** — how the daemon is structured: the FRR-style
  split between a central route manager and the protocol engines, and how the
  crates layer on top of a dependency-free core.
- **[Configuration](configuration.md)** — the complete `wren.toml` reference.
- **Protocols** — one chapter per protocol family: what is implemented, how it maps
  to the RFC, and how to configure and test it.
- **[The Core](core.md)** — the RIB, the FIB abstraction, best-path selection, and
  how to embed `wren-core` in another program.

## License

Wren follows an **open-core split**: the dependency-free **`wren-core`** is
**Apache-2.0** so it can be embedded anywhere (including downstream proprietary or
AGPL projects like the Velstra Sentinel), while the daemon and every other crate
are **GPL-2.0-or-later** — the same copyleft as BIRD, keeping the routing stack
fully open and protected against proprietary forks. Contributions are accepted
inbound = outbound under these licenses; no CLA is required.
