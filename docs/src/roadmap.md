# Coverage and release status {#roadmap}

This handbook is built from `main`. Check [tagged releases](https://github.com/Velstra/wren/releases) and the [changelog](https://github.com/Velstra/wren/blob/main/CHANGELOG.md) for the version you intend to deploy. The rows below point to repeatable acceptance cases for a checkout.

## Select a test by requirement {#protocols}

<a id="protocol-refinements"></a>

| Requirement | Where to start |
| --- | --- |
| Exchange IPv4 prefixes over an IPv6-only link | [BGP lab with a kernel next-hop check](protocols/bgp.md#ipv6-transport-true-unnumbered) |
| Add a peer without losing other sessions’ routes | [Three-peer reload procedure](monitoring.md#configuration-hot-reload--sighup) |
| Separate tenants in the control plane | [EVPN route types 2/3/5](protocols/evpn.md), [Linux VRF table isolation](vrf.md) |
| Verify an IGP adjacency | [OSPFv2](protocols/ospf.md), [OSPFv3](protocols/ospfv3.md), [IS-IS](protocols/isis.md), [Babel](protocols/babel.md) |
| Check first-hop or neighbor failover | [VRRP address movement](vrrp.md), [BFD and BGP state transitions](protocols/bfd.md) |
| Inspect multicast behavior | [IGMP querier](https://github.com/Velstra/wren/blob/main/scripts/igmp-querier-smoke.sh), [MLD querier](https://github.com/Velstra/wren/blob/main/scripts/mld-querier-smoke.sh), [PIM-SM](https://github.com/Velstra/wren/blob/main/scripts/pim-sm-smoke.sh) |

## Boundaries to check before deployment {#still-open}

<a id="on-the-radar-longer-term"></a>

The EVPN guide covers single-homed VTEPs. Ordinary Linux VRF table isolation and EVPN IP-VRF routes are distinct from MPLS VPNv4 service. FlowSpec exports selected rules through the control socket and expects an enforcing data-plane consumer. A lab that verifies a BGP route reached Linux does not measure line-rate throughput or interoperability with a particular vendor appliance.

## Platform and tests {#platform--core}

<a id="testing"></a>

```sh
cargo test --locked -p wren-core
bash scripts/run-all-tests.sh
```

The core suite runs in process. The integration suite needs a Linux kernel with the namespace, routing and protocol capabilities used by each test. For deployment-specific requirements, start with the linked individual lab and reproduce its assertions on your target environment. [Current issues](https://github.com/Velstra/wren/issues)
