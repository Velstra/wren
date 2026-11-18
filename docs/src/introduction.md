# Wren operator handbook {#introduction}

Wren exchanges routes with adjacent routers and can install selected paths in the Linux forwarding table. Use this handbook to evaluate a peering change in a disposable lab, inspect what reached the kernel, and decide which protocols fit your deployment.

## Choose a task {#how-to-read-this-handbook}

| Task | Start here |
| --- | --- |
| Validate a configuration without starting routing | [Build Wren and check a file](getting-started.md) |
| Carry IPv4 prefixes without assigning IPv4 addresses to the peering link | [Run the IPv6-only BGP lab](protocols/bgp.md#ipv6-transport-true-unnumbered) |
| Add a neighbor while unaffected BGP sessions keep their routes | [Reload and verify the change](monitoring.md#configuration-hot-reload--sighup) |
| Keep tenant routes in independent Linux tables | [Place a BGP instance in a VRF](vrf.md) |
| Feed forwarding decisions to another process | [Subscribe to route changes](monitoring.md#streaming-the-forwarding-table--wren-monitor-routes) |

## Which version? {#status}

The published handbook follows `main`. For a released binary, start with its [release notes](https://github.com/Velstra/wren/releases) and use the examples from the matching tag. [Coverage and release status](roadmap.md) distinguishes working scenarios from open requirements.

## License

The routing core uses Apache-2.0. The daemon and the other crates use GPL-2.0-or-later. [License files](https://github.com/Velstra/wren#license)
