# How Wren selects a route {#architecture}

## Follow a prefix {#the-central-router-loop}

1. A protocol accepts an advertisement and submits a candidate to the route manager.
2. The RIB compares candidates for that table and prefix. When the winner changes, the RIB produces an install or a removal.
3. The selected backend applies the forwarding update. Import and FIB export policy can affect what is retained or installed. Connected networks stay under kernel ownership.

To distinguish a learned path from an installed one, inspect all three views:

```sh
wren show bgp routes
wren show routes
ip -4 route show proto bgp
```

## Compare competing sources {#best-path-selection}

Within a table and prefix, higher administrative preference wins, followed by lower metric. Defaults include Connected 240, Static 200, OSPF 150, IS-IS 145, RIP 120, Babel 115, BGP 100, and Kernel 10. A BGP path first competes with other BGP paths inside the protocol. A configured static administrative `distance` uses the opposite scale: a larger distance makes it a weaker candidate.

## Trace the implementation {#the-crates}

<a id="pure-logic-vs-io"></a>

| Component | Responsibility |
| --- | --- |
| [wren-core](core.md) | Prefixes, next hops, route identity, best-route selection, and the FIB trait |
| [wren-filter](https://github.com/Velstra/wren/tree/main/crates/wren-filter) | Apply rule sets at import and export |
| [wren-daemon](https://github.com/Velstra/wren/tree/main/crates/wren-daemon) | Sockets, timers, control queries, the router loop, and configuration reload |
| [wren-netlink](https://github.com/Velstra/wren/tree/main/crates/wren-netlink) | Encode decisions as Linux kernel route updates |

Other processes can [subscribe to forwarding changes](monitoring.md#streaming-the-forwarding-table--wren-monitor-routes) over the local control socket.
