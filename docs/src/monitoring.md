# Monitoring

Wren exposes its state for monitoring the same way it exposes everything else: as
text over the [control socket](getting-started.md), in the tradition of BIRD's
`birdc` and FRR's `vtysh`. There is no embedded HTTP server and no second
listening port — the operational `show` commands and the metrics share the one
Unix socket.

## Operational `show` commands

```sh
wren show routes                 # the merged RIB (à la `ip route`)
wren show routes ospf            # … filtered to one protocol
wren show bgp [routes|paths|neighbors]
wren show ospf  [neighbors|interfaces|database]
wren show ospf3 [neighbors|interfaces]
wren show isis  [neighbors|interfaces|database]
wren show babel [neighbors|routes]
wren show rip   |  wren show ripng
wren show vrrp                   # VRRP virtual routers (first-hop HA)
```

Each is answered by the task that owns the state, so a `show` never blocks the
forwarding plane or races a RIB update.

## Streaming the forwarding table — `wren monitor routes`

Where `show routes` is a one-shot snapshot, `monitor routes` opens a **long-lived
subscription** and streams the forwarding table as it changes — an initial
snapshot of every current route, then live install/withdraw events as the RIB
moves:

```sh
$ wren monitor routes
% end-of-dump                                                  # snapshot complete
+ 10.20.0.0/24 table 254 via 10.0.0.2 proto bgp metric 1       # a route appeared
- 10.20.0.0/24 table 254                                       # …and was withdrawn
```

The format is deliberately line-based and stable so an external program can parse
it:

* `+ <prefix> table <t> [via <gw>] [dev <dev>] … proto <p> metric <m>` — a route
  was installed or changed (each next-hop carries its gateway and/or egress
  interface; `table` is always printed, so the VRF is unambiguous);
* `- <prefix> table <t>` — a route was withdrawn;
* `% end-of-dump` — the initial snapshot is complete; everything after is live.

The stream mirrors exactly what the router programs into the FIB (best-path,
post-export-filter; directly-connected routes are omitted, as the consumer owns
its own interface routes). This is Wren's equivalent of FRR zebra's **Forwarding
Plane Manager (FPM)**: the feed an external forwarding plane consumes to mirror
Wren's routing decisions — for example the [Velstra](https://github.com/Velstra)
eBPF/XDP data plane, which subscribes, resolves each next-hop's L2 address, and
programs its own route map. Keeping the contract a generic stream (rather than a
Velstra-specific `Fib` backend) leaves Wren free of any consumer coupling.

## Configuration hot-reload — `SIGHUP`

Send the running daemon `SIGHUP` and it **re-reads its configuration file and
applies the delta in place**, without restarting or disturbing unaffected
protocol sessions:

```sh
$ kill -HUP "$(pidof wren)"      # or: systemctl reload wren
```

On `SIGHUP` Wren re-reads the config, resolves its static routes afresh, and
diffs them against the running set — installing added routes, removing deleted
ones, and replacing changed ones through the same RIB/FIB pipeline as a live
protocol update. An added or removed static therefore shows up immediately in
`show routes` and streams to every open [`monitor routes`](#streaming-the-forwarding-table--wren-monitor-routes)
subscriber. Because no protocol engine is touched, **every BGP/OSPF/IS-IS/…
session and adjacency stays up across the reload**, as do the routes learned over
them. A config that fails to parse (or names an unknown filter) is logged and
ignored, so a bad edit never crashes the daemon or drops the running
configuration.

> Live reconfiguration of the protocol engines themselves — adding or removing
> BGP neighbours, enabling a protocol, or swapping filters on the fly — is not yet
> wired (each needs a per-engine reconfiguration path); today those still require a
> restart. Full model-driven management (gNMI/OpenConfig) is future work.

## Prometheus metrics

`wren show metrics` renders the [Prometheus text exposition format][fmt]:

```sh
$ wren show metrics
# HELP wren_rib_routes Best routes in the RIB by origin protocol.
# TYPE wren_rib_routes gauge
wren_rib_routes{protocol="bgp"} 12
wren_rib_routes{protocol="ospf"} 5
wren_rib_routes{protocol="connected"} 3
# HELP wren_bgp_neighbor_up Whether the BGP session to a neighbour is Established (1) or not (0).
# TYPE wren_bgp_neighbor_up gauge
wren_bgp_neighbor_up{neighbor="10.0.0.2",asn="65002"} 1
# HELP wren_bgp_neighbors_established BGP neighbours whose session is currently Established.
# TYPE wren_bgp_neighbors_established gauge
wren_bgp_neighbors_established 1
# HELP wren_bgp_rib_routes Best paths in the BGP Loc-RIB.
# TYPE wren_bgp_rib_routes gauge
wren_bgp_rib_routes 12
```

The exposition combines two sources into one document:

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `wren_rib_routes` | gauge | `protocol` | Best routes in the merged RIB, per origin protocol. Because every installed route carries its origin protocol, this one family covers **all** of them — bgp, ospf, isis, babel, rip, static, connected. |
| `wren_bgp_neighbor_up` | gauge | `neighbor`, `asn` | `1` when the session to that peer is Established, else `0` — the series to alert on. |
| `wren_bgp_neighbors_configured` | gauge | — | Configured BGP neighbours. |
| `wren_bgp_neighbors_established` | gauge | — | Neighbours currently Established. |
| `wren_bgp_route_refresh_received_total` | counter | `neighbor` | ROUTE-REFRESH requests received (RFC 2918). |
| `wren_bgp_rib_routes` | gauge | — | Best paths in the BGP Loc-RIB. |

### Scraping it

Prometheus pulls over HTTP, and Wren deliberately does not serve HTTP, so bridge
the socket the same way `bird_exporter` wraps `birdc` — for example a
[textfile-collector][tc] cron:

```sh
# /etc/cron.d/wren-metrics — node_exporter must run with
#   --collector.textfile.directory=/var/lib/node_exporter/textfile
* * * * *  root  wren show metrics > /var/lib/node_exporter/textfile/wren.prom.$$ \
                  && mv /var/lib/node_exporter/textfile/wren.prom.$$ \
                        /var/lib/node_exporter/textfile/wren.prom
```

or a one-liner that serves the socket on demand:

```sh
socat TCP-LISTEN:9999,reuseaddr,fork EXEC:'wren show metrics'
```

## BMP — streaming BGP state to a monitoring station

For BGP specifically, Wren speaks the [BGP Monitoring Protocol][bmp] (BMP,
RFC 7854): it connects out to a monitoring station and streams its BGP state as it
changes — an Initiation message, a **Peer Up** when a session establishes (carrying
both OPEN messages), a **Route Monitoring** message wrapping every UPDATE a peer
sends (so the station sees the router's Adj-RIB-In), and a **Peer Down** when a
session drops. This is what feeds collectors like `pmacct`, OpenBMP or a BMP-aware
Kafka pipeline.

Point Wren at a station with `[bgp.bmp]`:

```toml
[bgp.bmp]
station   = "203.0.113.9:11019"   # the station's host:port (BMP is conventionally 11019)
sys-name  = "edge-router-1"        # optional; defaults to the router id
sys-descr = "wren edge"            # optional; defaults to "wren"
```

BMP is **best-effort and never back-pressures routing**: events are offered to the
client with a non-blocking send and dropped if the station is slow or down, and the
client reconnects on failure. State is not replayed on reconnect — the station sees
observations from connect time forward.

[fmt]: https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
[tc]: https://github.com/prometheus/node_exporter#textfile-collector
[bmp]: https://datatracker.ietf.org/doc/html/rfc7854
