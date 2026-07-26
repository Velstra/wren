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

## Streaming filter rules — `wren monitor flowspec`

BGP FlowSpec (RFC 8955) carries **traffic-filtering rules** in BGP: an upstream
tells you to discard, rate-limit or re-mark a particular flow, typically to
mitigate a DDoS before it reaches you. Wren selects the best path per rule into a
FlowSpec RIB (`show bgp flowspec`) — but enforcing one means touching a
forwarding datapath, which is a separate, privileged job.

`monitor flowspec` is that hand-off, the same shape as `monitor routes`: an
initial snapshot of every installed rule, then live changes.

```sh
$ wren monitor flowspec
+ flowspec action discard match dst 10.50.0.0/24 proto =6 dport =22
% end-of-dump                                        # snapshot complete
+ flowspec action rate-limit:12500 match src 192.0.2.0/24
- flowspec match dst 10.50.0.0/24 proto =6 dport =22
```

* `+ flowspec action <a>[,<a>…] match <flow specification>` — install or replace
  a rule;
* `- flowspec match <flow specification>` — the rule has no path left and must
  stop being enforced;
* `% end-of-dump` — the snapshot is complete; everything after is live.

Two details matter to anyone writing a consumer:

**The match section is last, and everything before it is keyword/value pairs.**
A flow specification is itself a variable-length list of pairs (`dst …`,
`proto …`, `dport …`), so it cannot be followed by anything. Read pairs until the
`match` keyword; take the rest as the specification. A field added in a later
release slots in before `match` and leaves that parse intact.

**Actions are space-free tokens**, not the human-readable rendering that
`show bgp flowspec` prints:

| Token | Meaning |
|---|---|
| `discard` | drop matching traffic (RFC 8955 §7.1: a traffic-rate of zero) |
| `rate-limit:<bytes-per-second>` | limit matching traffic to that rate |
| `mark:<dscp>` | rewrite the DSCP of matching packets |
| `none` | the rule carried **no recognised action community** |

`none` is deliberately explicit. A rule can reach the RIB without a usable action
community, and implying `discard` there would turn a malformed advertisement into
a blackhole — so the feed says what it knows and lets the consumer decide.

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
subscriber. Unaffected protocol engines are not touched, so **every
BGP/OSPF/IS-IS/… session and adjacency stays up across the reload**, as do the
routes learned over them. A config that fails to parse (or names an unknown
filter) is logged and ignored, so a bad edit never crashes the daemon or drops
the running configuration.

The same reload also **adds and removes BGP neighbours live**: Wren diffs the
re-read neighbour set against the running one and, without restarting the
daemon, dials a newly-configured peer to bring its session up and tears a removed
peer down with a Cease "Peer De-configured" (RFC 4486), withdrawing the routes it
had taught us. **Neighbours that are unchanged keep their session and learned
routes** — only the added and removed peers are disturbed.

> Still restart-only: per-neighbour BGP *attribute* changes on an existing peer
> (timers, filters, policy, address families — an unchanged peer address whose
> settings differ is left running as-is), enabling a protocol that was off at
> startup, adding a *passive* neighbour at runtime, and reconfiguring the other
> protocol engines on the fly. Full model-driven management (gNMI/OpenConfig) is
> future work.

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
