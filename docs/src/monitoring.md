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
```

Each is answered by the task that owns the state, so a `show` never blocks the
forwarding plane or races a RIB update.

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

[fmt]: https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format
[tc]: https://github.com/prometheus/node_exporter#textfile-collector
