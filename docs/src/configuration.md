# Configure routes and policy {#configuration}

## Start with one file {#top-level}

Wren loads TOML from `/etc/wren/wren.toml` or the path supplied with `--config`. Use a unique 32-bit router ID. The ID is still written as an IPv4 address on a router with only IPv6 transport.

<a id="static-routes"></a>

```toml
router-id = "192.0.2.10"
[[static]]
prefix = "198.51.100.0/24"
via = "192.0.2.1"
```

Save this as `router.toml`. Check it before starting the daemon:

```sh
wren check --config router.toml
```

The result should report one static route. A successful check validates the file; use a peer and a kernel route lookup to verify reachability.

## Apply an explicit eBGP policy {#route-filters--filter-and-import}

This complete example permits a single peer prefix in and a single local prefix out. Both filters reject everything else.

```toml
router-id = "192.0.2.10"

[[filter]]
name = "from-peer"
default = "reject"
[[filter.rule]]
prefix = ["203.0.113.0/24"]
action = "accept"

[[filter]]
name = "to-peer"
default = "reject"
[[filter.rule]]
prefix = ["198.51.100.0/24"]
action = "accept"

[bgp]
enabled = true
local-as = 65001
network = ["198.51.100.0/24"]
[[bgp.neighbor]]
address = "192.0.2.20"
remote-as = 65002
import = "from-peer"
export = "to-peer"
```

With default RFC 8212 policy, a session can be Established and exchange no usable routes in a direction with no attached policy. [Verify the filters in a running lab](protocols/bgp.md#default-deny-without-policy-rfc-8212).

## Protocol configuration

| Section | Example |
| --- | --- |
| <span id="bgp-4--bgp">`[bgp]`</span> | [IPv4 routes over an IPv6-only link](protocols/bgp.md#ipv6-transport-true-unnumbered) |
| <span id="ospfv2--ospf">`[ospf]`</span> | [Two IPv4 neighbors on a point-to-point link](protocols/ospf.md) |
| <span id="ospfv3--ospf3">`[ospf3]`</span> | [IPv6 link-local adjacency](protocols/ospfv3.md) |
| <span id="rip-ipv4--rip">`[rip]`</span> and <span id="ripng-ipv6--ripng">`[ripng]`</span> | [Advertise static routes by family](protocols/rip.md) |
| <span id="babel--babel">`[babel]`</span> | [Observe a Babel neighbor and route](protocols/babel.md) |
| `[isis]`, `[bfd]`, `[[vrf]]`, `[[vrrp]]` | [IS-IS](protocols/isis.md), [BFD](protocols/bfd.md), [VRFs](vrf.md), [VRRP](vrrp.md) |

[Full schema and defaults](https://github.com/Velstra/wren/tree/main/crates/wren-config/src) · [Worked configuration](https://github.com/Velstra/wren/blob/main/examples/wren.toml)
