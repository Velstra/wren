# BGP on Linux {#bgp-4}

Wren can carry an IPv4 prefix across a peering link with only IPv6 addresses. Use the example below to verify both the negotiated next hop and the installed Linux route.

<a id="extended-next-hop--ipv4-over-ipv6-rfc-5549"></a>
<a id="configuration"></a>
<a id="ipv6-unicast--mp-bgp-rfc-4760"></a>
<a id="link-local-next-hops-rfc-2545"></a>

## Peer over an IPv6-only link {#ipv6-transport-true-unnumbered}

The lab connects AS 65001 to AS 65002 over `2001:db8::/64`. Router B originates `10.99.0.0/24`. A and B negotiate extended next-hop encoding; the 32-bit router IDs do not need to be assigned to the peering interfaces.

**Router A · receiving peer**

```toml
router-id = "10.0.0.1"
[bgp]
enabled             = true
local-as            = 65001
ebgp-require-policy = false
[[bgp.neighbor]]
address          = "2001:db8::2"
remote-as        = 65002
extended-nexthop = true
```

**Router B · originating peer**

```toml
router-id = "10.0.0.2"
[bgp]
enabled             = true
local-as            = 65002
network             = ["10.99.0.0/24"]
next-hop6           = "2001:db8::2"
ebgp-require-policy = false
[[bgp.neighbor]]
address          = "2001:db8::1"
remote-as        = 65001
passive          = true
extended-nexthop = true
```

The example sets `ebgp-require-policy = false` for this isolated two-router test. For deployment, attach explicit import and export filters as in the [configuration guide](../configuration.md#route-filters--filter-and-import).



<a id="operational-visibility"></a>

## Verify the route in Linux {#testing-it}

From the checkout root on Linux with iproute2 and user/network namespaces enabled:

```sh
bash scripts/bgp-unnumbered-smoke.sh
```

| Inspect | What the lab checks |
| --- | --- |
| `wren show bgp neighbors` | `2001:db8::2 AS 65002 Established` |
| `wren show bgp` | `10.99.0.0/24` has an IPv6 next hop |
| `ip -4 route show proto bgp` | `10.99.0.0/24 via inet6 … dev veth0` |

For a directly connected peer the next hop may be link-local. Check the egress interface alongside that address. If the peer is up but the route is absent, check address-family negotiation and eBGP policy first. [Full test fixture](https://github.com/Velstra/wren/blob/main/scripts/bgp-unnumbered-smoke.sh).


<a id="route-policy--per-neighbour-import--export-filters"></a>
<a id="turning-it-off-where-you-mean-it"></a>

## Filter what an eBGP peer can exchange {#default-deny-without-policy-rfc-8212}

The default eBGP policy requires explicit filters for each direction. The [configuration example](../configuration.md#route-filters--filter-and-import) admits one prefix per direction. Run `bash scripts/bgp-default-deny-smoke.sh` to compare the four cases: neither filter, import only, export only, and both. A peer can remain Established throughout while its usable route set changes.


## Change and observe sessions {#what-is-implemented}

[Add or remove a peer while other sessions stay up](../monitoring.md#configuration-hot-reload--sighup). For other protocol mechanisms, each linked lab below includes both ends and the assertions made on the receiver. From the checkout root, run `bash scripts/<lab-name>-smoke.sh`.


### Select and propagate paths

| Capability | What to verify | Lab |
| --- | --- | --- |
| <a id="4-octet-as-numbers-rfc-6793"></a>Four-octet ASNs | Negotiate a four-byte ASN across a peering session. | [bgp-4octet](https://github.com/Velstra/wren/blob/main/scripts/bgp-4octet-smoke.sh) |
| <a id="multipath-ecmp"></a>Equal-cost next hops | Check that two eligible paths produce a multipath kernel route. | [bgp-multipath](https://github.com/Velstra/wren/blob/main/scripts/bgp-multipath-smoke.sh) |
| <a id="add-path-rfc-7911"></a>ADD-PATH | Compare one path with multiple path IDs announced to an IPv4 peer. | [bgp-add-path](https://github.com/Velstra/wren/blob/main/scripts/bgp-add-path-smoke.sh) |
| <a id="redistribution"></a>Redistribution | Originate selected routes from another protocol in BGP. | [bgp-redistribute](https://github.com/Velstra/wren/blob/main/scripts/bgp-redistribute-smoke.sh) |
| <a id="propagation-transit"></a>Transit | Observe the AS path after an advertisement crosses a transit AS. | [bgp-propagate](https://github.com/Velstra/wren/blob/main/scripts/bgp-propagate-smoke.sh) |
| <a id="route-reflection-rfc-4456"></a>Route reflection | Relay a route between iBGP clients without a direct client-to-client session. | [bgp-route-reflection](https://github.com/Velstra/wren/blob/main/scripts/bgp-route-reflection-smoke.sh) |
| <a id="confederations-rfc-5065"></a>Confederations | Compare AS paths inside the confederation and at the external edge. | [bgp-confederation](https://github.com/Velstra/wren/blob/main/scripts/bgp-confederation-smoke.sh) |
| <a id="default-originate"></a>Default origination | Limit which neighbor receives the advertised default. | [bgp-default-originate](https://github.com/Velstra/wren/blob/main/scripts/bgp-default-originate-smoke.sh) |
| <a id="address-aggregation-rfc-4271-9222"></a>Address aggregation | Compare the summary and its contributing prefixes. | [bgp-aggregate](https://github.com/Velstra/wren/blob/main/scripts/bgp-aggregate-smoke.sh) |


### Tag and validate routes

| Capability | What to verify | Lab |
| --- | --- | --- |
| <a id="communities-rfc-1997"></a>Standard communities | Recognize community attributes at the receiving peer. | [bgp-community](https://github.com/Velstra/wren/blob/main/scripts/bgp-community-smoke.sh) |
| <a id="per-prefix-communities-via-the-export-filter"></a>Per-prefix tags | Apply tags selectively with a neighbor export filter. | [bgp-export-filter](https://github.com/Velstra/wren/blob/main/scripts/bgp-export-filter-smoke.sh) |
| <a id="large-communities-rfc-8092"></a>Large communities | Observe the global administrator and two local values on a received route. | [bgp-large-community](https://github.com/Velstra/wren/blob/main/scripts/bgp-large-community-smoke.sh) |
| <a id="extended-communities-rfc-4360"></a>Extended communities | Inspect extended community attributes after exchange. | [bgp-ext-community](https://github.com/Velstra/wren/blob/main/scripts/bgp-ext-community-smoke.sh) |
| <a id="rpki-origin-validation-rfc-6811"></a>Origin validation | Compare Valid, Invalid and NotFound results against local ROAs. | [bgp-rpki](https://github.com/Velstra/wren/blob/main/scripts/bgp-rpki-smoke.sh) |
| <a id="fetching-roas-over-rtr-rfc-8210"></a>RTR cache | Fetch ROAs from a validating cache and check how invalid origins are handled. | [bgp-rtr](https://github.com/Velstra/wren/blob/main/scripts/bgp-rtr-smoke.sh) |


### Operate sessions

| Capability | What to verify | Lab |
| --- | --- | --- |
| <a id="connection-collision-detection-rfc-4271-68"></a>Connection collisions | Check which session remains when both neighbors initiate. | [bgp-collision](https://github.com/Velstra/wren/blob/main/scripts/bgp-collision-smoke.sh) |
| <a id="ttl-security-gtsm-rfc-5082"></a>TTL security | Set the expected hop distance consistently on both peers. | [bgp-ttl-security](https://github.com/Velstra/wren/blob/main/scripts/bgp-ttl-security-smoke.sh) |
| <a id="tcp-md5-authentication-passwords-rfc-2385"></a>TCP-MD5 | Configure matching peer authentication on a supported Linux kernel. | [bgp-password-v6](https://github.com/Velstra/wren/blob/main/scripts/bgp-password-v6-smoke.sh) |
| <a id="tcp-ao-authentication-rfc-5925"></a>TCP-AO | Negotiate a session on a kernel with TCP-AO support. | [bgp-tcp-ao](https://github.com/Velstra/wren/blob/main/scripts/bgp-tcp-ao-smoke.sh) |
| <a id="maximum-prefix-limit-rfc-4486"></a>Maximum prefixes | Bound the number of prefixes accepted from one peer. | [bgp-max-prefix](https://github.com/Velstra/wren/blob/main/scripts/bgp-max-prefix-smoke.sh) |
| <a id="route-refresh-rfc-2918"></a>Route refresh | Request advertisements again over an established session. | [bgp-route-refresh](https://github.com/Velstra/wren/blob/main/scripts/bgp-route-refresh-smoke.sh) |
| <a id="graceful-restart-rfc-4724"></a><a id="helper-behaviour"></a>Graceful restart | Observe retained routes on a helper when its peer restarts. | [bgp-graceful-restart](https://github.com/Velstra/wren/blob/main/scripts/bgp-graceful-restart-smoke.sh) |
