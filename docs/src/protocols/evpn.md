# Exchange tenant reachability with EVPN {#evpn}

Use a MAC-VRF to exchange tenant MAC addresses and an IP-VRF to exchange tenant prefixes. Each imports its own route targets. A route reflector can relay these advertisements without being a tenant VTEP.

<a id="two-entities-not-one"></a>

## Configure the first router {#configuration}

This leaf advertises a MAC/IP on VNI 10100 and an IP prefix in L3 VNI 50100. Its peer is an iBGP route reflector. The other leaf uses its own addresses and matching tenant import targets.

```toml
router-id = "10.0.0.1"
[bgp]
enabled  = true
local-as = 65010
[[bgp.neighbor]]
address   = "10.0.0.254"
remote-as = 65010
passive   = true
evpn      = true
[bgp.evpn]
vtep-ip = "10.0.0.1"
srv6-locator = "fc00:0:1::/48"
[[bgp.evpn.instance]]
evi = 100
vni = 10100
advertise-mac = ["02:00:5e:00:00:01/10.100.0.1"]
[[bgp.evpn.ip-vrf]]
name = "tenant-a"
l3-vni = 50100
advertise-prefix = ["10.20.0.0/24"]
router-mac = "02:00:5e:00:00:aa"
```

<a id="the-monitor-stream"></a>

## Observe the result {#operational-visibility}

```sh
bash scripts/bgp-evpn-smoke.sh
```

On a separate running instance, inspect the same state:

```sh
wren show evpn
wren monitor evpn
```

On the receiving leaf, the test checks the remote MAC, flood VTEP, and `10.20.0.0/24` in tenant-a. The monitor emits `vni` for bridging entries and `l3vni` for routed entries.

[Lab source](https://github.com/Velstra/wren/blob/main/scripts/bgp-evpn-smoke.sh).

<a id="router-mac-is-not-optional-under-vxlan"></a>
<a id="type-5-uses-the-interface-less-model"></a>
<a id="evpn-over-srv6"></a>

## VXLAN and SRv6 service identifiers {#what-is-implemented}

For routed VXLAN traffic the IP-VRF advertises a router MAC. With `srv6-locator` configured, eligible EVPN advertisements also carry service SIDs. Use the receiving leaf’s `show evpn` and monitor output to verify the remote next hop and SID. A forwarding-plane consumer implements the encapsulation.

<a id="not-yet-implemented"></a>

## Advertise a local MAC on demand {#advertising-at-runtime}

On a running VNI, `wren evpn advertise 10100 02:00:00:00:00:cc 192.0.2.20` originates a type-2 route. Use `wren evpn withdraw 10100 02:00:00:00:00:cc` to withdraw it. The documented lab covers single-homed leaf VTEPs and route types 2, 3, and 5.
