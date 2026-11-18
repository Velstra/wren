# OSPFv3 over IPv6 {#ospfv3}

OSPFv3 peers over IPv6 link-local addresses. Its router ID is still 32 bits. An IPv4 address on the peering interface is unnecessary.

<a id="what-changed-from-ospfv2"></a>

## Configure the first router {#configuration}

On a point-to-point interface, set a unique router ID on each node and enable the matching interface on its peer.

```toml
router-id = "10.0.0.1"
[ospf3]
enabled = true
interfaces = ["veth0"]
network-type = "point-to-point"
```


## Observe the result {#inspecting-it}

```sh
bash scripts/ospf3-show-smoke.sh
```

On a separate running instance, inspect the same state:

```sh
wren show ospf3 neighbors
wren show ospf3 interfaces
```

On the running lab, the neighbor appears as `10.0.0.2 via fe80:… dev veth0 state Full`. The interface view identifies area `0.0.0.0` and `PtP`.

[Lab source](https://github.com/Velstra/wren/blob/main/scripts/ospf3-show-smoke.sh).

<a id="not-yet-implemented"></a>

## Validate additional requirements {#what-is-implemented}

Use [the OSPFv3/BFD lab](https://github.com/Velstra/wren/blob/main/scripts/ospf3-bfd-smoke.sh) to observe a failed BFD session tear down the adjacency. For authenticated adjacencies, use the [authentication trailer configuration](https://github.com/Velstra/wren/blob/main/scripts/ospf3-auth-smoke.sh) on both peers.
