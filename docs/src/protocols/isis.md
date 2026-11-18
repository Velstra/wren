# IS-IS on a point-to-point link {#is-is}

IS-IS exchanges link-state information over the interface itself. Identify the router by its unique system ID and inspect adjacency level as well as interface state.

<a id="how-it-differs-from-ospf"></a>

## Configure the first router {#configuration}

This router uses the fixture’s six-byte system ID. Give the peer its own ID and matching level/network type.

```toml
router-id = "10.0.0.1"
[isis]
enabled = true
interfaces = ["veth0"]
system-id = "0000.0000.0001"
network-type = "point-to-point"
hello-interval = 3
```


## Observe the result {#inspecting-it}

```sh
bash scripts/isis-show-smoke.sh
```

On a separate running instance, inspect the same state:

```sh
wren show isis neighbors
wren show isis interfaces
wren show isis database
```

The lab checks that `0000.0000.0002` reaches `Up` at level 1 and that `veth0` is a point-to-point `l1l2` interface.

[Lab source](https://github.com/Velstra/wren/blob/main/scripts/isis-show-smoke.sh).

<a id="redistribution-from-the-rib"></a>
<a id="authentication-iso-10589-98-rfc-5310"></a>
<a id="not-yet-implemented"></a>

## Levels, redistribution, and authentication {#what-is-implemented}

Use the [three-way handshake test](https://github.com/Velstra/wren/blob/main/scripts/isis-threeway-smoke.sh) for point-to-point adjacency and the [L1/L2 leak test](https://github.com/Velstra/wren/blob/main/scripts/isis-l1l2-leak-smoke.sh) for cross-level prefix policy. The [redistribution](https://github.com/Velstra/wren/blob/main/scripts/isis-redistribute-smoke.sh) and [authentication](https://github.com/Velstra/wren/blob/main/scripts/isis-auth-smoke.sh) fixtures include both endpoints.
