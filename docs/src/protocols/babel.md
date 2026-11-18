# Babel neighbor and route inspection {#babel}

Babel uses Hello and IHU messages to measure a neighboring link. Examine receive and total link cost before interpreting the metric of a learned IPv6 prefix.

<a id="what-is-implemented"></a>

## Configure the first router {#configuration}

The two test routers use separate interfaces joined by a veth pair. This is router A.

```toml
router-id = "10.0.0.1"
[babel]
enabled = true
interfaces = ["veth0"]
```

<a id="testing-it"></a>

## Observe the result {#inspecting-it}

```sh
bash scripts/babel-show-smoke.sh
```

On a separate running instance, inspect the same state:

```sh
wren show babel neighbors
wren show babel routes
```

The lab finds a link-local neighbor with numeric `rxcost` and `cost` values, then checks `2001:db8:99::/64` through a link-local next hop.

[Lab source](https://github.com/Velstra/wren/blob/main/scripts/babel-show-smoke.sh).

<a id="not-yet-implemented"></a>

## Redistribute selected routes {#redistribution-from-the-rib}

The [redistribution lab](https://github.com/Velstra/wren/blob/main/scripts/babel-redistribute-smoke.sh) exercises the export policy. Use the [VRF lab](https://github.com/Velstra/wren/blob/main/scripts/vrf-babel-smoke.sh) when the route belongs in a separate Linux table. The neighbor lab above measures a wired virtual link; use your own topology to evaluate wireless behavior.
