# RIPv2 and RIPng {#rip--ripng}

Use `[rip]` for IPv4 and `[ripng]` for IPv6. Enable both on the same link when both families should advertise routes.

<a id="redistribution-from-the-rib"></a>

## Configure the first router {#configuration}

The lab originates two static routes. Each protocol exports the route in its own address family.

```toml
router-id = "10.0.0.1"
[[static]]
prefix = "10.99.0.0/24"
via    = "10.0.0.2"
[[static]]
prefix = "2001:db8:99::/64"
via    = "2001:db8::2"
[rip]
enabled      = true
interfaces   = ["veth0"]
redistribute = ["static"]
[ripng]
enabled      = true
interfaces   = ["veth0"]
redistribute = ["static"]
```

<a id="testing-it"></a>

## Observe the result {#inspecting-it}

```sh
bash scripts/rip-show-smoke.sh
```

On a separate running instance, inspect the same state:

```sh
wren show rip
wren show ripng
```

Inspect `10.99.0.0/24` in the RIP table and `2001:db8:99::/64` in RIPng. With a kernel backend, inspect learned routes separately with `ip -4 route` and `ip -6 route`.

[Lab source](https://github.com/Velstra/wren/blob/main/scripts/rip-show-smoke.sh).


## Filter advertisements {#what-is-implemented}

Run the [IPv4 redistribution lab](https://github.com/Velstra/wren/blob/main/scripts/rip-redistribute-smoke.sh) and the [IPv6 redistribution lab](https://github.com/Velstra/wren/blob/main/scripts/ripng-redistribute-smoke.sh) to compare an accepted and a rejected route across a live adjacency.
