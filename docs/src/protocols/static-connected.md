# Static and connected routes {#static--connected-routes}

## Declare a static route {#static-routes}

Use `via` for a gateway, `dev` for an on-link destination, or both to pin a gateway to an interface. A blackhole route has no next hop. This example keeps a fallback route to the documentation prefix.

```toml
router-id = "192.0.2.10"
[[static]]
prefix = "198.51.100.0/24"
via = "192.0.2.1"
distance = 250
```

Save as `fallback.toml` and run `wren check -c fallback.toml`. With the kernel backend, the gateway must resolve through an interface. Check `wren show routes` for the selected path and `ip -4 route show exact 198.51.100.0/24` for the kernel result. A higher administrative distance makes the fallback less preferred.

## Interpret connected networks {#connected-direct-networks}

Linux creates a route when it configures a local subnet. Wren can use connected networks for route selection and redistribution. Interface routes stay under kernel ownership; they are omitted from the [forwarding export stream](../monitoring.md#streaming-the-forwarding-table--wren-monitor-routes). Inspect `ip -4 route show proto kernel` to see routes installed by address configuration.
