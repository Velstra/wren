# Static & Connected Routes

Before any dynamic protocol runs, Wren tracks two kinds of locally-known routes.

## Static routes

Static routes are declared in the config as a `[[static]]` array and seeded into
the RIB at startup. Each becomes a `Route` with `Protocol::Static` (preference
200), so a static route beats anything a dynamic protocol learns for the same
prefix, but loses to a directly-connected network.

```toml
[[static]]
prefix = "10.99.0.0/16"
via    = "10.9.9.254"

[[static]]
prefix = "10.88.0.0/16"
dev    = "dummy0"
metric = 50
```

A next hop is `via` (a gateway), `dev` (an interface, for an on-link route), or
both (a gateway pinned to an interface). With the kernel backend these install
straight away:

```text
10.99.0.0/16 via 10.9.9.254 proto static
10.88.0.0/16 dev dummy0 proto static metric 50
```

## Connected (direct) networks

When an interface has an address, the kernel creates a directly-connected route
for its subnet. Wren discovers these via `getifaddrs` and tracks them as
`Protocol::Connected` (preference 240 — the most preferred source) for two
reasons:

1. **Best-path** — a connected network must win over any learned route to the same
   subnet.
2. **Redistribution** — connected networks are advertised into the running
   protocols (for example, RIP advertises them to neighbours).

Crucially, the router **never reprograms** a connected route into the kernel — the
kernel already owns it. Reinstalling it would fight the kernel's own entry. So
connected routes are tracked in the RIB and redistributed, but the FIB step is
skipped for them; in `ip route` they stay `proto kernel`, while only learned
routes appear as `proto rip` / `proto ospf` / `proto bgp`.

Connected discovery covers both IPv4 (seeded into RIP) and IPv6 (seeded into
RIPng, skipping link-local `fe80::/10`).
