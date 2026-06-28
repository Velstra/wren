# Configuration

Wren's configuration is a single TOML document. Unknown keys are rejected, so a
typo fails fast rather than being silently ignored. This chapter is the complete
reference; each protocol chapter shows the same options in context.

## Top level

```toml
router-id = "10.0.0.1"   # a 32-bit id, written as an IPv4 address
```

| Key | Type | Notes |
|---|---|---|
| `router-id` | string | The router's identity, conventionally an interface address. Required by OSPF; the default BGP identifier. |

The remaining configuration is grouped into a `[[static]]` array and one table per
protocol: `[rip]`, `[ripng]`, `[ospf]`, `[ospf3]`, `[bgp]`, `[babel]`.

## Static routes

A `[[static]]` array of operator-configured routes. At least one of `via` / `dev`
is required.

```toml
[[static]]
prefix = "0.0.0.0/0"
via    = "192.0.2.1"

[[static]]
prefix = "10.20.0.0/16"
dev    = "eth1"
metric = 10
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `prefix` | string | — | Destination `addr/len`. |
| `via` | string | — | Gateway address. |
| `dev` | string | — | Outgoing interface (on-link, or to pin a gateway). |
| `metric` | integer | `0` | Lower wins among static routes. |

## RIP (IPv4) — `[rip]`

```toml
[rip]
enabled    = true
interfaces = ["eth1", "eth2"]
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Run RIP. |
| `interfaces` | list | `[]` | Interfaces to send/receive RIP on. |

See [RIP & RIPng](protocols/rip.md).

## RIPng (IPv6) — `[ripng]`

```toml
[ripng]
enabled    = true
interfaces = ["eth1", "eth2"]
```

Same fields as `[rip]`, for IPv6 (RFC 2080).

## OSPFv2 — `[ospf]`

```toml
[ospf]
enabled        = true
interfaces     = ["eth1", "eth2"]   # all placed in `area`
area           = "0.0.0.0"          # default: the backbone
router-priority = 1                  # 0 = never become DR
cost           = 10
network-type   = "broadcast"        # or "point-to-point"

# Interfaces in a different area (for an area border router):
[[ospf.interface]]
name = "eth3"
area = "0.0.0.1"

# Redistribute static routes as AS-external (type-5) LSAs (makes this an ASBR):
redistribute-static = true
redistribute-metric = 20
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Run OSPF. |
| `interfaces` | list | `[]` | Interfaces placed in `area`. |
| `area` | string | `0.0.0.0` | Default area for `interfaces`. |
| `router-priority` | integer | `1` | DR-election priority; `0` is never DR. |
| `cost` | integer | `10` | Output cost advertised for these links. |
| `network-type` | string | `broadcast` | `broadcast` (elects a DR) or `point-to-point`. |
| `[[ospf.interface]]` | array | `[]` | Per-interface `{ name, area }` overrides, for an ABR. |
| `redistribute-static` | bool | `false` | Advertise static routes as type-5 LSAs. |
| `redistribute-metric` | integer | `20` | External metric for redistributed routes. |

See [OSPFv2](protocols/ospf.md).

## OSPFv3 — `[ospf3]`

OSPF for IPv6 (RFC 5340). The same shape as `[ospf]`, plus an Instance ID; the
interfaces are routed for IPv6 and the next hops are link-local addresses.

```toml
[ospf3]
enabled        = true
interfaces     = ["eth1", "eth2"]   # all placed in `area`
area           = "0.0.0.0"          # default: the backbone
router-priority = 1                  # 0 = never become DR
cost           = 10
network-type   = "broadcast"        # or "point-to-point"
instance-id    = 0                   # several OSPFv3 instances per link

# Interfaces in a different area (for an area border router):
[[ospf3.interface]]
name = "eth3"
area = "0.0.0.1"

# Redistribute static routes as AS-external LSAs (makes this an ASBR); only the
# IPv6 statics are advertised:
redistribute-static = true
redistribute-metric = 20
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Run OSPFv3. |
| `interfaces` | list | `[]` | Interfaces placed in `area`. |
| `area` | string | `0.0.0.0` | Default area for `interfaces`. |
| `router-priority` | integer | `1` | DR-election priority; `0` is never DR. |
| `cost` | integer | `10` | Output cost advertised for these links. |
| `network-type` | string | `broadcast` | `broadcast` (elects a DR) or `point-to-point`. |
| `instance-id` | integer | `0` | OSPFv3 Instance ID carried in every packet. |
| `[[ospf3.interface]]` | array | `[]` | Per-interface `{ name, area }` overrides, for an ABR. |
| `redistribute-static` | bool | `false` | Advertise IPv6 static routes as AS-external LSAs. |
| `redistribute-metric` | integer | `20` | External metric for redistributed routes. |

OSPFv3 needs a top-level `router-id` (still a 32-bit dotted quad, even over IPv6).
See [OSPFv3](protocols/ospfv3.md).

## BGP-4 — `[bgp]`

```toml
[bgp]
enabled   = true
local-as  = 65001
router-id = "10.0.0.1"        # defaults to the top-level router-id
hold-time = 90                # seconds; default 180
network   = ["10.10.0.0/24"]  # prefixes this speaker originates

[[bgp.neighbor]]
address   = "10.0.0.2"
remote-as = 65002             # eBGP when it differs from local-as

[[bgp.neighbor]]
address   = "10.0.0.3"
remote-as = 65001             # iBGP
passive   = true              # wait for the peer to connect
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Run BGP. |
| `local-as` | integer | — | This speaker's AS (2-octet). Required, non-zero. |
| `router-id` | string | top-level `router-id` | The BGP identifier. |
| `hold-time` | integer | `180` | Proposed Hold Time in seconds. |
| `network` | list | `[]` | Prefixes to originate into BGP. |
| `[[bgp.neighbor]]` | array | `[]` | Peers — see below. |

Each `[[bgp.neighbor]]`:

| Key | Type | Default | Notes |
|---|---|---|---|
| `address` | string | — | The peer's IP address. |
| `remote-as` | integer | — | The peer's AS (eBGP if it differs from `local-as`). |
| `passive` | bool | `false` | Wait for the peer to connect rather than dialling it. |

See [BGP-4](protocols/bgp.md).

## Babel — `[babel]`

```toml
[babel]
enabled    = true
interfaces = ["eth1", "eth2"]
network    = ["10.10.0.0/24"]  # extra prefixes beyond the connected ones
router-id  = "10.0.0.1"        # defaults to the top-level router-id
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Run Babel. |
| `interfaces` | list | `[]` | Interfaces Babel runs on. |
| `network` | list | `[]` | Prefixes to originate beyond the connected ones. |
| `router-id` | string | top-level `router-id` | A dotted quad packed into the low four octets of the 8-octet Babel Router-ID. |

See [Babel](protocols/babel.md).

## Route filters — `[[filter]]` and `[import]`

Filters are Wren's BIRD-style policy: each one is a named, ordered list of rules
plus a default action. A rule's conditions are ANDed; the **first** rule whose
conditions all hold decides the route's fate (accept or reject), after applying any
attribute changes. Filters are attached to protocols **on import** — applied to
every route a protocol announces, before it enters the RIB — via the `[import]`
table (`protocol = "filter-name"`). A rejected route never reaches the RIB; if it
had been accepted before, re-announcing it now withdraws the stale entry.

```toml
[[filter]]
name    = "clean-bgp"
default = "accept"            # "accept" (default) or "reject"

  [[filter.rule]]
  prefix = ["10.0.0.0/8+", "172.16.0.0/12+", "192.168.0.0/16+"]  # reject martians
  action = "reject"

  [[filter.rule]]
  protocol     = "bgp"
  metric-ge    = 1000         # match routes with metric ≥ 1000 …
  action       = "reject"     # … and drop them

  [[filter.rule]]
  prefix       = ["0.0.0.0/0{8,24}"]
  add-metric   = 50           # tag the rest
  action       = "accept"

# Apply filters to protocols on import (into the RIB).
[import]
bgp = "clean-bgp"
rip = "clean-bgp"
```

**Prefix patterns** (any-match within a rule's `prefix` list):

| Written | Matches |
|---|---|
| `10.0.0.0/8` | exactly `10.0.0.0/8` |
| `10.0.0.0/8+` | `10.0.0.0/8` or any more-specific |
| `10.0.0.0/8{16,24}` | within `10.0.0.0/8`, length 16–24 |

**Rule keys** (`[[filter.rule]]`):

| Key | Type | Notes |
|---|---|---|
| `prefix` | list | Prefix patterns; matches if the route's prefix matches any. |
| `protocol` | string | `connected`/`static`/`rip`/`ospf`/`isis`/`babel`/`bgp`/`kernel`. |
| `metric-le` / `metric-ge` | integer | The route's metric must be ≤ / ≥ this. |
| `set-metric` | integer | Set the metric of a matching route. |
| `add-metric` | integer | Add a (signed) delta to the metric, saturating. |
| `set-preference` | integer | Set the administrative preference. |
| `set-community` | list | Replace the route's communities (`asn:value` or a well-known name like `no-export`); consumed by BGP origination. |
| `add-community` | list | Append communities to the route, after any `set-community`. |
| `set-large-community` | list | Replace the route's large communities (`global:local1:local2`, RFC 8092); consumed by BGP origination. |
| `add-large-community` | list | Append large communities to the route, after any `set-large-community`. |
| `set-ext-community` | list | Replace the route's extended communities (`rt:asn:n` / `ro:asn:n` / `rt:ipv4:n`, RFC 4360); consumed by BGP origination. |
| `add-ext-community` | list | Append extended communities to the route, after any `set-ext-community`. |
| `action` | string | `accept` or `reject` (required). |

**Export filters** reuse the same engine on the way *out* of the RIB. The
`[export]` table attaches a filter to a consumer, one key per consumer: `kernel`
gates (and may rewrite) each best-path route before it is programmed into the
forwarding table — exactly like BIRD's `kernel` protocol export filter — and
`bgp` / `ospf` / `rip` / `ripng` / `babel` / `isis` gate (and rewrite) the routes
redistributed into each of those protocols:

```toml
[export]
kernel = "only-public"   # only program filter-accepted routes into the kernel
bgp    = "tag"           # rewrite (e.g. set communities on) routes redistributed into BGP
```

A route the **kernel** export filter rejects stays in the RIB (so best-path and
any future redistribution still see it) but is not installed in the kernel; if
the best path later changes to a rejected route, the previously-installed entry
is withdrawn. A protocol export filter likewise gates what that protocol
re-originates, and its `set-community` is how routes get **per-prefix**
communities into BGP (see [BGP » Per-prefix communities](protocols/bgp.md#per-prefix-communities-via-the-export-filter)).
