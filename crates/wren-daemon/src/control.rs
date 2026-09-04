//! # The control socket — operational `show` commands
//!
//! A small Unix-domain socket the daemon listens on so an operator can ask a
//! running `wren` about its state (`wren show routes`, à la BIRD's `birdc` or
//! FRR's `vtysh`). The protocol is deliberately trivial: the client writes one
//! command line, the server writes back the rendered text answer and closes.
//!
//! The server never touches the RIB directly — it forwards each parsed query to
//! the task that owns the state and waits for the rendered answer on a oneshot:
//! `show routes` goes to the [central router loop](crate::router), `show bgp` to
//! the [BGP task](crate::bgp). Best-path selection, FIB programming and `show` all
//! stay single-threaded on the one task that owns each RIB.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

#[cfg(feature = "babel")]
use crate::babel::{BabelQuery, BabelQueryRequest};
use crate::bfd::{BfdQuery, BfdQueryRequest};
use crate::bgp::{
    BgpQuery, BgpQueryRequest, EvpnEvent, EvpnSubscribe, FlowSpecEvent, FlowSpecSubscribe,
};
#[cfg(feature = "isis")]
use crate::isis::{IsisQuery, IsisQueryRequest};
#[cfg(feature = "ospf")]
use crate::ospf::{OspfQuery, OspfQueryRequest};
#[cfg(feature = "ospf3")]
use crate::ospf3::{Ospf3Query, Ospf3QueryRequest};
#[cfg(feature = "pim")]
use crate::pim::{PimQuery, PimQueryRequest};
use crate::query::OwnedQuery;
#[cfg(feature = "rip")]
use crate::rip::{RipQuery, RipQueryRequest};
use crate::router::{Query, QueryRequest, RouteEvent, RouteSubscribe};
#[cfg(feature = "vrrp")]
use crate::vrrp::VrrpQueryRequest;

/// The query channels the control socket forwards to. Every per-protocol channel
/// is `None` when that protocol is not configured, so `show <proto>` can report
/// that instead of hanging.
#[derive(Clone)]
pub struct Channels {
    /// To the central router loop (`show routes`).
    pub router: mpsc::Sender<QueryRequest>,
    /// To the central router loop to open a route-export stream (`monitor
    /// routes`). Always present — the router always runs.
    pub subscribe: mpsc::Sender<RouteSubscribe>,
    /// To the BGP task to open an EVPN monitor stream (`monitor evpn`), if BGP is
    /// running. This is the EVPN↔fabric bridge feed the fabric controller consumes.
    pub evpn_subscribe: Option<mpsc::Sender<EvpnSubscribe>>,
    /// To the BGP task to open a FlowSpec monitor stream (`monitor flowspec`),
    /// if BGP is running — the mitigation feed a forwarding datapath consumes.
    pub flowspec_subscribe: Option<mpsc::Sender<FlowSpecSubscribe>>,
    /// To the BGP task (`show bgp`), if BGP is running.
    pub bgp: Option<mpsc::Sender<BgpQueryRequest>>,
    /// To the BFD task (`show bfd`), if any BFD session is configured.
    pub bfd: Option<mpsc::Sender<BfdQueryRequest>>,
    /// To the OSPF task (`show ospf`), if OSPF is running.
    #[cfg(feature = "ospf")]
    pub ospf: Option<mpsc::Sender<OspfQueryRequest>>,
    /// To the OSPFv3 task (`show ospf3`), if OSPFv3 is running.
    #[cfg(feature = "ospf3")]
    pub ospf3: Option<mpsc::Sender<Ospf3QueryRequest>>,
    /// To the IS-IS task (`show isis`), if IS-IS is running.
    #[cfg(feature = "isis")]
    pub isis: Option<mpsc::Sender<IsisQueryRequest>>,
    /// To the Babel task (`show babel`), if Babel is running.
    #[cfg(feature = "babel")]
    pub babel: Option<mpsc::Sender<BabelQueryRequest>>,
    /// To the RIP task (`show rip`), if RIPv2 is running.
    #[cfg(feature = "rip")]
    pub rip: Option<mpsc::Sender<RipQueryRequest>>,
    /// To the RIPng task (`show ripng`), if RIPng is running.
    #[cfg(feature = "rip")]
    pub ripng: Option<mpsc::Sender<RipQueryRequest>>,
    /// To the VRRP task (`show vrrp`), if any virtual router is configured.
    #[cfg(feature = "vrrp")]
    pub vrrp: Option<mpsc::Sender<VrrpQueryRequest>>,
    /// To the PIM-SM task (`show pim`), if PIM is running.
    #[cfg(feature = "pim")]
    pub pim: Option<mpsc::Sender<PimQueryRequest>>,
}

/// Serve the control socket at `path`, forwarding queries to the owning tasks.
///
/// Recreates the socket (removing a stale one from a previous run) and accepts
/// connections until cancelled. Binding failures (e.g. an unwritable `/run`)
/// propagate to the caller, which logs them and leaves the daemon running without
/// a control socket.
pub async fn serve(path: PathBuf, channels: Channels) -> Result<()> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // A leftover socket file from a previous run would make bind fail with EADDRINUSE.
    let _ = std::fs::remove_file(&path);
    let listener =
        UnixListener::bind(&path).with_context(|| format!("binding control socket {path:?}"))?;
    // Restrict the socket to owner (root) rather than relying on the inherited
    // umask: the control protocol accepts actions (e.g. `bgp refresh <peer>`),
    // not just read-only `show`, so an unprivileged local user must not be able
    // to connect.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("securing control socket {path:?}"))?;
    }
    info!(socket = ?path, "control socket listening");

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accepting control client")?;
        let channels = channels.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, channels).await {
                warn!(error = %e, "control connection");
            }
        });
    }
}

/// Read one command line, answer it, and close the connection.
async fn handle_conn(stream: UnixStream, channels: Channels) -> Result<()> {
    let mut reader = BufReader::new(stream);
    // Read one command line, but cap it: an unterminated line would otherwise
    // let a client grow this connection's buffer without bound. Uses the
    // BufReader's fill_buf/consume so the reader stays intact for the long-lived
    // subscribe path (which only writes afterwards).
    const MAX_COMMAND_LEN: usize = 4096;
    let mut line_buf: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf().await.context("reading command")?;
        if chunk.is_empty() {
            break; // EOF before newline
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            line_buf.extend_from_slice(&chunk[..pos]);
            reader.consume(pos + 1);
            break;
        }
        let taken = chunk.len();
        line_buf.extend_from_slice(chunk);
        reader.consume(taken);
        if line_buf.len() > MAX_COMMAND_LEN {
            anyhow::bail!("control command exceeds {MAX_COMMAND_LEN} bytes");
        }
    }
    let line = String::from_utf8_lossy(&line_buf);
    let line = line.trim();

    // A subscribe command opens a long-lived export stream rather than a one-shot
    // query/response, so handle it before the per-protocol parsers. `monitor evpn`
    // is checked first (its object distinguishes it from `monitor routes`).
    if is_evpn_subscribe_command(line) {
        return stream_evpn(reader, &channels.evpn_subscribe).await;
    }
    if is_flowspec_subscribe_command(line) {
        return stream_flowspec(reader, &channels.flowspec_subscribe).await;
    }
    if is_subscribe_command(line) {
        return stream_routes(reader, &channels.subscribe).await;
    }

    // Dispatch the command to the first protocol that recognises it. Each disabled
    // protocol's arm is compiled out with its feature, so the unknown-command fallback
    // simply takes over. BGP and `show routes` are always present.
    let mut response: Option<String> = None;
    // `show metrics` is the one command that aggregates across tasks: it concatenates
    // the router's RIB metrics with the BGP task's session metrics into one Prometheus
    // exposition. Each task owns distinct metric families, so the families never
    // collide. Handled before the per-protocol parsers (none of which match it).
    if is_metrics_command(line) {
        let mut out = ask(&channels.router, Query::Metrics, "router").await;
        if let Some(bgp) = &channels.bgp {
            out.push_str(&ask(bgp, BgpQuery::Metrics, "bgp").await);
        }
        response = Some(out);
    }
    if response.is_none() {
        if let Some(query) = parse_bgp_query(line) {
            response = Some(ask_opt(&channels.bgp, query, "bgp").await);
        }
    }
    if response.is_none() {
        if let Some(query) = parse_bfd_query(line) {
            response = Some(ask_opt(&channels.bfd, query, "bfd").await);
        }
    }
    #[cfg(feature = "ospf3")]
    if response.is_none() {
        if let Some(query) = parse_ospf3_query(line) {
            response = Some(ask_opt(&channels.ospf3, query, "ospf3").await);
        }
    }
    #[cfg(feature = "ospf")]
    if response.is_none() {
        if let Some(query) = parse_ospf_query(line) {
            response = Some(ask_opt(&channels.ospf, query, "ospf").await);
        }
    }
    #[cfg(feature = "isis")]
    if response.is_none() {
        if let Some(query) = parse_isis_query(line) {
            response = Some(ask_opt(&channels.isis, query, "isis").await);
        }
    }
    #[cfg(feature = "babel")]
    if response.is_none() {
        if let Some(query) = parse_babel_query(line) {
            response = Some(ask_opt(&channels.babel, query, "babel").await);
        }
    }
    #[cfg(feature = "rip")]
    if response.is_none() {
        if let Some(query) = parse_rip_query(line, "ripng") {
            response = Some(ask_opt(&channels.ripng, query, "ripng").await);
        } else if let Some(query) = parse_rip_query(line, "rip") {
            response = Some(ask_opt(&channels.rip, query, "rip").await);
        }
    }
    #[cfg(feature = "vrrp")]
    if response.is_none() {
        if let Some(query) = crate::vrrp::parse_vrrp_query(line) {
            response = Some(ask_opt(&channels.vrrp, query, "vrrp").await);
        }
    }
    #[cfg(feature = "pim")]
    if response.is_none() {
        if let Some(query) = parse_pim_query(line) {
            response = Some(ask_opt(&channels.pim, query, "pim").await);
        }
    }
    if response.is_none() {
        if let Some(query) = parse_query(line) {
            response = Some(ask(&channels.router, query, "router").await);
        }
    }
    let response = response.unwrap_or_else(|| {
        format!(
            "error: unknown command {line:?}\n\
             usage: show routes [protocol] | show bgp [routes|paths|neighbors|roa|evpn|flowspec|sr-policy|link-state] | \
             show evpn | bgp refresh <peer> | evpn advertise|withdraw <vni> <mac> [ip] | \
             show ospf [neighbors|interfaces|database] | show ospf3 [neighbors|interfaces] | \
             show isis [neighbors|interfaces|database] | show babel [neighbors|routes] | \
             show bfd | show rip | show ripng | show vrrp | show pim [neighbors|mroute] | show vrf | \
             show metrics | monitor routes | monitor evpn | monitor flowspec\n"
        )
    });

    reader
        .get_mut()
        .write_all(response.as_bytes())
        .await
        .context("writing response")?;
    Ok(())
}

/// Forward a query to the task that owns the state and await its rendered answer.
/// One generic body for every protocol: build the request, send it, await the
/// oneshot, and fall back to an `unavailable` message if the task is gone.
async fn ask<R: OwnedQuery>(queries: &mpsc::Sender<R>, query: R::Query, name: &str) -> String {
    let (tx, rx) = oneshot::channel();
    if queries.send(R::build(query, tx)).await.is_err() {
        return format!("error: {name} unavailable\n");
    }
    rx.await
        .unwrap_or_else(|_| format!("error: {name} unavailable\n"))
}

/// Like [`ask`], for a protocol whose task may not be running: reply that it is
/// not enabled rather than hanging on a channel that was never created.
async fn ask_opt<R: OwnedQuery>(
    queries: &Option<mpsc::Sender<R>>,
    query: R::Query,
    name: &str,
) -> String {
    match queries {
        Some(q) => ask(q, query, name).await,
        None => format!("{name} is not enabled\n"),
    }
}

/// Whether `line` is the `show metrics` command (or the bare `metrics`). This is
/// the one command answered by aggregating several tasks rather than a single typed
/// query, so it is recognised here instead of in a per-protocol parser.
pub fn is_metrics_command(line: &str) -> bool {
    let mut tokens = line.split_whitespace();
    match tokens.next() {
        Some("metrics") => tokens.next().is_none(),
        Some("show") => tokens.next() == Some("metrics") && tokens.next().is_none(),
        _ => false,
    }
}

/// Whether `line` opens a route-export subscription. The verb is `monitor` (à la
/// `ip monitor route`) or `subscribe`; the object is `routes`/`route`. This stream
/// is the FPM-style feed an external forwarding plane consumes, so it is
/// recognised before the one-shot `show` parsers.
pub fn is_subscribe_command(line: &str) -> bool {
    let mut tokens = line.split_whitespace();
    match tokens.next() {
        Some("monitor") | Some("subscribe") => {
            matches!(tokens.next(), Some("routes") | Some("route")) && tokens.next().is_none()
        }
        _ => false,
    }
}

/// Whether `line` opens a FlowSpec monitor subscription (`monitor flowspec`).
/// The mitigation counterpart of [`is_evpn_subscribe_command`]: the feed a
/// forwarding datapath consumes to enforce the rules this speaker selected.
pub fn is_flowspec_subscribe_command(line: &str) -> bool {
    let mut tokens = line.split_whitespace();
    match tokens.next() {
        Some("monitor") | Some("subscribe") => {
            tokens.next() == Some("flowspec") && tokens.next().is_none()
        }
        _ => false,
    }
}

/// Whether `line` opens an EVPN monitor subscription (`monitor evpn`). Same verb
/// as [`is_subscribe_command`] (`monitor`/`subscribe`) but the object is `evpn`;
/// this is the FPM-style EVPN feed the Velstra fabric controller consumes to
/// program its overlay maps (the EVPN↔fabric bridge).
pub fn is_evpn_subscribe_command(line: &str) -> bool {
    let mut tokens = line.split_whitespace();
    match tokens.next() {
        Some("monitor") | Some("subscribe") => {
            tokens.next() == Some("evpn") && tokens.next().is_none()
        }
        _ => false,
    }
}

/// Render one [`RouteEvent`] as a single line of the route-export stream:
///
/// ```text
/// + <prefix> table <t> [via <gw>] [dev <dev>] … proto <p> metric <m>   (update)
/// - <prefix> table <t>                                                 (withdraw)
/// % end-of-dump                                                        (snapshot done)
/// ```
///
/// The format is line-based and stable so an external forwarding plane (the
/// Velstra eBPF datapath) can parse it; `table` is always printed so the VRF is
/// unambiguous, and each next-hop carries its gateway and/or egress interface.
fn format_route_event(event: &RouteEvent) -> String {
    let mut out = String::new();
    match event {
        RouteEvent::Update(route) => {
            let _ = write!(out, "+ {} table {}", route.prefix, route.table);
            for nh in &route.nexthops {
                if let Some(gw) = nh.gateway {
                    let _ = write!(out, " via {gw}");
                }
                if let Some(dev) = &nh.iface {
                    let _ = write!(out, " dev {dev}");
                }
            }
            let _ = writeln!(
                out,
                " proto {} metric {}",
                route.protocol.name(),
                route.metric
            );
        }
        RouteEvent::Withdraw { table, prefix } => {
            let _ = writeln!(out, "- {prefix} table {table}");
        }
        RouteEvent::EndOfDump => out.push_str("% end-of-dump\n"),
    }
    out
}

/// Render one [`EvpnEvent`] as a single line of the EVPN monitor stream:
///
/// ```text
/// + evpn vni <vni> mac <mac> [ip <ip>] vtep <vtep> [srv6 <sid>]  (remote MAC learn/change)
/// - evpn vni <vni> mac <mac>                          (remote MAC withdraw)
/// + evpn vni <vni> flood <vtep> [srv6 <sid>]          (BUM flood VTEP add)
/// - evpn vni <vni> flood <vtep>                       (BUM flood VTEP remove)
/// + evpn l3vni <vni> prefix <p> vtep <v> [router-mac <m>] [gw <g>] [srv6 <sid>]
///                                                     (remote subnet learn/change)
/// - evpn l3vni <vni> prefix <p>                       (remote subnet withdraw)
/// % end-of-dump                                       (snapshot done)
/// ```
///
/// Line-based and stable so the fabric controller can parse it into overlay-map
/// updates. The MAC is lower-case colon-hex; `vni` names the EVI's L2 VNI.
///
/// The prefix lines use the distinct keyword `l3vni`, not `vni`, precisely so a
/// consumer written against the earlier format keeps working: it matches on the
/// keyword after the verb, so an unrecognised line is skipped rather than mistaken
/// for a bridging update on some VNI it serves. Extensions here stay append-only
/// for that reason.
fn format_evpn_event(event: &EvpnEvent) -> String {
    let mut out = String::new();
    match event {
        EvpnEvent::MacUpdate {
            vni,
            mac,
            ip,
            vtep,
            srv6_sid,
        } => {
            let _ = write!(out, "+ evpn vni {vni} mac {}", fmt_mac(mac));
            if let Some(ip) = ip {
                let _ = write!(out, " ip {ip}");
            }
            let _ = write!(out, " vtep {vtep}");
            if let Some(sid) = srv6_sid {
                let _ = write!(out, " srv6 {}", wren_bgp::srv6::sid_to_string(sid));
            }
            out.push('\n');
        }
        EvpnEvent::MacWithdraw { vni, mac } => {
            let _ = writeln!(out, "- evpn vni {vni} mac {}", fmt_mac(mac));
        }
        EvpnEvent::FloodUpdate {
            vni,
            vtep,
            srv6_sid,
        } => {
            let _ = write!(out, "+ evpn vni {vni} flood {vtep}");
            // The End.DT2M SID, when the peer runs SRv6. Without it a consumer on
            // an SRv6 fabric has a flood *peer* and no flood *target*: the VTEP
            // address identifies the advertiser but is not something an SRv6
            // datapath can encapsulate toward, so BUM traffic simply stops.
            if let Some(sid) = srv6_sid {
                let _ = write!(out, " srv6 {}", wren_bgp::srv6::sid_to_string(sid));
            }
            out.push('\n');
        }
        EvpnEvent::FloodWithdraw { vni, vtep } => {
            let _ = writeln!(out, "- evpn vni {vni} flood {vtep}");
        }
        EvpnEvent::PrefixUpdate {
            l3_vni,
            prefix,
            vtep,
            router_mac,
            gw,
            srv6_sid,
        } => {
            let _ = write!(out, "+ evpn l3vni {l3_vni} prefix {prefix} vtep {vtep}");
            if let Some(mac) = router_mac {
                let _ = write!(out, " router-mac {}", fmt_mac(mac));
            }
            if let Some(gw) = gw {
                let _ = write!(out, " gw {gw}");
            }
            if let Some(sid) = srv6_sid {
                let _ = write!(out, " srv6 {}", wren_bgp::srv6::sid_to_string(sid));
            }
            out.push('\n');
        }
        EvpnEvent::PrefixWithdraw { l3_vni, prefix } => {
            let _ = writeln!(out, "- evpn l3vni {l3_vni} prefix {prefix}");
        }
        EvpnEvent::EndOfDump => out.push_str("% end-of-dump\n"),
    }
    out
}

/// Format a MAC address as lower-case colon-hex (`aa:bb:cc:dd:ee:ff`).
fn fmt_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse one control command line into a [`Query`]. Returns `None` for anything
/// not understood, so the caller can reply with usage.
pub fn parse_query(line: &str) -> Option<Query> {
    let mut tokens = line.split_whitespace();
    match tokens.next()? {
        "show" => match tokens.next()? {
            "routes" | "route" => {
                let protocol = match tokens.next() {
                    Some(name) => Some(crate::protocol_from_name(name)?),
                    None => None,
                };
                // A trailing extra token is a malformed command.
                if tokens.next().is_some() {
                    return None;
                }
                Some(Query::Routes { protocol })
            }
            "vrf" | "vrfs" => {
                if tokens.next().is_some() {
                    return None;
                }
                Some(Query::Vrfs)
            }
            _ => None,
        },
        _ => None,
    }
}

/// Parse a BGP command into a [`BgpQuery`]. Two forms are accepted: the read-only
/// `show bgp [routes|neighbors]` (a bare `show bgp` defaults to the routes view),
/// and the action `bgp refresh <peer>` which sends that peer a ROUTE-REFRESH
/// (RFC 2918). Returns `None` for anything else (so the caller can fall through to
/// the other parsers).
pub fn parse_bgp_query(line: &str) -> Option<BgpQuery> {
    let mut tokens = line.split_whitespace();
    match tokens.next()? {
        "show" => match tokens.next()? {
            "bgp" => {
                let query = match tokens.next() {
                    None | Some("routes") | Some("route") => BgpQuery::Routes,
                    Some("paths") | Some("path") => BgpQuery::Paths,
                    Some("neighbors") | Some("neighbours") | Some("summary") => BgpQuery::Neighbors,
                    Some("roa") | Some("roas") => BgpQuery::Roa,
                    Some("evpn") => BgpQuery::Evpn,
                    Some("flowspec") => BgpQuery::FlowSpec,
                    Some("sr-policy") | Some("srpolicy") => BgpQuery::SrPolicy,
                    Some("link-state") | Some("linkstate") | Some("ls") => BgpQuery::LinkState,
                    Some(_) => return None,
                };
                // A trailing extra token is a malformed command.
                if tokens.next().is_some() {
                    return None;
                }
                Some(query)
            }
            // `show evpn`: the per-EVI MAC-VRF views (RFC 7432 §9).
            "evpn" => {
                if tokens.next().is_some() {
                    return None;
                }
                Some(BgpQuery::EvpnVnis)
            }
            // `show sr-policy`: the selected SR Policies (RFC 9256, SAFI 73).
            "sr-policy" | "srpolicy" => {
                if tokens.next().is_some() {
                    return None;
                }
                Some(BgpQuery::SrPolicy)
            }
            _ => None,
        },
        // `bgp refresh <addr>`: the address is required and must parse, then the
        // command takes no more tokens.
        "bgp" => {
            if tokens.next()? != "refresh" {
                return None;
            }
            let addr = tokens.next()?.parse().ok()?;
            if tokens.next().is_some() {
                return None;
            }
            Some(BgpQuery::Refresh(addr))
        }
        // `evpn advertise|withdraw <vni> <mac> [ip]`: dynamically originate or withdraw
        // a type-2 MAC/IP route at runtime — the write-side counterpart to the
        // `monitor evpn` read feed. `<vni>` is the L2 VNI, `<mac>` is colon-hex, and the
        // optional `<ip>` is a host address for ARP/ND suppression.
        "evpn" => {
            let withdraw = match tokens.next()? {
                "advertise" => false,
                "withdraw" => true,
                _ => return None,
            };
            let vni: u32 = tokens.next()?.parse().ok()?;
            let mac = parse_mac(tokens.next()?)?;
            let ip = match tokens.next() {
                Some(s) => Some(s.parse::<std::net::IpAddr>().ok()?),
                None => None,
            };
            if tokens.next().is_some() {
                return None;
            }
            Some(BgpQuery::EvpnAdvertise {
                vni,
                mac,
                ip,
                withdraw,
            })
        }
        _ => None,
    }
}

/// Parse a MAC address in `aa:bb:cc:dd:ee:ff` form into its six octets. Returns
/// `None` unless it is exactly six colon-separated hexadecimal bytes.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// Parse a `show pim [neighbors|mroute]` command into a [`PimQuery`]. A bare `show
/// pim` defaults to the neighbours view. Returns `None` for anything else (so the
/// caller can fall through to the other query parsers).
#[cfg(feature = "pim")]
pub fn parse_pim_query(line: &str) -> Option<PimQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "pim" {
        return None;
    }
    let query = match tokens.next() {
        None | Some("neighbors") | Some("neighbours") => PimQuery::Neighbors,
        Some("mroute") | Some("mroutes") | Some("tree") => PimQuery::Mroute,
        Some(_) => return None,
    };
    // A trailing extra token is a malformed command.
    if tokens.next().is_some() {
        return None;
    }
    Some(query)
}

/// Parse a `show bfd` command into a [`BfdQuery`]. BFD keeps only session state,
/// so the sole view is the session table; a bare `show bfd` (or `show bfd
/// sessions`) is it. Returns `None` for anything else (so the caller can fall
/// through to the other parsers).
pub fn parse_bfd_query(line: &str) -> Option<BfdQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "bfd" {
        return None;
    }
    let query = match tokens.next() {
        None | Some("sessions") | Some("session") | Some("neighbors") | Some("neighbours") => {
            BfdQuery::Sessions
        }
        Some(_) => return None,
    };
    // A trailing extra token is a malformed command.
    if tokens.next().is_some() {
        return None;
    }
    Some(query)
}

/// Parse a `show ospf [neighbors|interfaces]` command into an [`OspfQuery`]. A
/// bare `show ospf` defaults to the neighbours view. Returns `None` for anything
/// else (so the caller can fall through to the other query parsers).
#[cfg(feature = "ospf")]
pub fn parse_ospf_query(line: &str) -> Option<OspfQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "ospf" {
        return None;
    }
    let query = match tokens.next() {
        None | Some("neighbors") | Some("neighbours") => OspfQuery::Neighbors,
        Some("interfaces") | Some("interface") | Some("iface") => OspfQuery::Interfaces,
        Some("database") | Some("db") | Some("lsdb") => OspfQuery::Database,
        Some(_) => return None,
    };
    // A trailing extra token is a malformed command.
    if tokens.next().is_some() {
        return None;
    }
    Some(query)
}

/// Parse a `show ospf3 [neighbors|interfaces]` command into an [`Ospf3Query`]. A
/// bare `show ospf3` defaults to the neighbours view. Returns `None` for anything
/// else (so the caller can fall through; note the keyword is the exact token
/// `ospf3`, so `show ospf` is not matched here).
#[cfg(feature = "ospf3")]
pub fn parse_ospf3_query(line: &str) -> Option<Ospf3Query> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "ospf3" {
        return None;
    }
    let query = match tokens.next() {
        None | Some("neighbors") | Some("neighbours") => Ospf3Query::Neighbors,
        Some("interfaces") | Some("interface") | Some("iface") => Ospf3Query::Interfaces,
        Some(_) => return None,
    };
    // A trailing extra token is a malformed command.
    if tokens.next().is_some() {
        return None;
    }
    Some(query)
}

/// Parse a `show isis [neighbors|interfaces|database]` command into an
/// [`IsisQuery`]. A bare `show isis` defaults to the adjacencies view. Returns
/// `None` for anything else (so the caller can fall through to the other parsers).
#[cfg(feature = "isis")]
pub fn parse_isis_query(line: &str) -> Option<IsisQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "isis" {
        return None;
    }
    let query = match tokens.next() {
        None | Some("neighbors") | Some("neighbours") | Some("adjacencies") => IsisQuery::Neighbors,
        Some("interfaces") | Some("interface") | Some("iface") => IsisQuery::Interfaces,
        Some("database") | Some("db") | Some("lsdb") => IsisQuery::Database,
        Some(_) => return None,
    };
    // A trailing extra token is a malformed command.
    if tokens.next().is_some() {
        return None;
    }
    Some(query)
}

/// Parse a `show babel [neighbors|routes]` command into a [`BabelQuery`]. A bare
/// `show babel` defaults to the neighbours view. Returns `None` for anything else.
#[cfg(feature = "babel")]
pub fn parse_babel_query(line: &str) -> Option<BabelQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "babel" {
        return None;
    }
    let query = match tokens.next() {
        None | Some("neighbors") | Some("neighbours") => BabelQuery::Neighbors,
        Some("routes") | Some("route") => BabelQuery::Routes,
        Some(_) => return None,
    };
    // A trailing extra token is a malformed command.
    if tokens.next().is_some() {
        return None;
    }
    Some(query)
}

/// Parse a `show rip` / `show ripng` command into a [`RipQuery`], matching the
/// given `keyword` (`"rip"` or `"ripng"`). RIP keeps no adjacency state, so the
/// only view is its routing table; a bare `show rip` (or `show rip routes`) is the
/// table. Returns `None` for anything else (so the caller can fall through).
#[cfg(feature = "rip")]
pub fn parse_rip_query(line: &str, keyword: &str) -> Option<RipQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != keyword {
        return None;
    }
    let query = match tokens.next() {
        None | Some("routes") | Some("route") => RipQuery::Routes,
        Some(_) => return None,
    };
    // A trailing extra token is a malformed command.
    if tokens.next().is_some() {
        return None;
    }
    Some(query)
}

/// Connect to a running daemon's control socket, send `command`, print the reply.
/// Used by the `wren show …` client subcommand.
pub async fn run_client(path: &Path, command: &str) -> Result<()> {
    let mut stream = UnixStream::connect(path).await.with_context(|| {
        format!("connecting to control socket {path:?} (is wren running with --socket {path:?}?)")
    })?;
    stream.write_all(command.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.shutdown().await?; // EOF on the write half so the server can finish

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .context("reading response")?;
    print!("{response}");
    Ok(())
}

/// Serve a route-export subscription: register with the router, then stream each
/// [`RouteEvent`] to the client as a line until the channel ends or the client
/// disconnects. Long-lived, unlike the one-shot query path. A dropped client is
/// noticed on the next write and the router prunes the (now-closed) sender on its
/// next fan-out.
async fn stream_routes(
    mut reader: BufReader<UnixStream>,
    subscribe: &mpsc::Sender<RouteSubscribe>,
) -> Result<()> {
    // Bounded: the router drops this subscriber if the buffer fills (a client
    // that stops reading), which bounds the memory it can cost the router.
    let (tx, mut rx) = mpsc::channel(crate::router::SUBSCRIBER_CAP);
    if subscribe.send(RouteSubscribe { events: tx }).await.is_err() {
        reader
            .get_mut()
            .write_all(b"error: router unavailable\n")
            .await
            .ok();
        return Ok(());
    }
    let stream = reader.get_mut();
    while let Some(event) = rx.recv().await {
        if stream
            .write_all(format_route_event(&event).as_bytes())
            .await
            .is_err()
        {
            break; // client gone
        }
    }
    Ok(())
}

/// Render one FlowSpec monitor event as its wire line.
///
/// ```text
/// + flowspec action <a>[,<a>…] match <flow specification>
/// - flowspec match <flow specification>
/// % end-of-dump
/// ```
///
/// The fields before `match` are **keyword/value pairs** and the flow
/// specification — itself keyword/value pairs, and variable in length — is
/// always last. A consumer therefore reads pairs until it sees `match`, and
/// takes everything after it as the specification; a field added later slots in
/// before `match` without breaking that parse.
///
/// Actions are compact single tokens (`discard`, `rate-limit:<bytes-per-second>`,
/// `mark:<dscp>`) rather than the human-readable rendering, so no action ever
/// contains a space. `action none` means the rule carried no recognised action
/// community — deliberately explicit rather than silently implying `discard`,
/// which would turn a malformed advertisement into a blackhole.
fn format_flowspec_event(event: &FlowSpecEvent) -> String {
    match event {
        FlowSpecEvent::RuleUpdate { nlri, actions } => {
            let rendered: Vec<String> = actions.iter().map(flowspec_action_token).collect();
            let action = if rendered.is_empty() {
                "none".to_string()
            } else {
                rendered.join(",")
            };
            format!("+ flowspec action {action} match {nlri}\n")
        }
        FlowSpecEvent::RuleWithdraw { nlri } => format!("- flowspec match {nlri}\n"),
        FlowSpecEvent::EndOfDump => "% end-of-dump\n".to_string(),
    }
}

/// One traffic-filtering action as a space-free wire token.
fn flowspec_action_token(action: &wren_bgp::flowspec::Action) -> String {
    use wren_bgp::flowspec::Action;
    match action {
        // RFC 8955 §7.1: a traffic-rate of zero *is* the discard action.
        Action::RateLimit(r) if *r == 0.0 => "discard".to_string(),
        Action::RateLimit(r) => format!("rate-limit:{r}"),
        Action::Marking(d) => format!("mark:{d}"),
    }
}

/// Serve a FlowSpec monitor subscription (`wren monitor flowspec`): register with
/// the BGP task, then stream each event to the client as a line. The mirror of
/// [`stream_evpn`]; a dropped client is noticed on the next write and the BGP
/// task prunes the closed sender on its next fan-out.
async fn stream_flowspec(
    mut reader: BufReader<UnixStream>,
    subscribe: &Option<mpsc::Sender<FlowSpecSubscribe>>,
) -> Result<()> {
    let Some(subscribe) = subscribe else {
        reader
            .get_mut()
            .write_all(b"bgp is not enabled\n")
            .await
            .ok();
        return Ok(());
    };
    let (tx, mut rx) = mpsc::channel(crate::bgp::FLOWSPEC_SUBSCRIBER_CAP);
    if subscribe
        .send(FlowSpecSubscribe { events: tx })
        .await
        .is_err()
    {
        reader
            .get_mut()
            .write_all(b"error: bgp unavailable\n")
            .await
            .ok();
        return Ok(());
    }
    let stream = reader.get_mut();
    while let Some(event) = rx.recv().await {
        if stream
            .write_all(format_flowspec_event(&event).as_bytes())
            .await
            .is_err()
        {
            break; // client gone
        }
    }
    Ok(())
}

/// Serve an EVPN monitor subscription (`wren monitor evpn`): register with the BGP
/// task, then stream each [`EvpnEvent`] to the client as a line until the channel
/// ends or the client disconnects. If BGP is not running there is nothing to
/// subscribe to, so report that instead of hanging. Long-lived, like
/// [`stream_routes`]; a dropped client is noticed on the next write and the BGP
/// task prunes the closed sender on its next fan-out.
async fn stream_evpn(
    mut reader: BufReader<UnixStream>,
    subscribe: &Option<mpsc::Sender<EvpnSubscribe>>,
) -> Result<()> {
    let Some(subscribe) = subscribe else {
        reader
            .get_mut()
            .write_all(b"evpn is not enabled\n")
            .await
            .ok();
        return Ok(());
    };
    // Bounded: the BGP task drops this subscriber if the buffer fills (a client
    // that stops reading), which bounds the memory it can cost the task.
    let (tx, mut rx) = mpsc::channel(crate::bgp::EVPN_SUBSCRIBER_CAP);
    if subscribe.send(EvpnSubscribe { events: tx }).await.is_err() {
        reader
            .get_mut()
            .write_all(b"error: bgp unavailable\n")
            .await
            .ok();
        return Ok(());
    }
    let stream = reader.get_mut();
    while let Some(event) = rx.recv().await {
        if stream
            .write_all(format_evpn_event(&event).as_bytes())
            .await
            .is_err()
        {
            break; // client gone
        }
    }
    Ok(())
}

/// Connect to a running daemon, open a route-export stream (`wren monitor
/// routes`), and print each event line as it arrives until the daemon closes the
/// stream or the client is interrupted. Each line is flushed immediately so the
/// feed is usable live (and survives a `timeout`/SIGTERM in tests, which would
/// otherwise lose block-buffered output).
pub async fn run_monitor_client(path: &Path, command: &str) -> Result<()> {
    use std::io::Write as _;
    let stream = UnixStream::connect(path).await.with_context(|| {
        format!("connecting to control socket {path:?} (is wren running with --socket {path:?}?)")
    })?;
    let (read_half, mut write_half) = stream.into_split();
    write_half.write_all(command.as_bytes()).await?;
    write_half.write_all(b"\n").await?;

    let mut lines = BufReader::new(read_half).lines();
    let mut out = std::io::stdout();
    while let Some(line) = lines
        .next_line()
        .await
        .context("reading route-export stream")?
    {
        writeln!(out, "{line}").ok();
        out.flush().ok();
    }
    Ok(())
}

#[cfg(test)]
mod flowspec_monitor_tests {
    use super::*;
    use std::net::IpAddr;
    use wren_bgp::flowspec::{Action, Component, FlowSpec, NumOp};
    use wren_bgp::flowspec_rib::FlowSpecNlri;

    fn rule() -> FlowSpecNlri {
        let mut spec = FlowSpec {
            components: Vec::new(),
        };
        spec.components.push(Component::DestPrefix(
            "10.0.0.0/24".parse::<wren_core::Prefix>().unwrap(),
        ));
        spec.components.push(Component::IpProto(vec![NumOp::eq(6)]));
        FlowSpecNlri::v4(spec)
    }

    /// The flow specification is variable in length, so it has to come last and
    /// every field before it has to be a keyword/value pair — otherwise a
    /// consumer cannot tell where the match begins.
    #[test]
    fn the_match_is_last_and_the_prefix_is_keyword_value() {
        let line = format_flowspec_event(&FlowSpecEvent::RuleUpdate {
            nlri: rule(),
            actions: vec![Action::DISCARD],
        });
        let line = line.trim_end();
        let (head, tail) = line.split_once(" match ").expect("a match section");
        assert_eq!(head, "+ flowspec action discard");
        assert!(tail.contains("dst 10.0.0.0/24"), "{tail}");
        assert!(tail.contains("proto"), "{tail}");

        let withdraw = format_flowspec_event(&FlowSpecEvent::RuleWithdraw { nlri: rule() });
        assert!(withdraw.starts_with("- flowspec match "), "{withdraw}");
        assert_eq!(
            format_flowspec_event(&FlowSpecEvent::EndOfDump),
            "% end-of-dump\n"
        );
    }

    /// Every action must be a single space-free token: the match section is
    /// whitespace-delimited, so an action containing a space would make the line
    /// unparseable. (The human-readable rendering — "rate-limit 5000 bytes/s" —
    /// is deliberately *not* what goes on the wire.)
    #[test]
    fn actions_are_space_free_tokens() {
        for action in [
            Action::DISCARD,
            Action::RateLimit(12500.0),
            Action::Marking(46),
        ] {
            let token = flowspec_action_token(&action);
            assert!(!token.contains(' '), "action token {token:?} has a space");
        }
        assert_eq!(flowspec_action_token(&Action::DISCARD), "discard");
        assert_eq!(flowspec_action_token(&Action::Marking(46)), "mark:46");

        // Several actions on one rule join with a comma, still space-free.
        let line = format_flowspec_event(&FlowSpecEvent::RuleUpdate {
            nlri: rule(),
            actions: vec![Action::RateLimit(12500.0), Action::Marking(46)],
        });
        let head = line.split(" match ").next().unwrap().to_string();
        assert_eq!(head, "+ flowspec action rate-limit:12500,mark:46");
    }

    /// A rule advertised without a recognised action community is still in the
    /// RIB. Saying so explicitly beats implying "discard" — that would turn a
    /// malformed advertisement into a blackhole.
    #[test]
    fn an_action_less_rule_says_none_rather_than_implying_discard() {
        let line = format_flowspec_event(&FlowSpecEvent::RuleUpdate {
            nlri: rule(),
            actions: Vec::new(),
        });
        assert!(line.starts_with("+ flowspec action none match "), "{line}");
        assert!(!line.contains("discard"), "{line}");
    }

    /// An IPv6 rule must be distinguishable from a v4 one on the wire, or a
    /// consumer would program a v6 match into a v4 table.
    #[test]
    fn ipv6_rules_are_tagged() {
        let mut spec = FlowSpec {
            components: Vec::new(),
        };
        spec.components.push(Component::DestPrefix(
            "2001:db8::/32".parse::<wren_core::Prefix>().unwrap(),
        ));
        let nlri = FlowSpecNlri {
            afi: wren_bgp::AFI_IPV6,
            spec,
        };
        let line = format_flowspec_event(&FlowSpecEvent::RuleUpdate {
            nlri,
            actions: vec![Action::DISCARD],
        });
        assert!(line.contains("match [ipv6] "), "{line}");
        let _ = IpAddr::from([0u8; 4]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wren_core::Protocol;

    #[test]
    fn parse_query_understands_show_routes() {
        assert!(matches!(
            parse_query("show routes"),
            Some(Query::Routes { protocol: None })
        ));
        assert!(matches!(
            parse_query("show route ospf"),
            Some(Query::Routes {
                protocol: Some(Protocol::Ospf)
            })
        ));
    }

    #[test]
    fn recognises_the_metrics_command() {
        assert!(is_metrics_command("show metrics"));
        assert!(is_metrics_command("metrics"));
        // Not a metrics command.
        assert!(!is_metrics_command("show routes"));
        assert!(!is_metrics_command("show metrics extra"));
        assert!(!is_metrics_command("metrics bgp"));
        assert!(!is_metrics_command(""));
        // And it does not collide with the other parsers.
        assert!(parse_query("show metrics").is_none());
        assert!(parse_bgp_query("show metrics").is_none());
    }

    #[test]
    fn parse_query_rejects_garbage_and_unknown_protocols() {
        assert!(parse_query("").is_none());
        assert!(parse_query("show").is_none());
        assert!(parse_query("show neighbors").is_none());
        assert!(parse_query("show routes nonsense").is_none());
        assert!(parse_query("show routes ospf extra").is_none());
    }

    #[test]
    fn parse_bgp_query_understands_show_bgp() {
        assert_eq!(parse_bgp_query("show bgp"), Some(BgpQuery::Routes));
        assert_eq!(parse_bgp_query("show bgp routes"), Some(BgpQuery::Routes));
        assert_eq!(
            parse_bgp_query("show bgp neighbors"),
            Some(BgpQuery::Neighbors)
        );
        assert_eq!(
            parse_bgp_query("show bgp summary"),
            Some(BgpQuery::Neighbors)
        );
        assert_eq!(parse_bgp_query("show bgp paths"), Some(BgpQuery::Paths));
        assert_eq!(parse_bgp_query("show bgp path"), Some(BgpQuery::Paths));
        assert_eq!(parse_bgp_query("show bgp roa"), Some(BgpQuery::Roa));
        assert_eq!(parse_bgp_query("show bgp roas"), Some(BgpQuery::Roa));
        assert_eq!(parse_bgp_query("show bgp evpn"), Some(BgpQuery::Evpn));
        assert_eq!(
            parse_bgp_query("show bgp flowspec"),
            Some(BgpQuery::FlowSpec)
        );
        assert_eq!(
            parse_bgp_query("show bgp sr-policy"),
            Some(BgpQuery::SrPolicy)
        );
        assert_eq!(parse_bgp_query("show sr-policy"), Some(BgpQuery::SrPolicy));
        assert_eq!(
            parse_bgp_query("show bgp link-state"),
            Some(BgpQuery::LinkState)
        );
        assert_eq!(parse_bgp_query("show evpn"), Some(BgpQuery::EvpnVnis));
    }

    #[test]
    fn parse_bgp_query_rejects_others() {
        assert!(parse_bgp_query("show routes").is_none()); // router query, not bgp
        assert!(parse_bgp_query("show bgp nonsense").is_none());
        assert!(parse_bgp_query("show bgp routes extra").is_none());
        assert!(parse_bgp_query("show evpn extra").is_none());
        assert!(parse_bgp_query("").is_none());
    }

    #[test]
    fn parse_bgp_query_understands_refresh() {
        use std::net::{IpAddr, Ipv4Addr};
        assert_eq!(
            parse_bgp_query("bgp refresh 10.0.0.2"),
            Some(BgpQuery::Refresh(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))))
        );
        // An IPv6 (unnumbered) peer address parses too.
        assert_eq!(
            parse_bgp_query("bgp refresh 2001:db8::1"),
            Some(BgpQuery::Refresh("2001:db8::1".parse().unwrap()))
        );
        // A missing, malformed or extra-token address is rejected.
        assert!(parse_bgp_query("bgp refresh").is_none());
        assert!(parse_bgp_query("bgp refresh nonsense").is_none());
        assert!(parse_bgp_query("bgp refresh 10.0.0.2 extra").is_none());
        assert!(parse_bgp_query("bgp nonsense").is_none());
    }

    #[test]
    fn parse_bgp_query_understands_evpn_advertise() {
        // Happy path with an IPv4 host IP.
        assert_eq!(
            parse_bgp_query("evpn advertise 100 aa:bb:cc:dd:ee:ff 10.0.0.5"),
            Some(BgpQuery::EvpnAdvertise {
                vni: 100,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ip: Some("10.0.0.5".parse().unwrap()),
                withdraw: false,
            })
        );
        // Happy path with an IPv6 host IP.
        assert_eq!(
            parse_bgp_query("evpn advertise 100 aa:bb:cc:dd:ee:ff 2001:db8::5"),
            Some(BgpQuery::EvpnAdvertise {
                vni: 100,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ip: Some("2001:db8::5".parse().unwrap()),
                withdraw: false,
            })
        );
        // No IP: MAC-only type-2 route.
        assert_eq!(
            parse_bgp_query("evpn advertise 42 02:00:5e:10:00:01"),
            Some(BgpQuery::EvpnAdvertise {
                vni: 42,
                mac: [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
                ip: None,
                withdraw: false,
            })
        );
        // Withdraw sets the flag.
        assert_eq!(
            parse_bgp_query("evpn withdraw 100 aa:bb:cc:dd:ee:ff"),
            Some(BgpQuery::EvpnAdvertise {
                vni: 100,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ip: None,
                withdraw: true,
            })
        );
    }

    #[test]
    fn parse_bgp_query_rejects_malformed_evpn_advertise() {
        assert!(parse_bgp_query("evpn advertise").is_none()); // missing vni + mac
        assert!(parse_bgp_query("evpn advertise 100").is_none()); // missing mac
        assert!(parse_bgp_query("evpn advertise notanum aa:bb:cc:dd:ee:ff").is_none()); // bad vni
        assert!(parse_bgp_query("evpn advertise 100 zz:bb:cc:dd:ee:ff").is_none()); // bad mac
        assert!(parse_bgp_query("evpn advertise 100 aa:bb:cc:dd:ee").is_none()); // short mac
        assert!(parse_bgp_query("evpn advertise 100 aa:bb:cc:dd:ee:ff bad-ip").is_none()); // bad ip
        assert!(parse_bgp_query("evpn advertise 100 aa:bb:cc:dd:ee:ff 10.0.0.5 x").is_none()); // extra
        assert!(parse_bgp_query("evpn frobnicate 100 aa:bb:cc:dd:ee:ff").is_none());
        // bad verb
    }

    #[test]
    fn parse_bfd_query_understands_show_bfd() {
        assert_eq!(parse_bfd_query("show bfd"), Some(BfdQuery::Sessions));
        assert_eq!(
            parse_bfd_query("show bfd sessions"),
            Some(BfdQuery::Sessions)
        );
        assert_eq!(
            parse_bfd_query("show bfd neighbors"),
            Some(BfdQuery::Sessions)
        );
        // Not a bfd command / malformed.
        assert!(parse_bfd_query("show bgp").is_none());
        assert!(parse_bfd_query("show bfd nonsense").is_none());
        assert!(parse_bfd_query("show bfd sessions extra").is_none());
        assert!(parse_bfd_query("").is_none());
    }

    #[cfg(feature = "ospf")]
    #[test]
    fn parse_ospf_query_understands_show_ospf() {
        assert_eq!(parse_ospf_query("show ospf"), Some(OspfQuery::Neighbors));
        assert_eq!(
            parse_ospf_query("show ospf neighbors"),
            Some(OspfQuery::Neighbors)
        );
        assert_eq!(
            parse_ospf_query("show ospf interfaces"),
            Some(OspfQuery::Interfaces)
        );
        assert_eq!(
            parse_ospf_query("show ospf iface"),
            Some(OspfQuery::Interfaces)
        );
        assert_eq!(
            parse_ospf_query("show ospf database"),
            Some(OspfQuery::Database)
        );
        assert_eq!(parse_ospf_query("show ospf db"), Some(OspfQuery::Database));
        assert_eq!(
            parse_ospf_query("show ospf lsdb"),
            Some(OspfQuery::Database)
        );
    }

    #[cfg(feature = "ospf")]
    #[test]
    fn parse_ospf_query_rejects_others() {
        assert!(parse_ospf_query("show bgp").is_none()); // bgp query, not ospf
        assert!(parse_ospf_query("show ospf nonsense").is_none());
        assert!(parse_ospf_query("show ospf neighbors extra").is_none());
        assert!(parse_ospf_query("").is_none());
    }

    #[cfg(feature = "ospf3")]
    #[test]
    fn parse_ospf3_query_understands_show_ospf3() {
        assert_eq!(parse_ospf3_query("show ospf3"), Some(Ospf3Query::Neighbors));
        assert_eq!(
            parse_ospf3_query("show ospf3 neighbors"),
            Some(Ospf3Query::Neighbors)
        );
        assert_eq!(
            parse_ospf3_query("show ospf3 interfaces"),
            Some(Ospf3Query::Interfaces)
        );
        assert_eq!(
            parse_ospf3_query("show ospf3 iface"),
            Some(Ospf3Query::Interfaces)
        );
    }

    #[cfg(all(feature = "ospf", feature = "ospf3"))]
    #[test]
    fn parse_ospf3_and_ospf_stay_distinct() {
        // Exact-token keywords: `show ospf3` is not an `ospf` query and vice-versa,
        // so the dispatcher can try both without collision.
        assert!(parse_ospf3_query("show ospf").is_none());
        assert!(parse_ospf_query("show ospf3").is_none());
        assert!(parse_ospf3_query("show ospf3 nonsense").is_none());
        assert!(parse_ospf3_query("show ospf3 neighbors extra").is_none());
        assert!(parse_ospf3_query("").is_none());
    }

    #[cfg(feature = "isis")]
    #[test]
    fn parse_isis_query_understands_show_isis() {
        assert_eq!(parse_isis_query("show isis"), Some(IsisQuery::Neighbors));
        assert_eq!(
            parse_isis_query("show isis neighbors"),
            Some(IsisQuery::Neighbors)
        );
        assert_eq!(
            parse_isis_query("show isis adjacencies"),
            Some(IsisQuery::Neighbors)
        );
        assert_eq!(
            parse_isis_query("show isis interfaces"),
            Some(IsisQuery::Interfaces)
        );
        for alias in ["database", "db", "lsdb"] {
            assert_eq!(
                parse_isis_query(&format!("show isis {alias}")),
                Some(IsisQuery::Database)
            );
        }
    }

    #[cfg(feature = "isis")]
    #[test]
    fn parse_isis_query_rejects_others() {
        assert!(parse_isis_query("show ospf").is_none()); // ospf query, not isis
        assert!(parse_isis_query("show isis nonsense").is_none());
        assert!(parse_isis_query("show isis neighbors extra").is_none());
        assert!(parse_isis_query("").is_none());
    }

    #[cfg(feature = "babel")]
    #[test]
    fn parse_babel_query_understands_show_babel() {
        assert_eq!(parse_babel_query("show babel"), Some(BabelQuery::Neighbors));
        assert_eq!(
            parse_babel_query("show babel neighbors"),
            Some(BabelQuery::Neighbors)
        );
        assert_eq!(
            parse_babel_query("show babel neighbours"),
            Some(BabelQuery::Neighbors)
        );
        assert_eq!(
            parse_babel_query("show babel routes"),
            Some(BabelQuery::Routes)
        );
    }

    #[cfg(feature = "babel")]
    #[test]
    fn parse_babel_query_rejects_others() {
        assert!(parse_babel_query("show isis").is_none()); // isis query, not babel
        assert!(parse_babel_query("show babel nonsense").is_none());
        assert!(parse_babel_query("show babel neighbors extra").is_none());
        assert!(parse_babel_query("").is_none());
    }

    #[cfg(feature = "rip")]
    #[test]
    fn parse_rip_query_understands_show_rip_and_ripng() {
        assert_eq!(parse_rip_query("show rip", "rip"), Some(RipQuery::Routes));
        assert_eq!(
            parse_rip_query("show rip routes", "rip"),
            Some(RipQuery::Routes)
        );
        assert_eq!(
            parse_rip_query("show ripng", "ripng"),
            Some(RipQuery::Routes)
        );
        assert_eq!(
            parse_rip_query("show ripng route", "ripng"),
            Some(RipQuery::Routes)
        );
    }

    #[cfg(feature = "rip")]
    #[test]
    fn parse_rip_query_keeps_rip_and_ripng_distinct() {
        // The keyword match is exact, so `show ripng` is not a `rip` query and
        // vice-versa — this is what lets the dispatcher try both without collision.
        assert!(parse_rip_query("show ripng", "rip").is_none());
        assert!(parse_rip_query("show rip", "ripng").is_none());
        assert!(parse_rip_query("show bgp", "rip").is_none());
        assert!(parse_rip_query("show rip nonsense", "rip").is_none());
        assert!(parse_rip_query("show rip routes extra", "rip").is_none());
        assert!(parse_rip_query("", "rip").is_none());
    }

    #[test]
    fn is_subscribe_command_matches_monitor_and_subscribe() {
        assert!(is_subscribe_command("monitor routes"));
        assert!(is_subscribe_command("monitor route"));
        assert!(is_subscribe_command("subscribe routes"));
        // Not a subscribe command / malformed.
        assert!(!is_subscribe_command("monitor"));
        assert!(!is_subscribe_command("monitor routes extra"));
        assert!(!is_subscribe_command("show routes"));
        assert!(!is_subscribe_command(""));
    }

    #[test]
    fn format_route_event_renders_update_withdraw_and_end_of_dump() {
        use wren_core::{NextHop, Route};
        let route = Route::new(
            "10.0.0.0/24".parse().unwrap(),
            Protocol::Ospf,
            vec![NextHop::via_dev("192.0.2.1".parse().unwrap(), "eth0")],
            20,
        );
        // table 254 is RT_TABLE_MAIN, always printed for unambiguous VRF parsing.
        assert_eq!(
            format_route_event(&RouteEvent::Update(route)),
            "+ 10.0.0.0/24 table 254 via 192.0.2.1 dev eth0 proto ospf metric 20\n"
        );
        assert_eq!(
            format_route_event(&RouteEvent::Withdraw {
                table: 254,
                prefix: "10.0.0.0/24".parse().unwrap(),
            }),
            "- 10.0.0.0/24 table 254\n"
        );
        assert_eq!(
            format_route_event(&RouteEvent::EndOfDump),
            "% end-of-dump\n"
        );
    }

    #[test]
    fn is_evpn_subscribe_command_matches_monitor_evpn_only() {
        assert!(is_flowspec_subscribe_command("monitor flowspec"));
        assert!(is_flowspec_subscribe_command("subscribe flowspec"));
        assert!(!is_flowspec_subscribe_command("monitor evpn"));
        assert!(!is_flowspec_subscribe_command("monitor flowspec extra"));
        assert!(!is_flowspec_subscribe_command("show bgp flowspec"));

        assert!(is_evpn_subscribe_command("monitor evpn"));
        assert!(is_evpn_subscribe_command("subscribe evpn"));
        // The `routes` object is the other stream, not this one.
        assert!(!is_evpn_subscribe_command("monitor routes"));
        assert!(!is_evpn_subscribe_command("monitor evpn extra"));
        assert!(!is_evpn_subscribe_command("monitor"));
        assert!(!is_evpn_subscribe_command(""));
        // And `monitor evpn` must not be misread as a route subscription.
        assert!(!is_subscribe_command("monitor evpn"));
    }

    #[test]
    fn format_evpn_event_renders_mac_flood_and_end_of_dump() {
        use std::net::IpAddr;
        let mac = [0x02, 0x00, 0x5e, 0x00, 0x00, 0x01];
        let vtep: IpAddr = "10.0.0.1".parse().unwrap();
        // MAC with a bound IP (for ARP/ND suppression).
        assert_eq!(
            format_evpn_event(&EvpnEvent::MacUpdate {
                vni: 10100,
                mac,
                ip: Some("10.100.0.1".parse().unwrap()),
                vtep,
                srv6_sid: None,
            }),
            "+ evpn vni 10100 mac 02:00:5e:00:00:01 ip 10.100.0.1 vtep 10.0.0.1\n"
        );
        // MAC without a bound IP.
        assert_eq!(
            format_evpn_event(&EvpnEvent::MacUpdate {
                vni: 10100,
                mac,
                ip: None,
                vtep,
                srv6_sid: None,
            }),
            "+ evpn vni 10100 mac 02:00:5e:00:00:01 vtep 10.0.0.1\n"
        );
        // MAC carried over SRv6: the End.DT2U service SID is appended as `srv6 <sid>`.
        let sid: wren_bgp::srv6::Srv6Sid =
            std::net::Ipv6Addr::new(0xfc00, 0, 1, 0, 0x2774, 0, 0, 0).octets();
        assert_eq!(
            format_evpn_event(&EvpnEvent::MacUpdate {
                vni: 10100,
                mac,
                ip: None,
                vtep,
                srv6_sid: Some(sid),
            }),
            "+ evpn vni 10100 mac 02:00:5e:00:00:01 vtep 10.0.0.1 srv6 fc00:0:1:0:2774::\n"
        );
        assert_eq!(
            format_evpn_event(&EvpnEvent::MacWithdraw { vni: 10100, mac }),
            "- evpn vni 10100 mac 02:00:5e:00:00:01\n"
        );
        assert_eq!(
            format_evpn_event(&EvpnEvent::FloodUpdate {
                vni: 10100,
                vtep,
                srv6_sid: None
            }),
            "+ evpn vni 10100 flood 10.0.0.1\n"
        );
        // The flood line on an SRv6 fabric carries the End.DT2M SID. Without it a
        // consumer knows *who* to flood to and has no address to flood *at*: the
        // VTEP identifies the advertiser, and an SRv6 datapath cannot encapsulate
        // toward it. Note this is a different SID from the End.DT2U one above —
        // discriminator 1 rather than 0 — because one SID means one behaviour.
        let flood_sid: wren_bgp::srv6::Srv6Sid =
            std::net::Ipv6Addr::new(0xfc00, 0, 1, 1, 0x2774, 0, 0, 0).octets();
        assert_eq!(
            format_evpn_event(&EvpnEvent::FloodUpdate {
                vni: 10100,
                vtep,
                srv6_sid: Some(flood_sid),
            }),
            "+ evpn vni 10100 flood 10.0.0.1 srv6 fc00:0:1:1:2774::\n"
        );
        assert_eq!(
            format_evpn_event(&EvpnEvent::FloodWithdraw { vni: 10100, vtep }),
            "- evpn vni 10100 flood 10.0.0.1\n"
        );
        assert_eq!(format_evpn_event(&EvpnEvent::EndOfDump), "% end-of-dump\n");

        // Type-5 (RFC 9136): a routed subnet, keyed by the tenant's L3 VNI. The
        // keyword is `l3vni`, not `vni` — a consumer written against the earlier
        // format must skip the line rather than read it as a bridging update for a
        // VNI it serves, which is why the extension is append-only and re-keyed.
        assert_eq!(
            format_evpn_event(&EvpnEvent::PrefixUpdate {
                l3_vni: 50100,
                prefix: "10.20.0.0/24".parse().unwrap(),
                vtep,
                router_mac: Some([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]),
                gw: None,
                srv6_sid: None,
            }),
            "+ evpn l3vni 50100 prefix 10.20.0.0/24 vtep 10.0.0.1 router-mac 02:aa:bb:cc:dd:ee\n"
        );
        assert_eq!(
            format_evpn_event(&EvpnEvent::PrefixWithdraw {
                l3_vni: 50100,
                prefix: "10.20.0.0/24".parse().unwrap(),
            }),
            "- evpn l3vni 50100 prefix 10.20.0.0/24\n"
        );
    }
}
