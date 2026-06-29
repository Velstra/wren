//! # wren — the routing daemon binary
//!
//! Ties the pieces together: read the [`wren_config::Config`], seed a
//! [`wren_core::Rib`] with the static routes, and then run the [central router
//! loop](router) — the sole owner of the RIB and the forwarding plane — while the
//! protocol engines run in their own tasks and feed it [`router::RouteUpdate`]s.
//!
//! Today the one wired protocol is **RIP** ([`rip`], RFC 2453): when `[rip]` is
//! enabled it opens its multicast sockets, learns routes from neighbours and
//! announces them to the router, which installs the winners via the chosen
//! [`Fib`] backend (the kernel over netlink, or the in-memory dry-run plane).

#[cfg(feature = "babel")]
mod babel;
mod bfd;
mod bgp;
mod bmp;
mod connected;
mod control;
mod metrics;
#[cfg(feature = "isis")]
mod isis;
#[cfg(feature = "ospf")]
mod ospf;
#[cfg(feature = "ospf3")]
mod ospf3;
#[cfg(feature = "rip")]
mod rip;
#[cfg(feature = "rip")]
mod ripng;
mod router;
mod rtr;
// Always compiled: BFD (always-on) uses `setsockopt_int` for IPv6 hop limit /
// `IPV6_V6ONLY`, on top of every `_rawsock` protocol runner.
mod sockopt;

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use wren_core::{Fib, FibChange, MemoryFib, Protocol, Rib, RouteDistinguisher};
use wren_filter::{parse_action, Action, Decision, Filter, Match, Modify, PrefixList, Rule};
use wren_netlink::KernelFib;

/// Which forwarding plane to drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Backend {
    /// Install routes into the Linux kernel table over netlink (needs
    /// `CAP_NET_ADMIN`).
    Kernel,
    /// Compute routes in memory only — never touch the kernel (a dry run).
    Memory,
}

/// Command-line arguments.
#[derive(Parser, Debug)]
#[command(name = "wren", version, about = "Wren — a routing daemon in Rust")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/wren/wren.toml")]
    config: PathBuf,

    /// Forwarding-plane backend. Defaults to the safe in-memory one; `kernel`
    /// programs real routes via netlink.
    #[arg(long, value_enum, default_value_t = Backend::Memory)]
    backend: Backend,

    /// Alias for `--backend memory`: compute and log routes but never touch the
    /// kernel.
    #[arg(long)]
    dry_run: bool,

    /// Control socket the daemon serves (and the `show` client connects to).
    #[arg(long, default_value = DEFAULT_CONTROL_SOCKET)]
    socket: PathBuf,

    /// Without a subcommand, run the daemon; `show …` queries a running one.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Subcommands. Absent → run the daemon.
#[derive(Subcommand, Debug)]
enum Command {
    /// Query a running wren daemon over its control socket, e.g. `wren show
    /// routes` or `wren show routes ospf`.
    Show {
        /// The query words, e.g. `routes` or `routes ospf`.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Run a BGP action on a running wren daemon, e.g. `wren bgp refresh
    /// 10.0.0.2` to send that peer a ROUTE-REFRESH (RFC 2918).
    Bgp {
        /// The action words, e.g. `refresh 10.0.0.2`.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

/// The mpsc capacity for protocol → router updates.
const UPDATE_QUEUE: usize = 1024;

/// The mpsc capacity for router → protocol redistribution pushes.
const REDIST_QUEUE: usize = 1024;

/// The mpsc capacity for control → router queries.
const QUERY_QUEUE: usize = 16;

/// The mpsc capacity for protocol → BFD-engine registration commands. Generous so a
/// burst of OSPF neighbours reaching Full at once never blocks the protocol task.
const BFD_QUEUE: usize = 256;

/// The mpsc capacity for the BGP engine → BMP client event feed. Generous, since the
/// engine offers events with `try_send` and drops on a full queue (best-effort
/// monitoring must never back-pressure routing).
const BMP_QUEUE: usize = 1024;

/// Where the daemon serves — and the client connects to — by default.
const DEFAULT_CONTROL_SOCKET: &str = "/run/wren/wren.sock";

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Client mode: connect to a running daemon, print its answer, and exit —
    // without standing up the daemon or its logging.
    if let Some(Command::Show { args: words }) = &args.command {
        let command = format!("show {}", words.join(" "));
        return control::run_client(&args.socket, command.trim()).await;
    }
    if let Some(Command::Bgp { args: words }) = &args.command {
        let command = format!("bgp {}", words.join(" "));
        return control::run_client(&args.socket, command.trim()).await;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = wren_config::Config::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    info!(router_id = ?cfg.router_id, "configuration loaded");

    // Pick the forwarding plane. `--dry-run` forces the in-memory backend.
    let backend = if args.dry_run {
        Backend::Memory
    } else {
        args.backend
    };
    let mut fib: Box<dyn Fib> = match backend {
        Backend::Kernel => {
            Box::new(KernelFib::new().map_err(|e| anyhow::anyhow!("opening kernel FIB: {e}"))?)
        }
        Backend::Memory => Box::new(MemoryFib::default()),
    };

    // Resolve the static routes once: their prefixes are the set we keep when
    // reconciling away a previous instance's leftover forwarding-plane routes.
    let statics = cfg.static_routes().context("resolving static routes")?;
    let keep: HashSet<_> = statics.iter().map(|r| (r.table, r.prefix)).collect();

    // Reconcile at startup: drop routes a previous wren instance left in the
    // forwarding plane that the current config no longer programs, so a restart
    // doesn't leave stale routes behind. (A no-op on the dry-run in-memory plane;
    // dynamic protocols re-install their routes as they reconverge.)
    match fib.owned_routes() {
        Ok(owned) if !owned.is_empty() => {
            let removed = router::reconcile_owned(fib.as_mut(), owned, &keep);
            if removed > 0 {
                info!(removed, "reconciled stale routes from a previous instance");
            }
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "reading existing routes for reconciliation failed"),
    }

    // Compile the configured filters and resolve the import (per-protocol, into the
    // RIB) and export (RIB → FIB) attachments. A bad filter fails startup. Done before
    // seeding the statics so a VRF's route-map can be applied to its static routes.
    let by_name = compile_named_filters(&cfg).context("compiling filters")?;
    let imports = resolve_import_filters(&cfg, &by_name).context("resolving import filters")?;
    let fib_export = resolve_fib_export(&cfg, &by_name).context("resolving export filters")?;
    let (vrf_imports, vrf_exports) =
        build_vrf_routemaps(&cfg, &by_name).context("resolving vrf route-maps")?;
    let vrfs = build_vrf_infos(&cfg).context("resolving vrfs")?;
    if !imports.is_empty() {
        info!(protocols = imports.len(), "import filters active");
    }
    if fib_export.is_some() {
        info!("FIB export filter active");
    }
    if !vrfs.is_empty() {
        info!(vrfs = vrfs.len(), "VRFs configured");
    }

    // Seed the RIB with the configured static routes, programming each best-path
    // change into the forwarding plane as it happens. A static route in a VRF is run
    // through that VRF's import route-map (entering the VRF) and, when programmed,
    // its export route-map (VRF → kernel); either may drop or rewrite it.
    let mut rib = Rib::new();
    let mut installed = 0usize;
    for route in statics {
        let route = match vrf_routemap(&vrf_imports, route) {
            Some(r) => r,
            None => continue, // import route-map rejected it
        };
        if let Some(change) = rib.update(route) {
            if let FibChange::Install(best) = &change {
                // The export route-map may drop it (kept in the RIB, off the FIB).
                if let Some(best) = vrf_routemap(&vrf_exports, best.clone()) {
                    fib.apply(&FibChange::Install(best)).map_err(|e| anyhow::anyhow!(e))?;
                    installed += 1;
                }
            } else {
                fib.apply(&change).map_err(|e| anyhow::anyhow!(e))?;
            }
        }
    }
    for r in rib.iter_best() {
        info!(prefix = %r.prefix, table = r.table, protocol = r.protocol.name(), metric = r.metric, "best route");
    }
    info!(prefixes = installed, backend = ?backend, "static routes programmed");

    // The router receives updates from every protocol engine. Keep a sender in
    // hand so the channel never closes just because no protocol is enabled — the
    // daemon then idles until Ctrl-C.
    let (updates_tx, updates_rx) = mpsc::channel(UPDATE_QUEUE);

    // Redistribution targets: protocol engines the router pushes RIB best-path
    // changes to (currently BGP). Populated when a protocol declares `redistribute`.
    let mut redist_targets: Vec<router::RedistTarget> = Vec::new();

    // The control socket forwards `show` queries to the task that owns the state:
    // `show routes` to the router, `show bgp` to the BGP task. Both `_tx` ends are
    // held for the whole run so the owning task's query branch never sees a closed
    // channel (which would busy-loop the select).
    let (queries_tx, queries_rx) = mpsc::channel(QUERY_QUEUE);
    let (bgp_queries_tx, bgp_queries_rx) = mpsc::channel(QUERY_QUEUE);
    let mut bgp_queries_rx = Some(bgp_queries_rx);
    let bgp_enabled = cfg.bgp.as_ref().is_some_and(|b| b.enabled);
    // BFD (RFC 5880): one engine, registered with by every protocol that enables it.
    // `bfd_register` carries Register/Deregister commands to the engine; each protocol
    // has its own down channel the engine notifies (BGP's `bfd_down`, OSPF's
    // `ospf_bfd`). `bfd_queries` answers `show bfd`. All `_tx` ends are held for the
    // daemon's life so channels never close. The engine is spawned once when any
    // protocol enables BFD.
    let (bfd_register_tx, bfd_register_rx) = mpsc::channel::<bfd::BfdCommand>(BFD_QUEUE);
    let mut bfd_register_rx = Some(bfd_register_rx);
    let (bfd_queries_tx, bfd_queries_rx) = mpsc::channel(QUERY_QUEUE);
    let mut bfd_queries_rx = Some(bfd_queries_rx);
    let (bfd_down_tx, bfd_down_rx) = mpsc::channel::<std::net::IpAddr>(QUERY_QUEUE);
    let mut bfd_down_rx = Some(bfd_down_rx);
    #[cfg(feature = "ospf")]
    let (ospf_bfd_tx, ospf_bfd_rx) = mpsc::channel::<std::net::IpAddr>(QUERY_QUEUE);
    #[cfg(feature = "ospf")]
    let mut ospf_bfd_rx = Some(ospf_bfd_rx);
    #[cfg(feature = "ospf3")]
    let (ospf3_bfd_tx, ospf3_bfd_rx) = mpsc::channel::<std::net::IpAddr>(QUERY_QUEUE);
    #[cfg(feature = "ospf3")]
    let mut ospf3_bfd_rx = Some(ospf3_bfd_rx);
    #[cfg(feature = "isis")]
    let (isis_bfd_tx, isis_bfd_rx) = mpsc::channel::<std::net::IpAddr>(QUERY_QUEUE);
    #[cfg(feature = "isis")]
    let mut isis_bfd_rx = Some(isis_bfd_rx);
    let bgp_bfd = cfg
        .bgp
        .as_ref()
        .is_some_and(|b| b.enabled && b.neighbor.iter().any(|n| n.bfd));
    #[cfg(feature = "ospf")]
    let ospf_bfd = cfg.ospf.as_ref().is_some_and(|o| o.enabled && o.bfd);
    #[cfg(not(feature = "ospf"))]
    let ospf_bfd = false;
    #[cfg(feature = "ospf3")]
    let ospf3_bfd = cfg.ospf3.as_ref().is_some_and(|o| o.enabled && o.bfd);
    #[cfg(not(feature = "ospf3"))]
    let ospf3_bfd = false;
    #[cfg(feature = "isis")]
    let isis_bfd = cfg.isis.as_ref().is_some_and(|i| i.enabled && i.bfd);
    #[cfg(not(feature = "isis"))]
    let isis_bfd = false;
    let bfd_enabled = bgp_bfd || ospf_bfd || ospf3_bfd || isis_bfd;
    // Spawn the single BFD engine if any protocol enables it; protocols register
    // their peers over `bfd_register` once their sessions warrant it.
    if bfd_enabled {
        let session = bfd_session_config(cfg.bfd.as_ref());
        let auth = match bfd_auth_config(cfg.bfd.as_ref()) {
            Ok(a) => a,
            Err(e) => {
                error!(error = %e, "BFD authentication misconfigured; running without it");
                None
            }
        };
        let rrx = bfd_register_rx.take().expect("bfd register rx taken once");
        let bqrx = bfd_queries_rx.take().expect("bfd queries rx taken once");
        info!(auth = auth.is_some(), "BFD engine starting");
        tokio::spawn(async move {
            if let Err(e) = bfd::run(bfd::BfdConfig { session, auth }, rrx, bqrx).await {
                error!(error = %e, "BFD engine stopped");
            }
        });
    }
    // The RTR (RFC 8210) ROA feed into the BGP engine. `rtr_tx` is held here for the
    // daemon's lifetime so the channel stays open even when no RTR cache is configured
    // (the BGP select branch then simply never fires); the client task, if spawned,
    // gets a clone.
    let (rtr_tx, rtr_rx) = mpsc::channel::<Vec<wren_bgp::rpki::Roa>>(QUERY_QUEUE);
    let mut rtr_rx = Some(rtr_rx);
    // The BMP (RFC 7854) event feed from the BGP engine to the monitoring-station
    // client. The receiver is taken when the client is spawned; the sender is handed
    // to `bgp::run` only when `[bgp.bmp]` is configured, so otherwise no events are
    // produced. The channel is bounded and the engine offers events with `try_send`,
    // so a slow/absent station never back-pressures routing.
    let (bmp_tx, bmp_rx) = mpsc::channel::<bmp::BmpEvent>(BMP_QUEUE);
    let mut bmp_rx = Some(bmp_rx);
    #[cfg(feature = "ospf")]
    let (ospf_queries_tx, ospf_queries_rx) = mpsc::channel(QUERY_QUEUE);
    #[cfg(feature = "ospf")]
    let mut ospf_queries_rx = Some(ospf_queries_rx);
    #[cfg(feature = "ospf")]
    let ospf_enabled = cfg.ospf.as_ref().is_some_and(|o| o.enabled);
    #[cfg(feature = "ospf3")]
    let (ospf3_queries_tx, ospf3_queries_rx) = mpsc::channel(QUERY_QUEUE);
    #[cfg(feature = "ospf3")]
    let mut ospf3_queries_rx = Some(ospf3_queries_rx);
    #[cfg(feature = "ospf3")]
    let ospf3_enabled = cfg.ospf3.as_ref().is_some_and(|o| o.enabled);
    #[cfg(feature = "isis")]
    let (isis_queries_tx, isis_queries_rx) = mpsc::channel(QUERY_QUEUE);
    #[cfg(feature = "isis")]
    let mut isis_queries_rx = Some(isis_queries_rx);
    #[cfg(feature = "isis")]
    let isis_enabled = cfg.isis.as_ref().is_some_and(|i| i.enabled);
    #[cfg(feature = "babel")]
    let (babel_queries_tx, babel_queries_rx) = mpsc::channel(QUERY_QUEUE);
    #[cfg(feature = "babel")]
    let mut babel_queries_rx = Some(babel_queries_rx);
    #[cfg(feature = "babel")]
    let babel_enabled = cfg.babel.as_ref().is_some_and(|b| b.enabled);
    #[cfg(feature = "rip")]
    let (rip_queries_tx, rip_queries_rx) = mpsc::channel(QUERY_QUEUE);
    #[cfg(feature = "rip")]
    let mut rip_queries_rx = Some(rip_queries_rx);
    #[cfg(feature = "rip")]
    let rip_enabled = cfg.rip.as_ref().is_some_and(|r| r.enabled);
    #[cfg(feature = "rip")]
    let (ripng_queries_tx, ripng_queries_rx) = mpsc::channel(QUERY_QUEUE);
    #[cfg(feature = "rip")]
    let mut ripng_queries_rx = Some(ripng_queries_rx);
    #[cfg(feature = "rip")]
    let ripng_enabled = cfg.ripng.as_ref().is_some_and(|r| r.enabled);
    {
        let socket = args.socket.clone();
        let channels = control::Channels {
            router: queries_tx.clone(),
            bgp: bgp_enabled.then(|| bgp_queries_tx.clone()),
            bfd: bfd_enabled.then(|| bfd_queries_tx.clone()),
            #[cfg(feature = "ospf")]
            ospf: ospf_enabled.then(|| ospf_queries_tx.clone()),
            #[cfg(feature = "ospf3")]
            ospf3: ospf3_enabled.then(|| ospf3_queries_tx.clone()),
            #[cfg(feature = "isis")]
            isis: isis_enabled.then(|| isis_queries_tx.clone()),
            #[cfg(feature = "babel")]
            babel: babel_enabled.then(|| babel_queries_tx.clone()),
            #[cfg(feature = "rip")]
            rip: rip_enabled.then(|| rip_queries_tx.clone()),
            #[cfg(feature = "rip")]
            ripng: ripng_enabled.then(|| ripng_queries_tx.clone()),
        };
        tokio::spawn(async move {
            if let Err(e) = control::serve(socket, channels).await {
                warn!(error = %e, "control socket disabled");
            }
        });
    }

    // Spawn the RIP engine if it is configured.
    #[cfg(feature = "rip")]
    if let Some(ripcfg) = cfg.rip.as_ref().filter(|r| r.enabled) {
        if backend == Backend::Memory {
            warn!("RIP is enabled but the backend is in-memory — learned routes will not be installed in the kernel");
        }
        // Wire redistribution: the router pushes best-path routes of the configured
        // source protocols (through the optional `[export] rip` filter) for RIP to
        // advertise to its neighbours.
        let (redist_tx, redist_rx) = mpsc::channel(REDIST_QUEUE);
        let rip_export = cfg.export.as_ref().and_then(|e| e.rip.as_deref());
        match build_redist_target(
            Protocol::Rip,
            &ripcfg.redistribute,
            rip_export,
            &by_name,
            redist_tx,
        ) {
            Ok(Some(target)) => {
                info!(sources = target.sources.len(), "RIP redistribution active");
                redist_targets.push(target);
            }
            Ok(None) => {}
            Err(e) => error!(error = %e, "RIP redistribution not configured"),
        }
        let redistribute_metric = ripcfg.redistribute_metric.unwrap_or(1);
        let interfaces = ripcfg.interfaces.clone();
        let tx = updates_tx.clone();
        let qrx = rip_queries_rx.take().expect("rip queries rx taken once");
        tokio::spawn(async move {
            if let Err(e) = rip::run(interfaces, tx, redist_rx, redistribute_metric, qrx).await {
                error!(error = %e, "RIP engine stopped");
            }
        });
    }

    // Spawn the RIPng (IPv6) engine if it is configured.
    #[cfg(feature = "rip")]
    if let Some(ripngcfg) = cfg.ripng.as_ref().filter(|r| r.enabled) {
        if backend == Backend::Memory {
            warn!("RIPng is enabled but the backend is in-memory — learned routes will not be installed in the kernel");
        }
        // Wire redistribution: the router pushes best-path routes of the configured
        // source protocols (through the optional `[export] ripng` filter) for RIPng
        // to advertise to its neighbours. Only IPv6 routes are carried.
        let (redist_tx, redist_rx) = mpsc::channel(REDIST_QUEUE);
        let ripng_export = cfg.export.as_ref().and_then(|e| e.ripng.as_deref());
        match build_redist_target(
            Protocol::Rip,
            &ripngcfg.redistribute,
            ripng_export,
            &by_name,
            redist_tx,
        ) {
            Ok(Some(target)) => {
                info!(sources = target.sources.len(), "RIPng redistribution active");
                redist_targets.push(target);
            }
            Ok(None) => {}
            Err(e) => error!(error = %e, "RIPng redistribution not configured"),
        }
        let redistribute_metric = ripngcfg.redistribute_metric.unwrap_or(1);
        let interfaces = ripngcfg.interfaces.clone();
        let tx = updates_tx.clone();
        let qrx = ripng_queries_rx.take().expect("ripng queries rx taken once");
        tokio::spawn(async move {
            if let Err(e) = ripng::run(interfaces, tx, redist_rx, redistribute_metric, qrx).await {
                error!(error = %e, "RIPng engine stopped");
            }
        });
    }

    // Spawn the OSPFv2 engine if it is configured.
    #[cfg(feature = "ospf")]
    if let Some(ospfcfg) = cfg.ospf.as_ref().filter(|o| o.enabled) {
        match build_ospf_config(&cfg, ospfcfg) {
            Ok(run_cfg) => {
                if backend == Backend::Memory {
                    warn!("OSPF is enabled but the backend is in-memory — learned routes will not be installed in the kernel");
                }
                // Wire redistribution: the router pushes best-path routes of the
                // configured source protocols (through the optional `[export] ospf`
                // filter) for OSPF to originate as AS-external (type-5) LSAs.
                let (redist_tx, redist_rx) = mpsc::channel(REDIST_QUEUE);
                let ospf_export = cfg.export.as_ref().and_then(|e| e.ospf.as_deref());
                match build_redist_target(
                    Protocol::Ospf,
                    &ospfcfg.redistribute,
                    ospf_export,
                    &by_name,
                    redist_tx,
                ) {
                    Ok(Some(target)) => {
                        info!(sources = target.sources.len(), "OSPF redistribution active");
                        redist_targets.push(target);
                    }
                    Ok(None) => {}
                    Err(e) => error!(error = %e, "OSPF redistribution not configured"),
                }
                let tx = updates_tx.clone();
                let qrx = ospf_queries_rx.take().expect("ospf queries rx taken once");
                // BFD (RFC 5880) plumbing: the engine registration channel, OSPF's own
                // notify sender (included in each registration), and the down channel
                // the engine reports failures on. Inert unless `[ospf] bfd` is set.
                let breg = bfd_register_tx.clone();
                let bnotify = ospf_bfd_tx.clone();
                let bdrx = ospf_bfd_rx.take().expect("ospf bfd rx taken once");
                tokio::spawn(async move {
                    if let Err(e) =
                        ospf::run(run_cfg, tx, redist_rx, qrx, breg, bnotify, bdrx).await
                    {
                        error!(error = %e, "OSPF engine stopped");
                    }
                });
            }
            Err(e) => error!(error = %e, "OSPF not started"),
        }
    }

    // Spawn the OSPFv3 (IPv6) engine if it is configured.
    #[cfg(feature = "ospf3")]
    if let Some(ospf3cfg) = cfg.ospf3.as_ref().filter(|o| o.enabled) {
        match build_ospf3_config(&cfg, ospf3cfg) {
            Ok(run_cfg) => {
                if backend == Backend::Memory {
                    warn!("OSPFv3 is enabled but the backend is in-memory — learned routes will not be installed in the kernel");
                }
                let tx = updates_tx.clone();
                let qrx = ospf3_queries_rx.take().expect("ospf3 queries rx taken once");
                // BFD (RFC 5880) plumbing: the engine registration channel, OSPFv3's
                // own notify channel, and the down channel the engine reports failures
                // on. Inert unless `[ospf3] bfd` is set.
                let breg = bfd_register_tx.clone();
                let bnotify = ospf3_bfd_tx.clone();
                let bdrx = ospf3_bfd_rx.take().expect("ospf3 bfd rx taken once");
                tokio::spawn(async move {
                    if let Err(e) = ospf3::run(run_cfg, tx, qrx, breg, bnotify, bdrx).await {
                        error!(error = %e, "OSPFv3 engine stopped");
                    }
                });
            }
            Err(e) => error!(error = %e, "OSPFv3 not started"),
        }
    }

    // Spawn the BGP-4 engine if it is configured.
    if let Some(bgpcfg) = cfg.bgp.as_ref().filter(|b| b.enabled) {
        match build_bgp_config(&cfg, bgpcfg, &by_name) {
            Ok(run_cfg) => {
                if backend == Backend::Memory {
                    warn!("BGP is enabled but the backend is in-memory — learned routes will not be installed in the kernel");
                }
                // Wire redistribution: the router pushes best-path routes of the
                // configured source protocols (through the optional `[export] bgp`
                // filter) down this channel for BGP to originate.
                let (redist_tx, redist_rx) = mpsc::channel(REDIST_QUEUE);
                let bgp_export = cfg.export.as_ref().and_then(|e| e.bgp.as_deref());
                match build_redist_target(
                    Protocol::Bgp,
                    &bgpcfg.redistribute,
                    bgp_export,
                    &by_name,
                    redist_tx,
                ) {
                    Ok(Some(target)) => {
                        info!(sources = target.sources.len(), "BGP redistribution active");
                        redist_targets.push(target);
                    }
                    Ok(None) => {}
                    Err(e) => error!(error = %e, "BGP redistribution not configured"),
                }
                // Spawn the RTR client if a validating cache is configured; it feeds
                // ROAs into the BGP engine over `rtr_tx`.
                if let Some(rtrcfg) = bgpcfg.rtr.as_ref() {
                    match rtrcfg.server.parse::<std::net::SocketAddr>() {
                        Ok(server) => {
                            let rtr_run = rtr::RtrConfig { server, refresh: rtrcfg.refresh };
                            let roas_tx = rtr_tx.clone();
                            info!(%server, "RTR client starting");
                            tokio::spawn(async move { rtr::run(rtr_run, roas_tx).await });
                        }
                        Err(e) => {
                            error!(server = %rtrcfg.server, error = %e, "RTR server must be host:port; RTR disabled")
                        }
                    }
                }
                // Spawn the BMP client if a monitoring station is configured; the BGP
                // engine streams Peer Up / Route Monitoring / Peer Down to it. The
                // engine gets a sender only when BMP is on, so it produces no events
                // otherwise.
                let bmp_for_engine = if let Some(bmpcfg) = bgpcfg.bmp.as_ref() {
                    match bmpcfg.station.parse::<std::net::SocketAddr>() {
                        Ok(station) => {
                            let sys_name = bmpcfg
                                .sys_name
                                .clone()
                                .unwrap_or_else(|| run_cfg.router_id.to_string());
                            let sys_descr =
                                bmpcfg.sys_descr.clone().unwrap_or_else(|| "wren".to_string());
                            let brx = bmp_rx.take().expect("bmp rx taken once");
                            info!(%station, "BMP client starting");
                            tokio::spawn(async move {
                                bmp::run(bmp::BmpConfig { station, sys_name, sys_descr }, brx).await
                            });
                            Some(bmp_tx.clone())
                        }
                        Err(e) => {
                            error!(station = %bmpcfg.station, error = %e, "BMP station must be host:port; BMP disabled");
                            None
                        }
                    }
                } else {
                    None
                };
                let tx = updates_tx.clone();
                let qrx = bgp_queries_rx.take().expect("bgp queries rx taken once");
                let rrx = rtr_rx.take().expect("rtr rx taken once");
                let bdrx = bfd_down_rx.take().expect("bfd down rx taken once");
                tokio::spawn(async move {
                    if let Err(e) =
                        bgp::run(run_cfg, tx, qrx, redist_rx, rrx, bmp_for_engine, bdrx).await
                    {
                        error!(error = %e, "BGP engine stopped");
                    }
                });
                // Register each `bfd = true` neighbour with the BFD engine (RFC 5880).
                // When BFD reports the peer down, the engine notifies `bfd_down_tx`,
                // which the BGP engine reads to tear the session down.
                for n in &bgpcfg.neighbor {
                    if !n.bfd {
                        continue;
                    }
                    // A per-neighbour key overrides the global `[bfd]` one, so distinct
                    // peers can authenticate with distinct passwords; `None` inherits
                    // the global key (applied in the BFD engine).
                    let auth = match resolve_bfd_auth(
                        n.bfd_auth_type.as_deref(),
                        n.bfd_auth_key_id,
                        n.bfd_auth_key.as_deref(),
                    ) {
                        Ok(a) => a,
                        Err(e) => {
                            warn!(neighbor = %n.address, error = %e, "ignoring per-neighbour BFD auth; using the global key");
                            None
                        }
                    };
                    match parse_neighbor_addr(&n.address) {
                        Ok((peer, scope)) => {
                            let _ = bfd_register_tx
                                .send(bfd::BfdCommand::Register {
                                    peer,
                                    scope_id: scope.unwrap_or(0),
                                    consumer: bfd::BfdConsumer::Bgp,
                                    notify: bfd_down_tx.clone(),
                                    auth,
                                })
                                .await;
                        }
                        Err(e) => warn!(error = %e, "skipping BFD for an unparsable neighbour address"),
                    }
                }
            }
            Err(e) => error!(error = %e, "BGP not started"),
        }
    }

    // Spawn the Babel engine if it is configured.
    #[cfg(feature = "babel")]
    if let Some(babelcfg) = cfg.babel.as_ref().filter(|b| b.enabled) {
        match build_babel_config(&cfg, babelcfg) {
            Ok(run_cfg) => {
                if backend == Backend::Memory {
                    warn!("Babel is enabled but the backend is in-memory — learned routes will not be installed in the kernel");
                }
                // Wire redistribution: the router pushes best-path routes of the
                // configured source protocols (through the optional `[export] babel`
                // filter) for Babel to originate to its neighbours.
                let (redist_tx, redist_rx) = mpsc::channel(REDIST_QUEUE);
                let babel_export = cfg.export.as_ref().and_then(|e| e.babel.as_deref());
                match build_redist_target(
                    Protocol::Babel,
                    &babelcfg.redistribute,
                    babel_export,
                    &by_name,
                    redist_tx,
                ) {
                    Ok(Some(target)) => {
                        info!(sources = target.sources.len(), "Babel redistribution active");
                        redist_targets.push(target);
                    }
                    Ok(None) => {}
                    Err(e) => error!(error = %e, "Babel redistribution not configured"),
                }
                let tx = updates_tx.clone();
                let qrx = babel_queries_rx.take().expect("babel queries rx taken once");
                tokio::spawn(async move {
                    if let Err(e) = babel::run(run_cfg, tx, redist_rx, qrx).await {
                        error!(error = %e, "Babel engine stopped");
                    }
                });
            }
            Err(e) => error!(error = %e, "Babel not started"),
        }
    }

    // Spawn the IS-IS engine if it is configured.
    #[cfg(feature = "isis")]
    if let Some(isiscfg) = cfg.isis.as_ref().filter(|i| i.enabled) {
        match build_isis_config(&cfg, isiscfg) {
            Ok(run_cfg) => {
                if backend == Backend::Memory {
                    warn!("IS-IS is enabled but the backend is in-memory — learned routes will not be installed in the kernel");
                }
                // Wire redistribution: the router pushes best-path routes of the
                // configured source protocols (through the optional `[export] isis`
                // filter) for IS-IS to advertise as reachability in its own LSP.
                let (redist_tx, redist_rx) = mpsc::channel(REDIST_QUEUE);
                let isis_export = cfg.export.as_ref().and_then(|e| e.isis.as_deref());
                match build_redist_target(
                    Protocol::Isis,
                    &isiscfg.redistribute,
                    isis_export,
                    &by_name,
                    redist_tx,
                ) {
                    Ok(Some(target)) => {
                        info!(sources = target.sources.len(), "IS-IS redistribution active");
                        redist_targets.push(target);
                    }
                    Ok(None) => {}
                    Err(e) => error!(error = %e, "IS-IS redistribution not configured"),
                }
                let tx = updates_tx.clone();
                let qrx = isis_queries_rx.take().expect("isis queries rx taken once");
                // BFD (RFC 5880) plumbing: the engine registration channel, IS-IS's
                // own notify channel, and the down channel the engine reports failures
                // on. Inert unless `[isis] bfd` is set.
                let breg = bfd_register_tx.clone();
                let bnotify = isis_bfd_tx.clone();
                let bdrx = isis_bfd_rx.take().expect("isis bfd rx taken once");
                tokio::spawn(async move {
                    if let Err(e) = isis::run(run_cfg, tx, redist_rx, qrx, breg, bnotify, bdrx).await {
                        error!(error = %e, "IS-IS engine stopped");
                    }
                });
            }
            Err(e) => error!(error = %e, "IS-IS not started"),
        }
    }

    // Push the statically-seeded best routes to the redistribution targets once;
    // they were installed directly above, bypassing the router loop's fan-out.
    router::redistribute_seed(&redist_targets, &rib).await;

    info!("wren is running; press Ctrl-C to stop");
    tokio::select! {
        _ = router::run(&mut rib, fib.as_mut(), updates_rx, &imports, fib_export.as_ref(), &redist_targets, &vrfs, queries_rx) => {
            warn!("router loop ended (all protocol senders dropped)");
        }
        r = tokio::signal::ctrl_c() => {
            r.context("waiting for shutdown signal")?;
            info!("shutting down");
        }
    }
    Ok(())
}

/// Resolve the textual `[ospf]` config into the runner's [`ospf::OspfConfig`],
/// parsing the Router ID (required) and area and applying the defaults.
#[cfg(feature = "ospf")]
fn build_ospf_config(
    cfg: &wren_config::Config,
    ospf: &wren_config::Ospf,
) -> Result<ospf::OspfConfig> {
    let router_id: Ipv4Addr = cfg
        .router_id
        .as_deref()
        .context("OSPF needs a top-level `router-id`")?
        .parse()
        .context("router-id must be an IPv4 dotted quad")?;
    let default_area: Ipv4Addr = match ospf.area.as_deref() {
        Some(a) => a
            .parse()
            .context("ospf area must be a dotted quad, e.g. \"0.0.0.0\"")?,
        None => Ipv4Addr::UNSPECIFIED, // the backbone, 0.0.0.0
    };
    let iface_type = match ospf.network_type.as_deref() {
        None | Some("broadcast") => wren_ospf::interface::InterfaceType::Broadcast,
        Some("point-to-point") | Some("p2p") => wren_ospf::interface::InterfaceType::PointToPoint,
        Some(other) => {
            anyhow::bail!(
                "ospf network-type {other:?} (expected \"broadcast\" or \"point-to-point\")"
            )
        }
    };
    // Interfaces named in `interfaces` are in the default area; per-interface
    // `[[ospf.interface]]` entries carry their own area.
    let mut interfaces: Vec<ospf::OspfIfaceCfg> = ospf
        .interfaces
        .iter()
        .map(|name| {
            Ok(ospf::OspfIfaceCfg {
                name: name.clone(),
                area: default_area,
            })
        })
        .collect::<Result<_>>()?;
    for ic in &ospf.interface {
        let area: Ipv4Addr = match ic.area.as_deref() {
            Some(a) => a
                .parse()
                .context("ospf interface area must be a dotted quad")?,
            None => default_area,
        };
        interfaces.push(ospf::OspfIfaceCfg {
            name: ic.name.clone(),
            area,
        });
    }
    // Redistribute the configured static routes as AS-external destinations.
    let redistribute = if ospf.redistribute_static {
        let metric = ospf.redistribute_metric.unwrap_or(20);
        cfg.static_routes()
            .context("resolving static routes for OSPF redistribution")?
            .into_iter()
            .map(|r| ospf::RedistRoute {
                prefix: r.prefix,
                metric,
            })
            .collect()
    } else {
        Vec::new()
    };
    // Parse a list of area ids (dotted quads) into a set.
    let parse_areas = |list: &[String], what: &str| -> Result<std::collections::HashSet<Ipv4Addr>> {
        list.iter()
            .map(|a| a.parse().with_context(|| format!("ospf {what} must be a dotted quad, e.g. \"1.0.0.0\"")))
            .collect()
    };
    // Stub areas (RFC 2328 §3.6), plus the totally-stubby ("no-summary") subset,
    // which are stubs that additionally suppress inter-area summaries.
    let totally_stubby_areas = parse_areas(&ospf.totally_stubby_areas, "totally-stubby-area")?;
    let mut stub_areas = parse_areas(&ospf.stub_areas, "stub-area")?;
    stub_areas.extend(totally_stubby_areas.iter().copied()); // a totally-stubby area is a stub
    if stub_areas.contains(&Ipv4Addr::UNSPECIFIED) {
        anyhow::bail!("the backbone area 0.0.0.0 cannot be a stub area (RFC 2328 §3.6)");
    }
    // NSSA areas (RFC 3101) plus the totally-NSSA subset, and mutually exclusive
    // with stubs.
    let totally_nssa_areas = parse_areas(&ospf.totally_nssa_areas, "totally-nssa-area")?;
    // Plain NSSAs into which the ABR also injects a type-7 default (RFC 3101 §2.3),
    // keeping their summaries — distinct from the no-summary totally-NSSA set.
    let nssa_default_areas = parse_areas(&ospf.nssa_default_areas, "nssa-default-area")?;
    let mut nssa_areas = parse_areas(&ospf.nssa_areas, "nssa-area")?;
    nssa_areas.extend(totally_nssa_areas.iter().copied()); // a totally-NSSA area is an NSSA
    nssa_areas.extend(nssa_default_areas.iter().copied()); // a default-injecting area is an NSSA
    if nssa_areas.contains(&Ipv4Addr::UNSPECIFIED) {
        anyhow::bail!("the backbone area 0.0.0.0 cannot be an NSSA area (RFC 3101)");
    }
    if let Some(a) = nssa_areas.intersection(&stub_areas).next() {
        anyhow::bail!("area {a} cannot be both a stub and an NSSA area");
    }
    let auth = build_ospf_auth(ospf)?;
    Ok(ospf::OspfConfig {
        router_id,
        iface_type,
        priority: ospf.router_priority.unwrap_or(1),
        cost: ospf.cost.unwrap_or(10),
        hello_interval: wren_ospf::DEFAULT_HELLO_INTERVAL,
        dead_interval: wren_ospf::DEFAULT_DEAD_INTERVAL,
        interfaces,
        redistribute,
        redistribute_metric: ospf.redistribute_metric.unwrap_or(20),
        stub_areas,
        stub_default_cost: ospf.stub_default_cost.unwrap_or(1),
        nssa_areas,
        totally_stubby_areas,
        totally_nssa_areas,
        nssa_default_areas,
        auth,
        bfd: ospf.bfd,
    })
}

/// Build the OSPF packet authentication (RFC 2328 §D) from the `[ospf]` `auth-*`
/// fields: `"none"` (the default), `"text"` for a simple cleartext password (≤ 8
/// bytes), or `"md5"` for keyed-MD5 (key ≤ 16 bytes, key id defaulting to 1).
#[cfg(feature = "ospf")]
fn build_ospf_auth(ospf: &wren_config::Ospf) -> Result<wren_ospf::packet::Auth> {
    use wren_ospf::packet::Auth;
    match ospf.auth_type.as_deref() {
        None | Some("none") => Ok(Auth::Null),
        Some("text") => {
            let key = ospf
                .auth_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .context("ospf auth-type \"text\" requires a non-empty auth-key")?;
            if key.len() > 8 {
                anyhow::bail!("ospf simple-password auth-key must be at most 8 bytes (RFC 2328 §D)");
            }
            Ok(Auth::Simple(key.as_bytes().to_vec()))
        }
        Some("md5") => {
            let key = ospf
                .auth_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .context("ospf auth-type \"md5\" requires a non-empty auth-key")?;
            if key.len() > 16 {
                anyhow::bail!("ospf md5 auth-key must be at most 16 bytes (RFC 2328 §D)");
            }
            Ok(Auth::Md5 {
                key_id: ospf.auth_key_id.unwrap_or(1),
                key: key.as_bytes().to_vec(),
                seq: 0,
            })
        }
        Some(other) => anyhow::bail!("unknown ospf auth-type {other:?} (want none, text or md5)"),
    }
}

/// Resolve the textual `[ospf3]` config into the runner's [`ospf3::Ospf3Config`],
/// parsing the Router ID (required, still a 32-bit id over IPv6), the area and the
/// Instance ID, and redistributing only the IPv6 statics.
#[cfg(feature = "ospf3")]
fn build_ospf3_config(
    cfg: &wren_config::Config,
    ospf3: &wren_config::Ospf3,
) -> Result<ospf3::Ospf3Config> {
    let router_id: Ipv4Addr = cfg
        .router_id
        .as_deref()
        .context("OSPFv3 needs a top-level `router-id`")?
        .parse()
        .context("router-id must be an IPv4 dotted quad")?;
    let default_area: Ipv4Addr = match ospf3.area.as_deref() {
        Some(a) => a
            .parse()
            .context("ospf3 area must be a dotted quad, e.g. \"0.0.0.0\"")?,
        None => Ipv4Addr::UNSPECIFIED, // the backbone, 0.0.0.0
    };
    let iface_type = match ospf3.network_type.as_deref() {
        None | Some("broadcast") => wren_ospfv3::interface::InterfaceType::Broadcast,
        Some("point-to-point") | Some("p2p") => wren_ospfv3::interface::InterfaceType::PointToPoint,
        Some(other) => {
            anyhow::bail!(
                "ospf3 network-type {other:?} (expected \"broadcast\" or \"point-to-point\")"
            )
        }
    };
    let mut interfaces: Vec<ospf3::Ospf3IfaceCfg> = ospf3
        .interfaces
        .iter()
        .map(|name| ospf3::Ospf3IfaceCfg {
            name: name.clone(),
            area: default_area,
        })
        .collect();
    for ic in &ospf3.interface {
        let area: Ipv4Addr = match ic.area.as_deref() {
            Some(a) => a
                .parse()
                .context("ospf3 interface area must be a dotted quad")?,
            None => default_area,
        };
        interfaces.push(ospf3::Ospf3IfaceCfg {
            name: ic.name.clone(),
            area,
        });
    }
    // Redistribute the configured static routes; the runner keeps only the IPv6.
    let redistribute = if ospf3.redistribute_static {
        let metric = ospf3.redistribute_metric.unwrap_or(20);
        cfg.static_routes()
            .context("resolving static routes for OSPFv3 redistribution")?
            .into_iter()
            .map(|r| ospf3::RedistRoute {
                prefix: r.prefix,
                metric,
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(ospf3::Ospf3Config {
        router_id,
        iface_type,
        priority: ospf3.router_priority.unwrap_or(1),
        cost: ospf3.cost.unwrap_or(10),
        hello_interval: wren_ospfv3::DEFAULT_HELLO_INTERVAL,
        dead_interval: wren_ospfv3::DEFAULT_DEAD_INTERVAL,
        instance_id: ospf3.instance_id.unwrap_or(0),
        interfaces,
        redistribute,
        bfd: ospf3.bfd,
    })
}

/// Resolve the textual `[bgp]` config into the runner's [`bgp::BgpConfig`],
/// parsing the local AS (required), the Router ID (from `[bgp]` or the top-level),
/// the peers and the originated networks.
/// Parse a BGP neighbour address: an IPv4 or IPv6 address, optionally with an IPv6
/// link-local interface scope (`fe80::1%eth0`). Returns the address and, for a scoped
/// link-local, the interface's index (so the connector can dial `fe80::/10`).
fn parse_neighbor_addr(s: &str) -> Result<(std::net::IpAddr, Option<u32>)> {
    let (addr_part, scope) = match s.split_once('%') {
        Some((a, ifname)) => (a, Some(ifname)),
        None => (s, None),
    };
    let addr: std::net::IpAddr = addr_part
        .parse()
        .with_context(|| format!("bgp neighbor address {s:?} must be an IP address"))?;
    let scope_id = match scope {
        Some(ifname) => {
            let cstr = std::ffi::CString::new(ifname)
                .with_context(|| format!("bgp neighbor interface {ifname:?} is not a valid name"))?;
            // SAFETY: `cstr` is a valid NUL-terminated C string; if_nametoindex reads it.
            let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
            if idx == 0 {
                anyhow::bail!("bgp neighbor interface {ifname:?} not found (for address {s:?})");
            }
            Some(idx)
        }
        None => None,
    };
    Ok((addr, scope_id))
}

/// Resolve the shared BFD (RFC 5880) session timing from the `[bfd]` block: the
/// `min-tx` / `min-rx` intervals (milliseconds, default 300) and `detect-mult`
/// (default 3), converted to the microsecond units the session FSM uses. Every BFD
/// session — across protocols — shares this timing.
fn bfd_session_config(bfd: Option<&wren_config::Bfd>) -> wren_bfd::SessionConfig {
    let min_tx_ms = bfd.and_then(|b| b.min_tx).unwrap_or(300).max(1);
    let min_rx_ms = bfd.and_then(|b| b.min_rx).unwrap_or(300).max(1);
    let detect_mult = bfd.and_then(|b| b.detect_mult).unwrap_or(3).max(1);
    wren_bfd::SessionConfig {
        desired_min_tx_us: min_tx_ms.saturating_mul(1000),
        required_min_rx_us: min_rx_ms.saturating_mul(1000),
        detect_mult,
    }
}

/// Resolve the shared BFD authentication (RFC 5880 §6.7) from the `[bfd]` block:
/// `auth-type` selects the algorithm and `auth-key` is the shared secret (`auth-key-id`
/// the wire key id, default 1). Returns `None` when `auth-type` is unset (no
/// authentication), or an error when it is set without a key or names an unknown type.
/// Run a route through a VRF route-map: `None` if the route is in the default VRF or
/// the VRF has no such route-map; otherwise the filter's verdict (rewritten route on
/// accept, dropped on reject). Returns `Some(route)` to keep it, `None` to drop it.
fn vrf_routemap(maps: &std::collections::HashMap<u32, Filter>, route: wren_core::Route) -> Option<wren_core::Route> {
    match maps.get(&route.table) {
        Some(filter) => match filter.apply(&route) {
            Decision::Accept(r) => Some(r),
            Decision::Reject => None,
        },
        None => Some(route),
    }
}

/// Resolve each VRF's `import` / `export` route-maps to compiled filters, keyed by the
/// VRF's kernel table (so they can be looked up by a route's table). An unknown filter
/// name fails startup.
fn build_vrf_routemaps(
    cfg: &wren_config::Config,
    by_name: &std::collections::HashMap<String, Filter>,
) -> Result<(std::collections::HashMap<u32, Filter>, std::collections::HashMap<u32, Filter>)> {
    let mut imports = std::collections::HashMap::new();
    let mut exports = std::collections::HashMap::new();
    for v in &cfg.vrfs {
        if let Some(name) = &v.import {
            imports.insert(v.table, named_filter(by_name, name, "vrf import")?);
        }
        if let Some(name) = &v.export {
            exports.insert(v.table, named_filter(by_name, name, "vrf export")?);
        }
    }
    Ok((imports, exports))
}

/// Resolve the configured VRFs into the router's [`router::VrfInfo`] view, validating
/// each Route Distinguisher and rejecting a duplicate table id.
fn build_vrf_infos(cfg: &wren_config::Config) -> Result<Vec<router::VrfInfo>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(cfg.vrfs.len());
    for v in &cfg.vrfs {
        if !seen.insert(v.table) {
            anyhow::bail!("vrf {:?}: table {} is used by more than one vrf", v.name, v.table);
        }
        let rd = match &v.rd {
            Some(s) => Some(
                RouteDistinguisher::parse(s)
                    .with_context(|| format!("vrf {:?}: invalid route distinguisher {s:?}", v.name))?
                    .to_string(),
            ),
            None => None,
        };
        out.push(router::VrfInfo { name: v.name.clone(), table: v.table, rd });
    }
    Ok(out)
}

fn bfd_auth_config(bfd: Option<&wren_config::Bfd>) -> Result<Option<wren_bfd::AuthConfig>> {
    let Some(bfd) = bfd else { return Ok(None) };
    resolve_bfd_auth(bfd.auth_type.as_deref(), bfd.auth_key_id, bfd.auth_key.as_deref())
}

/// Resolve a BFD authentication block from its three fields, shared by the global
/// `[bfd]` key and any per-neighbour override (so different sessions can use different
/// keys). `None` type → no authentication; a type without a key, or an unknown type,
/// is an error.
fn resolve_bfd_auth(
    auth_type: Option<&str>,
    key_id: Option<u8>,
    key: Option<&str>,
) -> Result<Option<wren_bfd::AuthConfig>> {
    let Some(ty) = auth_type else { return Ok(None) };
    let auth_type = match ty {
        "simple" => wren_bfd::AuthType::SimplePassword,
        "keyed-md5" => wren_bfd::AuthType::KeyedMd5,
        "meticulous-md5" => wren_bfd::AuthType::MeticulousKeyedMd5,
        "keyed-sha1" => wren_bfd::AuthType::KeyedSha1,
        "meticulous-sha1" => wren_bfd::AuthType::MeticulousKeyedSha1,
        other => anyhow::bail!(
            "bfd auth-type {other:?} (expected one of simple, keyed-md5, meticulous-md5, keyed-sha1, meticulous-sha1)"
        ),
    };
    let key = key.context("bfd auth-type is set but auth-key is missing")?;
    if key.is_empty() {
        anyhow::bail!("bfd auth-key must not be empty");
    }
    // The Simple Password section caps the key at 16 octets (RFC 5880 §4.2).
    if matches!(auth_type, wren_bfd::AuthType::SimplePassword) && key.len() > 16 {
        anyhow::bail!("bfd simple-password auth-key must be at most 16 bytes");
    }
    Ok(Some(wren_bfd::AuthConfig {
        auth_type,
        key_id: key_id.unwrap_or(1),
        secret: key.as_bytes().to_vec(),
    }))
}

fn build_bgp_config(
    cfg: &wren_config::Config,
    bgp: &wren_config::Bgp,
    by_name: &std::collections::HashMap<String, Filter>,
) -> Result<bgp::BgpConfig> {
    if bgp.local_as == 0 {
        anyhow::bail!("bgp needs a non-zero `local-as`");
    }
    let router_id: Ipv4Addr = bgp
        .router_id
        .as_deref()
        .or(cfg.router_id.as_deref())
        .context("BGP needs a `router-id` (in [bgp] or top-level)")?
        .parse()
        .context("bgp router-id must be an IPv4 dotted quad")?;
    let hold_time = bgp.hold_time.unwrap_or(wren_bgp::DEFAULT_HOLD_TIME);

    let mut peers = Vec::with_capacity(bgp.neighbor.len());
    for n in &bgp.neighbor {
        // The transport address: IPv4, or IPv6 for an unnumbered/RFC 5549 session. An
        // IPv6 link-local may carry an interface scope (`fe80::1%eth0`) to dial it on.
        let (addr, scope_id) = parse_neighbor_addr(&n.address)?;
        // TCP-MD5 (RFC 2385) and TCP-AO (RFC 5925) are wired for IPv4 transport only
        // here; on an IPv6 peer a configured key is ignored (with a warning).
        let (password, ao_key) = if addr.is_ipv4() {
            (n.password.clone(), n.ao_key.clone())
        } else {
            if n.password.is_some() || n.ao_key.is_some() {
                tracing::warn!(peer = %addr, "TCP-MD5/AO is IPv4-only; ignoring the key on this IPv6 (unnumbered) BGP peer");
            }
            (None, None)
        };
        if let Some(pw) = &password {
            if pw.is_empty() || pw.len() > 80 {
                anyhow::bail!(
                    "bgp neighbor {addr} password must be 1..=80 bytes (TCP-MD5, RFC 2385)"
                );
            }
        }
        if let Some(key) = &ao_key {
            if key.is_empty() || key.len() > 80 {
                anyhow::bail!("bgp neighbor {addr} ao-key must be 1..=80 bytes (TCP-AO, RFC 5925)");
            }
        }
        if password.is_some() && ao_key.is_some() {
            anyhow::bail!(
                "bgp neighbor {addr} cannot use both password (TCP-MD5) and ao-key (TCP-AO)"
            );
        }
        let import = match &n.import {
            Some(name) => Some(named_filter(by_name, name, "bgp neighbor import")?),
            None => None,
        };
        let export = match &n.export {
            Some(name) => Some(named_filter(by_name, name, "bgp neighbor export")?),
            None => None,
        };
        peers.push(bgp::BgpPeerCfg {
            addr,
            scope_id,
            remote_as: n.remote_as,
            passive: n.passive,
            rr_client: n.route_reflector_client,
            ttl_security: n.ttl_security,
            password,
            ao_key,
            ao_key_id: n.ao_key_id.unwrap_or(100),
            max_prefix: n.max_prefix.filter(|&m| m > 0),
            default_originate: n.default_originate,
            add_path: n.add_path,
            ext_nexthop: n.extended_nexthop,
            import,
            export,
        });
    }

    let mut originate = Vec::with_capacity(bgp.network.len());
    for net in &bgp.network {
        originate.push(
            net.parse()
                .with_context(|| format!("bgp network {net:?} must be addr/len"))?,
        );
    }

    // Address aggregates (RFC 4271 §9.2.2.2): each `[[bgp.aggregate]]` prefix is
    // advertised as a summary whenever a more-specific originated route contributes.
    let mut aggregates = Vec::with_capacity(bgp.aggregate.len());
    for agg in &bgp.aggregate {
        let prefix: wren_core::Prefix = agg
            .prefix
            .parse()
            .with_context(|| format!("bgp aggregate {:?} must be addr/len", agg.prefix))?;
        if prefix.len() >= prefix.max_len() {
            anyhow::bail!(
                "bgp aggregate {:?} is a host route and can never have a more-specific contributor",
                agg.prefix
            );
        }
        aggregates.push(bgp::Aggregate { prefix, summary_only: agg.summary_only });
    }

    // Static RPKI ROAs (RFC 6811): the Validated ROA Payloads received-route origins
    // are checked against. `max-length` defaults to the prefix's own length.
    let mut roas = Vec::with_capacity(bgp.roa.len());
    for r in &bgp.roa {
        let prefix: wren_core::Prefix = r
            .prefix
            .parse()
            .with_context(|| format!("bgp roa {:?} must be addr/len", r.prefix))?;
        let max_length = r.max_length.unwrap_or(prefix.len());
        if max_length < prefix.len() || max_length > prefix.max_len() {
            anyhow::bail!(
                "bgp roa {:?} max-length {} must be between the prefix length {} and {}",
                r.prefix,
                max_length,
                prefix.len(),
                prefix.max_len()
            );
        }
        roas.push(wren_bgp::rpki::Roa { prefix, max_length, origin_as: r.origin_as });
    }

    let next_hop6 = match bgp.next_hop6.as_deref() {
        Some(s) => Some(
            s.parse::<std::net::Ipv6Addr>()
                .with_context(|| format!("bgp next-hop6 {s:?} must be an IPv6 address"))?,
        ),
        None => None,
    };

    // The route-reflector CLUSTER_ID defaults to the BGP router-id (RFC 4456).
    let cluster_id: Ipv4Addr = match bgp.cluster_id.as_deref() {
        Some(s) => s
            .parse()
            .with_context(|| format!("bgp cluster-id {s:?} must be an IPv4 dotted quad"))?,
        None => router_id,
    };

    let mut communities = Vec::with_capacity(bgp.community.len());
    for c in &bgp.community {
        communities.push(
            wren_bgp::community::parse_community(c)
                .with_context(|| format!("bgp community {c:?} must be asn:value or a well-known name"))?,
        );
    }
    let large_communities = parse_large_communities(&bgp.large_community)
        .context("bgp large-community")?;
    let ext_communities = parse_ext_communities(&bgp.ext_community).context("bgp ext-community")?;

    // Confederation (RFC 5065): the Confederation Identifier presented externally,
    // and the Member-AS numbers of the other sub-ASes (confed-eBGP peers).
    if bgp.confederation_id.is_some() && bgp.confederation_members.is_empty() {
        warn!("bgp `confederation-id` set but `confederation-members` is empty; every differing remote-as is treated as a true external peer");
    }

    Ok(bgp::BgpConfig {
        local_as: bgp.local_as,
        router_id,
        hold_time,
        peers,
        originate,
        next_hop6,
        cluster_id,
        communities,
        large_communities,
        ext_communities,
        confederation_id: bgp.confederation_id,
        confederation_members: bgp.confederation_members.clone(),
        max_paths: bgp.multipath.unwrap_or(1).max(1),
        aggregates,
        roas,
        rpki_reject_invalid: bgp.rpki_reject_invalid,
    })
}

/// Build a protocol's redistribution target from its `redistribute` list (the RIB
/// source protocols whose routes it re-originates) and an optional export filter.
/// Returns `None` when no source protocols are configured. The consuming protocol
/// is rejected from its own source set so it never redistributes its own routes
/// (a loop).
fn build_redist_target(
    protocol: Protocol,
    redistribute: &[String],
    export_filter: Option<&str>,
    by_name: &std::collections::HashMap<String, Filter>,
    tx: mpsc::Sender<router::Redistribution>,
) -> Result<Option<router::RedistTarget>> {
    let mut sources = HashSet::new();
    for name in redistribute {
        let source = protocol_from_name(name).with_context(|| {
            format!("{} redistribute {name:?} is not a known protocol", protocol.name())
        })?;
        if source == protocol {
            anyhow::bail!("{} cannot redistribute its own routes", protocol.name());
        }
        sources.insert(source);
    }
    if sources.is_empty() {
        return Ok(None);
    }
    let filter = match export_filter {
        Some(name) => Some(named_filter(by_name, name, "export")?),
        None => None,
    };
    Ok(Some(router::RedistTarget {
        protocol,
        sources,
        filter,
        tx,
    }))
}

/// Resolve the textual `[babel]` config into the runner's [`babel::BabelConfig`],
/// deriving the 8-octet Router-ID from `[babel]` or the top-level `router-id` and
/// parsing the originated networks.
#[cfg(feature = "babel")]
fn build_babel_config(
    cfg: &wren_config::Config,
    babel: &wren_config::Babel,
) -> Result<babel::BabelConfig> {
    let router_id_v4: Ipv4Addr = babel
        .router_id
        .as_deref()
        .or(cfg.router_id.as_deref())
        .context("Babel needs a `router-id` (in [babel] or top-level)")?
        .parse()
        .context("babel router-id must be an IPv4 dotted quad")?;

    let mut originate = Vec::with_capacity(babel.network.len());
    for net in &babel.network {
        originate.push(
            net.parse()
                .with_context(|| format!("babel network {net:?} must be addr/len"))?,
        );
    }

    Ok(babel::BabelConfig {
        router_id: babel::router_id_from_ipv4(router_id_v4),
        interfaces: babel.interfaces.clone(),
        originate,
        redistribute_metric: babel.redistribute_metric.unwrap_or(0),
    })
}

/// Compile every `[[filter]]` definition into a [`wren_filter::Filter`], keyed by
/// name. An empty name or an unparsable pattern/action is a hard error.
fn compile_named_filters(
    cfg: &wren_config::Config,
) -> Result<std::collections::HashMap<String, Filter>> {
    let mut by_name = std::collections::HashMap::new();
    for def in &cfg.filters {
        if def.name.is_empty() {
            anyhow::bail!("a [[filter]] is missing its `name`");
        }
        let filter = compile_filter(def).with_context(|| format!("filter {:?}", def.name))?;
        by_name.insert(def.name.clone(), filter);
    }
    Ok(by_name)
}

/// Look up a named filter, erroring if it is not defined.
fn named_filter(
    by_name: &std::collections::HashMap<String, Filter>,
    name: &str,
    context: &str,
) -> Result<Filter> {
    by_name
        .get(name)
        .cloned()
        .with_context(|| format!("{context} references unknown filter {name:?}"))
}

/// Resolve the `[import]` table into the router's per-protocol import filters.
fn resolve_import_filters(
    cfg: &wren_config::Config,
    by_name: &std::collections::HashMap<String, Filter>,
) -> Result<router::ImportFilters> {
    let mut imports = router::ImportFilters::new();
    for (proto_name, filter_name) in &cfg.import {
        let protocol = protocol_from_name(proto_name)
            .with_context(|| format!("import key {proto_name:?} is not a known protocol"))?;
        let filter = named_filter(by_name, filter_name, "import")?;
        imports.insert(protocol, filter);
    }
    Ok(imports)
}

/// Resolve the `[export]` table into the FIB export filter (RIB → kernel), if any.
fn resolve_fib_export(
    cfg: &wren_config::Config,
    by_name: &std::collections::HashMap<String, Filter>,
) -> Result<Option<Filter>> {
    let Some(export) = cfg.export.as_ref() else {
        return Ok(None);
    };
    match export.kernel.as_deref() {
        Some(name) => Ok(Some(named_filter(by_name, name, "export.kernel")?)),
        None => Ok(None),
    }
}

/// Parse a list of community strings (`asn:value` or a well-known name) into
/// their 32-bit values, for a filter rule's `set-community`/`add-community`.
fn parse_communities(list: &[String]) -> Result<Vec<u32>> {
    list.iter()
        .map(|c| {
            wren_bgp::community::parse_community(c)
                .with_context(|| format!("community {c:?} must be asn:value or a well-known name"))
        })
        .collect()
}

/// Parse a list of large-community strings (`global:local1:local2`, RFC 8092) into
/// their triples, for `[bgp] large-community` or a filter's `*-large-community`.
fn parse_large_communities(list: &[String]) -> Result<Vec<(u32, u32, u32)>> {
    list.iter()
        .map(|c| {
            wren_bgp::large_community::parse_large_community(c)
                .with_context(|| format!("large community {c:?} must be global:local1:local2"))
        })
        .collect()
}

/// Parse a list of extended-community strings (`rt:asn:n`, `ro:asn:n`,
/// `rt:ipv4:n`, …; RFC 4360) into their raw 8-octet values, for
/// `[bgp] ext-community` or a filter's `*-ext-community`.
fn parse_ext_communities(list: &[String]) -> Result<Vec<[u8; 8]>> {
    list.iter()
        .map(|c| {
            wren_bgp::ext_community::parse_ext_community(c).with_context(|| {
                format!("ext community {c:?} must be rt:/ro: asn:n, an IPv4 form, or 0x<16 hex>")
            })
        })
        .collect()
}

/// Compile one [`wren_config::FilterDef`] into a [`wren_filter::Filter`].
fn compile_filter(def: &wren_config::FilterDef) -> Result<Filter> {
    let default = match def.default.as_deref() {
        None => Action::Accept,
        Some(s) => parse_action(s).map_err(|e| anyhow::anyhow!("default {e}"))?,
    };
    let mut rules = Vec::with_capacity(def.rule.len());
    for r in &def.rule {
        let prefix = if r.prefix.is_empty() {
            None
        } else {
            let mut patterns = Vec::with_capacity(r.prefix.len());
            for p in &r.prefix {
                patterns.push(
                    p.parse()
                        .map_err(|e| anyhow::anyhow!("prefix {p:?}: {e}"))?,
                );
            }
            Some(PrefixList(patterns))
        };
        let protocol = match &r.protocol {
            None => None,
            Some(name) => Some(
                protocol_from_name(name)
                    .with_context(|| format!("rule protocol {name:?} is unknown"))?,
            ),
        };
        let matcher = Match {
            prefix,
            protocol,
            metric_le: r.metric_le,
            metric_ge: r.metric_ge,
        };
        let set_communities = match &r.set_community {
            None => None,
            Some(list) => Some(parse_communities(list)?),
        };
        let add_communities = parse_communities(&r.add_community)?;
        let set_large_communities = match &r.set_large_community {
            None => None,
            Some(list) => Some(parse_large_communities(list)?),
        };
        let add_large_communities = parse_large_communities(&r.add_large_community)?;
        let set_ext_communities = match &r.set_ext_community {
            None => None,
            Some(list) => Some(parse_ext_communities(list)?),
        };
        let add_ext_communities = parse_ext_communities(&r.add_ext_community)?;
        let modify = Modify {
            set_metric: r.set_metric,
            add_metric: r.add_metric,
            set_preference: r.set_preference,
            set_communities,
            add_communities,
            set_large_communities,
            add_large_communities,
            set_ext_communities,
            add_ext_communities,
        };
        let action = parse_action(&r.action).map_err(|e| anyhow::anyhow!("rule action {e}"))?;
        rules.push(Rule {
            matcher,
            modify,
            action,
        });
    }
    Ok(Filter { rules, default })
}

/// Map a protocol name (as in [`wren_core::Protocol::name`]) to the protocol.
fn protocol_from_name(name: &str) -> Option<Protocol> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "connected" => Protocol::Connected,
        "static" => Protocol::Static,
        "kernel" => Protocol::Kernel,
        "rip" => Protocol::Rip,
        "ospf" => Protocol::Ospf,
        "isis" => Protocol::Isis,
        "babel" => Protocol::Babel,
        "bgp" => Protocol::Bgp,
        _ => return None,
    })
}

/// Resolve the textual `[isis]` config into the runner's [`isis::IsisConfig`]:
/// the System ID (explicit or derived from the Router ID), the area, the level and
/// the interfaces with their network type.
#[cfg(feature = "isis")]
fn build_isis_config(
    cfg: &wren_config::Config,
    isis: &wren_config::Isis,
) -> Result<isis::IsisConfig> {
    let system_id = match isis.system_id.as_deref() {
        Some(s) => isis::parse_system_id(s)?,
        None => {
            let rid: Ipv4Addr = cfg
                .router_id
                .as_deref()
                .context("IS-IS needs a `system-id` (in [isis]) or a top-level `router-id`")?
                .parse()
                .context("router-id must be an IPv4 dotted quad")?;
            isis::system_id_from_router_id(rid)
        }
    };
    let area = match isis.area.as_deref() {
        Some(a) => isis::parse_area(a)?,
        None => isis::parse_area("49.0000").expect("default area is valid"),
    };
    let level = match isis.level.as_deref() {
        None | Some("l1l2") | Some("L1L2") => wren_isis::IsLevel::L1L2,
        Some("l1") | Some("L1") => wren_isis::IsLevel::L1,
        Some("l2") | Some("L2") => wren_isis::IsLevel::L2,
        Some(other) => anyhow::bail!("isis level {other:?} (expected \"l1\", \"l2\" or \"l1l2\")"),
    };
    let iface_type = match isis.network_type.as_deref() {
        None | Some("broadcast") => isis::IfaceType::Broadcast,
        Some("point-to-point") | Some("p2p") => isis::IfaceType::PointToPoint,
        Some(other) => anyhow::bail!(
            "isis network-type {other:?} (expected \"broadcast\" or \"point-to-point\")"
        ),
    };
    let interfaces = isis
        .interfaces
        .iter()
        .map(|name| isis::IsisIfaceCfg {
            name: name.clone(),
            iface_type,
        })
        .collect();

    let metric = isis.metric.unwrap_or(10);
    Ok(isis::IsisConfig {
        system_id,
        area,
        level,
        priority: isis.priority.unwrap_or(64),
        metric,
        redistribute_metric: isis.redistribute_metric.unwrap_or(metric),
        hello_interval: isis.hello_interval.unwrap_or(10),
        holding_multiplier: 3,
        interfaces,
        bfd: isis.bfd,
    })
}
