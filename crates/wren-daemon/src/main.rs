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

mod babel;
mod bgp;
mod connected;
mod control;
mod isis;
mod ospf;
mod ospf3;
mod rip;
mod ripng;
mod router;

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use wren_core::{Fib, MemoryFib, Protocol, Rib};
use wren_filter::{parse_action, Action, Filter, Match, Modify, PrefixList, Rule};
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
}

/// The mpsc capacity for protocol → router updates.
const UPDATE_QUEUE: usize = 1024;

/// The mpsc capacity for router → protocol redistribution pushes.
const REDIST_QUEUE: usize = 1024;

/// The mpsc capacity for control → router queries.
const QUERY_QUEUE: usize = 16;

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
    let keep: HashSet<_> = statics.iter().map(|r| r.prefix).collect();

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

    // Seed the RIB with the configured static routes, programming each best-path
    // change into the forwarding plane as it happens.
    let mut rib = Rib::new();
    let mut installed = 0usize;
    for route in statics {
        if let Some(change) = rib.update(route) {
            fib.apply(&change).map_err(|e| anyhow::anyhow!(e))?;
            installed += 1;
        }
    }
    for r in rib.iter_best() {
        info!(prefix = %r.prefix, protocol = r.protocol.name(), metric = r.metric, "best route");
    }
    info!(prefixes = installed, backend = ?backend, "static routes programmed");

    // Compile the configured filters and resolve the import (per-protocol, into the
    // RIB) and export (RIB → FIB) attachments. A bad filter fails startup.
    let by_name = compile_named_filters(&cfg).context("compiling filters")?;
    let imports = resolve_import_filters(&cfg, &by_name).context("resolving import filters")?;
    let fib_export = resolve_fib_export(&cfg, &by_name).context("resolving export filters")?;
    if !imports.is_empty() {
        info!(protocols = imports.len(), "import filters active");
    }
    if fib_export.is_some() {
        info!("FIB export filter active");
    }

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
    let (ospf_queries_tx, ospf_queries_rx) = mpsc::channel(QUERY_QUEUE);
    let mut ospf_queries_rx = Some(ospf_queries_rx);
    let ospf_enabled = cfg.ospf.as_ref().is_some_and(|o| o.enabled);
    let (ospf3_queries_tx, ospf3_queries_rx) = mpsc::channel(QUERY_QUEUE);
    let mut ospf3_queries_rx = Some(ospf3_queries_rx);
    let ospf3_enabled = cfg.ospf3.as_ref().is_some_and(|o| o.enabled);
    let (isis_queries_tx, isis_queries_rx) = mpsc::channel(QUERY_QUEUE);
    let mut isis_queries_rx = Some(isis_queries_rx);
    let isis_enabled = cfg.isis.as_ref().is_some_and(|i| i.enabled);
    let (babel_queries_tx, babel_queries_rx) = mpsc::channel(QUERY_QUEUE);
    let mut babel_queries_rx = Some(babel_queries_rx);
    let babel_enabled = cfg.babel.as_ref().is_some_and(|b| b.enabled);
    let (rip_queries_tx, rip_queries_rx) = mpsc::channel(QUERY_QUEUE);
    let mut rip_queries_rx = Some(rip_queries_rx);
    let rip_enabled = cfg.rip.as_ref().is_some_and(|r| r.enabled);
    let (ripng_queries_tx, ripng_queries_rx) = mpsc::channel(QUERY_QUEUE);
    let mut ripng_queries_rx = Some(ripng_queries_rx);
    let ripng_enabled = cfg.ripng.as_ref().is_some_and(|r| r.enabled);
    {
        let socket = args.socket.clone();
        let channels = control::Channels {
            router: queries_tx.clone(),
            bgp: bgp_enabled.then(|| bgp_queries_tx.clone()),
            ospf: ospf_enabled.then(|| ospf_queries_tx.clone()),
            ospf3: ospf3_enabled.then(|| ospf3_queries_tx.clone()),
            isis: isis_enabled.then(|| isis_queries_tx.clone()),
            babel: babel_enabled.then(|| babel_queries_tx.clone()),
            rip: rip_enabled.then(|| rip_queries_tx.clone()),
            ripng: ripng_enabled.then(|| ripng_queries_tx.clone()),
        };
        tokio::spawn(async move {
            if let Err(e) = control::serve(socket, channels).await {
                warn!(error = %e, "control socket disabled");
            }
        });
    }

    // Spawn the RIP engine if it is configured.
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
                tokio::spawn(async move {
                    if let Err(e) = ospf::run(run_cfg, tx, redist_rx, qrx).await {
                        error!(error = %e, "OSPF engine stopped");
                    }
                });
            }
            Err(e) => error!(error = %e, "OSPF not started"),
        }
    }

    // Spawn the OSPFv3 (IPv6) engine if it is configured.
    if let Some(ospf3cfg) = cfg.ospf3.as_ref().filter(|o| o.enabled) {
        match build_ospf3_config(&cfg, ospf3cfg) {
            Ok(run_cfg) => {
                if backend == Backend::Memory {
                    warn!("OSPFv3 is enabled but the backend is in-memory — learned routes will not be installed in the kernel");
                }
                let tx = updates_tx.clone();
                let qrx = ospf3_queries_rx.take().expect("ospf3 queries rx taken once");
                tokio::spawn(async move {
                    if let Err(e) = ospf3::run(run_cfg, tx, qrx).await {
                        error!(error = %e, "OSPFv3 engine stopped");
                    }
                });
            }
            Err(e) => error!(error = %e, "OSPFv3 not started"),
        }
    }

    // Spawn the BGP-4 engine if it is configured.
    if let Some(bgpcfg) = cfg.bgp.as_ref().filter(|b| b.enabled) {
        match build_bgp_config(&cfg, bgpcfg) {
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
                let tx = updates_tx.clone();
                let qrx = bgp_queries_rx.take().expect("bgp queries rx taken once");
                tokio::spawn(async move {
                    if let Err(e) = bgp::run(run_cfg, tx, qrx, redist_rx).await {
                        error!(error = %e, "BGP engine stopped");
                    }
                });
            }
            Err(e) => error!(error = %e, "BGP not started"),
        }
    }

    // Spawn the Babel engine if it is configured.
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
                tokio::spawn(async move {
                    if let Err(e) = isis::run(run_cfg, tx, redist_rx, qrx).await {
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
        _ = router::run(&mut rib, fib.as_mut(), updates_rx, &imports, fib_export.as_ref(), &redist_targets, queries_rx) => {
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
    })
}

/// Resolve the textual `[ospf3]` config into the runner's [`ospf3::Ospf3Config`],
/// parsing the Router ID (required, still a 32-bit id over IPv6), the area and the
/// Instance ID, and redistributing only the IPv6 statics.
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
    })
}

/// Resolve the textual `[bgp]` config into the runner's [`bgp::BgpConfig`],
/// parsing the local AS (required), the Router ID (from `[bgp]` or the top-level),
/// the peers and the originated networks.
fn build_bgp_config(cfg: &wren_config::Config, bgp: &wren_config::Bgp) -> Result<bgp::BgpConfig> {
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
        let addr: Ipv4Addr = n
            .address
            .parse()
            .with_context(|| format!("bgp neighbor address {:?} must be IPv4", n.address))?;
        peers.push(bgp::BgpPeerCfg {
            addr,
            remote_as: n.remote_as,
            passive: n.passive,
            rr_client: n.route_reflector_client,
        });
    }

    let mut originate = Vec::with_capacity(bgp.network.len());
    for net in &bgp.network {
        originate.push(
            net.parse()
                .with_context(|| format!("bgp network {net:?} must be addr/len"))?,
        );
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
    })
}
