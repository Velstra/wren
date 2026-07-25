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
mod bfd_echo;
mod bgp;
mod bmp;
mod connected;
mod control;
mod fib;
#[cfg(feature = "igmp")]
mod igmp;
#[cfg(feature = "isis")]
mod isis;
#[cfg(feature = "igmp")]
mod mld;
mod metrics;
#[cfg(feature = "pim")]
mod mroute;
#[cfg(feature = "pim")]
mod pim;
#[cfg(feature = "ospf")]
mod ospf;
#[cfg(feature = "ospf3")]
mod ospf3;
mod query;
#[cfg(feature = "rip")]
mod rip;
#[cfg(feature = "rip")]
mod ripng;
mod reload;
mod router;
mod rtr;
#[cfg(feature = "vrrp")]
mod vrrp;
// Always compiled: BFD (always-on) uses `setsockopt_int` for IPv6 hop limit /
// `IPV6_V6ONLY`, on top of every `_rawsock` protocol runner.
mod sockopt;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
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
    /// Run an EVPN action on a running wren daemon, e.g. `wren evpn advertise 100
    /// aa:bb:cc:dd:ee:ff 10.0.0.5` to dynamically originate a type-2 MAC/IP route
    /// (or `evpn withdraw …` to remove it). The write-side counterpart to `monitor
    /// evpn`; the fabric datapath calls this as it learns/ages local MACs.
    Evpn {
        /// The action words, e.g. `advertise 100 aa:bb:cc:dd:ee:ff 10.0.0.5`.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Stream the forwarding table from a running wren daemon as it changes
    /// (`wren monitor routes`): an initial snapshot followed by live route
    /// install/withdraw events. The FPM-style feed an external forwarding plane
    /// consumes; runs until interrupted.
    Monitor {
        /// What to monitor, e.g. `routes`.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Join a multicast group on an interface and hold the membership (a diagnostic
    /// / test helper). The kernel then emits genuine IGMP membership reports for the
    /// group; runs until interrupted. Used by the IGMP querier smoke to stand in for
    /// a receiving host.
    #[cfg(feature = "igmp")]
    McastJoin {
        /// The multicast group to join, e.g. `239.1.1.1`.
        group: String,
        /// The interface to join it on, e.g. `eth0`.
        #[arg(long)]
        iface: String,
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
    if let Some(Command::Evpn { args: words }) = &args.command {
        let command = format!("evpn {}", words.join(" "));
        return control::run_client(&args.socket, command.trim()).await;
    }
    // Monitor mode: open a long-lived route-export stream and print events as they
    // arrive, until interrupted.
    if let Some(Command::Monitor { args: words }) = &args.command {
        let command = format!("monitor {}", words.join(" "));
        return control::run_monitor_client(&args.socket, command.trim()).await;
    }
    // `mcast-join` is a leaf helper: join the group and park (the kernel emits IGMP
    // reports for it). It never returns, so handle it before standing up the daemon.
    #[cfg(feature = "igmp")]
    if let Some(Command::McastJoin { group, iface }) = &args.command {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
        let g: IpAddr = group
            .parse()
            .with_context(|| format!("mcast-join group {group:?} is not an IP address"))?;
        return igmp::mcast_join_blocking(g, iface);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Supervision: each routing protocol runs in its own spawned task. With
    // unwinding (no panic=abort, see the workspace Cargo.toml), a panic in one
    // protocol's FSM terminates only that task rather than the whole daemon.
    // This hook makes such a panic visible via tracing instead of being lost
    // when the discarded JoinHandle drops, so the operator sees which protocol
    // died and where. (Restart-on-panic supervision is future work.)
    {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let location = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "<unknown>".to_string());
            tracing::error!(location = %location, "task panicked: {info}");
            default_hook(info);
        }));
    }

    let cfg = wren_config::Config::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    info!(router_id = ?cfg.router_id, "configuration loaded");

    // Pick the forwarding plane. `--dry-run` forces the in-memory backend.
    let backend = if args.dry_run {
        Backend::Memory
    } else {
        args.backend
    };
    let fib_backend: Box<dyn Fib + Send> = match backend {
        Backend::Kernel => {
            Box::new(KernelFib::new().map_err(|e| anyhow::anyhow!("opening kernel FIB: {e}"))?)
        }
        Backend::Memory => Box::new(MemoryFib::default()),
    };
    // Move the forwarding plane onto its own OS thread (review C7): its blocking
    // netlink syscalls then never run on — and never stall — the async runtime.
    // Everything below talks to it through this async handle.
    let fib = fib::spawn(fib_backend);

    // Resolve the static routes once: their prefixes are the set we keep when
    // reconciling away a previous instance's leftover forwarding-plane routes.
    let statics = cfg.static_routes().context("resolving static routes")?;
    let keep: HashSet<_> = statics.iter().map(|r| (r.table, r.prefix)).collect();

    // Reconcile at startup: drop routes a previous wren instance left in the
    // forwarding plane that the current config no longer programs, so a restart
    // doesn't leave stale routes behind. (A no-op on the dry-run in-memory plane;
    // dynamic protocols re-install their routes as they reconverge.)
    match fib.owned_routes().await {
        Ok(owned) if !owned.is_empty() => {
            let removed = router::reconcile_owned(&fib, owned, &keep).await;
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
    // The static routes actually admitted into the RIB (after each VRF import
    // route-map): the baseline the router diffs a SIGHUP reload against.
    let mut seeded_statics: Vec<wren_core::Route> = Vec::new();
    for route in statics {
        let route = match vrf_routemap(&vrf_imports, route) {
            Some(r) => r,
            None => continue, // import route-map rejected it
        };
        seeded_statics.push(route.clone());
        if let Some(change) = rib.update(route) {
            if let FibChange::Install(best) = &change {
                // The export route-map may drop it (kept in the RIB, off the FIB).
                if let Some(best) = vrf_routemap(&vrf_exports, best.clone()) {
                    fib.apply(FibChange::Install(best))
                        .await
                        .map_err(|e| anyhow::anyhow!(e))?;
                    installed += 1;
                }
            } else {
                fib.apply(change).await.map_err(|e| anyhow::anyhow!(e))?;
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
    // Route-export subscriptions (`wren monitor routes`) → the router loop. The
    // `_tx` end is held for the whole run so the router's subscribe select arm
    // never sees a closed channel.
    let (subscribe_tx, subscribe_rx) = mpsc::channel(QUERY_QUEUE);
    // SIGHUP config hot-reload → the router loop. On SIGHUP a background task re-reads
    // the config file, re-resolves its static routes, and sends them here; the router
    // diffs against the running set and applies only the delta. The `_tx` end is held
    // for the whole run so the router's reload select arm never sees a closed channel.
    let (reload_tx, reload_rx) = mpsc::channel::<router::ReloadRoutes>(QUERY_QUEUE);
    // SIGHUP route-filter hot-reload → the router loop. On SIGHUP the reload task
    // re-compiles the filters and sends the new import + FIB-export set here; the
    // router swaps its live filter set wholesale (re-evaluated on the next update each
    // affects). The `_tx` end is held for the whole run so the router's filter-reload
    // select arm never sees a closed channel.
    let (filter_reload_tx, filter_reload_rx) = mpsc::channel::<router::FilterReload>(QUERY_QUEUE);
    // SIGHUP BGP neighbour hot-reload → the BGP task. On SIGHUP the reload task diffs the
    // re-read neighbour set against the running one and sends the add/remove delta here;
    // the BGP engine starts the added peers and tears the removed ones down, leaving
    // unchanged peers untouched. The `_tx` end is held for the whole run (moved into the
    // reload task) so the engine's reconfig arm never sees a closed channel; the `_rx` is
    // taken into `bgp::run` only when BGP is enabled.
    let (bgp_reload_tx, bgp_reload_rx) = mpsc::channel::<bgp::BgpReconfig>(QUERY_QUEUE);
    let mut bgp_reload_rx = Some(bgp_reload_rx);
    // EVPN monitor subscriptions (`wren monitor evpn`) → the BGP task. The `_tx`
    // end is held in `Channels` (only when BGP runs) so the task's subscribe arm
    // never sees a closed channel; the `_rx` is moved into `bgp::run`.
    let (evpn_subscribe_tx, evpn_subscribe_rx) = mpsc::channel(QUERY_QUEUE);
    let mut evpn_subscribe_rx = Some(evpn_subscribe_rx);
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
    #[cfg(feature = "rip")]
    let (rip_bfd_tx, rip_bfd_rx) = mpsc::channel::<std::net::IpAddr>(QUERY_QUEUE);
    #[cfg(feature = "rip")]
    let mut rip_bfd_rx = Some(rip_bfd_rx);
    #[cfg(feature = "babel")]
    let (babel_bfd_tx, babel_bfd_rx) = mpsc::channel::<std::net::IpAddr>(QUERY_QUEUE);
    #[cfg(feature = "babel")]
    let mut babel_bfd_rx = Some(babel_bfd_rx);
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
    #[cfg(feature = "rip")]
    let rip_bfd = cfg.rip.as_ref().is_some_and(|r| r.enabled && r.bfd);
    #[cfg(not(feature = "rip"))]
    let rip_bfd = false;
    #[cfg(feature = "babel")]
    let babel_bfd = cfg.babel.as_ref().is_some_and(|b| b.enabled && b.bfd);
    #[cfg(not(feature = "babel"))]
    let babel_bfd = false;
    let bfd_enabled = bgp_bfd || ospf_bfd || ospf3_bfd || isis_bfd || rip_bfd || babel_bfd;

    // Graceful shutdown (M10): a watch channel every protocol engine observes.
    // On Ctrl-C `main` flips it to `true`; each engine's select loop then emits
    // its protocol goodbye (VRRP priority-0, BGP CEASE, RIP/Babel poison, …) and
    // returns. `main` collects the engines' JoinHandles and awaits them within a
    // grace window so those goodbyes actually reach the wire before the process
    // exits. This is the ProtocolRunner lifecycle seam (Architektur-3) — the same
    // signal a future config hot-reload would ride. Engines subscribe with
    // `shutdown_tx.subscribe()`; ones not yet wired for a goodbye simply keep
    // running until the process exits, exactly as before.
    const GRACEFUL_SHUTDOWN_SECS: u64 = 2;
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let mut proto_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // Full-configuration hot-reload (SIGHUP): supervises the dynamic protocol engines
    // (OSPF/OSPFv3, RIP/RIPng, Babel, IS-IS, VRRP) so a later SIGHUP can start a
    // newly-enabled one, stop a newly-disabled one, or restart one whose interface set
    // changed — each by (re)spawning just that engine's task, never the whole daemon.
    // Startup-spawned engines call `mark_started` below (getting their stop signal from
    // it); their respawn closures are registered just before the reload task.
    let mut supervisor = reload::Supervisor::new(shutdown_tx.clone());

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
        let echo = bfd_echo_config(cfg.bfd.as_ref());
        let rrx = bfd_register_rx.take().expect("bfd register rx taken once");
        let bqrx = bfd_queries_rx.take().expect("bfd queries rx taken once");
        info!(
            auth = auth.is_some(),
            echo = echo.is_some(),
            "BFD engine starting"
        );
        let sd = shutdown_tx.subscribe();
        proto_handles.push(tokio::spawn(async move {
            if let Err(e) = bfd::run(
                bfd::BfdConfig {
                    session,
                    auth,
                    echo,
                },
                rrx,
                bqrx,
                sd,
            )
            .await
            {
                error!(error = %e, "BFD engine stopped");
            }
        }));
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
    #[cfg(feature = "vrrp")]
    let (vrrp_queries_tx, vrrp_queries_rx) = mpsc::channel(QUERY_QUEUE);
    #[cfg(feature = "vrrp")]
    let mut vrrp_queries_rx = Some(vrrp_queries_rx);
    #[cfg(feature = "vrrp")]
    let vrrp_enabled = !cfg.vrrp.is_empty();
    // PIM-SM (`show pim …`) query channel, and the IGMP→PIM membership feed. Both
    // exist only when PIM is enabled in `[multicast.pim]`.
    #[cfg(feature = "pim")]
    let pim_enabled = cfg
        .multicast
        .as_ref()
        .filter(|m| m.enabled)
        .and_then(|m| m.pim.as_ref())
        .map(|p| p.enabled)
        .unwrap_or(false);
    #[cfg(feature = "pim")]
    let (pim_queries_tx, pim_queries_rx) = mpsc::channel(QUERY_QUEUE);
    #[cfg(feature = "pim")]
    let mut pim_queries_rx = Some(pim_queries_rx);
    #[cfg(feature = "pim")]
    let (pim_membership_tx, pim_membership_rx) = mpsc::channel::<igmp::MembershipUpdate>(QUERY_QUEUE);
    #[cfg(feature = "pim")]
    let mut pim_membership_rx = Some(pim_membership_rx);
    {
        let socket = args.socket.clone();
        let channels = control::Channels {
            router: queries_tx.clone(),
            subscribe: subscribe_tx.clone(),
            evpn_subscribe: bgp_enabled.then(|| evpn_subscribe_tx.clone()),
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
            #[cfg(feature = "vrrp")]
            vrrp: vrrp_enabled.then(|| vrrp_queries_tx.clone()),
            #[cfg(feature = "pim")]
            pim: pim_enabled.then(|| pim_queries_tx.clone()),
        };
        tokio::spawn(async move {
            if let Err(e) = control::serve(socket, channels).await {
                warn!(error = %e, "control socket disabled");
            }
        });
    }

    // Spawn the VRRP engine if any virtual router is configured.
    #[cfg(feature = "vrrp")]
    if vrrp_enabled {
        match build_vrrp_instances(&cfg) {
            Ok(instances) => {
                let qrx = vrrp_queries_rx.take().expect("vrrp queries rx taken once");
                let shutdown = supervisor.mark_started("vrrp", vrrp_sig(&cfg));
                proto_handles.push(tokio::spawn(async move {
                    if let Err(e) = vrrp::run(instances, qrx, shutdown).await {
                        error!(error = %e, "VRRP engine stopped");
                    }
                }));
            }
            Err(e) => error!(error = %e, "VRRP not started"),
        }
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
        let ripcfg_bfd = ripcfg.bfd;
        // The VRF this RIP instance runs in (its routes go into that VRF's table).
        let rip_table = match &ripcfg.vrf {
            Some(name) => cfg
                .vrf_table(name)
                .with_context(|| format!("rip references unknown vrf {name:?}"))?,
            None => wren_core::RT_TABLE_MAIN,
        };
        let tx = updates_tx.clone();
        let qrx = rip_queries_rx.take().expect("rip queries rx taken once");
        // BFD (RFC 5880) plumbing: the engine registration channel, RIP's own notify
        // sender (included in each registration), and the down channel the engine
        // reports failures on. Inert unless `[rip] bfd` is set.
        let breg = bfd_register_tx.clone();
        let bnotify = rip_bfd_tx.clone();
        let bdrx = rip_bfd_rx.take().expect("rip bfd rx taken once");
        let sd = supervisor.mark_started("rip", rip_sig(&cfg));
        proto_handles.push(tokio::spawn(async move {
            if let Err(e) = rip::run(
                interfaces,
                rip_table,
                tx,
                redist_rx,
                redistribute_metric,
                qrx,
                ripcfg_bfd,
                breg,
                bnotify,
                bdrx,
                sd,
            )
            .await
            {
                error!(error = %e, "RIP engine stopped");
            }
        }));
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
                info!(
                    sources = target.sources.len(),
                    "RIPng redistribution active"
                );
                redist_targets.push(target);
            }
            Ok(None) => {}
            Err(e) => error!(error = %e, "RIPng redistribution not configured"),
        }
        let redistribute_metric = ripngcfg.redistribute_metric.unwrap_or(1);
        let interfaces = ripngcfg.interfaces.clone();
        let tx = updates_tx.clone();
        let qrx = ripng_queries_rx
            .take()
            .expect("ripng queries rx taken once");
        let sd = supervisor.mark_started("ripng", ripng_sig(&cfg));
        proto_handles.push(tokio::spawn(async move {
            if let Err(e) =
                ripng::run(interfaces, tx, redist_rx, redistribute_metric, qrx, sd).await
            {
                error!(error = %e, "RIPng engine stopped");
            }
        }));
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
                let sd = supervisor.mark_started("ospf", ospf_sig(&cfg));
                proto_handles.push(tokio::spawn(async move {
                    if let Err(e) =
                        ospf::run(run_cfg, tx, redist_rx, qrx, breg, bnotify, bdrx, sd).await
                    {
                        error!(error = %e, "OSPF engine stopped");
                    }
                }));
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
                let qrx = ospf3_queries_rx
                    .take()
                    .expect("ospf3 queries rx taken once");
                // BFD (RFC 5880) plumbing: the engine registration channel, OSPFv3's
                // own notify channel, and the down channel the engine reports failures
                // on. Inert unless `[ospf3] bfd` is set.
                let breg = bfd_register_tx.clone();
                let bnotify = ospf3_bfd_tx.clone();
                let bdrx = ospf3_bfd_rx.take().expect("ospf3 bfd rx taken once");
                let sd = supervisor.mark_started("ospf3", ospf3_sig(&cfg));
                proto_handles.push(tokio::spawn(async move {
                    if let Err(e) = ospf3::run(run_cfg, tx, qrx, breg, bnotify, bdrx, sd).await {
                        error!(error = %e, "OSPFv3 engine stopped");
                    }
                }));
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
                            let rtr_run = rtr::RtrConfig {
                                server,
                                refresh: rtrcfg.refresh,
                            };
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
                            let sys_descr = bmpcfg
                                .sys_descr
                                .clone()
                                .unwrap_or_else(|| "wren".to_string());
                            let brx = bmp_rx.take().expect("bmp rx taken once");
                            info!(%station, "BMP client starting");
                            tokio::spawn(async move {
                                bmp::run(
                                    bmp::BmpConfig {
                                        station,
                                        sys_name,
                                        sys_descr,
                                    },
                                    brx,
                                )
                                .await
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
                let esrx = evpn_subscribe_rx
                    .take()
                    .expect("evpn subscribe rx taken once");
                let sd = shutdown_tx.subscribe();
                let rcrx = bgp_reload_rx.take().expect("bgp reload rx taken once");
                proto_handles.push(tokio::spawn(async move {
                    if let Err(e) = bgp::run(
                        run_cfg,
                        tx,
                        qrx,
                        redist_rx,
                        rrx,
                        bmp_for_engine,
                        bdrx,
                        esrx,
                        sd,
                        rcrx,
                    )
                    .await
                    {
                        error!(error = %e, "BGP engine stopped");
                    }
                }));
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
                        Err(e) => {
                            warn!(error = %e, "skipping BFD for an unparsable neighbour address")
                        }
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
                        info!(
                            sources = target.sources.len(),
                            "Babel redistribution active"
                        );
                        redist_targets.push(target);
                    }
                    Ok(None) => {}
                    Err(e) => error!(error = %e, "Babel redistribution not configured"),
                }
                let tx = updates_tx.clone();
                let qrx = babel_queries_rx
                    .take()
                    .expect("babel queries rx taken once");
                // BFD (RFC 5880) plumbing: the engine registration channel, Babel's own
                // notify sender (included in each registration), and the down channel
                // the engine reports failures on. Inert unless `[babel] bfd` is set.
                let breg = bfd_register_tx.clone();
                let bnotify = babel_bfd_tx.clone();
                let bdrx = babel_bfd_rx.take().expect("babel bfd rx taken once");
                let sd = supervisor.mark_started("babel", babel_sig(&cfg));
                proto_handles.push(tokio::spawn(async move {
                    if let Err(e) = babel::run(run_cfg, tx, redist_rx, qrx, breg, bnotify, bdrx, sd).await {
                        error!(error = %e, "Babel engine stopped");
                    }
                }));
            }
            Err(e) => error!(error = %e, "Babel not started"),
        }
    }

    // Spawn the IGMP querier / proxy (RFC 3376 / RFC 4605) if it is configured. It
    // owns its own membership state and touches neither the RIB nor the FIB (the
    // multicast forwarding cache is a separate kernel table), so it needs none of
    // the router/redistribution plumbing — just a shutdown handle.
    #[cfg(feature = "igmp")]
    if let Some(mccfg) = cfg.multicast.as_ref().filter(|m| m.enabled) {
        match build_querier_config(mccfg) {
            Ok(mut run_cfg) => {
                // When PIM-SM is enabled, the IGMP querier feeds membership changes to
                // the PIM runner so it can build the multicast trees.
                #[cfg(feature = "pim")]
                if pim_enabled {
                    run_cfg.pim_feed = Some(pim_membership_tx.clone());
                }
                // IGMP (IPv4) — on by default; MLD (IPv6) — off by default. Both run
                // the same querier over their address family on the same interfaces.
                if mccfg.igmp.unwrap_or(true) {
                    let sd = shutdown_tx.subscribe();
                    let run_cfg = run_cfg.clone();
                    proto_handles.push(tokio::spawn(async move {
                        if let Err(e) = igmp::run(run_cfg, sd).await {
                            error!(error = %e, "IGMP querier stopped");
                        }
                    }));
                }
                if mccfg.mld.unwrap_or(false) {
                    let sd = shutdown_tx.subscribe();
                    proto_handles.push(tokio::spawn(async move {
                        if let Err(e) = mld::run(run_cfg, sd).await {
                            error!(error = %e, "MLD querier stopped");
                        }
                    }));
                }
            }
            Err(e) => error!(error = %e, "IGMP/MLD not started"),
        }
    }

    // Spawn the PIM-SM router (RFC 7761, static RP) if `[multicast.pim]` is enabled.
    // It consumes the IGMP membership feed wired above and programs the kernel
    // multicast forwarding cache directly (not the RIB/FIB).
    #[cfg(feature = "pim")]
    if pim_enabled {
        if let Some(mccfg) = cfg.multicast.as_ref().filter(|m| m.enabled) {
            match build_pim_config(mccfg) {
                Ok(run_cfg) => {
                    let sd = shutdown_tx.subscribe();
                    let mrx = pim_membership_rx.take().expect("pim membership rx taken once");
                    let qrx = pim_queries_rx.take().expect("pim queries rx taken once");
                    proto_handles.push(tokio::spawn(async move {
                        if let Err(e) = pim::run(run_cfg, mrx, qrx, sd).await {
                            error!(error = %e, "PIM-SM router stopped");
                        }
                    }));
                }
                Err(e) => error!(error = %e, "PIM-SM not started"),
            }
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
                        info!(
                            sources = target.sources.len(),
                            "IS-IS redistribution active"
                        );
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
                let sd = supervisor.mark_started("isis", isis_sig(&cfg));
                proto_handles.push(tokio::spawn(async move {
                    if let Err(e) =
                        isis::run(run_cfg, tx, redist_rx, qrx, breg, bnotify, bdrx, sd).await
                    {
                        error!(error = %e, "IS-IS engine stopped");
                    }
                }));
            }
            Err(e) => error!(error = %e, "IS-IS not started"),
        }
    }

    // Push the statically-seeded best routes to the redistribution targets once;
    // they were installed directly above, bypassing the router loop's fan-out.
    router::redistribute_seed(&redist_targets, &rib).await;

    // Register each dynamic protocol's hot-reload behaviour with the supervisor: how to
    // read its reload signature and how to (re)spawn its engine task from a freshly-read
    // config. A protocol that is *off* at startup is registered too, so a later SIGHUP
    // can start it. A supervisor-spawned generation runs with fresh internal channels;
    // it therefore has no `show <proto>` control-socket route and does not re-register
    // `redistribute` (documented deferrals — see `reload.rs`).
    #[cfg(feature = "ospf")]
    {
        let updates_tx = updates_tx.clone();
        let breg = bfd_register_tx.clone();
        let bnotify = ospf_bfd_tx.clone();
        supervisor.register(
            "ospf",
            Box::new(ospf_sig),
            Box::new(move |cfg, stop| {
                let ospfcfg = cfg.ospf.as_ref().filter(|o| o.enabled)?;
                let run_cfg = match build_ospf_config(cfg, ospfcfg) {
                    Ok(c) => c,
                    Err(e) => {
                        error!(error = %e, "OSPF hot-reload config invalid; not started");
                        return None;
                    }
                };
                let (rtx, redist_rx) = mpsc::channel(REDIST_QUEUE);
                let (qtx, qrx) = mpsc::channel(QUERY_QUEUE);
                let (bdtx, bdrx) = mpsc::channel(QUERY_QUEUE);
                let tx = updates_tx.clone();
                let breg = breg.clone();
                let bnotify = bnotify.clone();
                let join = tokio::spawn(async move {
                    if let Err(e) =
                        ospf::run(run_cfg, tx, redist_rx, qrx, breg, bnotify, bdrx, stop).await
                    {
                        error!(error = %e, "OSPF engine stopped");
                    }
                });
                Some(reload::SpawnOut {
                    join,
                    parked: vec![Box::new(rtx), Box::new(qtx), Box::new(bdtx)],
                })
            }),
        );
    }
    #[cfg(feature = "ospf3")]
    {
        let updates_tx = updates_tx.clone();
        let breg = bfd_register_tx.clone();
        let bnotify = ospf3_bfd_tx.clone();
        supervisor.register(
            "ospf3",
            Box::new(ospf3_sig),
            Box::new(move |cfg, stop| {
                let ospf3cfg = cfg.ospf3.as_ref().filter(|o| o.enabled)?;
                let run_cfg = match build_ospf3_config(cfg, ospf3cfg) {
                    Ok(c) => c,
                    Err(e) => {
                        error!(error = %e, "OSPFv3 hot-reload config invalid; not started");
                        return None;
                    }
                };
                let (qtx, qrx) = mpsc::channel(QUERY_QUEUE);
                let (bdtx, bdrx) = mpsc::channel(QUERY_QUEUE);
                let tx = updates_tx.clone();
                let breg = breg.clone();
                let bnotify = bnotify.clone();
                let join = tokio::spawn(async move {
                    if let Err(e) = ospf3::run(run_cfg, tx, qrx, breg, bnotify, bdrx, stop).await {
                        error!(error = %e, "OSPFv3 engine stopped");
                    }
                });
                Some(reload::SpawnOut {
                    join,
                    parked: vec![Box::new(qtx), Box::new(bdtx)],
                })
            }),
        );
    }
    #[cfg(feature = "rip")]
    {
        let updates_tx = updates_tx.clone();
        let breg = bfd_register_tx.clone();
        let bnotify = rip_bfd_tx.clone();
        supervisor.register(
            "rip",
            Box::new(rip_sig),
            Box::new(move |cfg, stop| {
                let ripcfg = cfg.rip.as_ref().filter(|r| r.enabled)?;
                let rip_table = match &ripcfg.vrf {
                    Some(name) => match cfg.vrf_table(name) {
                        Some(t) => t,
                        None => {
                            error!(vrf = %name, "RIP hot-reload references unknown vrf; not started");
                            return None;
                        }
                    },
                    None => wren_core::RT_TABLE_MAIN,
                };
                let interfaces = ripcfg.interfaces.clone();
                let ripcfg_bfd = ripcfg.bfd;
                let metric = ripcfg.redistribute_metric.unwrap_or(1);
                let (rtx, redist_rx) = mpsc::channel(REDIST_QUEUE);
                let (qtx, qrx) = mpsc::channel(QUERY_QUEUE);
                let (bdtx, bdrx) = mpsc::channel(QUERY_QUEUE);
                let tx = updates_tx.clone();
                let breg = breg.clone();
                let bnotify = bnotify.clone();
                let join = tokio::spawn(async move {
                    if let Err(e) = rip::run(
                        interfaces, rip_table, tx, redist_rx, metric, qrx, ripcfg_bfd, breg,
                        bnotify, bdrx, stop,
                    )
                    .await
                    {
                        error!(error = %e, "RIP engine stopped");
                    }
                });
                Some(reload::SpawnOut {
                    join,
                    parked: vec![Box::new(rtx), Box::new(qtx), Box::new(bdtx)],
                })
            }),
        );
    }
    #[cfg(feature = "rip")]
    {
        let updates_tx = updates_tx.clone();
        supervisor.register(
            "ripng",
            Box::new(ripng_sig),
            Box::new(move |cfg, stop| {
                let ripngcfg = cfg.ripng.as_ref().filter(|r| r.enabled)?;
                let interfaces = ripngcfg.interfaces.clone();
                let metric = ripngcfg.redistribute_metric.unwrap_or(1);
                let (rtx, redist_rx) = mpsc::channel(REDIST_QUEUE);
                let (qtx, qrx) = mpsc::channel(QUERY_QUEUE);
                let tx = updates_tx.clone();
                let join = tokio::spawn(async move {
                    if let Err(e) = ripng::run(interfaces, tx, redist_rx, metric, qrx, stop).await {
                        error!(error = %e, "RIPng engine stopped");
                    }
                });
                Some(reload::SpawnOut {
                    join,
                    parked: vec![Box::new(rtx), Box::new(qtx)],
                })
            }),
        );
    }
    #[cfg(feature = "babel")]
    {
        let updates_tx = updates_tx.clone();
        let breg = bfd_register_tx.clone();
        let bnotify = babel_bfd_tx.clone();
        supervisor.register(
            "babel",
            Box::new(babel_sig),
            Box::new(move |cfg, stop| {
                let babelcfg = cfg.babel.as_ref().filter(|b| b.enabled)?;
                let run_cfg = match build_babel_config(cfg, babelcfg) {
                    Ok(c) => c,
                    Err(e) => {
                        error!(error = %e, "Babel hot-reload config invalid; not started");
                        return None;
                    }
                };
                let (rtx, redist_rx) = mpsc::channel(REDIST_QUEUE);
                let (qtx, qrx) = mpsc::channel(QUERY_QUEUE);
                let (bdtx, bdrx) = mpsc::channel(QUERY_QUEUE);
                let tx = updates_tx.clone();
                let breg = breg.clone();
                let bnotify = bnotify.clone();
                let join = tokio::spawn(async move {
                    if let Err(e) =
                        babel::run(run_cfg, tx, redist_rx, qrx, breg, bnotify, bdrx, stop).await
                    {
                        error!(error = %e, "Babel engine stopped");
                    }
                });
                Some(reload::SpawnOut {
                    join,
                    parked: vec![Box::new(rtx), Box::new(qtx), Box::new(bdtx)],
                })
            }),
        );
    }
    #[cfg(feature = "isis")]
    {
        let updates_tx = updates_tx.clone();
        let breg = bfd_register_tx.clone();
        let bnotify = isis_bfd_tx.clone();
        supervisor.register(
            "isis",
            Box::new(isis_sig),
            Box::new(move |cfg, stop| {
                let isiscfg = cfg.isis.as_ref().filter(|i| i.enabled)?;
                let run_cfg = match build_isis_config(cfg, isiscfg) {
                    Ok(c) => c,
                    Err(e) => {
                        error!(error = %e, "IS-IS hot-reload config invalid; not started");
                        return None;
                    }
                };
                let (rtx, redist_rx) = mpsc::channel(REDIST_QUEUE);
                let (qtx, qrx) = mpsc::channel(QUERY_QUEUE);
                let (bdtx, bdrx) = mpsc::channel(QUERY_QUEUE);
                let tx = updates_tx.clone();
                let breg = breg.clone();
                let bnotify = bnotify.clone();
                let join = tokio::spawn(async move {
                    if let Err(e) =
                        isis::run(run_cfg, tx, redist_rx, qrx, breg, bnotify, bdrx, stop).await
                    {
                        error!(error = %e, "IS-IS engine stopped");
                    }
                });
                Some(reload::SpawnOut {
                    join,
                    parked: vec![Box::new(rtx), Box::new(qtx), Box::new(bdtx)],
                })
            }),
        );
    }
    #[cfg(feature = "vrrp")]
    {
        supervisor.register(
            "vrrp",
            Box::new(vrrp_sig),
            Box::new(move |cfg, stop| {
                if cfg.vrrp.is_empty() {
                    return None;
                }
                let instances = match build_vrrp_instances(cfg) {
                    Ok(i) => i,
                    Err(e) => {
                        error!(error = %e, "VRRP hot-reload config invalid; not started");
                        return None;
                    }
                };
                let (qtx, qrx) = mpsc::channel(QUERY_QUEUE);
                let join = tokio::spawn(async move {
                    if let Err(e) = vrrp::run(instances, qrx, stop).await {
                        error!(error = %e, "VRRP engine stopped");
                    }
                });
                Some(reload::SpawnOut {
                    join,
                    parked: vec![Box::new(qtx)],
                })
            }),
        );
    }

    // SIGHUP: re-read the whole configuration and hot-apply the delta without a daemon
    // restart. Static routes and route filters reconcile live in the router; BGP
    // neighbours (add/remove) reconcile live in the BGP engine; the dynamic protocol
    // engines (OSPF/OSPFv3, RIP/RIPng, Babel, IS-IS, VRRP) are started/stopped/restarted
    // by the `supervisor`. A reload that fails to parse (or names a bad filter) is logged
    // and ignored so the running configuration is kept rather than a broken one applied.
    let config_path = args.config.clone();
    // Only diff BGP neighbours when BGP is running: the engine is spawned only when it was
    // enabled at startup, so an added neighbour has an engine to bring it up.
    let bgp_reconfig_enabled = bgp_enabled;
    // The neighbour set the running BGP engine holds, by transport address — the baseline
    // the next reload diffs against. Seeded from the startup config.
    let mut known_bgp_peers: std::collections::HashSet<std::net::IpAddr> = cfg
        .bgp
        .as_ref()
        .filter(|b| b.enabled)
        .map(|b| {
            b.neighbor
                .iter()
                .filter_map(|n| parse_neighbor_addr(&n.address).ok().map(|(addr, _)| addr))
                .collect()
        })
        .unwrap_or_default();
    // Install the SIGHUP stream up front; a failure disables hot-reload but the daemon
    // runs on. `None` leaves the reload select arm parked forever (never fires).
    let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, "cannot install SIGHUP handler; config hot-reload disabled");
            None
        }
    };
    // SIGTERM is what an init system (systemd `stop`, a container runtime) sends to
    // ask for shutdown — Ctrl-C only delivers SIGINT. Without this, a `systemctl
    // stop wren` hard-kills the process and NONE of the graceful-shutdown work runs
    // (protocol goodbyes, and VRRP relinquishing mastership + releasing its VIP), so
    // a backup only takes over on the master-down timeout. Install it alongside
    // SIGINT; a failure just leaves SIGINT as the only graceful path.
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, "cannot install SIGTERM handler; only SIGINT/Ctrl-C will shut down");
            None
        }
    };

    info!("wren is running; send SIGINT (Ctrl-C) or SIGTERM to stop");
    // The router loop runs for the whole process. Pin it so the reload/shutdown `select!`
    // below can be re-entered on every SIGHUP without ever restarting it.
    let router_fut = router::run(
        &mut rib,
        &fib,
        updates_rx,
        &imports,
        fib_export.as_ref(),
        &redist_targets,
        &vrfs,
        queries_rx,
        subscribe_rx,
        &seeded_statics,
        reload_rx,
        filter_reload_rx,
    );
    tokio::pin!(router_fut);
    loop {
        // A daemon whose SIGHUP handler failed to install still needs a live future for
        // that arm; `pending()` never fires, so reload is simply inert.
        let hup_wait = async {
            match hup.as_mut() {
                Some(h) => {
                    h.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = &mut router_fut => {
                warn!("router loop ended (all protocol senders dropped)");
                break;
            }
            _ = hup_wait => {
                info!("SIGHUP received; reloading configuration");
                apply_reload(
                    &config_path,
                    &reload_tx,
                    &filter_reload_tx,
                    &bgp_reload_tx,
                    bgp_reconfig_enabled,
                    &mut known_bgp_peers,
                    &mut supervisor,
                )
                .await;
            }
            r = async {
                // Shut down on either SIGINT (Ctrl-C) or SIGTERM (systemd `stop`).
                match term.as_mut() {
                    Some(t) => tokio::select! {
                        r = tokio::signal::ctrl_c() => r,
                        _ = t.recv() => Ok(()),
                    },
                    None => tokio::signal::ctrl_c().await,
                }
            } => {
                r.context("waiting for shutdown signal")?;
                info!("shutting down; notifying peers");
                // Tell every wired engine to send its protocol goodbye, then give them a
                // bounded grace window to flush it before the process exits (M10). Routes
                // are deliberately left installed in the FIB so traffic keeps flowing
                // across a restart.
                let _ = shutdown_tx.send(true);
                let deadline = tokio::time::Instant::now()
                    + std::time::Duration::from_secs(GRACEFUL_SHUTDOWN_SECS);
                for handle in std::mem::take(&mut proto_handles) {
                    if tokio::time::timeout_at(deadline, handle).await.is_err() {
                        warn!("graceful-shutdown grace period elapsed; exiting anyway");
                        break;
                    }
                }
                // Await any engines the supervisor (re)started on a SIGHUP within the
                // same window — their goodbye rides the same shutdown signal via the
                // per-engine stop relay.
                supervisor.join_all(deadline).await;
                break;
            }
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
    let parse_areas = |list: &[String],
                       what: &str|
     -> Result<std::collections::HashSet<Ipv4Addr>> {
        list.iter()
            .map(|a| {
                a.parse()
                    .with_context(|| format!("ospf {what} must be a dotted quad, e.g. \"1.0.0.0\""))
            })
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
    let vrf_table = match &ospf.vrf {
        Some(name) => cfg
            .vrf_table(name)
            .with_context(|| format!("ospf references unknown vrf {name:?}"))?,
        None => wren_core::RT_TABLE_MAIN,
    };
    Ok(ospf::OspfConfig {
        router_id,
        iface_type,
        priority: ospf.router_priority.unwrap_or(1),
        cost: ospf.cost.unwrap_or(10),
        hello_interval: ospf.hello_interval.unwrap_or(wren_ospf::DEFAULT_HELLO_INTERVAL),
        dead_interval: ospf.dead_interval.unwrap_or(wren_ospf::DEFAULT_DEAD_INTERVAL),
        interfaces,
        passive_interfaces: ospf.passive_interfaces.iter().cloned().collect(),
        redistribute,
        redistribute_metric: ospf.redistribute_metric.unwrap_or(20),
        stub_areas,
        stub_default_cost: ospf.stub_default_cost.unwrap_or(1),
        nssa_areas,
        totally_stubby_areas,
        totally_nssa_areas,
        nssa_default_areas,
        auth,
        auth_replay_protection: ospf.auth_replay_protection.unwrap_or(true),
        graceful_restart: ospf.graceful_restart,
        grace_period: ospf.graceful_restart_period.unwrap_or(120),
        bfd: ospf.bfd,
        vrf_table,
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
                anyhow::bail!(
                    "ospf simple-password auth-key must be at most 8 bytes (RFC 2328 §D)"
                );
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
        auth: build_ospf3_auth(ospf3)?,
        auth_replay_protection: ospf3.auth_replay_protection.unwrap_or(true),
    })
}

/// Resolve the `[ospf3]` authentication config into the runner's RFC 7166
/// [`Auth`](wren_ospfv3::packet::Auth): `"none"` (or unset) sends plain packets,
/// `"hmac-sha256"` appends and verifies an HMAC-SHA-256 Authentication Trailer.
#[cfg(feature = "ospf3")]
fn build_ospf3_auth(ospf3: &wren_config::Ospf3) -> Result<wren_ospfv3::packet::Auth> {
    use wren_ospfv3::packet::Auth;
    match ospf3.auth_type.as_deref() {
        None | Some("none") => Ok(Auth::None),
        Some("hmac-sha256") => {
            let key = ospf3
                .auth_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .context("ospf3 auth-type \"hmac-sha256\" requires a non-empty auth-key")?;
            Ok(Auth::Hmac {
                sa_id: ospf3.auth_sa_id.unwrap_or(1),
                key: key.as_bytes().to_vec(),
                seq: 0,
            })
        }
        Some(other) => {
            anyhow::bail!("unknown ospf3 auth-type {other:?} (want none or hmac-sha256)")
        }
    }
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
            let cstr = std::ffi::CString::new(ifname).with_context(|| {
                format!("bgp neighbor interface {ifname:?} is not a valid name")
            })?;
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

/// Parse a BGP Role name (RFC 9234 §4) into a [`wren_bgp::capability::BgpRole`]. The
/// accepted names mirror the capability values: `provider`, `customer`, `peer`,
/// `rs-server` (Route Server) and `rs-client` (Route Server client).
fn parse_bgp_role(s: &str) -> Result<wren_bgp::capability::BgpRole> {
    use wren_bgp::capability::BgpRole;
    Ok(match s {
        "provider" => BgpRole::Provider,
        "customer" => BgpRole::Customer,
        "peer" => BgpRole::Peer,
        "rs-server" | "rs_server" => BgpRole::RouteServer,
        "rs-client" | "rs_client" => BgpRole::RouteServerClient,
        other => anyhow::bail!(
            "unknown role {other:?} (expected provider, customer, peer, rs-server or rs-client)"
        ),
    })
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

/// Resolve the BFD Echo timing (RFC 5880 §6.4) from the `[bfd]` block: `echo = true`
/// enables it, `echo-interval` (ms, default 100) sets the transmit interval, and the
/// shared `detect-mult` sets the Echo detection multiplier. `None` when Echo is off.
fn bfd_echo_config(bfd: Option<&wren_config::Bfd>) -> Option<bfd::EchoParams> {
    let b = bfd?;
    if !b.echo {
        return None;
    }
    let interval_ms = b.echo_interval.unwrap_or(100).max(1);
    let detect_mult = b.detect_mult.unwrap_or(3).max(1);
    Some(bfd::EchoParams {
        interval_us: (interval_ms as u64).saturating_mul(1000),
        detect_mult,
    })
}

/// Resolve the shared BFD authentication (RFC 5880 §6.7) from the `[bfd]` block:
/// `auth-type` selects the algorithm and `auth-key` is the shared secret (`auth-key-id`
/// the wire key id, default 1). Returns `None` when `auth-type` is unset (no
/// authentication), or an error when it is set without a key or names an unknown type.
/// Run a route through a VRF route-map: `None` if the route is in the default VRF or
/// the VRF has no such route-map; otherwise the filter's verdict (rewritten route on
/// accept, dropped on reject). Returns `Some(route)` to keep it, `None` to drop it.
fn vrf_routemap(
    maps: &std::collections::HashMap<u32, Filter>,
    route: wren_core::Route,
) -> Option<wren_core::Route> {
    match maps.get(&route.table) {
        Some(filter) => match filter.apply(&route) {
            Decision::Accept(r) => Some(r),
            Decision::Reject => None,
        },
        None => Some(route),
    }
}

// --- Reload signatures (hot-reload) -----------------------------------------------
//
// Each dynamic protocol's [`reload::Sig`] captures the two things a SIGHUP acts on for
// it: whether it is enabled, and its interface set. A restart is triggered only when
// one of those changes, so an unrelated edit elsewhere in the file never bounces an
// adjacency. Other per-protocol knobs still need a full daemon restart to take effect.

#[cfg(feature = "ospf")]
fn ospf_sig(cfg: &wren_config::Config) -> reload::Sig {
    match cfg.ospf.as_ref() {
        Some(o) => reload::Sig::new(
            o.enabled,
            o.interfaces
                .iter()
                .cloned()
                .chain(o.interface.iter().map(|i| i.name.clone())),
        ),
        None => reload::Sig::new(false, Vec::<String>::new()),
    }
}

#[cfg(feature = "ospf3")]
fn ospf3_sig(cfg: &wren_config::Config) -> reload::Sig {
    match cfg.ospf3.as_ref() {
        Some(o) => reload::Sig::new(
            o.enabled,
            o.interfaces
                .iter()
                .cloned()
                .chain(o.interface.iter().map(|i| i.name.clone())),
        ),
        None => reload::Sig::new(false, Vec::<String>::new()),
    }
}

#[cfg(feature = "rip")]
fn rip_sig(cfg: &wren_config::Config) -> reload::Sig {
    match cfg.rip.as_ref() {
        Some(r) => reload::Sig::new(r.enabled, r.interfaces.clone()),
        None => reload::Sig::new(false, Vec::<String>::new()),
    }
}

#[cfg(feature = "rip")]
fn ripng_sig(cfg: &wren_config::Config) -> reload::Sig {
    match cfg.ripng.as_ref() {
        Some(r) => reload::Sig::new(r.enabled, r.interfaces.clone()),
        None => reload::Sig::new(false, Vec::<String>::new()),
    }
}

#[cfg(feature = "babel")]
fn babel_sig(cfg: &wren_config::Config) -> reload::Sig {
    match cfg.babel.as_ref() {
        Some(b) => reload::Sig::new(b.enabled, b.interfaces.clone()),
        None => reload::Sig::new(false, Vec::<String>::new()),
    }
}

#[cfg(feature = "isis")]
fn isis_sig(cfg: &wren_config::Config) -> reload::Sig {
    match cfg.isis.as_ref() {
        Some(i) => reload::Sig::new(i.enabled, i.interfaces.clone()),
        None => reload::Sig::new(false, Vec::<String>::new()),
    }
}

#[cfg(feature = "vrrp")]
fn vrrp_sig(cfg: &wren_config::Config) -> reload::Sig {
    // VRRP has no single `enabled` flag: it runs when any `[[vrrp]]` instance is
    // defined. Each instance keys the signature by `interface/vrid` so adding or
    // removing an instance restarts the engine.
    reload::Sig::new(
        !cfg.vrrp.is_empty(),
        cfg.vrrp
            .iter()
            .map(|v| format!("{}/{}", v.interface, v.vrid)),
    )
}

/// The parts of a re-read configuration a SIGHUP hot-reload hands the running daemon:
/// the resolved static routes (for the router) and, when BGP is enabled, the resolved
/// neighbour set (for the BGP engine's neighbour delta).
struct ReloadedConfig {
    /// The freshly-parsed configuration, handed to the protocol supervisor so it can
    /// diff each dynamic engine's signature and start/stop/restart the ones that changed.
    cfg: wren_config::Config,
    /// Static routes, each already run through its VRF's import route-map — the same
    /// baseline the router holds, so it can diff and apply only the delta.
    statics: Vec<wren_core::Route>,
    /// The recompiled per-protocol import filters (for the router's live filter swap).
    imports: router::ImportFilters,
    /// The recompiled FIB export filter, or `None` (for the router's live filter swap).
    fib_export: Option<Filter>,
    /// The configured BGP peers, or `None` when BGP is disabled/absent (the reload then
    /// carries no neighbour delta).
    bgp_peers: Option<Vec<bgp::BgpPeerCfg>>,
}

/// Re-read the configuration file for a SIGHUP hot-reload: resolve its static routes
/// (applying each VRF's import route-map exactly as startup does, so the result is the
/// same baseline the router already holds) and, when BGP is enabled, build its neighbour
/// set. Returns both, or an error — a missing/unparsable file, bad TOML, or an unknown
/// filter — so the caller can keep the running configuration rather than apply a broken
/// one. Only neighbour add/remove is acted on by the caller; the rest of the BGP config
/// is not live-reconfigured.
fn reload_config(path: &std::path::Path) -> Result<ReloadedConfig> {
    let cfg = wren_config::Config::load(path)
        .with_context(|| format!("reloading {}", path.display()))?;
    let by_name = compile_named_filters(&cfg).context("compiling filters")?;
    let imports = resolve_import_filters(&cfg, &by_name).context("resolving import filters")?;
    let fib_export = resolve_fib_export(&cfg, &by_name).context("resolving export filters")?;
    let (vrf_imports, _vrf_exports) =
        build_vrf_routemaps(&cfg, &by_name).context("resolving vrf route-maps")?;
    let mut statics = Vec::new();
    for route in cfg.static_routes().context("resolving static routes")? {
        if let Some(route) = vrf_routemap(&vrf_imports, route) {
            statics.push(route);
        }
    }
    let bgp_peers = match cfg.bgp.as_ref().filter(|b| b.enabled) {
        Some(b) => Some(
            build_bgp_config(&cfg, b, &by_name)
                .context("resolving bgp neighbours")?
                .peers,
        ),
        None => None,
    };
    Ok(ReloadedConfig {
        cfg,
        statics,
        imports,
        fib_export,
        bgp_peers,
    })
}

/// Apply one SIGHUP config hot-reload: re-read the file and reconcile the running
/// daemon to it. Static routes and route filters reconcile live in the router; BGP
/// neighbours (add/remove) reconcile live in the BGP engine; the dynamic protocol
/// engines are started/stopped/restarted by the `supervisor`. A reload that fails to
/// parse or resolve is logged and dropped, keeping the running configuration.
#[allow(clippy::too_many_arguments)] // one reload step wires every hot-reloadable sink
async fn apply_reload(
    config_path: &std::path::Path,
    reload_tx: &mpsc::Sender<router::ReloadRoutes>,
    filter_reload_tx: &mpsc::Sender<router::FilterReload>,
    bgp_reload_tx: &mpsc::Sender<bgp::BgpReconfig>,
    bgp_reconfig_enabled: bool,
    known_bgp_peers: &mut std::collections::HashSet<std::net::IpAddr>,
    supervisor: &mut reload::Supervisor,
) {
    let reloaded = match reload_config(config_path) {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "config reload failed; keeping the running configuration");
            return;
        }
    };
    let static_count = reloaded.statics.len();
    if reload_tx
        .send(router::ReloadRoutes {
            statics: reloaded.statics,
        })
        .await
        .is_err()
    {
        warn!("router loop gone; static hot-reload skipped");
    }
    if filter_reload_tx
        .send(router::FilterReload {
            imports: reloaded.imports,
            fib_export: reloaded.fib_export,
        })
        .await
        .is_err()
    {
        warn!("router loop gone; filter hot-reload skipped");
    }
    info!(statics = static_count, "configuration reloaded");
    // BGP neighbour hot-reload: diff the re-read neighbour set against the running one
    // and send the add/remove delta to the BGP engine.
    if bgp_reconfig_enabled {
        if let Some(new_peers) = reloaded.bgp_peers {
            let new_set: std::collections::HashSet<std::net::IpAddr> =
                new_peers.iter().map(|p| p.addr).collect();
            let add: Vec<bgp::BgpPeerCfg> = new_peers
                .into_iter()
                .filter(|p| !known_bgp_peers.contains(&p.addr))
                .collect();
            let remove: Vec<std::net::IpAddr> = known_bgp_peers
                .iter()
                .copied()
                .filter(|a| !new_set.contains(a))
                .collect();
            if add.is_empty() && remove.is_empty() {
                *known_bgp_peers = new_set;
            } else {
                let (added, removed) = (add.len(), remove.len());
                if bgp_reload_tx
                    .send(bgp::BgpReconfig { add, remove })
                    .await
                    .is_err()
                {
                    warn!("BGP engine gone; neighbour hot-reload skipped");
                } else {
                    info!(added, removed, "BGP neighbours hot-reloaded");
                    *known_bgp_peers = new_set;
                }
            }
        }
    }
    // Dynamic protocol engines (OSPF/OSPFv3, RIP/RIPng, Babel, IS-IS, VRRP): start,
    // stop, or restart just the ones whose enable flag or interface set changed.
    supervisor.apply(&reloaded.cfg);
}

/// Resolve each VRF's `import` / `export` route-maps to compiled filters, keyed by the
/// VRF's kernel table (so they can be looked up by a route's table). An unknown filter
/// name fails startup.
fn build_vrf_routemaps(
    cfg: &wren_config::Config,
    by_name: &std::collections::HashMap<String, Filter>,
) -> Result<(
    std::collections::HashMap<u32, Filter>,
    std::collections::HashMap<u32, Filter>,
)> {
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
            anyhow::bail!(
                "vrf {:?}: table {} is used by more than one vrf",
                v.name,
                v.table
            );
        }
        let rd = match &v.rd {
            Some(s) => Some(
                RouteDistinguisher::parse(s)
                    .with_context(|| {
                        format!("vrf {:?}: invalid route distinguisher {s:?}", v.name)
                    })?
                    .to_string(),
            ),
            None => None,
        };
        out.push(router::VrfInfo {
            name: v.name.clone(),
            table: v.table,
            rd,
        });
    }
    Ok(out)
}

fn bfd_auth_config(bfd: Option<&wren_config::Bfd>) -> Result<Option<wren_bfd::AuthConfig>> {
    let Some(bfd) = bfd else { return Ok(None) };
    resolve_bfd_auth(
        bfd.auth_type.as_deref(),
        bfd.auth_key_id,
        bfd.auth_key.as_deref(),
    )
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
        // TCP-MD5 (RFC 2385) and TCP-AO (RFC 5925) apply to both IPv4 and IPv6 transport
        // (A8-rest): the key is installed on the session socket with the peer's own
        // address family, so it flows through for any neighbour regardless of family.
        let (password, ao_key) = (n.password.clone(), n.ao_key.clone());
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
        // BGP Role (RFC 9234 §4): the local speaker's role toward this neighbour.
        let role = match n.role.as_deref() {
            Some(s) => Some(parse_bgp_role(s).with_context(|| {
                format!("bgp neighbor {addr} role {s:?}")
            })?),
            None => None,
        };
        // ebgp-multihop (raised session TTL) and ttl-security (GTSM) drive the TTL in
        // opposite directions, so a neighbour may configure at most one (RFC 5082).
        if n.ttl_security.is_some() && n.ebgp_multihop.is_some() {
            anyhow::bail!(
                "bgp neighbor {addr} cannot set both ttl-security (GTSM) and ebgp-multihop"
            );
        }
        if let Some(ttl) = n.ebgp_multihop {
            if ttl == 0 {
                anyhow::bail!("bgp neighbor {addr} ebgp-multihop must be 1..=255");
            }
        }
        // update-source: bind the dialled connection to this local address. Its family
        // must match the neighbour's transport address (a v4 neighbour needs a v4 source).
        let update_source = match &n.update_source {
            Some(s) => {
                let src: std::net::IpAddr = s
                    .parse()
                    .with_context(|| format!("bgp neighbor {addr} update-source {s:?} must be an IP address"))?;
                if src.is_ipv4() != addr.is_ipv4() {
                    anyhow::bail!(
                        "bgp neighbor {addr} update-source {s:?} address family must match the neighbour's"
                    );
                }
                Some(src)
            }
            None => None,
        };
        // local-as: a full per-session AS override. It must be non-zero; keeping it equal
        // to the global local-as is harmless (the session behaves as an ordinary one).
        if let Some(0) = n.local_as {
            anyhow::bail!("bgp neighbor {addr} local-as must be non-zero");
        }
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
            evpn: n.evpn,
            flowspec: n.flowspec,
            srpolicy: n.srpolicy,
            link_state: n.link_state,
            import,
            export,
            role,
            local_as: n.local_as,
            update_source,
            ebgp_multihop: n.ebgp_multihop,
            description: n.description.clone(),
            shutdown: n.shutdown,
            hold_time: n.hold_time,
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
        aggregates.push(bgp::Aggregate {
            prefix,
            summary_only: agg.summary_only,
        });
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
        roas.push(wren_bgp::rpki::Roa {
            prefix,
            max_length,
            origin_as: r.origin_as,
        });
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
        communities.push(wren_bgp::community::parse_community(c).with_context(|| {
            format!("bgp community {c:?} must be asn:value or a well-known name")
        })?);
    }
    let large_communities =
        parse_large_communities(&bgp.large_community).context("bgp large-community")?;
    let ext_communities = parse_ext_communities(&bgp.ext_community).context("bgp ext-community")?;

    // Confederation (RFC 5065): the Confederation Identifier presented externally,
    // and the Member-AS numbers of the other sub-ASes (confed-eBGP peers).
    if bgp.confederation_id.is_some() && bgp.confederation_members.is_empty() {
        warn!("bgp `confederation-id` set but `confederation-members` is empty; every differing remote-as is treated as a true external peer");
    }

    let (vrf_table, vrf_device) = match &bgp.vrf {
        Some(name) => (
            cfg.vrf_table(name)
                .with_context(|| format!("bgp references unknown vrf {name:?}"))?,
            Some(name.clone()),
        ),
        None => (wren_core::RT_TABLE_MAIN, None),
    };
    // EVPN (RFC 7432): resolve the VTEP identity and each instance's RD / RTs / static
    // MACs. Absent when `[bgp.evpn]` is not configured.
    let evpn = match &bgp.evpn {
        Some(e) => Some(build_evpn_config(e, bgp.local_as, router_id)?),
        None => None,
    };
    if evpn.is_some() && !bgp.neighbor.iter().any(|n| n.evpn) {
        warn!("bgp `[bgp.evpn]` is configured but no neighbor has `evpn = true`; no peer will carry EVPN");
    }
    // FlowSpec (RFC 8955): resolve each `[[bgp.flowspec.rule]]` into a flow spec plus
    // its action. Absent when `[bgp.flowspec]` is not configured.
    let flowspec = match &bgp.flowspec {
        Some(f) => Some(build_flowspec_config(f)?),
        None => None,
    };
    if flowspec.is_some() && !bgp.neighbor.iter().any(|n| n.flowspec) {
        warn!("bgp `[bgp.flowspec]` is configured but no neighbor has `flowspec = true`; no peer will carry FlowSpec");
    }
    // SR Policy (RFC 9256, SAFI 73): resolve each `[[bgp.srpolicy]]` into an NLRI plus
    // its Tunnel Encapsulation contents.
    let mut srpolicy_originate = Vec::with_capacity(bgp.srpolicy.len());
    for p in &bgp.srpolicy {
        srpolicy_originate.push(build_srpolicy(p)?);
    }
    if !srpolicy_originate.is_empty() && !bgp.neighbor.iter().any(|n| n.srpolicy) {
        warn!("bgp `[[bgp.srpolicy]]` is configured but no neighbor has `srpolicy = true`; no peer will carry SR Policy");
    }
    // BGP-LS (RFC 7752, SAFI 71): resolve each static `[[bgp.link-state]]` object into
    // its Link-State NLRI plus BGP-LS attribute.
    let mut link_state_originate = Vec::with_capacity(bgp.link_state.len());
    for o in &bgp.link_state {
        link_state_originate.push(build_link_state(o)?);
    }
    if !link_state_originate.is_empty() && !bgp.neighbor.iter().any(|n| n.link_state) {
        warn!("bgp `[[bgp.link-state]]` is configured but no neighbor has `link-state = true`; no peer will carry BGP-LS");
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
        ebgp_require_policy: bgp.ebgp_require_policy,
        vrf_table,
        vrf_device,
        evpn,
        flowspec,
        srpolicy_originate,
        link_state_originate,
    })
}

/// Resolve one `[[bgp.srpolicy]]` into an SR Policy NLRI plus its Tunnel
/// Encapsulation contents (RFC 9256). A segment / binding-SID that parses as an
/// IPv6 address is an SRv6 SID; a bare integer is an MPLS label.
fn build_srpolicy(
    p: &wren_config::BgpSrPolicy,
) -> Result<(
    wren_bgp::sr_policy::SrPolicyNlri,
    wren_bgp::sr_policy::SrPolicyEncoding,
)> {
    use wren_bgp::sr_policy::{
        BindingSid, Segment, SegmentList, SrPolicyEncoding, SrPolicyNlri,
    };
    let endpoint: std::net::IpAddr = p
        .endpoint
        .parse()
        .with_context(|| format!("bgp srpolicy endpoint {:?} must be an IP address", p.endpoint))?;
    let nlri = SrPolicyNlri {
        color: p.color,
        endpoint,
        distinguisher: p.distinguisher.unwrap_or(1),
    };
    let binding_sid = match &p.binding_sid {
        Some(s) => parse_sid_or_label(s)
            .with_context(|| format!("bgp srpolicy binding-sid {s:?}"))
            .map(|seg| match seg {
                Segment::Srv6Sid { sid, .. } => BindingSid::Srv6Sid(sid),
                Segment::MplsLabel(l) => BindingSid::MplsLabel(l),
            })?,
        None => BindingSid::None,
    };
    let mut segments = Vec::with_capacity(p.segment_list.len());
    for s in &p.segment_list {
        segments.push(parse_sid_or_label(s).with_context(|| format!("bgp srpolicy segment {s:?}"))?);
    }
    let encoding = SrPolicyEncoding {
        preference: p.preference,
        binding_sid,
        priority: p.priority,
        policy_name: p.name.clone(),
        segment_lists: if segments.is_empty() {
            vec![]
        } else {
            vec![SegmentList {
                weight: p.weight,
                segments,
            }]
        },
    };
    Ok((nlri, encoding))
}

/// Parse an SR Policy segment / binding SID: an IPv6 address is an SRv6 SID; a bare
/// integer is an MPLS label (RFC 9256).
fn parse_sid_or_label(s: &str) -> Result<wren_bgp::sr_policy::Segment> {
    use wren_bgp::sr_policy::Segment;
    if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        return Ok(Segment::Srv6Sid {
            sid: v6.octets(),
            behavior: None,
            structure: None,
        });
    }
    if let Ok(label) = s.parse::<u32>() {
        return Ok(Segment::MplsLabel(label));
    }
    anyhow::bail!("{s:?} is neither an IPv6 SRv6 SID nor an MPLS label")
}

/// Resolve one static `[[bgp.link-state]]` object into a BGP-LS NLRI plus its
/// attribute (RFC 7752): a Node, Link or Prefix with the given descriptors and
/// attributes. Node identity uses the OSPF 4-octet IGP Router-ID.
fn build_link_state(
    o: &wren_config::BgpLinkState,
) -> Result<(
    wren_bgp::link_state::LinkStateNlri,
    wren_bgp::link_state::BgpLsAttribute,
)> {
    use wren_bgp::link_state::{
        BgpLsAttribute, LinkStateNlri, LsObjectKind, LsTlv, ATTR_ADMIN_GROUP, ATTR_IGP_METRIC,
        ATTR_NODE_NAME, SUBTLV_AUTONOMOUS_SYSTEM, SUBTLV_IGP_ROUTER_ID, TLV_IP_REACHABILITY,
        TLV_LOCAL_NODE_DESCRIPTORS, TLV_REMOTE_NODE_DESCRIPTORS,
    };
    // The IGP the object is attributed to (RFC 7752 §3.2 Protocol-IDs).
    let protocol = match o.protocol.as_deref().unwrap_or("ospf") {
        "isis-l1" => 1,
        "isis-l2" => 2,
        "ospf" | "ospfv2" => 3,
        "direct" => 4,
        "static" => 5,
        "ospfv3" => 6,
        other => anyhow::bail!("bgp link-state protocol {other:?} is unknown"),
    };
    let router_id: Ipv4Addr = o
        .router_id
        .parse()
        .with_context(|| format!("bgp link-state router-id {:?} must be a dotted quad", o.router_id))?;
    // Build a Node Descriptors TLV (256 local / 257 remote) from an IGP Router-ID and
    // optional AS.
    let node_descriptors = |rid: Ipv4Addr, as_num: Option<u32>, typ: u16| -> LsTlv {
        let mut sub = Vec::new();
        if let Some(asn) = as_num {
            LsTlv {
                typ: SUBTLV_AUTONOMOUS_SYSTEM,
                value: asn.to_be_bytes().to_vec(),
            }
            .encode(&mut sub);
        }
        LsTlv {
            typ: SUBTLV_IGP_ROUTER_ID,
            value: rid.octets().to_vec(),
        }
        .encode(&mut sub);
        LsTlv { typ, value: sub }
    };

    let mut descriptors = vec![node_descriptors(
        router_id,
        o.autonomous_system,
        TLV_LOCAL_NODE_DESCRIPTORS,
    )];
    let kind = match o.kind.as_str() {
        "node" => LsObjectKind::Node,
        "link" => {
            let remote: Ipv4Addr = o
                .remote_router_id
                .as_deref()
                .context("bgp link-state link needs a `remote-router-id`")?
                .parse()
                .context("bgp link-state remote-router-id must be a dotted quad")?;
            descriptors.push(node_descriptors(remote, None, TLV_REMOTE_NODE_DESCRIPTORS));
            // Link descriptors: IPv4 interface (259) / neighbor (260) addresses.
            if let Some(a) = &o.local_interface {
                let ip: Ipv4Addr = a.parse().context("bgp link-state local-interface")?;
                descriptors.push(LsTlv { typ: 259, value: ip.octets().to_vec() });
            }
            if let Some(a) = &o.remote_interface {
                let ip: Ipv4Addr = a.parse().context("bgp link-state remote-interface")?;
                descriptors.push(LsTlv { typ: 260, value: ip.octets().to_vec() });
            }
            LsObjectKind::Link
        }
        "prefix" | "ipv4-prefix" => {
            let p: wren_core::Prefix = o
                .prefix
                .as_deref()
                .context("bgp link-state prefix needs a `prefix`")?
                .parse()
                .context("bgp link-state prefix must be addr/len")?;
            // IP Reachability (265): prefix-length then the significant prefix octets.
            let octet_len = p.len().div_ceil(8) as usize;
            let bytes: Vec<u8> = match p.addr() {
                std::net::IpAddr::V4(a) => a.octets()[..octet_len].to_vec(),
                std::net::IpAddr::V6(a) => a.octets()[..octet_len].to_vec(),
            };
            let mut value = vec![p.len()];
            value.extend_from_slice(&bytes);
            descriptors.push(LsTlv { typ: TLV_IP_REACHABILITY, value });
            if p.addr().is_ipv6() {
                LsObjectKind::Ipv6Prefix
            } else {
                LsObjectKind::Ipv4Prefix
            }
        }
        other => anyhow::bail!("bgp link-state type {other:?} must be node, link or prefix"),
    };

    // The attribute TLVs relevant to the object.
    let mut tlvs = Vec::new();
    if let Some(name) = &o.name {
        tlvs.push(LsTlv {
            typ: ATTR_NODE_NAME,
            value: name.as_bytes().to_vec(),
        });
    }
    if let Some(m) = o.igp_metric {
        // 3-octet IGP metric (RFC 7752 §3.3.2.3).
        tlvs.push(LsTlv {
            typ: ATTR_IGP_METRIC,
            value: m.to_be_bytes()[1..4].to_vec(),
        });
    }
    if let Some(ag) = o.admin_group {
        tlvs.push(LsTlv {
            typ: ATTR_ADMIN_GROUP,
            value: ag.to_be_bytes().to_vec(),
        });
    }

    let nlri = LinkStateNlri {
        kind,
        protocol,
        identifier: 0,
        descriptors,
    };
    Ok((nlri, BgpLsAttribute::new(tlvs)))
}

/// Resolve `[bgp.evpn]` into a [`bgp::EvpnConfig`]: parse the VTEP IP, and for each
/// instance the Route Distinguisher (defaulting to `router-id:evi`), the import and
/// export Route Targets (defaulting both to the auto-derived `rt:<local-as>:<vni>`
/// when neither is set, RFC 7432 §7.10.1), and the static MACs to advertise.
fn build_evpn_config(
    e: &wren_config::BgpEvpn,
    local_as: u32,
    router_id: Ipv4Addr,
) -> Result<bgp::EvpnConfig> {
    let vtep_ip: IpAddr = e
        .vtep_ip
        .parse()
        .with_context(|| format!("bgp evpn vtep-ip {:?} must be an IP address", e.vtep_ip))?;
    // The auto-derived Route Target is a 2-octet-AS community, so an AS above 65535
    // cannot be represented — warn where a default RT would be relied on.
    if local_as > u16::MAX as u32
        && e.instance
            .iter()
            .any(|i| i.rt_import.is_empty() && i.rt_export.is_empty())
    {
        warn!(
            "bgp local-as {local_as} exceeds 65535; the auto-derived 2-octet EVPN Route Target truncates it — set explicit rt-import/rt-export"
        );
    }
    let mut instances = Vec::with_capacity(e.instance.len());
    for inst in &e.instance {
        let rd = match &inst.rd {
            Some(s) => parse_rd(s).with_context(|| {
                format!(
                    "bgp evpn instance {} rd {s:?} must be ip:value or asn:value",
                    inst.evi
                )
            })?,
            None => wren_bgp::evpn::Rd::from_ip(router_id, inst.evi),
        };
        let mut rt_import = Vec::with_capacity(inst.rt_import.len());
        for s in &inst.rt_import {
            rt_import.push(
                wren_bgp::ext_community::parse_ext_community(s).with_context(|| {
                    format!(
                        "bgp evpn instance {} rt-import {s:?} must be rt:asn:value",
                        inst.evi
                    )
                })?,
            );
        }
        let mut rt_export = Vec::with_capacity(inst.rt_export.len());
        for s in &inst.rt_export {
            rt_export.push(
                wren_bgp::ext_community::parse_ext_community(s).with_context(|| {
                    format!(
                        "bgp evpn instance {} rt-export {s:?} must be rt:asn:value",
                        inst.evi
                    )
                })?,
            );
        }
        // Default BOTH directions to the auto-derived rt:<local-as>:<vni> only when
        // neither was set (RFC 7432 §7.10.1).
        if rt_import.is_empty() && rt_export.is_empty() {
            let auto = wren_bgp::evpn_rib::auto_route_target(local_as as u16, inst.vni);
            rt_import.push(auto);
            rt_export.push(auto);
        }
        let mut macs = Vec::with_capacity(inst.advertise_mac.len());
        for s in &inst.advertise_mac {
            macs.push(
                parse_mac_ip(s)
                    .with_context(|| format!("bgp evpn instance {} advertise-mac", inst.evi))?,
            );
        }
        instances.push(bgp::EvpnInstanceCfg {
            evi: inst.evi,
            vni: inst.vni,
            rd,
            rt_import,
            rt_export,
            macs,
        });
    }
    // The tenant IP-VRFs (RFC 9136). Same RD/RT resolution as an instance, but keyed
    // on the L3 VNI — an IP-VRF's Route Targets are its own, so the auto-derived
    // fallback must use `l3-vni`, never an instance's L2 VNI.
    let mut ip_vrfs = Vec::with_capacity(e.ip_vrf.len());
    for v in &e.ip_vrf {
        let rd = match &v.rd {
            Some(s) => parse_rd(s).with_context(|| {
                format!(
                    "bgp evpn ip-vrf {} rd {s:?} must be ip:value or asn:value",
                    v.name
                )
            })?,
            // An EVI derives its RD from the 16-bit `evi`; an IP-VRF has no such
            // field, so the L3 VNI supplies the assigned number — truncated to the
            // 2 octets the type-1 RD allows, which is why an explicit `rd` is the
            // right answer for a VNI above 65535.
            None => wren_bgp::evpn::Rd::from_ip(router_id, v.l3_vni as u16),
        };
        let mut rt_import = Vec::with_capacity(v.rt_import.len());
        for s in &v.rt_import {
            rt_import.push(
                wren_bgp::ext_community::parse_ext_community(s)
                    .with_context(|| format!("bgp evpn ip-vrf {} rt-import {s:?}", v.name))?,
            );
        }
        let mut rt_export = Vec::with_capacity(v.rt_export.len());
        for s in &v.rt_export {
            rt_export.push(
                wren_bgp::ext_community::parse_ext_community(s)
                    .with_context(|| format!("bgp evpn ip-vrf {} rt-export {s:?}", v.name))?,
            );
        }
        if rt_import.is_empty() && rt_export.is_empty() {
            let auto = wren_bgp::evpn_rib::auto_route_target(local_as as u16, v.l3_vni);
            rt_import.push(auto);
            rt_export.push(auto);
        }
        ip_vrfs.push(bgp::IpVrfCfg {
            name: v.name.clone(),
            l3_vni: v.l3_vni,
            rd,
            rt_import,
            rt_export,
        });
    }

    // Optional SRv6 locator (RFC 9252): "addr/len", byte-aligned, length 8..=96.
    let srv6_locator = match &e.srv6_locator {
        None => None,
        Some(s) => {
            let (addr_s, len_s) = s
                .split_once('/')
                .with_context(|| format!("bgp evpn srv6-locator {s:?} must be addr/len"))?;
            let addr: std::net::Ipv6Addr = addr_s.parse().with_context(|| {
                format!("bgp evpn srv6-locator {s:?} address must be an IPv6 address")
            })?;
            let len: u8 = len_s
                .parse()
                .with_context(|| format!("bgp evpn srv6-locator {s:?} length must be a number"))?;
            if len % 8 != 0 || !(8..=96).contains(&len) {
                anyhow::bail!(
                    "bgp evpn srv6-locator {s:?}: must be a byte-aligned IPv6 prefix with length 8..=96"
                );
            }
            Some((addr, len))
        }
    };
    Ok(bgp::EvpnConfig {
        vtep_ip,
        srv6_locator,
        instances,
        ip_vrfs,
    })
}

/// Resolve `[bgp.flowspec]` into a [`bgp::FlowSpecConfig`]: for each rule, assemble
/// the match components (dest/source prefix, protocol, ports) into a FlowSpec NLRI
/// and parse its traffic-filtering action (RFC 8955 §4 + §7). A rule with no match
/// component is rejected — it would match all traffic. IPv4 (AFI 1) only for now.
fn build_flowspec_config(f: &wren_config::BgpFlowSpec) -> Result<bgp::FlowSpecConfig> {
    use wren_bgp::flowspec::{Component, FlowSpec};
    use wren_bgp::flowspec_rib::FlowSpecNlri;

    let mut rules = Vec::with_capacity(f.rule.len());
    for (i, r) in f.rule.iter().enumerate() {
        let mut components = Vec::new();
        if let Some(d) = &r.dest {
            let p: wren_core::Prefix = d
                .parse()
                .with_context(|| format!("bgp flowspec rule {i} dest {d:?} must be addr/len"))?;
            if !p.is_ipv4() {
                anyhow::bail!("bgp flowspec rule {i} dest {d:?}: only IPv4 flow rules are supported");
            }
            components.push(Component::DestPrefix(p));
        }
        if let Some(s) = &r.source {
            let p: wren_core::Prefix = s
                .parse()
                .with_context(|| format!("bgp flowspec rule {i} source {s:?} must be addr/len"))?;
            if !p.is_ipv4() {
                anyhow::bail!(
                    "bgp flowspec rule {i} source {s:?}: only IPv4 flow rules are supported"
                );
            }
            components.push(Component::SrcPrefix(p));
        }
        if !r.protocol.is_empty() {
            components.push(Component::IpProto(flowspec_num_ops(&r.protocol)));
        }
        if !r.port.is_empty() {
            components.push(Component::Port(flowspec_num_ops(&r.port)));
        }
        if !r.dest_port.is_empty() {
            components.push(Component::DestPort(flowspec_num_ops(&r.dest_port)));
        }
        if !r.source_port.is_empty() {
            components.push(Component::SrcPort(flowspec_num_ops(&r.source_port)));
        }
        if components.is_empty() {
            anyhow::bail!(
                "bgp flowspec rule {i} has no match component; it would match all traffic"
            );
        }
        let action = parse_flowspec_action(r.action.as_deref())
            .with_context(|| format!("bgp flowspec rule {i} action"))?;
        rules.push(bgp::FlowSpecRuleCfg {
            nlri: FlowSpecNlri::v4(FlowSpec { components }),
            action,
        });
    }
    Ok(bgp::FlowSpecConfig { rules })
}

/// A list of port/protocol values as OR-joined `= value` FlowSpec numeric ops.
fn flowspec_num_ops(values: &[u16]) -> Vec<wren_bgp::flowspec::NumOp> {
    values
        .iter()
        .map(|&v| wren_bgp::flowspec::NumOp::eq(v as u64))
        .collect()
}

/// Parse a FlowSpec action string (RFC 8955 §7): `"discard"` / `"drop"`,
/// `"rate-limit:<bytes-per-second>"` (a float; `0` is discard) or `"mark:<dscp>"`.
/// `None` defaults to discard.
fn parse_flowspec_action(s: Option<&str>) -> Result<wren_bgp::flowspec::Action> {
    use wren_bgp::flowspec::Action;
    let s = s.unwrap_or("discard").trim();
    if s.eq_ignore_ascii_case("discard") || s.eq_ignore_ascii_case("drop") {
        return Ok(Action::DISCARD);
    }
    if let Some(rate) = s.strip_prefix("rate-limit:") {
        let bytes: f32 = rate
            .trim()
            .parse()
            .with_context(|| format!("rate-limit rate {rate:?} must be a number (bytes/s)"))?;
        return Ok(Action::RateLimit(bytes));
    }
    if let Some(dscp) = s.strip_prefix("mark:") {
        let d: u8 = dscp
            .trim()
            .parse()
            .with_context(|| format!("mark dscp {dscp:?} must be a number 0..=63"))?;
        if d > 63 {
            anyhow::bail!("mark dscp {d} must be 0..=63");
        }
        return Ok(Action::Marking(d));
    }
    anyhow::bail!("unknown action {s:?}; expected discard | rate-limit:<bytes/s> | mark:<dscp>")
}

/// Parse an EVPN Route Distinguisher: `ip:value` (a type-1 `router-id:value` RD) or
/// `asn:value` (a type-0 2-octet-AS RD), per RFC 4364 §4.2.
fn parse_rd(s: &str) -> Result<wren_bgp::evpn::Rd> {
    let (admin, value) = s
        .split_once(':')
        .context("expected ip:value or asn:value")?;
    if let Ok(ip) = admin.parse::<Ipv4Addr>() {
        let v: u16 = value
            .parse()
            .context("rd value must be a 16-bit number for an ip:value rd")?;
        return Ok(wren_bgp::evpn::Rd::from_ip(ip, v));
    }
    let asn: u16 = admin
        .parse()
        .context("rd admin must be an IPv4 address or a 16-bit AS")?;
    let v: u32 = value
        .parse()
        .context("rd value must be a 32-bit number for an asn:value rd")?;
    Ok(wren_bgp::evpn::Rd::from_as2(asn, v))
}

/// Parse an EVPN `advertise-mac` entry: `aa:bb:cc:dd:ee:ff` or
/// `aa:bb:cc:dd:ee:ff/10.0.0.5` (the optional IP feeds remote ARP/ND suppression).
fn parse_mac_ip(s: &str) -> Result<([u8; 6], Option<IpAddr>)> {
    let (mac_str, ip) = match s.split_once('/') {
        Some((m, i)) => (
            m,
            Some(
                i.parse::<IpAddr>()
                    .with_context(|| format!("mac ip {i:?} must be an IP address"))?,
            ),
        ),
        None => (s, None),
    };
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("mac {mac_str:?} must be six colon-separated hex octets");
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16)
            .with_context(|| format!("mac octet {p:?} must be a hex byte"))?;
    }
    Ok((mac, ip))
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
            format!(
                "{} redistribute {name:?} is not a known protocol",
                protocol.name()
            )
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

/// Resolve the `[multicast]` config into the IGMP runner's [`igmp::QuerierConfig`],
/// sorting the interfaces by role (querier / proxy upstream / proxy downstream).
/// RFC 4605 allows a single upstream interface, so more than one is rejected.
#[cfg(feature = "igmp")]
fn build_querier_config(mc: &wren_config::Multicast) -> Result<igmp::QuerierConfig> {
    use wren_config::MulticastRole;
    let mut querier_interfaces = Vec::new();
    let mut downstream = Vec::new();
    let mut upstream = None;
    for i in &mc.interfaces {
        match i.role {
            MulticastRole::Querier => querier_interfaces.push(i.name.clone()),
            MulticastRole::Downstream => downstream.push(i.name.clone()),
            MulticastRole::Upstream => {
                if upstream.replace(i.name.clone()).is_some() {
                    anyhow::bail!("multicast: only one upstream interface is supported (RFC 4605)");
                }
            }
        }
    }
    if querier_interfaces.is_empty() && downstream.is_empty() && upstream.is_none() {
        anyhow::bail!("[multicast] is enabled but no interfaces are configured");
    }
    Ok(igmp::QuerierConfig {
        querier_interfaces,
        upstream,
        downstream,
        robustness: mc.robustness.unwrap_or(2),
        query_interval: std::time::Duration::from_secs(mc.query_interval.unwrap_or(125) as u64),
        query_response_interval: std::time::Duration::from_secs(
            mc.query_response_interval.unwrap_or(10) as u64,
        ),
        igmp_version: mc.igmp_version.unwrap_or(3),
        // Wired by the caller when PIM-SM is enabled (see the multicast spawn block).
        pim_feed: None,
    })
}

/// Resolve the `[multicast.pim]` config into the PIM-SM runner's [`pim::PimConfig`].
/// The RP address is required; the interfaces default to every multicast interface if
/// none are listed explicitly.
#[cfg(feature = "pim")]
fn build_pim_config(mc: &wren_config::Multicast) -> Result<pim::PimConfig> {
    let p = mc
        .pim
        .as_ref()
        .filter(|p| p.enabled)
        .ok_or_else(|| anyhow::anyhow!("[multicast.pim] not enabled"))?;
    let rp = p
        .rp_address
        .ok_or_else(|| anyhow::anyhow!("[multicast.pim] requires rp-address (static RP)"))?;
    let interfaces = if p.interfaces.is_empty() {
        mc.interfaces.iter().map(|i| i.name.clone()).collect()
    } else {
        p.interfaces.clone()
    };
    if interfaces.is_empty() {
        anyhow::bail!("[multicast.pim] has no interfaces");
    }
    Ok(pim::PimConfig {
        interfaces,
        rp,
        hello_interval: std::time::Duration::from_secs(
            p.hello_interval.unwrap_or(wren_pim::DEFAULT_HELLO_PERIOD_SECS) as u64,
        ),
    })
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

    let vrf_table = match &babel.vrf {
        Some(name) => cfg
            .vrf_table(name)
            .with_context(|| format!("babel references unknown vrf {name:?}"))?,
        None => wren_core::RT_TABLE_MAIN,
    };
    Ok(babel::BabelConfig {
        router_id: babel::router_id_from_ipv4(router_id_v4),
        interfaces: babel.interfaces.clone(),
        originate,
        redistribute_metric: babel.redistribute_metric.unwrap_or(0),
        bfd: babel.bfd,
        vrf_table,
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
    let vrf_table = match &isis.vrf {
        Some(name) => cfg
            .vrf_table(name)
            .with_context(|| format!("isis references unknown vrf {name:?}"))?,
        None => wren_core::RT_TABLE_MAIN,
    };
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
        leak_l2_to_l1: isis.l2_to_l1_leaking,
        bfd: isis.bfd,
        vrf_table,
        auth: build_isis_auth(isis)?,
    })
}

/// Resolve the `[isis]` authentication config into the runner's [`IsisAuth`]:
/// `"text"` is the cleartext password of ISO 10589 §9.8, `"hmac-sha256"` the
/// Generic Cryptographic Authentication of RFC 5310, which signs the encoded PDU
/// instead of putting the secret on the wire. The older `password` key stays valid
/// as a shorthand for `auth-type = "text"`.
#[cfg(feature = "isis")]
fn build_isis_auth(isis: &wren_config::Isis) -> Result<Option<wren_isis::auth::IsisAuth>> {
    use wren_isis::auth::IsisAuth;
    let key = |ty: &str| -> Result<Vec<u8>> {
        let key = isis
            .auth_key
            .as_deref()
            .or(isis.password.as_deref())
            .filter(|k| !k.is_empty())
            .with_context(|| format!("isis auth-type {ty:?} requires a non-empty auth-key"))?;
        Ok(key.as_bytes().to_vec())
    };
    match isis.auth_type.as_deref() {
        // Unset falls back to the older `password` key, so existing configs keep
        // working unchanged.
        None => Ok(isis
            .password
            .clone()
            .filter(|p| !p.is_empty())
            .map(|p| IsisAuth::Cleartext(p.into_bytes()))),
        Some("none") => Ok(None),
        Some("text") => Ok(Some(IsisAuth::Cleartext(key("text")?))),
        Some("hmac-md5") => Ok(Some(IsisAuth::HmacMd5 {
            key: key("hmac-md5")?,
        })),
        Some("hmac-sha256") => Ok(Some(IsisAuth::HmacSha256 {
            key: key("hmac-sha256")?,
            key_id: isis.auth_key_id.unwrap_or(1),
        })),
        Some(other) => anyhow::bail!(
            "unknown isis auth-type {other:?} (want none, text, hmac-md5 or hmac-sha256)"
        ),
    }
}

/// Resolve the `[[vrrp]]` definitions into the VRRP runner's instance configs,
/// parsing the virtual addresses and validating the VRID, priority and interval.
#[cfg(feature = "vrrp")]
fn build_vrrp_instances(cfg: &wren_config::Config) -> Result<Vec<vrrp::InstanceConfig>> {
    let mut out = Vec::new();
    for def in &cfg.vrrp {
        if def.vrid == 0 {
            anyhow::bail!("vrrp on {:?}: vrid must be 1–255", def.interface);
        }
        if def.priority == 0 {
            anyhow::bail!("vrrp vrid {}: priority must be 1–255", def.vrid);
        }
        if def.virtual_addresses.is_empty() {
            anyhow::bail!(
                "vrrp vrid {}: at least one virtual-address is required",
                def.vrid
            );
        }
        let mut addresses = Vec::new();
        for a in &def.virtual_addresses {
            let ip: std::net::IpAddr = a.parse().with_context(|| {
                format!(
                    "vrrp vrid {}: virtual-address {a:?} is not an IP address",
                    def.vrid
                )
            })?;
            addresses.push(ip);
        }
        // Every virtual address of one router must be of the same family.
        let ipv6 = addresses[0].is_ipv6();
        if addresses.iter().any(|a| a.is_ipv6() != ipv6) {
            anyhow::bail!(
                "vrrp vrid {}: virtual-addresses mix IPv4 and IPv6",
                def.vrid
            );
        }
        let prefix_len = def.prefix_length.unwrap_or(if ipv6 { 64 } else { 24 });
        // Round the interval to centiseconds, clamped to the 12-bit wire field.
        let advert_int_cs = (def.advert_interval_ms / 10).clamp(1, 0x0fff) as u16;
        out.push(vrrp::InstanceConfig {
            interface: def.interface.clone(),
            vrid: def.vrid,
            priority: def.priority,
            advert_int_cs,
            preempt: def.preempt,
            addresses,
            prefix_len,
            track_interfaces: def.track_interfaces.clone(),
            priority_decrement: def.priority_decrement,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    /// Resolve a `[bgp]` block from TOML through [`build_bgp_config`] with no named
    /// filters, returning the resolved config (or the resolution error).
    fn resolve_bgp(toml: &str) -> Result<bgp::BgpConfig> {
        let cfg = wren_config::Config::from_toml(toml).expect("valid toml");
        let bgp = cfg.bgp.clone().expect("bgp present");
        let by_name = std::collections::HashMap::new();
        build_bgp_config(&cfg, &bgp, &by_name)
    }

    #[test]
    fn bgp_neighbor_session_options_resolve() {
        let resolved = resolve_bgp(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            local-as = 65099
            update-source = "10.0.0.9"
            ebgp-multihop = 5
            description = "transit"
            shutdown = true
            hold-time = 30
            "#,
        )
        .expect("resolves");
        let p = &resolved.peers[0];
        assert_eq!(p.local_as, Some(65099));
        assert_eq!(p.update_source, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))));
        assert_eq!(p.ebgp_multihop, Some(5));
        assert_eq!(p.description.as_deref(), Some("transit"));
        assert!(p.shutdown);
        assert_eq!(p.hold_time, Some(30));
    }

    #[test]
    fn bgp_ttl_security_and_ebgp_multihop_are_mutually_exclusive() {
        // Configuring GTSM and multihop on one neighbour is rejected (RFC 5082 practice).
        let err = resolve_bgp(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            ttl-security = 1
            ebgp-multihop = 4
            "#,
        )
        .err().expect("must reject both");
        assert!(err.to_string().contains("ttl-security"));
        assert!(err.to_string().contains("ebgp-multihop"));
    }

    #[test]
    fn bgp_update_source_family_must_match_neighbor() {
        // An IPv6 update-source on an IPv4 neighbour is a configuration error.
        let err = resolve_bgp(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            update-source = "2001:db8::9"
            "#,
        )
        .err().expect("family mismatch rejected");
        assert!(err.to_string().contains("address family"));
    }

    #[test]
    fn bgp_local_as_must_be_non_zero() {
        let err = resolve_bgp(
            r#"
            router-id = "10.0.0.1"
            [bgp]
            enabled = true
            local-as = 65001
            [[bgp.neighbor]]
            address = "10.0.0.2"
            remote-as = 65002
            local-as = 0
            "#,
        )
        .err().expect("zero local-as rejected");
        assert!(err.to_string().contains("local-as"));
    }

    #[test]
    fn parse_mac_ip_without_ip() {
        let (mac, ip) = parse_mac_ip("02:00:5e:10:00:01").unwrap();
        assert_eq!(mac, [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);
        assert_eq!(ip, None);
    }

    #[test]
    fn parse_mac_ip_with_v4_and_v6() {
        let (mac, ip) = parse_mac_ip("aa:bb:cc:dd:ee:ff/10.0.0.5").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));

        let (_, ip6) = parse_mac_ip("aa:bb:cc:dd:ee:ff/2001:db8::5").unwrap();
        assert_eq!(
            ip6,
            Some(IpAddr::V6("2001:db8::5".parse::<Ipv6Addr>().unwrap()))
        );
    }

    #[test]
    fn parse_mac_ip_rejects_malformed() {
        assert!(parse_mac_ip("02:00:5e:10:00").is_err()); // too few octets
        assert!(parse_mac_ip("02:00:5e:10:00:01:02").is_err()); // too many octets
        assert!(parse_mac_ip("zz:00:5e:10:00:01").is_err()); // non-hex octet
        assert!(parse_mac_ip("02:00:5e:10:00:01/not-an-ip").is_err()); // bad ip
    }

    #[test]
    fn parse_rd_ip_and_asn_forms() {
        // ip:value → type-1 RD.
        let rd = parse_rd("192.0.2.1:100").unwrap();
        assert_eq!(rd.to_string(), "192.0.2.1:100");
        // asn:value → type-0 RD.
        let rd = parse_rd("65001:10100").unwrap();
        assert_eq!(rd.to_string(), "65001:10100");
    }

    #[test]
    fn parse_rd_rejects_malformed() {
        assert!(parse_rd("no-colon").is_err());
        assert!(parse_rd("192.0.2.1:99999999").is_err()); // value too big for ip:value
        assert!(parse_rd("70000:10").is_err()); // admin not a 16-bit AS or ip
    }
}
