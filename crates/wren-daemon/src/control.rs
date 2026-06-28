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

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::babel::{BabelQuery, BabelQueryRequest};
use crate::bgp::{BgpQuery, BgpQueryRequest};
use crate::isis::{IsisQuery, IsisQueryRequest};
use crate::ospf::{OspfQuery, OspfQueryRequest};
use crate::ospf3::{Ospf3Query, Ospf3QueryRequest};
use crate::rip::{RipQuery, RipQueryRequest};
use crate::router::{Query, QueryRequest};

/// The query channels the control socket forwards to. Every per-protocol channel
/// is `None` when that protocol is not configured, so `show <proto>` can report
/// that instead of hanging.
#[derive(Clone)]
pub struct Channels {
    /// To the central router loop (`show routes`).
    pub router: mpsc::Sender<QueryRequest>,
    /// To the BGP task (`show bgp`), if BGP is running.
    pub bgp: Option<mpsc::Sender<BgpQueryRequest>>,
    /// To the OSPF task (`show ospf`), if OSPF is running.
    pub ospf: Option<mpsc::Sender<OspfQueryRequest>>,
    /// To the OSPFv3 task (`show ospf3`), if OSPFv3 is running.
    pub ospf3: Option<mpsc::Sender<Ospf3QueryRequest>>,
    /// To the IS-IS task (`show isis`), if IS-IS is running.
    pub isis: Option<mpsc::Sender<IsisQueryRequest>>,
    /// To the Babel task (`show babel`), if Babel is running.
    pub babel: Option<mpsc::Sender<BabelQueryRequest>>,
    /// To the RIP task (`show rip`), if RIPv2 is running.
    pub rip: Option<mpsc::Sender<RipQueryRequest>>,
    /// To the RIPng task (`show ripng`), if RIPng is running.
    pub ripng: Option<mpsc::Sender<RipQueryRequest>>,
}

/// A per-protocol query channel's request type: it pairs a typed query with the
/// oneshot the owning task answers on. Implementing this for each protocol's
/// `*QueryRequest` lets the control socket's send/await/fallback logic live once
/// in the generic [`ask`] / [`ask_opt`], instead of a near-identical `ask_*` per
/// protocol.
trait OwnedQuery: Send + 'static {
    /// The query enum this request carries.
    type Query: Send;
    /// Build the request from a query and the responder the task replies on.
    fn build(query: Self::Query, respond: oneshot::Sender<String>) -> Self;
}

impl OwnedQuery for QueryRequest {
    type Query = Query;
    fn build(query: Query, respond: oneshot::Sender<String>) -> Self {
        QueryRequest { query, respond }
    }
}
impl OwnedQuery for BgpQueryRequest {
    type Query = BgpQuery;
    fn build(query: BgpQuery, respond: oneshot::Sender<String>) -> Self {
        BgpQueryRequest { query, respond }
    }
}
impl OwnedQuery for OspfQueryRequest {
    type Query = OspfQuery;
    fn build(query: OspfQuery, respond: oneshot::Sender<String>) -> Self {
        OspfQueryRequest { query, respond }
    }
}
impl OwnedQuery for Ospf3QueryRequest {
    type Query = Ospf3Query;
    fn build(query: Ospf3Query, respond: oneshot::Sender<String>) -> Self {
        Ospf3QueryRequest { query, respond }
    }
}
impl OwnedQuery for IsisQueryRequest {
    type Query = IsisQuery;
    fn build(query: IsisQuery, respond: oneshot::Sender<String>) -> Self {
        IsisQueryRequest { query, respond }
    }
}
impl OwnedQuery for BabelQueryRequest {
    type Query = BabelQuery;
    fn build(query: BabelQuery, respond: oneshot::Sender<String>) -> Self {
        BabelQueryRequest { query, respond }
    }
}
impl OwnedQuery for RipQueryRequest {
    type Query = RipQuery;
    fn build(query: RipQuery, respond: oneshot::Sender<String>) -> Self {
        RipQueryRequest { query, respond }
    }
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
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("reading command")?;
    let line = line.trim();

    let response = if let Some(query) = parse_bgp_query(line) {
        ask_opt(&channels.bgp, query, "bgp").await
    } else if let Some(query) = parse_ospf3_query(line) {
        ask_opt(&channels.ospf3, query, "ospf3").await
    } else if let Some(query) = parse_ospf_query(line) {
        ask_opt(&channels.ospf, query, "ospf").await
    } else if let Some(query) = parse_isis_query(line) {
        ask_opt(&channels.isis, query, "isis").await
    } else if let Some(query) = parse_babel_query(line) {
        ask_opt(&channels.babel, query, "babel").await
    } else if let Some(query) = parse_rip_query(line, "ripng") {
        ask_opt(&channels.ripng, query, "ripng").await
    } else if let Some(query) = parse_rip_query(line, "rip") {
        ask_opt(&channels.rip, query, "rip").await
    } else if let Some(query) = parse_query(line) {
        ask(&channels.router, query, "router").await
    } else {
        format!(
            "error: unknown command {line:?}\n\
             usage: show routes [protocol] | show bgp [routes|neighbors] | \
             show ospf [neighbors|interfaces] | show ospf3 [neighbors|interfaces] | \
             show isis [neighbors|interfaces] | show babel [neighbors|routes] | \
             show rip | show ripng\n"
        )
    };

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
            _ => None,
        },
        _ => None,
    }
}

/// Parse a `show bgp [routes|neighbors]` command into a [`BgpQuery`]. A bare
/// `show bgp` defaults to the routes view. Returns `None` for anything else (so
/// the caller can fall through to the router queries).
pub fn parse_bgp_query(line: &str) -> Option<BgpQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "bgp" {
        return None;
    }
    let query = match tokens.next() {
        None | Some("routes") | Some("route") => BgpQuery::Routes,
        Some("neighbors") | Some("neighbours") | Some("summary") => BgpQuery::Neighbors,
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
pub fn parse_ospf_query(line: &str) -> Option<OspfQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "ospf" {
        return None;
    }
    let query = match tokens.next() {
        None | Some("neighbors") | Some("neighbours") => OspfQuery::Neighbors,
        Some("interfaces") | Some("interface") | Some("iface") => OspfQuery::Interfaces,
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

/// Parse a `show isis [neighbors|interfaces]` command into an [`IsisQuery`]. A
/// bare `show isis` defaults to the adjacencies view. Returns `None` for anything
/// else (so the caller can fall through to the other query parsers).
pub fn parse_isis_query(line: &str) -> Option<IsisQuery> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "show" || tokens.next()? != "isis" {
        return None;
    }
    let query = match tokens.next() {
        None | Some("neighbors") | Some("neighbours") | Some("adjacencies") => {
            IsisQuery::Neighbors
        }
        Some("interfaces") | Some("interface") | Some("iface") => IsisQuery::Interfaces,
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
        assert_eq!(parse_bgp_query("show bgp neighbors"), Some(BgpQuery::Neighbors));
        assert_eq!(parse_bgp_query("show bgp summary"), Some(BgpQuery::Neighbors));
    }

    #[test]
    fn parse_bgp_query_rejects_others() {
        assert!(parse_bgp_query("show routes").is_none()); // router query, not bgp
        assert!(parse_bgp_query("show bgp nonsense").is_none());
        assert!(parse_bgp_query("show bgp routes extra").is_none());
        assert!(parse_bgp_query("").is_none());
    }

    #[test]
    fn parse_ospf_query_understands_show_ospf() {
        assert_eq!(parse_ospf_query("show ospf"), Some(OspfQuery::Neighbors));
        assert_eq!(parse_ospf_query("show ospf neighbors"), Some(OspfQuery::Neighbors));
        assert_eq!(
            parse_ospf_query("show ospf interfaces"),
            Some(OspfQuery::Interfaces)
        );
        assert_eq!(parse_ospf_query("show ospf iface"), Some(OspfQuery::Interfaces));
    }

    #[test]
    fn parse_ospf_query_rejects_others() {
        assert!(parse_ospf_query("show bgp").is_none()); // bgp query, not ospf
        assert!(parse_ospf_query("show ospf nonsense").is_none());
        assert!(parse_ospf_query("show ospf neighbors extra").is_none());
        assert!(parse_ospf_query("").is_none());
    }

    #[test]
    fn parse_ospf3_query_understands_show_ospf3() {
        assert_eq!(parse_ospf3_query("show ospf3"), Some(Ospf3Query::Neighbors));
        assert_eq!(parse_ospf3_query("show ospf3 neighbors"), Some(Ospf3Query::Neighbors));
        assert_eq!(
            parse_ospf3_query("show ospf3 interfaces"),
            Some(Ospf3Query::Interfaces)
        );
        assert_eq!(parse_ospf3_query("show ospf3 iface"), Some(Ospf3Query::Interfaces));
    }

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

    #[test]
    fn parse_isis_query_understands_show_isis() {
        assert_eq!(parse_isis_query("show isis"), Some(IsisQuery::Neighbors));
        assert_eq!(parse_isis_query("show isis neighbors"), Some(IsisQuery::Neighbors));
        assert_eq!(
            parse_isis_query("show isis adjacencies"),
            Some(IsisQuery::Neighbors)
        );
        assert_eq!(
            parse_isis_query("show isis interfaces"),
            Some(IsisQuery::Interfaces)
        );
    }

    #[test]
    fn parse_isis_query_rejects_others() {
        assert!(parse_isis_query("show ospf").is_none()); // ospf query, not isis
        assert!(parse_isis_query("show isis nonsense").is_none());
        assert!(parse_isis_query("show isis neighbors extra").is_none());
        assert!(parse_isis_query("").is_none());
    }

    #[test]
    fn parse_babel_query_understands_show_babel() {
        assert_eq!(parse_babel_query("show babel"), Some(BabelQuery::Neighbors));
        assert_eq!(parse_babel_query("show babel neighbors"), Some(BabelQuery::Neighbors));
        assert_eq!(parse_babel_query("show babel neighbours"), Some(BabelQuery::Neighbors));
        assert_eq!(parse_babel_query("show babel routes"), Some(BabelQuery::Routes));
    }

    #[test]
    fn parse_babel_query_rejects_others() {
        assert!(parse_babel_query("show isis").is_none()); // isis query, not babel
        assert!(parse_babel_query("show babel nonsense").is_none());
        assert!(parse_babel_query("show babel neighbors extra").is_none());
        assert!(parse_babel_query("").is_none());
    }

    #[test]
    fn parse_rip_query_understands_show_rip_and_ripng() {
        assert_eq!(parse_rip_query("show rip", "rip"), Some(RipQuery::Routes));
        assert_eq!(parse_rip_query("show rip routes", "rip"), Some(RipQuery::Routes));
        assert_eq!(parse_rip_query("show ripng", "ripng"), Some(RipQuery::Routes));
        assert_eq!(parse_rip_query("show ripng route", "ripng"), Some(RipQuery::Routes));
    }

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
}
