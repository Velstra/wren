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
use crate::router::{Query, QueryRequest};

/// The query channels the control socket forwards to. `bgp` / `ospf` / `isis` are
/// `None` when that protocol is not configured, so `show bgp` / `show ospf` /
/// `show isis` can report that instead of hanging.
#[derive(Clone)]
pub struct Channels {
    /// To the central router loop (`show routes`).
    pub router: mpsc::Sender<QueryRequest>,
    /// To the BGP task (`show bgp`), if BGP is running.
    pub bgp: Option<mpsc::Sender<BgpQueryRequest>>,
    /// To the OSPF task (`show ospf`), if OSPF is running.
    pub ospf: Option<mpsc::Sender<OspfQueryRequest>>,
    /// To the IS-IS task (`show isis`), if IS-IS is running.
    pub isis: Option<mpsc::Sender<IsisQueryRequest>>,
    /// To the Babel task (`show babel`), if Babel is running.
    pub babel: Option<mpsc::Sender<BabelQueryRequest>>,
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
        match &channels.bgp {
            Some(bgp) => ask_bgp(bgp, query).await,
            None => "bgp is not enabled\n".to_string(),
        }
    } else if let Some(query) = parse_ospf_query(line) {
        match &channels.ospf {
            Some(ospf) => ask_ospf(ospf, query).await,
            None => "ospf is not enabled\n".to_string(),
        }
    } else if let Some(query) = parse_isis_query(line) {
        match &channels.isis {
            Some(isis) => ask_isis(isis, query).await,
            None => "isis is not enabled\n".to_string(),
        }
    } else if let Some(query) = parse_babel_query(line) {
        match &channels.babel {
            Some(babel) => ask_babel(babel, query).await,
            None => "babel is not enabled\n".to_string(),
        }
    } else if let Some(query) = parse_query(line) {
        ask_router(&channels.router, query).await
    } else {
        format!(
            "error: unknown command {line:?}\n\
             usage: show routes [protocol] | show bgp [routes|neighbors] | \
             show ospf [neighbors|interfaces] | show isis [neighbors|interfaces] | \
             show babel [neighbors|routes]\n"
        )
    };

    reader
        .get_mut()
        .write_all(response.as_bytes())
        .await
        .context("writing response")?;
    Ok(())
}

/// Forward a router query and await its rendered answer.
async fn ask_router(queries: &mpsc::Sender<QueryRequest>, query: Query) -> String {
    let (tx, rx) = oneshot::channel();
    if queries.send(QueryRequest { query, respond: tx }).await.is_err() {
        return "error: router unavailable\n".to_string();
    }
    rx.await
        .unwrap_or_else(|_| "error: router unavailable\n".to_string())
}

/// Forward a BGP query and await its rendered answer.
async fn ask_bgp(queries: &mpsc::Sender<BgpQueryRequest>, query: BgpQuery) -> String {
    let (tx, rx) = oneshot::channel();
    if queries.send(BgpQueryRequest { query, respond: tx }).await.is_err() {
        return "error: bgp unavailable\n".to_string();
    }
    rx.await
        .unwrap_or_else(|_| "error: bgp unavailable\n".to_string())
}

/// Forward an OSPF query and await its rendered answer.
async fn ask_ospf(queries: &mpsc::Sender<OspfQueryRequest>, query: OspfQuery) -> String {
    let (tx, rx) = oneshot::channel();
    if queries.send(OspfQueryRequest { query, respond: tx }).await.is_err() {
        return "error: ospf unavailable\n".to_string();
    }
    rx.await
        .unwrap_or_else(|_| "error: ospf unavailable\n".to_string())
}

/// Forward an IS-IS query and await its rendered answer.
async fn ask_isis(queries: &mpsc::Sender<IsisQueryRequest>, query: IsisQuery) -> String {
    let (tx, rx) = oneshot::channel();
    if queries.send(IsisQueryRequest { query, respond: tx }).await.is_err() {
        return "error: isis unavailable\n".to_string();
    }
    rx.await
        .unwrap_or_else(|_| "error: isis unavailable\n".to_string())
}

/// Forward a Babel query and await its rendered answer.
async fn ask_babel(queries: &mpsc::Sender<BabelQueryRequest>, query: BabelQuery) -> String {
    let (tx, rx) = oneshot::channel();
    if queries.send(BabelQueryRequest { query, respond: tx }).await.is_err() {
        return "error: babel unavailable\n".to_string();
    }
    rx.await
        .unwrap_or_else(|_| "error: babel unavailable\n".to_string())
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
}
