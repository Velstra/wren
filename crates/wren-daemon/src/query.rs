//! The generic control-socket query request shared by every protocol task.
//!
//! Each protocol exposes a small `Query` enum (what `show <proto> …` can ask) and
//! owns an `mpsc::Receiver<QueryRequest<ItsQuery>>`; it answers by sending rendered
//! text on the request's `respond` channel. The control socket builds these requests
//! through [`OwnedQuery`] so its send/await/fallback logic lives once (in
//! `control::ask`/`ask_opt`) instead of a near-identical helper per protocol.

use tokio::sync::oneshot;

/// A typed query paired with the oneshot channel the owning task answers it on.
pub struct QueryRequest<Q> {
    /// What is being asked.
    pub query: Q,
    /// Where to send the rendered text answer.
    pub respond: oneshot::Sender<String>,
}

/// Lets the control socket's generic `ask`/`ask_opt` build any protocol's request
/// from a query and a responder without naming the concrete type. Implemented once,
/// generically, for [`QueryRequest<Q>`] — so a new `show` consumer needs no plumbing
/// here, only its own `Query` enum and an `mpsc::Receiver<QueryRequest<ItsQuery>>`.
pub trait OwnedQuery: Send + 'static {
    /// The query enum this request carries.
    type Query: Send;
    /// Build the request from a query and the responder the task replies on.
    fn build(query: Self::Query, respond: oneshot::Sender<String>) -> Self;
}

impl<Q: Send + 'static> OwnedQuery for QueryRequest<Q> {
    type Query = Q;
    fn build(query: Q, respond: oneshot::Sender<String>) -> Self {
        QueryRequest { query, respond }
    }
}
