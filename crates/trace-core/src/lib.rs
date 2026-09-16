//! Identity, clock, and provider plumbing shared by the instrumentation facades.
//!
//! `moq-trace` and `quic-trace` describe different lifecycles, but they agree on
//! three things: one process-wide identifier space, one host clock, and one
//! backend seam. This crate owns those three so that neither facade can drift
//! from the other. Nothing here describes a MoQ or QUIC lifecycle; the schemas
//! live in the facades.

mod backend;
mod clock;
mod ids;

pub use backend::{Backend, Handle, Schema, Tracepoint};
pub use clock::now_ns;
pub use ids::{next_span_id, next_trace_id};
