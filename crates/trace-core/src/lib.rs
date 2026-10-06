//! Identity, clock, and provider plumbing shared by the instrumentation facades.
//!
//! `moq-trace` and `quic-trace` describe different lifecycles, but they agree on
//! three things: one process-wide identifier space, one host clock, and one
//! backend seam. This crate owns those three so that neither facade can drift
//! from the other. Nothing here describes a MoQ or QUIC lifecycle; the schemas
//! live in the facades.
//!
//! With the `lttng` feature, identifiers and time come from the native provider
//! library, which the C++ facade calls too. The QUIC provider hosts them because
//! MoQ tracing layers over QUIC tracing in both languages.

mod backend;
mod clock;
mod ids;
mod wire;

pub use backend::{Backend, Schema, Tracepoint};
pub use clock::now_ns;
pub use ids::{next_connection_id, next_span_id, next_trace_id};
pub use wire::{PhaseEdge, encode_optional};
