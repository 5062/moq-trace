//! Process-wide identifier allocation shared by the facades.

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TRACE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a process-wide trace identifier shared by every facade.
///
/// Identifiers are process-local. One capture can hold several processes, and
/// the analysis pairs providers by object and transport metadata rather than by
/// assuming an identifier from one provider is present in the other.
pub fn next_trace_id() -> u64 {
    NEXT_TRACE_ID.fetch_add(1, Ordering::Relaxed)
}

/// Allocate a process-wide phase span identifier shared by every facade.
///
/// Span identifiers come from their own counter, so a trace identifier and a
/// span identifier never collide by construction.
pub fn next_span_id() -> u64 {
    NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed)
}

/// Allocate a process-wide transport connection identifier.
///
/// A transport assigns one when a connection is created and stamps it on every
/// packet, socket, and object event for that connection. The counter never
/// reuses a value, so the analysis can join frames to objects by connection ID
/// without bounding the join in time. An address-derived ID such as Quinn's
/// `stable_id` does not have that property, because the allocator can hand the
/// address to a later connection once the first one is freed.
pub fn next_connection_id() -> u64 {
    NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
}
