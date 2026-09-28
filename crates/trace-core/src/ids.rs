//! Process-wide identifier allocation shared by the facades.
//!
//! With the `lttng` feature the counters live in the native provider library,
//! which the C++ facade also calls, so Rust and C++ hooks in one process never
//! hand out the same identifier. Without it, no provider is linked and nothing
//! can be emitted, so Rust keeps counters of its own for the recording backend.

/// Allocate a process-wide trace identifier shared by every facade.
///
/// Identifiers are process-local. One capture can hold several processes, and
/// the analysis pairs providers by object and transport metadata rather than by
/// assuming an identifier from one provider is present in the other.
#[inline]
pub fn next_trace_id() -> u64 {
    source::next_trace_id()
}

/// Allocate a process-wide phase span identifier shared by every facade.
///
/// Span identifiers come from their own counter, so a trace identifier and a
/// span identifier never collide by construction.
#[inline]
pub fn next_span_id() -> u64 {
    source::next_span_id()
}

/// Allocate a process-wide transport connection identifier.
///
/// A transport assigns one when a connection is created and stamps it on every
/// packet, socket, and object event for that connection. The counter never
/// reuses a value, so the analysis can join frames to objects by connection ID
/// without bounding the join in time. An address-derived ID such as Quinn's
/// `stable_id` does not have that property, because the allocator can hand the
/// address to a later connection once the first one is freed.
#[inline]
pub fn next_connection_id() -> u64 {
    source::next_connection_id()
}

#[cfg(all(feature = "lttng", target_os = "linux"))]
mod source {
    use quic_trace_lttng_sys as ffi;

    pub(super) fn next_trace_id() -> u64 {
        unsafe { ffi::quic_trace_next_trace_id() }
    }

    pub(super) fn next_span_id() -> u64 {
        unsafe { ffi::quic_trace_next_span_id() }
    }

    pub(super) fn next_connection_id() -> u64 {
        unsafe { ffi::quic_trace_next_connection_id() }
    }
}

#[cfg(not(all(feature = "lttng", target_os = "linux")))]
mod source {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TRACE_ID: AtomicU64 = AtomicU64::new(1);
    static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);
    static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

    pub(super) fn next_trace_id() -> u64 {
        NEXT_TRACE_ID.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn next_span_id() -> u64 {
        NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn next_connection_id() -> u64 {
        NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
    }
}
