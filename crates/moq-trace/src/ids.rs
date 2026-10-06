//! Process-wide MoQ identifier allocation shared with the C++ facade.
//!
//! With the `lttng` feature the counters live in the native MoQ provider
//! library, which the C++ facade also calls, so Rust and C++ hooks in one
//! process never hand out the same session or logical group. Without it, no
//! provider is linked and nothing can be emitted, so Rust keeps counters of its
//! own.

/// Allocate a process-wide session identifier shared by every facade.
#[inline]
pub fn next_session_id() -> u64 {
    source::next_session_id()
}

/// Allocate a process-wide logical group instance.
///
/// The analysis pairs an ingress object with its outbound copies by logical
/// identity, so a group must never be reused within a process. Allocating it
/// here rather than inventing one keeps it unique across Rust and C++ hooks. A
/// relay pairs this with a frame ordinal through [`crate::LogicalId::new`].
#[inline]
pub fn next_logical_group() -> u64 {
    source::next_logical_group()
}

#[cfg(all(feature = "lttng", target_os = "linux"))]
mod source {
    use moq_trace_lttng_sys as ffi;

    pub(super) fn next_session_id() -> u64 {
        unsafe { ffi::moq_trace_next_session_id() }
    }

    pub(super) fn next_logical_group() -> u64 {
        unsafe { ffi::moq_trace_next_logical_group() }
    }
}

#[cfg(not(all(feature = "lttng", target_os = "linux")))]
mod source {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
    static NEXT_LOGICAL_GROUP: AtomicU64 = AtomicU64::new(1);

    pub(super) fn next_session_id() -> u64 {
        NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)
    }

    pub(super) fn next_logical_group() -> u64 {
        NEXT_LOGICAL_GROUP.fetch_add(1, Ordering::Relaxed)
    }
}
