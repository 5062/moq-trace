//! The monotonic clock shared by the facades.

/// Return a monotonic timestamp in nanoseconds from the host clock.
///
/// With the `lttng` feature this reads the clock through the native provider
/// library, the same function the C++ facade calls, so events emitted by Rust
/// and C++ code in one relay share one timestamp epoch. Without it nothing is
/// emitted, so no epoch needs to match and time counts from the first read.
#[inline]
pub fn now_ns() -> u64 {
    source::now_ns()
}

#[cfg(all(feature = "lttng", target_os = "linux"))]
mod source {
    pub(super) fn now_ns() -> u64 {
        unsafe { quic_trace_lttng_sys::quic_trace_now_ns() }
    }
}

#[cfg(not(all(feature = "lttng", target_os = "linux")))]
mod source {
    use std::sync::OnceLock;
    use std::time::Instant;

    pub(super) fn now_ns() -> u64 {
        static START: OnceLock<Instant> = OnceLock::new();
        START
            .get_or_init(Instant::now)
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}
