//! The monotonic clock shared by the facades.

/// Return a monotonic timestamp in nanoseconds from the host clock.
///
/// With the `lttng` feature this reads the clock through the native provider
/// library, the same function the C++ facade calls, so events emitted by Rust
/// and C++ code in one relay share one timestamp epoch. Without it, Rust reads
/// `CLOCK_MONOTONIC` itself, which is the same epoch on Unix.
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

#[cfg(all(not(all(feature = "lttng", target_os = "linux")), unix))]
mod source {
    pub(super) fn now_ns() -> u64 {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // CLOCK_MONOTONIC cannot fail given a valid pointer, as the provider
        // library's clock also assumes.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
        let seconds = u64::try_from(value.tv_sec).unwrap_or(0);
        let nanos = u64::try_from(value.tv_nsec).unwrap_or(0);
        seconds.saturating_mul(1_000_000_000).saturating_add(nanos)
    }
}

/// Off Unix there is no `CLOCK_MONOTONIC` to share, and no provider to share it
/// with, so time counts from the first read.
#[cfg(not(unix))]
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
