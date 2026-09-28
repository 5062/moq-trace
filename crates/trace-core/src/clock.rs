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

#[cfg(not(all(feature = "lttng", target_os = "linux")))]
mod source {
    use std::sync::OnceLock;

    pub(super) fn now_ns() -> u64 {
        #[cfg(unix)]
        {
            let mut value = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
            if result == 0 {
                let seconds = u64::try_from(value.tv_sec).unwrap_or(0);
                let nanos = u64::try_from(value.tv_nsec).unwrap_or(0);
                return seconds.saturating_mul(1_000_000_000).saturating_add(nanos);
            }
        }
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}
