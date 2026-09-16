//! The monotonic clock shared by the facades.

use std::sync::OnceLock;

/// Return a monotonic timestamp in nanoseconds from the host clock.
///
/// `CLOCK_MONOTONIC` is shared with the C++ facade, so events emitted by Rust
/// and C++ code in one relay use the same timestamp epoch.
pub fn now_ns() -> u64 {
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
