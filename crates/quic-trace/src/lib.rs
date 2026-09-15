//! Typed, scoped tracing for QUIC packets, STREAM frames, and UDP socket operations.

#[cfg(all(feature = "lttng", not(target_os = "linux")))]
compile_error!("the lttng feature is supported only on Linux");

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

mod backend;

mod packet;
use packet::PhaseEdge;
pub use packet::{
    PacketContext, PacketOutcome, PacketPhase, PacketPhaseTrace, PacketTrace, StreamFrame,
};

mod socket;
pub use socket::{SocketOutcome, SocketStats, SocketTrace};

/// Event direction at the local transport interface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Direction {
    /// Event was observed while receiving from a peer.
    Rx,
    /// Event was observed while transmitting to a peer.
    Tx,
}

/// QUIC packet number space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketSpace {
    /// QUIC Initial packet space.
    Initial,
    /// QUIC Handshake packet space.
    Handshake,
    /// QUIC 0-RTT packet space.
    ZeroRtt,
    /// QUIC 1-RTT application data packet space.
    Data,
}

/// A cheap cloneable handle used by transport instrumentation sites.
#[derive(Clone, Default)]
pub struct Handle {
    inner: Option<backend::Handle>,
}

static NEXT_TRACE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);

fn next_span_id() -> u64 {
    #[cfg(test)]
    SPAN_IDS.with(|ids| ids.set(ids.get() + 1));
    NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed)
}

impl Handle {
    #[cfg(test)]
    fn new() -> Self {
        Self {
            inner: Some(backend::Handle::owned(backend::Backend::new())),
        }
    }

    /// Create a handle that never emits events.
    pub fn disabled() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn events(&self) -> Vec<backend::Event> {
        self.inner
            .as_ref()
            .map(|inner| inner.events())
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn enable_only(&self, tracepoint: backend::Tracepoint) {
        if let Some(inner) = &self.inner {
            inner.enable_only(tracepoint);
        }
    }

    #[cfg(test)]
    fn set_enabled(&self, tracepoint: backend::Tracepoint, enabled: bool) {
        if let Some(inner) = &self.inner {
            inner.set_enabled(tracepoint, enabled);
        }
    }
}

static GLOBAL: OnceLock<backend::Backend> = OnceLock::new();

/// Return the process-global transport trace handle.
pub fn global() -> Handle {
    if !backend::available() {
        return Handle::disabled();
    }
    Handle {
        inner: Some(backend::Handle::shared(
            GLOBAL.get_or_init(backend::Backend::new),
        )),
    }
}

/// Return a process-relative monotonic timestamp in nanoseconds.
pub fn now_ns() -> u64 {
    #[cfg(test)]
    CLOCK_READS.with(|reads| reads.set(reads.get() + 1));
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
thread_local! {
    static CLOCK_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static SPAN_IDS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_bookkeeping_counts() {
    CLOCK_READS.with(|reads| reads.set(0));
    SPAN_IDS.with(|ids| ids.set(0));
}

#[cfg(test)]
fn clock_reads() -> u64 {
    CLOCK_READS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn span_ids() -> u64 {
    SPAN_IDS.with(std::cell::Cell::get)
}

#[cfg(test)]
mod tests;
