//! Typed, scoped tracing for QUIC packets, STREAM frames, and UDP socket operations.

#[cfg(all(feature = "lttng", not(target_os = "linux")))]
compile_error!("the lttng feature is supported only on Linux");

use std::sync::OnceLock;

use trace_core::PhaseEdge;
pub use trace_core::{next_connection_id, next_span_id, next_trace_id, now_ns};

mod backend;

mod packet;
pub use packet::{
    PacketContext, PacketOutcome, PacketPhase, PacketPhaseTrace, PacketTrace, StreamFrame,
};

mod socket;
pub use socket::{SocketCall, SocketOutcome, SocketStats, SocketTrace};

mod blocked;
pub use blocked::{SendBlockedReason, SendBlockedTrace};

mod path;
pub use path::ConnectionPath;

mod send;
pub use send::PendingSend;

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

impl Handle {
    /// Create a handle that never emits events.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Return whether any transport event would be recorded now.
    ///
    /// A stack that captures timestamps of its own before it knows which
    /// lifecycle they belong to, such as the completion of a receive system
    /// call, checks this first so an untraced build reads no clock.
    pub fn is_enabled(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.any_enabled(&backend::ALL_TRACEPOINTS))
    }

    /// Read the clock only when any transport event would be recorded now.
    ///
    /// A stack stamps an instant it may later attach to a lifecycle, such as
    /// the return of a system call made outside [`Handle::socket_call`], with
    /// this, so an untraced build reads no clock.
    pub fn now_ns_if_enabled(&self) -> Option<u64> {
        let inner = self.inner.as_ref()?;
        inner
            .any_enabled(&backend::ALL_TRACEPOINTS)
            .then(|| inner.now_ns())
    }
}

static GLOBAL: OnceLock<backend::Backend> = OnceLock::new();

/// Return the process-global transport trace handle.
pub fn global() -> Handle {
    if !backend::available() {
        return Handle::disabled();
    }
    Handle {
        inner: Some(GLOBAL.get_or_init(backend::Backend::native)),
    }
}

#[cfg(test)]
mod tests;
