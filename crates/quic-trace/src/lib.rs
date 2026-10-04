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
pub use socket::{SocketOutcome, SocketStats, SocketTrace};

mod path;
pub use path::ConnectionPath;

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
}

static GLOBAL: OnceLock<backend::Backend> = OnceLock::new();

/// Return the process-global transport trace handle.
pub fn global() -> Handle {
    if !backend::available() {
        return Handle::disabled();
    }
    Handle {
        inner: Some(backend::Handle::shared(
            GLOBAL.get_or_init(backend::Backend::native),
        )),
    }
}

#[cfg(test)]
mod tests;
