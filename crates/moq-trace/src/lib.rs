//! MoQ object tracing layered over the shared QUIC transport tracing toolkit.

#[cfg(all(feature = "lttng", not(target_os = "linux")))]
compile_error!("the lttng feature is supported only on Linux");

use std::sync::OnceLock;

pub use quic_trace::{
    ConnectionPath, Direction, PacketContext, PacketOutcome, PacketPhase, PacketPhaseTrace,
    PacketSpace, PacketTrace, SendBlockedReason, SendBlockedTrace, SocketOutcome, SocketStats,
    SocketTrace, StreamFrame, next_connection_id,
};
pub use trace_core::now_ns;

mod backend;

mod ids;
pub use ids::{next_logical_group, next_session_id};

mod object;
pub use object::{
    LogicalId, ObjectContext, ObjectIdentity, ObjectOutcome, ObjectPhase, ObjectPhaseTrace,
    ObjectTrace, TransportCall, transport_call,
};

use trace_core::PhaseEdge;

/// A cheap cloneable handle for MoQ and transport instrumentation sites.
#[derive(Clone, Default)]
pub struct Handle {
    inner: Option<backend::Handle>,
    transport: quic_trace::Handle,
    session_id: Option<u64>,
    connection_id: Option<u64>,
}

impl Handle {
    /// Create a handle that never emits events.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Return a clone that stamps object events with this session ID.
    ///
    /// Prefer [`next_session_id`] as the source, so the ID stays unique across
    /// Rust and C++ hooks in one process.
    pub fn with_session_id(mut self, session_id: u64) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Return a clone that stamps object events with this transport connection ID.
    pub fn with_connection_id(mut self, connection_id: u64) -> Self {
        self.connection_id = Some(connection_id);
        self
    }

    /// Start a QUIC packet trace through the shared transport toolkit.
    pub fn packet(&self, context: PacketContext) -> PacketTrace {
        self.transport.packet(context)
    }

    /// Start a UDP socket trace through the shared transport toolkit.
    pub fn socket(&self, direction: Direction, connection_id: Option<u64>) -> SocketTrace {
        self.transport.socket(direction, connection_id)
    }

    /// Record a connection's path through the shared transport toolkit.
    pub fn connection_path(&self, connection_id: u64, path: ConnectionPath) {
        self.transport.connection_path(connection_id, path);
    }

    /// Start an interval in which a connection cannot send, through the shared
    /// transport toolkit.
    pub fn send_blocked(
        &self,
        connection_id: u64,
        reason: SendBlockedReason,
        stream_id: Option<u64>,
    ) -> SendBlockedTrace {
        self.transport
            .send_blocked(connection_id, reason, stream_id)
    }
}

static GLOBAL: OnceLock<backend::Backend> = OnceLock::new();

/// Return the process-global handle shared by MoQ and transport hooks.
///
/// The object and transport providers are separate LTTng providers, so this
/// reaches each one through its own facade. Object events carry the same
/// process-wide trace identifiers the transport facade allocates.
pub fn global() -> Handle {
    let transport = quic_trace::global();
    let inner = backend::available().then(|| GLOBAL.get_or_init(backend::Backend::native));
    Handle {
        inner,
        transport,
        session_id: None,
        connection_id: None,
    }
}

#[cfg(test)]
mod tests;
