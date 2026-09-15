//! MoQ object tracing layered over the shared QUIC transport tracing toolkit.

#[cfg(all(feature = "lttng", not(target_os = "linux")))]
compile_error!("the lttng feature is supported only on Linux");

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

pub use quic_trace::{
    Direction, PacketContext, PacketOutcome, PacketPhase, PacketPhaseTrace, PacketSpace,
    PacketTrace, SocketOutcome, SocketStats, SocketTrace, StreamFrame,
};

mod backend;

mod object;
pub use object::{
    LogicalId, ObjectContext, ObjectIdentity, ObjectOutcome, ObjectPhase, ObjectPhaseTrace,
    ObjectTrace,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhaseEdge {
    Start,
    Done,
}

/// A cheap cloneable handle for MoQ and transport instrumentation sites.
#[derive(Clone, Default)]
pub struct Handle {
    inner: Option<backend::Handle>,
    transport: quic_trace::Handle,
    session_id: Option<u64>,
    connection_id: Option<u64>,
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

fn next_span_id() -> u64 {
    #[cfg(test)]
    SPAN_IDS.with(|ids| ids.set(ids.get() + 1));
    quic_trace::next_span_id()
}

impl Handle {
    #[cfg(test)]
    fn new() -> Self {
        Self {
            inner: Some(backend::Handle::owned(backend::Backend::new())),
            transport: quic_trace::Handle::disabled(),
            session_id: None,
            connection_id: None,
        }
    }

    /// Create a handle that never emits events.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Return a clone that stamps object events with this process-local session ID.
    pub fn with_session_id(mut self, session_id: u64) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Return a clone that stamps object events with this transport connection ID.
    pub fn with_connection_id(mut self, connection_id: u64) -> Self {
        self.connection_id = Some(connection_id);
        self
    }

    /// Return a clone that stamps object events with the next process-local session ID.
    pub fn with_new_session_id(mut self) -> Self {
        self.session_id = Some(NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed));
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
}

static GLOBAL: OnceLock<backend::Backend> = OnceLock::new();

/// Return the process-global handle shared by MoQ and transport hooks.
pub fn global() -> Handle {
    let transport = quic_trace::global();
    let inner = backend::available()
        .then(|| backend::Handle::shared(GLOBAL.get_or_init(backend::Backend::new)));
    Handle {
        inner,
        transport,
        session_id: None,
        connection_id: None,
    }
}

/// Return the transport toolkit's process-relative monotonic timestamp in nanoseconds.
pub fn now_ns() -> u64 {
    #[cfg(test)]
    CLOCK_READS.with(|reads| reads.set(reads.get() + 1));
    quic_trace::now_ns()
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
