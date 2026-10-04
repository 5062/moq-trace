use crate::backend::{Event, Tracepoint};
use crate::{Direction, Handle};

/// Result of one UDP socket operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SocketOutcome {
    /// The socket operation completed successfully.
    Success,
    /// The socket was not ready and registered a wakeup.
    Pending,
    /// The socket reported that the operation would block.
    WouldBlock,
    /// The socket reported a connection reset.
    ConnectionReset,
    /// The socket operation failed with another error.
    Error,
    /// The trace token was dropped before an outcome was recorded.
    Abandoned,
}

/// Batch measurements returned by one UDP socket operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SocketStats {
    /// Number of buffers processed by the operation.
    pub buffers: usize,
    /// Number of UDP datagrams represented by those buffers.
    pub datagrams: usize,
    /// Total number of bytes represented by those buffers.
    pub bytes: usize,
}

impl SocketStats {
    /// Create socket batch measurements.
    pub fn new(buffers: usize, datagrams: usize, bytes: usize) -> Self {
        Self {
            buffers,
            datagrams,
            bytes,
        }
    }
}

/// The tracepoints a socket trace token covers.
const SOCKET_TRACEPOINTS: [Tracepoint; 2] = [Tracepoint::SocketStart, Tracepoint::SocketEnd];

/// A UDP socket operation whose completion consumes the token.
pub struct SocketTrace {
    state: Option<SocketTraceState>,
}

struct SocketTraceState {
    backend: crate::backend::Handle,
    trace_id: u64,
}

impl Handle {
    /// Start a UDP socket operation.
    pub fn socket(&self, direction: Direction, connection_id: Option<u64>) -> SocketTrace {
        let Some(inner) = self.inner.as_ref() else {
            return SocketTrace::disabled();
        };
        if !inner.any_enabled(&SOCKET_TRACEPOINTS) {
            return SocketTrace::disabled();
        }
        let trace_id = inner.next_trace_id();
        inner.emit(Event::SocketStart {
            timestamp_ns: inner.now_ns(),
            trace_id,
            direction,
            connection_id,
        });
        SocketTrace {
            state: Some(SocketTraceState {
                backend: inner.clone(),
                trace_id,
            }),
        }
    }
}

impl SocketTrace {
    fn disabled() -> Self {
        Self { state: None }
    }

    /// Finish the socket operation with its result and batch measurements.
    pub fn finish(mut self, outcome: SocketOutcome, stats: SocketStats) {
        if let Some(state) = self.state.take() {
            state.emit_end(outcome, stats, None);
        }
    }

    /// Finish the socket operation at a previously captured timestamp.
    ///
    /// A provider reads the clock immediately after the system call returns
    /// and ends both this operation and the packets it carried at that
    /// instant, so the socket event and the packets agree exactly.
    pub fn finish_at(mut self, outcome: SocketOutcome, stats: SocketStats, timestamp_ns: u64) {
        if let Some(state) = self.state.take() {
            state.emit_end(outcome, stats, Some(timestamp_ns));
        }
    }
}

impl SocketTraceState {
    fn emit_end(self, outcome: SocketOutcome, stats: SocketStats, timestamp_ns: Option<u64>) {
        let Self { backend, trace_id } = self;
        backend.emit(Event::SocketEnd {
            timestamp_ns: timestamp_ns.unwrap_or_else(|| backend.now_ns()),
            trace_id,
            outcome,
            stats,
        });
    }
}

impl Drop for SocketTrace {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.emit_end(SocketOutcome::Abandoned, SocketStats::default(), None);
        }
    }
}
