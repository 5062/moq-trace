use crate::{Direction, Handle, now_ns};

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
        if !inner.socket_enabled() {
            return SocketTrace::disabled();
        }
        let trace_id = crate::NEXT_TRACE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        inner.socket_start(now_ns(), trace_id, direction, connection_id);
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
            state.emit_end(outcome, stats);
        }
    }
}

impl SocketTraceState {
    fn emit_end(self, outcome: SocketOutcome, stats: SocketStats) {
        self.backend
            .socket_end(now_ns(), self.trace_id, outcome, stats);
    }
}

impl Drop for SocketTrace {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.emit_end(SocketOutcome::Abandoned, SocketStats::default());
        }
    }
}
