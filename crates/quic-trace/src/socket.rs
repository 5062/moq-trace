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

impl SocketOutcome {
    /// Describe a completed socket system call from its `errno`, or 0 for success.
    ///
    /// The outcome is the system call's own result, before any error policy of
    /// the stack, so the same kernel result records the same outcome on every
    /// stack. `EAGAIN` and `EWOULDBLOCK` would block and `ECONNRESET` is a reset.
    /// Everything else is an error, `ENOBUFS` included, even where a stack
    /// retries it like `EAGAIN`.
    pub fn from_errno(errno: i32) -> Self {
        if errno == 0 {
            return Self::Success;
        }
        Self::from_io_error(&std::io::Error::from_raw_os_error(errno))
    }

    /// Describe a failed socket system call from the error it returned.
    ///
    /// An error that carries an OS code is classified by that code, the same
    /// way [`SocketOutcome::from_errno`] and the C++ facade's
    /// `quic_trace::socket_outcome` classify it.
    pub fn from_io_error(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::WouldBlock => Self::WouldBlock,
            std::io::ErrorKind::ConnectionReset => Self::ConnectionReset,
            _ => Self::Error,
        }
    }
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

    /// Measure one buffer of `bytes` that GSO or GRO splits into datagrams of
    /// `segment_size`.
    ///
    /// A buffer holds at least one datagram, so one without segmentation, a
    /// segment size of zero, and an empty datagram each count as one. Sum the
    /// measurements of a batch's buffers to describe the whole operation.
    pub fn buffer(bytes: usize, segment_size: Option<usize>) -> Self {
        let datagrams = match segment_size {
            Some(size) if size > 0 => bytes.div_ceil(size).max(1),
            _ => 1,
        };
        Self::new(1, datagrams, bytes)
    }
}

impl std::ops::AddAssign for SocketStats {
    fn add_assign(&mut self, other: Self) {
        self.buffers += other.buffers;
        self.datagrams += other.datagrams;
        self.bytes += other.bytes;
    }
}

impl std::iter::Sum for SocketStats {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |mut total, stats| {
            total += stats;
            total
        })
    }
}

/// The tracepoints a socket trace token covers.
const SOCKET_TRACEPOINTS: [Tracepoint; 2] = [Tracepoint::SocketStart, Tracepoint::SocketEnd];

/// A UDP socket operation whose completion consumes the token.
pub struct SocketTrace(Option<SocketTraceState>);

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
        SocketTrace(Some(SocketTraceState {
            backend: inner,
            trace_id,
        }))
    }
}

impl SocketTrace {
    /// Return a disabled socket trace token.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Finish the socket operation with its result and batch measurements.
    pub fn finish(mut self, outcome: SocketOutcome, stats: SocketStats) {
        if let Some(state) = self.0.take() {
            state.emit_end(outcome, stats, None);
        }
    }

    /// Finish the socket operation at a previously captured timestamp.
    ///
    /// A provider reads the clock immediately after the system call returns
    /// and ends both this operation and the packets it carried at that
    /// instant, so the socket event and the packets agree exactly.
    pub fn finish_at(mut self, outcome: SocketOutcome, stats: SocketStats, timestamp_ns: u64) {
        if let Some(state) = self.0.take() {
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
        if let Some(state) = self.0.take() {
            state.emit_end(SocketOutcome::Abandoned, SocketStats::default(), None);
        }
    }
}

/// One UDP system call, recorded as a socket operation that ends when the call
/// returned.
///
/// A stack starts the call just before the system call, marks
/// [`SocketCall::returned`] right after it, and then finishes with the call's
/// own result, before any error policy of the stack. The returned instant also
/// starts or ends the packets the call carried, so the socket event and those
/// packets agree exactly. When no transport event would be recorded, no clock
/// is read and the call reports no instant.
///
/// Dropping the call unfinished records an abandoned operation.
pub struct SocketCall {
    trace: SocketTrace,
    clock: Option<crate::backend::Handle>,
    returned_ns: Option<u64>,
}

impl Handle {
    /// Start a socket operation for one system call about to be made.
    pub fn socket_call(&self, direction: Direction, connection_id: Option<u64>) -> SocketCall {
        SocketCall {
            trace: self.socket(direction, connection_id),
            clock: self.inner.filter(|_| self.is_enabled()),
            returned_ns: None,
        }
    }
}

impl SocketCall {
    /// Mark that the system call returned, and return that instant.
    ///
    /// Call this immediately after the system call, before any other work, so
    /// the instant is the call's completion. The instant is `None` when no
    /// transport event would be recorded.
    pub fn returned(&mut self) -> Option<u64> {
        if let Some(clock) = self.clock {
            self.returned_ns = Some(clock.now_ns());
        }
        self.returned_ns
    }

    /// Finish a call that succeeded with the buffers it carried.
    pub fn succeeded(self, stats: SocketStats) {
        self.finish(SocketOutcome::Success, stats);
    }

    /// Finish a call that failed with the error it returned.
    ///
    /// The outcome is classified as [`SocketOutcome::from_io_error`] does.
    pub fn failed(self, error: &std::io::Error) {
        self.finish(SocketOutcome::from_io_error(error), SocketStats::default());
    }

    /// Finish the operation at the returned instant, or now when it was never
    /// marked.
    fn finish(self, outcome: SocketOutcome, stats: SocketStats) {
        match self.returned_ns {
            Some(at_ns) => self.trace.finish_at(outcome, stats, at_ns),
            None => self.trace.finish(outcome, stats),
        }
    }
}
