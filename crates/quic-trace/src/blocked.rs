use crate::backend::{Event, Tracepoint};
use crate::{Handle, PhaseEdge};

/// Why a connection could not send data it had.
///
/// The provider binding casts this to its wire value, so the declaration order
/// is the encoding and must match the C enum in `provider/interface.h`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SendBlockedReason {
    /// Bytes in flight filled the congestion window.
    CongestionWindow,
    /// The pacer delayed the next datagram.
    Pacing,
    /// An unvalidated path reached its anti-amplification limit.
    Amplification,
    /// A write found the peer's connection-level `MAX_DATA` used up.
    ConnectionFlowControl,
    /// A write found the peer's `MAX_STREAM_DATA` for its stream used up.
    StreamFlowControl,
    /// A write found the local buffer of unacknowledged data full.
    SendBuffer,
}

/// An interval in which a connection could not send, ended by the token.
///
/// The interval starts when the token is created and ends when it is finished
/// or dropped. A stack keeps one token per reason while the condition holds:
/// per connection for the transmit reasons, and per stream for a blocked write.
/// Dropping the token, for example when the connection closes, ends the
/// interval at that instant.
pub struct SendBlockedTrace(Option<SendBlockedState>);

struct SendBlockedState {
    backend: crate::backend::Handle,
    span_id: u64,
    connection_id: u64,
    stream_id: Option<u64>,
    reason: SendBlockedReason,
}

impl Handle {
    /// Start an interval in which `connection_id` cannot send for `reason`.
    ///
    /// Pass the stream a blocked write targets, or `None` when the connection
    /// as a whole cannot transmit.
    pub fn send_blocked(
        &self,
        connection_id: u64,
        reason: SendBlockedReason,
        stream_id: Option<u64>,
    ) -> SendBlockedTrace {
        let Some(inner) = self.inner.as_ref() else {
            return SendBlockedTrace(None);
        };
        if !inner.enabled(Tracepoint::SendBlocked) {
            return SendBlockedTrace(None);
        }
        let state = SendBlockedState {
            backend: inner,
            span_id: inner.next_span_id(),
            connection_id,
            stream_id,
            reason,
        };
        state.emit(PhaseEdge::Start, state.backend.now_ns());
        SendBlockedTrace(Some(state))
    }
}

impl SendBlockedTrace {
    /// Return a token that records nothing.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Return why the connection is blocked, if this token records an interval.
    pub fn reason(&self) -> Option<SendBlockedReason> {
        self.0.as_ref().map(|state| state.reason)
    }

    /// End the interval now, when the connection can send again.
    pub fn finish(self) {
        drop(self);
    }
}

impl SendBlockedState {
    fn emit(&self, edge: PhaseEdge, timestamp_ns: u64) {
        self.backend.emit(Event::SendBlocked {
            timestamp_ns,
            span_id: self.span_id,
            connection_id: self.connection_id,
            stream_id: self.stream_id,
            reason: self.reason,
            edge,
        });
    }
}

impl std::fmt::Debug for SendBlockedTrace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("SendBlockedTrace")
            .field(&self.reason())
            .finish()
    }
}

impl Drop for SendBlockedTrace {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            state.emit(PhaseEdge::Done, state.backend.now_ns());
        }
    }
}
