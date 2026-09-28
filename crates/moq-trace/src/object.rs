use std::task::Poll;

use crate::backend::{Event, Tracepoint};
use crate::{Direction, Handle, PhaseEdge};

/// Identity shared by ingress and every outbound copy of one logical object.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalId {
    group: u64,
    frame: u64,
}

impl LogicalId {
    /// Create an identity from a process-unique group instance and frame ordinal.
    pub fn new(group: u64, frame: u64) -> Self {
        Self { group, frame }
    }

    /// Return the process-unique group instance.
    pub fn group(self) -> u64 {
        self.group
    }

    /// Return the zero-based frame ordinal within the group.
    pub fn frame(self) -> u64 {
        self.frame
    }
}

impl std::fmt::Display for LogicalId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.group, self.frame)
    }
}

/// A measured step in the moq-transport object lifecycle.
///
/// Phases measure processing. Time a phase spends waiting on I/O, such as bytes
/// that have not arrived or flow control that blocks a write, belongs to no
/// phase. A phase that awaits I/O should run through [`ObjectTrace::measure`],
/// which records only the polls that do work. Such a phase can therefore appear
/// several times for one object, so a per-object figure sums the occurrences.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ObjectPhase {
    /// Parse an inbound object header.
    HeaderParse,
    /// Create an inbound object in the relay model.
    Create,
    /// Read inbound payload bytes from the transport.
    ///
    /// The phase covers the transport handing received bytes to the relay. It
    /// excludes waiting for them to arrive, and it excludes copying them into
    /// the relay model, which belongs to `FrameCommit`. A relay may record one
    /// phase per chunk.
    PayloadRead,
    /// Make received payload bytes visible to relay consumers.
    ///
    /// The phase covers writing payload bytes into the relay model and the step
    /// that marks the object complete, whichever of those wakes a waiting
    /// consumer. A relay may record one phase per chunk, and the completion step
    /// belongs to the last one or to a final phase of its own.
    FrameCommit,
    /// Clone or select an outbound object from the relay model.
    Clone,
    /// Encode an outbound object header.
    HeaderEncode,
    /// Write an outbound object payload.
    PayloadWrite,
}

/// Result of an object lifecycle or phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ObjectOutcome {
    /// Processing completed successfully.
    Success,
    /// Processing completed with an error.
    Failed,
    /// The phase token was dropped before an outcome was recorded.
    Abandoned,
}

/// Stable identity of one moq-transport object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectIdentity {
    pub(crate) track_alias: u64,
    pub(crate) group_id: u64,
    pub(crate) object_id: u64,
}

impl ObjectIdentity {
    /// Create a wire identity from its track alias, group ID, and object ID.
    pub fn new(track_alias: u64, group_id: u64, object_id: u64) -> Self {
        Self {
            track_alias,
            group_id,
            object_id,
        }
    }
}

/// Stable metadata known before a moq-transport object trace starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectContext {
    pub(crate) logical_id: LogicalId,
    pub(crate) identity: ObjectIdentity,
    pub(crate) direction: Direction,
    pub(crate) stream_id: Option<u64>,
    pub(crate) stream_offset_start: Option<u64>,
    start_ns: Option<u64>,
    payload_bytes: u64,
}

impl ObjectContext {
    /// Create object metadata from its wire identity and logical relay identity.
    pub fn new(direction: Direction, identity: ObjectIdentity, logical_id: LogicalId) -> Self {
        Self {
            logical_id,
            identity,
            direction,
            stream_id: None,
            stream_offset_start: None,
            start_ns: None,
            payload_bytes: 0,
        }
    }

    /// Attach the transport stream identifier.
    pub fn with_stream_id(mut self, stream_id: u64) -> Self {
        self.stream_id = Some(stream_id);
        self
    }

    /// Attach the inclusive stream byte offset where this object starts.
    pub fn with_stream_offset_start(mut self, offset_start: u64) -> Self {
        self.stream_offset_start = Some(offset_start);
        self
    }

    /// Attach a lifecycle start timestamp captured before the context was known.
    pub fn with_start_ns(mut self, start_ns: u64) -> Self {
        self.start_ns = Some(start_ns);
        self
    }

    /// Attach a payload size known before tracing starts.
    pub fn with_payload_bytes(mut self, payload_bytes: u64) -> Self {
        self.payload_bytes = payload_bytes;
        self
    }
}

/// A moq-transport object trace, or a zero-work disabled token.
#[must_use = "object traces must be explicitly finished when processing completes"]
pub struct ObjectTrace(Option<ObjectTraceState>);

struct ObjectTraceState {
    backend: crate::backend::Handle,
    trace_id: u64,
    payload_bytes: u64,
    stream_offset_end: Option<u64>,
}

/// A scoped object phase whose completion consumes the token.
///
/// The phase borrows its object because the object holds the payload size and
/// stream offset the phase reports. A packet phase has no equivalent metadata to
/// update, so that token owns its backend handle instead. The difference is the
/// metadata, not the backend.
#[must_use = "dropping an object phase records an abandoned phase"]
pub struct ObjectPhaseTrace<'a> {
    object: &'a mut ObjectTrace,
    state: Option<(u64, ObjectPhase)>,
}

/// The tracepoints an object trace token covers.
const OBJECT_TRACEPOINTS: [Tracepoint; 3] = [Tracepoint::Start, Tracepoint::Phase, Tracepoint::End];

impl ObjectTrace {
    /// Return a disabled object trace token.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Update the object payload size once it is known.
    pub fn set_payload_bytes(&mut self, payload_bytes: u64) {
        if let Some(state) = &mut self.0 {
            state.payload_bytes = payload_bytes;
        }
    }

    /// Update the exclusive stream byte offset reached by this object.
    pub fn set_stream_offset_end(&mut self, stream_offset_end: u64) {
        if let Some(state) = &mut self.0 {
            state.stream_offset_end = Some(stream_offset_end);
        }
    }

    /// Start a measured object lifecycle phase.
    pub fn phase(&mut self, phase: ObjectPhase) -> ObjectPhaseTrace<'_> {
        let state = self.0.as_ref().and_then(|state| {
            if !state.backend.enabled(Tracepoint::Phase) {
                return None;
            }
            let span_id = state.backend.next_span_id();
            state.emit_phase(span_id, phase, PhaseEdge::Start, None);
            Some((span_id, phase))
        });
        ObjectPhaseTrace {
            object: self,
            state,
        }
    }

    /// Run a phase that awaits I/O, recording only the polls that do work.
    ///
    /// Each poll of `future` becomes one occurrence of `phase`, timed from the
    /// start of the poll to its return, so time the future spends pending belongs
    /// to no phase. A poll that returns pending records `Success`, because it did
    /// its share of the work without failing. The poll that completes records
    /// `Success` or `Failed` from the result. Both edges of an occurrence are
    /// emitted after its poll returns, so the provider calls add nothing to the
    /// measured interval.
    pub async fn measure<F, T, E>(&mut self, phase: ObjectPhase, future: F) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|cx| {
            let Some(state) = self
                .0
                .as_ref()
                .filter(|state| state.backend.enabled(Tracepoint::Phase))
            else {
                return future.as_mut().poll(cx);
            };
            let start_ns = state.backend.now_ns();
            let poll = future.as_mut().poll(cx);
            let end_ns = state.backend.now_ns();
            let outcome = match &poll {
                Poll::Ready(Err(_)) => ObjectOutcome::Failed,
                _ => ObjectOutcome::Success,
            };
            let span_id = state.backend.next_span_id();
            state.emit_phase_at(span_id, phase, PhaseEdge::Start, None, start_ns);
            state.emit_phase_at(span_id, phase, PhaseEdge::Done, Some(outcome), end_ns);
            poll
        })
        .await
    }

    /// Finish the object interval with the latest metadata and result.
    pub fn finish(mut self, outcome: ObjectOutcome) {
        let Some(state) = self.0.take() else {
            return;
        };
        state.emit_end(outcome);
    }
}

impl ObjectTraceState {
    fn emit_phase(
        &self,
        span_id: u64,
        phase: ObjectPhase,
        edge: PhaseEdge,
        outcome: Option<ObjectOutcome>,
    ) {
        self.emit_phase_at(span_id, phase, edge, outcome, self.backend.now_ns());
    }

    fn emit_phase_at(
        &self,
        span_id: u64,
        phase: ObjectPhase,
        edge: PhaseEdge,
        outcome: Option<ObjectOutcome>,
        timestamp_ns: u64,
    ) {
        self.backend.emit(Event::Phase {
            timestamp_ns,
            trace_id: self.trace_id,
            span_id,
            phase,
            edge,
            outcome,
        });
    }

    fn emit_end(self, outcome: ObjectOutcome) {
        let Self {
            backend,
            trace_id,
            payload_bytes,
            stream_offset_end,
        } = self;
        backend.emit(Event::End {
            timestamp_ns: backend.now_ns(),
            trace_id,
            stream_offset_end,
            payload_bytes,
            outcome,
        });
    }
}

impl Drop for ObjectTrace {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            state.emit_end(ObjectOutcome::Abandoned);
        }
    }
}

impl ObjectPhaseTrace<'_> {
    /// Update the object payload size once it is known.
    pub fn set_payload_bytes(&mut self, payload_bytes: u64) {
        self.object.set_payload_bytes(payload_bytes);
    }

    /// Update the exclusive stream byte offset reached by this object.
    pub fn set_stream_offset_end(&mut self, stream_offset_end: u64) {
        self.object.set_stream_offset_end(stream_offset_end);
    }

    /// Finish the phase with an explicit result.
    pub fn finish(mut self, outcome: ObjectOutcome) {
        self.emit_done(outcome);
    }

    /// Emit the completing edge once; a phase only has state while its object does.
    fn emit_done(&mut self, outcome: ObjectOutcome) {
        if let (Some((span_id, phase)), Some(object)) = (self.state.take(), &self.object.0) {
            object.emit_phase(span_id, phase, PhaseEdge::Done, Some(outcome));
        }
    }
}

impl Drop for ObjectPhaseTrace<'_> {
    fn drop(&mut self) {
        self.emit_done(ObjectOutcome::Abandoned);
    }
}

impl Handle {
    /// Start a moq-transport object trace.
    pub fn object(&self, context: ObjectContext) -> ObjectTrace {
        let Some(inner) = self.inner.as_ref() else {
            return ObjectTrace::disabled();
        };
        if !inner.any_enabled(&OBJECT_TRACEPOINTS) {
            return ObjectTrace::disabled();
        }
        let trace_id = inner.next_trace_id();
        inner.emit(Event::Start {
            timestamp_ns: context.start_ns.unwrap_or_else(|| inner.now_ns()),
            trace_id,
            session_id: self.session_id,
            connection_id: self.connection_id,
            context: context.clone(),
        });
        ObjectTrace(Some(ObjectTraceState {
            backend: inner.clone(),
            trace_id,
            payload_bytes: context.payload_bytes,
            stream_offset_end: None,
        }))
    }
}
