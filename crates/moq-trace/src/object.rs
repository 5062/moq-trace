use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

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
    ///
    /// Take the group from [`crate::next_logical_group`], which stays unique across
    /// Rust and C++ hooks in one process.
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
/// Phases measure processing, except [`ObjectPhase::DeliveryWait`] and
/// [`ObjectPhase::WriteBlocked`], which name the two waits on the forwarding
/// path. Any other waiting, such as for bytes that have not arrived, belongs to
/// no phase. A phase that awaits I/O should run through [`ObjectTrace::measure`]
/// or [`ObjectTrace::measure_waiting`], which record only the polls that do
/// work. Such a phase can therefore appear several times for one object, so a
/// per-object figure sums the occurrences.
///
/// Declaration order is the wire encoding shared with the C provider, so new
/// variants are appended rather than placed in pipeline order.
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
    /// that marks the object complete. A relay may record one phase per chunk,
    /// and the completion step belongs to the last one or to a final phase of
    /// its own. Waking consumers belongs to [`ObjectPhase::Notify`] when the
    /// relay performs it as a step of its own, and to this phase otherwise.
    FrameCommit,
    /// Clone or select an outbound object from the relay model.
    Clone,
    /// Encode an outbound object header.
    HeaderEncode,
    /// Write an outbound object payload.
    PayloadWrite,
    /// Wake or enumerate the consumers of a newly readable inbound object.
    ///
    /// This is the fan-out work every copy shares, so it is recorded once on
    /// the inbound object rather than on each copy. A relay whose model wakes
    /// consumers inside the call that commits the bytes cannot separate the
    /// two, so it records that call as [`ObjectPhase::FrameCommit`] and emits
    /// no `Notify`. A relay that wakes consumers per chunk may record one
    /// occurrence per chunk.
    Notify,
    /// Wait from the instant the relay made the object readable until this
    /// copy's [`ObjectPhase::Clone`] starts.
    ///
    /// The wait covers waking the consumer and the scheduler delay before it
    /// runs. The relay captures the readable instant with [`crate::now_ns`]
    /// where it publishes the object, keeps it in its model, and the consumer
    /// passes it to [`ObjectTrace::phase_at`] on the outbound copy. The wait can
    /// therefore start before the copy's lifecycle does.
    DeliveryWait,
    /// Wait from a write that could not proceed until the relay resumes it.
    ///
    /// Stream or connection flow control, transport backpressure, and an
    /// asynchronous lock held by another task all block a write this way. The
    /// wait ends when the writer runs again, so it includes the delay between
    /// the wake and the next poll. A synchronous lock contended inside a write
    /// call blocks inside the call, so that time stays in the write phase.
    WriteBlocked,
    /// Time inside a call into the transport API made by another phase.
    ///
    /// The phase nests inside the work phase that made the call, such as the
    /// stream write inside [`ObjectPhase::PayloadWrite`], and covers whatever
    /// the transport runs in it: packet building and sends for a stack that
    /// transmits synchronously, and the transport's own locks. It is never MoQ
    /// work, so analysis subtracts it from the phase around it. A Rust hook
    /// records it by wrapping the transport future in [`transport_call`].
    TransportCall,
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

    /// Return whether this object records phase events.
    ///
    /// A hook that times a phase from clock readings of its own, such as one
    /// that splits a call into several phases with [`ObjectTrace::phase_at`],
    /// checks this first so it reads no clock when nothing would be recorded.
    pub fn records_phases(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|state| state.backend.enabled(Tracepoint::Phase))
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

    /// Start an object phase at a timestamp captured earlier.
    ///
    /// Take `start_ns` from [`crate::now_ns`], so it shares the clock of every
    /// other event. A wait that began elsewhere, such as
    /// [`ObjectPhase::DeliveryWait`], starts this way.
    pub fn phase_at(&mut self, phase: ObjectPhase, start_ns: u64) -> ObjectPhaseTrace<'_> {
        let state = self.0.as_ref().and_then(|state| {
            if !state.backend.enabled(Tracepoint::Phase) {
                return None;
            }
            let span_id = state.backend.next_span_id();
            state.emit_phase_at(span_id, phase, PhaseEdge::Start, None, start_ns);
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
        self.measure_polls(phase, None, future).await
    }

    /// Run a phase that awaits I/O, recording its polls and the waits between them.
    ///
    /// Each poll of `future` becomes one occurrence of `phase`, as in
    /// [`ObjectTrace::measure`]. Each stretch from a poll that returned pending
    /// to the next poll becomes one occurrence of `wait`, normally
    /// [`ObjectPhase::WriteBlocked`]. A wait is emitted after the poll that ends
    /// it returns, so its provider calls fall outside every measured interval. A
    /// future dropped while pending records no final wait, because nothing
    /// resumed it.
    pub async fn measure_waiting<F, T, E>(
        &mut self,
        phase: ObjectPhase,
        wait: ObjectPhase,
        future: F,
    ) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        self.measure_polls(phase, Some(wait), future).await
    }

    async fn measure_polls<F, T, E>(
        &mut self,
        phase: ObjectPhase,
        wait: Option<ObjectPhase>,
        future: F,
    ) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        let mut future = std::pin::pin!(future);
        // When the last poll returned pending, the instant it did.
        let mut pending_since = None;
        std::future::poll_fn(|cx| {
            let Some(state) = self
                .0
                .as_ref()
                .filter(|state| state.backend.enabled(Tracepoint::Phase))
            else {
                return future.as_mut().poll(cx);
            };
            let start_ns = state.backend.now_ns();
            let scope = CallScope::enter(&state.backend);
            let poll = future.as_mut().poll(cx);
            let calls = scope.exit();
            let end_ns = state.backend.now_ns();
            if let (Some(wait), Some(wait_start_ns)) = (wait, pending_since.take()) {
                let span_id = state.backend.next_span_id();
                state.emit_phase_at(span_id, wait, PhaseEdge::Start, None, wait_start_ns);
                let outcome = Some(ObjectOutcome::Success);
                state.emit_phase_at(span_id, wait, PhaseEdge::Done, outcome, start_ns);
            }
            let outcome = match &poll {
                Poll::Ready(Err(_)) => ObjectOutcome::Failed,
                _ => ObjectOutcome::Success,
            };
            let span_id = state.backend.next_span_id();
            state.emit_phase_at(span_id, phase, PhaseEdge::Start, None, start_ns);
            state.emit_phase_at(span_id, phase, PhaseEdge::Done, Some(outcome), end_ns);
            for &(call_start, call_end) in calls.intervals() {
                let span_id = state.backend.next_span_id();
                let call = ObjectPhase::TransportCall;
                state.emit_phase_at(span_id, call, PhaseEdge::Start, None, call_start);
                let outcome = Some(ObjectOutcome::Success);
                state.emit_phase_at(span_id, call, PhaseEdge::Done, outcome, call_end);
            }
            if poll.is_pending() {
                pending_since = Some(end_ns);
            }
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

/// Transport call intervals one measured poll holds before merging later ones
/// into its last.
const CALL_CAPACITY: usize = 8;

/// The transport calls recorded while one measured poll ran.
///
/// Calls beyond the capacity extend the last interval to the end of the latest
/// one, so the intervals cover every call and never overlap, at the cost of
/// also covering the MoQ work between the merged calls.
#[derive(Default)]
struct Calls {
    intervals: [(u64, u64); CALL_CAPACITY],
    len: usize,
}

impl Calls {
    fn intervals(&self) -> &[(u64, u64)] {
        &self.intervals[..self.len]
    }

    fn push(&mut self, start_ns: u64, end_ns: u64) {
        if self.len < CALL_CAPACITY {
            self.intervals[self.len] = (start_ns, end_ns);
            self.len += 1;
        } else {
            self.intervals[CALL_CAPACITY - 1].1 = end_ns;
        }
    }
}

/// The measured poll running on this thread, which transport calls record into.
struct ActivePoll {
    backend: crate::backend::Handle,
    calls: Calls,
    /// Whether a transport call is already running, so a nested one is not
    /// counted twice.
    in_call: bool,
}

thread_local! {
    static ACTIVE_POLL: RefCell<Option<ActivePoll>> = const { RefCell::new(None) };
}

/// Makes a measured poll the target of transport calls on this thread.
///
/// The scope is thread-local because a poll runs on one thread, and it lives in
/// the Rust facade because only Rust transports are polled from MoQ phases. A
/// C++ hook times a transport call with an explicit nested phase instead.
struct CallScope {
    previous: Option<Option<ActivePoll>>,
}

impl CallScope {
    fn enter(backend: &crate::backend::Handle) -> Self {
        let active = ActivePoll {
            backend: backend.clone(),
            calls: Calls::default(),
            in_call: false,
        };
        let previous = ACTIVE_POLL.with(|cell| cell.replace(Some(active)));
        Self {
            previous: Some(previous),
        }
    }

    /// Restore the enclosing scope and return the calls this one recorded.
    fn exit(mut self) -> Calls {
        let previous = self.previous.take().expect("a scope exits once");
        ACTIVE_POLL
            .with(|cell| cell.replace(previous))
            .map(|active| active.calls)
            .unwrap_or_default()
    }
}

impl Drop for CallScope {
    /// Restore the enclosing scope when a poll unwinds before exiting.
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            ACTIVE_POLL.with(|cell| *cell.borrow_mut() = previous);
        }
    }
}

/// A transport future whose polls are timed as [`ObjectPhase::TransportCall`].
///
/// Created by [`transport_call`]. Outside a poll measured by
/// [`ObjectTrace::measure`] or [`ObjectTrace::measure_waiting`] it reads no
/// clock and only forwards the poll, and a build without the `lttng` feature
/// forwards every poll without looking for one.
#[must_use = "futures do nothing unless polled"]
pub struct TransportCall<F> {
    future: F,
}

/// Time each poll of a transport future as a call into the transport API.
///
/// Wrap the future a MoQ phase awaits from the transport, such as a stream
/// write or read, so the time spent inside the transport is recorded on the
/// object whose phase is being measured on this thread. Analysis subtracts that
/// time from the phase, which leaves the MoQ layer's own work.
pub fn transport_call<F: Future>(future: F) -> TransportCall<F> {
    TransportCall { future }
}

impl<F: Future> Future for TransportCall<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        // SAFETY: `future` is structurally pinned. It is never moved out of the
        // wrapper, and the wrapper has no `Drop` impl or `Unpin` override.
        let future = unsafe { self.map_unchecked_mut(|call| &mut call.future) };
        // A build that cannot emit never opens a scope, so it skips the lookup.
        if !crate::backend::available() {
            return future.poll(cx);
        }
        let start_ns = ACTIVE_POLL.with(|cell| {
            let mut active = cell.borrow_mut();
            let active = active.as_mut().filter(|active| !active.in_call)?;
            active.in_call = true;
            Some(active.backend.now_ns())
        });
        let poll = future.poll(cx);
        if let Some(start_ns) = start_ns {
            ACTIVE_POLL.with(|cell| {
                if let Some(active) = cell.borrow_mut().as_mut() {
                    let end_ns = active.backend.now_ns();
                    active.calls.push(start_ns, end_ns);
                    active.in_call = false;
                }
            });
        }
        poll
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
        self.emit_done(outcome, None);
    }

    /// Finish the phase at a timestamp captured at the measured boundary.
    ///
    /// Take `timestamp_ns` from [`crate::now_ns`], so it shares the clock of
    /// every other event.
    pub fn finish_at(mut self, outcome: ObjectOutcome, timestamp_ns: u64) {
        self.emit_done(outcome, Some(timestamp_ns));
    }

    /// Emit the completing edge once; a phase only has state while its object does.
    fn emit_done(&mut self, outcome: ObjectOutcome, timestamp_ns: Option<u64>) {
        if let (Some((span_id, phase)), Some(object)) = (self.state.take(), &self.object.0) {
            let timestamp_ns = timestamp_ns.unwrap_or_else(|| object.backend.now_ns());
            object.emit_phase_at(span_id, phase, PhaseEdge::Done, Some(outcome), timestamp_ns);
        }
    }
}

impl Drop for ObjectPhaseTrace<'_> {
    fn drop(&mut self) {
        self.emit_done(ObjectOutcome::Abandoned, None);
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
