//! LTTng-UST adapter for MoQ object events.

use crate::{ObjectContext, ObjectOutcome, ObjectPhase, PhaseEdge};

#[derive(Clone)]
pub(crate) enum Handle {
    Shared(&'static Backend),
    #[cfg(test)]
    Owned(std::sync::Arc<Backend>),
}

impl Handle {
    #[cfg(test)]
    pub(crate) fn owned(inner: Backend) -> Self {
        Self::Owned(std::sync::Arc::new(inner))
    }

    pub(crate) fn shared(inner: &'static Backend) -> Self {
        Self::Shared(inner)
    }
}

impl std::ops::Deref for Handle {
    type Target = Backend;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Shared(inner) => inner,
            #[cfg(test)]
            Self::Owned(inner) => inner,
        }
    }
}

pub(crate) struct Backend {
    #[cfg(test)]
    events: std::sync::Mutex<Vec<Event>>,
    #[cfg(test)]
    enabled: std::sync::atomic::AtomicU8,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum Tracepoint {
    Start,
    Phase,
    End,
}

#[cfg(test)]
impl Tracepoint {
    const fn mask(self) -> u8 {
        1 << self as u8
    }
}

impl Backend {
    pub(crate) fn new() -> Self {
        #[cfg(not(test))]
        platform::initialize();
        Self {
            #[cfg(test)]
            events: std::sync::Mutex::new(Vec::new()),
            #[cfg(test)]
            enabled: std::sync::atomic::AtomicU8::new(u8::MAX),
        }
    }

    #[cfg(test)]
    pub(crate) fn enable_only(&self, tracepoint: Tracepoint) {
        self.enabled
            .store(tracepoint.mask(), std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    fn enabled(&self, tracepoint: Tracepoint) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed) & tracepoint.mask() != 0
    }

    pub(crate) fn object_enabled(&self) -> bool {
        #[cfg(test)]
        return self.enabled(Tracepoint::Start)
            || self.enabled(Tracepoint::Phase)
            || self.enabled(Tracepoint::End);
        #[cfg(not(test))]
        platform::object_enabled()
    }

    pub(crate) fn object_phase_enabled(&self) -> bool {
        #[cfg(test)]
        return self.enabled(Tracepoint::Phase);
        #[cfg(not(test))]
        platform::object_phase_enabled()
    }

    pub(crate) fn object_start(
        &self,
        _timestamp_ns: u64,
        trace_id: u64,
        _handle: &crate::Handle,
        context: &ObjectContext,
    ) {
        #[cfg(test)]
        self.record(Event::Start {
            trace_id,
            logical_id: context.logical_id,
        });
        #[cfg(not(test))]
        platform::object_start(_timestamp_ns, trace_id, _handle, context);
    }

    pub(crate) fn object_end(
        &self,
        _timestamp_ns: u64,
        trace_id: u64,
        stream_offset_end: Option<u64>,
        payload_bytes: u64,
        outcome: ObjectOutcome,
    ) {
        #[cfg(test)]
        self.record(Event::End {
            trace_id,
            stream_offset_end,
            payload_bytes,
            outcome,
        });
        #[cfg(not(test))]
        platform::object_end(
            _timestamp_ns,
            trace_id,
            stream_offset_end,
            payload_bytes,
            outcome,
        );
    }

    pub(crate) fn object_phase(
        &self,
        _timestamp_ns: u64,
        trace_id: u64,
        span_id: u64,
        _phase: ObjectPhase,
        _edge: PhaseEdge,
        _outcome: Option<ObjectOutcome>,
    ) {
        #[cfg(test)]
        self.record(Event::Phase { trace_id, span_id });
        #[cfg(not(test))]
        platform::object_phase(_timestamp_ns, trace_id, span_id, _phase, _edge, _outcome);
    }

    #[cfg(test)]
    fn record(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }

    #[cfg(test)]
    pub(crate) fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

pub(crate) const fn available() -> bool {
    cfg!(all(feature = "lttng", target_os = "linux"))
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    Start {
        trace_id: u64,
        logical_id: crate::LogicalId,
    },
    End {
        trace_id: u64,
        stream_offset_end: Option<u64>,
        payload_bytes: u64,
        outcome: ObjectOutcome,
    },
    Phase {
        trace_id: u64,
        span_id: u64,
    },
}

#[cfg(test)]
impl Event {
    pub(crate) fn trace_id(&self) -> u64 {
        match *self {
            Self::Start { trace_id, .. }
            | Self::End { trace_id, .. }
            | Self::Phase { trace_id, .. } => trace_id,
        }
    }
}

#[cfg(all(feature = "lttng", target_os = "linux", not(test)))]
mod platform {
    use moq_trace_lttng_sys as ffi;

    use super::*;

    pub(super) fn initialize() {
        unsafe { ffi::moq_trace_provider_init() };
    }

    pub(super) fn object_enabled() -> bool {
        unsafe {
            ffi::moq_trace_moq_object_start_enabled()
                || ffi::moq_trace_moq_object_phase_enabled()
                || ffi::moq_trace_moq_object_end_enabled()
        }
    }

    pub(super) fn object_phase_enabled() -> bool {
        unsafe { ffi::moq_trace_moq_object_phase_enabled() }
    }

    pub(super) fn object_start(
        timestamp_ns: u64,
        trace_id: u64,
        handle: &crate::Handle,
        context: &ObjectContext,
    ) {
        unsafe {
            if !ffi::moq_trace_moq_object_start_enabled() {
                return;
            }
            let (has_session_id, session_id) = optional(handle.session_id);
            let (has_connection_id, connection_id) = optional(handle.connection_id);
            let (has_stream_id, stream_id) = optional(context.stream_id);
            let (has_stream_offset_start, stream_offset_start) =
                optional(context.stream_offset_start);
            ffi::moq_trace_moq_object_start(&ffi::moq_trace_moq_object_start {
                timestamp_ns,
                trace_id,
                logical_group: context.logical_id.group(),
                logical_frame: context.logical_id.frame(),
                has_session_id,
                session_id,
                has_connection_id,
                connection_id,
                direction: direction(context.direction),
                track_alias: context.identity.track_alias,
                group_id: context.identity.group_id,
                object_id: context.identity.object_id,
                has_stream_id,
                stream_id,
                has_stream_offset_start,
                stream_offset_start,
            });
        }
    }

    pub(super) fn object_end(
        timestamp_ns: u64,
        trace_id: u64,
        stream_offset_end: Option<u64>,
        payload_bytes: u64,
        outcome: ObjectOutcome,
    ) {
        unsafe {
            if !ffi::moq_trace_moq_object_end_enabled() {
                return;
            }
            let (has_stream_offset_end, stream_offset_end) = optional(stream_offset_end);
            ffi::moq_trace_moq_object_end(&ffi::moq_trace_moq_object_end {
                timestamp_ns,
                trace_id,
                has_stream_offset_end,
                stream_offset_end,
                payload_bytes,
                outcome: object_outcome(outcome),
            });
        }
    }

    pub(super) fn object_phase(
        timestamp_ns: u64,
        trace_id: u64,
        span_id: u64,
        phase: ObjectPhase,
        edge: PhaseEdge,
        outcome: Option<ObjectOutcome>,
    ) {
        unsafe {
            if !ffi::moq_trace_moq_object_phase_enabled() {
                return;
            }
            let (has_outcome, outcome) = optional_enum(outcome, object_outcome);
            ffi::moq_trace_moq_object_phase(&ffi::moq_trace_moq_object_phase {
                timestamp_ns,
                trace_id,
                span_id,
                phase: encode_object_phase(phase),
                edge: encode_edge(edge),
                has_outcome,
                outcome,
            });
        }
    }

    fn optional(value: Option<u64>) -> (u8, u64) {
        value.map_or((0, 0), |value| (1, value))
    }

    fn optional_enum<T>(value: Option<T>, convert: fn(T) -> u8) -> (u8, u8) {
        value.map_or((0, 0), |value| (1, convert(value)))
    }

    fn direction(value: crate::Direction) -> u8 {
        match value {
            crate::Direction::Rx => ffi::moq_trace_direction_MOQ_TRACE_DIRECTION_RX as u8,
            crate::Direction::Tx => ffi::moq_trace_direction_MOQ_TRACE_DIRECTION_TX as u8,
        }
    }

    fn encode_edge(value: PhaseEdge) -> u8 {
        match value {
            PhaseEdge::Start => ffi::moq_trace_edge_MOQ_TRACE_EDGE_START as u8,
            PhaseEdge::Done => ffi::moq_trace_edge_MOQ_TRACE_EDGE_DONE as u8,
        }
    }

    fn encode_object_phase(value: ObjectPhase) -> u8 {
        match value {
            ObjectPhase::HeaderParse => {
                ffi::moq_trace_object_phase_MOQ_TRACE_OBJECT_PHASE_HEADER_PARSE as u8
            }
            ObjectPhase::Create => ffi::moq_trace_object_phase_MOQ_TRACE_OBJECT_PHASE_CREATE as u8,
            ObjectPhase::PayloadRead => {
                ffi::moq_trace_object_phase_MOQ_TRACE_OBJECT_PHASE_PAYLOAD_READ as u8
            }
            ObjectPhase::FrameCommit => {
                ffi::moq_trace_object_phase_MOQ_TRACE_OBJECT_PHASE_FRAME_COMMIT as u8
            }
            ObjectPhase::Clone => ffi::moq_trace_object_phase_MOQ_TRACE_OBJECT_PHASE_CLONE as u8,
            ObjectPhase::HeaderEncode => {
                ffi::moq_trace_object_phase_MOQ_TRACE_OBJECT_PHASE_HEADER_ENCODE as u8
            }
            ObjectPhase::PayloadWrite => {
                ffi::moq_trace_object_phase_MOQ_TRACE_OBJECT_PHASE_PAYLOAD_WRITE as u8
            }
        }
    }

    fn object_outcome(value: ObjectOutcome) -> u8 {
        match value {
            ObjectOutcome::Success => {
                ffi::moq_trace_object_outcome_MOQ_TRACE_OBJECT_OUTCOME_SUCCESS as u8
            }
            ObjectOutcome::Failed => {
                ffi::moq_trace_object_outcome_MOQ_TRACE_OBJECT_OUTCOME_FAILED as u8
            }
            ObjectOutcome::Abandoned => {
                ffi::moq_trace_object_outcome_MOQ_TRACE_OBJECT_OUTCOME_ABANDONED as u8
            }
        }
    }
}

#[cfg(all(not(all(feature = "lttng", target_os = "linux")), not(test)))]
mod platform {
    use super::*;

    pub(super) fn initialize() {}
    pub(super) fn object_enabled() -> bool {
        false
    }
    pub(super) fn object_phase_enabled() -> bool {
        false
    }
    pub(super) fn object_start(_: u64, _: u64, _: &crate::Handle, _: &ObjectContext) {}
    pub(super) fn object_end(_: u64, _: u64, _: Option<u64>, _: u64, _: ObjectOutcome) {}
    pub(super) fn object_phase(
        _: u64,
        _: u64,
        _: u64,
        _: ObjectPhase,
        _: PhaseEdge,
        _: Option<ObjectOutcome>,
    ) {
    }
}
