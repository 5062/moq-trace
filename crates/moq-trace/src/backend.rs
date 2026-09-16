//! The `moq_trace:*` schema on the shared backend seam.
//!
//! The provider binding casts the public enums to their wire value, so the
//! declaration order of each enum is its encoding and must match the C enum in
//! `provider/interface.h`. Reordering variants changes the wire contract.

use crate::{ObjectContext, ObjectOutcome, ObjectPhase, PhaseEdge};
use trace_core::{
    Backend as CoreBackend, Handle as CoreHandle, Schema, Tracepoint as CoreTracepoint,
};

/// The tracepoints the `moq_trace:*` schema exposes.
#[derive(Clone, Copy)]
pub(crate) enum Tracepoint {
    /// A moq-transport object trace started.
    Start,
    /// An object lifecycle phase started or completed.
    Phase,
    /// A moq-transport object trace ended.
    End,
}

impl CoreTracepoint for Tracepoint {
    fn index(self) -> u32 {
        self as u32
    }
}

/// One event in the `moq_trace:*` schema.
///
/// The native provider translates an event into the provider call of the same
/// name. A recording backend keeps the event as it was handed over, including
/// the timestamp taken at the emission site, so a test observes the values the
/// provider would have received.
#[cfg_attr(not(all(feature = "lttng", target_os = "linux")), allow(dead_code))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    /// An object trace started, carrying the session and connection it belongs to.
    Start {
        timestamp_ns: u64,
        trace_id: u64,
        session_id: Option<u64>,
        connection_id: Option<u64>,
        context: ObjectContext,
    },
    /// An object trace ended with the final payload and stream metadata.
    End {
        timestamp_ns: u64,
        trace_id: u64,
        stream_offset_end: Option<u64>,
        payload_bytes: u64,
        outcome: ObjectOutcome,
    },
    /// An object phase started or completed.
    Phase {
        timestamp_ns: u64,
        trace_id: u64,
        span_id: u64,
        phase: ObjectPhase,
        edge: PhaseEdge,
        outcome: Option<ObjectOutcome>,
    },
}

/// The `moq_trace:*` schema.
pub(crate) enum ObjectSchema {}

impl Schema for ObjectSchema {
    type Tracepoint = Tracepoint;
    type Event = Event;

    fn initialize() {
        platform::initialize();
    }

    fn enabled(tracepoint: Tracepoint) -> bool {
        platform::enabled(tracepoint)
    }

    fn tracepoint(event: &Event) -> Tracepoint {
        match event {
            Event::Start { .. } => Tracepoint::Start,
            Event::End { .. } => Tracepoint::End,
            Event::Phase { .. } => Tracepoint::Phase,
        }
    }

    fn emit(event: Event) {
        platform::emit(event);
    }
}

/// A cheap, cloneable reference to the process-global object backend.
pub(crate) type Handle = CoreHandle<ObjectSchema>;

/// The object provider of one process.
pub(crate) type Backend = CoreBackend<ObjectSchema>;

/// Return whether this build can emit object events.
pub(crate) const fn available() -> bool {
    cfg!(all(feature = "lttng", target_os = "linux"))
}

#[cfg(all(feature = "lttng", target_os = "linux"))]
mod platform {
    use moq_trace_lttng_sys as ffi;

    use super::*;

    pub(super) fn initialize() {
        unsafe { ffi::moq_trace_provider_init() };
    }

    pub(super) fn enabled(tracepoint: Tracepoint) -> bool {
        unsafe {
            match tracepoint {
                Tracepoint::Start => ffi::moq_trace_moq_object_start_enabled(),
                Tracepoint::Phase => ffi::moq_trace_moq_object_phase_enabled(),
                Tracepoint::End => ffi::moq_trace_moq_object_end_enabled(),
            }
        }
    }

    pub(super) fn emit(event: Event) {
        match event {
            Event::Start {
                timestamp_ns,
                trace_id,
                session_id,
                connection_id,
                context,
            } => object_start(timestamp_ns, trace_id, session_id, connection_id, &context),
            Event::End {
                timestamp_ns,
                trace_id,
                stream_offset_end,
                payload_bytes,
                outcome,
            } => object_end(
                timestamp_ns,
                trace_id,
                stream_offset_end,
                payload_bytes,
                outcome,
            ),
            Event::Phase {
                timestamp_ns,
                trace_id,
                span_id,
                phase,
                edge,
                outcome,
            } => object_phase(timestamp_ns, trace_id, span_id, phase, edge, outcome),
        }
    }

    fn object_start(
        timestamp_ns: u64,
        trace_id: u64,
        session_id: Option<u64>,
        connection_id: Option<u64>,
        context: &ObjectContext,
    ) {
        unsafe {
            let (has_session_id, session_id) = optional(session_id);
            let (has_connection_id, connection_id) = optional(connection_id);
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
                direction: context.direction as u8,
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

    fn object_end(
        timestamp_ns: u64,
        trace_id: u64,
        stream_offset_end: Option<u64>,
        payload_bytes: u64,
        outcome: ObjectOutcome,
    ) {
        unsafe {
            let (has_stream_offset_end, stream_offset_end) = optional(stream_offset_end);
            ffi::moq_trace_moq_object_end(&ffi::moq_trace_moq_object_end {
                timestamp_ns,
                trace_id,
                has_stream_offset_end,
                stream_offset_end,
                payload_bytes,
                outcome: outcome as u8,
            });
        }
    }

    fn object_phase(
        timestamp_ns: u64,
        trace_id: u64,
        span_id: u64,
        phase: ObjectPhase,
        edge: PhaseEdge,
        outcome: Option<ObjectOutcome>,
    ) {
        unsafe {
            let (has_outcome, outcome) = optional(outcome.map(|value| value as u8));
            ffi::moq_trace_moq_object_phase(&ffi::moq_trace_moq_object_phase {
                timestamp_ns,
                trace_id,
                span_id,
                phase: phase as u8,
                edge: edge as u8,
                has_outcome,
                outcome,
            });
        }
    }

    /// Encode an optional field as its wire value, or zero when it is absent.
    ///
    /// The provider payload has no sum type for an absent field, so the `has_`
    /// flag and a zero value together carry the option.
    fn optional<T: Copy + Default>(value: Option<T>) -> (u8, T) {
        value.map_or((0, T::default()), |value| (1, value))
    }
}

#[cfg(not(all(feature = "lttng", target_os = "linux")))]
mod platform {
    use super::*;

    pub(super) fn initialize() {}

    pub(super) fn enabled(_: Tracepoint) -> bool {
        false
    }

    pub(super) fn emit(_: Event) {}
}
