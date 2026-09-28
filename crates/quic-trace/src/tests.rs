use super::*;

use crate::backend::{Event, Tracepoint};

/// A handle over a backend that records events in process.
///
/// Recording replaces only the leaf provider call, so these tests drive the
/// same dispatch a live relay does.
fn trace() -> Handle {
    Handle {
        inner: Some(backend::Handle::owned(backend::Backend::recording())),
    }
}

fn recording(handle: &Handle) -> &backend::Backend {
    handle.inner.as_ref().expect("the handle has a backend")
}

fn events(handle: &Handle) -> Vec<Event> {
    handle
        .inner
        .as_ref()
        .map(|inner| inner.events())
        .unwrap_or_default()
}

/// Return the trace identifier an event carries.
fn trace_id(event: &Event) -> u64 {
    match event {
        Event::PacketStart { trace_id, .. }
        | Event::PacketEnd { trace_id, .. }
        | Event::PacketPhase { trace_id, .. }
        | Event::StreamFrame { trace_id, .. }
        | Event::SocketStart { trace_id, .. }
        | Event::SocketEnd { trace_id, .. } => *trace_id,
    }
}

#[test]
fn packet_end_contains_metadata_discovered_after_start() {
    let handle = trace();
    let mut packet = handle.packet(PacketContext::new(Direction::Rx, 7).with_byte_len(1200));
    packet.set_number(91);
    packet.set_space(PacketSpace::Data);
    packet
        .phase(PacketPhase::Routing)
        .finish(PacketOutcome::Success);
    packet.finish(PacketOutcome::Success);
    let events = events(&handle);
    assert!(matches!(
        events.first(),
        Some(Event::PacketStart { context, .. })
            if context.connection_id == 7 && context.direction == Direction::Rx
    ));
    let Some(Event::PacketPhase {
        span_id: start,
        phase: PacketPhase::Routing,
        edge: PhaseEdge::Start,
        ..
    }) = events.get(1)
    else {
        panic!("expected phase start");
    };
    let Some(Event::PacketPhase {
        span_id: finish,
        phase: PacketPhase::Routing,
        edge: PhaseEdge::Done,
        outcome: Some(PacketOutcome::Success),
        ..
    }) = events.get(2)
    else {
        panic!("expected phase completion");
    };
    assert_eq!(start, finish);
    assert!(matches!(
        events.last(),
        Some(Event::PacketEnd {
            context,
            outcome: PacketOutcome::Success,
            ..
        }) if context.packet_number == Some(91)
            && context.packet_space == Some(PacketSpace::Data)
            && context.byte_len == Some(1200)
    ));
}

#[test]
fn disabled_handle_is_noop() {
    let handle = Handle::disabled();
    handle
        .socket(Direction::Rx, None)
        .finish(SocketOutcome::Success, SocketStats::default());
    handle
        .packet(PacketContext::new(Direction::Rx, 7))
        .finish(PacketOutcome::Success);
    assert!(events(&handle).is_empty());
}

#[test]
fn disabled_packet_phase_allocates_no_identifier() {
    let packet = PacketTrace::disabled();
    let span_id = crate::next_span_id();
    packet
        .phase(PacketPhase::Routing)
        .finish(PacketOutcome::Success);
    assert_eq!(
        crate::next_span_id(),
        span_id + 1,
        "a disabled phase must not allocate a span identifier"
    );
}

#[test]
fn disabled_packet_phase_event_does_not_do_bookkeeping() {
    let handle = trace();
    let recording = recording(&handle);
    recording.enable_only(Tracepoint::PacketStart);
    let packet = handle.packet(PacketContext::new(Direction::Rx, 7));
    let clock_reads = recording.clock_reads();
    let span_ids = recording.span_id_calls();
    packet
        .phase(PacketPhase::Routing)
        .finish(PacketOutcome::Success);
    assert_eq!(recording.clock_reads(), clock_reads);
    assert_eq!(recording.span_id_calls(), span_ids);
}

#[test]
fn disabled_stream_frame_event_does_not_read_the_clock() {
    let handle = trace();
    let recording = recording(&handle);
    recording.enable_only(Tracepoint::PacketStart);
    let packet = handle.packet(PacketContext::new(Direction::Rx, 7));
    let clock_reads = recording.clock_reads();
    packet.stream_frame(StreamFrame::new(1, 0, 10), PacketOutcome::Success);
    assert_eq!(recording.clock_reads(), clock_reads);
}

#[test]
fn packet_phase_enablement_is_checked_when_phase_starts() {
    let handle = trace();
    let recording = recording(&handle);
    recording.enable_only(Tracepoint::PacketStart);
    let packet = handle.packet(PacketContext::new(Direction::Rx, 7));
    recording.set_enabled(Tracepoint::PacketPhase, true);
    packet
        .phase(PacketPhase::Routing)
        .finish(PacketOutcome::Success);
    assert_eq!(
        events(&handle)
            .iter()
            .filter(|event| matches!(event, Event::PacketPhase { .. }))
            .count(),
        2
    );
}

#[test]
fn trace_ids_are_unique_across_handles() {
    let first = trace();
    let second = trace();
    first
        .socket(Direction::Rx, None)
        .finish(SocketOutcome::Success, SocketStats::default());
    second
        .socket(Direction::Rx, None)
        .finish(SocketOutcome::Success, SocketStats::default());
    assert_ne!(trace_id(&events(&first)[0]), trace_id(&events(&second)[0]));
}

#[test]
fn handle_travels_across_tasks() {
    // A relay clones one handle into every connection task, so the handle must
    // stay movable and shareable between threads whatever a backend holds.
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<Handle>();
}

#[test]
#[cfg(all(feature = "lttng", target_os = "linux"))]
fn packet_phase_wire_values_match_the_provider() {
    // The provider receives each phase as its declaration index, so every
    // variant must keep the value of the C enumerator with the same name.
    use quic_trace_lttng_sys as ffi;
    let phases = [
        (
            PacketPhase::HeaderParse,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_HEADER_PARSE,
        ),
        (
            PacketPhase::Routing,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_ROUTING,
        ),
        (
            PacketPhase::Scheduling,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_SCHEDULING,
        ),
        (
            PacketPhase::HeaderUnprotect,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_HEADER_UNPROTECT,
        ),
        (
            PacketPhase::PayloadDecrypt,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_PAYLOAD_DECRYPT,
        ),
        (
            PacketPhase::FrameProcess,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_FRAME_PROCESS,
        ),
        (
            PacketPhase::FrameEncode,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_FRAME_ENCODE,
        ),
        (
            PacketPhase::PacketEncrypt,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_PACKET_ENCRYPT,
        ),
        (
            PacketPhase::Application,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_APPLICATION,
        ),
    ];
    for (phase, wire) in phases {
        assert_eq!(phase as u32, wire, "{phase:?}");
    }
}

#[test]
#[cfg(not(feature = "lttng"))]
fn disabled_global_is_noop_without_lttng() {
    let handle = global();
    handle
        .packet(PacketContext::new(Direction::Rx, 7))
        .finish(PacketOutcome::Success);
    assert!(events(&handle).is_empty());
}

/// Rust and C++ hooks in one process must draw identifiers and time from the
/// same native source, which the C++ facade calls directly. Interleaving the two
/// callers shows one counter: any other test allocating concurrently only widens
/// the gaps, never reorders or repeats a value.
#[cfg(all(feature = "lttng", target_os = "linux"))]
#[test]
fn identifiers_and_clock_come_from_the_native_provider() {
    use quic_trace_lttng_sys as ffi;

    let rust = next_trace_id();
    let native = unsafe { ffi::quic_trace_next_trace_id() };
    assert!(rust < native && native < next_trace_id());

    let rust = next_span_id();
    let native = unsafe { ffi::quic_trace_next_span_id() };
    assert!(rust < native && native < next_span_id());

    let rust = next_connection_id();
    let native = unsafe { ffi::quic_trace_next_connection_id() };
    assert!(rust < native && native < next_connection_id());

    let rust = now_ns();
    let native = unsafe { ffi::quic_trace_now_ns() };
    assert!(rust <= native && native <= now_ns());
}
