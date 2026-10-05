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

/// Return the trace identifier an event carries, if it belongs to a lifecycle.
fn trace_id(event: &Event) -> Option<u64> {
    match event {
        Event::PacketStart { trace_id, .. }
        | Event::PacketEnd { trace_id, .. }
        | Event::PacketPhase { trace_id, .. }
        | Event::StreamFrame { trace_id, .. }
        | Event::SocketStart { trace_id, .. }
        | Event::SocketEnd { trace_id, .. } => Some(*trace_id),
        Event::ConnectionPath { .. } | Event::SendBlocked { .. } => None,
    }
}

/// Return an event's timestamp.
fn timestamp(event: &Event) -> u64 {
    match event {
        Event::PacketStart { timestamp_ns, .. }
        | Event::PacketEnd { timestamp_ns, .. }
        | Event::PacketPhase { timestamp_ns, .. }
        | Event::StreamFrame { timestamp_ns, .. }
        | Event::SocketStart { timestamp_ns, .. }
        | Event::SocketEnd { timestamp_ns, .. }
        | Event::ConnectionPath { timestamp_ns, .. }
        | Event::SendBlocked { timestamp_ns, .. } => *timestamp_ns,
    }
}

#[test]
fn packet_and_socket_end_at_a_captured_send_completion() {
    let handle = trace();
    let socket = handle.socket(Direction::Tx, None);
    let first = handle.packet(PacketContext::new(Direction::Tx, 7));
    let second = handle.packet(PacketContext::new(Direction::Tx, 7));
    let completion = now_ns() + 1_000;
    socket.finish_at(
        SocketOutcome::Success,
        SocketStats::new(1, 2, 2400),
        completion,
    );
    first.finish_at(PacketOutcome::Success, completion);
    second.finish_at(PacketOutcome::Dropped, completion);
    let ends: Vec<_> = events(&handle)
        .into_iter()
        .filter(|event| matches!(event, Event::PacketEnd { .. } | Event::SocketEnd { .. }))
        .collect();
    assert_eq!(ends.len(), 3);
    assert!(ends.iter().all(|event| timestamp(event) == completion));
    assert!(matches!(
        ends[2],
        Event::PacketEnd {
            outcome: PacketOutcome::Dropped,
            ..
        }
    ));
}

#[test]
fn stream_frame_records_a_captured_acceptance_time() {
    let handle = trace();
    let packet = handle.packet(PacketContext::new(Direction::Rx, 7));
    let accepted = now_ns();
    packet.stream_frame_at(StreamFrame::new(4, 0, 10), PacketOutcome::Success, accepted);
    packet.stream_frame_at(
        StreamFrame::new(4, 10, 20),
        PacketOutcome::Dropped,
        accepted + 5,
    );
    packet.finish(PacketOutcome::Success);
    let frames: Vec<_> = events(&handle)
        .into_iter()
        .filter_map(|event| match event {
            Event::StreamFrame {
                timestamp_ns,
                frame,
                outcome,
                ..
            } => Some((timestamp_ns, frame, outcome)),
            _ => None,
        })
        .collect();
    assert_eq!(
        frames,
        vec![
            (accepted, StreamFrame::new(4, 0, 10), PacketOutcome::Success),
            (
                accepted + 5,
                StreamFrame::new(4, 10, 20),
                PacketOutcome::Dropped
            ),
        ]
    );
}

#[test]
fn queue_phases_bound_the_packet_lifecycle() {
    let handle = trace();
    let read = now_ns();
    let packet = handle.packet(PacketContext::new(Direction::Rx, 7).with_start_ns(read));
    packet
        .phase_at(PacketPhase::ReadQueue, read)
        .finish(PacketOutcome::Success);
    packet.finish(PacketOutcome::Success);
    let events = events(&handle);
    assert_eq!(timestamp(&events[0]), read);
    assert!(matches!(
        events[1],
        Event::PacketPhase {
            phase: PacketPhase::ReadQueue,
            edge: PhaseEdge::Start,
            timestamp_ns,
            ..
        } if timestamp_ns == read
    ));
}

#[test]
fn connection_path_encodes_addresses_as_ipv6() {
    use std::net::SocketAddr;

    let handle = trace();
    let local: SocketAddr = "10.0.0.1:4443".parse().unwrap();
    let peer: SocketAddr = "[2001:db8::7]:50266".parse().unwrap();
    handle.connection_path(9, ConnectionPath::new(local, peer));
    let events = events(&handle);
    let [
        Event::ConnectionPath {
            connection_id: 9,
            path,
            ..
        },
    ] = events.as_slice()
    else {
        panic!("expected one connection path event, got {events:?}");
    };
    assert_eq!(path.local, local);
    assert_eq!(path.peer, peer);
    let mapped = crate::path::address_bits(local.ip());
    assert_eq!((mapped >> 64) as u64, 0);
    assert_eq!(mapped as u64, 0x0000_ffff_0a00_0001);
    let v6 = crate::path::address_bits(peer.ip());
    assert_eq!((v6 >> 64) as u64, 0x2001_0db8_0000_0000);
    assert_eq!(v6 as u64, 7);
}

#[test]
fn disabled_connection_path_reads_no_clock() {
    let handle = trace();
    let recording = recording(&handle);
    recording.enable_only(Tracepoint::PacketStart);
    let clock_reads = recording.clock_reads();
    handle.connection_path(
        1,
        ConnectionPath::new(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ),
    );
    assert_eq!(recording.clock_reads(), clock_reads);
    assert!(events(&handle).is_empty());
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
fn send_blocked_pairs_its_edges_and_ends_on_drop() {
    let handle = trace();
    let finished = handle.send_blocked(3, SendBlockedReason::CongestionWindow, None);
    assert_eq!(finished.reason(), Some(SendBlockedReason::CongestionWindow));
    finished.finish();
    drop(handle.send_blocked(3, SendBlockedReason::StreamFlowControl, Some(8)));

    let edges: Vec<_> = events(&handle)
        .into_iter()
        .map(|event| match event {
            Event::SendBlocked {
                span_id,
                connection_id,
                stream_id,
                reason,
                edge,
                ..
            } => (span_id, connection_id, stream_id, reason, edge),
            other => panic!("unexpected event {other:?}"),
        })
        .collect();
    assert_eq!(edges.len(), 4);
    assert_eq!(edges[0].0, edges[1].0);
    assert_ne!(edges[0].0, edges[2].0);
    assert_eq!(edges[2].0, edges[3].0);
    assert_eq!(edges[0].4, PhaseEdge::Start);
    assert_eq!(edges[1].4, PhaseEdge::Done);
    assert_eq!(edges[3].4, PhaseEdge::Done, "dropping ends the interval");
    assert_eq!(edges[2].2, Some(8));
    assert_eq!(edges[2].3, SendBlockedReason::StreamFlowControl);
}

#[test]
fn disabled_send_blocked_reads_no_clock() {
    let handle = trace();
    let recording = recording(&handle);
    recording.enable_only(Tracepoint::PacketStart);
    let blocked = handle.send_blocked(3, SendBlockedReason::Pacing, None);
    assert_eq!(blocked.reason(), None);
    blocked.finish();
    assert_eq!(recording.clock_reads(), 0);
    assert!(events(&handle).is_empty());
}

#[test]
fn stream_frame_carries_its_retransmission_flag() {
    let handle = trace();
    let packet = handle.packet(PacketContext::new(Direction::Tx, 1));
    packet.stream_frame(
        StreamFrame::new(4, 0, 10).with_retransmission(true),
        PacketOutcome::Success,
    );
    packet.stream_frame(StreamFrame::new(4, 10, 20), PacketOutcome::Success);
    packet.finish(PacketOutcome::Success);
    let flags: Vec<_> = events(&handle)
        .into_iter()
        .filter_map(|event| match event {
            Event::StreamFrame { frame, .. } => Some(frame.retransmission),
            _ => None,
        })
        .collect();
    assert_eq!(flags, [Some(true), None]);
}

#[test]
#[cfg(all(feature = "lttng", target_os = "linux"))]
fn send_blocked_reason_wire_values_match_the_provider() {
    use quic_trace_lttng_sys as ffi;
    let reasons = [
        (
            SendBlockedReason::CongestionWindow,
            ffi::quic_trace_send_blocked_reason_QUIC_TRACE_SEND_BLOCKED_REASON_CONGESTION_WINDOW,
        ),
        (
            SendBlockedReason::Pacing,
            ffi::quic_trace_send_blocked_reason_QUIC_TRACE_SEND_BLOCKED_REASON_PACING,
        ),
        (
            SendBlockedReason::Amplification,
            ffi::quic_trace_send_blocked_reason_QUIC_TRACE_SEND_BLOCKED_REASON_AMPLIFICATION,
        ),
        (
            SendBlockedReason::ConnectionFlowControl,
            ffi::quic_trace_send_blocked_reason_QUIC_TRACE_SEND_BLOCKED_REASON_CONNECTION_FLOW_CONTROL,
        ),
        (
            SendBlockedReason::StreamFlowControl,
            ffi::quic_trace_send_blocked_reason_QUIC_TRACE_SEND_BLOCKED_REASON_STREAM_FLOW_CONTROL,
        ),
        (
            SendBlockedReason::SendBuffer,
            ffi::quic_trace_send_blocked_reason_QUIC_TRACE_SEND_BLOCKED_REASON_SEND_BUFFER,
        ),
    ];
    for (reason, wire) in reasons {
        assert_eq!(reason as u32, wire, "{reason:?}");
    }
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
        (
            PacketPhase::ReadQueue,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_READ_QUEUE,
        ),
        (
            PacketPhase::SendQueue,
            ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_SEND_QUEUE,
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
