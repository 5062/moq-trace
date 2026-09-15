use super::*;

fn trace() -> Handle {
    Handle::new()
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
    let events = handle.events();
    assert!(matches!(
        events.first(),
        Some(backend::Event::PacketStart {
            connection_id: 7,
            direction: Direction::Rx,
            ..
        })
    ));
    let Some(backend::Event::PacketPhase { span_id: start, .. }) = events.get(1) else {
        panic!("expected phase start");
    };
    let Some(backend::Event::PacketPhase {
        span_id: finish, ..
    }) = events.get(2)
    else {
        panic!("expected phase completion");
    };
    assert_eq!(start, finish);
    assert!(matches!(
        events.last(),
        Some(backend::Event::PacketEnd {
            packet_number: Some(91),
            packet_space: Some(PacketSpace::Data),
            byte_len: Some(1200),
            outcome: PacketOutcome::Success,
            ..
        })
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
    assert!(handle.events().is_empty());
}

#[test]
fn disabled_packet_phase_does_not_read_the_clock() {
    let packet = PacketTrace::disabled();
    reset_bookkeeping_counts();
    packet
        .phase(PacketPhase::Routing)
        .finish(PacketOutcome::Success);
    assert_eq!(clock_reads(), 0);
    assert_eq!(span_ids(), 0);
}

#[test]
fn disabled_packet_phase_event_does_not_do_bookkeeping() {
    let handle = trace();
    handle.enable_only(backend::Tracepoint::PacketStart);
    let packet = handle.packet(PacketContext::new(Direction::Rx, 7));
    reset_bookkeeping_counts();
    packet
        .phase(PacketPhase::Routing)
        .finish(PacketOutcome::Success);
    assert_eq!(clock_reads(), 0);
    assert_eq!(span_ids(), 0);
}

#[test]
fn disabled_stream_frame_event_does_not_read_the_clock() {
    let handle = trace();
    handle.enable_only(backend::Tracepoint::PacketStart);
    let packet = handle.packet(PacketContext::new(Direction::Rx, 7));
    reset_bookkeeping_counts();
    packet.stream_frame(StreamFrame::new(1, 0, 10), PacketOutcome::Success);
    assert_eq!(clock_reads(), 0);
}

#[test]
fn packet_phase_enablement_is_checked_when_phase_starts() {
    let handle = trace();
    handle.enable_only(backend::Tracepoint::PacketStart);
    let packet = handle.packet(PacketContext::new(Direction::Rx, 7));
    handle.set_enabled(backend::Tracepoint::PacketPhase, true);
    packet
        .phase(PacketPhase::Routing)
        .finish(PacketOutcome::Success);
    assert_eq!(
        handle
            .events()
            .iter()
            .filter(|event| matches!(event, backend::Event::PacketPhase { .. }))
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
    assert_ne!(first.events()[0].trace_id(), second.events()[0].trace_id());
}

#[test]
#[cfg(not(feature = "lttng"))]
fn disabled_global_is_noop_without_lttng() {
    let handle = global();
    handle
        .packet(PacketContext::new(Direction::Rx, 7))
        .finish(PacketOutcome::Success);
    assert!(handle.events().is_empty());
}
