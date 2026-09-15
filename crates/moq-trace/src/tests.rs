use super::*;

fn trace() -> Handle {
    Handle::new()
}

#[test]
fn object_children_reference_the_start_record() {
    let handle = trace().with_session_id(7).with_connection_id(42);
    let logical_id = LogicalId::new(9, 4);
    let mut object = handle.object(
        ObjectContext::new(Direction::Rx, ObjectIdentity::new(11, 12, 13), logical_id)
            .with_stream_id(16)
            .with_stream_offset_start(100),
    );
    let mut phase = object.phase(ObjectPhase::PayloadRead);
    phase.set_payload_bytes(44);
    phase.set_stream_offset_end(144);
    phase.finish(ObjectOutcome::Success);
    object.finish(ObjectOutcome::Success);
    let events = handle.events();
    assert_eq!(events.len(), 4);
    let trace_id = events[0].trace_id();
    assert!(events[1..].iter().all(|event| event.trace_id() == trace_id));
    assert!(matches!(
        events.first(),
        Some(backend::Event::Start { logical_id, .. })
            if logical_id.group() == 9 && logical_id.frame() == 4
    ));
    assert!(matches!(
        events.last(),
        Some(backend::Event::End {
            payload_bytes: 44,
            stream_offset_end: Some(144),
            outcome: ObjectOutcome::Success,
            ..
        })
    ));
    let Some(backend::Event::Phase { span_id: start, .. }) = events.get(1) else {
        panic!("expected phase start");
    };
    let Some(backend::Event::Phase { span_id: done, .. }) = events.get(2) else {
        panic!("expected phase completion");
    };
    assert_ne!(*start, 0);
    assert_eq!(start, done);
}

#[test]
fn dropping_an_object_records_abandonment() {
    let handle = trace();
    let object = handle.object(ObjectContext::new(
        Direction::Rx,
        ObjectIdentity::new(1, 2, 3),
        LogicalId::new(4, 5),
    ));
    drop(object);

    assert!(matches!(
        handle.events().last(),
        Some(backend::Event::End {
            outcome: ObjectOutcome::Abandoned,
            ..
        })
    ));
}

#[test]
fn disabled_handle_is_noop() {
    let handle = Handle::disabled();
    handle
        .object(ObjectContext::new(
            Direction::Rx,
            ObjectIdentity::new(1, 2, 3),
            LogicalId::new(4, 5),
        ))
        .finish(ObjectOutcome::Success);
    handle
        .socket(Direction::Rx, None)
        .finish(SocketOutcome::Success, SocketStats::default());
    assert!(handle.events().is_empty());
}

#[test]
fn disabled_object_phase_does_not_do_bookkeeping() {
    let handle = trace();
    handle.enable_only(backend::Tracepoint::Start);
    let mut object = handle.object(ObjectContext::new(
        Direction::Rx,
        ObjectIdentity::new(1, 2, 3),
        LogicalId::new(4, 5),
    ));
    reset_bookkeeping_counts();
    object
        .phase(ObjectPhase::PayloadRead)
        .finish(ObjectOutcome::Success);
    assert_eq!(clock_reads(), 0);
    assert_eq!(span_ids(), 0);
}

#[test]
#[cfg(not(feature = "lttng"))]
fn disabled_global_is_noop_without_lttng() {
    let handle = global();
    handle
        .object(ObjectContext::new(
            Direction::Rx,
            ObjectIdentity::new(1, 2, 3),
            LogicalId::new(4, 5),
        ))
        .finish(ObjectOutcome::Success);
    assert!(handle.events().is_empty());
}
