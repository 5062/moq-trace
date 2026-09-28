use super::*;

use crate::backend::{Event, Tracepoint};

/// A handle over a backend that records events in process.
///
/// Recording replaces only the leaf provider call, so these tests drive the
/// same dispatch a live relay does.
fn trace() -> Handle {
    Handle {
        inner: Some(backend::Handle::owned(backend::Backend::recording())),
        transport: quic_trace::Handle::disabled(),
        session_id: None,
        connection_id: None,
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
        Event::Start { trace_id, .. }
        | Event::End { trace_id, .. }
        | Event::Phase { trace_id, .. } => *trace_id,
    }
}

fn context() -> ObjectContext {
    ObjectContext::new(
        Direction::Rx,
        ObjectIdentity::new(1, 2, 3),
        LogicalId::new(4, 5),
    )
}

#[test]
fn object_children_reference_the_start_record() {
    let handle = trace().with_session_id(7).with_connection_id(42);
    let mut object = handle.object(
        ObjectContext::new(
            Direction::Rx,
            ObjectIdentity::new(11, 12, 13),
            LogicalId::new(9, 4),
        )
        .with_stream_id(16)
        .with_stream_offset_start(100),
    );
    let mut phase = object.phase(ObjectPhase::PayloadRead);
    phase.set_payload_bytes(44);
    phase.set_stream_offset_end(144);
    phase.finish(ObjectOutcome::Success);
    object.finish(ObjectOutcome::Success);
    let events = events(&handle);
    assert_eq!(events.len(), 4);
    let start = trace_id(&events[0]);
    assert!(events[1..].iter().all(|event| trace_id(event) == start));
    assert!(matches!(
        events.first(),
        Some(Event::Start {
            session_id: Some(7),
            connection_id: Some(42),
            context,
            ..
        }) if context.logical_id.group() == 9
            && context.logical_id.frame() == 4
            && context.stream_id == Some(16)
            && context.stream_offset_start == Some(100)
    ));
    assert!(matches!(
        events.last(),
        Some(Event::End {
            payload_bytes: 44,
            stream_offset_end: Some(144),
            outcome: ObjectOutcome::Success,
            ..
        })
    ));
    let Some(Event::Phase {
        span_id: start,
        phase: ObjectPhase::PayloadRead,
        edge: PhaseEdge::Start,
        outcome: None,
        ..
    }) = events.get(1)
    else {
        panic!("expected phase start");
    };
    let Some(Event::Phase {
        span_id: done,
        phase: ObjectPhase::PayloadRead,
        edge: PhaseEdge::Done,
        outcome: Some(ObjectOutcome::Success),
        ..
    }) = events.get(2)
    else {
        panic!("expected phase completion");
    };
    assert_ne!(*start, 0);
    assert_eq!(start, done);
}

#[test]
fn object_start_uses_a_timestamp_captured_before_its_context() {
    let handle = trace();
    handle
        .object(context().with_start_ns(123))
        .finish(ObjectOutcome::Success);

    assert!(matches!(
        events(&handle).first(),
        Some(Event::Start {
            timestamp_ns: 123,
            ..
        })
    ));
}

#[test]
fn dropping_an_object_records_abandonment() {
    let handle = trace();
    let object = handle.object(context());
    drop(object);

    assert!(matches!(
        events(&handle).last(),
        Some(Event::End {
            outcome: ObjectOutcome::Abandoned,
            ..
        })
    ));
}

#[test]
fn disabled_handle_is_noop() {
    let handle = Handle::disabled();
    handle.object(context()).finish(ObjectOutcome::Success);
    handle
        .socket(Direction::Rx, None)
        .finish(SocketOutcome::Success, SocketStats::default());
    assert!(events(&handle).is_empty());
}

#[test]
fn new_session_id_is_always_allocated() {
    let handle = Handle::disabled().with_new_session_id();
    assert!(handle.session_id.is_some());
}

#[test]
fn handle_travels_across_tasks() {
    // A relay clones one handle into every session and connection task, so the
    // handle must stay movable and shareable between threads whatever a backend
    // holds.
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<Handle>();
}

#[test]
fn disabled_object_phase_does_not_do_bookkeeping() {
    let handle = trace();
    let recording = recording(&handle);
    recording.enable_only(Tracepoint::Start);
    let mut object = handle.object(context());
    let clock_reads = recording.clock_reads();
    let span_ids = recording.span_id_calls();
    object
        .phase(ObjectPhase::PayloadRead)
        .finish(ObjectOutcome::Success);
    assert_eq!(recording.clock_reads(), clock_reads);
    assert_eq!(recording.span_id_calls(), span_ids);
}

#[test]
#[cfg(not(feature = "lttng"))]
fn disabled_global_is_noop_without_lttng() {
    let handle = global();
    handle.object(context()).finish(ObjectOutcome::Success);
    assert!(events(&handle).is_empty());
}

/// Poll `future` to completion on the current thread.
fn drive<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

/// A future that is pending on its first poll and then completes with `result`.
fn pending_once<T>(result: T) -> impl std::future::Future<Output = T> {
    let mut result = Some(result);
    let mut polled = false;
    std::future::poll_fn(move |_| {
        if !polled {
            polled = true;
            return std::task::Poll::Pending;
        }
        std::task::Poll::Ready(result.take().expect("polled after completion"))
    })
}

/// Return each phase occurrence as `(span_id, start_ns, done_ns, outcome)`.
fn phase_occurrences(events: &[Event]) -> Vec<(u64, u64, u64, Option<ObjectOutcome>)> {
    let mut occurrences = Vec::new();
    for event in events {
        let Event::Phase {
            timestamp_ns,
            span_id,
            edge,
            outcome,
            ..
        } = event
        else {
            continue;
        };
        match edge {
            PhaseEdge::Start => occurrences.push((*span_id, *timestamp_ns, 0, None)),
            PhaseEdge::Done => {
                let occurrence = occurrences
                    .iter_mut()
                    .find(|occurrence| occurrence.0 == *span_id)
                    .expect("a done edge follows its start edge");
                occurrence.2 = *timestamp_ns;
                occurrence.3 = *outcome;
            }
        }
    }
    occurrences
}

#[test]
fn measure_records_each_poll_and_excludes_pending_time() {
    let handle = trace();
    let mut object = handle.object(context());
    let result: Result<u32, ()> =
        drive(object.measure(ObjectPhase::PayloadRead, pending_once(Ok(7))));
    assert_eq!(result, Ok(7));
    object.finish(ObjectOutcome::Success);

    let occurrences = phase_occurrences(&events(&handle));
    assert_eq!(occurrences.len(), 2, "one occurrence per poll");
    assert_ne!(occurrences[0].0, occurrences[1].0);
    for (_, start_ns, done_ns, outcome) in &occurrences {
        assert!(start_ns <= done_ns);
        assert_eq!(*outcome, Some(ObjectOutcome::Success));
    }
    // The gap between the pending poll and the completing one belongs to no phase.
    assert!(occurrences[0].2 <= occurrences[1].1);
}

#[test]
fn measure_marks_the_completing_poll_failed_on_error() {
    let handle = trace();
    let mut object = handle.object(context());
    let result: Result<(), &str> =
        drive(object.measure(ObjectPhase::HeaderParse, pending_once(Err("short"))));
    assert_eq!(result, Err("short"));
    drop(object);

    let outcomes: Vec<_> = phase_occurrences(&events(&handle))
        .into_iter()
        .map(|occurrence| occurrence.3)
        .collect();
    assert_eq!(
        outcomes,
        [Some(ObjectOutcome::Success), Some(ObjectOutcome::Failed)]
    );
}

#[test]
fn measure_without_phase_tracing_only_runs_the_future() {
    let handle = trace();
    let recording = recording(&handle);
    recording.enable_only(Tracepoint::Start);
    let mut object = handle.object(context());
    let clock_reads = recording.clock_reads();
    let result: Result<u32, ()> =
        drive(object.measure(ObjectPhase::PayloadWrite, pending_once(Ok(3))));
    assert_eq!(result, Ok(3));
    assert_eq!(recording.clock_reads(), clock_reads);
    assert!(phase_occurrences(&events(&handle)).is_empty());
    object.finish(ObjectOutcome::Success);
}

#[test]
fn connection_ids_are_never_reused() {
    let first = next_connection_id();
    let second = next_connection_id();
    assert!(second > first);
}
