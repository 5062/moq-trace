//! Emit a handful of MoQ objects so a capture can be verified end to end.
//!
//! `just tracepoints` links this example and asserts the LTTng provider keeps
//! its tracepoint section, then reads the resulting trace back with Babeltrace.
//! Run it by hand under an active LTTng session to inspect the events.

use moq_trace::{Direction, LogicalId, ObjectContext, ObjectIdentity, ObjectOutcome, ObjectPhase};

fn main() {
    let handle = moq_trace::global().with_new_session_id();
    for index in 0..32u64 {
        let mut object = handle.object(ObjectContext::new(
            Direction::Tx,
            ObjectIdentity::new(1, 2, index),
            LogicalId::new(index, 0),
        ));
        object
            .phase(ObjectPhase::Create)
            .finish(ObjectOutcome::Success);
        object.finish(ObjectOutcome::Success);
    }
}
