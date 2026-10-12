//! Timing of the consumer wakes a relay model runs while an object is published.

use std::cell::RefCell;

use crate::object::Intervals;

/// Wake intervals one publish step holds before merging later ones into its last.
const WAKE_CAPACITY: usize = 4;

/// The wakes recorded while one publish step ran.
pub(crate) type Wakes = Intervals<WAKE_CAPACITY>;

/// The publish step running on this thread, which wakes record into.
struct ActivePublish {
    backend: crate::backend::Handle,
    wakes: Wakes,
}

thread_local! {
    static ACTIVE_PUBLISH: RefCell<Option<ActivePublish>> = const { RefCell::new(None) };
}

/// Restores the enclosing publish step, even when the observed step unwinds.
struct Restore(Option<Option<ActivePublish>>);

impl Drop for Restore {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            ACTIVE_PUBLISH.with(|cell| *cell.borrow_mut() = previous);
        }
    }
}

/// Run `step`, recording the wakes it runs on this thread.
///
/// Only wakes that run synchronously inside `step` on the calling thread are
/// recorded. A nested call records into its own [`Wakes`], and the enclosing
/// one resumes afterwards without them.
pub(crate) fn observe<R>(backend: crate::backend::Handle, step: impl FnOnce() -> R) -> (R, Wakes) {
    let active = ActivePublish {
        backend,
        wakes: Wakes::default(),
    };
    let mut restore = Restore(Some(ACTIVE_PUBLISH.with(|cell| cell.replace(Some(active)))));
    let result = step();
    let previous = restore.0.take().expect("a step restores once");
    let wakes = ACTIVE_PUBLISH
        .with(|cell| cell.replace(previous))
        .map(|active| active.wakes)
        .unwrap_or_default();
    (result, wakes)
}

/// A consumer wake that a relay model runs, timed for the object being published.
///
/// A relay model wakes its waiting consumers when it makes data readable,
/// usually as a modification guard drops. Holding a `Wake` across that wake
/// lets [`crate::ObjectTrace::publish`] record it as
/// [`crate::ObjectPhase::Notify`] instead of as the publish step's own work:
/// begin it just before the wake and let it drop just after.
///
/// Outside a publish step the wake reads no clock, so an untraced modification
/// costs one thread-local check, and a build without the `lttng` feature skips
/// even that.
#[must_use = "a wake is timed until the value drops"]
pub struct Wake(Option<u64>);

impl Wake {
    /// Start timing a wake, when an object is being published on this thread.
    pub fn begin() -> Self {
        if !crate::backend::available() {
            return Self(None);
        }
        Self(ACTIVE_PUBLISH.with(|cell| {
            cell.borrow()
                .as_ref()
                .map(|active| active.backend.now_ns())
        }))
    }
}

impl Drop for Wake {
    fn drop(&mut self) {
        let Some(start_ns) = self.0.take() else {
            return;
        };
        ACTIVE_PUBLISH.with(|cell| {
            if let Some(active) = cell.borrow_mut().as_mut() {
                let end_ns = active.backend.now_ns();
                active.wakes.push(start_ns, end_ns);
            }
        });
    }
}
