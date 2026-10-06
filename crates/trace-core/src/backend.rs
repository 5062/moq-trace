//! The provider seam shared by the MoQ and QUIC facades.
//!
//! A facade owns its schema and its native provider binding. This module owns
//! the dispatch around them. A production build is a thin wrapper over the
//! provider: it carries no state and no recording branch. The `recording`
//! feature adds an in-process sink with an enable mask and bookkeeping
//! counters, so a test drives the same dispatch path a live relay does and only
//! the leaf call differs.

#[cfg(not(feature = "recording"))]
use std::marker::PhantomData;
#[cfg(feature = "recording")]
use std::sync::Mutex;
#[cfg(feature = "recording")]
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{next_span_id, next_trace_id, now_ns};

/// A single tracepoint exposed by one schema.
///
/// The index is a position in the schema's enable mask. It is a local detail of
/// the backend seam and is not part of the provider contract; only provider
/// event names, enum values, fields, and units are.
pub trait Tracepoint: Copy + 'static {
    /// Return this tracepoint's bit position in the schema enable mask.
    ///
    /// A schema may expose at most 64 tracepoints.
    fn index(self) -> u32;
}

/// One instrumentation schema: its tracepoints, its events, and its provider.
pub trait Schema: 'static {
    /// The tracepoints this schema exposes.
    type Tracepoint: Tracepoint;
    /// The payload of one event.
    ///
    /// The native provider translates it into a provider call. A recording
    /// backend retains it so tests and tooling can inspect what was emitted.
    type Event: Clone + Send + 'static;

    /// Return whether the process has this tracepoint enabled.
    fn enabled(tracepoint: Self::Tracepoint) -> bool;

    /// Return the tracepoint that carries this event.
    fn tracepoint(event: &Self::Event) -> Self::Tracepoint;

    /// Emit one event to the native provider.
    ///
    /// The backend checks enablement before calling this, so the provider
    /// binding does not have to.
    fn emit(event: Self::Event);
}

/// Return the enable mask bit for one tracepoint.
#[cfg(feature = "recording")]
fn mask<S: Schema>(tracepoint: S::Tracepoint) -> u64 {
    1_u64 << tracepoint.index()
}

/// A sink that retains events in process instead of emitting them.
///
/// Every tracepoint starts enabled. The counters exist so a test can prove that
/// a disabled tracepoint performs no bookkeeping at all, which is the property
/// that keeps instrumentation affordable on a hot path.
#[cfg(feature = "recording")]
struct Recording<S: Schema> {
    enabled: AtomicU64,
    events: Mutex<Vec<S::Event>>,
    span_id_calls: AtomicU64,
    clock_reads: AtomicU64,
}

#[cfg(feature = "recording")]
impl<S: Schema> Recording<S> {
    fn new() -> Self {
        Self {
            enabled: AtomicU64::new(u64::MAX),
            events: Mutex::new(Vec::new()),
            span_id_calls: AtomicU64::new(0),
            clock_reads: AtomicU64::new(0),
        }
    }

    fn enabled(&self, tracepoint: S::Tracepoint) -> bool {
        self.enabled.load(Ordering::Relaxed) & mask::<S>(tracepoint) != 0
    }

    fn enable_only(&self, tracepoint: S::Tracepoint) {
        self.enabled.store(mask::<S>(tracepoint), Ordering::Relaxed);
    }

    fn set_enabled(&self, tracepoint: S::Tracepoint, enabled: bool) {
        let bit = mask::<S>(tracepoint);
        if enabled {
            self.enabled.fetch_or(bit, Ordering::Relaxed);
        } else {
            self.enabled.fetch_and(!bit, Ordering::Relaxed);
        }
    }
}

/// A provider selection for one schema.
///
/// Without the `recording` feature the backend is always bound to the native
/// provider and holds no state. With it, the backend may instead own a recording
/// sink, boxed so that the native backend stays the size of one pointer. A
/// process keeps one backend per provider in a `OnceLock`, and every trace
/// token holds a `&'static` reference to it, which costs no atomic to copy.
pub struct Backend<S: Schema> {
    #[cfg(feature = "recording")]
    recording: Option<Box<Recording<S>>>,
    #[cfg(not(feature = "recording"))]
    schema: PhantomData<fn() -> S>,
}

impl<S: Schema> Backend<S> {
    /// Create the backend bound to the native provider.
    pub fn native() -> Self {
        Self {
            #[cfg(feature = "recording")]
            recording: None,
            #[cfg(not(feature = "recording"))]
            schema: PhantomData,
        }
    }

    /// Create a backend that records events in process.
    ///
    /// Recording is for tests and tooling that need to inspect what a facade
    /// would have emitted. The backend never calls the provider, and it is
    /// leaked so that trace tokens can borrow it for `'static` like the native
    /// one. Each call leaks one backend, which a test process can afford.
    #[cfg(feature = "recording")]
    pub fn recording() -> &'static Self {
        Box::leak(Box::new(Self {
            recording: Some(Box::new(Recording::new())),
        }))
    }

    /// Return whether a tracepoint is enabled.
    #[inline]
    pub fn enabled(&self, tracepoint: S::Tracepoint) -> bool {
        #[cfg(feature = "recording")]
        if let Some(recording) = &self.recording {
            return recording.enabled(tracepoint);
        }
        S::enabled(tracepoint)
    }

    /// Return whether any of these tracepoints is enabled.
    ///
    /// A facade uses this to decide whether a lifecycle token is worth creating
    /// at all, since a token over nothing must not allocate or read the clock.
    #[inline]
    pub fn any_enabled(&self, tracepoints: &[S::Tracepoint]) -> bool {
        tracepoints
            .iter()
            .any(|tracepoint| self.enabled(*tracepoint))
    }

    /// Restrict a recording backend to a single tracepoint.
    ///
    /// Panics if this backend is bound to the native provider, which has no mask
    /// to restrict and reports enablement from the provider instead.
    #[cfg(feature = "recording")]
    pub fn enable_only(&self, tracepoint: S::Tracepoint) {
        self.sink().enable_only(tracepoint);
    }

    /// Enable or disable one tracepoint on a recording backend.
    ///
    /// Panics if this backend is bound to the native provider.
    #[cfg(feature = "recording")]
    pub fn set_enabled(&self, tracepoint: S::Tracepoint, enabled: bool) {
        self.sink().set_enabled(tracepoint, enabled);
    }

    /// Record an event, or emit it to the native provider.
    ///
    /// Enablement is checked here so that no call site can emit an event the
    /// provider did not ask for.
    #[inline]
    pub fn emit(&self, event: S::Event) {
        if !self.enabled(S::tracepoint(&event)) {
            return;
        }
        #[cfg(feature = "recording")]
        if let Some(recording) = &self.recording {
            recording
                .events
                .lock()
                .expect("the recording event list is never poisoned")
                .push(event);
            return;
        }
        S::emit(event);
    }

    /// Return the events a recording backend has retained, oldest first.
    ///
    /// Panics if this backend is bound to the native provider.
    #[cfg(feature = "recording")]
    pub fn events(&self) -> Vec<S::Event> {
        self.sink()
            .events
            .lock()
            .expect("the recording event list is never poisoned")
            .clone()
    }

    /// Allocate a process-wide trace identifier.
    #[inline]
    pub fn next_trace_id(&self) -> u64 {
        next_trace_id()
    }

    /// Allocate a process-wide phase span identifier.
    #[inline]
    pub fn next_span_id(&self) -> u64 {
        #[cfg(feature = "recording")]
        if let Some(recording) = &self.recording {
            recording.span_id_calls.fetch_add(1, Ordering::Relaxed);
        }
        next_span_id()
    }

    /// Return a monotonic timestamp in nanoseconds from the host clock.
    #[inline]
    pub fn now_ns(&self) -> u64 {
        #[cfg(feature = "recording")]
        if let Some(recording) = &self.recording {
            recording.clock_reads.fetch_add(1, Ordering::Relaxed);
        }
        now_ns()
    }

    /// Return how many span identifiers a recording backend has allocated.
    ///
    /// Panics if this backend is bound to the native provider.
    #[cfg(feature = "recording")]
    pub fn span_id_calls(&self) -> u64 {
        self.sink().span_id_calls.load(Ordering::Relaxed)
    }

    /// Return how many clock reads a recording backend has counted.
    ///
    /// Panics if this backend is bound to the native provider.
    #[cfg(feature = "recording")]
    pub fn clock_reads(&self) -> u64 {
        self.sink().clock_reads.load(Ordering::Relaxed)
    }

    /// Return the recording sink, which only exists for a recording backend.
    #[cfg(feature = "recording")]
    fn sink(&self) -> &Recording<S> {
        self.recording
            .as_deref()
            .expect("this backend is bound to the native provider")
    }
}
