use std::sync::atomic::Ordering;

use crate::{Direction, Handle, PacketSpace, now_ns};

/// Result of packet or packet-phase processing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum PacketOutcome {
    /// Processing completed successfully.
    Success,
    /// Input could not be parsed.
    Malformed,
    /// Packet authentication failed.
    AuthenticationFailed,
    /// Processing deliberately discarded the packet.
    Dropped,
    /// The trace token was dropped before an outcome was recorded.
    Abandoned,
}

/// A measured step in the QUIC packet lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum PacketPhase {
    /// Parse the protected packet header.
    HeaderParse,
    /// Route a decoded packet to its connection.
    Routing,
    /// Wait for the connection task to begin processing the packet.
    Scheduling,
    /// Remove QUIC header protection.
    HeaderUnprotect,
    /// Decrypt and authenticate the packet payload.
    PayloadDecrypt,
    /// Process one decoded QUIC frame.
    FrameProcess,
    /// Encode frames into a packet payload.
    FrameEncode,
    /// Encrypt the packet and apply header protection.
    PacketEncrypt,
}

/// Whether a packet phase record starts or completes work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhaseEdge {
    Start,
    Done,
}

/// Metadata known when a packet trace begins.
#[derive(Clone, Debug)]
#[cfg_attr(not(all(feature = "lttng", target_os = "linux")), allow(dead_code))]
pub struct PacketContext {
    pub(crate) connection_id: u64,
    pub(crate) direction: Direction,
    pub(crate) packet_number: Option<u64>,
    pub(crate) packet_space: Option<PacketSpace>,
    pub(crate) byte_len: Option<usize>,
    start_ns: Option<u64>,
}

impl PacketContext {
    /// Create packet metadata for one QUIC connection and direction.
    pub fn new(direction: Direction, connection_id: u64) -> Self {
        Self {
            connection_id,
            direction,
            packet_number: None,
            packet_space: None,
            byte_len: None,
            start_ns: None,
        }
    }

    /// Attach the QUIC packet number.
    pub fn with_number(mut self, number: u64) -> Self {
        self.packet_number = Some(number);
        self
    }

    /// Attach the QUIC packet number space.
    pub fn with_space(mut self, space: PacketSpace) -> Self {
        self.packet_space = Some(space);
        self
    }

    /// Attach the encoded packet length in bytes.
    pub fn with_byte_len(mut self, byte_len: usize) -> Self {
        self.byte_len = Some(byte_len);
        self
    }

    /// Attach a packet start timestamp captured before the trace was created.
    pub fn with_start_ns(mut self, start_ns: u64) -> Self {
        self.start_ns = Some(start_ns);
        self
    }
}

/// STREAM frame byte range carried by one QUIC packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamFrame {
    pub(crate) stream_id: u64,
    pub(crate) offset_start: u64,
    pub(crate) offset_end: u64,
}

impl StreamFrame {
    /// Create a STREAM frame mapping with an exclusive end offset.
    pub fn new(stream_id: u64, offset_start: u64, offset_end: u64) -> Self {
        Self {
            stream_id,
            offset_start,
            offset_end,
        }
    }
}

/// A QUIC packet whose completion consumes the token.
#[must_use = "dropping a packet trace records an abandoned packet"]
pub struct PacketTrace(Option<PacketTraceState>);

struct PacketTraceState {
    backend: crate::backend::Handle,
    trace_id: u64,
    context: PacketContext,
}

/// A packet phase whose completion consumes the token.
#[must_use = "dropping a packet phase records an abandoned phase"]
pub struct PacketPhaseTrace(Option<PacketPhaseTraceState>);

struct PacketPhaseTraceState {
    backend: crate::backend::Handle,
    trace_id: u64,
    span_id: u64,
    start_ns: u64,
    phase: PacketPhase,
}

impl Handle {
    /// Start a QUIC packet trace.
    pub fn packet(&self, context: PacketContext) -> PacketTrace {
        let Some(inner) = self.inner.as_ref() else {
            return PacketTrace::disabled();
        };
        if !inner.packet_enabled() {
            return PacketTrace::disabled();
        }
        let trace_id = crate::NEXT_TRACE_ID.fetch_add(1, Ordering::Relaxed);
        inner.packet_start(context.start_ns.unwrap_or_else(now_ns), trace_id, &context);
        PacketTrace(Some(PacketTraceState {
            backend: inner.clone(),
            trace_id,
            context,
        }))
    }
}

impl PacketTrace {
    /// Return a disabled packet trace token.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Record the packet number discovered during RX processing.
    pub fn set_number(&mut self, number: u64) {
        if let Some(state) = &mut self.0 {
            state.context.packet_number = Some(number);
        }
    }

    /// Record the packet number space discovered during RX processing.
    pub fn set_space(&mut self, space: PacketSpace) {
        if let Some(state) = &mut self.0 {
            state.context.packet_space = Some(space);
        }
    }

    /// Record the final encoded packet length.
    pub fn set_byte_len(&mut self, byte_len: usize) {
        if let Some(state) = &mut self.0 {
            state.context.byte_len = Some(byte_len);
        }
    }

    /// Start a measured packet lifecycle phase.
    pub fn phase(&self, phase: PacketPhase) -> PacketPhaseTrace {
        let Some(state) = &self.0 else {
            return PacketPhaseTrace::disabled();
        };
        if !state.backend.packet_phase_enabled() {
            return PacketPhaseTrace::disabled();
        }
        Self::start_phase_at(state, phase, now_ns())
    }

    /// Start a measured packet phase at a previously captured timestamp.
    pub fn phase_at(&self, phase: PacketPhase, timestamp_ns: u64) -> PacketPhaseTrace {
        let Some(state) = &self.0 else {
            return PacketPhaseTrace::disabled();
        };
        if !state.backend.packet_phase_enabled() {
            return PacketPhaseTrace::disabled();
        }
        Self::start_phase_at(state, phase, timestamp_ns)
    }

    fn start_phase_at(
        state: &PacketTraceState,
        phase: PacketPhase,
        timestamp_ns: u64,
    ) -> PacketPhaseTrace {
        let span_id = crate::next_span_id();
        state.backend.packet_phase(
            timestamp_ns,
            state.trace_id,
            span_id,
            phase,
            PhaseEdge::Start,
            None,
        );
        PacketPhaseTrace(Some(PacketPhaseTraceState {
            backend: state.backend.clone(),
            trace_id: state.trace_id,
            span_id,
            start_ns: timestamp_ns,
            phase,
        }))
    }

    /// Record a STREAM frame carried by this packet.
    pub fn stream_frame(&self, frame: StreamFrame, outcome: PacketOutcome) {
        let Some(state) = &self.0 else {
            return;
        };
        if !state.backend.stream_frame_enabled() {
            return;
        }
        state
            .backend
            .stream_frame(now_ns(), state.trace_id, frame, outcome);
    }

    /// Finish the packet with an explicit result.
    pub fn finish(mut self, outcome: PacketOutcome) {
        if let Some(state) = self.0.take() {
            state.emit_end(outcome);
        }
    }
}

impl PacketTraceState {
    fn emit_end(self, outcome: PacketOutcome) {
        self.backend
            .packet_end(now_ns(), self.trace_id, &self.context, outcome);
    }
}

impl Drop for PacketTrace {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            state.emit_end(PacketOutcome::Abandoned);
        }
    }
}

impl PacketPhaseTrace {
    fn disabled() -> Self {
        Self(None)
    }

    /// Finish the phase with an explicit result.
    pub fn finish(mut self, outcome: PacketOutcome) {
        if let Some(state) = self.0.take() {
            state.emit_done(outcome);
        }
    }

    /// Finish the phase at a previously captured timestamp.
    pub fn finish_at(mut self, outcome: PacketOutcome, timestamp_ns: u64) {
        if let Some(state) = self.0.take() {
            state.emit_done_at(outcome, timestamp_ns);
        }
    }
}

impl PacketPhaseTraceState {
    fn emit_done(self, outcome: PacketOutcome) {
        self.emit_done_at(outcome, now_ns());
    }

    fn emit_done_at(self, outcome: PacketOutcome, timestamp_ns: u64) {
        debug_assert!(timestamp_ns >= self.start_ns);
        self.backend.packet_phase(
            timestamp_ns,
            self.trace_id,
            self.span_id,
            self.phase,
            PhaseEdge::Done,
            Some(outcome),
        );
    }
}

impl Drop for PacketPhaseTrace {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            state.emit_done(PacketOutcome::Abandoned);
        }
    }
}
