use crate::backend::{Event, Tracepoint};
use crate::{Direction, Handle, PacketSpace, PhaseEdge};

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
    /// Run application callbacks the transport invokes synchronously while it
    /// processes an inbound packet.
    ///
    /// A stack that hands data to the application after packet processing
    /// returns never records this phase. The interval does not overlap the
    /// packet's other phases, so subtracting it leaves the transport's own
    /// share of the packet lifecycle.
    Application,
    /// Wait from the completion of the socket read that returned the packet's
    /// datagram until the packet's processing begins.
    ///
    /// An RX packet starts at that read's completion, so this phase starts at
    /// the packet start. Packets from one read wait at once, so their
    /// intervals overlap.
    ReadQueue,
    /// Wait from the end of packet encryption until the socket send that
    /// accepts the packet's datagram completes.
    ///
    /// A TX packet ends at that send's completion, so this phase ends at the
    /// packet end. It includes the send system call, which every packet in
    /// the batch shares.
    SendQueue,
}

/// Metadata known when a packet trace begins.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub(crate) retransmission: Option<bool>,
}

impl StreamFrame {
    /// Create a STREAM frame mapping with an exclusive end offset.
    pub fn new(stream_id: u64, offset_start: u64, offset_end: u64) -> Self {
        Self {
            stream_id,
            offset_start,
            offset_end,
            retransmission: None,
        }
    }

    /// Mark whether a TX frame resends bytes an earlier packet carried.
    ///
    /// A sender knows this when it builds the frame. A receiver cannot tell a
    /// repair from a first transmission, so an RX frame leaves it unset.
    pub fn with_retransmission(mut self, retransmission: bool) -> Self {
        self.retransmission = Some(retransmission);
        self
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

/// The tracepoints a packet trace token covers.
const PACKET_TRACEPOINTS: [Tracepoint; 4] = [
    Tracepoint::PacketStart,
    Tracepoint::PacketPhase,
    Tracepoint::StreamFrame,
    Tracepoint::PacketEnd,
];

impl Handle {
    /// Start a QUIC packet trace.
    pub fn packet(&self, context: PacketContext) -> PacketTrace {
        let Some(inner) = self.inner.as_ref() else {
            return PacketTrace::disabled();
        };
        if !inner.any_enabled(&PACKET_TRACEPOINTS) {
            return PacketTrace::disabled();
        }
        let trace_id = inner.next_trace_id();
        let timestamp_ns = context.start_ns.unwrap_or_else(|| inner.now_ns());
        inner.emit(Event::PacketStart {
            timestamp_ns,
            trace_id,
            context: context.clone(),
        });
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
        self.start_phase(phase, None)
    }

    /// Start a measured packet phase at a previously captured timestamp.
    pub fn phase_at(&self, phase: PacketPhase, timestamp_ns: u64) -> PacketPhaseTrace {
        self.start_phase(phase, Some(timestamp_ns))
    }

    /// Start a phase at `timestamp_ns`, or at the current time when it is absent.
    ///
    /// The clock is read only after enablement is checked, so a disabled phase
    /// costs no clock read.
    fn start_phase(&self, phase: PacketPhase, timestamp_ns: Option<u64>) -> PacketPhaseTrace {
        let Some(state) = &self.0 else {
            return PacketPhaseTrace::disabled();
        };
        if !state.backend.enabled(Tracepoint::PacketPhase) {
            return PacketPhaseTrace::disabled();
        }
        let timestamp_ns = timestamp_ns.unwrap_or_else(|| state.backend.now_ns());
        let span_id = state.backend.next_span_id();
        state.backend.emit(Event::PacketPhase {
            timestamp_ns,
            trace_id: state.trace_id,
            span_id,
            phase,
            edge: PhaseEdge::Start,
            outcome: None,
        });
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
        self.emit_stream_frame(frame, outcome, None);
    }

    /// Record a STREAM frame at a previously captured timestamp.
    ///
    /// An RX frame's timestamp is the instant the stream's receive buffer
    /// accepted its bytes. A stack that learns the outcome only later stamps
    /// that instant and records the frame afterwards with this method.
    pub fn stream_frame_at(&self, frame: StreamFrame, outcome: PacketOutcome, timestamp_ns: u64) {
        self.emit_stream_frame(frame, outcome, Some(timestamp_ns));
    }

    /// Record a STREAM frame at `timestamp_ns`, or at the current time when it is absent.
    ///
    /// The clock is read only after enablement is checked, so a disabled frame
    /// costs no clock read.
    fn emit_stream_frame(
        &self,
        frame: StreamFrame,
        outcome: PacketOutcome,
        timestamp_ns: Option<u64>,
    ) {
        let Some(state) = &self.0 else {
            return;
        };
        if !state.backend.enabled(Tracepoint::StreamFrame) {
            return;
        }
        state.backend.emit(Event::StreamFrame {
            timestamp_ns: timestamp_ns.unwrap_or_else(|| state.backend.now_ns()),
            trace_id: state.trace_id,
            frame,
            outcome,
        });
    }

    /// Finish the packet with an explicit result.
    pub fn finish(mut self, outcome: PacketOutcome) {
        if let Some(state) = self.0.take() {
            state.emit_end(outcome, None);
        }
    }

    /// Finish the packet at a previously captured timestamp.
    ///
    /// Every packet one socket send carried ends at that send's completion,
    /// so a stack captures the completion once and ends each packet with it.
    pub fn finish_at(mut self, outcome: PacketOutcome, timestamp_ns: u64) {
        if let Some(state) = self.0.take() {
            state.emit_end(outcome, Some(timestamp_ns));
        }
    }
}

impl PacketTraceState {
    fn emit_end(self, outcome: PacketOutcome, timestamp_ns: Option<u64>) {
        let Self {
            backend,
            trace_id,
            context,
        } = self;
        backend.emit(Event::PacketEnd {
            timestamp_ns: timestamp_ns.unwrap_or_else(|| backend.now_ns()),
            trace_id,
            context,
            outcome,
        });
    }
}

impl Drop for PacketTrace {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            state.emit_end(PacketOutcome::Abandoned, None);
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
        let timestamp_ns = self.backend.now_ns();
        self.emit_done_at(outcome, timestamp_ns);
    }

    fn emit_done_at(self, outcome: PacketOutcome, timestamp_ns: u64) {
        debug_assert!(timestamp_ns >= self.start_ns);
        self.backend.emit(Event::PacketPhase {
            timestamp_ns,
            trace_id: self.trace_id,
            span_id: self.span_id,
            phase: self.phase,
            edge: PhaseEdge::Done,
            outcome: Some(outcome),
        });
    }
}

impl Drop for PacketPhaseTrace {
    fn drop(&mut self) {
        if let Some(state) = self.0.take() {
            state.emit_done(PacketOutcome::Abandoned);
        }
    }
}
