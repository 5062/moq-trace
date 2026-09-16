//! The `quic_trace:*` schema on the shared backend seam.

use crate::{
    Direction, PacketContext, PacketOutcome, PacketPhase, PhaseEdge, SocketOutcome, SocketStats,
    StreamFrame,
};
use trace_core::{
    Backend as CoreBackend, Handle as CoreHandle, Schema, Tracepoint as CoreTracepoint,
};

/// The tracepoints the `quic_trace:*` schema exposes.
#[derive(Clone, Copy)]
pub(crate) enum Tracepoint {
    /// A QUIC packet trace started.
    PacketStart,
    /// A packet lifecycle phase started or completed.
    PacketPhase,
    /// A STREAM frame was carried by a packet.
    StreamFrame,
    /// A QUIC packet trace ended.
    PacketEnd,
    /// A UDP socket operation started.
    SocketStart,
    /// A UDP socket operation ended.
    SocketEnd,
}

impl CoreTracepoint for Tracepoint {
    fn index(self) -> u32 {
        self as u32
    }
}

/// One event in the `quic_trace:*` schema.
///
/// The native provider translates an event into the provider call of the same
/// name. A recording backend keeps the event as it was handed over, including
/// the timestamp taken at the emission site, so a test observes the values the
/// provider would have received.
#[cfg_attr(not(all(feature = "lttng", target_os = "linux")), allow(dead_code))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    /// A packet trace started with the metadata known up front.
    PacketStart {
        timestamp_ns: u64,
        trace_id: u64,
        context: PacketContext,
    },
    /// A packet trace ended with the metadata discovered during processing.
    PacketEnd {
        timestamp_ns: u64,
        trace_id: u64,
        context: PacketContext,
        outcome: PacketOutcome,
    },
    /// A packet phase started or completed.
    PacketPhase {
        timestamp_ns: u64,
        trace_id: u64,
        span_id: u64,
        phase: PacketPhase,
        edge: PhaseEdge,
        outcome: Option<PacketOutcome>,
    },
    /// A STREAM frame carried by a packet.
    StreamFrame {
        timestamp_ns: u64,
        trace_id: u64,
        frame: StreamFrame,
        outcome: PacketOutcome,
    },
    /// A UDP socket operation started.
    SocketStart {
        timestamp_ns: u64,
        trace_id: u64,
        direction: Direction,
        connection_id: Option<u64>,
    },
    /// A UDP socket operation ended.
    SocketEnd {
        timestamp_ns: u64,
        trace_id: u64,
        outcome: SocketOutcome,
        stats: SocketStats,
    },
}

/// The `quic_trace:*` schema.
pub(crate) enum TransportSchema {}

impl Schema for TransportSchema {
    type Tracepoint = Tracepoint;
    type Event = Event;

    fn initialize() {
        platform::initialize();
    }

    fn enabled(tracepoint: Tracepoint) -> bool {
        platform::enabled(tracepoint)
    }

    fn tracepoint(event: &Event) -> Tracepoint {
        match event {
            Event::PacketStart { .. } => Tracepoint::PacketStart,
            Event::PacketEnd { .. } => Tracepoint::PacketEnd,
            Event::PacketPhase { .. } => Tracepoint::PacketPhase,
            Event::StreamFrame { .. } => Tracepoint::StreamFrame,
            Event::SocketStart { .. } => Tracepoint::SocketStart,
            Event::SocketEnd { .. } => Tracepoint::SocketEnd,
        }
    }

    fn emit(event: Event) {
        platform::emit(event);
    }
}

/// A cheap, cloneable reference to the process-global transport backend.
pub(crate) type Handle = CoreHandle<TransportSchema>;

/// The transport provider of one process.
pub(crate) type Backend = CoreBackend<TransportSchema>;

/// Return whether this build can emit transport events.
pub(crate) const fn available() -> bool {
    cfg!(all(feature = "lttng", target_os = "linux"))
}

#[cfg(all(feature = "lttng", target_os = "linux"))]
mod platform {
    use quic_trace_lttng_sys as ffi;

    use super::*;

    pub(super) fn initialize() {
        unsafe { ffi::quic_trace_provider_init() };
    }

    pub(super) fn enabled(tracepoint: Tracepoint) -> bool {
        unsafe {
            match tracepoint {
                Tracepoint::PacketStart => ffi::quic_trace_quic_packet_start_enabled(),
                Tracepoint::PacketPhase => ffi::quic_trace_quic_packet_phase_enabled(),
                Tracepoint::StreamFrame => ffi::quic_trace_quic_stream_frame_enabled(),
                Tracepoint::PacketEnd => ffi::quic_trace_quic_packet_end_enabled(),
                Tracepoint::SocketStart => ffi::quic_trace_udp_socket_start_enabled(),
                Tracepoint::SocketEnd => ffi::quic_trace_udp_socket_end_enabled(),
            }
        }
    }

    pub(super) fn emit(event: Event) {
        match event {
            Event::PacketStart {
                timestamp_ns,
                trace_id,
                context,
            } => packet_start(timestamp_ns, trace_id, &context),
            Event::PacketEnd {
                timestamp_ns,
                trace_id,
                context,
                outcome,
            } => packet_end(timestamp_ns, trace_id, &context, outcome),
            Event::PacketPhase {
                timestamp_ns,
                trace_id,
                span_id,
                phase,
                edge,
                outcome,
            } => packet_phase(timestamp_ns, trace_id, span_id, phase, edge, outcome),
            Event::StreamFrame {
                timestamp_ns,
                trace_id,
                frame,
                outcome,
            } => stream_frame(timestamp_ns, trace_id, frame, outcome),
            Event::SocketStart {
                timestamp_ns,
                trace_id,
                direction,
                connection_id,
            } => socket_start(timestamp_ns, trace_id, direction, connection_id),
            Event::SocketEnd {
                timestamp_ns,
                trace_id,
                outcome,
                stats,
            } => socket_end(timestamp_ns, trace_id, outcome, stats),
        }
    }

    fn packet_start(timestamp_ns: u64, trace_id: u64, context: &PacketContext) {
        unsafe {
            let (has_packet_number, packet_number) = optional(context.packet_number);
            let (has_packet_space, packet_space) =
                optional_enum(context.packet_space, packet_space);
            let (has_byte_len, byte_len) = optional(context.byte_len.map(to_u64));
            ffi::quic_trace_quic_packet_start(&ffi::quic_trace_quic_packet_start {
                timestamp_ns,
                trace_id,
                connection_id: context.connection_id,
                direction: direction(context.direction),
                has_packet_number,
                packet_number,
                has_packet_space,
                packet_space,
                has_byte_len,
                byte_len,
            });
        }
    }

    fn packet_end(
        timestamp_ns: u64,
        trace_id: u64,
        context: &PacketContext,
        outcome: PacketOutcome,
    ) {
        unsafe {
            let (has_packet_number, packet_number) = optional(context.packet_number);
            let (has_packet_space, packet_space) =
                optional_enum(context.packet_space, packet_space);
            let (has_byte_len, byte_len) = optional(context.byte_len.map(to_u64));
            ffi::quic_trace_quic_packet_end(&ffi::quic_trace_quic_packet_end {
                timestamp_ns,
                trace_id,
                has_packet_number,
                packet_number,
                has_packet_space,
                packet_space,
                has_byte_len,
                byte_len,
                outcome: packet_outcome(outcome),
            });
        }
    }

    fn packet_phase(
        timestamp_ns: u64,
        trace_id: u64,
        span_id: u64,
        phase: PacketPhase,
        edge: PhaseEdge,
        outcome: Option<PacketOutcome>,
    ) {
        unsafe {
            let (has_outcome, outcome) = optional_enum(outcome, packet_outcome);
            ffi::quic_trace_quic_packet_phase(&ffi::quic_trace_quic_packet_phase {
                timestamp_ns,
                trace_id,
                span_id,
                phase: encode_packet_phase(phase),
                edge: encode_edge(edge),
                has_outcome,
                outcome,
            });
        }
    }

    fn stream_frame(timestamp_ns: u64, trace_id: u64, frame: StreamFrame, outcome: PacketOutcome) {
        unsafe {
            ffi::quic_trace_quic_stream_frame(&ffi::quic_trace_quic_stream_frame {
                timestamp_ns,
                trace_id,
                stream_id: frame.stream_id,
                offset_start: frame.offset_start,
                offset_end: frame.offset_end,
                outcome: packet_outcome(outcome),
            });
        }
    }

    fn socket_start(
        timestamp_ns: u64,
        trace_id: u64,
        direction_value: Direction,
        connection_id: Option<u64>,
    ) {
        unsafe {
            let (has_connection_id, connection_id) = optional(connection_id);
            ffi::quic_trace_udp_socket_start(&ffi::quic_trace_udp_socket_start {
                timestamp_ns,
                trace_id,
                has_connection_id,
                connection_id,
                direction: direction(direction_value),
            });
        }
    }

    fn socket_end(timestamp_ns: u64, trace_id: u64, outcome: SocketOutcome, stats: SocketStats) {
        unsafe {
            ffi::quic_trace_udp_socket_end(&ffi::quic_trace_udp_socket_end {
                timestamp_ns,
                trace_id,
                outcome: socket_outcome(outcome),
                buffers: to_u64(stats.buffers),
                datagrams: to_u64(stats.datagrams),
                bytes: to_u64(stats.bytes),
            });
        }
    }

    fn optional(value: Option<u64>) -> (u8, u64) {
        value.map_or((0, 0), |value| (1, value))
    }

    fn optional_enum<T>(value: Option<T>, convert: fn(T) -> u8) -> (u8, u8) {
        value.map_or((0, 0), |value| (1, convert(value)))
    }

    fn to_u64(value: usize) -> u64 {
        value.try_into().unwrap_or(u64::MAX)
    }

    fn direction(value: Direction) -> u8 {
        match value {
            Direction::Rx => ffi::quic_trace_direction_QUIC_TRACE_DIRECTION_RX as u8,
            Direction::Tx => ffi::quic_trace_direction_QUIC_TRACE_DIRECTION_TX as u8,
        }
    }

    fn encode_edge(value: PhaseEdge) -> u8 {
        match value {
            PhaseEdge::Start => ffi::quic_trace_edge_QUIC_TRACE_EDGE_START as u8,
            PhaseEdge::Done => ffi::quic_trace_edge_QUIC_TRACE_EDGE_DONE as u8,
        }
    }

    fn packet_space(value: crate::PacketSpace) -> u8 {
        match value {
            crate::PacketSpace::Initial => {
                ffi::quic_trace_packet_space_QUIC_TRACE_PACKET_SPACE_INITIAL as u8
            }
            crate::PacketSpace::Handshake => {
                ffi::quic_trace_packet_space_QUIC_TRACE_PACKET_SPACE_HANDSHAKE as u8
            }
            crate::PacketSpace::ZeroRtt => {
                ffi::quic_trace_packet_space_QUIC_TRACE_PACKET_SPACE_ZERO_RTT as u8
            }
            crate::PacketSpace::Data => {
                ffi::quic_trace_packet_space_QUIC_TRACE_PACKET_SPACE_DATA as u8
            }
        }
    }

    fn encode_packet_phase(value: PacketPhase) -> u8 {
        match value {
            PacketPhase::HeaderParse => {
                ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_HEADER_PARSE as u8
            }
            PacketPhase::Routing => {
                ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_ROUTING as u8
            }
            PacketPhase::Scheduling => {
                ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_SCHEDULING as u8
            }
            PacketPhase::HeaderUnprotect => {
                ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_HEADER_UNPROTECT as u8
            }
            PacketPhase::PayloadDecrypt => {
                ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_PAYLOAD_DECRYPT as u8
            }
            PacketPhase::FrameProcess => {
                ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_FRAME_PROCESS as u8
            }
            PacketPhase::FrameEncode => {
                ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_FRAME_ENCODE as u8
            }
            PacketPhase::PacketEncrypt => {
                ffi::quic_trace_packet_phase_QUIC_TRACE_PACKET_PHASE_PACKET_ENCRYPT as u8
            }
        }
    }

    fn packet_outcome(value: PacketOutcome) -> u8 {
        match value {
            PacketOutcome::Success => {
                ffi::quic_trace_packet_outcome_QUIC_TRACE_PACKET_OUTCOME_SUCCESS as u8
            }
            PacketOutcome::Malformed => {
                ffi::quic_trace_packet_outcome_QUIC_TRACE_PACKET_OUTCOME_MALFORMED as u8
            }
            PacketOutcome::AuthenticationFailed => {
                ffi::quic_trace_packet_outcome_QUIC_TRACE_PACKET_OUTCOME_AUTHENTICATION_FAILED as u8
            }
            PacketOutcome::Dropped => {
                ffi::quic_trace_packet_outcome_QUIC_TRACE_PACKET_OUTCOME_DROPPED as u8
            }
            PacketOutcome::Abandoned => {
                ffi::quic_trace_packet_outcome_QUIC_TRACE_PACKET_OUTCOME_ABANDONED as u8
            }
        }
    }

    fn socket_outcome(value: SocketOutcome) -> u8 {
        match value {
            SocketOutcome::Success => {
                ffi::quic_trace_socket_outcome_QUIC_TRACE_SOCKET_OUTCOME_SUCCESS as u8
            }
            SocketOutcome::Pending => {
                ffi::quic_trace_socket_outcome_QUIC_TRACE_SOCKET_OUTCOME_PENDING as u8
            }
            SocketOutcome::WouldBlock => {
                ffi::quic_trace_socket_outcome_QUIC_TRACE_SOCKET_OUTCOME_WOULD_BLOCK as u8
            }
            SocketOutcome::ConnectionReset => {
                ffi::quic_trace_socket_outcome_QUIC_TRACE_SOCKET_OUTCOME_CONNECTION_RESET as u8
            }
            SocketOutcome::Error => {
                ffi::quic_trace_socket_outcome_QUIC_TRACE_SOCKET_OUTCOME_ERROR as u8
            }
            SocketOutcome::Abandoned => {
                ffi::quic_trace_socket_outcome_QUIC_TRACE_SOCKET_OUTCOME_ABANDONED as u8
            }
        }
    }
}

#[cfg(not(all(feature = "lttng", target_os = "linux")))]
mod platform {
    use super::*;

    pub(super) fn initialize() {}

    pub(super) fn enabled(_: Tracepoint) -> bool {
        false
    }

    pub(super) fn emit(_: Event) {}
}
