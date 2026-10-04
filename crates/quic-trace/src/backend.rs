//! The `quic_trace:*` schema on the shared backend seam.
//!
//! The provider binding casts the public enums to their wire value, so the
//! declaration order of each enum is its encoding and must match the C enum in
//! `provider/interface.h`. Reordering variants changes the wire contract.

use crate::{
    ConnectionPath, Direction, PacketContext, PacketOutcome, PacketPhase, PhaseEdge, SocketOutcome,
    SocketStats, StreamFrame,
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
    /// A connection recorded the path it sends on.
    ConnectionPath,
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
    /// A connection recorded the path it sends on.
    ConnectionPath {
        timestamp_ns: u64,
        connection_id: u64,
        path: ConnectionPath,
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
            Event::ConnectionPath { .. } => Tracepoint::ConnectionPath,
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

    use trace_core::encode_optional;

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
                Tracepoint::ConnectionPath => ffi::quic_trace_quic_connection_path_enabled(),
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
            Event::ConnectionPath {
                timestamp_ns,
                connection_id,
                path,
            } => connection_path(timestamp_ns, connection_id, path),
        }
    }

    fn packet_start(timestamp_ns: u64, trace_id: u64, context: &PacketContext) {
        unsafe {
            let (has_packet_number, packet_number) = encode_optional(context.packet_number);
            let (has_packet_space, packet_space) =
                encode_optional(context.packet_space.map(|value| value as u8));
            let (has_byte_len, byte_len) = encode_optional(context.byte_len.map(to_u64));
            ffi::quic_trace_quic_packet_start(&ffi::quic_trace_quic_packet_start {
                timestamp_ns,
                trace_id,
                connection_id: context.connection_id,
                direction: context.direction as u8,
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
            let (has_packet_number, packet_number) = encode_optional(context.packet_number);
            let (has_packet_space, packet_space) =
                encode_optional(context.packet_space.map(|value| value as u8));
            let (has_byte_len, byte_len) = encode_optional(context.byte_len.map(to_u64));
            ffi::quic_trace_quic_packet_end(&ffi::quic_trace_quic_packet_end {
                timestamp_ns,
                trace_id,
                has_packet_number,
                packet_number,
                has_packet_space,
                packet_space,
                has_byte_len,
                byte_len,
                outcome: outcome as u8,
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
            let (has_outcome, outcome) = encode_optional(outcome.map(|value| value as u8));
            ffi::quic_trace_quic_packet_phase(&ffi::quic_trace_quic_packet_phase {
                timestamp_ns,
                trace_id,
                span_id,
                phase: phase as u8,
                edge: edge as u8,
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
                outcome: outcome as u8,
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
            let (has_connection_id, connection_id) = encode_optional(connection_id);
            ffi::quic_trace_udp_socket_start(&ffi::quic_trace_udp_socket_start {
                timestamp_ns,
                trace_id,
                has_connection_id,
                connection_id,
                direction: direction_value as u8,
            });
        }
    }

    fn socket_end(timestamp_ns: u64, trace_id: u64, outcome: SocketOutcome, stats: SocketStats) {
        unsafe {
            ffi::quic_trace_udp_socket_end(&ffi::quic_trace_udp_socket_end {
                timestamp_ns,
                trace_id,
                outcome: outcome as u8,
                buffers: to_u64(stats.buffers),
                datagrams: to_u64(stats.datagrams),
                bytes: to_u64(stats.bytes),
            });
        }
    }

    fn connection_path(timestamp_ns: u64, connection_id: u64, path: ConnectionPath) {
        let local = crate::path::address_bits(path.local.ip());
        let peer = crate::path::address_bits(path.peer.ip());
        unsafe {
            ffi::quic_trace_quic_connection_path(&ffi::quic_trace_quic_connection_path {
                timestamp_ns,
                connection_id,
                local_address_high: (local >> 64) as u64,
                local_address_low: local as u64,
                local_port: path.local.port(),
                peer_address_high: (peer >> 64) as u64,
                peer_address_low: peer as u64,
                peer_port: path.peer.port(),
            });
        }
    }

    fn to_u64(value: usize) -> u64 {
        value.try_into().unwrap_or(u64::MAX)
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
