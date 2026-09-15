//! LTTng-UST adapter at the instrumentation seam.

use crate::{
    Direction, PacketContext, PacketOutcome, PacketPhase, PhaseEdge, SocketOutcome, SocketStats,
    StreamFrame,
};

#[derive(Clone)]
pub(crate) enum Handle {
    Shared(&'static Backend),
    #[cfg(test)]
    Owned(std::sync::Arc<Backend>),
}

impl Handle {
    #[cfg(test)]
    pub(crate) fn owned(inner: Backend) -> Self {
        Self::Owned(std::sync::Arc::new(inner))
    }

    pub(crate) fn shared(inner: &'static Backend) -> Self {
        Self::Shared(inner)
    }
}

impl std::ops::Deref for Handle {
    type Target = Backend;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Shared(inner) => inner,
            #[cfg(test)]
            Self::Owned(inner) => inner,
        }
    }
}

pub(crate) struct Backend {
    #[cfg(test)]
    events: std::sync::Mutex<Vec<Event>>,
    #[cfg(test)]
    enabled: std::sync::atomic::AtomicU16,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum Tracepoint {
    PacketStart,
    PacketPhase,
    StreamFrame,
    PacketEnd,
    SocketStart,
    SocketEnd,
}

#[cfg(test)]
impl Tracepoint {
    const fn mask(self) -> u16 {
        1 << self as u16
    }
}

impl Backend {
    pub(crate) fn new() -> Self {
        #[cfg(not(test))]
        platform::initialize();
        Self {
            #[cfg(test)]
            events: std::sync::Mutex::new(Vec::new()),
            #[cfg(test)]
            enabled: std::sync::atomic::AtomicU16::new(u16::MAX),
        }
    }

    #[cfg(test)]
    pub(crate) fn enable_only(&self, tracepoint: Tracepoint) {
        self.enabled
            .store(tracepoint.mask(), std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn set_enabled(&self, tracepoint: Tracepoint, enabled: bool) {
        if enabled {
            self.enabled
                .fetch_or(tracepoint.mask(), std::sync::atomic::Ordering::Relaxed);
        } else {
            self.enabled
                .fetch_and(!tracepoint.mask(), std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    fn any_enabled(&self, tracepoints: &[Tracepoint]) -> bool {
        let enabled = self.enabled.load(std::sync::atomic::Ordering::Relaxed);
        tracepoints
            .iter()
            .any(|tracepoint| enabled & tracepoint.mask() != 0)
    }

    #[cfg(test)]
    fn enabled(&self, tracepoint: Tracepoint) -> bool {
        self.any_enabled(&[tracepoint])
    }

    pub(crate) fn packet_enabled(&self) -> bool {
        #[cfg(test)]
        return self.any_enabled(&[
            Tracepoint::PacketStart,
            Tracepoint::PacketPhase,
            Tracepoint::StreamFrame,
            Tracepoint::PacketEnd,
        ]);
        #[cfg(not(test))]
        platform::packet_enabled()
    }

    pub(crate) fn socket_enabled(&self) -> bool {
        #[cfg(test)]
        return self.any_enabled(&[Tracepoint::SocketStart, Tracepoint::SocketEnd]);
        #[cfg(not(test))]
        platform::socket_enabled()
    }

    pub(crate) fn packet_phase_enabled(&self) -> bool {
        #[cfg(test)]
        return self.enabled(Tracepoint::PacketPhase);
        #[cfg(not(test))]
        platform::packet_phase_enabled()
    }

    pub(crate) fn stream_frame_enabled(&self) -> bool {
        #[cfg(test)]
        return self.enabled(Tracepoint::StreamFrame);
        #[cfg(not(test))]
        platform::stream_frame_enabled()
    }

    pub(crate) fn packet_start(&self, _timestamp_ns: u64, trace_id: u64, context: &PacketContext) {
        #[cfg(test)]
        self.record(Event::PacketStart {
            trace_id,
            connection_id: context.connection_id,
            direction: context.direction,
        });
        #[cfg(not(test))]
        platform::packet_start(_timestamp_ns, trace_id, context);
    }

    pub(crate) fn packet_end(
        &self,
        _timestamp_ns: u64,
        trace_id: u64,
        context: &PacketContext,
        outcome: PacketOutcome,
    ) {
        #[cfg(test)]
        self.record(Event::PacketEnd {
            trace_id,
            packet_number: context.packet_number,
            packet_space: context.packet_space,
            byte_len: context.byte_len,
            outcome,
        });
        #[cfg(not(test))]
        platform::packet_end(_timestamp_ns, trace_id, context, outcome);
    }

    pub(crate) fn packet_phase(
        &self,
        _timestamp_ns: u64,
        trace_id: u64,
        span_id: u64,
        _phase: PacketPhase,
        _edge: PhaseEdge,
        _outcome: Option<PacketOutcome>,
    ) {
        #[cfg(test)]
        self.record(Event::PacketPhase { trace_id, span_id });
        #[cfg(not(test))]
        platform::packet_phase(_timestamp_ns, trace_id, span_id, _phase, _edge, _outcome);
    }

    pub(crate) fn stream_frame(
        &self,
        _timestamp_ns: u64,
        trace_id: u64,
        _frame: StreamFrame,
        _outcome: PacketOutcome,
    ) {
        #[cfg(test)]
        self.record(Event::StreamFrame { trace_id });
        #[cfg(not(test))]
        platform::stream_frame(_timestamp_ns, trace_id, _frame, _outcome);
    }

    pub(crate) fn socket_start(
        &self,
        _timestamp_ns: u64,
        trace_id: u64,
        _direction: Direction,
        _connection_id: Option<u64>,
    ) {
        #[cfg(test)]
        self.record(Event::SocketStart { trace_id });
        #[cfg(not(test))]
        platform::socket_start(_timestamp_ns, trace_id, _direction, _connection_id);
    }

    pub(crate) fn socket_end(
        &self,
        _timestamp_ns: u64,
        trace_id: u64,
        _outcome: SocketOutcome,
        _stats: SocketStats,
    ) {
        #[cfg(test)]
        self.record(Event::SocketEnd { trace_id });
        #[cfg(not(test))]
        platform::socket_end(_timestamp_ns, trace_id, _outcome, _stats);
    }

    #[cfg(test)]
    fn record(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }

    #[cfg(test)]
    pub(crate) fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

pub(crate) const fn available() -> bool {
    cfg!(all(feature = "lttng", target_os = "linux"))
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    PacketStart {
        trace_id: u64,
        connection_id: u64,
        direction: Direction,
    },
    PacketEnd {
        trace_id: u64,
        packet_number: Option<u64>,
        packet_space: Option<crate::PacketSpace>,
        byte_len: Option<usize>,
        outcome: PacketOutcome,
    },
    PacketPhase {
        trace_id: u64,
        span_id: u64,
    },
    StreamFrame {
        trace_id: u64,
    },
    SocketStart {
        trace_id: u64,
    },
    SocketEnd {
        trace_id: u64,
    },
}

#[cfg(test)]
impl Event {
    pub(crate) fn trace_id(&self) -> u64 {
        match *self {
            Self::PacketStart { trace_id, .. }
            | Self::PacketEnd { trace_id, .. }
            | Self::PacketPhase { trace_id, .. }
            | Self::StreamFrame { trace_id }
            | Self::SocketStart { trace_id }
            | Self::SocketEnd { trace_id } => trace_id,
        }
    }
}

#[cfg(all(feature = "lttng", target_os = "linux", not(test)))]
mod platform {
    use quic_trace_lttng_sys as ffi;

    use super::*;

    pub(super) fn initialize() {
        unsafe { ffi::quic_trace_provider_init() };
    }

    pub(super) fn packet_enabled() -> bool {
        unsafe {
            ffi::quic_trace_quic_packet_start_enabled()
                || ffi::quic_trace_quic_packet_phase_enabled()
                || ffi::quic_trace_quic_stream_frame_enabled()
                || ffi::quic_trace_quic_packet_end_enabled()
        }
    }

    pub(super) fn socket_enabled() -> bool {
        unsafe {
            ffi::quic_trace_udp_socket_start_enabled() || ffi::quic_trace_udp_socket_end_enabled()
        }
    }

    pub(super) fn packet_phase_enabled() -> bool {
        unsafe { ffi::quic_trace_quic_packet_phase_enabled() }
    }

    pub(super) fn stream_frame_enabled() -> bool {
        unsafe { ffi::quic_trace_quic_stream_frame_enabled() }
    }

    pub(super) fn packet_start(timestamp_ns: u64, trace_id: u64, context: &PacketContext) {
        unsafe {
            if !ffi::quic_trace_quic_packet_start_enabled() {
                return;
            }
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

    pub(super) fn packet_end(
        timestamp_ns: u64,
        trace_id: u64,
        context: &PacketContext,
        outcome: PacketOutcome,
    ) {
        unsafe {
            if !ffi::quic_trace_quic_packet_end_enabled() {
                return;
            }
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

    pub(super) fn packet_phase(
        timestamp_ns: u64,
        trace_id: u64,
        span_id: u64,
        phase: PacketPhase,
        edge: PhaseEdge,
        outcome: Option<PacketOutcome>,
    ) {
        unsafe {
            if !ffi::quic_trace_quic_packet_phase_enabled() {
                return;
            }
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

    pub(super) fn stream_frame(
        timestamp_ns: u64,
        trace_id: u64,
        frame: StreamFrame,
        outcome: PacketOutcome,
    ) {
        unsafe {
            if ffi::quic_trace_quic_stream_frame_enabled() {
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
    }

    pub(super) fn socket_start(
        timestamp_ns: u64,
        trace_id: u64,
        direction_value: Direction,
        connection_id: Option<u64>,
    ) {
        unsafe {
            if !ffi::quic_trace_udp_socket_start_enabled() {
                return;
            }
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

    pub(super) fn socket_end(
        timestamp_ns: u64,
        trace_id: u64,
        outcome: SocketOutcome,
        stats: SocketStats,
    ) {
        unsafe {
            if ffi::quic_trace_udp_socket_end_enabled() {
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

#[cfg(all(not(all(feature = "lttng", target_os = "linux")), not(test)))]
mod platform {
    use super::*;

    pub(super) fn initialize() {}
    pub(super) fn packet_enabled() -> bool {
        false
    }
    pub(super) fn socket_enabled() -> bool {
        false
    }
    pub(super) fn packet_phase_enabled() -> bool {
        false
    }
    pub(super) fn stream_frame_enabled() -> bool {
        false
    }
    pub(super) fn packet_start(_: u64, _: u64, _: &PacketContext) {}
    pub(super) fn packet_end(_: u64, _: u64, _: &PacketContext, _: PacketOutcome) {}
    pub(super) fn packet_phase(
        _: u64,
        _: u64,
        _: u64,
        _: PacketPhase,
        _: PhaseEdge,
        _: Option<PacketOutcome>,
    ) {
    }
    pub(super) fn stream_frame(_: u64, _: u64, _: StreamFrame, _: PacketOutcome) {}
    pub(super) fn socket_start(_: u64, _: u64, _: Direction, _: Option<u64>) {}
    pub(super) fn socket_end(_: u64, _: u64, _: SocketOutcome, _: SocketStats) {}
}
