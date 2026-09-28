#ifndef QUIC_TRACE_TRACE_HPP
#define QUIC_TRACE_TRACE_HPP

#include <quic_trace/interface.h>

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <utility>

namespace quic_trace {

namespace detail {

inline std::once_flag provider_once;

inline void initialize() { std::call_once(provider_once, quic_trace_provider_init); }

// Identity and time come from the provider library rather than from this
// header, so Rust and C++ hooks in one process share the same counters and
// clock epoch instead of each allocating from its own.
inline std::uint64_t now_ns() { return quic_trace_now_ns(); }

}  // namespace detail

/** Return a timestamp from the host monotonic clock in nanoseconds. */
inline std::uint64_t now_ns() { return detail::now_ns(); }

/** Allocate a process-wide stable transport connection identifier. */
inline std::uint64_t next_connection_id() { return quic_trace_next_connection_id(); }

/** Metadata known when a QUIC packet trace starts. */
struct PacketContext {
  /** QUIC connection identifier associated with the packet. */
  std::uint64_t connection_id = 0;
  /** Direction at the local transport interface. */
  quic_trace_direction direction = QUIC_TRACE_DIRECTION_RX;
  /** Packet number, when known. */
  std::optional<std::uint64_t> packet_number;
  /** Packet number space, when known. */
  std::optional<quic_trace_packet_space> packet_space;
  /** Encoded packet length in bytes, when known. */
  std::optional<std::uint64_t> byte_len;
  /** Timestamp captured before the packet trace starts, when known. */
  std::optional<std::uint64_t> start_ns;
};

/** A scoped packet phase that records abandonment unless explicitly finished. */
class PacketPhase {
 public:
  /** Create a disabled phase. */
  PacketPhase() = default;

  PacketPhase(const PacketPhase&) = delete;
  PacketPhase& operator=(const PacketPhase&) = delete;

  /** Transfer ownership of a phase. */
  PacketPhase(PacketPhase&& other) noexcept { *this = std::move(other); }

  /** Transfer ownership after abandoning any currently held phase. */
  PacketPhase& operator=(PacketPhase&& other) noexcept {
    if (this != &other) {
      abandon();
      trace_id_ = std::exchange(other.trace_id_, 0);
      span_id_ = std::exchange(other.span_id_, 0);
      phase_ = other.phase_;
    }
    return *this;
  }

  /** Record abandonment when the phase leaves scope unfinished. */
  ~PacketPhase() { abandon(); }

  /** Finish the phase with an explicit result. */
  void finish(quic_trace_packet_outcome outcome) {
    if (span_id_ == 0) return;
    finish_at(outcome, detail::now_ns());
  }

  /** Finish the phase at a timestamp captured at the measured boundary. */
  void finish_at(quic_trace_packet_outcome outcome, std::uint64_t timestamp_ns) {
    if (span_id_ == 0) return;
    emit(timestamp_ns, QUIC_TRACE_EDGE_DONE, outcome);
    span_id_ = 0;
  }

 private:
  friend class Packet;

  PacketPhase(std::uint64_t trace_id, quic_trace_packet_phase phase,
              std::uint64_t timestamp_ns)
      : trace_id_(trace_id),
        span_id_(quic_trace_next_span_id()),
        phase_(phase) {
    emit(timestamp_ns, QUIC_TRACE_EDGE_START, std::nullopt);
  }

  void emit(std::uint64_t timestamp_ns, quic_trace_edge edge,
            std::optional<quic_trace_packet_outcome> outcome) const {
    const struct quic_trace_quic_packet_phase event{
        timestamp_ns,
        trace_id_,
        span_id_,
        static_cast<std::uint8_t>(phase_),
        static_cast<std::uint8_t>(edge),
        static_cast<std::uint8_t>(outcome.has_value()),
        static_cast<std::uint8_t>(outcome.value_or(QUIC_TRACE_PACKET_OUTCOME_SUCCESS)),
    };
    quic_trace_quic_packet_phase(&event);
  }

  void abandon() {
    if (span_id_ != 0) finish(QUIC_TRACE_PACKET_OUTCOME_ABANDONED);
  }

  std::uint64_t trace_id_ = 0;
  std::uint64_t span_id_ = 0;
  quic_trace_packet_phase phase_ = QUIC_TRACE_PACKET_PHASE_HEADER_PARSE;
};

/** A scoped QUIC packet that records abandonment unless explicitly finished. */
class Packet {
 public:
  /** Start a packet trace when any packet event is enabled. */
  explicit Packet(PacketContext context) : context_(context) {
    detail::initialize();
    if (!quic_trace_quic_packet_start_enabled() &&
        !quic_trace_quic_packet_end_enabled() &&
        !quic_trace_quic_packet_phase_enabled() &&
        !quic_trace_quic_stream_frame_enabled()) {
      return;
    }
    trace_id_ = quic_trace_next_trace_id();
    if (quic_trace_quic_packet_start_enabled()) emit_start();
  }

  Packet(const Packet&) = delete;
  Packet& operator=(const Packet&) = delete;

  /** Transfer ownership of a packet trace. */
  Packet(Packet&& other) noexcept { *this = std::move(other); }

  /** Transfer ownership after abandoning any currently held packet. */
  Packet& operator=(Packet&& other) noexcept {
    if (this != &other) {
      abandon();
      trace_id_ = std::exchange(other.trace_id_, 0);
      context_ = other.context_;
    }
    return *this;
  }

  /** Record abandonment when the packet leaves scope unfinished. */
  ~Packet() { abandon(); }

  /** Record a packet number discovered after processing begins. */
  void set_number(std::uint64_t value) { context_.packet_number = value; }

  /** Record a packet number space discovered after processing begins. */
  void set_space(quic_trace_packet_space value) { context_.packet_space = value; }

  /** Record the final encoded packet size. */
  void set_byte_len(std::uint64_t value) { context_.byte_len = value; }

  /** Start a measured packet phase. */
  PacketPhase phase(quic_trace_packet_phase value) const {
    if (trace_id_ == 0 || !quic_trace_quic_packet_phase_enabled()) return {};
    return PacketPhase(trace_id_, value, detail::now_ns());
  }

  /** Start a measured packet phase at a previously captured timestamp. */
  PacketPhase phase_at(quic_trace_packet_phase value,
                       std::uint64_t timestamp_ns) const {
    if (trace_id_ == 0 || !quic_trace_quic_packet_phase_enabled()) return {};
    return PacketPhase(trace_id_, value, timestamp_ns);
  }

  /** Associate a half-open STREAM byte range with this packet. */
  void stream_frame(std::uint64_t stream_id, std::uint64_t offset_start,
                    std::uint64_t offset_end,
                    quic_trace_packet_outcome outcome) const {
    if (trace_id_ == 0 || !quic_trace_quic_stream_frame_enabled()) return;
    const struct quic_trace_quic_stream_frame event{
        detail::now_ns(), trace_id_, stream_id, offset_start, offset_end,
        static_cast<std::uint8_t>(outcome)};
    quic_trace_quic_stream_frame(&event);
  }

  /** Finish the packet with an explicit result. */
  void finish(quic_trace_packet_outcome outcome) {
    if (trace_id_ == 0) return;
    if (quic_trace_quic_packet_end_enabled()) emit_end(outcome);
    trace_id_ = 0;
  }

 private:
  void emit_start() const {
    const struct quic_trace_quic_packet_start event{
        context_.start_ns ? *context_.start_ns : detail::now_ns(),
        trace_id_,
        context_.connection_id,
        static_cast<std::uint8_t>(context_.direction),
        static_cast<std::uint8_t>(context_.packet_number.has_value()),
        context_.packet_number.value_or(0),
        static_cast<std::uint8_t>(context_.packet_space.has_value()),
        static_cast<std::uint8_t>(context_.packet_space.value_or(QUIC_TRACE_PACKET_SPACE_INITIAL)),
        static_cast<std::uint8_t>(context_.byte_len.has_value()),
        context_.byte_len.value_or(0),
    };
    quic_trace_quic_packet_start(&event);
  }

  void emit_end(quic_trace_packet_outcome outcome) const {
    const struct quic_trace_quic_packet_end event{
        detail::now_ns(),
        trace_id_,
        static_cast<std::uint8_t>(context_.packet_number.has_value()),
        context_.packet_number.value_or(0),
        static_cast<std::uint8_t>(context_.packet_space.has_value()),
        static_cast<std::uint8_t>(context_.packet_space.value_or(QUIC_TRACE_PACKET_SPACE_INITIAL)),
        static_cast<std::uint8_t>(context_.byte_len.has_value()),
        context_.byte_len.value_or(0),
        static_cast<std::uint8_t>(outcome),
    };
    quic_trace_quic_packet_end(&event);
  }

  void abandon() {
    if (trace_id_ != 0) finish(QUIC_TRACE_PACKET_OUTCOME_ABANDONED);
  }

  std::uint64_t trace_id_ = 0;
  PacketContext context_;
};

/** Batch measurements produced by one UDP socket operation. */
struct SocketStats {
  /** Number of buffers processed by the operation. */
  std::uint64_t buffers = 0;
  /** Number of datagrams represented by those buffers. */
  std::uint64_t datagrams = 0;
  /** Total bytes represented by those buffers. */
  std::uint64_t bytes = 0;
};

/** A scoped UDP socket operation. */
class Socket {
 public:
  /** Start a socket trace when either socket event is enabled. */
  Socket(quic_trace_direction direction,
         std::optional<std::uint64_t> connection_id = std::nullopt)
      : direction_(direction), connection_id_(connection_id) {
    detail::initialize();
    if (!quic_trace_udp_socket_start_enabled() &&
        !quic_trace_udp_socket_end_enabled()) return;
    trace_id_ = quic_trace_next_trace_id();
    if (quic_trace_udp_socket_start_enabled()) emit_start();
  }

  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept { *this = std::move(other); }
  Socket& operator=(Socket&& other) noexcept {
    if (this != &other) {
      abandon();
      trace_id_ = std::exchange(other.trace_id_, 0);
      direction_ = other.direction_;
      connection_id_ = other.connection_id_;
    }
    return *this;
  }
  ~Socket() { abandon(); }

  /** Finish the socket operation with its result and batch measurements. */
  void finish(quic_trace_socket_outcome outcome, SocketStats stats = {}) {
    if (trace_id_ == 0) return;
    if (quic_trace_udp_socket_end_enabled()) {
      const struct quic_trace_udp_socket_end event{detail::now_ns(), trace_id_,
          static_cast<std::uint8_t>(outcome), stats.buffers, stats.datagrams,
          stats.bytes};
      quic_trace_udp_socket_end(&event);
    }
    trace_id_ = 0;
  }

 private:
  void emit_start() const {
    const struct quic_trace_udp_socket_start event{
        detail::now_ns(), trace_id_,
        static_cast<std::uint8_t>(connection_id_.has_value()),
        connection_id_.value_or(0), static_cast<std::uint8_t>(direction_)};
    quic_trace_udp_socket_start(&event);
  }

  void abandon() {
    if (trace_id_ != 0) finish(QUIC_TRACE_SOCKET_OUTCOME_ABANDONED);
  }

  std::uint64_t trace_id_ = 0;
  quic_trace_direction direction_ = QUIC_TRACE_DIRECTION_RX;
  std::optional<std::uint64_t> connection_id_;
};

}  // namespace quic_trace

#endif  // QUIC_TRACE_TRACE_HPP
