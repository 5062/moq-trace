#ifndef QUIC_TRACE_TRACE_HPP
#define QUIC_TRACE_TRACE_HPP

#include <quic_trace/interface.h>

#include <array>
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
  /**
   * Create a disabled packet that records nothing, for work that must not
   * start a lifecycle, such as re-serializing a packet already traced.
   */
  Packet() = default;

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

  /**
   * Associate a half-open STREAM byte range with this packet.
   *
   * A sender passes `retransmission` to say whether the frame resends bytes an
   * earlier packet carried. A receiver cannot tell, so it leaves it unset.
   */
  void stream_frame(std::uint64_t stream_id, std::uint64_t offset_start,
                    std::uint64_t offset_end, quic_trace_packet_outcome outcome,
                    std::optional<bool> retransmission = std::nullopt) const {
    if (trace_id_ == 0 || !quic_trace_quic_stream_frame_enabled()) return;
    emit_stream_frame(detail::now_ns(), stream_id, offset_start, offset_end,
                      outcome, retransmission);
  }

  /**
   * Associate a STREAM byte range with this packet at a captured timestamp.
   *
   * An RX frame's timestamp is the instant the stream's receive buffer accepted
   * its bytes. A stack that learns the outcome only later stamps that instant
   * and records the frame afterwards with this method.
   */
  void stream_frame_at(std::uint64_t stream_id, std::uint64_t offset_start,
                       std::uint64_t offset_end,
                       quic_trace_packet_outcome outcome,
                       std::uint64_t timestamp_ns,
                       std::optional<bool> retransmission = std::nullopt) const {
    if (trace_id_ == 0 || !quic_trace_quic_stream_frame_enabled()) return;
    emit_stream_frame(timestamp_ns, stream_id, offset_start, offset_end, outcome,
                      retransmission);
  }

  /** Finish the packet with an explicit result. */
  void finish(quic_trace_packet_outcome outcome) {
    if (trace_id_ == 0) return;
    if (quic_trace_quic_packet_end_enabled()) emit_end(detail::now_ns(), outcome);
    trace_id_ = 0;
  }

  /**
   * Finish the packet at a captured timestamp.
   *
   * Every packet one socket send carried ends at that send's completion, so a
   * stack captures the completion once and ends each packet with it.
   */
  void finish_at(quic_trace_packet_outcome outcome, std::uint64_t timestamp_ns) {
    if (trace_id_ == 0) return;
    if (quic_trace_quic_packet_end_enabled()) emit_end(timestamp_ns, outcome);
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

  void emit_stream_frame(std::uint64_t timestamp_ns, std::uint64_t stream_id,
                         std::uint64_t offset_start, std::uint64_t offset_end,
                         quic_trace_packet_outcome outcome,
                         std::optional<bool> retransmission) const {
    const struct quic_trace_quic_stream_frame event{
        timestamp_ns,
        trace_id_,
        stream_id,
        offset_start,
        offset_end,
        static_cast<std::uint8_t>(outcome),
        static_cast<std::uint8_t>(retransmission.has_value()),
        static_cast<std::uint8_t>(retransmission.value_or(false)),
    };
    quic_trace_quic_stream_frame(&event);
  }

  void emit_end(std::uint64_t timestamp_ns, quic_trace_packet_outcome outcome) const {
    const struct quic_trace_quic_packet_end event{
        timestamp_ns,
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

/**
 * An interval in which a connection cannot send, ended by `finish()` or scope.
 *
 * A stack keeps one per reason while the condition holds: per connection for
 * the transmit reasons, and per stream for a blocked write. Destroying it, for
 * example when the connection closes, ends the interval at that instant.
 */
class SendBlocked {
 public:
  /** Create an object that records nothing. */
  SendBlocked() = default;

  /**
   * Start an interval in which `connection_id` cannot send for `reason`.
   *
   * Pass the stream a blocked write targets, or nothing when the connection as
   * a whole cannot transmit.
   */
  SendBlocked(std::uint64_t connection_id, quic_trace_send_blocked_reason reason,
              std::optional<std::uint64_t> stream_id = std::nullopt)
      : connection_id_(connection_id), stream_id_(stream_id), reason_(reason) {
    detail::initialize();
    if (!quic_trace_quic_send_blocked_enabled()) return;
    span_id_ = quic_trace_next_span_id();
    emit(QUIC_TRACE_EDGE_START);
  }

  SendBlocked(const SendBlocked&) = delete;
  SendBlocked& operator=(const SendBlocked&) = delete;

  /** Transfer ownership of an interval. */
  SendBlocked(SendBlocked&& other) noexcept { *this = std::move(other); }

  /** Transfer ownership after ending any currently held interval. */
  SendBlocked& operator=(SendBlocked&& other) noexcept {
    if (this != &other) {
      finish();
      span_id_ = std::exchange(other.span_id_, 0);
      connection_id_ = other.connection_id_;
      stream_id_ = other.stream_id_;
      reason_ = other.reason_;
    }
    return *this;
  }

  /** End the interval when the object leaves scope. */
  ~SendBlocked() { finish(); }

  /** Return whether this object records an open interval. */
  bool active() const { return span_id_ != 0; }

  /** End the interval now, when the connection can send again. */
  void finish() {
    if (span_id_ == 0) return;
    emit(QUIC_TRACE_EDGE_DONE);
    span_id_ = 0;
  }

 private:
  void emit(quic_trace_edge edge) const {
    const struct quic_trace_quic_send_blocked event{
        detail::now_ns(),
        span_id_,
        connection_id_,
        static_cast<std::uint8_t>(stream_id_.has_value()),
        stream_id_.value_or(0),
        static_cast<std::uint8_t>(reason_),
        static_cast<std::uint8_t>(edge),
    };
    quic_trace_quic_send_blocked(&event);
  }

  std::uint64_t span_id_ = 0;
  std::uint64_t connection_id_ = 0;
  std::optional<std::uint64_t> stream_id_;
  quic_trace_send_blocked_reason reason_ = QUIC_TRACE_SEND_BLOCKED_REASON_CONGESTION_WINDOW;
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
    // A disabled end event costs no clock read.
    if (!quic_trace_udp_socket_end_enabled()) {
      trace_id_ = 0;
      return;
    }
    finish_at(outcome, stats, detail::now_ns());
  }

  /**
   * Finish the socket operation at a captured timestamp.
   *
   * A provider reads the clock immediately after the system call returns and
   * ends both this operation and the packets it carried at that instant, so the
   * socket event and the packets agree exactly.
   */
  void finish_at(quic_trace_socket_outcome outcome, SocketStats stats,
                 std::uint64_t timestamp_ns) {
    if (trace_id_ == 0) return;
    if (quic_trace_udp_socket_end_enabled()) {
      const struct quic_trace_udp_socket_end event{timestamp_ns, trace_id_,
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

/**
 * One end of a connection path.
 *
 * The address is IPv6 in network byte order, with IPv4 written as IPv4-mapped
 * IPv6 (::ffff:a.b.c.d), so one form covers both families.
 */
struct PathEndpoint {
  /** IPv6 address bytes in network byte order. */
  std::array<std::uint8_t, 16> address{};
  /** Port in host byte order. */
  std::uint16_t port = 0;

  /** Describe an IPv4 endpoint from its address bytes in network byte order. */
  static PathEndpoint ipv4(const std::array<std::uint8_t, 4>& address,
                           std::uint16_t port) {
    PathEndpoint endpoint;
    endpoint.address[10] = 0xff;
    endpoint.address[11] = 0xff;
    for (std::size_t i = 0; i < address.size(); ++i) endpoint.address[12 + i] = address[i];
    endpoint.port = port;
    return endpoint;
  }

  /** Describe an IPv6 endpoint from its address bytes in network byte order. */
  static PathEndpoint ipv6(const std::array<std::uint8_t, 16>& address,
                           std::uint16_t port) {
    PathEndpoint endpoint;
    endpoint.address = address;
    endpoint.port = port;
    return endpoint;
  }
};

namespace detail {

/** Read eight address bytes as one big-endian integer. */
inline std::uint64_t address_half(const std::array<std::uint8_t, 16>& address,
                                  std::size_t offset) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | address[offset + i];
  return value;
}

}  // namespace detail

/**
 * Record the path a connection sends on.
 *
 * A stack records the path when it creates a connection and again whenever the
 * path changes, such as after a validated migration. Each event holds until the
 * connection's next one, which lets analysis join the connection's packets to a
 * packet capture by address. The local address may be the wildcard address
 * when the socket is bound to it and the stack does not learn the address the
 * kernel chose.
 */
inline void connection_path(std::uint64_t connection_id, const PathEndpoint& local,
                            const PathEndpoint& peer) {
  detail::initialize();
  if (!quic_trace_quic_connection_path_enabled()) return;
  const struct quic_trace_quic_connection_path event{
      detail::now_ns(),
      connection_id,
      detail::address_half(local.address, 0),
      detail::address_half(local.address, 8),
      local.port,
      detail::address_half(peer.address, 0),
      detail::address_half(peer.address, 8),
      peer.port,
  };
  quic_trace_quic_connection_path(&event);
}

}  // namespace quic_trace

#endif  // QUIC_TRACE_TRACE_HPP
