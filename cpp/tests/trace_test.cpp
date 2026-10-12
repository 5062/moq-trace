#include <quic_trace/trace.hpp>

#include <cstdint>

// The test links with `--wrap=quic_trace_now_ns`, so every read of the shared
// clock the facade makes passes through here and can be counted.
extern "C" std::uint64_t __real_quic_trace_now_ns(void);

namespace {
unsigned clock_reads = 0;
}  // namespace

extern "C" std::uint64_t __wrap_quic_trace_now_ns(void) {
  ++clock_reads;
  return __real_quic_trace_now_ns();
}

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <type_traits>

int main() {
  static_assert(!std::is_copy_constructible_v<quic_trace::Packet>);
  static_assert(std::is_move_constructible_v<quic_trace::Packet>);
  assert(quic_trace::next_connection_id() != quic_trace::next_connection_id());
  assert(quic_trace::now_ns() <= quic_trace::now_ns());
  // Proves the wrap is live, so the counts below observe every clock read.
  assert(clock_reads == 2);

  quic_trace::PacketContext context;
  context.connection_id = 7;
  context.direction = QUIC_TRACE_DIRECTION_RX;
  quic_trace::Packet packet(context);
  packet.set_number(9);
  const auto before_phase = clock_reads;
  auto phase = packet.phase(QUIC_TRACE_PACKET_PHASE_PAYLOAD_DECRYPT);
  phase.finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
  if (!quic_trace_quic_packet_phase_enabled()) {
    assert(clock_reads == before_phase);
  }
  quic_trace::PacketPhase disabled_phase;
  const auto before_disabled_finish = clock_reads;
  disabled_phase.finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
  assert(clock_reads == before_disabled_finish);
  packet.stream_frame(3, 0, 1200, QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
  packet.finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);

  quic_trace::Socket socket(QUIC_TRACE_DIRECTION_TX, 7);
  socket.finish(QUIC_TRACE_SOCKET_OUTCOME_SUCCESS, {1, 1, 1200});

  // Socket-bounded lifecycles: an RX packet starts at its read's completion
  // and a TX packet ends at its send's completion, both captured once.
  const std::uint64_t read_ns = quic_trace::now_ns();
  quic_trace::PacketContext rx_context;
  rx_context.connection_id = 7;
  rx_context.start_ns = read_ns;
  quic_trace::Packet rx(rx_context);
  rx.phase_at(QUIC_TRACE_PACKET_PHASE_READ_QUEUE, read_ns)
      .finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
  rx.stream_frame_at(3, 0, 1200, QUIC_TRACE_PACKET_OUTCOME_SUCCESS, read_ns);
  rx.finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);

  quic_trace::PacketContext tx_context;
  tx_context.connection_id = 7;
  tx_context.direction = QUIC_TRACE_DIRECTION_TX;
  quic_trace::Packet tx(tx_context);
  auto queued = tx.phase(QUIC_TRACE_PACKET_PHASE_SEND_QUEUE);
  quic_trace::Socket send(QUIC_TRACE_DIRECTION_TX);
  const std::uint64_t sent_ns = quic_trace::now_ns();
  send.finish_at(QUIC_TRACE_SOCKET_OUTCOME_SUCCESS, {1, 1, 1200}, sent_ns);
  queued.finish_at(QUIC_TRACE_PACKET_OUTCOME_SUCCESS, sent_ns);
  tx.finish_at(QUIC_TRACE_PACKET_OUTCOME_SUCCESS, sent_ns);

  // A disabled packet records nothing and reads no clock.
  const auto before_disabled_packet = clock_reads;
  quic_trace::Packet disabled_packet;
  disabled_packet.phase(QUIC_TRACE_PACKET_PHASE_SEND_QUEUE)
      .finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
  disabled_packet.finish_at(QUIC_TRACE_PACKET_OUTCOME_SUCCESS, 1);
  assert(clock_reads == before_disabled_packet);

  const auto mapped = quic_trace::PathEndpoint::ipv4({10, 0, 0, 1}, 4443);
  assert(mapped.address[10] == 0xff && mapped.address[11] == 0xff);
  assert(mapped.address[12] == 10 && mapped.address[15] == 1);
  assert(quic_trace::detail::address_half(mapped.address, 0) == 0);
  assert(quic_trace::detail::address_half(mapped.address, 8) == 0x0000ffff0a000001ULL);
  std::array<std::uint8_t, 16> v6{0x20, 0x01, 0x0d, 0xb8};
  v6[15] = 7;
  const auto peer = quic_trace::PathEndpoint::ipv6(v6, 50266);
  assert(quic_trace::detail::address_half(peer.address, 0) == 0x20010db800000000ULL);
  assert(quic_trace::detail::address_half(peer.address, 8) == 7);
  const auto before_path = clock_reads;
  quic_trace::connection_path(7, mapped, peer);
  if (!quic_trace_quic_connection_path_enabled()) {
    assert(clock_reads == before_path);
  }

  // Socket addresses convert to the same endpoints as the explicit forms.
  sockaddr_in v4_address{};
  v4_address.sin_family = AF_INET;
  v4_address.sin_port = htons(4443);
  v4_address.sin_addr.s_addr = htonl(0x0a000001);
  const auto from_v4 = quic_trace::PathEndpoint::from_sockaddr(
      reinterpret_cast<const sockaddr*>(&v4_address));
  assert(from_v4.address == mapped.address && from_v4.port == 4443);
  sockaddr_in6 v6_address{};
  v6_address.sin6_family = AF_INET6;
  v6_address.sin6_port = htons(50266);
  std::memcpy(&v6_address.sin6_addr, v6.data(), v6.size());
  const auto from_v6 = quic_trace::PathEndpoint::from_sockaddr(
      reinterpret_cast<const sockaddr*>(&v6_address));
  assert(from_v6.address == peer.address && from_v6.port == 50266);
  sockaddr unspecified{};
  unspecified.sa_family = AF_UNSPEC;
  const auto unknown = quic_trace::PathEndpoint::from_sockaddr(&unspecified);
  const std::array<std::uint8_t, 16> unspecified_address{};
  assert(unknown.address == unspecified_address && unknown.port == 0);

  // The outcome is the system call's own result, before any stack policy.
  assert(quic_trace::socket_outcome(0) == QUIC_TRACE_SOCKET_OUTCOME_SUCCESS);
  assert(quic_trace::socket_outcome(EAGAIN) == QUIC_TRACE_SOCKET_OUTCOME_WOULD_BLOCK);
  assert(quic_trace::socket_outcome(ECONNRESET) ==
         QUIC_TRACE_SOCKET_OUTCOME_CONNECTION_RESET);
  assert(quic_trace::socket_outcome(ENOBUFS) == QUIC_TRACE_SOCKET_OUTCOME_ERROR);

  // A pending send holds only traced packets, and ends them with its outcome.
  static_assert(!std::is_copy_constructible_v<quic_trace::PendingSend>);
  quic_trace::PendingSend pending;
  quic_trace::PacketContext pending_context;
  pending_context.connection_id = 7;
  pending_context.direction = QUIC_TRACE_DIRECTION_TX;
  quic_trace::Packet pending_packet(pending_context);
  const bool traced = pending_packet.traced();
  pending.add(std::move(pending_packet));
  pending.add(quic_trace::Packet());
  assert(pending.empty() == !traced);
  quic_trace::PendingSend coalesced;
  coalesced.append(std::move(pending));
  assert(pending.empty());
  const auto before_dropped = clock_reads;
  coalesced.dropped(quic_trace::now_ns());
  assert(coalesced.empty());
  if (!traced) assert(clock_reads == before_dropped + 1);
}
