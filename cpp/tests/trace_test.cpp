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

#include <cassert>
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
}
