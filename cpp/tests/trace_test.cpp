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
}
