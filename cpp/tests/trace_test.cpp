#include <time.h>

namespace {
unsigned clock_reads = 0;
int counted_clock_gettime(clockid_t clock, timespec* value) {
  ++clock_reads;
  return ::clock_gettime(clock, value);
}
}  // namespace

#define clock_gettime counted_clock_gettime
#include <quic_trace/trace.hpp>
#undef clock_gettime

#include <cassert>
#include <type_traits>

int main() {
  static_assert(!std::is_copy_constructible_v<quic_trace::Packet>);
  static_assert(std::is_move_constructible_v<quic_trace::Packet>);
  assert(quic_trace::next_connection_id() != quic_trace::next_connection_id());
  assert(quic_trace::now_ns() <= quic_trace::now_ns());

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
