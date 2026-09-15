#include "trace.hpp"

#include <type_traits>

int main() {
  static_assert(!std::is_copy_constructible_v<quic_trace::Packet>);
  static_assert(std::is_move_constructible_v<quic_trace::Packet>);

  quic_trace::PacketContext context;
  context.connection_id = 7;
  context.direction = QUIC_TRACE_DIRECTION_RX;
  quic_trace::Packet packet(context);
  packet.set_number(9);
  auto phase = packet.phase(QUIC_TRACE_PACKET_PHASE_PAYLOAD_DECRYPT);
  phase.finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
  packet.stream_frame(3, 0, 1200, QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
  packet.finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);

  quic_trace::Socket socket(QUIC_TRACE_DIRECTION_TX, 7);
  socket.finish(QUIC_TRACE_SOCKET_OUTCOME_SUCCESS, {1, 1, 1200});
}
