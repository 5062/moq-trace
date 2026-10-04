// Emit the same lifecycle fixture as the Rust facade_contract example.
#include <moq_trace/trace.hpp>

int main() {
  const auto connection = quic_trace::next_connection_id();
  const auto session = moq_trace::next_session_id();
  const auto logical = moq_trace::next_logical_id();
  std::array<std::uint8_t, 16> peer{0x20, 0x01, 0x0d, 0xb8};
  peer[15] = 2;
  quic_trace::connection_path(connection, quic_trace::PathEndpoint::ipv4({10, 0, 0, 1}, 4443),
                              quic_trace::PathEndpoint::ipv6(peer, 50000));
  for (const auto direction : {QUIC_TRACE_DIRECTION_RX, QUIC_TRACE_DIRECTION_TX}) {
    moq_trace::ObjectContext context;
    context.direction = direction;
    context.identity = {3, 4, 5};
    context.logical_id = logical;
    context.session_id = session;
    context.connection_id = connection;
    context.stream_id = 7;
    context.stream_offset_start = 8;
    context.start_ns = 100;
    moq_trace::Object object(context);
    for (const auto phase : {MOQ_TRACE_OBJECT_PHASE_HEADER_PARSE, MOQ_TRACE_OBJECT_PHASE_CREATE,
         MOQ_TRACE_OBJECT_PHASE_PAYLOAD_READ, MOQ_TRACE_OBJECT_PHASE_FRAME_COMMIT,
         MOQ_TRACE_OBJECT_PHASE_CLONE, MOQ_TRACE_OBJECT_PHASE_HEADER_ENCODE, MOQ_TRACE_OBJECT_PHASE_PAYLOAD_WRITE}) {
      object.phase(phase).finish(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS);
    }
    object.set_payload_bytes(1024);
    object.set_stream_offset_end(1032);
    object.finish(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS);
    moq_trace::ObjectContext empty;
    empty.direction = direction;
    {
      moq_trace::Object abandoned(empty);
      abandoned.phase(MOQ_TRACE_OBJECT_PHASE_CREATE);
    }
    moq_trace::Object failed(empty);
    failed.phase(MOQ_TRACE_OBJECT_PHASE_PAYLOAD_WRITE).finish(MOQ_TRACE_OBJECT_OUTCOME_FAILED);
    failed.finish(MOQ_TRACE_OBJECT_OUTCOME_FAILED);
    for (const auto space : {QUIC_TRACE_PACKET_SPACE_INITIAL, QUIC_TRACE_PACKET_SPACE_HANDSHAKE,
         QUIC_TRACE_PACKET_SPACE_ZERO_RTT, QUIC_TRACE_PACKET_SPACE_DATA}) {
      quic_trace::PacketContext packet_context;
      packet_context.direction = direction;
      packet_context.connection_id = connection;
      packet_context.packet_number = 9;
      packet_context.packet_space = space;
      packet_context.byte_len = 1200;
      packet_context.start_ns = 200;
      quic_trace::Packet packet(packet_context);
      for (const auto phase : {QUIC_TRACE_PACKET_PHASE_HEADER_PARSE, QUIC_TRACE_PACKET_PHASE_ROUTING,
           QUIC_TRACE_PACKET_PHASE_SCHEDULING, QUIC_TRACE_PACKET_PHASE_HEADER_UNPROTECT,
           QUIC_TRACE_PACKET_PHASE_PAYLOAD_DECRYPT, QUIC_TRACE_PACKET_PHASE_FRAME_PROCESS,
           QUIC_TRACE_PACKET_PHASE_FRAME_ENCODE, QUIC_TRACE_PACKET_PHASE_PACKET_ENCRYPT,
           QUIC_TRACE_PACKET_PHASE_APPLICATION, QUIC_TRACE_PACKET_PHASE_READ_QUEUE, QUIC_TRACE_PACKET_PHASE_SEND_QUEUE}) {
        packet.phase(phase).finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
      }
      packet.stream_frame(7, 8, 1032, QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
      packet.finish(QUIC_TRACE_PACKET_OUTCOME_SUCCESS);
    }
    quic_trace::PacketContext completed_context;
    completed_context.direction = direction;
    completed_context.connection_id = connection;
    completed_context.start_ns = 250;
    quic_trace::Packet completed(completed_context);
    completed.set_number(10);
    completed.set_space(QUIC_TRACE_PACKET_SPACE_DATA);
    completed.set_byte_len(1200);
    completed.phase_at(QUIC_TRACE_PACKET_PHASE_SEND_QUEUE, 300).finish_at(QUIC_TRACE_PACKET_OUTCOME_SUCCESS, 400);
    completed.stream_frame_at(7, 8, 1032, QUIC_TRACE_PACKET_OUTCOME_SUCCESS, 450);
    completed.finish_at(QUIC_TRACE_PACKET_OUTCOME_SUCCESS, 500);
    quic_trace::Socket socket(direction, connection);
    socket.finish_at(QUIC_TRACE_SOCKET_OUTCOME_SUCCESS, {1, 2, 1200}, 600);
    for (const auto outcome : {QUIC_TRACE_PACKET_OUTCOME_MALFORMED,
         QUIC_TRACE_PACKET_OUTCOME_AUTHENTICATION_FAILED, QUIC_TRACE_PACKET_OUTCOME_DROPPED}) {
      quic_trace::PacketContext packet_context;
      packet_context.direction = direction;
      packet_context.connection_id = connection;
      quic_trace::Packet packet(packet_context);
      packet.phase(QUIC_TRACE_PACKET_PHASE_FRAME_PROCESS).finish(outcome);
      packet.stream_frame(7, 8, 1032, outcome);
      packet.finish(outcome);
    }
    {
      quic_trace::PacketContext packet_context;
      packet_context.direction = direction;
      packet_context.connection_id = connection;
      quic_trace::Packet abandoned(packet_context);
      abandoned.phase(QUIC_TRACE_PACKET_PHASE_FRAME_PROCESS);
    }
    for (const auto outcome : {QUIC_TRACE_SOCKET_OUTCOME_SUCCESS, QUIC_TRACE_SOCKET_OUTCOME_PENDING,
         QUIC_TRACE_SOCKET_OUTCOME_WOULD_BLOCK, QUIC_TRACE_SOCKET_OUTCOME_CONNECTION_RESET, QUIC_TRACE_SOCKET_OUTCOME_ERROR}) {
      quic_trace::Socket socket(direction, connection);
      socket.finish(outcome, {1, 2, 1200});
    }
    quic_trace::Socket abandoned(direction);
  }
}
