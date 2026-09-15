#include <moq_trace/trace.hpp>
#include <quic_trace/trace.hpp>

int main() {
  moq_trace::ObjectContext context;
  context.logical_id = {1, 2};
  context.identity = {3, 4, 5};

  moq_trace::Object object(context);
  object.finish(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS);

  quic_trace::Socket socket(QUIC_TRACE_DIRECTION_RX, std::nullopt);
  socket.finish(QUIC_TRACE_SOCKET_OUTCOME_SUCCESS);
  return 0;
}
