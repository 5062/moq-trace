#include <moq_trace/trace.hpp>

#include <type_traits>

int main() {
  static_assert(!std::is_copy_constructible_v<moq_trace::Object>);
  static_assert(std::is_move_constructible_v<moq_trace::Object>);
  static_assert(!std::is_copy_constructible_v<moq_trace::ObjectPhase>);

  moq_trace::ObjectContext context;
  context.logical_id = {1, 2};
  context.identity = {3, 4, 5};
  context.session_id = moq_trace::next_session_id();
  context.connection_id = 6;
  context.stream_id = 7;
  context.stream_offset_start = 8;

  moq_trace::Object object(context);
  auto phase = object.phase(MOQ_TRACE_OBJECT_PHASE_PAYLOAD_READ);
  phase.finish(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS);
  object.set_payload_bytes(1024);
  object.set_stream_offset_end(1032);
  object.finish(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS);
  return 0;
}
