#include <time.h>

namespace {
unsigned clock_reads = 0;
int counted_clock_gettime(clockid_t clock, timespec* value) {
  ++clock_reads;
  return ::clock_gettime(clock, value);
}
}  // namespace

#define clock_gettime counted_clock_gettime
#include <moq_trace/trace.hpp>
#undef clock_gettime

#include <cassert>
#include <type_traits>

int main() {
  static_assert(!std::is_copy_constructible_v<moq_trace::Object>);
  static_assert(std::is_move_constructible_v<moq_trace::Object>);
  static_assert(!std::is_copy_constructible_v<moq_trace::ObjectPhase>);
  assert(!(moq_trace::next_logical_id() == moq_trace::next_logical_id()));

  moq_trace::ObjectContext context;
  context.logical_id = {1, 2};
  context.identity = {3, 4, 5};
  context.session_id = moq_trace::next_session_id();
  context.connection_id = 6;
  context.stream_id = 7;
  context.stream_offset_start = 8;
  context.start_ns = 9;

  moq_trace::Object object(context);
  const auto before_phase = clock_reads;
  auto phase = object.phase(MOQ_TRACE_OBJECT_PHASE_PAYLOAD_READ);
  phase.finish(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS);
  if (!moq_trace_moq_object_phase_enabled()) {
    assert(clock_reads == before_phase);
  }
  moq_trace::ObjectPhase disabled_phase;
  const auto before_disabled_finish = clock_reads;
  disabled_phase.finish(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS);
  assert(clock_reads == before_disabled_finish);
  object.set_payload_bytes(1024);
  object.set_stream_offset_end(1032);
  object.finish(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS);
  return 0;
}
