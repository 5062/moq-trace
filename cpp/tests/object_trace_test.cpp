#include <moq_trace/trace.hpp>

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
#include <utility>
#include <vector>

namespace {

using Intervals = std::vector<std::pair<std::uint64_t, std::uint64_t>>;

Intervals notify_of(const moq_trace::FanOutSpans& spans) {
  Intervals notify;
  spans.for_each_notify([&](std::uint64_t start_ns, std::uint64_t end_ns) {
    notify.emplace_back(start_ns, end_ns);
  });
  return notify;
}

// NOTIFY covers the fan-out minus each copy's work, and the copies never
// overlap it however they are reported.
void check_fan_out_spans() {
  assert(notify_of(moq_trace::FanOutSpans{}).empty());

  moq_trace::FanOutSpans spans(100);
  spans.exclude(110, 130);
  spans.exclude(125, 140);  // Overlaps the previous copy, so it is clamped.
  spans.exclude(90, 95);    // Precedes the clamped floor, so it is empty.
  spans.exclude(160, 170);
  assert(notify_of(spans).empty());  // Not closed yet.
  spans.close(180);
  spans.close(999);  // The first close wins.
  assert((notify_of(spans) == Intervals{{100, 110}, {140, 160}, {170, 180}}));

  // A copy that ends the fan-out leaves no trailing interval.
  moq_trace::FanOutSpans to_end(0);
  to_end.exclude(10, 20);
  to_end.close(20);
  assert((notify_of(to_end) == Intervals{{0, 10}}));

  // Exclusions beyond the capacity merge into the last one.
  moq_trace::FanOutSpans full(0);
  for (std::uint64_t i = 0; i < moq_trace::FanOutSpans::kCapacity + 2; ++i) {
    full.exclude(10 * i + 1, 10 * i + 2);
  }
  full.close(1000);
  const Intervals merged = notify_of(full);
  assert(merged.size() == moq_trace::FanOutSpans::kCapacity + 1);
  assert(merged.back().first == 10 * (moq_trace::FanOutSpans::kCapacity + 1) + 2);
}

// Scopes time a fan-out only while object phases are enabled, and nest.
void check_fan_out_scopes() {
  const bool enabled = moq_trace_moq_object_phase_enabled();
  assert(!moq_trace::FanOut::active());
  const auto before = clock_reads;
  {
    moq_trace::FanOut outer;
    assert(moq_trace::FanOut::active() == enabled);
    {
      moq_trace::CopyWork copy;
      copy.begin(quic_trace::now_ns());
      moq_trace::FanOut inner;
      inner.end();
      assert(moq_trace::FanOut::active() == enabled);
    }
    const moq_trace::FanOutSpans& spans = outer.end();
    assert(spans.start_ns().has_value() == enabled);
    assert(!moq_trace::FanOut::active());
    assert(&outer.end() == &spans);
  }
  if (!enabled) {
    // Outside a fan-out, CopyWork reads only the clock its caller passed.
    assert(clock_reads == before + 1);
  }
}

}  // namespace

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
  assert(object.records_phases() == moq_trace_moq_object_phase_enabled());
  assert(!moq_trace::Object(moq_trace::ObjectContext{}).records_phases() ||
         moq_trace_moq_object_phase_enabled());
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

  check_fan_out_spans();
  check_fan_out_scopes();
  return 0;
}
