#ifndef MOQ_TRACE_TRACE_HPP
#define MOQ_TRACE_TRACE_HPP

#include <moq_trace/interface.h>

#include <quic_trace/trace.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

namespace moq_trace {

/** Identity shared by ingress and every outbound copy of one logical object. */
struct LogicalId {
  /** Process-local group instance shared by every object copy. */
  std::uint64_t group = 0;
  /** Frame ordinal within the logical group. */
  std::uint64_t frame = 0;

  /** Compare both components of a logical object identity. */
  bool operator==(const LogicalId& other) const {
    return group == other.group && frame == other.frame;
  }
};

/**
 * Allocate a process-wide logical group instance, starting at frame zero.
 *
 * The group comes from the provider library, so Rust and C++ hooks in one
 * process never hand out the same one.
 */
inline LogicalId next_logical_id() { return {moq_trace_next_logical_group(), 0}; }

/** Stable wire identity of one MoQ transport object. */
struct ObjectIdentity {
  /** MoQ track alias carrying the object. */
  std::uint64_t track_alias = 0;
  /** Wire group identifier. */
  std::uint64_t group_id = 0;
  /** Wire object identifier within the group. */
  std::uint64_t object_id = 0;
};

/** Metadata known when a MoQ object trace starts. */
struct ObjectContext {
  /** Logical identity shared by ingress and outbound copies. */
  LogicalId logical_id;
  /** Wire identity of this object. */
  ObjectIdentity identity;
  /** Direction at the MoQ transport interface. */
  quic_trace_direction direction = QUIC_TRACE_DIRECTION_RX;
  /** Session identifier, when the relay has one. */
  std::optional<std::uint64_t> session_id;
  /** QUIC connection identifier, when known. */
  std::optional<std::uint64_t> connection_id;
  /** Unidirectional stream carrying the object, when known. */
  std::optional<std::uint64_t> stream_id;
  /** Inclusive stream offset where the object starts, when known. */
  std::optional<std::uint64_t> stream_offset_start;
  /** Timestamp captured before the remaining object context was known. */
  std::optional<std::uint64_t> start_ns;
  /** Payload size known before the object trace starts. */
  std::uint64_t payload_bytes = 0;
};

/** A scoped object phase that records abandonment unless explicitly finished. */
class ObjectPhase {
 public:
  /** Create a disabled phase. */
  ObjectPhase() = default;

  ObjectPhase(const ObjectPhase&) = delete;
  ObjectPhase& operator=(const ObjectPhase&) = delete;

  /** Transfer ownership of a phase. */
  ObjectPhase(ObjectPhase&& other) noexcept { *this = std::move(other); }

  /** Transfer ownership after abandoning any currently held phase. */
  ObjectPhase& operator=(ObjectPhase&& other) noexcept {
    if (this != &other) {
      abandon();
      trace_id_ = std::exchange(other.trace_id_, 0);
      span_id_ = std::exchange(other.span_id_, 0);
      phase_ = other.phase_;
    }
    return *this;
  }

  /** Record abandonment when the phase leaves scope unfinished. */
  ~ObjectPhase() { abandon(); }

  /** Finish the phase with an explicit result. */
  void finish(moq_trace_object_outcome outcome) {
    if (span_id_ == 0) return;
    finish_at(outcome, quic_trace::now_ns());
  }

  /** Finish the phase at a timestamp captured at the measured boundary. */
  void finish_at(moq_trace_object_outcome outcome, std::uint64_t timestamp_ns) {
    if (span_id_ == 0) return;
    emit(timestamp_ns, MOQ_TRACE_EDGE_DONE, outcome);
    span_id_ = 0;
  }

 private:
  friend class Object;

  ObjectPhase(std::uint64_t trace_id, moq_trace_object_phase phase,
              std::uint64_t timestamp_ns)
      : trace_id_(trace_id),
        span_id_(quic_trace_next_span_id()),
        phase_(phase) {
    emit(timestamp_ns, MOQ_TRACE_EDGE_START, std::nullopt);
  }

  void emit(std::uint64_t timestamp_ns, moq_trace_edge edge,
            std::optional<moq_trace_object_outcome> outcome) const {
    const struct moq_trace_moq_object_phase event{
        timestamp_ns,
        trace_id_,
        span_id_,
        static_cast<std::uint8_t>(phase_),
        static_cast<std::uint8_t>(edge),
        static_cast<std::uint8_t>(outcome.has_value()),
        static_cast<std::uint8_t>(outcome.value_or(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS)),
    };
    moq_trace_moq_object_phase(&event);
  }

  void abandon() {
    if (span_id_ != 0) finish(MOQ_TRACE_OBJECT_OUTCOME_ABANDONED);
  }

  std::uint64_t trace_id_ = 0;
  std::uint64_t span_id_ = 0;
  moq_trace_object_phase phase_ = MOQ_TRACE_OBJECT_PHASE_HEADER_PARSE;
};

/** A scoped MoQ object that records abandonment unless explicitly finished. */
class Object {
 public:
  /** Start an object trace when any object event is enabled. */
  explicit Object(ObjectContext context)
      : context_(context), payload_bytes_(context.payload_bytes) {
    if (!moq_trace_moq_object_start_enabled() &&
        !moq_trace_moq_object_end_enabled() &&
        !moq_trace_moq_object_phase_enabled()) {
      return;
    }
    trace_id_ = quic_trace_next_trace_id();
    if (moq_trace_moq_object_start_enabled()) emit_start();
  }

  Object(const Object&) = delete;
  Object& operator=(const Object&) = delete;

  /** Transfer ownership of an object trace. */
  Object(Object&& other) noexcept { *this = std::move(other); }

  /** Transfer ownership after abandoning any currently held object. */
  Object& operator=(Object&& other) noexcept {
    if (this != &other) {
      abandon();
      trace_id_ = std::exchange(other.trace_id_, 0);
      context_ = other.context_;
      payload_bytes_ = other.payload_bytes_;
      stream_offset_end_ = other.stream_offset_end_;
    }
    return *this;
  }

  /** Record abandonment when the object leaves scope unfinished. */
  ~Object() { abandon(); }

  /** Update the object payload size once it is known. */
  void set_payload_bytes(std::uint64_t value) { payload_bytes_ = value; }

  /** Update the exclusive stream byte offset reached by this object. */
  void set_stream_offset_end(std::uint64_t value) {
    stream_offset_end_ = value;
  }

  /**
   * Return whether this object records phase events.
   *
   * A hook that times a phase from clock readings of its own checks this first
   * so it reads no clock when nothing would be recorded.
   */
  bool records_phases() const {
    return trace_id_ != 0 && moq_trace_moq_object_phase_enabled();
  }

  /** Start a measured object phase. */
  ObjectPhase phase(moq_trace_object_phase value) const {
    if (trace_id_ == 0 || !moq_trace_moq_object_phase_enabled()) return {};
    return ObjectPhase(trace_id_, value, quic_trace::now_ns());
  }

  /** Start a measured object phase at a previously captured timestamp. */
  ObjectPhase phase_at(moq_trace_object_phase value,
                       std::uint64_t timestamp_ns) const {
    if (trace_id_ == 0 || !moq_trace_moq_object_phase_enabled()) return {};
    return ObjectPhase(trace_id_, value, timestamp_ns);
  }

  /** Finish the object with an explicit result. */
  void finish(moq_trace_object_outcome outcome) {
    if (trace_id_ == 0) return;
    if (moq_trace_moq_object_end_enabled()) emit_end(outcome);
    trace_id_ = 0;
  }

 private:
  void emit_start() const {
    const struct moq_trace_moq_object_start event{
        context_.start_ns ? *context_.start_ns : quic_trace::now_ns(),
        trace_id_,
        context_.logical_id.group,
        context_.logical_id.frame,
        static_cast<std::uint8_t>(context_.session_id.has_value()),
        context_.session_id.value_or(0),
        static_cast<std::uint8_t>(context_.connection_id.has_value()),
        context_.connection_id.value_or(0),
        static_cast<std::uint8_t>(context_.direction),
        context_.identity.track_alias,
        context_.identity.group_id,
        context_.identity.object_id,
        static_cast<std::uint8_t>(context_.stream_id.has_value()),
        context_.stream_id.value_or(0),
        static_cast<std::uint8_t>(context_.stream_offset_start.has_value()),
        context_.stream_offset_start.value_or(0),
    };
    moq_trace_moq_object_start(&event);
  }

  void emit_end(moq_trace_object_outcome outcome) const {
    const struct moq_trace_moq_object_end event{
        quic_trace::now_ns(),
        trace_id_,
        static_cast<std::uint8_t>(stream_offset_end_.has_value()),
        stream_offset_end_.value_or(0),
        payload_bytes_,
        static_cast<std::uint8_t>(outcome),
    };
    moq_trace_moq_object_end(&event);
  }

  void abandon() {
    if (trace_id_ != 0) finish(MOQ_TRACE_OBJECT_OUTCOME_ABANDONED);
  }

  std::uint64_t trace_id_ = 0;
  ObjectContext context_;
  std::uint64_t payload_bytes_ = 0;
  std::optional<std::uint64_t> stream_offset_end_;
};

/** Allocate a process-wide session identifier shared with Rust hooks. */
inline std::uint64_t next_session_id() { return moq_trace_next_session_id(); }

/**
 * The NOTIFY intervals of one synchronous fan-out on the trace clock.
 *
 * A relay that calls its consumers synchronously runs every outbound copy
 * inside the loop that notifies them. NOTIFY covers that loop, and each copy's
 * own work, from the start of its lifecycle until its consumer returns, is
 * excluded because it belongs to the copy. The value is copyable, so a relay
 * that starts the inbound object's trace only after the fan-out can carry the
 * intervals to it and record them there.
 *
 * Excluded intervals beyond the capacity merge into the last one, so they still
 * cover every copy and never overlap, at the cost of also excluding the notify
 * work between the merged copies.
 */
class FanOutSpans {
 public:
  /** Excluded intervals held before later ones merge into the last. */
  static constexpr std::size_t kCapacity = 8;

  /** Create spans that record nothing. */
  FanOutSpans() = default;

  /** Start spans at a timestamp captured where the fan-out began. */
  explicit FanOutSpans(std::uint64_t start_ns) : start_ns_(start_ns) {}

  /** Return when the fan-out began, if it was timed. */
  std::optional<std::uint64_t> start_ns() const { return start_ns_; }

  /** Exclude a copy's work, clamped to follow earlier exclusions. */
  void exclude(std::uint64_t start_ns, std::uint64_t end_ns) {
    if (!start_ns_ || end_ns_) return;
    std::uint64_t floor = *start_ns_;
    if (len_ > 0) floor = std::max(floor, excluded_[len_ - 1].second);
    start_ns = std::max(start_ns, floor);
    if (end_ns <= start_ns) return;
    if (len_ < kCapacity) {
      excluded_[len_++] = {start_ns, end_ns};
    } else {
      excluded_[kCapacity - 1].second = end_ns;
    }
  }

  /** End the fan-out at a timestamp captured where its loop returned. */
  void close(std::uint64_t end_ns) {
    if (start_ns_ && !end_ns_) end_ns_ = end_ns;
  }

  /** Call `visit(start_ns, end_ns)` for each non-empty NOTIFY interval. */
  template <typename Visit>
  void for_each_notify(Visit&& visit) const {
    if (!start_ns_ || !end_ns_) return;
    std::uint64_t cursor = *start_ns_;
    for (std::size_t i = 0; i < len_; ++i) {
      const auto [excluded_start, excluded_end] = excluded_[i];
      if (excluded_start >= *end_ns_) break;
      if (excluded_start > cursor) visit(cursor, excluded_start);
      cursor = std::max(cursor, excluded_end);
    }
    if (*end_ns_ > cursor) visit(cursor, *end_ns_);
  }

  /** Compare the recorded fan-out, including its excluded intervals. */
  bool operator==(const FanOutSpans& other) const {
    if (start_ns_ != other.start_ns_ || end_ns_ != other.end_ns_ ||
        len_ != other.len_) {
      return false;
    }
    return std::equal(excluded_.begin(), excluded_.begin() + len_,
                      other.excluded_.begin());
  }

  /** Compare the recorded fan-out, including its excluded intervals. */
  bool operator!=(const FanOutSpans& other) const { return !(*this == other); }

  /** Record the NOTIFY intervals on the inbound object they fanned out. */
  void record(const Object& inbound) const {
    if (!inbound.records_phases()) return;
    for_each_notify([&](std::uint64_t start_ns, std::uint64_t end_ns) {
      inbound.phase_at(MOQ_TRACE_OBJECT_PHASE_NOTIFY, start_ns)
          .finish_at(MOQ_TRACE_OBJECT_OUTCOME_SUCCESS, end_ns);
    });
  }

 private:
  std::optional<std::uint64_t> start_ns_;
  std::optional<std::uint64_t> end_ns_;
  std::array<std::pair<std::uint64_t, std::uint64_t>, kCapacity> excluded_{};
  std::size_t len_ = 0;
};

/**
 * Times a synchronous fan-out on this thread while it is in scope.
 *
 * It reads no clock unless object phases are enabled. Scopes nest: an inner
 * fan-out, such as one an in-process relay hop starts inside a copy, collects
 * its own exclusions, and the outer one resumes when it ends.
 */
class FanOut {
 public:
  /** Start timing a fan-out, when object phases are enabled. */
  FanOut() {
    if (!moq_trace_moq_object_phase_enabled()) return;
    spans_ = FanOutSpans(quic_trace::now_ns());
    previous_ = std::exchange(active_, this);
    timing_ = true;
  }

  FanOut(const FanOut&) = delete;
  FanOut& operator=(const FanOut&) = delete;

  /** Stop timing when the scope ends without an explicit end. */
  ~FanOut() { end(); }

  /** Stop timing and return the spans. Later calls return the same spans. */
  const FanOutSpans& end() {
    if (timing_) {
      spans_.close(quic_trace::now_ns());
      active_ = previous_;
      timing_ = false;
    }
    return spans_;
  }

  /** Return whether a fan-out is being timed on this thread. */
  static bool active() { return active_ != nullptr; }

  /** Exclude a copy's work from the fan-out timed on this thread, if any. */
  static void exclude(std::uint64_t start_ns, std::uint64_t end_ns) {
    if (active_ != nullptr) active_->spans_.exclude(start_ns, end_ns);
  }

 private:
  inline static thread_local FanOut* active_ = nullptr;
  FanOut* previous_ = nullptr;
  FanOutSpans spans_;
  bool timing_ = false;
};

/**
 * Excludes one copy's synchronous work from the fan-out timed on this thread.
 *
 * Place it where the consumer handles the copy. The work starts at `begin`,
 * normally the copy lifecycle's start, and ends when the scope does. Outside a
 * fan-out it reads no clock.
 */
class CopyWork {
 public:
  /** Create a scope that excludes nothing until it begins. */
  CopyWork() = default;

  CopyWork(const CopyWork&) = delete;
  CopyWork& operator=(const CopyWork&) = delete;

  /** Exclude the work from its start until now. */
  ~CopyWork() {
    if (start_ns_) FanOut::exclude(*start_ns_, quic_trace::now_ns());
  }

  /** Mark where the copy's work began, unless an earlier start is marked. */
  void begin(std::uint64_t start_ns) {
    if (!start_ns_ && FanOut::active()) start_ns_ = start_ns;
  }

 private:
  std::optional<std::uint64_t> start_ns_;
};

}  // namespace moq_trace

#endif  // MOQ_TRACE_TRACE_HPP
