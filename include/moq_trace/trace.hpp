#ifndef MOQ_TRACE_TRACE_HPP
#define MOQ_TRACE_TRACE_HPP

#include <moq_trace/interface.h>

#include <quic_trace/trace.hpp>

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

}  // namespace moq_trace

#endif  // MOQ_TRACE_TRACE_HPP
