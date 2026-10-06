#ifndef MOQ_TRACE_INTERFACE_H
#define MOQ_TRACE_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum moq_trace_direction {
	MOQ_TRACE_DIRECTION_RX,
	MOQ_TRACE_DIRECTION_TX,
};

enum moq_trace_edge {
	MOQ_TRACE_EDGE_START,
	MOQ_TRACE_EDGE_DONE,
};

/*
 * Declaration order is the wire encoding, so new phases are appended rather
 * than placed in pipeline order. Every phase measures work except
 * DELIVERY_WAIT and WRITE_BLOCKED, which measure waits; any other time an
 * object spends waiting belongs to no phase. TRANSPORT_CALL nests inside
 * another work phase rather than following it.
 */
enum moq_trace_object_phase {
	MOQ_TRACE_OBJECT_PHASE_HEADER_PARSE,
	MOQ_TRACE_OBJECT_PHASE_CREATE,
	/* The transport handing received payload bytes to the relay. Waiting for
	 * them to arrive and copying them into the relay model are excluded. */
	MOQ_TRACE_OBJECT_PHASE_PAYLOAD_READ,
	/* Write payload bytes into the relay model and mark the object complete,
	 * so the bytes become visible to relay consumers. Waking those consumers
	 * belongs to NOTIFY when the relay performs it as a separate step. */
	MOQ_TRACE_OBJECT_PHASE_FRAME_COMMIT,
	MOQ_TRACE_OBJECT_PHASE_CLONE,
	MOQ_TRACE_OBJECT_PHASE_HEADER_ENCODE,
	MOQ_TRACE_OBJECT_PHASE_PAYLOAD_WRITE,
	/* RX: wake or enumerate the consumers of a newly readable object. This is
	 * the fan-out work shared by every copy, recorded on the inbound object. */
	MOQ_TRACE_OBJECT_PHASE_NOTIFY,
	/* TX wait: from the instant the relay made the object readable until this
	 * copy's CLONE starts. It can start before the copy's lifecycle does. */
	MOQ_TRACE_OBJECT_PHASE_DELIVERY_WAIT,
	/* TX wait: from a write that could not proceed until the relay resumes
	 * writing, for flow control, backpressure, or an asynchronous lock. */
	MOQ_TRACE_OBJECT_PHASE_WRITE_BLOCKED,
	/* Nested: time inside a call into the transport API made by another phase
	 * of this object, such as the stream write inside PAYLOAD_WRITE. It covers
	 * whatever the transport runs in the call, including packet building,
	 * sends, and its locks, and is never MoQ work. */
	MOQ_TRACE_OBJECT_PHASE_TRANSPORT_CALL,
};

/*
 * How an object lifecycle or phase ended. FAILED is an error in processing, and
 * ABANDONED a trace that ended without a recorded outcome. EXPIRED, DROPPED,
 * and RESET mean the relay or its peer deliberately stopped the object, so it
 * was not delivered but nothing went wrong. Declaration order is the wire
 * encoding, so new outcomes are appended.
 */
enum moq_trace_object_outcome {
	MOQ_TRACE_OBJECT_OUTCOME_SUCCESS,
	MOQ_TRACE_OBJECT_OUTCOME_FAILED,
	MOQ_TRACE_OBJECT_OUTCOME_ABANDONED,
	/* A delivery deadline passed before the object was delivered. */
	MOQ_TRACE_OBJECT_OUTCOME_EXPIRED,
	/* Relay policy discarded the object: it fell outside a subscription's
	 * window, or the cache evicted it before a reader got to it. */
	MOQ_TRACE_OBJECT_OUTCOME_DROPPED,
	/* The stream carrying the object was reset or stopped before it finished. */
	MOQ_TRACE_OBJECT_OUTCOME_RESET,
};

struct moq_trace_moq_object_start {
	uint64_t timestamp_ns;
	uint64_t trace_id;
	uint64_t logical_group;
	uint64_t logical_frame;
	uint8_t has_session_id;
	uint64_t session_id;
	uint8_t has_connection_id;
	uint64_t connection_id;
	uint8_t direction;
	uint64_t track_alias;
	uint64_t group_id;
	uint64_t object_id;
	uint8_t has_stream_id;
	uint64_t stream_id;
	uint8_t has_stream_offset_start;
	uint64_t stream_offset_start;
};

struct moq_trace_moq_object_end {
	uint64_t timestamp_ns;
	uint64_t trace_id;
	uint8_t has_stream_offset_end;
	uint64_t stream_offset_end;
	uint64_t payload_bytes;
	uint8_t outcome;
};

struct moq_trace_moq_object_phase {
	uint64_t timestamp_ns;
	uint64_t trace_id;
	uint64_t span_id;
	uint8_t phase;
	uint8_t edge;
	uint8_t has_outcome;
	uint8_t outcome;
};

bool moq_trace_moq_object_start_enabled(void);
void moq_trace_moq_object_start(const struct moq_trace_moq_object_start *event);
bool moq_trace_moq_object_end_enabled(void);
void moq_trace_moq_object_end(const struct moq_trace_moq_object_end *event);
bool moq_trace_moq_object_phase_enabled(void);
void moq_trace_moq_object_phase(const struct moq_trace_moq_object_phase *event);

/*
 * Process-wide MoQ identity shared by every facade, in any language.
 *
 * Session identifiers and logical group instances come from two counters that
 * start at 1 and never repeat. A process that instruments some code from Rust
 * and some from C++ must link one copy of this library so both draw from the
 * same counters.
 */
uint64_t moq_trace_next_session_id(void);
uint64_t moq_trace_next_logical_group(void);

#ifdef __cplusplus
}
#endif

#endif /* MOQ_TRACE_INTERFACE_H */
