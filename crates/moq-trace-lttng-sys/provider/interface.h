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

enum moq_trace_object_phase {
	MOQ_TRACE_OBJECT_PHASE_HEADER_PARSE,
	MOQ_TRACE_OBJECT_PHASE_CREATE,
	/* The transport handing received payload bytes to the relay. Waiting for
	 * them to arrive and copying them into the relay model are excluded. Every
	 * phase excludes time spent waiting on I/O. */
	MOQ_TRACE_OBJECT_PHASE_PAYLOAD_READ,
	/* Write payload bytes into the relay model and mark the object complete,
	 * so the bytes become visible to relay consumers. */
	MOQ_TRACE_OBJECT_PHASE_FRAME_COMMIT,
	MOQ_TRACE_OBJECT_PHASE_CLONE,
	MOQ_TRACE_OBJECT_PHASE_HEADER_ENCODE,
	MOQ_TRACE_OBJECT_PHASE_PAYLOAD_WRITE,
};

enum moq_trace_object_outcome {
	MOQ_TRACE_OBJECT_OUTCOME_SUCCESS,
	MOQ_TRACE_OBJECT_OUTCOME_FAILED,
	MOQ_TRACE_OBJECT_OUTCOME_ABANDONED,
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
void moq_trace_provider_init(void);

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
