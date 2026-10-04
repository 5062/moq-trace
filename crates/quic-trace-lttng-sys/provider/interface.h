#ifndef QUIC_TRACE_INTERFACE_H
#define QUIC_TRACE_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum quic_trace_direction {
	QUIC_TRACE_DIRECTION_RX,
	QUIC_TRACE_DIRECTION_TX,
};

enum quic_trace_edge {
	QUIC_TRACE_EDGE_START,
	QUIC_TRACE_EDGE_DONE,
};

enum quic_trace_packet_space {
	QUIC_TRACE_PACKET_SPACE_INITIAL,
	QUIC_TRACE_PACKET_SPACE_HANDSHAKE,
	QUIC_TRACE_PACKET_SPACE_ZERO_RTT,
	QUIC_TRACE_PACKET_SPACE_DATA,
};

enum quic_trace_packet_phase {
	QUIC_TRACE_PACKET_PHASE_HEADER_PARSE,
	QUIC_TRACE_PACKET_PHASE_ROUTING,
	QUIC_TRACE_PACKET_PHASE_SCHEDULING,
	QUIC_TRACE_PACKET_PHASE_HEADER_UNPROTECT,
	QUIC_TRACE_PACKET_PHASE_PAYLOAD_DECRYPT,
	QUIC_TRACE_PACKET_PHASE_FRAME_PROCESS,
	QUIC_TRACE_PACKET_PHASE_FRAME_ENCODE,
	QUIC_TRACE_PACKET_PHASE_PACKET_ENCRYPT,
	QUIC_TRACE_PACKET_PHASE_APPLICATION,
	QUIC_TRACE_PACKET_PHASE_READ_QUEUE,
	QUIC_TRACE_PACKET_PHASE_SEND_QUEUE,
};

enum quic_trace_packet_outcome {
	QUIC_TRACE_PACKET_OUTCOME_SUCCESS,
	QUIC_TRACE_PACKET_OUTCOME_MALFORMED,
	QUIC_TRACE_PACKET_OUTCOME_AUTHENTICATION_FAILED,
	QUIC_TRACE_PACKET_OUTCOME_DROPPED,
	QUIC_TRACE_PACKET_OUTCOME_ABANDONED,
};

enum quic_trace_socket_outcome {
	QUIC_TRACE_SOCKET_OUTCOME_SUCCESS,
	QUIC_TRACE_SOCKET_OUTCOME_PENDING,
	QUIC_TRACE_SOCKET_OUTCOME_WOULD_BLOCK,
	QUIC_TRACE_SOCKET_OUTCOME_CONNECTION_RESET,
	QUIC_TRACE_SOCKET_OUTCOME_ERROR,
	QUIC_TRACE_SOCKET_OUTCOME_ABANDONED,
};

struct quic_trace_quic_packet_start {
	uint64_t timestamp_ns;
	uint64_t trace_id;
	uint64_t connection_id;
	uint8_t direction;
	uint8_t has_packet_number;
	uint64_t packet_number;
	uint8_t has_packet_space;
	uint8_t packet_space;
	uint8_t has_byte_len;
	uint64_t byte_len;
};

struct quic_trace_quic_packet_end {
	uint64_t timestamp_ns;
	uint64_t trace_id;
	uint8_t has_packet_number;
	uint64_t packet_number;
	uint8_t has_packet_space;
	uint8_t packet_space;
	uint8_t has_byte_len;
	uint64_t byte_len;
	uint8_t outcome;
};

struct quic_trace_quic_packet_phase {
	uint64_t timestamp_ns;
	uint64_t trace_id;
	uint64_t span_id;
	uint8_t phase;
	uint8_t edge;
	uint8_t has_outcome;
	uint8_t outcome;
};

struct quic_trace_quic_stream_frame {
	uint64_t timestamp_ns;
	uint64_t trace_id;
	uint64_t stream_id;
	uint64_t offset_start;
	uint64_t offset_end;
	uint8_t outcome;
};

/*
 * The addresses one connection sends between, from the time of the event until
 * the connection's next path event. Addresses are IPv6, with IPv4 written as
 * IPv4-mapped IPv6 (::ffff:a.b.c.d), split into the high and low 64 bits of the
 * address in network byte order. Ports are in host byte order.
 */
struct quic_trace_quic_connection_path {
	uint64_t timestamp_ns;
	uint64_t connection_id;
	uint64_t local_address_high;
	uint64_t local_address_low;
	uint16_t local_port;
	uint64_t peer_address_high;
	uint64_t peer_address_low;
	uint16_t peer_port;
};

struct quic_trace_udp_socket_start {
	uint64_t timestamp_ns;
	uint64_t trace_id;
	uint8_t has_connection_id;
	uint64_t connection_id;
	uint8_t direction;
};

struct quic_trace_udp_socket_end {
	uint64_t timestamp_ns;
	uint64_t trace_id;
	uint8_t outcome;
	uint64_t buffers;
	uint64_t datagrams;
	uint64_t bytes;
};

bool quic_trace_quic_packet_start_enabled(void);
void quic_trace_quic_packet_start(const struct quic_trace_quic_packet_start *event);
bool quic_trace_quic_packet_end_enabled(void);
void quic_trace_quic_packet_end(const struct quic_trace_quic_packet_end *event);
bool quic_trace_quic_packet_phase_enabled(void);
void quic_trace_quic_packet_phase(const struct quic_trace_quic_packet_phase *event);
bool quic_trace_quic_stream_frame_enabled(void);
void quic_trace_quic_stream_frame(const struct quic_trace_quic_stream_frame *event);
bool quic_trace_quic_connection_path_enabled(void);
void quic_trace_quic_connection_path(const struct quic_trace_quic_connection_path *event);
bool quic_trace_udp_socket_start_enabled(void);
void quic_trace_udp_socket_start(const struct quic_trace_udp_socket_start *event);
bool quic_trace_udp_socket_end_enabled(void);
void quic_trace_udp_socket_end(const struct quic_trace_udp_socket_end *event);
void quic_trace_provider_init(void);

/*
 * Process-wide identity and time shared by every facade, in any language.
 *
 * Trace, span, and connection identifiers come from three counters that start
 * at 1 and never repeat. Timestamps are CLOCK_MONOTONIC nanoseconds. A process
 * that instruments some code from Rust and some from C++ must link one copy of
 * this library so both draw from the same counters and clock.
 */
uint64_t quic_trace_next_trace_id(void);
uint64_t quic_trace_next_span_id(void);
uint64_t quic_trace_next_connection_id(void);
uint64_t quic_trace_now_ns(void);

#ifdef __cplusplus
}
#endif

#endif /* QUIC_TRACE_INTERFACE_H */
