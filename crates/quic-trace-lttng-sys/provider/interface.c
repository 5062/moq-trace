#include "interface.h"

#define LTTNG_UST_TRACEPOINT_DEFINE
#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#include "events.h"

#if defined(__has_attribute)
#	if __has_attribute(retain)
#		define QUIC_TRACE_RETAIN __attribute__((retain))
#	endif
#endif

#ifndef QUIC_TRACE_RETAIN
#	define QUIC_TRACE_RETAIN
#endif

/*
 * LTTng-UST discovers tracepoints through the linker-synthesized
 * __start/__stop_lttng_ust_tracepoints_ptrs symbols. LLD does not treat those
 * symbols as roots under --gc-sections (its default --start-stop-gc behaviour)
 * and rustc links with LLD, so the section is collected and the provider
 * registers nothing while `lttng list` still advertises every event. An
 * exported, linker-retained reference to each pointer holds the section in
 * place under both LLD and GNU ld.
 */
QUIC_TRACE_RETAIN __attribute__((used, visibility("default"))) void *const quic_trace_tracepoints[] = {
	&lttng_ust_tracepoint_ptr_quic_trace___quic_packet_start,
	&lttng_ust_tracepoint_ptr_quic_trace___quic_packet_end,
	&lttng_ust_tracepoint_ptr_quic_trace___quic_packet_phase,
	&lttng_ust_tracepoint_ptr_quic_trace___quic_stream_frame,
	&lttng_ust_tracepoint_ptr_quic_trace___udp_socket_start,
	&lttng_ust_tracepoint_ptr_quic_trace___udp_socket_end,
};

/*
 * Tracepoints register from a constructor in the generated events.h. This entry
 * point only gives instrumented code a symbol to reference so the linker keeps
 * the provider object.
 */
void quic_trace_provider_init(void) {}

bool quic_trace_quic_packet_start_enabled(void) { return lttng_ust_tracepoint_enabled(quic_trace, quic_packet_start); }
void quic_trace_quic_packet_start(const struct quic_trace_quic_packet_start *event) { lttng_ust_tracepoint(quic_trace, quic_packet_start, event); }
bool quic_trace_quic_packet_end_enabled(void) { return lttng_ust_tracepoint_enabled(quic_trace, quic_packet_end); }
void quic_trace_quic_packet_end(const struct quic_trace_quic_packet_end *event) { lttng_ust_tracepoint(quic_trace, quic_packet_end, event); }
bool quic_trace_quic_packet_phase_enabled(void) { return lttng_ust_tracepoint_enabled(quic_trace, quic_packet_phase); }
void quic_trace_quic_packet_phase(const struct quic_trace_quic_packet_phase *event) { lttng_ust_tracepoint(quic_trace, quic_packet_phase, event); }
bool quic_trace_quic_stream_frame_enabled(void) { return lttng_ust_tracepoint_enabled(quic_trace, quic_stream_frame); }
void quic_trace_quic_stream_frame(const struct quic_trace_quic_stream_frame *event) { lttng_ust_tracepoint(quic_trace, quic_stream_frame, event); }
bool quic_trace_udp_socket_start_enabled(void) { return lttng_ust_tracepoint_enabled(quic_trace, udp_socket_start); }
void quic_trace_udp_socket_start(const struct quic_trace_udp_socket_start *event) { lttng_ust_tracepoint(quic_trace, udp_socket_start, event); }
bool quic_trace_udp_socket_end_enabled(void) { return lttng_ust_tracepoint_enabled(quic_trace, udp_socket_end); }
void quic_trace_udp_socket_end(const struct quic_trace_udp_socket_end *event) { lttng_ust_tracepoint(quic_trace, udp_socket_end, event); }
