#include "interface.h"

#define LTTNG_UST_TRACEPOINT_DEFINE
#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#include "events.h"

#if defined(__has_attribute)
#	if __has_attribute(retain)
#		define MOQ_TRACE_RETAIN __attribute__((retain))
#	endif
#endif

#ifndef MOQ_TRACE_RETAIN
#	define MOQ_TRACE_RETAIN
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
MOQ_TRACE_RETAIN __attribute__((used, visibility("default"))) void *const moq_trace_tracepoints[] = {
	&lttng_ust_tracepoint_ptr_moq_trace___moq_object_start,
	&lttng_ust_tracepoint_ptr_moq_trace___moq_object_end,
	&lttng_ust_tracepoint_ptr_moq_trace___moq_object_phase,
};

/*
 * Tracepoints register from a constructor in the generated events.h. This entry
 * point only gives instrumented code a symbol to reference so the linker keeps
 * the provider object.
 */
void moq_trace_provider_init(void) {}

bool moq_trace_moq_object_start_enabled(void) { return lttng_ust_tracepoint_enabled(moq_trace, moq_object_start); }
void moq_trace_moq_object_start(const struct moq_trace_moq_object_start *event) { lttng_ust_tracepoint(moq_trace, moq_object_start, event); }
bool moq_trace_moq_object_end_enabled(void) { return lttng_ust_tracepoint_enabled(moq_trace, moq_object_end); }
void moq_trace_moq_object_end(const struct moq_trace_moq_object_end *event) { lttng_ust_tracepoint(moq_trace, moq_object_end, event); }
bool moq_trace_moq_object_phase_enabled(void) { return lttng_ust_tracepoint_enabled(moq_trace, moq_object_phase); }
void moq_trace_moq_object_phase(const struct moq_trace_moq_object_phase *event) { lttng_ust_tracepoint(moq_trace, moq_object_phase, event); }
