#include "interface.h"

#define LTTNG_UST_TRACEPOINT_DEFINE
#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#include "events.h"

static void *const moq_trace_refs[] = {
	&lttng_ust_tracepoint_ptr_moq_trace___moq_object_start,
	&lttng_ust_tracepoint_ptr_moq_trace___moq_object_end,
	&lttng_ust_tracepoint_ptr_moq_trace___moq_object_phase,
};

void moq_trace_provider_init(void) {
	(void)moq_trace_refs;
}

bool moq_trace_moq_object_start_enabled(void) { return lttng_ust_tracepoint_enabled(moq_trace, moq_object_start); }
void moq_trace_moq_object_start(const struct moq_trace_moq_object_start *event) { lttng_ust_tracepoint(moq_trace, moq_object_start, event); }
bool moq_trace_moq_object_end_enabled(void) { return lttng_ust_tracepoint_enabled(moq_trace, moq_object_end); }
void moq_trace_moq_object_end(const struct moq_trace_moq_object_end *event) { lttng_ust_tracepoint(moq_trace, moq_object_end, event); }
bool moq_trace_moq_object_phase_enabled(void) { return lttng_ust_tracepoint_enabled(moq_trace, moq_object_phase); }
void moq_trace_moq_object_phase(const struct moq_trace_moq_object_phase *event) { lttng_ust_tracepoint(moq_trace, moq_object_phase, event); }
