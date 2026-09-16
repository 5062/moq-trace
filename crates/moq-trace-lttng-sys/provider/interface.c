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
 *
 * The entries come from events.inc, so an event added there cannot be left out
 * of the retained set. A missing entry drops the event from a capture while
 * `lttng list` still reports it.
 */
MOQ_TRACE_RETAIN __attribute__((used, visibility("default"))) void *const moq_trace_tracepoints[] = {
#define EVENT(name) &lttng_ust_tracepoint_ptr_moq_trace___##name,
#include "events.inc"
};
#undef EVENT

/*
 * Tracepoints register from a constructor in the generated events.h. This entry
 * point only gives instrumented code a symbol to reference so the linker keeps
 * the provider object.
 */
void moq_trace_provider_init(void) {}

/*
 * Every wrapper comes from events.inc for the same reason. The enablement
 * predicate is a plain function for the facade to call, and it reads one state
 * word, so a disabled event never enters the tracepoint.
 */
#define EVENT(name) \
	bool moq_trace_##name##_enabled(void) { \
		return lttng_ust_tracepoint_enabled(moq_trace, name); \
	} \
	void moq_trace_##name(const struct moq_trace_##name *event) { \
		lttng_ust_tracepoint(moq_trace, name, event); \
	}

#include "events.inc"

#undef EVENT
