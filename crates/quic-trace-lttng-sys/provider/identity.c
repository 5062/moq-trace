#include "interface.h"

#include <time.h>

/*
 * Identity and time shared by every facade in the process.
 *
 * Rust and C++ hooks in one relay both call these, so a trace, span, or
 * connection identifier is unique across languages and every timestamp comes
 * from one epoch. The counters live in this library rather than in a facade
 * because a facade is compiled once per language, and a second copy would hand
 * out the same values again. Nothing here depends on LTTng.
 */

static uint64_t next_trace_id = 1;
static uint64_t next_span_id = 1;
static uint64_t next_connection_id = 1;

uint64_t quic_trace_next_trace_id(void) {
	return __atomic_fetch_add(&next_trace_id, 1, __ATOMIC_RELAXED);
}

uint64_t quic_trace_next_span_id(void) {
	return __atomic_fetch_add(&next_span_id, 1, __ATOMIC_RELAXED);
}

uint64_t quic_trace_next_connection_id(void) {
	return __atomic_fetch_add(&next_connection_id, 1, __ATOMIC_RELAXED);
}

uint64_t quic_trace_now_ns(void) {
	struct timespec value = {0, 0};
	/* CLOCK_MONOTONIC cannot fail on Linux given a valid pointer. */
	clock_gettime(CLOCK_MONOTONIC, &value);
	return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
