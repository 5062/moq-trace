#include "interface.h"

/*
 * MoQ identity shared by every facade in the process.
 *
 * Rust and C++ hooks in one relay both call these, so a session or logical
 * group identifier is unique across languages. The analysis pairs an ingress
 * object with its copies by logical identity, so two allocators handing out
 * the same group would pair objects that are unrelated. Nothing here depends
 * on LTTng.
 */

static uint64_t next_session_id = 1;
static uint64_t next_logical_group = 1;

uint64_t moq_trace_next_session_id(void) {
	return __atomic_fetch_add(&next_session_id, 1, __ATOMIC_RELAXED);
}

uint64_t moq_trace_next_logical_group(void) {
	return __atomic_fetch_add(&next_logical_group, 1, __ATOMIC_RELAXED);
}
