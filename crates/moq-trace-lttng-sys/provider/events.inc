/*
 * The MoQ object events this provider declares, in declaration order.
 *
 * provider.c.in includes this file repeatedly with different definitions of
 * EVENT to stamp out the linker-retained tracepoint array and the enablement
 * and emission wrappers. A single list means the provider cannot retain an
 * event it does not wrap, or wrap one it does not retain.
 *
 * There is deliberately no include guard, because every inclusion has to
 * re-expand the list.
 */

EVENT(moq_object_start)
EVENT(moq_object_end)
EVENT(moq_object_phase)
