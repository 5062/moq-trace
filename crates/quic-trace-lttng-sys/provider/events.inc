/*
 * The QUIC transport events this provider declares, in declaration order.
 *
 * interface.c includes this file repeatedly with different definitions of
 * EVENT to stamp out the linker-retained tracepoint array and the enablement
 * and emission wrappers. A single list means the provider cannot retain an
 * event it does not wrap, or wrap one it does not retain.
 *
 * There is deliberately no include guard, because every inclusion has to
 * re-expand the list.
 */

EVENT(quic_packet_start)
EVENT(quic_packet_end)
EVENT(quic_packet_phase)
EVENT(quic_stream_frame)
EVENT(quic_send_blocked)
EVENT(quic_connection_path)
EVENT(udp_socket_start)
EVENT(udp_socket_end)
