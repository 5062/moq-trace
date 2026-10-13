-- The addresses each traced connection recorded, as 128-bit IPv6 values.
SELECT connection_id, timestamp_ns,
       (local_address_high::UHUGEINT << 64) | local_address_low::UHUGEINT AS local_address,
       local_port,
       (peer_address_high::UHUGEINT << 64) | peer_address_low::UHUGEINT AS peer_address,
       peer_port
FROM quic_connection_path;
