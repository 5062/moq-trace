-- Every sample stage inserts here, in the layout of `metrics.samples`, which
-- takes them once the metric definitions name every metric staged.
CREATE TEMP TABLE staged_samples (
    metric VARCHAR NOT NULL,
    rx_trace_id UBIGINT,
    tx_trace_id UBIGINT,
    packet_trace_id UBIGINT,
    span_id UBIGINT,
    elapsed_ns BIGINT NOT NULL,
    value_ns BIGINT NOT NULL
);

-- Each selected copy with the packet coverage of its inbound object and its
-- own. Coverage resolution rejects an object it cannot cover, so every selected
-- copy is here.
CREATE TEMP VIEW covered_copies AS
SELECT copy.*,
       inbound.origin_ns AS rx_origin_ns, inbound.complete_ns AS rx_complete_ns,
       outbound.first_ns AS tx_first_ns, outbound.complete_ns AS tx_complete_ns,
       outbound.complete_packet_trace_id AS tx_complete_packet_trace_id
FROM selected_copies AS copy
JOIN model.coverage AS inbound ON inbound.object_trace_id = copy.rx_trace_id
JOIN model.coverage AS outbound ON outbound.object_trace_id = copy.tx_trace_id;
