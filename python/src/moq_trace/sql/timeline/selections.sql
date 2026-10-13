-- The objects the timeline figure draws, in selection order.
SELECT s.rx_trace_id, s.statistic, s.target_ns / 1000.0, s.actual_ns / 1000.0,
       object.group_id, object.object_id, object.start_ns
FROM metrics.timeline_selections s JOIN model.objects object ON s.rx_trace_id = object.trace_id
ORDER BY s.selection_order;
