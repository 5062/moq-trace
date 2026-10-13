-- The inbound objects that started inside the steady-state window.
CREATE TEMP TABLE selected_rx AS
SELECT * FROM model.objects
SEMI JOIN inbound_objects AS inbound USING (trace_id)
WHERE start_ns BETWEEN $start AND $end;
