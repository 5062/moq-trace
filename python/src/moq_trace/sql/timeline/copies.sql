-- The copies of one selected object, with each copy's end relative to `$origin`.
SELECT session_id, copy_ordinal, (end_ns - $origin) / 1000.0
FROM model.objects
WHERE rx_trace_id = $rx AND copy_ordinal IS NOT NULL
ORDER BY copy_ordinal;
