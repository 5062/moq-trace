-- Construction macros are temporary and never required by artifact readers.
-- Widen unsigned timestamps before subtraction so reversed spans stay signed.
CREATE OR REPLACE TEMP MACRO span_ns(start, finish) AS (finish::HUGEINT - start::HUGEINT)::BIGINT;

-- Clamp pre-origin elapsed times to zero.
CREATE OR REPLACE TEMP MACRO elapsed_ns(instant, origin) AS greatest(span_ns(origin, instant), 0);

-- Plotting conversions use microseconds.
CREATE OR REPLACE TEMP MACRO span_us(start, finish) AS span_ns(start, finish) / 1000.0;

-- Half-open offset buckets keep zero-length ranges in their offset bucket.
CREATE OR REPLACE TEMP MACRO offset_buckets(start, finish, width) AS range(
         (start // width)::BIGINT,
         ((greatest(finish, start + 1) - 1) // width + 1)::BIGINT
       );
