from __future__ import annotations

import pathlib
import random
import sys

import pyarrow as pa

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE))

from analysis_case import ModelCase  # noqa: E402

from moq_trace.analysis import coverage, sql  # noqa: E402
from moq_trace.analysis.analyze import (  # noqa: E402
    _derive_samples,
    _select_window,
)
from moq_trace.decode import ctf  # noqa: E402
from moq_trace.errors import TraceError  # noqa: E402


class CoverageTests(ModelCase):
    """Resolve which packets cover each object's byte range."""

    def test_coverage_requires_packets_for_selected_objects(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)
        with self.assertRaisesRegex(TraceError, "does not have complete packet coverage"):
            coverage.resolve(self.connection)

    def test_empty_stream_frames_do_not_open_object_coverage(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.packet(5, "rx", 1)
        self.connection.execute(
            """UPDATE raw.quic_stream_frame
               SET offset_start = 8, offset_end = 8, timestamp_ns = 50000
               WHERE trace_id = 5"""
        )
        self.connection.execute("UPDATE raw.quic_packet_start SET timestamp_ns = 40000 WHERE trace_id = 5")
        self.connection.execute(
            "UPDATE raw.quic_packet_phase SET timestamp_ns = 40000 WHERE trace_id = 5 AND phase = 'read_queue' "
            "AND edge = 'start'"
        )
        self.prepare_model()
        origin = _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)

        coverage.resolve(self.connection)
        _derive_samples(self.connection, origin)

        self.assertEqual(
            self.connection.execute(
                """SELECT origin_ns, packet_ids FROM (SELECT c.object_trace_id AS trace_id, c.origin_ns,
                c.first_ns, c.complete_ns, list(p.packet_trace_id ORDER BY p.ordinal) AS packet_ids
                FROM model.coverage c JOIN model.coverage_packets p USING (object_trace_id) GROUP
                BY ALL) WHERE trace_id = 1"""
            ).fetchone(),
            (90000, [3]),
        )
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM selected_packets WHERE trace_id = 5").fetchone()[0],
            0,
        )

    def test_retransmissions_measure_repair_and_stay_out_of_coverage(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.object_phase(1, 1, "frame_commit", 150_000, 151_000)
        self.object_phase(2, 1, "payload_write", 205_000, 215_000)
        self.connection.execute("UPDATE raw.quic_stream_frame SET retransmission = 0 WHERE trace_id = 4")
        # A later packet resends the copy's bytes and completes 40 µs after it.
        self.packet(5, "tx", 2)
        self.connection.execute(
            "UPDATE raw.quic_stream_frame SET retransmission = 1 WHERE trace_id = 5;"
            "UPDATE raw.quic_packet_end SET timestamp_ns = 350000 WHERE trace_id = 5;"
            "UPDATE raw.quic_packet_phase SET timestamp_ns = 350000 WHERE trace_id = 5 AND edge = 'done'"
        )

        waits = self._transport_waits()
        self.assertEqual(waits["tx_repair"], 350_000 - 310_000)
        complete = self.connection.execute(
            "SELECT complete_packet_trace_id FROM model.coverage WHERE object_trace_id = 2"
        ).fetchone()[0]
        self.assertEqual(complete, 4, "the repair does not complete the copy")

    def test_dropped_frames_contribute_no_coverage(self) -> None:
        self.object_start(1, "rx", 1)
        self.object_start(2, "tx", 2)
        self.packet(3, "rx", 1)
        self.packet(4, "tx", 2)
        self.connection.execute("UPDATE raw.quic_stream_frame SET outcome = 'dropped' WHERE trace_id = 3")
        self.prepare_model()
        _select_window(self.connection, object_size=16, subscribers=1, warmup_seconds=0, cooldown_seconds=0)

        with self.assertRaisesRegex(TraceError, "object trace 1 does not have complete packet coverage"):
            coverage.resolve(self.connection)

    def _build_model(self) -> None:
        """Pair the raw events into the model without validating them, as a bare coverage input."""

        self.connection.execute("CREATE TYPE outcome AS ENUM ('success', 'malformed', 'dropped')")
        self.connection.execute(sql.read("model/schema"))
        self.connection.execute(sql.read("model/populate"))

    def insert_rows(self, table: str, rows: list[dict]) -> None:
        for row in rows:
            row.setdefault("pid", 0)
            row.setdefault("tid", 1)
        self.connection.register("rows", pa.Table.from_pylist(rows, schema=ctf.SCHEMAS[table]))
        self.connection.execute(f"INSERT INTO raw.{table} SELECT *, pid::UINTEGER AS process_id FROM rows")
        self.connection.unregister("rows")

    def _random_coverage_trace(self, seed: int, *, complete: bool) -> None:
        """Insert random targets and frames around bucket boundaries.

        When `complete` is set, every target is also tiled by frames sent in a
        random order, so each one resolves despite retransmissions, zero-length
        frames, and failed packets mixed into the recording.
        """

        bucket = coverage._BUCKET_BYTES
        generator = random.Random(seed)
        streams = [
            (connection_id, direction, stream_id)
            for connection_id in (1, 2)
            for direction in ("rx", "tx")
            for stream_id in (10, 11)
        ]
        targets, packet_starts, packet_ends, frames = [], [], [], []
        clock = iter(range(1, 1_000_000))

        def send(connection_id, direction, stream_id, ranges, outcome="success"):
            trace_id = 1_000 + len(packet_starts)
            packet_starts.append(
                dict(
                    ctf_timestamp_ns=next(clock),
                    timestamp_ns=next(clock),
                    trace_id=trace_id,
                    connection_id=connection_id,
                    direction=direction,
                )
            )
            packet_ends.append(
                dict(
                    ctf_timestamp_ns=next(clock),
                    timestamp_ns=generator.randrange(10**6, 10**6 + 50),
                    trace_id=trace_id,
                    outcome=outcome,
                )
            )
            for start, end in ranges:
                frames.append(
                    dict(
                        ctf_timestamp_ns=next(clock),
                        # A narrow clock range makes frames tie on time, so the
                        # packet end and ID tiebreaks are exercised too.
                        timestamp_ns=generator.randrange(40),
                        trace_id=trace_id,
                        stream_id=stream_id,
                        offset_start=start,
                        offset_end=end,
                        outcome=generator.choice(("success", "success", "malformed")) if not complete else "success",
                    )
                )

        for connection_id, direction, stream_id in streams:
            offset = generator.choice((0, bucket - 3))
            for _ in range(12):
                size = generator.choice((1, 17, 1_200, bucket - 1, bucket, bucket + 1, 3 * bucket + 5))
                targets.append((len(targets) + 1, connection_id, direction, stream_id, offset, offset + size))
                offset += size
            if complete:
                first = targets[-12][4]
                position = first
                while position < offset:
                    end = min(offset, position + generator.choice((1, 700, 1_200, bucket, 2 * bucket + 1)))
                    send(connection_id, direction, stream_id, [(position, end)])
                    position = end
            for _ in range(60):
                start = generator.choice((generator.randrange(offset + 1), generator.randrange(4) * bucket))
                length = generator.choice((0, 1, 1_200, bucket, 2 * bucket + 1, generator.randrange(3 * bucket)))
                ranges = [(start, start + length)] * generator.choice((1, 1, 2))
                send(
                    connection_id,
                    direction,
                    stream_id,
                    ranges,
                    outcome=generator.choice(("success", "success", "success", "dropped")),
                )
        self.insert_rows("quic_packet_start", packet_starts)
        self.insert_rows("quic_packet_end", packet_ends)
        self.insert_rows("quic_stream_frame", frames)
        self._build_model()
        self.connection.execute(
            """CREATE TEMP TABLE coverage_targets(trace_id UBIGINT, connection_id UBIGINT, direction VARCHAR,
                   stream_id UBIGINT, stream_offset_start UBIGINT, stream_offset_end UBIGINT)"""
        )
        self.connection.executemany("INSERT INTO coverage_targets VALUES (?, ?, ?, ?, ?, ?)", targets)
        self.connection.execute(sql.read("coverage/trace-source"))

    def _plain_overlaps(self) -> list[tuple]:
        """Pair targets with frames by a plain overlap join, in completion order.

        A TX frame completes at its packet's end, the send's completion, and an
        RX frame at its own timestamp, the receive buffer's acceptance.
        """

        return self.connection.execute(
            """SELECT object.trace_id, frame.offset_start, frame.offset_end,
                      packet.trace_id, packet.start_ns,
                      CASE packet.direction WHEN 'tx' THEN packet.end_ns ELSE frame.timestamp_ns END AS completion_ns
               FROM coverage_targets AS object
               JOIN model.packets AS packet
                 ON packet.connection_id = object.connection_id
                AND packet.direction = object.direction
                AND packet.outcome = 'success'
               JOIN quic_stream_frame AS frame
                 ON frame.trace_id = packet.trace_id
                AND frame.outcome = 'success'
                AND frame.stream_id = object.stream_id
                AND greatest(frame.offset_start, object.stream_offset_start)
                      < least(frame.offset_end, object.stream_offset_end)
               ORDER BY object.trace_id, completion_ns, packet.trace_id,
                        frame.offset_start, frame.offset_end"""
        ).fetchall()

    def test_bucketed_frames_match_the_plain_overlap_join(self) -> None:
        """The bucketed range join reports exactly the pairs a plain overlap join does."""

        self._random_coverage_trace(7, complete=False)
        expected = self._plain_overlaps()
        self.assertGreater(len(expected), 100)
        self.connection.execute(sql.read("coverage/frames-stage"), {"bucket": coverage._BUCKET_BYTES})
        self.assertEqual(
            self.connection.execute(
                """SELECT trace_id, offset_start, offset_end, packet_id, packet_start_ns, completion_ns
                   FROM coverage_frames ORDER BY trace_id, seq"""
            ).fetchall(),
            expected,
        )

    def test_coverage_matches_sequential_gap_subtraction(self) -> None:
        """Set-based completion agrees with replaying frames one at a time."""

        for seed in (7, 11, 23):
            with self.subTest(seed=seed):
                self.tearDown()
                self.setUp()
                self._random_coverage_trace(seed, complete=True)
                targets = self.connection.execute(
                    "SELECT trace_id, stream_offset_start, stream_offset_end FROM coverage_targets"
                ).fetchall()
                frames: dict[int, list[tuple]] = {}
                for row in self._plain_overlaps():
                    frames.setdefault(row[0], []).append(row[1:])
                expected = sorted(
                    (trace_id, *_sequential_coverage(start, end, frames.get(trace_id, ())))
                    for trace_id, start, end in targets
                )

                coverage._resolve_targets(self.connection)

                self.assertEqual(
                    self.connection.execute(
                        """SELECT * FROM (SELECT c.object_trace_id AS trace_id, c.origin_ns,
                            c.first_ns, c.complete_ns,
                        list(p.packet_trace_id ORDER BY p.ordinal) AS packet_ids FROM model.coverage c JOIN
                        model.coverage_packets p USING (object_trace_id) GROUP BY ALL) ORDER BY
                        trace_id"""
                    ).fetchall(),
                    expected,
                )

    def test_coverage_rejects_a_range_with_a_gap(self) -> None:
        self.packet(3, "rx", 1)
        self.connection.execute("UPDATE raw.quic_stream_frame SET offset_end = 8 WHERE trace_id = 3")
        self._build_model()
        self.connection.execute(
            """CREATE TEMP TABLE coverage_targets AS
               SELECT 1::UBIGINT AS trace_id, 1::UBIGINT AS connection_id, 'rx' AS direction,
                      10::UBIGINT AS stream_id, 0::UBIGINT AS stream_offset_start,
                      16::UBIGINT AS stream_offset_end"""
        )
        self.connection.execute(sql.read("coverage/trace-source"))
        with self.assertRaisesRegex(TraceError, "object trace 1 does not have complete packet coverage"):
            coverage._resolve_targets(self.connection)


def _sequential_coverage(start: int, end: int, frames) -> tuple:
    """Replay `frames` in order until they cover `[start, end)`, as a reference.

    Returns the earliest packet start among the replayed frames, the completion
    of the first frame, the completion of the frame that closes the last gap,
    and the packets in order of first use.
    """

    gaps = [(start, end)]
    packet_ids: list[int] = []
    first = None
    origin = None
    for offset_start, offset_end, packet_id, packet_start, completion in frames:
        covered_start, covered_end = max(offset_start, start), min(offset_end, end)
        remaining = []
        for left, right in gaps:
            if covered_end <= left or right <= covered_start:
                remaining.append((left, right))
                continue
            if left < covered_start:
                remaining.append((left, covered_start))
            if covered_end < right:
                remaining.append((covered_end, right))
        gaps = remaining
        if packet_id not in packet_ids:
            packet_ids.append(packet_id)
        if first is None:
            first = completion
        origin = packet_start if origin is None else min(origin, packet_start)
        if not gaps:
            return (origin, first, completion, packet_ids)
    raise AssertionError(f"reference coverage of [{start}, {end}) is incomplete")
