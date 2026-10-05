"""Check the provider declarations and analyzer as one current-release contract."""

from __future__ import annotations

import pathlib
import re
import sys
import unittest

import pyarrow as pa

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python/src"))

from moq_trace.decode import ctf  # noqa: E402


class ProviderContractTests(unittest.TestCase):
    def test_provider_fields_types_and_enums_match_the_analyzer(self) -> None:
        for provider, events in ctf.PROVIDER_EVENTS.items():
            directory = ROOT / "crates" / (provider.replace("_", "-") + "-lttng-sys") / "provider"
            header = re.sub(r"/\*.*?\*/", "", (directory / "interface.h").read_text(), flags=re.S)
            template = (directory / "events.tp").read_text()
            declared = re.findall(r"EVENT\((\w+)\)", (directory / "events.inc").read_text())
            self.assertCountEqual(declared, events)
            blocks = dict(
                re.findall(
                    rf"LTTNG_UST_TRACEPOINT_EVENT\({provider}, (\w+),(.*?)(?=LTTNG_UST_TRACEPOINT_EVENT|\Z)",
                    template,
                    re.S,
                )
            )
            self.assertCountEqual(blocks, events)
            enum_blocks = dict(
                re.findall(
                    rf"LTTNG_UST_TRACEPOINT_ENUM\({provider}, (\w+),(.*?)(?=LTTNG_UST_TRACEPOINT_(?:ENUM|EVENT)|\Z)",
                    template,
                    re.S,
                )
            )
            enums = {}
            for name, body in enum_blocks.items():
                constants = re.findall(r'lttng_ust_field_enum_value\("(\w+)", (\w+)\)', body)
                native = re.search(rf"enum {provider}_{name}\s*\{{(.*?)\}}", header, re.S)
                self.assertIsNotNone(native, name)
                entries = re.findall(r"\b([A-Z][A-Z_0-9]+)\s*,", native[1])
                # Declaration order assigns the numeric encoding; labels must
                # follow that order and preserve each constant's meaning.
                self.assertEqual([constant for _, constant in constants], entries)
                self.assertEqual(
                    [label for label, _ in constants],
                    [constant.removeprefix(f"{provider}_{name}_".upper()).lower() for constant in entries],
                )
                enums[name] = constants
            for event in events:
                with self.subTest(event=event):
                    struct = re.search(rf"struct {provider}_{event}\s*\{{(.*?)\}}", header, re.S)
                    native_fields = re.findall(r"(uint\d+_t)\s+(\w+);", struct[1])
                    integers = re.findall(r"lttng_ust_field_integer\((uint\d+_t), (\w+), event->(\w+)\)", blocks[event])
                    enum_fields = re.findall(
                        rf"lttng_ust_field_enum\({provider}, (\w+), (uint\d+_t), (\w+), event->(\w+)\)",
                        blocks[event],
                    )
                    emitted = [(kind, name) for kind, name, source in integers]
                    emitted += [(kind, name) for enum, kind, name, source in enum_fields]
                    self.assertCountEqual(emitted, native_fields)
                    self.assertTrue(all(name == source for _, name, source in integers))
                    self.assertTrue(all(name == source and enum in enums for enum, _, name, source in enum_fields))
                    labels = {name for _, _, name, _ in enum_fields}
                    schema = ctf.SCHEMAS[event]
                    self.assertCountEqual(
                        [name for _, name in native_fields if not name.startswith("has_")],
                        schema.names[len(ctf.CONTEXT_FIELDS) :],
                    )
                    for kind, name in native_fields:
                        if name.startswith("has_"):
                            self.assertEqual(kind, "uint8_t")
                            self.assertIn(name.removeprefix("has_"), schema.names)
                        elif name in labels:
                            self.assertEqual(schema.field(name).type, pa.string())
                        elif name == "timestamp_ns":
                            # Native monotonic clocks are unsigned; analysis
                            # rejects overflow before signed span arithmetic.
                            self.assertEqual(kind, "uint64_t")
                            self.assertEqual(schema.field(name).type, pa.int64())
                        else:
                            self.assertEqual(schema.field(name).type, getattr(pa, kind.removesuffix("_t"))())


if __name__ == "__main__":
    unittest.main()
