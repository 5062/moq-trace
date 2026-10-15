"""The standalone toolkit commands need neither the workspace nor SSH."""

from __future__ import annotations

import subprocess
import sys
import unittest


class StandaloneCliTests(unittest.TestCase):
    def test_toolkit_commands_import_without_the_workspace_or_ssh(self) -> None:
        source = """
import importlib.abc
import sys

class NoRunner(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {"asyncssh", "moq_workspace_bench"}:
            raise ImportError(f"standalone toolkit imported {fullname}")

sys.meta_path.insert(0, NoRunner())
from moq_trace.run.cli import parser
from moq_trace.run.verify import record

for arguments in (
    ["analyze", "trace", "--output", "analysis.duckdb", "--object-size", "1024", "--subscribers", "1"],
    ["verify", "trace", "--run", "fixture"],
    ["plot", "analysis.duckdb"],
):
    assert parser().parse_args(arguments).command == arguments[0]
"""
        result = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
