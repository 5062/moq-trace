"""Check the direction of imports between the package layers.

Analysis must be able to re-run on a capture without SSH or host code, and the
decoders must stay usable without the DuckDB pipeline, so a lower layer
importing a higher one fails here instead of surfacing as a dependency cycle.
"""

from __future__ import annotations

import ast
import pathlib
import unittest

PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "src" / "moq_trace"

# Each layer may import itself, the shared root modules, and the layers listed.
ALLOWED = {
    "decode": set(),
    "analysis": {"decode"},
    "plot": {"analysis"},
    "run": {"analysis", "decode", "plot"},
}
LAYERS = set(ALLOWED)


def layers_in(source: str, package: tuple[str, ...]) -> set[str]:
    """Return the layers that `source`, a module of `package`, imports."""

    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            base = package[: len(package) - (node.level - 1)]
            module = tuple(node.module.split(".")) if node.module else ()
            targets = [base + module] if module else [base + (alias.name,) for alias in node.names]
        elif node.module and node.module.startswith("moq_trace."):
            targets = [tuple(node.module.split("."))[1:]]
        else:
            continue
        found.update(target[0] for target in targets if target and target[0] in LAYERS)
    return found


def imported_layers(path: pathlib.Path) -> set[str]:
    return layers_in(path.read_text(), path.relative_to(PACKAGE).parts[:-1])


class LayeringTests(unittest.TestCase):
    def test_lower_layers_do_not_import_higher_ones(self) -> None:
        for layer, allowed in ALLOWED.items():
            for path in sorted((PACKAGE / layer).rglob("*.py")):
                with self.subTest(module=str(path.relative_to(PACKAGE))):
                    self.assertLessEqual(imported_layers(path) - {layer}, allowed)

    def test_shared_root_modules_do_not_import_a_layer(self) -> None:
        # render is the presentation entry point and names the layers it draws from.
        for name in ("errors", "manifest", "metadata", "labels"):
            with self.subTest(module=name):
                self.assertEqual(imported_layers(PACKAGE / f"{name}.py"), set())

    def test_the_guard_detects_an_upward_import(self) -> None:
        source = "from ..run import hosts\nfrom .. import labels, run\nfrom moq_trace.run import cli\n"
        self.assertEqual(layers_in(source, ("analysis",)), {"run"})
        self.assertEqual(
            layers_in("from . import sql\nfrom ..decode import ctf\n", ("analysis",)), {"analysis", "decode"}
        )


if __name__ == "__main__":
    unittest.main()
