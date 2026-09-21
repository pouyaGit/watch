"""EPIC7 Part 19: invariants — AST guards for the observation runtime.

The runtime is the ONE place a transport may live (EPIC7 §5 requires a
real, narrowly scoped observation adapter). Everything else must stay
network-free. This module pins:

- exactly one sanctioned transport file may import http/socket;
- that transport imports lazily (never at module import time);
- no raw-URL submission paths; no verdict vocabulary;
- frozen EPIC6 files byte-identical scope (asserted by hashes in the
  read-only manifest — here we pin structural boundaries).
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: The single sanctioned transport module (EPIC7 §5 adapter).
SANCTIONED_TRANSPORT = "aec/runtime/adapters/http_observation.py"

RUNTIME_DIRS = (
    "aec/runtime/policy",
    "aec/runtime/adapters",
    "aec/runtime/execution",
    "aec/runtime/results",
)

FORBIDDEN_WORDS = (
    "confirmed", "vulnerable", "exploitable", "finding", "verdict",
    "exploit", "live_deps", "observation_lane", "bypass",
)

TRANSPORT_NAMES = ("socket", "http", "urllib", "requests", "httpx",
                   "aiohttp", "ssl")


def _py_files():
    for directory in RUNTIME_DIRS:
        base = ROOT / directory
        if base.exists():
            for path in sorted(base.glob("*.py")):
                yield path


class TestSingleTransport(unittest.TestCase):
    def test_only_sanctioned_module_imports_transport(self):
        for path in _py_files():
            relative = str(path.relative_to(ROOT))
            if relative == SANCTIONED_TRANSPORT:
                continue
            tree = ast.parse(path.read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(
                        alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
            for name in TRANSPORT_NAMES:
                self.assertNotIn(
                    name, imported,
                    f"{relative} imports transport {name!r}")

    def test_sanctioned_transport_imports_lazily(self):
        """http/socket imports must be function-local, never top-level."""
        path = ROOT / SANCTIONED_TRANSPORT
        self.assertTrue(path.exists())
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name.split(".")[0] for a in node.names] \
                    if isinstance(node, ast.Import) else [node.module or ""]
                if isinstance(node, ast.ImportFrom):
                    names = [node.module.split(".")[0]]
                if any(n in TRANSPORT_NAMES for n in names):
                    parent = _function_parent(tree, node)
                    self.assertIsNotNone(
                        parent, "transport import must be function-local")

    def test_sanctioned_module_exists_only_once(self):
        matches = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")
                   if "http" in p.name and "observation" in p.name]
        self.assertEqual(matches, [SANCTIONED_TRANSPORT])


def _function_parent(tree: ast.Module, target: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if child is target:
                    return node
    return None


class TestNoVerdictVocabulary(unittest.TestCase):
    def test_no_conclusion_words_in_code(self):
        for path in _py_files():
            relative = str(path.relative_to(ROOT))
            if relative == SANCTIONED_TRANSPORT:
                continue
            tree = ast.parse(path.read_text())
            constants: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Expr) and isinstance(
                        node.value, ast.Constant) and isinstance(
                            node.value.value, str):
                    continue  # docstring
                if isinstance(node, ast.Constant) and isinstance(
                        node.value, str):
                    constants.add(node.value.lower())
                elif isinstance(node, ast.Attribute):
                    constants.add(node.attr.lower())
            for word in FORBIDDEN_WORDS:
                self.assertNotIn(word, constants,
                                 f"{relative} contains {word!r}")


class TestNoRawUrlSubmission(unittest.TestCase):
    def test_runtime_never_accepts_raw_url_parameter(self):
        for path in _py_files():
            if path.name == "__init__.py":
                continue
            text = path.read_text()
            self.assertNotIn('"url"', text, str(path))
            self.assertNotIn("'url'", text, str(path))


class TestSourceModeSeparation(unittest.TestCase):
    def test_runtime_mentions_both_modes(self):
        path = ROOT / "aec/runtime/execution/runtime.py"
        text = path.read_text()
        self.assertIn("REAL_WATCH_DATA", text)
        self.assertIn("OFFLINE_FIXTURE", text)

    def test_dry_run_never_executes(self):
        path = ROOT / "aec/runtime/execution/runtime.py"
        text = path.read_text()
        self.assertIn("DRY_RUN", text)
        # The transport must never be invoked in dry-run: pin the refusal
        # shape that the runtime tests already assert behaviorally.
        self.assertIn("executed=False", text)


class TestFrozenBoundary(unittest.TestCase):
    def test_runtime_does_not_import_executor(self):
        """The runtime consumes executor output; it must not import the
        EPIC6 executor module (which is data-only and separate)."""
        for path in _py_files():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotEqual(
                        node.module, "aec.execution.executor", str(path))
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotEqual(
                            alias.name, "aec.execution.executor",
                            str(path))

    def test_no_verification_chain_imports(self):
        for path in _py_files():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(
                        node.module.startswith(("ai.verification",
                                                "ai.authorizer",
                                                "ai.execution")),
                        str(path))


class TestPolicyFailClosed(unittest.TestCase):
    def test_no_wildcard_imports(self):
        for path in _py_files():
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(
                        a.name == "*" for a in node.names):
                    self.fail(f"wildcard import in {path}")


if __name__ == "__main__":
    unittest.main()