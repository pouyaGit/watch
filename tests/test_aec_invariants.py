"""EPIC6 Part 17: security invariants — AST guards for the execution layer."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

NEW_PACKAGES = (
    "aec/execution",
    "aec/specialists",
    "aec/research",
    "aec/evidence_bridge",
    "aec/runtime",
    "aec/replay",
)

FORBIDDEN_IMPORTS = (
    "socket",
    "ssl",
    "http",
    "urllib",
    "subprocess",
    "requests",
    "aiohttp",
    "httpx",
)

FORBIDDEN_MODULES = (
    "ai.execution",
    "ai.authorizer",
    "ai.evidence",
    "ai.verification",
    "backend",
)

FORBIDDEN_WORDS = (
    "confirmed",
    "vulnerable",
    "exploitable",
    "finding",
    "verdict",
    "exploit",
    "live_deps",
    "observation_lane",
)

# The claim guard enumerates the banned words by design (it is the
# enforcer), so the vocabulary scans exempt it.
ENFORCER_EXEMPT = ("aec/research/guard.py",)


def module_files():
    for package in NEW_PACKAGES:
        directory = ROOT / package
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.py")):
            yield package, path


def code_constants(path: Path) -> set[str]:
    """String literals outside docstrings/comments in a module."""
    tree = ast.parse(path.read_text())
    constants: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            continue  # docstring
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            constants.add(node.value.lower())
        elif isinstance(node, ast.Attribute):
            constants.add(node.attr.lower())
    return constants


class TestNoNetworkImports(unittest.TestCase):
    def test_no_forbidden_imports(self):
        for package, path in module_files():
            tree = ast.parse(path.read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(
                        alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            for forbidden in FORBIDDEN_IMPORTS:
                self.assertNotIn(
                    forbidden, imported, f"{package}:{path.name}")


class TestNoBackendImports(unittest.TestCase):
    def test_no_backend_or_ai_imports(self):
        for package, path in module_files():
            tree = ast.parse(path.read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module)
            for forbidden in FORBIDDEN_MODULES:
                self.assertNotIn(
                    forbidden, imported, f"{package}:{path.name}")


class TestNoVerdictVocabulary(unittest.TestCase):
    def test_no_conclusion_words_in_code(self):
        for package, path in module_files():
            relative = str(path.relative_to(ROOT))
            if relative in ENFORCER_EXEMPT:
                continue
            constants = code_constants(path)
            for word in FORBIDDEN_WORDS:
                self.assertNotIn(
                    word, constants,
                    f"{package}:{path.name} code contains {word!r}")


class TestNoArbitraryHttp(unittest.TestCase):
    def test_no_http_verb_phrases_in_execution(self):
        directory = ROOT / "aec/execution"
        if not directory.exists():
            return
        for path in directory.glob("*.py"):
            text = path.read_text()
            self.assertNotIn("requests.", text)
            self.assertNotIn("http.client", text)
            self.assertNotIn("urlopen", text)


class TestAuthorizationBoundary(unittest.TestCase):
    def test_no_bypass_in_code(self):
        for package, path in module_files():
            relative = str(path.relative_to(ROOT))
            if relative in ENFORCER_EXEMPT:
                continue
            constants = code_constants(path)
            self.assertNotIn(
                "bypass", constants, f"{package}:{path.name}")

    def test_executor_mentions_waiting_authorization(self):
        path = ROOT / "aec/execution/executor.py"
        if path.exists():
            text = path.read_text()
            self.assertIn("WAITING_AUTHORIZATION", text)


class TestEvidenceBoundary(unittest.TestCase):
    def test_evidence_bridge_never_creates_findings(self):
        path = ROOT / "aec/evidence_bridge/bridge.py"
        if path.exists():
            constants = code_constants(path)
            self.assertNotIn("finding", constants)


class TestSourceModeSeparation(unittest.TestCase):
    def test_source_modes_stated_everywhere(self):
        for package, path in module_files():
            if path.name in ("models.py", "__init__.py"):
                continue
            relative = str(path.relative_to(ROOT))
            if relative in ENFORCER_EXEMPT:
                continue
            text = path.read_text()
            if "source_mode" in text or "SOURCE_MODES" in text:
                # Modules that import the closed vocabulary from the
                # identity module are covered by the owner's statement.
                if "from aec.replay.identity import" in text:
                    continue
                self.assertIn("OFFLINE_FIXTURE", text,
                              f"{package}:{path.name}")
                self.assertIn("REAL_WATCH_DATA", text,
                              f"{package}:{path.name}")


class TestLiveModulesAbsent(unittest.TestCase):
    def test_no_live_deps_module(self):
        self.assertFalse((ROOT / "aec/live_deps.py").exists())

    def test_no_observation_lane_module(self):
        self.assertFalse((ROOT / "aec/observation_lane.py").exists())

    def test_no_socket_usage_anywhere_in_aec(self):
        aec_directory = ROOT / "aec"
        for path in aec_directory.rglob("*.py"):
            if "no_network" in path.name:
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotEqual(
                            alias.name, "socket", f"{path}")

    def test_frozen_files_still_exist(self):
        for relative in (
            "ai/authorizer/service.py",
            "ai/verification/verifier.py",
            "backend/tasks_registry.py",
            "backend/task_runner.py",
        ):
            self.assertTrue((ROOT / relative).exists(), relative)


if __name__ == "__main__":
    unittest.main()