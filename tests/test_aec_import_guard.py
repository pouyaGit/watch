"""Static guard on the aec/ package (S1/S2 boundary).

Execution plan §4.3 for ``test_aec_import_guard.py``:

- static AST scan: no forbidden imports in ``aec/`` (§2.3)
- ``aec/live_deps.py`` and ``aec/observation_lane.py`` do not exist in this phase

The point is structural: AEC-1's offline half must be unable to reach the
network, spawn processes, or widen into the authority chain, whatever a future
edit intends. If a module needs a transport, that is Track B and needs an
operator authorization — not an import.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[1]
AEC_DIR = REPO_ROOT / "aec"

#: Modules aec/ may import. Everything else must be justified in review.
ALLOWED_STDLIB = frozenset(
    {
        "__future__",
        "aec",
        "argparse",
        "collections",
        "dataclasses",
        "datetime",
        "enum",
        "functools",
        "hashlib",
        "itertools",
        "json",
        "math",
        "pathlib",
        "re",
        "string",
        "typing",
        "unicodedata",
        "uuid",
    }
)

#: Never allowed, whatever the reason (transport, process, or project internals).
FORBIDDEN_MODULES = frozenset(
    {
        "asyncio",
        "backend",
        "boto3",
        "concurrent",
        "ctypes",
        "dns",
        "ftplib",
        "http",
        "httpx",
        "importlib",
        "multiprocessing",
        "os",
        "paramiko",
        "pymongo",
        "requests",
        "scapy",
        "shelve",
        "shutil",
        "signal",
        "socket",
        "socketserver",
        "sqlite3",
        "ssl",
        "subprocess",
        "telnetlib",
        "tempfile",
        "urllib",
        "urllib3",
        "webbrowser",
        "websocket",
        "websockets",
        "ai",
        "watch_xss_verify",
    }
)

#: Modules that belong to the separately authorized Track B and must not exist yet.
MUST_NOT_EXIST = (
    AEC_DIR / "live_deps.py",
    AEC_DIR / "observation_lane.py",
)

#: Danger flags that must never be raised to True inside aec/.
FORBIDDEN_FLAG_VALUES = {
    "AEC_LIVE_HTTP_ENABLED": False,
}

#: Frozen production capability gates: aec/ may document them, never set them.
FROZEN_LIVE_FLAGS = frozenset({"LIVE_TRAFFIC_ENABLED", "LIVE_BROWSER", "LIVE_NUCLEI"})


def _assignment_targets(node):
    """Targets being assigned to by ``node`` (empty list for other statements)."""
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return [node.target]
    return []


def _target_text(target) -> str:
    """Dotted source text of an assignment target (``ai.executor.FLAG``)."""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        prefix = _target_text(target.value)
        return f"{prefix}.{target.attr}" if prefix else target.attr
    return ""


def aec_modules():
    return sorted(path for path in AEC_DIR.glob("*.py"))


class TestImportGuard(unittest.TestCase):
    def test_the_package_has_modules_to_guard(self):
        self.assertGreaterEqual(len(aec_modules()), 5)

    def test_no_forbidden_imports(self):
        offenders = []
        for path in aec_modules():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    names = [node.module.split(".")[0]]
                else:
                    continue
                for name in names:
                    if name in FORBIDDEN_MODULES:
                        offenders.append(f"{path.name}:{node.lineno} imports {name}")
                    elif name not in ALLOWED_STDLIB:
                        offenders.append(f"{path.name}:{node.lineno} imports {name} (not on the allowlist)")
        self.assertEqual(offenders, [], f"forbidden imports in aec/: {offenders}")

    def test_no_dynamic_import_escape_hatches(self):
        banned_bare = {"__import__", "compile", "eval", "exec", "input"}
        banned_attrs = {
            "check_call",
            "check_output",
            "import_module",
            "load_module",
            "popen",
            "Popen",
            "spawn",
            "spawnl",
            "spawnv",
            "system",
        }
        offenders = []
        for path in aec_modules():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                # ``re.compile`` compiles a pattern, it is not the builtin.
                if isinstance(func, ast.Name) and func.id in banned_bare:
                    offenders.append(f"{path.name}:{node.lineno} calls {func.id}")
                elif isinstance(func, ast.Attribute) and func.attr in banned_attrs:
                    offenders.append(f"{path.name}:{node.lineno} calls .{func.attr}")
        self.assertEqual(offenders, [], f"dynamic execution in aec/: {offenders}")

    def test_track_b_modules_do_not_exist_yet(self):
        for path in MUST_NOT_EXIST:
            self.assertFalse(path.exists(), f"{path} belongs to Track B and must not exist in this phase")

    def test_aec_own_live_flag_is_false_at_runtime(self):
        import aec

        self.assertIs(aec.AEC_LIVE_HTTP_ENABLED, False, "AEC-1 live HTTP must stay disabled")

    def test_capability_flags_are_never_raised_from_aec(self):
        """aec/ may *document* the frozen gates, never move them.

        What matters is assignment: no AEC-1 module may set a frozen live flag,
        by name, by attribute, or through ``setattr``.
        """
        offenders = []
        for path in aec_modules():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                for target in _assignment_targets(node):
                    text = _target_text(target)
                    if text in FROZEN_LIVE_FLAGS or text.split(".")[-1] in FROZEN_LIVE_FLAGS:
                        offenders.append(f"{path.name}:{node.lineno} assigns {text}")
                if isinstance(node, ast.Call):
                    func = node.func
                    name = getattr(func, "id", None) or getattr(func, "attr", None)
                    if name == "setattr" and len(node.args) >= 2:
                        literal = node.args[1]
                        if isinstance(literal, ast.Constant) and literal.value in FROZEN_LIVE_FLAGS:
                            offenders.append(f"{path.name}:{node.lineno} setattr({literal.value})")
        self.assertEqual(offenders, [], f"aec/ must never raise a frozen live gate: {offenders}")

    def test_public_api_never_claims_a_verdict(self):
        for path in aec_modules():
            # ``NOT_CONFIRMED`` is the plan's mandated disclaimer, not a claim.
            text = path.read_text(encoding="utf-8").replace("NOT_CONFIRMED", "")
            for forbidden in ("CONFIRMED", "CONFIDENT", "EXPLOITABLE", "SEVERITY_", "VULNERABLE"):
                self.assertNotIn(forbidden, text, f"{path.name} must not carry verdict vocabulary")


if __name__ == "__main__":
    unittest.main()
