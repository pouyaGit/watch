"""Tests for scripts/watch-agent/delivery/policy.py (Autonomous Delivery Pipeline v1).

The policy module is a *deterministic, side-effect-free* description of what
the delivery layer may promote. These tests pin the policy surface, the path
classification, the promotion rules and the absence of any execution or
filesystem write.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parents[1]
DELIVERY_DIR = REPO_ROOT / "scripts" / "watch-agent" / "delivery"
POLICY_PATH = DELIVERY_DIR / "policy.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PolicyTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_module("watch_delivery_policy", POLICY_PATH)


class TestPolicySurface(PolicyTestCase):
    def test_policy_file_exists(self):
        self.assertTrue(POLICY_PATH.is_file(), f"missing {POLICY_PATH}")

    def test_policy_version_is_declared(self):
        self.assertTrue(self.policy.POLICY_VERSION)

    def test_allowed_and_forbidden_paths_are_declared_and_ordered(self):
        self.assertIsInstance(self.policy.ALLOWED_PATHS, tuple)
        self.assertIsInstance(self.policy.FORBIDDEN_PATHS, tuple)
        self.assertTrue(self.policy.ALLOWED_PATHS)
        self.assertTrue(self.policy.FORBIDDEN_PATHS)

    def test_required_checks_are_the_six_documented_checks(self):
        self.assertEqual(
            self.policy.REQUIRED_CHECKS,
            (
                "BRANCH",
                "COMMIT",
                "TESTS",
                "PATH_GUARD",
                "REPORT",
                "PRODUCTION_UNTOUCHED",
            ),
        )

    def test_every_required_check_has_a_description(self):
        for check in self.policy.REQUIRED_CHECKS:
            self.assertIn(check, self.policy.CHECK_DESCRIPTIONS)
            self.assertTrue(self.policy.CHECK_DESCRIPTIONS[check])

    def test_verdict_constants(self):
        self.assertEqual(self.policy.VERDICT_READY, "READY FOR PROMOTION")
        self.assertEqual(self.policy.VERDICT_BLOCKED, "BLOCKED")
        self.assertEqual(self.policy.CHECK_PASS, "PASS")
        self.assertEqual(self.policy.CHECK_BLOCK, "BLOCK")
        self.assertEqual(self.policy.CHECK_SKIPPED, "SKIPPED")

    def test_policy_declares_that_it_never_executes(self):
        self.assertFalse(self.policy.POLICY_EXECUTES)
        self.assertTrue(self.policy.POLICY_SIDE_EFFECT_FREE)


class TestPathClassification(PolicyTestCase):
    def dominant(self, path):
        return self.policy.classify_path(path)

    def test_allowed_paths(self):
        for path in (
            "aec/selection.py",
            "tests/test_delivery_policy.py",
            "agent-reports/autonomous-delivery-pipeline-v1.md",
            "scripts/watch-agent/delivery/status.sh",
            "ai_data/aec/pilot-selection.json",
            "docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md",
            "backend/investigation_engine/request_planner.py",
            "web/templates/command_center.html",
            "api.py",
            ".gitignore",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.dominant(path), "ALLOWED")
                self.assertTrue(self.policy.is_allowed_path(path))

    def test_forbidden_authority_chain_paths(self):
        for path in (
            "ai/execution/http_executor.py",
            "ai/evidence/builder.py",
            "ai/verification/deterministic/gate.py",
            "ai/authorizer/service.py",
            "ai/finding/eligibility.py",
            "ai/limits/ceilings.py",
            "ai/live_validation/lane.py",
            "ai/schemas/execution_authorization.py",
            "watch_xss_verify.py",
            "backend/tasks_registry.py",
            "AGENTS.md",
            "run-pipeline.sh",
            ".github/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.dominant(path), "FORBIDDEN")
                self.assertTrue(self.policy.is_forbidden_path(path))
                self.assertFalse(self.policy.is_allowed_path(path))

    def test_forbidden_covers_new_files_in_a_forbidden_directory(self):
        self.assertEqual(self.dominant("ai/execution/brand_new_module.py"), "FORBIDDEN")
        self.assertEqual(self.dominant("systemd/watch-delivery.service"), "SYSTEM")

    def test_secret_paths(self):
        for path in (".env", ".env.local", "deploy/server.pem", "config/id_rsa", "keys/private.key"):
            with self.subTest(path=path):
                self.assertEqual(self.dominant(path), "SECRET")
                self.assertEqual(self.policy.severity_for(self.dominant(path)), "BLOCK")

    def test_env_file_reports_both_secret_and_environment_kinds(self):
        kinds = self.policy.classify_path_kinds(".env")
        self.assertIn("SECRET", kinds)
        self.assertIn("ENV", kinds)
        self.assertEqual(self.dominant(".env"), "SECRET")

    def test_system_paths(self):
        for path in ("systemd/watch.service", "systemd/watch.timer", "watch-backup.socket"):
            with self.subTest(path=path):
                self.assertEqual(self.dominant(path), "SYSTEM")

    def test_unknown_path_is_a_warning_not_a_block(self):
        self.assertEqual(self.dominant("some-new-top-level-dir/thing.py"), "UNKNOWN")
        self.assertEqual(self.policy.severity_for("UNKNOWN"), "WARN")

    def test_classification_is_total_and_never_raises(self):
        for path in ("", "/", "..", "../../etc/passwd", "C:\\Windows\\system32", "./a/../b.py"):
            with self.subTest(path=path):
                self.assertIsInstance(self.dominant(path), str)
                self.assertTrue(self.policy.classify_path_kinds(path))

    def test_traversal_is_never_allowed(self):
        self.assertEqual(self.dominant("../../etc/passwd"), "FORBIDDEN")
        self.assertFalse(self.policy.is_allowed_path("../outside.py"))

    def test_leading_dot_slash_is_normalised(self):
        self.assertEqual(self.dominant("./aec/selection.py"), "ALLOWED")
        self.assertEqual(self.dominant("/opt/watch/aec/selection.py"), "ALLOWED")

    def test_blocking_severity_for_forbidden_secret_env_system(self):
        for kind in ("FORBIDDEN", "SECRET", "ENV", "SYSTEM"):
            with self.subTest(kind=kind):
                self.assertEqual(self.policy.severity_for(kind), "BLOCK")


class TestDeterminism(PolicyTestCase):
    def test_fingerprint_is_stable(self):
        first = self.policy.policy_fingerprint()
        second = self.policy.policy_fingerprint()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_document_is_json_serialisable_and_sorted(self):
        document = self.policy.policy_document()
        first = json.dumps(document, sort_keys=True)
        second = json.dumps(self.policy.policy_document(), sort_keys=True)
        self.assertEqual(first, second)
        json.loads(first)

    def test_classification_is_idempotent(self):
        paths = ["aec/x.py", "ai/execution/y.py", ".env", "systemd/a.service", "misc/z"]
        once = [self.policy.classify_path(p) for p in paths]
        twice = [self.policy.classify_path(p) for p in paths]
        self.assertEqual(once, twice)

    def test_path_lists_have_no_duplicates(self):
        for name in ("ALLOWED_PATHS", "FORBIDDEN_PATHS", "SECRET_PATTERNS", "ENV_PATTERNS", "SYSTEM_PATTERNS"):
            with self.subTest(collection=name):
                items = getattr(self.policy, name)
                self.assertEqual(len(items), len(set(items)))


class TestPromotionRules(PolicyTestCase):
    def passing(self):
        return {check: "PASS" for check in self.policy.REQUIRED_CHECKS}

    def test_all_checks_pass_is_ready(self):
        result = self.policy.promotion_verdict(self.passing())
        self.assertEqual(result["verdict"], self.policy.VERDICT_READY)
        self.assertEqual(result["blocking"], [])
        self.assertFalse(result["blocked"])

    def test_any_blocking_check_blocks(self):
        checks = self.passing()
        checks["PATH_GUARD"] = "BLOCK"
        result = self.policy.promotion_verdict(checks)
        self.assertEqual(result["verdict"], self.policy.VERDICT_BLOCKED)
        self.assertTrue(result["blocked"])
        self.assertIn("PATH_GUARD", " ".join(result["blocking"]))

    def test_missing_check_blocks(self):
        checks = self.passing()
        del checks["TESTS"]
        result = self.policy.promotion_verdict(checks)
        self.assertEqual(result["verdict"], self.policy.VERDICT_BLOCKED)
        self.assertIn("TESTS", " ".join(result["blocking"]))

    def test_unknown_check_name_blocks(self):
        checks = self.passing()
        checks["MADE_UP"] = "PASS"
        result = self.policy.promotion_verdict(checks)
        self.assertEqual(result["verdict"], self.policy.VERDICT_BLOCKED)
        self.assertIn("MADE_UP", " ".join(result["blocking"]))

    def test_skipped_tests_is_ready_but_labelled_unverified(self):
        checks = self.passing()
        checks["TESTS"] = "SKIPPED"
        result = self.policy.promotion_verdict(checks)
        self.assertEqual(result["verdict"], "READY FOR PROMOTION (TESTS SKIPPED)")
        self.assertFalse(result["blocked"])
        self.assertEqual(result["skipped"], ["TESTS"])

    def test_skipped_check_does_not_hide_a_block(self):
        checks = self.passing()
        checks["TESTS"] = "SKIPPED"
        checks["REPORT"] = "BLOCK"
        result = self.policy.promotion_verdict(checks)
        self.assertEqual(result["verdict"], self.policy.VERDICT_BLOCKED)

    def test_verdict_is_order_independent(self):
        forward = self.policy.promotion_verdict(self.passing())
        reverse = self.policy.promotion_verdict(
            dict(reversed(list(self.passing().items())))
        )
        self.assertEqual(forward, reverse)

    def test_reasons_are_sorted_and_unique(self):
        checks = self.passing()
        checks["PATH_GUARD"] = "BLOCK"
        checks["REPORT"] = "BLOCK"
        result = self.policy.promotion_verdict(checks)
        self.assertEqual(result["blocking"], sorted(set(result["blocking"])))

    def test_non_string_check_state_blocks_instead_of_crashing(self):
        checks = self.passing()
        checks["TESTS"] = None
        result = self.policy.promotion_verdict(checks)
        self.assertEqual(result["verdict"], self.policy.VERDICT_BLOCKED)

    def test_empty_check_set_blocks(self):
        result = self.policy.promotion_verdict({})
        self.assertEqual(result["verdict"], self.policy.VERDICT_BLOCKED)
        self.assertEqual(len(result["blocking"]), len(self.policy.REQUIRED_CHECKS))


class TestNoExecutionOrWrites(unittest.TestCase):
    """policy.py must be pure: no execution, no imports that can act."""

    @classmethod
    def setUpClass(cls):
        cls.source = POLICY_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def imports(self):
        names = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split(".")[0])
        return names

    def test_forbidden_imports_absent(self):
        forbidden = {
            "os",
            "subprocess",
            "socket",
            "shutil",
            "pathlib",
            "tempfile",
            "http",
            "urllib",
            "requests",
            "git",
        }
        self.assertEqual(self.imports() & forbidden, set())

    def test_no_file_or_process_calls(self):
        banned = {
            "open",
            "system",
            "popen",
            "run",
            "check_call",
            "check_output",
            "exec",
            "eval",
            "write_text",
            "write_bytes",
            "mkdir",
            "unlink",
            "remove",
        }
        called = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
                elif isinstance(func, ast.Attribute):
                    called.add(func.attr)
        self.assertEqual(called & banned, set())

    def test_module_import_creates_no_files(self):
        before = sorted(p.name for p in DELIVERY_DIR.iterdir())
        load_module("watch_delivery_policy_probe", POLICY_PATH)
        after = sorted(p.name for p in DELIVERY_DIR.iterdir())
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
