"""EPIC12 — safety and non-regression guards for the new layer.

These tests assert *properties of the code itself*: no network primitive, no
second taxonomy, no second gate, no mutation of EPIC11, no randomness, and a
fail-closed budget and store.
"""

from __future__ import annotations

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import contracts as ct  # noqa: E402
from backend.research_agents.finding.integrity import gate as ig  # noqa: E402
from backend.research_agents.finding.integrity import taxonomy as tx  # noqa: E402
from backend.research_agents.verification import budget as vb  # noqa: E402
from backend.research_agents.verification import store as vs  # noqa: E402

PKG = Path(__file__).resolve().parents[1] / "backend" / "research_agents" / "verification"
MODULES = sorted(PKG.glob("*.py"))
SOURCE = {p.name: p.read_text() for p in MODULES}


class TestNoForbiddenPrimitives(unittest.TestCase):
    #: Network / process primitives.  ``urllib.parse`` is allowed: it is pure
    #: string parsing used for the scope check, it opens nothing.
    FORBIDDEN_IMPORTS = {"socket", "subprocess", "urllib.request",
                         "urllib.error", "urllib2", "http.client", "requests",
                         "httpx", "ftplib", "smtplib", "telnetlib",
                         "asyncio.subprocess", "shutil", "random", "uuid",
                         "pickle", "ctypes", "multiprocessing", "pty"}

    def _imports(self, source: str) -> set[str]:
        tree = ast.parse(source)
        found: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    found.add(node.module)
        return found

    def test_no_network_or_process_imports(self):
        for name, source in SOURCE.items():
            for imported in self._imports(source):
                root = imported.split(".")[0]
                self.assertNotIn(imported, self.FORBIDDEN_IMPORTS,
                                 f"{name}: {imported}")
                self.assertNotIn(root, self.FORBIDDEN_IMPORTS,
                                 f"{name}: {imported}")

    def test_no_dynamic_execution(self):
        for name, source in SOURCE.items():
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func,
                                                              ast.Name):
                    self.assertNotIn(node.func.id,
                                     {"eval", "exec", "compile", "__import__",
                                      "globals", "locals", "input"},
                                     f"{name}: {node.func.id}")

    def test_no_shell_or_system_calls(self):
        for name, source in SOURCE.items():
            for needle in ("os.system", "os.popen", "os.exec", "os.fork",
                           "subprocess", "shell=True", "Popen"):
                self.assertNotIn(needle, source, f"{name}: {needle}")

    def test_no_payload_literals(self):
        # the classifier legitimately contains the DETECTOR substrings
        # (``<script``, ``onerror``); no module may carry a real payload
        for name, source in SOURCE.items():
            for needle in ("alert(1)", "onerror=", "javascript:",
                           "UNION SELECT", "../../../", "<?php"):
                self.assertNotIn(needle, source, f"{name}: {needle}")

    def test_no_action_declares_payload_content(self):
        from backend.research_agents.verification import actions as ac
        for action_type, spec in ac.ACTION_SPECS.items():
            blob = " ".join((spec.label, spec.limitation)).lower()
            for needle in ("<script", "alert(", "onerror", "payload:"):
                self.assertNotIn(needle, blob, f"{action_type}: {needle}")


class TestNoSecondTaxonomyOrGate(unittest.TestCase):
    def test_epic11_evidence_vocabulary_is_unchanged(self):
        self.assertEqual(len(tx.EVIDENCE_TYPES), 15)
        self.assertEqual(tx.CONFIRMATION_EVIDENCE,
                         frozenset({tx.PAYLOAD_EXECUTION,
                                    tx.EXPLOITABILITY_ESTABLISHED}))

    def test_epic11_gate_states_are_unchanged(self):
        self.assertEqual(ig.INTEGRITY_STATES,
                         ("VERIFIED", "VERIFICATION_PENDING", "BLOCKED",
                          "REJECTED"))

    def test_xss_contract_is_unchanged(self):
        self.assertEqual(ct.XSS.contract_id,
                         ct.contract_for("XSS").contract_id)
        self.assertEqual(
            tuple(ct.XSS.confirmation_claim.required_groups),
            ((tx.REFLECTION_OBSERVED, tx.OUTPUT_CONTEXT_IDENTIFIED,
              tx.DOM_SINK_IDENTIFIED),
             (tx.PAYLOAD_EXECUTION, tx.EXPLOITABILITY_ESTABLISHED)))
        self.assertEqual(ct.XSS.confirmation_claim.min_unique_observations, 2)

    def test_the_layer_declares_no_second_evidence_vocabulary(self):
        for name, source in SOURCE.items():
            self.assertNotIn("EVIDENCE_TYPES =", source, name)
            self.assertNotIn("SIGNAL_TO_TYPE =", source, name)
            self.assertNotIn("EVIDENCE_STAGE =", source, name)

    def test_the_layer_declares_no_second_gate(self):
        for name, source in SOURCE.items():
            self.assertNotIn("def decide(", source, name)
            self.assertNotIn("def evaluate_integrity(", source, name)

    def test_the_engine_delegates_the_verdict_to_epic11(self):
        source = SOURCE["engine.py"]
        self.assertIn("ig.decide(", source)
        self.assertIn("cl.evaluate_rows(", source)

    def test_the_layer_never_assigns_into_epic11_modules(self):
        for name, source in SOURCE.items():
            for needle in ("tx.EVIDENCE_TYPES =", "tx.SIGNAL_TO_TYPE =",
                           "ig.INTEGRITY_STATES =", "ct.CONTRACTS[",
                           "tx.NEGATIVE_SIGNALS =", "tx.NOT_TESTED_SIGNALS ="):
                self.assertNotIn(needle, source, f"{name}: {needle}")

    def test_the_layer_never_writes_to_a_pinned_ai_module(self):
        for name, source in SOURCE.items():
            for needle in ("ai.execution", "ai.authorizer", "ai.evidence",
                           "ai.verification"):
                self.assertNotIn(f"from {needle}", source, f"{name}: {needle}")

    def test_rule_versions_are_declared(self):
        for name, source in SOURCE.items():
            if name in ("__init__.py",):
                continue
            self.assertIn("epic12-", source, name)


class TestFailClosedBudget(unittest.TestCase):
    def setUp(self):
        self.store = vs.VerificationActionStore(
            tempfile.mkdtemp(prefix="epic12-safety-"))

    def test_unknown_resource_is_refused(self):
        b = vb.VerificationBudget(self.store, dict(vb.DEFAULT_VERIFICATION_LIMITS))
        with self.assertRaises(vb.VerificationBudgetExhausted):
            b.ensure("max_unicorns", 1)

    def test_over_limit_is_refused(self):
        b = vb.VerificationBudget(self.store, {"max_actions": 1})
        b.ensure("max_actions", 1)
        with self.assertRaises(vb.VerificationBudgetExhausted):
            b.ensure("max_actions", 1)

    def test_allow_is_non_raising_and_false_when_unknown(self):
        b = vb.VerificationBudget(self.store, {"max_actions": 1})
        self.assertFalse(b.allow("max_unicorns", 1))

    def test_zero_limits_refuse_everything(self):
        b = vb.VerificationBudget(self.store, dict(vb.DEFAULT_VERIFICATION_LIMITS))
        self.assertEqual(b.limits["max_payload_attempts"], 0)
        self.assertFalse(b.allow("max_payload_attempts", 1))

    def test_refusals_are_recorded_in_the_ledger(self):
        b = vb.VerificationBudget(self.store, {"max_actions": 0})
        with self.assertRaises(vb.VerificationBudgetExhausted):
            b.ensure("max_actions", 1, reason="test")
        rows = self.store.budget_ledger()
        self.assertTrue(rows)
        self.assertTrue(any("over_limit" in str(r.get("reason"))
                            for r in rows))

    def test_report_is_json_safe(self):
        b = vb.VerificationBudget(self.store, dict(vb.DEFAULT_VERIFICATION_LIMITS))
        b.ensure("max_actions", 1)
        json.dumps(b.report(), sort_keys=True)


class TestStoreSafety(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="epic12-store-safety-")
        self.store = vs.VerificationActionStore(self.base)

    def test_files_are_inside_the_base_dir(self):
        for name in (vs.ACTIONS_FILE, vs.OBSERVATIONS_FILE, vs.LOOPS_FILE,
                     vs.BUDGET_FILE):
            path = self.store._path(name)
            self.assertTrue(str(path).startswith(str(Path(self.base))), name)

    def test_corrupt_tail_is_tolerated(self):
        path = self.store._path(vs.OBSERVATIONS_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"observation_id": "x"\n')
        self.assertEqual(self.store.list_observations(candidate_id="c"), [])

    def test_rows_are_sorted_json(self):
        self.store.record_loop({"candidate_id": "c", "termination": "BLOCKED",
                                "objective_id": "v1"})
        raw = self.store._path(vs.LOOPS_FILE).read_text().strip()
        self.assertEqual(json.loads(raw)["termination"], "BLOCKED")

    def test_reading_a_missing_store_is_empty_not_an_error(self):
        other = vs.VerificationActionStore(self.base + "-missing")
        self.assertEqual(other.list_observations(candidate_id="c"), [])
        self.assertIsNone(other.latest_loop("c"))

    def test_no_secret_shaped_content_in_the_module_sources(self):
        for name, source in SOURCE.items():
            for needle in ("BEGIN PRIVATE KEY", "api_key=", "password=",
                           "secret=", "token="):
                self.assertNotIn(needle.lower(), source.lower(), name)


class TestDeterminism(unittest.TestCase):
    def test_no_randomness_sources(self):
        for name, source in SOURCE.items():
            for needle in ("import random", "from random", "uuid4",
                           "os.urandom", "time.time()"):
                self.assertNotIn(needle, source, f"{name}: {needle}")

    def test_no_wall_clock_in_evidence_paths(self):
        # evidence and markers must be reproducible from the inputs alone
        for name in ("executors.py", "observations.py", "planner.py",
                     "engine.py", "chains.py"):
            self.assertNotIn("datetime.now", SOURCE[name], name)


if __name__ == "__main__":
    unittest.main()
