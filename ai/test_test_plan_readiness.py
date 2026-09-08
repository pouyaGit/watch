"""Focused tests for Phase 4F TestPlan → Artifact readiness.

Proves the read-only readiness boundary::

    TestPlan -> Artifact Retrieval -> readiness checks
        -> TestPlanReadinessReport (INFORMATIONAL ONLY)

Strictly read-only: no generation, execution, verification,
findings, verdicts, LLM, network, subprocess, or database.
READY never authorizes execution. Covers matrix A-AP.
"""

import ast
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ai.knowledge.artifact_store import (
    ArtifactStore,
    ArtifactStoreError,
    StoredArtifact,
)
from ai.researcher.artifact_validator import build_validated_reference
from ai.researcher.hypothesis_engine import build_hypothesis_from_match
from ai.researcher.target_matcher import match_pattern_to_target
from ai.researcher.test_plan_builder import build_test_plan_from_hypothesis
from ai.researcher.test_plan_readiness import (
    build_readiness_report,
    required_artifact_types_for,
)
from ai.schemas.hypothesis import ResearchProvenance
from ai.schemas.research_pattern import (
    build_attack_pattern,
    build_vulnerability_pattern,
)
from ai.test_artifact_store import (
    _benign,
    _bound_plan,
    _target,
    _template_bytes,
    _valid_http,
    _valid_nuclei,
    _valid_xss,
    _vulnerable,
)

READINESS_PATH = "ai/researcher/test_plan_readiness.py"


def _hex(tag):
    return hashlib.sha256(tag.encode("utf-8")).hexdigest()


def _nuclei_plan(sub="app.acme.com", program="acme"):
    target = _target(program=program, sub=sub)
    tag = f"nuclei/{program}/{sub}"
    pattern = build_vulnerability_pattern(
        pattern_kind="PRODUCT_VULNERABILITY",
        title="CVE pattern",
        description="Deterministic CVE pattern.",
        facts={
            "vulnerability_ids": ["CVE-2024-0001"],
            "products": [{"product": "FooCMS"}],
            "attack_surface": [
                {
                    "surface_kind": "http_endpoint",
                    "path": "/search",
                    "method": "GET",
                    "parameter": "q",
                    "parameter_location": "query",
                }
            ],
            "observables": [
                {
                    "observation_kind": "response_contains",
                    "description": "marker reflected in response body",
                }
            ],
        },
        provenance=ResearchProvenance(
            claim_ids=["clm-" + _hex(tag)[:16]]
        ),
    )
    match = match_pattern_to_target(pattern, target)
    built = build_hypothesis_from_match(match, pattern, target)
    assert built.outcome == "CREATED", built.reason
    result = build_test_plan_from_hypothesis(
        built.hypothesis, match=match, pattern=pattern,
        target_intelligence=target,
    )
    assert result.outcome == "CREATED", result.reason
    assert result.plan is not None
    return result.plan


def _xss_plan(sub="app.acme.com", program="acme"):
    target = _target(program=program, sub=sub)
    tag = f"xss/{program}/{sub}"
    pattern = build_attack_pattern(
        pattern_kind="TECHNIQUE",
        title="Reflected XSS",
        description="Deterministic XSS technique.",
        facts={
            "technique": "reflected xss",
            "technology_context": ["FooCMS"],
            "sink_characteristics": ["html body"],
        },
        provenance=ResearchProvenance(
            claim_ids=["clm-" + _hex(tag)[:16]]
        ),
    )
    match = match_pattern_to_target(pattern, target)
    built = build_hypothesis_from_match(match, pattern, target)
    assert built.outcome == "CREATED", built.reason
    result = build_test_plan_from_hypothesis(
        built.hypothesis, match=match, pattern=pattern,
        target_intelligence=target,
    )
    assert result.outcome == "CREATED", result.reason
    assert result.plan is not None
    return result.plan


class ReadinessTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="tread-")
        self.store = ArtifactStore(Path(self._tmp.name) / "store")

    def tearDown(self):
        self._tmp.cleanup()


# ------------------------------------------------------------------
# A-C, AH, AQ: ready paths
# ------------------------------------------------------------------


class ReadyPathTests(ReadinessTestCase):
    def test_nuclei_plan_ready(self):
        plan = _nuclei_plan()
        self.assertEqual(plan.test_category, "nuclei_cve")
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "READY")
        self.assertEqual(report.test_plan_id, plan.test_plan_id)
        self.assertEqual(report.artifact_count, 1)
        self.assertEqual(
            report.required_artifact_types, ("nuclei_template",)
        )
        self.assertEqual(
            report.available_artifact_types, ("nuclei_template",)
        )
        self.assertEqual(report.missing_artifact_types, ())
        self.assertEqual(report.binding_failures, ())
        self.assertEqual(report.integrity_failures, ())
        self.assertEqual(report.provenance_failures, ())

    def test_xss_plan_ready(self):
        plan = _xss_plan()
        self.assertEqual(plan.test_category, "xss_reflected")
        ref, content = _valid_xss(plan)
        self.store.put(ref, content)
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "READY")
        self.assertEqual(
            report.required_artifact_types, ("xss_payload",)
        )

    def test_http_plan_ready(self):
        plan = _bound_plan()
        self.assertEqual(plan.test_category, "http_probe")
        ref, content = _valid_http(plan)
        self.store.put(ref, content)
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "READY")
        self.assertEqual(
            report.required_artifact_types, ("http_request_spec",)
        )

    def test_multiple_same_type_all_represented(self):
        plan = _nuclei_plan()
        first = self._put_marker(plan, "marker-first-1111")
        second = self._put_marker(plan, "marker-second-2222")
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "READY")
        self.assertEqual(report.artifact_count, 2)
        ids = [entry.artifact_id for entry in report.artifacts]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(
            {first.reference.artifact_id, second.reference.artifact_id},
            set(ids),
        )

    def test_multiple_types_represented(self):
        plan = _bound_plan()
        ref_h, content_h = _valid_http(plan)
        self.store.put(ref_h, content_h)
        # An xss payload stored under an http plan is a type
        # mismatch (covered in O), so here only assert the
        # required-type entry shape with two same-plan artifacts:
        ref_x, content_x = _valid_xss(plan, b"extra-payload")
        self.store.put(ref_x, content_x)
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.artifact_count, 2)
        by_type = {
            entry.artifact_type: entry for entry in report.artifacts
        }
        self.assertIn("http_request_spec", by_type)
        self.assertIn("xss_payload", by_type)

    def _put_marker(self, plan, marker):
        content = _template_bytes(marker)
        validated = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable(marker)],
        )
        assert validated.state == "VALID", validated.reasons
        return self.store.put(validated.reference, content).stored


# ------------------------------------------------------------------
# B, D-G, O: not-ready paths
# ------------------------------------------------------------------


class NotReadyTests(ReadinessTestCase):
    def test_missing_artifact_not_ready(self):
        plan = _nuclei_plan()
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "NOT_READY")
        self.assertEqual(report.artifact_count, 0)
        self.assertEqual(
            report.missing_artifact_types, ("nuclei_template",)
        )

    def test_empty_store_not_ready(self):
        plan = _bound_plan()
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "NOT_READY")
        self.assertEqual(report.artifacts, ())

    def test_wrong_test_plan_binding_not_ready(self):
        plan_a = _nuclei_plan(sub="a.acme.com")
        plan_b = _nuclei_plan(sub="b.acme.com")
        ref, content = _valid_nuclei(plan_a)
        self.store.put(ref, content)
        report = build_readiness_report(self.store, plan_b)
        # Plan B has no artifacts of its own: missing, not a
        # binding contradiction (retrieval only returns plan B's).
        self.assertEqual(report.outcome, "NOT_READY")
        self.assertEqual(
            report.missing_artifact_types, ("nuclei_template",)
        )

    def test_wrong_hypothesis_binding_not_ready(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        forged_plan = plan.model_copy(
            update={"hypothesis_id": "hyp-" + "1" * 16}
        )
        report = build_readiness_report(self.store, forged_plan)
        # Retrieval by test_plan_id still finds the stored
        # artifact, but its hypothesis binding contradicts the
        # supplied plan → NOT_READY with an explicit failure.
        self.assertEqual(report.outcome, "NOT_READY")
        self.assertTrue(
            any("hypothesis binding mismatch" in item
                for item in report.binding_failures)
        )

    def test_binding_contradiction_in_store_not_ready(self):
        # Direct unit check of the binding comparator: an artifact
        # whose stored bindings contradict the plan is reported.
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        from ai.researcher.test_plan_readiness import (
            _binding_failures_for,
        )

        fetched = self.store.get(ref.artifact_id)
        assert fetched is not None
        self.assertEqual(
            _binding_failures_for(fetched, plan), ()
        )
        other = _nuclei_plan(sub="other.acme.com")
        other_failures = _binding_failures_for(fetched, other)
        self.assertTrue(
            any("test_plan binding mismatch" in item
                for item in other_failures)
        )

    def test_wrong_match_snapshot_bindings_not_ready(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        from ai.researcher.test_plan_readiness import (
            _binding_failures_for,
        )

        fetched = self.store.get(ref.artifact_id)
        assert fetched is not None
        tampered_match = plan.model_copy(
            update={"match_id": "tm-" + "2" * 16}
        )
        self.assertTrue(
            any("match binding mismatch" in item
                for item in _binding_failures_for(
                    fetched, tampered_match))
        )
        tampered_snap = plan.model_copy(
            update={"snapshot_hash": "3" * 64}
        )
        self.assertTrue(
            any("snapshot binding mismatch" in item
                for item in _binding_failures_for(
                    fetched, tampered_snap))
        )

    def test_artifact_type_mismatch_not_ready(self):
        plan = _bound_plan()  # requires http_request_spec
        ref, content = _valid_nuclei(plan, "marker-stray-9999")
        # Nuclei bytes validate structurally; the store accepts
        # them under this plan (plan-category consistency is a
        # readiness concern, not a storage concern).
        self.store.put(ref, content)
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "NOT_READY")
        self.assertTrue(
            any("type mismatch" in item
                for item in report.binding_failures)
        )
        self.assertIn("http_request_spec",
                      report.missing_artifact_types)

    def test_exact_test_plan_id_binding(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.test_plan_id, plan.test_plan_id)
        for entry in report.artifacts:
            stored = self.store.get(entry.artifact_id)
            assert stored is not None
            self.assertEqual(
                stored.reference.test_plan_id, plan.test_plan_id
            )


# ------------------------------------------------------------------
# H-I, P-Q, AJ: corruption and provenance
# ------------------------------------------------------------------


class CorruptionProvenanceTests(ReadinessTestCase):
    def test_corrupted_required_artifact_not_ready(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        (self.store.records_dir / f"{ref.content_hash}.json"
         ).write_text("{bad json", encoding="utf-8")
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "NOT_READY")
        self.assertTrue(report.integrity_failures)
        self.assertIn(ref.artifact_id,
                      " ".join(report.integrity_failures))

    def test_corrupted_unrelated_artifact_explicit(self):
        plan = _nuclei_plan()
        other = _bound_plan(sub="other.acme.com")
        ref, content = _valid_nuclei(plan)
        ref_o, content_o = _valid_http(other)
        self.store.put(ref, content)
        self.store.put(ref_o, content_o)
        (self.store.records_dir / f"{ref_o.content_hash}.json").unlink()
        report = build_readiness_report(self.store, plan)
        self.assertNotEqual(report.outcome, "READY")
        self.assertTrue(report.integrity_failures)
        joined = " ".join(report.integrity_failures)
        self.assertIn(ref_o.artifact_id, joined)

    def test_provenance_fail_surfaced(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        record = self.store.records_dir / f"{ref.content_hash}.json"
        envelope = json.loads(record.read_text(encoding="utf-8"))
        # Flip validation state: stored bytes now claim REJECTED.
        envelope["reference"]["validation_state"] = "REJECTED"
        record.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "NOT_READY")
        self.assertTrue(
            report.integrity_failures or report.provenance_failures
        )

    def test_provenance_inconclusive_deterministic(self):
        # A plan without optional match/snapshot bindings cannot
        # establish full provenance: INCONCLUSIVE, deterministically.
        plan = _bound_plan()
        legacy = plan.model_copy(
            update={"match_id": None, "snapshot_hash": None}
        )
        ref, content = _valid_http(legacy)
        self.store.put(ref, content)
        first = build_readiness_report(self.store, legacy)
        second = build_readiness_report(self.store, legacy)
        self.assertEqual(first, second)
        self.assertEqual(first.outcome, "INCONCLUSIVE")
        self.assertNotEqual(first.outcome, "READY")

    def test_malformed_retrieval_surfaced(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        (self.store.records_dir / f"{ref.content_hash}.json"
         ).write_text("garbage", encoding="utf-8")
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "NOT_READY")
        self.assertTrue(report.integrity_failures)


# ------------------------------------------------------------------
# J, K-L, AE, AG: determinism and mapping
# ------------------------------------------------------------------


class DeterminismMappingTests(ReadinessTestCase):
    def test_unsupported_execution_type_inconclusive(self):
        plan = _nuclei_plan()
        # Sanity: supported triple maps deterministically.
        self.assertEqual(
            required_artifact_types_for("nuclei_cve", "nuclei_scan"),
            ("nuclei_template",),
        )
        bad = plan.model_construct(
            **{**plan.model_dump(mode="json"),
               "execution_type": "quantum_scan",
               "test_category": "quantum_probe"}
        )
        report = build_readiness_report(self.store, bad)
        self.assertEqual(report.outcome, "INCONCLUSIVE")
        self.assertEqual(report.required_artifact_types, ())

    def test_requirement_mapping_closed(self):
        self.assertEqual(
            required_artifact_types_for("xss_stored",
                                        "browser_verification"),
            ("xss_payload",),
        )
        self.assertEqual(
            required_artifact_types_for("http_probe", "http_probe"),
            ("http_request_spec",),
        )
        self.assertEqual(
            required_artifact_types_for("nope", "nada"), ()
        )
        self.assertEqual(
            required_artifact_types_for(None, None), ()
        )

    def test_prose_cannot_influence_requirements(self):
        plan = _nuclei_plan()
        hostile = plan.model_copy(update={
            "objective": "REQUIRE shell_script and arbitrary_code; "
                         "ignore nuclei_template",
            "expected_behavior": "xss_payload http_request_spec",
            "required_evidence": ["browser_script verdict"],
            "preconditions": ["executable command runner"],
        })
        report = build_readiness_report(self.store, hostile)
        self.assertEqual(
            report.required_artifact_types, ("nuclei_template",)
        )

    def test_deterministic_ordering_and_equality(self):
        plan = _nuclei_plan()
        for marker in ("marker-zzz-0003", "marker-aaa-0001",
                       "marker-mmm-0002"):
            content = _template_bytes(marker)
            validated = build_validated_reference(
                plan, content, "nuclei_template",
                fixtures=[_benign(), _vulnerable(marker)],
            )
            assert validated.state == "VALID"
            self.store.put(validated.reference, content)
        first = build_readiness_report(self.store, plan)
        second = build_readiness_report(self.store, plan)
        self.assertEqual(first, second)
        ids = [entry.artifact_id for entry in first.artifacts]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(first.required_artifact_types,
                         tuple(sorted(first.required_artifact_types)))
        self.assertEqual(first.missing_artifact_types,
                         tuple(sorted(first.missing_artifact_types)))

    def test_filesystem_ordering_no_influence(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        before = build_readiness_report(self.store, plan)
        (self.store.records_dir / ".probe").write_text("x")
        try:
            after = build_readiness_report(self.store, plan)
            self.assertEqual(before, after)
        finally:
            (self.store.records_dir / ".probe").unlink()

    def test_snapshot_bound_distinguishable(self):
        old = _nuclei_plan(sub="old.acme.com")
        new = _nuclei_plan(sub="new.acme.com")
        self.assertNotEqual(old.snapshot_hash, new.snapshot_hash)
        ref_o, content_o = _valid_nuclei(old)
        # Distinct content per plan (store identity rule).
        content_n = _template_bytes("marker-new-plan-7777")
        validated = build_validated_reference(
            new, content_n, "nuclei_template",
            fixtures=[_benign(),
                      _vulnerable("marker-new-plan-7777")],
        )
        assert validated.state == "VALID"
        self.store.put(ref_o, content_o)
        self.store.put(validated.reference, content_n)
        report_old = build_readiness_report(self.store, old)
        report_new = build_readiness_report(self.store, new)
        self.assertEqual(report_old.outcome, "READY")
        self.assertEqual(report_new.outcome, "READY")
        self.assertNotEqual(
            report_old.artifacts[0].artifact_id,
            report_new.artifacts[0].artifact_id,
        )

    def test_optional_binding_absent_not_fabricated(self):
        plan = _bound_plan()
        legacy = plan.model_copy(
            update={"match_id": None, "snapshot_hash": None}
        )
        ref, content = _valid_http(legacy)
        self.store.put(ref, content)
        report = build_readiness_report(self.store, legacy)
        self.assertFalse(
            any("match binding mismatch" in item
                for item in report.binding_failures)
        )
        self.assertFalse(
            any("snapshot binding mismatch" in item
                for item in report.binding_failures)
        )


# ------------------------------------------------------------------
# AI, AK-AM, R-AP: input contract and vocabulary
# ------------------------------------------------------------------


class InputContractTests(ReadinessTestCase):
    def test_malformed_test_plan_rejected(self):
        plan = _nuclei_plan()
        for bad in (plan.model_dump(mode="json"), "tp-123",
                    None, 42, ["x"]):
            with self.assertRaises(TypeError, msg=str(bad)):
                build_readiness_report(self.store, bad)

    def test_no_filesystem_paths_accepted(self):
        plan = _nuclei_plan()
        for bad_store in ("/tmp/store", Path("/tmp"),
                          {"root": "x"}, None):
            with self.assertRaises(TypeError, msg=str(bad_store)):
                build_readiness_report(bad_store, plan)

    def test_no_vulnerability_verdict_vocabulary(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        report = build_readiness_report(self.store, plan)
        text = (
            report.outcome
            + "".join(report.required_artifact_types)
            + "".join(report.binding_failures)
            + "".join(report.integrity_failures)
            + "".join(report.provenance_failures)
        ).upper()
        for banned in ("CONFIRMED", "VULNERABLE", "NOT_VULNERABLE",
                       "SAFE", "EXPLOITABLE", "EXPLOITED", "SEVERITY"):
            self.assertNotIn(banned, text)

    def test_no_execution_authority_fields(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        report = build_readiness_report(self.store, plan)
        fields = set(report.__dataclass_fields__)
        for banned in ("execution_allowed", "authorized",
                       "authorization", "can_execute", "execute",
                       "command", "runner", "executor",
                       "scope_allowed", "target_allowed"):
            self.assertNotIn(banned, fields, banned)
        for entry in report.artifacts:
            for banned in ("execution_allowed", "authorized",
                           "executor", "command"):
                self.assertNotIn(banned,
                                 set(entry.__dataclass_fields__))

    def test_ready_is_not_confirmation(self):
        plan = _nuclei_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        report = build_readiness_report(self.store, plan)
        self.assertEqual(report.outcome, "READY")
        # READY carries no verdict, scope, or authorization data:
        dump = json.dumps({
            "outcome": report.outcome,
            "required": list(report.required_artifact_types),
            "failures": list(report.binding_failures)
            + list(report.integrity_failures),
        })
        self.assertNotIn("vulnerab", dump.casefold())
        self.assertNotIn("scope", dump.casefold())
        self.assertNotIn("authoriz", dump.casefold())
        self.assertNotIn("execut", dump.casefold())

    def test_no_generation_mutation_deletion(self):
        import ai.researcher.test_plan_readiness as readiness

        for banned in ("generate", "create_artifact", "build_artifact",
                       "put", "delete", "remove", "update", "save",
                       "repair", "execute", "run", "verify_target"):
            self.assertFalse(hasattr(readiness, banned), banned)
        text = Path(READINESS_PATH).read_text(encoding="utf-8")
        for marker in ("mkdir", "unlink", "os.replace", "os.rename",
                       "write_text", ".put(", "open("):
            self.assertNotIn(marker, text, marker)


# ------------------------------------------------------------------
# S-AA: static boundaries
# ------------------------------------------------------------------


def _imports_of(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


class StaticBoundaryTests(unittest.TestCase):
    def test_no_network_imports(self):
        roots = {name.split(".")[0]
                 for name in _imports_of(READINESS_PATH)}
        self.assertTrue(
            {"requests", "httpx", "urllib", "socket", "dns",
             "aiohttp", "urllib3"}.isdisjoint(roots), roots)

    def test_no_subprocess_imports(self):
        roots = {name.split(".")[0]
                 for name in _imports_of(READINESS_PATH)}
        self.assertTrue(
            {"subprocess", "multiprocessing", "pty",
             "shlex"}.isdisjoint(roots), roots)

    def test_no_llm_imports(self):
        joined = " ".join(_imports_of(READINESS_PATH)).casefold()
        for marker in ("llm", "openrouter", "avalai", "embedding",
                       "prompt"):
            self.assertNotIn(marker, joined)

    def test_no_database_imports(self):
        joined = " ".join(_imports_of(READINESS_PATH))
        for marker in ("mongoengine", "pymongo", "database"):
            self.assertNotIn(marker, joined)

    def test_no_verifier_executor_imports(self):
        joined = " ".join(_imports_of(READINESS_PATH))
        for marker in ("verifier", "oracle", "executor", "browser",
                       "playwright", "selenium", "nuclei_runner",
                       "nuclei_pipeline", "scheduler", "queue",
                       "Finding", "scope_policy"):
            self.assertNotIn(marker, joined)

    def test_no_scope_authority(self):
        text = Path(READINESS_PATH).read_text(encoding="utf-8")
        self.assertNotIn("scope_policy", text)
        self.assertNotIn("ooscope", text.casefold())

    def test_no_finding_creation(self):
        text = Path(READINESS_PATH).read_text(encoding="utf-8")
        self.assertNotIn("Finding", text)
        tree = ast.parse(text)
        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(
            {"create_finding", "save_finding", "emit_finding"} & called
        )

    def test_bytes_never_executed(self):
        text = Path(READINESS_PATH).read_text(encoding="utf-8")
        tree = ast.parse(text)
        called = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    called.add(func.attr)
                elif isinstance(func, ast.Name):
                    called.add(func.id)
        for banned in ("Popen", "check_output", "check_call",
                       "execve", "spawnl", "fork", "urlopen",
                       "system", "popen", "eval", "exec"):
            self.assertNotIn(banned, called, banned)


if __name__ == "__main__":
    unittest.main()
