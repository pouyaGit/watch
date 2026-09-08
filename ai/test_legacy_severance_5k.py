"""Phase 5K regression tests — legacy severance + finding identity.

Offline / local hardening only. Stdlib ``unittest`` only. No network,
no DNS, no subprocess, no MongoDB, no browser, no JavaScript, no
Nuclei, no LLM, no Git, no live traffic.

Covers the three P0 integration hazards:

- P0-3: exactly one authoritative ``sealed-finding/v1`` (5J); the
  retired 5I seam shape is renamed + re-versioned and cross-validation
  fails loudly in both directions.
- P0-2: the retired 5I ``materialize_finding`` seam is hard-blocked;
  POTENTIAL reaches no finding store; CONFIRMED reaches only 5J.
- P0-1: the legacy World A entrypoint (``watch_xss_verify.main`` /
  ``__main__``) is permanently disabled and cannot execute
  network/browser; no production task points at legacy execution;
  5J imports no legacy finding factories; legacy schemas cannot
  enter 5J; finding identity stays deterministic.
"""

from __future__ import annotations

import ast
import inspect
import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from ai.finding.eligibility import check_eligibility
from ai.finding.legacy_block import source_references_banned
from ai.finding.materializer import (
    FindingInfrastructure,
    materialize,
)
from ai.finding.notify import (
    AlertLedgerMemory,
    RecordingNotificationSink,
)
from ai.finding.sealed import (
    FINDING_SCHEMA_VERSION,
    SealedFinding,
    canonical_finding_bytes,
)
from ai.finding.store_memory import (
    FindingStoreMemory,
    WorkflowStoreMemory,
)
from ai.schemas.finding import NucleiFinding
from ai.schemas.xss_finding import XSSFinding
from ai.test_deterministic_verifier import (
    AUTHZ_ORACLE,
    World,
    build_http_record,
    build_oracle_record,
)
from ai.verification.deterministic import materialize_finding
from ai.verification.deterministic.materialization import (
    MATERIALIZATION_SCHEMA_VERSION,
    DeprecatedSeamFinding,
    MaterializationSeamDisabledError,
)

import watch_xss_verify

REPO_ROOT = Path(__file__).resolve().parent.parent
FINDING_DIR = Path(__file__).parent / "finding"


def make_infra(world: World) -> tuple[FindingInfrastructure, dict]:
    """Fresh trusted 5J infra bundle wired to one evidence world."""
    audit: list = []
    sink = RecordingNotificationSink()
    infra = FindingInfrastructure(
        evidence_reader=world.seam(),
        finding_store=FindingStoreMemory(),
        workflow_store=WorkflowStoreMemory(),
        audit_sink=audit,
        notification_sink=sink,
        alert_ledger=AlertLedgerMemory(),
    )
    return infra, {"audit": audit, "sink": sink}


def confirmed_result(world: World | None = None):
    """Genuine CONFIRMED + eligible 5I result over sealed fixtures."""
    world = world or World()
    record, _ = build_oracle_record(world)
    outcome = world.verify(record, world.authz[AUTHZ_ORACLE])
    assert outcome.accepted and outcome.result is not None
    assert outcome.result.outcome == "CONFIRMED"
    assert outcome.result.finding_eligible
    return world, record, outcome.result


def potential_result(world: World | None = None):
    """Genuine POTENTIAL 5I result over sealed fixtures."""
    world = world or World()
    record, _ = build_http_record(world)
    outcome = world.verify(record, list(world.authz.values())[0])
    assert outcome.accepted and outcome.result is not None
    assert outcome.result.outcome == "POTENTIAL"
    return world, record, outcome.result


def seam_payload(**overrides) -> dict:
    """Minimal valid retired-seam payload (plain strings, no validators)."""
    payload = {
        "finding_schema_version": MATERIALIZATION_SCHEMA_VERSION,
        "finding_id": "xf-" + "ab" * 16,
        "classification_hash": "c" * 64,
        "evidence_id": "ev-" + "a" * 32,
        "execution_id": "ex-" + "b" * 32,
        "authorization_id": "authz-" + "c" * 16,
        "program_name": "acme",
        "target_host": "example.com",
        "target_scheme": "https",
        "target_effective_port": 443,
        "target_path_scope": "/",
        "artifact_id": "art-" + "d" * 16,
        "artifact_content_hash": "d" * 64,
        "test_plan_id": "tp-" + "e" * 16,
        "hypothesis_id": None,
        "match_id": None,
        "evidence_bindings_hash": "e" * 64,
        "evidence_observations_hash": "f" * 64,
        "evidence_content_hash": "0" * 64,
        "verifier_version": "verifier/v1",
        "rule_id": "rule/v1",
        "observation_schema_version": "obs/v1",
        "artifact_schema_version": "art/v1",
        "policy_version": "policy/v1",
        "outcome": "CONFIRMED",
        "confirmation_state": None,
        "oracle_channels": (),
        "severity": "high",
        "reason_code": "TEST",
    }
    payload.update(overrides)
    return payload


# ------------------------------------------------------------------
# P0-3 — exactly one authoritative sealed-finding/v1
# ------------------------------------------------------------------


class SealedFindingIdentityTests(unittest.TestCase):
    def test_5j_owns_sealed_finding_v1(self) -> None:
        self.assertEqual(FINDING_SCHEMA_VERSION, "sealed-finding/v1")
        self.assertEqual(
            SealedFinding.model_fields[
                "finding_schema_version"
            ].default,
            "sealed-finding/v1",
        )

    def test_5i_seam_version_is_distinct(self) -> None:
        self.assertEqual(
            MATERIALIZATION_SCHEMA_VERSION,
            "5i-materialized-finding/v1",
        )
        self.assertNotEqual(
            MATERIALIZATION_SCHEMA_VERSION, FINDING_SCHEMA_VERSION
        )
        self.assertEqual(
            DeprecatedSeamFinding.model_fields[
                "finding_schema_version"
            ].default,
            "5i-materialized-finding/v1",
        )

    def test_old_sealed_finding_name_is_gone(self) -> None:
        import ai.verification.deterministic as det
        import ai.verification.deterministic.materialization as mat

        for module in (det, mat):
            with self.assertRaises(AttributeError):
                getattr(module, "SealedFinding")
        self.assertFalse(hasattr(mat, "SealedFinding"))
        self.assertFalse(hasattr(det, "SealedFinding"))

    def test_no_5i_source_defines_sealed_finding_v1(self) -> None:
        det_dir = (
            Path(__file__).parent / "verification" / "deterministic"
        )
        offenders: list[str] = []
        for path in sorted(det_dir.glob("*.py")):
            tree = ast.parse(
                path.read_text(encoding="utf-8"), filename=path.name
            )
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and node.value == "sealed-finding/v1"
                ):
                    # Docstrings/prose may mention the 5J version;
                    # only code-level constants count.
                    offenders.append(
                        f"{path.name}:{node.lineno}"
                    )
        prose_only = {"materialization.py", "__init__.py"}
        code_offenders = [
            hit
            for hit in offenders
            if hit.split(":")[0] not in prose_only
        ]
        self.assertEqual(code_offenders, [])
        # Even the prose-mentioning modules must not ASSIGN it.
        for name in prose_only:
            path = det_dir / name
            tree = ast.parse(
                path.read_text(encoding="utf-8"), filename=name
            )
            assigned = [
                node.lineno
                for node in ast.walk(tree)
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(t, ast.Constant)
                    and t.value == "sealed-finding/v1"
                    for t in ast.walk(node)
                )
            ]
            self.assertEqual(assigned, [], name)

    def test_5j_finding_cannot_validate_as_old_seam(self) -> None:
        world, _, result = confirmed_result()
        infra, _ = make_infra(world)
        out = materialize(result, infra)
        self.assertTrue(out.accepted)
        assert out.finding is not None
        dumped = out.finding.model_dump(mode="json")
        with self.assertRaises(Exception):
            DeprecatedSeamFinding.model_validate(dumped)

    def test_old_seam_cannot_validate_as_5j_finding(self) -> None:
        seam = DeprecatedSeamFinding(**seam_payload())
        dumped = seam.model_dump(mode="json")
        with self.assertRaises(Exception):
            SealedFinding.model_validate(dumped)

    def test_identity_derivation_remains_deterministic(self) -> None:
        world, _, result = confirmed_result()
        infra, _ = make_infra(world)
        first = materialize(result, infra)
        self.assertTrue(first.accepted)
        assert first.finding is not None
        second = materialize(result, infra)
        self.assertTrue(second.accepted)
        assert second.finding is not None
        self.assertEqual(first.finding_id, second.finding_id)
        self.assertEqual(
            canonical_finding_bytes(first.finding),
            canonical_finding_bytes(second.finding),
        )
        self.assertTrue(second.deduplicated)


# ------------------------------------------------------------------
# P0-2 — no dual finding minting
# ------------------------------------------------------------------


class RetiredSeamBlockedTests(unittest.TestCase):
    def test_confirmed_old_api_raises_no_finding(self) -> None:
        world, _, result = confirmed_result()
        with self.assertRaises(MaterializationSeamDisabledError):
            materialize_finding(result, world.seam())

    def test_potential_old_api_raises_no_finding(self) -> None:
        world, _, result = potential_result()
        with self.assertRaises(MaterializationSeamDisabledError):
            materialize_finding(result, world.seam())

    def test_potential_rejected_by_5j(self) -> None:
        world, _, result = potential_result()
        decision = check_eligibility(result)
        self.assertFalse(decision.eligible)
        infra, _ = make_infra(world)
        out = materialize(result, infra)
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)

    def test_potential_reaches_no_finding_store(self) -> None:
        world, _, result = potential_result()
        infra, _ = make_infra(world)
        out = materialize(result, infra)
        self.assertFalse(out.accepted)
        self.assertEqual(
            infra.finding_store.list_ids(result.program_name), ()
        )

    def test_confirmed_reaches_only_5j(self) -> None:
        world, _, result = confirmed_result()
        with self.assertRaises(MaterializationSeamDisabledError):
            materialize_finding(result, world.seam())
        infra, _ = make_infra(world)
        out = materialize(result, infra)
        self.assertTrue(out.accepted)
        assert out.finding is not None
        self.assertIn(
            out.finding_id,
            infra.finding_store.list_ids(result.program_name),
        )

    def test_no_production_import_of_retired_seam(self) -> None:
        roots = [
            REPO_ROOT / "backend",
            REPO_ROOT / "api.py",
            FINDING_DIR,
        ]
        offenders: list[str] = []
        for root in roots:
            paths = (
                sorted(root.glob("*.py"))
                if root.is_file()
                else sorted(root.rglob("*.py"))
            )
            for path in paths:
                try:
                    source = path.read_text(encoding="utf-8")
                except OSError:
                    continue
                tree = ast.parse(source, filename=path.name)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        module = node.module or ""
                        if module.startswith(
                            "ai.verification.deterministic.materialization"
                        ):
                            offenders.append(str(path))
                            break
                        if module.startswith(
                            "ai.verification.deterministic"
                        ) and any(
                            a.name == "materialize_finding"
                            for a in node.names
                        ):
                            offenders.append(str(path))
                            break
        self.assertEqual(offenders, [])


# ------------------------------------------------------------------
# P0-1 — legacy World A severance
# ------------------------------------------------------------------


class LegacyEntrypointDisabledTests(unittest.TestCase):
    def test_production_entrypoint_fails_closed(self) -> None:
        self.assertTrue(watch_xss_verify.LEGACY_PRODUCTION_DISABLED)
        buf = io.StringIO()
        with redirect_stderr(buf):
            status = watch_xss_verify.main([])
        self.assertEqual(status, 2)
        self.assertIn("disabled", buf.getvalue().lower())
        self.assertIn("5B", buf.getvalue())

    def test_entrypoint_builds_nothing(self) -> None:
        calls: list = []

        def _bomb(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("legacy execution must not start")

        original_pipeline = watch_xss_verify.build_production_pipeline
        original_run_job = watch_xss_verify.run_job
        watch_xss_verify.build_production_pipeline = _bomb  # type: ignore[assignment]
        watch_xss_verify.run_job = _bomb  # type: ignore[assignment]
        try:
            buf = io.StringIO()
            with redirect_stderr(buf):
                status = watch_xss_verify.main(
                    ["--max-cases", "5", "--filter", "example.com"]
                )
            self.assertEqual(status, 2)
            self.assertEqual(calls, [])
        finally:
            watch_xss_verify.build_production_pipeline = original_pipeline
            watch_xss_verify.run_job = original_run_job

    def test_entrypoint_source_has_no_execution(self) -> None:
        source = inspect.getsource(watch_xss_verify.main)
        for token in (
            "build_production_pipeline",
            "run_job",
            "mongo_persist",
            "requests",
            "playwright",
            "HTTPEvidenceExecutor",
            "BrowserEvidenceExecutor",
        ):
            self.assertNotIn(token, source)
        guard_path = REPO_ROOT / "watch_xss_verify.py"
        guard_text = guard_path.read_text(encoding="utf-8")
        tree = ast.parse(guard_text, filename="watch_xss_verify.py")
        guards = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and "__name__" in ast.dump(node.test)
        ]
        self.assertTrue(guards)  # __main__ guard still present
        for guard in guards:
            segment = ast.get_source_segment(guard_text, guard) or ""
            self.assertIn("main(", segment)
            for token in ("run_job", "mongo_persist", "requests"):
                self.assertNotIn(token, segment)
        self.assertNotIn("ALLOW_LEGACY", guard_text)

    def test_no_task_registry_points_at_legacy(self) -> None:
        from backend.tasks_registry import TASKS_REGISTRY

        for task_id, entry in TASKS_REGISTRY.items():
            blob = f"{task_id} {entry.get('name', '')} {entry.get('script', '')}".lower()
            for marker in (
                "watch_xss_verify",
                "verify",
                "nuclei",
                "xss",
                "finding",
            ):
                self.assertNotIn(marker, blob, task_id)

    def test_dashboard_and_api_do_not_reference_legacy_job(self) -> None:
        for root in (REPO_ROOT / "backend", REPO_ROOT / "api.py"):
            paths = (
                [root]
                if root.is_file()
                else sorted(root.rglob("*.py"))
            )
            for path in paths:
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("watch_xss_verify", source, str(path))

    def test_5j_imports_no_legacy_factories(self) -> None:
        for path in sorted(FINDING_DIR.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            self.assertEqual(
                source_references_banned(source), (), path.name
            )
        for path in sorted(FINDING_DIR.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("materialize_finding", source, path.name)
            self.assertNotIn(
                "DeprecatedSeamFinding", source, path.name
            )

    def test_xss_finding_cannot_enter_5j(self) -> None:
        world, _, _ = confirmed_result()
        infra, _ = make_infra(world)
        legacy = XSSFinding(
            finding_id="xf-" + "1" * 32,
            case_id="case-1",
            target="https://example.com/",
            endpoint="https://example.com/?q=1",
            method="GET",
            xss_type="reflected",
            context_type="html_body",
            status="CONFIRMED",
            confidence=0.9,
        )
        out = materialize(legacy, infra)
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)

    def test_nuclei_finding_cannot_enter_5j(self) -> None:
        world, _, _ = confirmed_result()
        infra, _ = make_infra(world)
        legacy = NucleiFinding(
            cve_id="CVE-2026-0001",
            target="https://example.com/",
            program="acme",
            template_id="cve-2026-0001",
            severity="high",
            matched=True,
            scope_status="in_scope",
            presence_status="present",
            version_status="affected",
        )
        out = materialize(legacy, infra)
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)


if __name__ == "__main__":
    unittest.main()
