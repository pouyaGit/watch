"""Phase 5J Finding Pipeline tests (offline, deterministic).

Stdlib ``unittest`` only. No network, no DNS, no subprocess, no
MongoDB, no browser, no JavaScript, no Nuclei, no LLM, no Git.
Genuine 5I ``ClassificationResult`` objects come from the REAL frozen
5I pipeline (``verify_handoff``) over sealed fixtures imported from
the 5I suite — never hand-built for happy paths. Fakes: evidence
store/index, finding store, workflow store, audit sink, notification
sink, alert ledger.
"""

from __future__ import annotations

import ast
import threading
import unittest
from pathlib import Path

from ai.evidence import builder as seal
from ai.evidence.store import RetentionPolicy
from ai.schemas import evidence as ev
from ai.schemas.finding import NucleiFinding
from ai.schemas.xss_finding import XSSFinding
from ai.test_deterministic_verifier import (
    AUTHZ_ORACLE,
    OTHER_HOST,
    World,
    build_http_record,
    build_nuclei_record,
    build_oracle_record,
    build_stored_round,
)
from ai.verification.deterministic.models import (
    ARTIFACT_SCHEMA_VERSION,
    OBSERVATION_SCHEMA_VERSION,
    POLICY_VERSION,
    VERIFIER_VERSION,
)
from ai.verification.deterministic.result import (
    ClassificationResult,
    compute_result_hash,
)

from ai.finding.audit import FindingAuditEvent
from ai.finding.authority import (
    verify_authority_binding,
    verify_authority_structure,
)
from ai.finding.eligibility import (
    ELIGIBILITY_POLICY_VERSION,
    check_eligibility,
)
from ai.finding.legacy_block import (
    BANNED_IMPORTS,
    BANNED_TOKENS,
    HARD_BLOCKED_PATHS,
    source_references_banned,
)
from ai.finding.materializer import (
    FindingInfrastructure,
    finding_availability,
    materialize,
)
from ai.finding.notify import (
    ALERT_POLICY_VERSION,
    AlertLedgerMemory,
    RecordingNotificationSink,
    alert_id_for,
)
from ai.finding.sealed import (
    FINDING_SCHEMA_VERSION,
    SealedFinding,
    canonical_finding_bytes,
    finding_id_for,
)
from ai.finding.store_memory import (
    B2_BLOCKED,
    CORRUPT_COLLISION,
    DEDUPLICATED,
    PERSISTED,
    FindingStoreMemory,
    MongoFindingStoreAdapter,
    WorkflowStoreMemory,
    WorkflowVersionConflict,
)

FINDING_DIR = Path(__file__).parent / "finding"


def make_infra(world: World) -> tuple[FindingInfrastructure, dict]:
    """Fresh trusted infra bundle wired to one evidence world."""
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


def confirmed_oracle(world: World | None = None):
    """Genuine CONFIRMED + eligible 5I result (reflected oracle)."""
    world = world or World()
    record, _ = build_oracle_record(world)
    outcome = world.verify(record, world.authz[AUTHZ_ORACLE])
    assert outcome.accepted and outcome.result is not None
    assert outcome.result.outcome == "CONFIRMED"
    assert outcome.result.finding_eligible
    return world, record, outcome.result


def event_names(audit: list) -> list[str]:
    return [e.event for e in audit if isinstance(e, FindingAuditEvent)]


# ------------------------------------------------------------------
# ELIGIBILITY
# ------------------------------------------------------------------


class EligibilityTests(unittest.TestCase):
    def test_confirmed_eligible(self) -> None:
        _, _, result = confirmed_oracle()
        decision = check_eligibility(result)
        self.assertTrue(decision.eligible)
        self.assertEqual(decision.reason, "ELIGIBLE")

    def test_confirmed_flag_false_ineligible(self) -> None:
        _, _, result = confirmed_oracle()
        downgraded = result.model_copy(
            update={"finding_eligible": False}
        )
        decision = check_eligibility(downgraded)
        self.assertFalse(decision.eligible)
        self.assertEqual(
            decision.reason, "FINDING_ELIGIBLE_FLAG_FALSE"
        )

    def test_potential_rejected(self) -> None:
        world = World()
        record, _ = build_http_record(world)
        outcome = world.verify(record, list(world.authz.values())[0])
        self.assertEqual(outcome.result.outcome, "POTENTIAL")
        decision = check_eligibility(outcome.result)
        self.assertFalse(decision.eligible)
        self.assertEqual(
            decision.reason, "OUTCOME_NOT_FINDING_ELIGIBLE"
        )

    def test_unknown_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        unknown = result.model_copy(update={"outcome": "UNKNOWN"})
        decision = check_eligibility(unknown)
        self.assertFalse(decision.eligible)
        self.assertEqual(
            decision.reason, "OUTCOME_NOT_FINDING_ELIGIBLE"
        )

    def test_inconclusive_rejected(self) -> None:
        # pydantic v2 model_copy skips validation, so an INCONCLUSIVE
        # outcome literal CAN be smuggled into a copied instance —
        # and every 5J gate must still refuse it (fail closed).
        world = World()
        _, _, result = confirmed_oracle()
        forged = result.model_copy(update={"outcome": "INCONCLUSIVE"})
        self.assertFalse(
            verify_authority_structure(forged).authorized
        )
        self.assertFalse(check_eligibility(forged).eligible)
        infra, _ = make_infra(world)
        out = materialize(forged, infra)
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)

    def test_not_vulnerable_invariant(self) -> None:
        _, _, result = confirmed_oracle()
        negative = result.model_copy(
            update={"outcome": "NOT_VULNERABLE"}
        )
        decision = check_eligibility(negative)
        self.assertFalse(decision.eligible)
        self.assertEqual(
            decision.reason, "ELIGIBILITY_INVARIANT_VIOLATION"
        )

    def test_non_result_rejected_loudly(self) -> None:
        with self.assertRaises(TypeError):
            check_eligibility({"outcome": "CONFIRMED"})  # type: ignore[arg-type]

    def test_no_promotion_switch_exists(self) -> None:
        import ai.finding.eligibility as module

        source = Path(module.__file__).read_text(encoding="utf-8")
        for token in ("allow_potential", "PROMOTE", "enable_eligible"):
            self.assertNotIn(token, source)


# ------------------------------------------------------------------
# 5I AUTHORITY / PROVENANCE GATE
# ------------------------------------------------------------------


class AuthorityStructureTests(unittest.TestCase):
    def test_genuine_result_authorized(self) -> None:
        _, _, result = confirmed_oracle()
        decision = verify_authority_structure(result)
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.reason, "AUTHORITY_OK")

    def test_dict_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        decision = verify_authority_structure(result.model_dump())
        self.assertFalse(decision.authorized)
        self.assertEqual(
            decision.reason, "AUTHORITY_NOT_CLASSIFICATION_RESULT"
        )

    def test_legacy_findings_rejected(self) -> None:
        legacy_xss = XSSFinding(
            finding_id="xf-" + "0" * 32,
            case_id="case-1",
            target="https://example.com",
            endpoint="https://example.com/app",
            method="GET",
            xss_type="reflected",
            context_type="html_body",
            status="CONFIRMED",
            confidence=0.95,
        )
        legacy_nuclei = NucleiFinding(
            cve_id="CVE-2026-1557",
            target="https://example.com",
            program="acme",
            template_id="tpl-1",
            severity="high",
            matched=True,
            scope_status="READY",
            presence_status="LIVE",
            version_status="UNKNOWN",
        )
        for legacy in (legacy_xss, legacy_nuclei):
            decision = verify_authority_structure(legacy)
            self.assertFalse(decision.authorized)
            self.assertEqual(
                decision.reason, "AUTHORITY_NOT_CLASSIFICATION_RESULT"
            )

    def test_unknown_rule_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        forged = result.model_copy(
            update={"rule_id": "xss-imaginary/v1"}
        )
        decision = verify_authority_structure(forged)
        self.assertFalse(decision.authorized)
        self.assertEqual(decision.reason, "AUTHORITY_RULE_UNKNOWN")

    def test_rule_downgrade_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        forged = result.model_copy(
            update={"rule_id": "xss-reflected-oracle/v9"}
        )
        decision = verify_authority_structure(forged)
        self.assertFalse(decision.authorized)
        self.assertEqual(decision.reason, "AUTHORITY_RULE_UNKNOWN")

    def test_version_skew_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        for field, value in (
            ("verifier_version", "deterministic-verifier/5I-v9"),
            ("policy_version", "5i-severity-policy/v9"),
            (
                "observation_schema_version",
                "evidence/v9",
            ),
            ("artifact_schema_version", "artifact/v9"),
        ):
            with self.subTest(field=field):
                forged = result.model_copy(update={field: value})
                decision = verify_authority_structure(forged)
                self.assertFalse(decision.authorized)
                self.assertEqual(
                    decision.reason, "AUTHORITY_VERSION_PIN_MISMATCH"
                )

    def test_malformed_rule_display_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        forged = result.model_copy(update={"rule_id": "not-a-rule"})
        decision = verify_authority_structure(forged)
        self.assertFalse(decision.authorized)
        self.assertEqual(decision.reason, "AUTHORITY_RULE_UNKNOWN")

    def test_empty_reason_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        forged = result.model_copy(update={"reason_code": ""})
        decision = verify_authority_structure(forged)
        self.assertFalse(decision.authorized)
        self.assertEqual(
            decision.reason, "AUTHORITY_STRUCTURE_INVALID"
        )


class AuthorityBindingTests(unittest.TestCase):
    def test_genuine_binding_authorized(self) -> None:
        world, record, result = confirmed_oracle()
        decision = verify_authority_binding(result, record)
        self.assertTrue(decision.authorized)

    def test_severity_injection_rejected(self) -> None:
        world, record, result = confirmed_oracle()
        for severity in ("critical", "low", "info", "UNSET"):
            with self.subTest(severity=severity):
                forged = result.model_copy(
                    update={
                        "severity": severity,
                        "severity_unset_reason": "attacker",
                    }
                )
                decision = verify_authority_binding(forged, record)
                self.assertFalse(decision.authorized)
                self.assertEqual(
                    decision.reason, "AUTHORITY_SEVERITY_MISMATCH"
                )

    def test_unset_reason_tamper_rejected(self) -> None:
        world, record, result = confirmed_oracle()
        forged = result.model_copy(
            update={"severity_unset_reason": "attacker reason"}
        )
        decision = verify_authority_binding(forged, record)
        self.assertFalse(decision.authorized)
        self.assertEqual(
            decision.reason, "AUTHORITY_SEVERITY_MISMATCH"
        )

    def test_wrong_rule_for_class_rejected(self) -> None:
        world, record, result = confirmed_oracle()
        forged = result.model_copy(
            update={"rule_id": "http-meaningful-reflection/v1"}
        )
        self.assertTrue(
            verify_authority_structure(forged).authorized
        )
        decision = verify_authority_binding(forged, record)
        self.assertFalse(decision.authorized)
        self.assertEqual(decision.reason, "AUTHORITY_RULE_UNKNOWN")

    def test_binding_axes_rejected(self) -> None:
        world, record, result = confirmed_oracle()
        mutations = {
            "program_name": "evil",
            "target_host": OTHER_HOST,
            "target_scheme": "http",
            "target_effective_port": 8080,
            "target_path_scope": "/evil",
            "artifact_id": "art-" + "9" * 16,
            "artifact_content_hash": "9" * 64,
            "test_plan_id": "tp-" + "9" * 16,
            "evidence_bindings_hash": "8" * 64,
            "evidence_observations_hash": "8" * 64,
            "evidence_content_hash": "8" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                forged = result.model_copy(update={field: value})
                decision = verify_authority_binding(forged, record)
                self.assertFalse(decision.authorized)
                self.assertEqual(
                    decision.reason, "AUTHORITY_BINDING_MISMATCH"
                )

    def test_tampered_record_rejected(self) -> None:
        world, record, result = confirmed_oracle()
        tampered = record.model_copy(
            update={"program_name": "evil"}
        )
        decision = verify_authority_binding(result, tampered)
        self.assertFalse(decision.authorized)
        self.assertIn(
            decision.reason,
            (
                "AUTHORITY_EVIDENCE_UNVERIFIABLE",
                "AUTHORITY_BINDING_MISMATCH",
            ),
        )

    def test_non_record_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        decision = verify_authority_binding(
            result, {"evidence_id": "ev-" + "0" * 32}
        )
        self.assertFalse(decision.authorized)
        self.assertEqual(
            decision.reason, "AUTHORITY_EVIDENCE_INVALID"
        )


# ------------------------------------------------------------------
# MATERIALIZATION: HAPPY PATH + CONTRACT
# ------------------------------------------------------------------


class MaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def _materialize_confirmed(self):
        record, _ = build_oracle_record(self.world)
        outcome = self.world.verify(
            record, list(self.world.authz.values())[0]
        )
        infra, ctx = make_infra(self.world)
        out = materialize(outcome.result, infra)
        return out, infra, ctx, outcome.result

    def test_confirmed_materializes(self) -> None:
        out, infra, ctx, result = self._materialize_confirmed()
        self.assertTrue(out.accepted)
        self.assertEqual(out.reason, "PERSISTED")
        self.assertIsNotNone(out.finding)
        self.assertTrue(out.notified)
        self.assertIsNotNone(out.alert_id)
        finding = out.finding
        assert finding is not None
        self.assertEqual(
            finding.finding_schema_version, FINDING_SCHEMA_VERSION
        )
        self.assertEqual(finding.classification, "CONFIRMED")
        self.assertEqual(finding.severity, result.severity)
        self.assertEqual(
            finding.severity_unset_reason,
            result.severity_unset_reason,
        )
        self.assertEqual(
            finding.severity_policy_version, result.policy_version
        )
        self.assertEqual(
            finding.eligibility_policy_version,
            ELIGIBILITY_POLICY_VERSION,
        )
        self.assertEqual(
            finding.classification_result_hash,
            compute_result_hash(result),
        )
        self.assertEqual(
            finding.oracle_channels, tuple(result.oracle_channels)
        )
        self.assertEqual(
            finding.confirmation_state, result.confirmation_state
        )
        self.assertEqual(finding.reason_code, result.reason_code)
        self.assertEqual(finding.verifier_version, VERIFIER_VERSION)
        self.assertEqual(finding.policy_version, POLICY_VERSION)
        self.assertEqual(
            finding.observation_schema_version,
            OBSERVATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            finding.artifact_schema_version, ARTIFACT_SCHEMA_VERSION
        )
        self.assertIsNone(finding.round_id)
        self.assertIsNone(finding.submit_evidence_ref)
        self.assertIsNone(finding.submit_content_hash)
        names = event_names(ctx["audit"])
        for expected in (
            "FINDING_ELIGIBILITY_ACCEPTED",
            "FINDING_MATERIALIZED",
            "FINDING_PERSISTED",
        ):
            self.assertIn(expected, names)

    def test_stored_round_linkage_preserved(self) -> None:
        read_record, _ = build_stored_round(self.world)
        outcome = self.world.verify(
            read_record, list(self.world.authz.values())[-1]
        )
        self.assertTrue(outcome.accepted)
        self.assertEqual(outcome.result.outcome, "CONFIRMED")
        infra, _ = make_infra(self.world)
        out = materialize(outcome.result, infra)
        self.assertTrue(out.accepted, out.reason)
        assert out.finding is not None
        self.assertIsNotNone(out.finding.round_id)
        self.assertIsNotNone(out.finding.submit_evidence_ref)
        self.assertIsNotNone(out.finding.submit_content_hash)
        self.assertEqual(
            out.finding.submit_evidence_ref,
            read_record.browser.submit_evidence_ref,
        )

    def test_missing_submit_leg_no_finding(self) -> None:
        read_record, _ = build_stored_round(self.world)
        outcome = self.world.verify(
            read_record, list(self.world.authz.values())[-1]
        )
        self.assertEqual(outcome.result.outcome, "CONFIRMED")
        # Destroy the SUBMIT blob: linkage unresolvable, no rebinding.
        self.world.blobs._objects.clear()
        # Re-persist only the READ leg so the fresh read still works.
        self.world.store.persist_sealed(read_record)
        infra, _ = make_infra(self.world)
        out = materialize(outcome.result, infra)
        self.assertFalse(out.accepted)
        self.assertEqual(out.reason, "ROUND_SUBMIT_UNRESOLVED")
        self.assertIsNone(out.finding)

    def test_potential_no_finding(self) -> None:
        record, _ = build_http_record(self.world)
        outcome = self.world.verify(
            record, list(self.world.authz.values())[0]
        )
        self.assertEqual(outcome.result.outcome, "POTENTIAL")
        infra, ctx = make_infra(self.world)
        out = materialize(outcome.result, infra)
        self.assertFalse(out.accepted)
        self.assertEqual(out.reason, "OUTCOME_NOT_FINDING_ELIGIBLE")
        self.assertIsNone(out.finding)
        self.assertFalse(out.notified)
        self.assertIn(
            "FINDING_ELIGIBILITY_REJECTED", event_names(ctx["audit"])
        )
        self.assertEqual(len(ctx["sink"].published), 0)

    def test_nuclei_no_finding(self) -> None:
        record, _ = build_nuclei_record(
            self.world,
            obs_kwargs={"finding_like": True, "stdout_sample": "matched"},
        )
        outcome = self.world.verify(
            record, list(self.world.authz.values())[0]
        )
        self.assertNotEqual(outcome.result.outcome, "CONFIRMED")
        infra, _ = make_infra(self.world)
        out = materialize(outcome.result, infra)
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)
        self.assertFalse(out.notified)

    def test_confirmed_flag_false_no_finding(self) -> None:
        record, _ = build_oracle_record(self.world)
        outcome = self.world.verify(
            record, list(self.world.authz.values())[0]
        )
        downgraded = outcome.result.model_copy(
            update={"finding_eligible": False}
        )
        infra, _ = make_infra(self.world)
        out = materialize(downgraded, infra)
        self.assertFalse(out.accepted)
        self.assertEqual(out.reason, "FINDING_ELIGIBLE_FLAG_FALSE")

    def test_forged_classification_no_finding(self) -> None:
        # Self-consistent hand-built result (valid hash) with NO sealed
        # evidence behind it: the fresh read fails, no finding.
        record, _ = build_oracle_record(self.world)
        outcome = self.world.verify(
            record, list(self.world.authz.values())[0]
        )
        forged = outcome.result.model_copy(
            update={"evidence_id": "ev-" + "9" * 32}
        )
        empty = World()
        infra, _ = make_infra(empty)
        out = materialize(forged, infra)
        self.assertFalse(out.accepted)
        self.assertEqual(out.reason, "FRESH_READ_UNAVAILABLE")

    def test_non_result_input_rejected(self) -> None:
        infra, _ = make_infra(self.world)
        for bogus in (
            {"outcome": "CONFIRMED"},
            ["CONFIRMED"],
            "CONFIRMED",
            None,
        ):
            out = materialize(bogus, infra)
            self.assertFalse(out.accepted)
            self.assertEqual(
                out.reason, "AUTHORITY_NOT_CLASSIFICATION_RESULT"
            )

    def test_malicious_seam_cannot_mint(self) -> None:
        # A lying reader serving a DIFFERENT genuine record fails
        # binding; a reader serving garbage fails structurally.
        record, _ = build_oracle_record(self.world)
        outcome = self.world.verify(
            record, list(self.world.authz.values())[0]
        )
        other = World()
        other_record, _ = build_oracle_record(other)
        other.verify(other_record, list(other.authz.values())[0])

        class LyingReader:
            def read_verified(self, evidence_id: str):
                return other.seam().read_verified(
                    other_record.evidence_id
                )

            def read_by_content_hash(self, content_hash: str):
                return ()

        infra, _ = make_infra(self.world)
        lying = FindingInfrastructure(
            evidence_reader=LyingReader(),
            finding_store=infra.finding_store,
            workflow_store=infra.workflow_store,
            audit_sink=infra.audit_sink,
            notification_sink=infra.notification_sink,
            alert_ledger=infra.alert_ledger,
        )
        out = materialize(outcome.result, lying)
        self.assertFalse(out.accepted)
        self.assertIn(
            out.reason,
            ("AUTHORITY_BINDING_MISMATCH", "FRESH_INDEX_MISMATCH"),
        )

        class GarbageReader:
            def read_verified(self, evidence_id: str):
                return {"record": "garbage"}

            def read_by_content_hash(self, content_hash: str):
                return ()

        garbage = FindingInfrastructure(
            evidence_reader=GarbageReader(),
            finding_store=infra.finding_store,
            workflow_store=infra.workflow_store,
            audit_sink=infra.audit_sink,
            notification_sink=infra.notification_sink,
            alert_ledger=infra.alert_ledger,
        )
        out = materialize(outcome.result, garbage)
        self.assertFalse(out.accepted)
        self.assertEqual(out.reason, "FRESH_READ_MALFORMED")

    def test_wrong_typed_infra_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        infra, _ = make_infra(self.world)
        bad = FindingInfrastructure(
            evidence_reader=infra.evidence_reader,
            finding_store={"not": "a store"},  # type: ignore[arg-type]
            workflow_store=infra.workflow_store,
            audit_sink=infra.audit_sink,
            notification_sink=infra.notification_sink,
            alert_ledger=infra.alert_ledger,
        )
        with self.assertRaises(TypeError):
            materialize(result, bad)

    def test_store_round_trip(self) -> None:
        out, infra, _, _ = self._materialize_confirmed()
        assert out.finding is not None
        entry = infra.finding_store.get_entry(
            out.finding.program_name, out.finding.finding_id
        )
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(
            entry.payload, canonical_finding_bytes(out.finding)
        )
        reparsed = SealedFinding.model_validate_json(
            entry.payload.decode("utf-8")
        )
        self.assertEqual(reparsed, out.finding)


# ------------------------------------------------------------------
# FRESH EVIDENCE AXES (record-side tampering + liveness)
# ------------------------------------------------------------------


class FreshEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()
        self.record, _ = build_oracle_record(self.world)
        self.outcome = self.world.verify(
            self.record, list(self.world.authz.values())[0]
        )
        self.result = self.outcome.result

    def _materialize(self):
        infra, ctx = make_infra(self.world)
        return materialize(self.result, infra), infra, ctx

    def test_quarantined_no_finding(self) -> None:
        self.world.store.quarantine_evidence(
            self.record.evidence_id, reason="test-quarantine"
        )
        out, _, _ = self._materialize()
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)
        self.assertFalse(out.notified)

    def test_tombstoned_no_finding(self) -> None:
        self.world.store.tombstone_evidence(
            self.record.evidence_id,
            policy=RetentionPolicy(
                policy_id="ret-1", allow_blob_deletion=False
            ),
        )
        out, _, _ = self._materialize()
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)

    def test_corrupted_blob_no_finding(self) -> None:
        self.world.blobs.corrupt(self.record.content_hash)
        out, _, _ = self._materialize()
        self.assertFalse(out.accepted)
        self.assertIsNone(out.finding)

    def test_missing_evidence_no_finding(self) -> None:
        empty = World()
        infra, _ = make_infra(empty)
        out = materialize(self.result, infra)
        self.assertFalse(out.accepted)
        self.assertEqual(out.reason, "FRESH_READ_UNAVAILABLE")

    def test_index_claim_mismatch_no_finding(self) -> None:
        # Honest record, but the index claims a DIFFERENT triple (or a
        # dead lifecycle): fail closed, no finding.
        from ai.verification.deterministic.verified_read import (
            IndexClaims,
            VerifiedEvidence,
        )

        base = IndexClaims(
            evidence_id=self.record.evidence_id,
            execution_id=self.record.execution_id,
            authorization_id=self.record.authorization_id,
            content_hash=self.record.content_hash or "",
            bindings_hash=self.record.bindings_hash or "",
            observations_hash=self.record.observations_hash or "",
            lifecycle="INDEXED",
        )
        variants = {
            "hash_drift": base.__class__(
                **{
                    **base.__dict__,
                    "content_hash": "0" * 64,
                }
            ),
            "tombstoned": base.__class__(
                **{**base.__dict__, "tombstoned": True}
            ),
            "quarantined": base.__class__(
                **{**base.__dict__, "quarantined": True}
            ),
            "dead_lifecycle": base.__class__(
                **{**base.__dict__, "lifecycle": "TOMBSTONED"}
            ),
        }
        for name, claims in variants.items():
            with self.subTest(variant=name):
                record = self.record

                class DriftReader:
                    def read_verified(self, evidence_id: str):
                        return VerifiedEvidence(
                            record=record, index=claims
                        )

                    def read_by_content_hash(
                        self, content_hash: str
                    ):
                        return ()

                infra, _ = make_infra(self.world)
                drifted = FindingInfrastructure(
                    evidence_reader=DriftReader(),
                    finding_store=infra.finding_store,
                    workflow_store=infra.workflow_store,
                    audit_sink=infra.audit_sink,
                    notification_sink=infra.notification_sink,
                    alert_ledger=infra.alert_ledger,
                )
                out = materialize(self.result, drifted)
                self.assertFalse(out.accepted)
                self.assertEqual(out.reason, "FRESH_INDEX_MISMATCH")


# ------------------------------------------------------------------
# MULTI-PROGRAM / CROSS-AXIS ISOLATION
# ------------------------------------------------------------------


class IsolationTests(unittest.TestCase):
    def test_cross_program_no_finding(self) -> None:
        world_a = World()
        record, _ = build_oracle_record(world_a)
        outcome = world_a.verify(
            record, list(world_a.authz.values())[0]
        )
        world_b = World()
        infra, _ = make_infra(world_b)
        out = materialize(outcome.result, infra)
        self.assertFalse(out.accepted)

    def test_cross_axis_mutations_no_finding(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        mutations = {
            "program_name": "evil",
            "target_host": OTHER_HOST,
            "artifact_id": "art-" + "9" * 16,
            "authorization_id": "authz-" + "9" * 16,
            "execution_id": "ex-" + "9" * 32,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                forged = outcome.result.model_copy(
                    update={field: value}
                )
                store = FindingStoreMemory()
                single = FindingInfrastructure(
                    evidence_reader=infra.evidence_reader,
                    finding_store=store,
                    workflow_store=infra.workflow_store,
                    audit_sink=infra.audit_sink,
                    notification_sink=infra.notification_sink,
                    alert_ledger=infra.alert_ledger,
                )
                out = materialize(forged, single)
                self.assertFalse(out.accepted)
                self.assertEqual(len(store.list_ids("evil")), 0)

    def test_store_program_isolation(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        self.assertTrue(out.accepted)
        assert out.finding is not None
        self.assertIn(
            out.finding.finding_id,
            infra.finding_store.list_ids(out.finding.program_name),
        )
        self.assertEqual(infra.finding_store.list_ids("other"), ())
        self.assertIsNone(
            infra.finding_store.get_entry(
                "other", out.finding.finding_id
            )
        )


# ------------------------------------------------------------------
# DETERMINISM + IDENTITY
# ------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    def test_byte_identical_replay(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        first = materialize(outcome.result, infra)
        second = materialize(outcome.result, infra)
        self.assertTrue(first.accepted and second.accepted)
        assert first.finding is not None and second.finding is not None
        self.assertEqual(first.finding_id, second.finding_id)
        self.assertEqual(
            canonical_finding_bytes(first.finding),
            canonical_finding_bytes(second.finding),
        )
        self.assertTrue(second.deduplicated)
        self.assertFalse(second.notified)

    def test_timestamp_independent_identity(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        first = materialize(
            outcome.result, infra, materialized_at="2026-01-01T00:00:00Z"
        )
        second = materialize(
            outcome.result, infra, materialized_at="2027-06-06T06:06:06Z"
        )
        self.assertEqual(first.finding_id, second.finding_id)

    def test_version_fork_new_identity(self) -> None:
        _, _, result = confirmed_oracle()
        base_id = finding_id_for(
            classification_result_hash=compute_result_hash(result),
            evidence_bindings_hash=result.evidence_bindings_hash,
            evidence_observations_hash=(
                result.evidence_observations_hash
            ),
            evidence_content_hash=result.evidence_content_hash,
            verifier_version=result.verifier_version,
            rule_id=result.rule_id,
            policy_version=result.policy_version,
            eligibility_policy_version=ELIGIBILITY_POLICY_VERSION,
        )
        forked = finding_id_for(
            classification_result_hash=compute_result_hash(result),
            evidence_bindings_hash=result.evidence_bindings_hash,
            evidence_observations_hash=(
                result.evidence_observations_hash
            ),
            evidence_content_hash=result.evidence_content_hash,
            verifier_version=result.verifier_version,
            rule_id=result.rule_id,
            policy_version="5i-severity-policy/v9",
            eligibility_policy_version=ELIGIBILITY_POLICY_VERSION,
        )
        self.assertNotEqual(base_id, forked)
        self.assertTrue(base_id.startswith("xf-"))

    def test_different_evidence_different_identity(self) -> None:
        _, _, result_a = confirmed_oracle(World())
        _, _, result_b = confirmed_oracle(World())
        id_a = finding_id_for(
            classification_result_hash=compute_result_hash(result_a),
            evidence_bindings_hash=result_a.evidence_bindings_hash,
            evidence_observations_hash=(
                result_a.evidence_observations_hash
            ),
            evidence_content_hash=result_a.evidence_content_hash,
            verifier_version=result_a.verifier_version,
            rule_id=result_a.rule_id,
            policy_version=result_a.policy_version,
            eligibility_policy_version=ELIGIBILITY_POLICY_VERSION,
        )
        id_b = finding_id_for(
            classification_result_hash=compute_result_hash(result_b),
            evidence_bindings_hash=result_b.evidence_bindings_hash,
            evidence_observations_hash=(
                result_b.evidence_observations_hash
            ),
            evidence_content_hash=result_b.evidence_content_hash,
            verifier_version=result_b.verifier_version,
            rule_id=result_b.rule_id,
            policy_version=result_b.policy_version,
            eligibility_policy_version=ELIGIBILITY_POLICY_VERSION,
        )
        self.assertNotEqual(id_a, id_b)

    def test_model_immutable_and_closed(self) -> None:
        _, _, result = confirmed_oracle()
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        with self.assertRaises(Exception):
            out.finding.reason_code = "mutated"  # type: ignore[misc]
        with self.assertRaises(Exception):
            SealedFinding(
                finding_id=out.finding.finding_id,
                classification_result_hash=(
                    out.finding.classification_result_hash
                ),
                evidence_id=out.finding.evidence_id,
                execution_id=out.finding.execution_id,
                authorization_id=out.finding.authorization_id,
                program_name=out.finding.program_name,
                canonical_host=out.finding.canonical_host,
                scope_evaluation_identity=(
                    out.finding.scope_evaluation_identity
                ),
                artifact_id=out.finding.artifact_id,
                artifact_content_hash=(
                    out.finding.artifact_content_hash
                ),
                evidence_content_hash=(
                    out.finding.evidence_content_hash
                ),
                evidence_bindings_hash=(
                    out.finding.evidence_bindings_hash
                ),
                evidence_observations_hash=(
                    out.finding.evidence_observations_hash
                ),
                verifier_version=out.finding.verifier_version,
                rule_id=out.finding.rule_id,
                observation_schema_version=(
                    out.finding.observation_schema_version
                ),
                artifact_schema_version=(
                    out.finding.artifact_schema_version
                ),
                policy_version=out.finding.policy_version,
                eligibility_policy_version=(
                    out.finding.eligibility_policy_version
                ),
                severity=out.finding.severity,
                severity_policy_version=(
                    out.finding.severity_policy_version
                ),
                reason_code=out.finding.reason_code,
                injected_field="nope",
            )
        _ = result

    def test_no_timestamp_fields(self) -> None:
        fields = set(SealedFinding.model_fields)
        for banned in (
            "created_at",
            "materialized_at",
            "at",
            "timestamp",
            "persisted_at",
        ):
            self.assertNotIn(banned, fields)


# ------------------------------------------------------------------
# DEDUP / COLLISION / CONCURRENCY
# ------------------------------------------------------------------


class DedupTests(unittest.TestCase):
    def test_duplicate_is_idempotent_noop(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, ctx = make_infra(world)
        first = materialize(outcome.result, infra)
        second = materialize(outcome.result, infra)
        self.assertTrue(first.accepted)
        self.assertTrue(second.accepted)
        self.assertTrue(second.deduplicated)
        self.assertEqual(first.finding_id, second.finding_id)
        self.assertEqual(len(ctx["sink"].published), 1)
        names = event_names(ctx["audit"])
        self.assertIn("FINDING_DEDUPLICATED", names)
        self.assertEqual(
            len(infra.finding_store.list_ids(first.finding.program_name)),
            1,
        )

    def test_same_key_different_bytes_refused(self) -> None:
        store = FindingStoreMemory()
        key = "xf-" + "1" * 32
        self.assertEqual(
            store.put("acme", key, b'{"a":1}'), PERSISTED
        )
        self.assertEqual(
            store.put("acme", key, b'{"a":1}'), DEDUPLICATED
        )
        self.assertEqual(
            store.put("acme", key, b'{"a":2}'), CORRUPT_COLLISION
        )
        entry = store.get_entry("acme", key)
        assert entry is not None
        self.assertEqual(entry.payload, b'{"a":1}')

    def test_materializer_collision_fails_closed(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        first = materialize(outcome.result, infra)
        self.assertTrue(first.accepted)
        assert first.finding_id is not None
        # Poison the key with foreign bytes behind the materializer.
        poisoned = FindingStoreMemory()
        poisoned.put(
            first.finding.program_name,
            first.finding_id,
            b'{"forged":true}',
        )
        hijacked = FindingInfrastructure(
            evidence_reader=infra.evidence_reader,
            finding_store=poisoned,
            workflow_store=infra.workflow_store,
            audit_sink=infra.audit_sink,
            notification_sink=infra.notification_sink,
            alert_ledger=AlertLedgerMemory(),
        )
        out = materialize(outcome.result, hijacked)
        self.assertFalse(out.accepted)
        self.assertEqual(out.reason, "STORE_CORRUPT_COLLISION")
        self.assertFalse(out.notified)
        names = event_names(infra.audit_sink)
        self.assertIn("FINDING_STORE_REFUSED", names)

    def test_concurrent_identical_materialization(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, ctx = make_infra(world)
        barrier = threading.Barrier(8)
        results: list = []

        def worker() -> None:
            barrier.wait()
            results.append(materialize(outcome.result, infra))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r.accepted for r in results))
        persisted = [r for r in results if not r.deduplicated]
        self.assertEqual(len(persisted), 1)
        self.assertEqual(len(ctx["sink"].published), 1)
        self.assertEqual(
            len(
                infra.finding_store.list_ids(
                    persisted[0].finding.program_name
                )
            ),
            1,
        )
        workflow = infra.workflow_store.get_or_create(
            persisted[0].finding_id,
            persisted[0].finding.program_name,
        )
        self.assertEqual(workflow.state, "OPEN")


# ------------------------------------------------------------------
# WORKFLOW SEPARATION
# ------------------------------------------------------------------


class WorkflowTests(unittest.TestCase):
    def test_workflow_created_open(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        workflow = infra.workflow_store.get_or_create(
            out.finding_id, out.finding.program_name
        )
        self.assertEqual(workflow.state, "OPEN")
        self.assertEqual(workflow.version, 1)

    def test_cas_transition(self) -> None:
        store = WorkflowStoreMemory()
        record = store.get_or_create("xf-" + "2" * 32, "acme")
        updated = store.transition(
            "xf-" + "2" * 32,
            "acme",
            expected_version=1,
            state="ACKNOWLEDGED",
            acknowledged=True,
            assignee="analyst-1",
            add_labels=("triage",),
            add_comment="reviewed",
        )
        self.assertEqual(updated.version, 2)
        self.assertEqual(updated.state, "ACKNOWLEDGED")
        self.assertTrue(updated.acknowledged)
        with self.assertRaises(WorkflowVersionConflict):
            store.transition(
                "xf-" + "2" * 32,
                "acme",
                expected_version=1,
                state="RESOLVED",
            )
        self.assertEqual(record.version, 1)

    def test_illegal_transition_rejected(self) -> None:
        store = WorkflowStoreMemory()
        store.get_or_create("xf-" + "3" * 32, "acme")
        with self.assertRaises(ValueError):
            store.transition(
                "xf-" + "3" * 32,
                "acme",
                expected_version=1,
                state="RESOLVED",
            )

    def test_workflow_carries_no_security_fields(self) -> None:
        from ai.finding.store_memory import WorkflowRecord

        fields = set(WorkflowRecord.__dataclass_fields__)
        for banned in (
            "classification",
            "severity",
            "evidence_content_hash",
            "evidence_bindings_hash",
            "evidence_observations_hash",
            "artifact_content_hash",
            "target_host",
            "canonical_host",
            "verifier_version",
            "rule_id",
            "policy_version",
            "oracle_channels",
            "confirmation_state",
        ):
            self.assertNotIn(banned, fields)

    def test_finding_store_has_no_update_api(self) -> None:
        source = (FINDING_DIR / "store_memory.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        store_methods: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in (
                "FindingStore",
                "FindingStoreMemory",
            ):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        store_methods.add(item.name)
        for banned in (
            "update",
            "patch",
            "delete",
            "upsert",
            "save",
            "put_if_newer",
            "merge",
            "overwrite",
        ):
            self.assertNotIn(banned, store_methods)

    def test_workflow_mutation_never_touches_security(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        before = canonical_finding_bytes(out.finding)
        infra.workflow_store.transition(
            out.finding_id,
            out.finding.program_name,
            expected_version=1,
            state="ACKNOWLEDGED",
            add_comment="ops note",
        )
        entry = infra.finding_store.get_entry(
            out.finding.program_name, out.finding_id
        )
        assert entry is not None
        self.assertEqual(entry.payload, before)


# ------------------------------------------------------------------
# LIFECYCLE / RETENTION / AVAILABILITY
# ------------------------------------------------------------------


class LifecycleTests(unittest.TestCase):
    def test_tombstone_preserves_bytes(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, ctx = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        self.assertTrue(
            infra.finding_store.tombstone(
                out.finding.program_name,
                out.finding_id,
                reason="operator-review",
                actor="operator-1",
            )
        )
        entry = infra.finding_store.get_entry(
            out.finding.program_name, out.finding_id
        )
        assert entry is not None
        self.assertEqual(
            entry.payload, canonical_finding_bytes(out.finding)
        )
        self.assertEqual(entry.lifecycle, "TOMBSTONED")
        names = event_names(ctx["audit"])
        self.assertIn("FINDING_PERSISTED", names)

    def test_archive_preserves_bytes(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        self.assertTrue(
            infra.finding_store.archive(
                out.finding.program_name, out.finding_id
            )
        )
        entry = infra.finding_store.get_entry(
            out.finding.program_name, out.finding_id
        )
        assert entry is not None
        self.assertEqual(
            entry.payload, canonical_finding_bytes(out.finding)
        )
        self.assertEqual(entry.lifecycle, "ARCHIVED")

    def test_availability_persisted(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        self.assertEqual(
            finding_availability(out.finding, world.seam()), "PERSISTED"
        )

    def test_availability_evidence_gone(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        empty = World()
        self.assertEqual(
            finding_availability(out.finding, empty.seam()),
            "EVIDENCE_GONE",
        )

    def test_availability_unverifiable_not_negative(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        # Serve a well-formed but lifecycle-diverged row for the same
        # evidence id: availability degrades, history is untouched.
        diverged = record.model_copy(
            update={"lifecycle": "INCOMPLETE", "complete": False}
        )
        triple = seal.compute_hashes(diverged)
        fixed = diverged.model_copy(
            update={
                "bindings_hash": triple[0],
                "observations_hash": triple[1],
                "content_hash": triple[2],
            }
        )
        from ai.verification.deterministic.verified_read import (
            VerifiedEvidence,
        )

        class DivergedReader:
            def read_verified(self, evidence_id: str):
                return VerifiedEvidence(record=fixed, index=None)

            def read_by_content_hash(self, content_hash: str):
                return ()

        self.assertEqual(
            finding_availability(out.finding, DivergedReader()),
            "PERSISTED_UNVERIFIABLE",
        )
        # The persisted finding bytes are unchanged by the flag.
        entry = infra.finding_store.get_entry(
            out.finding.program_name, out.finding_id
        )
        assert entry is not None
        self.assertEqual(
            entry.payload, canonical_finding_bytes(out.finding)
        )


# ------------------------------------------------------------------
# AUDIT
# ------------------------------------------------------------------


class FindingAuditTests(unittest.TestCase):
    def test_happy_path_events(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, ctx = make_infra(world)
        out = materialize(outcome.result, infra)
        names = event_names(ctx["audit"])
        self.assertIn("FINDING_ELIGIBILITY_ACCEPTED", names)
        self.assertIn("FINDING_MATERIALIZED", names)
        self.assertIn("FINDING_PERSISTED", names)
        persisted = [
            e
            for e in ctx["audit"]
            if e.event == "FINDING_PERSISTED"
            and e.finding_id == out.finding_id
        ]
        self.assertTrue(persisted)
        for event in ctx["audit"]:
            self.assertEqual(event.actor, "finding-pipeline/5J")

    def test_rejection_events(self) -> None:
        world = World()
        record, _ = build_http_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, ctx = make_infra(world)
        out = materialize(outcome.result, infra)
        self.assertFalse(out.accepted)
        rejected = [
            e
            for e in ctx["audit"]
            if e.event == "FINDING_ELIGIBILITY_REJECTED"
        ]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(
            rejected[0].reason_code, "OUTCOME_NOT_FINDING_ELIGIBLE"
        )

    def test_audit_secrecy(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, ctx = make_infra(world)
        materialize(outcome.result, infra)
        for event in ctx["audit"]:
            dumped = event.model_dump_json()
            for needle in (
                "mongodb://",
                "password",
                "bearer ",
                "<script",
                "alert(",
                "stdout",
            ):
                self.assertNotIn(needle, dumped)

    def test_failing_sink_does_not_block(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)

        class ExplodingSink(list):
            def append(self, item: object) -> None:
                raise RuntimeError("sink on fire")

        loud = FindingInfrastructure(
            evidence_reader=infra.evidence_reader,
            finding_store=infra.finding_store,
            workflow_store=infra.workflow_store,
            audit_sink=ExplodingSink(),
            notification_sink=infra.notification_sink,
            alert_ledger=infra.alert_ledger,
        )
        out = materialize(outcome.result, loud)
        self.assertTrue(out.accepted)


# ------------------------------------------------------------------
# NOTIFICATION SEAM
# ------------------------------------------------------------------


class NotificationTests(unittest.TestCase):
    def test_only_fresh_persist_notifies(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, ctx = make_infra(world)
        first = materialize(outcome.result, infra)
        second = materialize(outcome.result, infra)
        self.assertTrue(first.notified)
        self.assertFalse(second.notified)
        self.assertEqual(len(ctx["sink"].published), 1)
        alert = ctx["sink"].published[0]
        self.assertEqual(alert.finding_id, first.finding_id)
        self.assertEqual(
            alert.alert_id, alert_id_for(first.finding_id)
        )
        self.assertFalse(alert.severity_pending)

    def test_rejection_never_notifies(self) -> None:
        world = World()
        record, _ = build_http_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, ctx = make_infra(world)
        out = materialize(outcome.result, infra)
        self.assertFalse(out.accepted)
        self.assertFalse(out.notified)
        self.assertEqual(len(ctx["sink"].published), 0)

    def test_alert_identity_deterministic(self) -> None:
        finding_id = "xf-" + "a" * 32
        first = alert_id_for(finding_id)
        second = alert_id_for(finding_id)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("alert-"))
        ledger = AlertLedgerMemory()
        self.assertTrue(ledger.claim(first))
        self.assertFalse(ledger.claim(first))

    def test_no_delivery_code_in_seam(self) -> None:
        source = (FINDING_DIR / "notify.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
        for banned in (
            "telegram",
            "requests",
            "httpx",
            "urllib",
            "smtplib",
            "socket",
        ):
            self.assertNotIn(banned, imported)


# ------------------------------------------------------------------
# SEVERITY BOUNDARY
# ------------------------------------------------------------------


class SeverityBoundaryTests(unittest.TestCase):
    def test_severity_verbatim_copy(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        self.assertEqual(
            out.finding.severity, outcome.result.severity
        )
        self.assertEqual(
            out.finding.severity_unset_reason,
            outcome.result.severity_unset_reason,
        )
        self.assertEqual(
            out.finding.severity_policy_version,
            outcome.result.policy_version,
        )

    def test_severity_only_flows_from_classification(self) -> None:
        # Every `severity=` write site in ai/finding must copy a
        # sealed source verbatim: the 5I classification triple on the
        # finding constructor, or the sealed finding on the offline
        # alert constructor (alerts derive from findings, never fresh
        # input). No literal, no mapping, no third source.
        for path in sorted(FINDING_DIR.glob("*.py")):
            tree = ast.parse(
                path.read_text(encoding="utf-8"), filename=path.name
            )
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                constructor = ""
                func = node.func
                if isinstance(func, ast.Name):
                    constructor = func.id
                elif isinstance(func, ast.Attribute):
                    constructor = func.attr
                for keyword in node.keywords:
                    if keyword.arg not in (
                        "severity",
                        "severity_unset_reason",
                        "severity_policy_version",
                    ):
                        continue
                    value = keyword.value
                    self.assertIsInstance(
                        value, ast.Attribute, path.name
                    )
                    self.assertIsInstance(value.value, ast.Name)
                    if constructor == "FindingAlert":
                        self.assertEqual(value.value.id, "finding")
                        self.assertIn(
                            value.attr,
                            ("severity", "severity_unset_reason"),
                        )
                    else:
                        self.assertEqual(
                            value.value.id, "classification"
                        )
                        self.assertIn(
                            value.attr,
                            (
                                "severity",
                                "severity_unset_reason",
                                "policy_version",
                            ),
                        )

    def test_severity_value_literals_absent(self) -> None:
        # No severity VALUE literal in executable code position: 5J
        # cannot name a severity to assign one. Excluded: prose
        # (docstring lines), type annotations (``Literal[...]``
        # slices and argument annotations), and three pinned benign
        # sites — the closed-vocabulary validation set in
        # authority.py, the model default in sealed.py, and the UNSET
        # display marker in materializer.py. Any NEW literal anywhere
        # else fails this test by design.
        severity_values = {
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "UNSET",
        }
        allowed: set[tuple[str, str]] = {
            ("authority.py", value) for value in severity_values
        } | {("sealed.py", "UNSET"), ("materializer.py", "UNSET")}

        def docstring_lines(tree: ast.Module) -> set[int]:
            lines: set[int] = set()
            for node in ast.walk(tree):
                if isinstance(
                    node,
                    (ast.Module, ast.ClassDef, ast.FunctionDef,
                     ast.AsyncFunctionDef),
                ):
                    body = node.body
                    if (
                        body
                        and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)
                    ):
                        start = body[0].lineno
                        end = body[0].end_lineno or start
                        lines.update(range(start, end + 1))
            return lines

        hits: list[tuple[str, str, int]] = []
        for path in sorted(FINDING_DIR.glob("*.py")):
            if path.name == "legacy_block.py":
                continue
            tree = ast.parse(
                path.read_text(encoding="utf-8"), filename=path.name
            )
            prose = docstring_lines(tree)
            parents: dict[ast.AST, ast.AST] = {}
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    parents[child] = node

            def in_annotation(node: ast.AST) -> bool:
                seen: ast.AST | None = node
                while seen in parents:
                    seen = parents[seen]
                    if isinstance(seen, ast.Subscript):
                        return True
                    if isinstance(seen, ast.arg):
                        return True
                return False

            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and node.value in severity_values
                    and node.lineno not in prose
                    and not in_annotation(node)
                ):
                    hits.append((path.name, node.value, node.lineno))
        unexpected = [hit for hit in hits if hit[:2] not in allowed]
        self.assertEqual(unexpected, [])
        # The allowlist itself must be fully exercised (no dead pins).
        exercised = {(name, value) for name, value, _ in hits}
        self.assertEqual(exercised, allowed)


# ------------------------------------------------------------------
# LEGACY HARD-BLOCK
# ------------------------------------------------------------------


class LegacyBlockTests(unittest.TestCase):
    def test_no_legacy_imports_or_references(self) -> None:
        for path in sorted(FINDING_DIR.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            hits = source_references_banned(source)
            self.assertEqual(hits, (), path.name)
            tree = ast.parse(source, filename=path.name)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for banned in BANNED_IMPORTS:
                        self.assertFalse(
                            module == banned
                            or module.startswith(banned + "."),
                            f"{path.name} imports {module}",
                        )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        for banned in BANNED_IMPORTS:
                            self.assertFalse(
                                alias.name == banned
                                or alias.name.startswith(banned + "."),
                                f"{path.name} imports {alias.name}",
                            )

    def test_banned_tokens_absent_from_code(self) -> None:
        for path in sorted(FINDING_DIR.glob("*.py")):
            if path.name == "legacy_block.py":
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=path.name)
            names: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    names.add(node.attr)
            for token in BANNED_TOKENS:
                self.assertNotIn(token, names, path.name)

    def test_no_offline_violations(self) -> None:
        for path in sorted(FINDING_DIR.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=path.name)
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    imported.add((node.module or "").split(".")[0])
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imported.add(alias.name.split(".")[0])
            for banned in (
                "socket",
                "subprocess",
                "urllib",
                "http",
                "playwright",
                "selenium",
                "pymongo",
                "mongoengine",
                "requests",
                "telegram",
                "database",
                "watch_xss_verify",
            ):
                self.assertNotIn(banned, imported, path.name)

    def test_legacy_outputs_cannot_enter(self) -> None:
        world = World()
        infra, _ = make_infra(world)
        legacy_payload = {
            "finding_id": "xf-" + "0" * 32,
            "status": "CONFIRMED",
            "severity": "high",
            "matched": True,
            "raw_output": "[matched] something",
        }
        out = materialize(legacy_payload, infra)
        self.assertFalse(out.accepted)
        self.assertEqual(
            out.reason, "AUTHORITY_NOT_CLASSIFICATION_RESULT"
        )

    def test_hard_block_inventory_complete(self) -> None:
        self.assertTrue(len(HARD_BLOCKED_PATHS) >= 10)
        joined = "\n".join(HARD_BLOCKED_PATHS)
        for marker in (
            "XSSVerifier",
            "XSSFinding",
            "NucleiFinding",
            "to_findings",
            "save_findings",
            "XssFindings",
            "mongo_persist",
        ):
            self.assertIn(marker, joined)


# ------------------------------------------------------------------
# CONTRACT / VERSION / MONGO-BLOCK
# ------------------------------------------------------------------


class ContractTests(unittest.TestCase):
    def test_finding_contract_fields(self) -> None:
        fields = set(SealedFinding.model_fields)
        for required in (
            "finding_id",
            "finding_schema_version",
            "classification_result_hash",
            "evidence_id",
            "execution_id",
            "authorization_id",
            "program_name",
            "canonical_host",
            "scheme",
            "effective_port",
            "path_scope",
            "target_resolution_identity",
            "scope_evaluation_identity",
            "artifact_id",
            "artifact_content_hash",
            "evidence_content_hash",
            "evidence_bindings_hash",
            "evidence_observations_hash",
            "verifier_version",
            "rule_id",
            "observation_schema_version",
            "artifact_schema_version",
            "policy_version",
            "eligibility_policy_version",
            "classification",
            "confirmation_state",
            "oracle_channels",
            "severity",
            "severity_unset_reason",
            "severity_policy_version",
            "executed_payload_hash",
            "derivation_contract_hash",
            "round_id",
            "submit_evidence_ref",
            "submit_content_hash",
            "reason_code",
        ):
            self.assertIn(required, fields)

    def test_finding_contract_exact(self) -> None:
        # Exact closed field set: no more, no fewer. Any added field
        # (timestamps, content, caller metadata) fails this test by
        # design — migration requires sealed-finding/vN, not drift.
        self.assertEqual(
            set(SealedFinding.model_fields),
            {
                "finding_schema_version",
                "finding_id",
                "classification_result_hash",
                "evidence_id",
                "execution_id",
                "authorization_id",
                "program_name",
                "canonical_host",
                "scheme",
                "effective_port",
                "path_scope",
                "target_resolution_identity",
                "scope_evaluation_identity",
                "artifact_id",
                "artifact_content_hash",
                "evidence_content_hash",
                "evidence_bindings_hash",
                "evidence_observations_hash",
                "verifier_version",
                "rule_id",
                "observation_schema_version",
                "artifact_schema_version",
                "policy_version",
                "eligibility_policy_version",
                "classification",
                "confirmation_state",
                "oracle_channels",
                "severity",
                "severity_unset_reason",
                "severity_policy_version",
                "executed_payload_hash",
                "derivation_contract_hash",
                "round_id",
                "submit_evidence_ref",
                "submit_content_hash",
                "reason_code",
            },
        )

    def test_resolution_scope_identities_bound(self) -> None:
        world = World()
        record, _ = build_oracle_record(world)
        outcome = world.verify(
            record, list(world.authz.values())[0]
        )
        infra, _ = make_infra(world)
        out = materialize(outcome.result, infra)
        assert out.finding is not None
        snapshot = record.snapshot_binding
        assert snapshot is not None
        self.assertEqual(
            out.finding.scope_evaluation_identity,
            snapshot.scope_lists_hash,
        )
        self.assertEqual(
            out.finding.target_resolution_identity,
            snapshot.snapshot_ref,
        )

    def test_unknown_rule_version_rejected(self) -> None:
        _, _, result = confirmed_oracle()
        forged = result.model_copy(
            update={"rule_id": "xss-reflected-oracle/v2"}
        )
        world = World()
        infra, _ = make_infra(world)
        out = materialize(forged, infra)
        self.assertFalse(out.accepted)
        self.assertEqual(out.reason, "AUTHORITY_RULE_UNKNOWN")

    def test_mongo_adapter_blocked(self) -> None:
        self.assertTrue(B2_BLOCKED)
        with self.assertRaises(RuntimeError):
            MongoFindingStoreAdapter()
        with self.assertRaises(RuntimeError):
            MongoFindingStoreAdapter.__new__(
                MongoFindingStoreAdapter
            ).put("acme", "xf-" + "0" * 32, b"{}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
