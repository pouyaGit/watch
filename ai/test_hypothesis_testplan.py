"""Focused tests for Hypothesis + TestPlan contracts (Phase 1).

These are DATA-CONTRACT tests: they prove the schemas have no
execution, verdict, or scope authority and that validation fails
closed. No network, no LLM, no executor is invoked.
"""

import unittest

from pydantic import ValidationError

from ai.schemas.hypothesis import (
    LLMMetadata,
    ResearchProvenance,
    TargetRef,
    build_hypothesis,
)
from ai.schemas.test_plan import (
    ArtifactRef,
    HttpRequestSpec,
    artifact_id_from_hash,
    build_test_plan,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_KB = "kb-" + "a" * 16
_SRC = "src-" + "b" * 16
_CLM = "clm-" + "c" * 16
_HASH = "d" * 64
_HASH2 = "e" * 64

_TARGET = TargetRef(
    program_name="acme",
    subdomain="app.acme.test",
    scope="in_scope",
    endpoint="https://app.acme.test/profile",
    technology_snapshot=["Nginx:1.25", "FooCMS:4.1"],
    observed_at="2026-09-01T00:00:00+00:00",
)

_PROV = ResearchProvenance(knowledge_ids=[_KB], source_ids=[_SRC])

_ART_HASH = "f" * 64
_ART_REF = ArtifactRef(
    artifact_id=artifact_id_from_hash(_ART_HASH),
    artifact_type="nuclei_template",
    content_hash=_ART_HASH,
)


def _hyp(**overrides):
    base = dict(
        target=_TARGET,
        hypothesis_type="vulnerability_relevance",
        statement="FooCMS 4.1 may be affected by CVE-2026-1234 on /profile",
        pattern_kind="cve",
        pattern_id="CVE-2026-1234",
        provenance=_PROV,
        priority=0.7,
        priority_basis="cvss 9.8 + 3 assets",
    )
    base.update(overrides)
    return build_hypothesis(**base)


def _plan(**overrides):
    hyp = _hyp()
    base = dict(
        hypothesis_id=hyp.hypothesis_id,
        target=_TARGET,
        test_category="nuclei_cve",
        objective="Probe /profile for FooCMS CVE-2026-1234 signature",
        execution_type="nuclei_scan",
        verifier_type="nuclei_verifier",
        provenance=_PROV,
        request_spec=HttpRequestSpec(
            method="GET", path="/profile", query_params={"id": "1"}
        ),
        expected_behavior="200 with FooCMS marker",
        required_evidence=["http 200 + body contains FooCMS string"],
    )
    base.update(overrides)
    return build_test_plan(**base)


# ==================================================================
# Hypothesis
# ==================================================================


class HypothesisValidConstructionTests(unittest.TestCase):
    def test_valid_construction(self):  # 1
        hyp = _hyp()
        self.assertEqual(hyp.status, "PROPOSED")
        self.assertEqual(hyp.schema_version, "hypothesis/v1")

    def test_required_fields(self):  # 2
        for missing in ("statement", "pattern_id"):
            with self.subTest(missing=missing):
                kwargs = dict(
                    target=_TARGET,
                    hypothesis_type="vulnerability_relevance",
                    statement="s",
                    pattern_kind="cve",
                    pattern_id="CVE-1",
                    provenance=_PROV,
                )
                kwargs[missing] = "   "
                with self.assertRaises(ValidationError):
                    build_hypothesis(**kwargs)

    def test_invalid_lifecycle_state(self):  # 3
        hyp = _hyp()
        with self.assertRaises(ValidationError):
            hyp.model_copy(update={"status": "APPROVED"}).model_validate(
                hyp.model_copy(update={"status": "APPROVED"}).model_dump()
            )

    def test_rejection_of_confirmed(self):  # 4
        hyp = _hyp()
        with self.assertRaises(ValidationError):
            hyp.model_validate({**hyp.model_dump(), "status": "CONFIRMED"})

    def test_rejection_of_not_vulnerable(self):  # 5
        hyp = _hyp()
        with self.assertRaises(ValidationError):
            hyp.model_validate(
                {**hyp.model_dump(), "status": "NOT_VULNERABLE"}
            )

    def test_rejection_of_verified(self):  # also implied
        hyp = _hyp()
        with self.assertRaises(ValidationError):
            hyp.model_validate({**hyp.model_dump(), "status": "VERIFIED"})

    def test_invalid_target_reference(self):  # 6
        with self.assertRaises(ValidationError):
            TargetRef(program_name="   ", subdomain="x.test")
        with self.assertRaises(ValidationError):
            TargetRef(program_name="acme", subdomain="")

    def test_missing_provenance(self):  # 7
        with self.assertRaises(ValidationError):
            ResearchProvenance()

    def test_malformed_provenance(self):  # 8
        with self.assertRaises(ValidationError):
            ResearchProvenance(knowledge_ids=["not-a-kb-id"])
        with self.assertRaises(ValidationError):
            ResearchProvenance(source_ids=["bad"])
        with self.assertRaises(ValidationError):
            ResearchProvenance(research_hashes=["short"])

    def test_deterministic_idempotency_key(self):  # 9
        a = _hyp()
        b = _hyp()
        self.assertEqual(a.idempotency_key, b.idempotency_key)
        self.assertEqual(a.hypothesis_id, b.hypothesis_id)

    def test_same_logical_basis_same_key(self):  # 10
        # Whitespace/case normalization must not fork identity.
        a = _hyp(statement="  FooCMS 4.1 MAY be affected  ")
        b = _hyp(statement="foocms 4.1 may be affected")
        self.assertEqual(a.idempotency_key, b.idempotency_key)

    def test_different_target_different_key(self):  # 11
        other_target = TargetRef(
            program_name="other", subdomain="app.acme.test", endpoint="https://app.acme.test/profile"
        )
        a = _hyp(target=_TARGET)
        b = _hyp(target=other_target)
        self.assertNotEqual(a.idempotency_key, b.idempotency_key)
        self.assertNotEqual(a.hypothesis_id, b.hypothesis_id)

    def test_different_provenance_different_key(self):  # 12
        prov2 = ResearchProvenance(knowledge_ids=[_KB], research_hashes=[_HASH2])
        a = _hyp(provenance=_PROV)
        b = _hyp(provenance=prov2)
        self.assertNotEqual(a.idempotency_key, b.idempotency_key)

    def test_unknown_fields_rejected(self):  # 13
        hyp = _hyp()
        with self.assertRaises(ValidationError):
            hyp.model_validate({**hyp.model_dump(), "extra_field": "evil"})

    def test_serialization_round_trip(self):  # 14
        hyp = _hyp()
        restored = hyp.__class__.model_validate(hyp.model_dump(mode="json"))
        self.assertEqual(restored, hyp)

    def test_ai_metadata_non_authoritative(self):  # 15
        a = _hyp()
        b = build_hypothesis(
            target=_TARGET,
            hypothesis_type="vulnerability_relevance",
            statement="FooCMS 4.1 may be affected by CVE-2026-1234 on /profile",
            pattern_kind="cve",
            pattern_id="CVE-2026-1234",
            provenance=_PROV,
            llm=LLMMetadata(provider="openrouter", model="strong-model"),
        )
        c = build_hypothesis(
            target=_TARGET,
            hypothesis_type="vulnerability_relevance",
            statement="FooCMS 4.1 may be affected by CVE-2026-1234 on /profile",
            pattern_kind="cve",
            pattern_id="CVE-2026-1234",
            provenance=_PROV,
            llm=LLMMetadata(provider="local", model="cheap-model"),
        )
        self.assertEqual(b.idempotency_key, c.idempotency_key)
        self.assertEqual(b.hypothesis_id, a.hypothesis_id)

    def test_priority_does_not_affect_identity(self):
        a = _hyp(priority=0.1)
        b = _hyp(priority=0.9)
        self.assertEqual(a.idempotency_key, b.idempotency_key)

    def test_superseded_requires_supersedes(self):
        hyp = _hyp()
        with self.assertRaises(ValidationError):
            hyp.model_copy(update={"status": "SUPERSEDED"}).model_validate(
                {**hyp.model_dump(), "status": "SUPERSEDED"}
            )

    def test_cancelled_requires_reason(self):
        hyp = _hyp()
        with self.assertRaises(ValidationError):
            hyp.model_validate({**hyp.model_dump(), "status": "CANCELLED"})


# ==================================================================
# TestPlan
# ==================================================================


class TestPlanValidConstructionTests(unittest.TestCase):
    def test_valid_construction(self):  # 16
        plan = _plan()
        self.assertEqual(plan.status, "PROPOSED")
        self.assertEqual(plan.schema_version, "testplan/v1")

    def test_required_hypothesis_binding(self):  # 17
        with self.assertRaises(ValidationError):
            build_test_plan(
                hypothesis_id="",
                target=_TARGET,
                test_category="nuclei_cve",
                objective="Probe",
                execution_type="nuclei_scan",
                verifier_type="nuclei_verifier",
                provenance=_PROV,
            )

    def test_invalid_lifecycle_state(self):  # 18
        plan = _plan()
        with self.assertRaises(ValidationError):
            plan.model_validate({**plan.model_dump(), "status": "CONFIRMED"})

    def test_rejection_of_confirmed(self):  # 19
        plan = _plan()
        with self.assertRaises(ValidationError):
            plan.model_validate({**plan.model_dump(), "status": "CONFIRMED"})

    def test_rejection_of_not_vulnerable(self):  # 20
        plan = _plan()
        with self.assertRaises(ValidationError):
            plan.model_validate(
                {**plan.model_dump(), "status": "NOT_VULNERABLE"}
            )

    def test_rejection_of_verified(self):
        plan = _plan()
        with self.assertRaises(ValidationError):
            plan.model_validate({**plan.model_dump(), "status": "VERIFIED"})

    def test_invalid_target_reference(self):  # 21
        with self.assertRaises(ValidationError):
            build_test_plan(
                hypothesis_id=_hyp().hypothesis_id,
                target=TargetRef(program_name="", subdomain="x.test"),
                test_category="nuclei_cve",
                objective="Probe",
                execution_type="nuclei_scan",
                verifier_type="nuclei_verifier",
                provenance=_PROV,
            )

    def test_executable_payload_field_rejection(self):  # 22
        plan = _plan()
        with self.assertRaises(ValidationError):
            plan.model_validate({**plan.model_dump(), "command": "rm -rf /"})
        with self.assertRaises(ValidationError):
            HttpRequestSpec.model_validate(
                {"method": "GET", "path": "/x", "extra": "evil"}
            )

    def test_arbitrary_command_tool_rejection(self):  # 23
        plan = _plan()
        for field in ("subprocess", "shell", "tool_call", "eval", "callback", "plugin"):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    plan.model_validate({**plan.model_dump(), field: "evil"})

    def test_invalid_provenance(self):  # 24
        with self.assertRaises(ValidationError):
            build_test_plan(
                hypothesis_id=_hyp().hypothesis_id,
                target=_TARGET,
                test_category="nuclei_cve",
                objective="Probe",
                execution_type="nuclei_scan",
                verifier_type="nuclei_verifier",
                provenance=ResearchProvenance(),  # type: ignore[arg-type]
            )

    def test_artifact_reference_behavior(self):  # 25
        plan = _plan(artifact_ref=_ART_REF)
        self.assertEqual(plan.artifact_ref.content_hash, _ART_HASH)  # type: ignore[union-attr]
        # Hash mismatch must fail
        with self.assertRaises(ValidationError):
            ArtifactRef(
                artifact_id=_ART_REF.artifact_id,
                content_hash=_HASH,
            )
        # Artifact ref is reference only, not executable content
        self.assertFalse(hasattr(plan.artifact_ref, "command"))

    def test_serialization_round_trip(self):  # 26
        plan = _plan()
        restored = plan.__class__.model_validate(plan.model_dump(mode="json"))
        self.assertEqual(restored, plan)

    def test_target_reference_descriptive(self):  # 27
        # TargetRef has no scope authority field; model fields are only identity + snapshot.
        self.assertNotIn("scope_allowed", TargetRef.model_fields)
        self.assertNotIn("scope_allowed", type(_plan()).model_fields)

    def test_no_scope_grant_authority(self):  # 28
        plan = _plan()
        dump = plan.model_dump()
        # Exhaustively assert no scope-grant-like key exists anywhere.
        for key in dump:
            self.assertNotIn("scope_allowed", key.lower())
            self.assertNotIn("allow_scope", key.lower())
        # Unknown field must fail closed
        with self.assertRaises(ValidationError):
            plan.model_validate({**dump, "scope_allowed": True})

    def test_unknown_fields_rejected(self):
        plan = _plan()
        with self.assertRaises(ValidationError):
            plan.model_validate({**plan.model_dump(), "extra": "evil"})

    def test_request_spec_path_validation(self):
        with self.assertRaises(ValidationError):
            HttpRequestSpec(path="not-a-path")
        with self.assertRaises(ValidationError):
            HttpRequestSpec(path="/evil\nHeader: injected")

    def test_idempotency_deterministic(self):
        a = _plan()
        b = _plan()
        self.assertEqual(a.idempotency_key, b.idempotency_key)

    def test_different_objective_different_key(self):
        a = _plan(objective="Probe A")
        b = _plan(objective="Probe B")
        self.assertNotEqual(a.idempotency_key, b.idempotency_key)


# ==================================================================
# Cross-contract
# ==================================================================


class CrossContractTests(unittest.TestCase):
    def test_plan_references_valid_hypothesis_identity(self):  # 29
        hyp = _hyp()
        plan = _plan(hypothesis_id=hyp.hypothesis_id)
        self.assertEqual(plan.hypothesis_id, hyp.hypothesis_id)
        with self.assertRaises(ValidationError):
            build_test_plan(
                hypothesis_id="bad-id",
                target=_TARGET,
                test_category="nuclei_cve",
                objective="Probe",
                execution_type="nuclei_scan",
                verifier_type="nuclei_verifier",
                provenance=_PROV,
            )

    def test_hypothesis_to_plan_provenance_auditable(self):  # 30
        hyp = _hyp()
        plan = _plan(hypothesis_id=hyp.hypothesis_id, provenance=hyp.provenance)
        self.assertEqual(plan.provenance, hyp.provenance)
        # Full chain traceable: plan -> hypothesis -> research hashes
        self.assertIn(_KB, plan.provenance.knowledge_ids)
        self.assertIn(_SRC, plan.provenance.source_ids)

    def test_no_field_represents_verdict(self):  # 31
        for model in (_hyp(), _plan()):
            for field_name in type(model).model_fields:
                lower = field_name.lower()
                self.assertNotIn("verdict", lower)
                self.assertNotIn("confirmed", lower)
        # Status literals must not include verdict values
        hyp = _hyp()
        with self.assertRaises(ValidationError):
            hyp.model_validate({**hyp.model_dump(), "status": "CONFIRMED"})
        plan = _plan()
        with self.assertRaises(ValidationError):
            plan.model_validate({**plan.model_dump(), "status": "CONFIRMED"})

    def test_unknown_extra_fields_fail_closed(self):  # 32
        hyp = _hyp()
        with self.assertRaises(ValidationError):
            hyp.model_validate({**hyp.model_dump(), "CONFIRMED": True})
        plan = _plan()
        with self.assertRaises(ValidationError):
            plan.model_validate(
                {**plan.model_dump(), "tool_call": {"name": "exec", "args": "rm"}}
            )


# ==================================================================
# Adversarial / LLM-shaped objects
# ==================================================================


class AdversarialTests(unittest.TestCase):
    def test_malicious_llm_object_cannot_become_hypothesis(self):
        malicious = {
            "status": "CONFIRMED",
            "target": "app.acme.test",
            "command": "rm -rf /",
            "tool_call": "exec",
            "subprocess": "shell",
        }
        from ai.schemas.hypothesis import Hypothesis

        with self.assertRaises(ValidationError):
            Hypothesis.model_validate(malicious)

    def test_malicious_llm_object_cannot_become_testplan(self):
        malicious = {
            "status": "CONFIRMED",
            "target": "app.acme.test",
            "command": "curl http://evil.test",
            "shell": "bash -i",
            "tool_call": {"name": "exec"},
        }
        from ai.schemas.test_plan import TestPlan

        with self.assertRaises(ValidationError):
            TestPlan.model_validate(malicious)

    def test_verdict_like_values_rejected_everywhere(self):
        for bad in ("CONFIRMED", "NOT_VULNERABLE", "VERIFIED", "VERIFIED_TRUE"):
            with self.subTest(bad=bad):
                hyp = _hyp()
                with self.assertRaises(ValidationError):
                    hyp.model_validate({**hyp.model_dump(), "status": bad})
                plan = _plan()
                with self.assertRaises(ValidationError):
                    plan.model_validate({**plan.model_dump(), "status": bad})

    def test_execution_like_fields_rejected(self):
        plan = _plan()
        hyp = _hyp()
        for bad_field in ("execute", "subprocess", "shell", "tool_call", "command", "eval", "callback"):
            with self.subTest(field=bad_field):
                with self.assertRaises(ValidationError):
                    plan.model_validate({**plan.model_dump(), bad_field: "evil"})
                with self.assertRaises(ValidationError):
                    hyp.model_validate({**hyp.model_dump(), bad_field: "evil"})

    def test_no_execution_authority_in_either_schema(self):
        for model in (_hyp(), _plan()):
            fields_lower = {k.lower() for k in type(model).model_fields}
            for forbidden in ("command", "subprocess", "shell", "tool_call", "eval", "execute", "callback", "plugin"):
                self.assertNotIn(forbidden, fields_lower)

    def test_no_verdict_authority_in_either_schema(self):
        for model in (_hyp(), _plan()):
            fields_lower = {k.lower() for k in type(model).model_fields}
            for forbidden in ("verdict", "confirmed", "not_vulnerable"):
                self.assertNotIn(forbidden, fields_lower)


if __name__ == "__main__":
    unittest.main()
