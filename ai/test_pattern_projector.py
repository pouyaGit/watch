"""Focused tests for the deterministic Pattern Projector (Phase 2B).

These tests prove the projector is a pure, deterministic
transformation from already grounded claims to normalized research
patterns: no LLM, no network, no execution; raw text can never become
a pattern; ungrounded claims and missing provenance are rejected;
interpretation never becomes fact; output is deterministic and order
independent; and Phase 2A validation remains fail-closed.
"""

import unittest

from pydantic import ValidationError

from ai.researcher import pattern_projector as projector
from ai.researcher.pattern_projector import (
    GroundedClaim,
    project_claim,
    project_claims,
)
from ai.schemas.ingestion import ExtractedClaim
from ai.schemas.knowledge import KnowledgeSourceClaims
from ai.schemas.research_pattern import (
    AttackPattern,
    VulnerabilityPattern,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_CLM = "clm-" + "c" * 16
_CLM2 = "clm-" + "d" * 16
_KB = "kb-" + "a" * 16
_SRC = "src-" + "b" * 16
_HASH = "e" * 64
_HASH2 = "f" * 64


def _claim(
    *,
    evidence_class="EXPLICIT",
    confidence=0.9,
    title="FooCMS profile bio stored XSS",
    summary="FooCMS renders the profile bio field without encoding",
    technologies=("FooCMS",),
    techniques=(),
    contexts=(),
    payload_patterns=(),
    verification_patterns=(),
    xss_types=(),
    wafs=(),
    tags=(),
    rationale="directly stated in source",
    snippet="FooCMS renders the profile bio field",
) -> ExtractedClaim:
    return ExtractedClaim(
        evidence_class=evidence_class,
        rationale=rationale,
        evidence_snippets=[{"text": snippet, "section": "body"}],
        title=title,
        summary=summary,
        technologies=list(technologies),
        xss_types=list(xss_types),
        contexts=list(contexts),
        wafs=list(wafs),
        techniques=list(techniques),
        payload_patterns=list(payload_patterns),
        verification_patterns=list(verification_patterns),
        tags=list(tags),
        confidence=confidence,
    )


def _grounded(
    claim=None,
    *,
    claim_id=_CLM,
    knowledge_id=_KB,
    source_id=_SRC,
    research_hash=_HASH,
) -> GroundedClaim:
    return GroundedClaim(
        claim=claim if claim is not None else _claim(),
        claim_id=claim_id,
        knowledge_id=knowledge_id,
        source_id=source_id,
        research_hash=research_hash,
    )


def _attack_claim(**overrides) -> ExtractedClaim:
    base = dict(
        technologies=("FooCMS",),
        techniques=("stored_xss_via_profile_field",),
        contexts=("html_body",),
        payload_patterns=("free-text profile input",),
        verification_patterns=("stored marker executes on read",),
    )
    base.update(overrides)
    return _claim(**base)


# ------------------------------------------------------------------
# Security boundary: no external authority
# ------------------------------------------------------------------


class NoExternalAuthorityTests(unittest.TestCase):
    def test_module_has_no_llm_dependency(self):
        names = set(projector.__dict__)
        for forbidden in (
            "LLMProvider",
            "OpenRouterProvider",
            "AvalaiProvider",
            "openrouter",
            "avalai",
            "complete",
            "generate",
        ):
            self.assertNotIn(forbidden, names)

    def test_module_has_no_network_dependency(self):
        names = set(projector.__dict__)
        for forbidden in (
            "requests",
            "urllib",
            "urllib3",
            "httpx",
            "socket",
            "http",
        ):
            self.assertNotIn(forbidden, names)

    def test_module_has_no_execution_dependency(self):
        names = set(projector.__dict__)
        for forbidden in (
            "subprocess",
            "os",
            "sys",
            "shutil",
            "eval",
            "exec",
        ):
            self.assertNotIn(forbidden, names)

    def test_module_does_not_touch_version_comparator(self):
        names = set(projector.__dict__)
        self.assertNotIn("correlator", names)
        self.assertNotIn("compare_version", names)
        self.assertNotIn("version", names)

    def test_projection_runs_with_network_disabled(self):
        import socket

        original = socket.socket

        def _blocked(*args, **kwargs):
            raise AssertionError("network access attempted")

        socket.socket = _blocked
        try:
            result = project_claims([_grounded(_attack_claim())])
        finally:
            socket.socket = original
        self.assertEqual(len(result.patterns), 2)

    def test_no_verdict_fields_anywhere(self):
        patterns = project_claim(_grounded(_attack_claim()))
        for pattern in patterns:
            fields = set(type(pattern).model_fields)
            for forbidden in (
                "verdict",
                "confirmed",
                "verified",
                "not_vulnerable",
                "finding_status",
                "evidence",
            ):
                self.assertNotIn(forbidden, fields)
            self.assertNotIn(
                pattern.status, ("CONFIRMED", "VERIFIED", "NOT_VULNERABLE")
            )

    def test_no_scope_fields_anywhere(self):
        patterns = project_claim(_grounded(_attack_claim()))
        for pattern in patterns:
            blob = pattern.model_dump(mode="json")
            self.assertNotIn("scope_allowed", blob)
            self.assertNotIn("allow_scope", blob)

    def test_no_target_match_fields_anywhere(self):
        patterns = project_claim(_grounded(_attack_claim()))
        for pattern in patterns:
            blob = pattern.model_dump(mode="json")
            self.assertNotIn("target_affected", blob)
            self.assertNotIn("match_score", blob)

    def test_no_execution_fields_anywhere(self):
        patterns = project_claim(_grounded(_attack_claim()))
        for pattern in patterns:
            blob = pattern.model_dump(mode="json")
            for forbidden in (
                "command",
                "subprocess",
                "shell",
                "tool_call",
                "callback",
                "plugin",
            ):
                self.assertNotIn(forbidden, blob)


# ------------------------------------------------------------------
# Input trust boundary
# ------------------------------------------------------------------


class InputTrustBoundaryTests(unittest.TestCase):
    def test_raw_text_cannot_become_pattern(self):
        with self.assertRaises(TypeError):
            project_claim("FooCMS has security issues")
        with self.assertRaises(TypeError):
            project_claim({"techniques": ["xss"]})

    def test_raw_batch_cannot_become_pattern(self):
        with self.assertRaises(TypeError):
            project_claims(["raw research text"])

    def test_source_document_cannot_become_pattern(self):
        from ai.schemas.ingestion import SourceDocument

        source = SourceDocument(
            title="t",
            source_url="https://example.test/x",
            source_type="writeup",
            content="FooCMS has security issues",
        )
        with self.assertRaises(TypeError):
            project_claim(source)

    def test_research_document_cannot_become_pattern(self):
        from ai.schemas.source import ResearchDocument

        document = ResearchDocument(
            source_type="cve",
            title="CVE-2026-1234",
            content="FooCMS 4.2.1 is affected",
            products=["FooCMS"],
        )
        with self.assertRaises(TypeError):
            project_claim(document)

    def test_model_inference_claim_rejected_at_boundary(self):
        claim = _claim(evidence_class="MODEL_INFERENCE", confidence=0.3)
        with self.assertRaises(ValueError):
            _grounded(claim)

    def test_unverified_store_claim_rejected_at_boundary(self):
        claim = KnowledgeSourceClaims(
            technologies=["FooCMS"],
            evidence_quality="UNVERIFIED",
            confidence=0.2,
        )
        with self.assertRaises(ValueError):
            _grounded(claim)

    def test_unknown_quality_store_claim_rejected_at_boundary(self):
        claim = KnowledgeSourceClaims(technologies=["FooCMS"])
        self.assertEqual(claim.evidence_quality, "UNKNOWN")
        with self.assertRaises(ValueError):
            _grounded(claim)

    def test_missing_claim_id_rejected(self):
        with self.assertRaises(ValueError):
            _grounded(_claim(), claim_id="")
        with self.assertRaises(ValueError):
            _grounded(_claim(), claim_id="not-a-claim-id")

    def test_malformed_provenance_ids_rejected(self):
        with self.assertRaises(ValueError):
            _grounded(_claim(), knowledge_id="kb-nope")
        with self.assertRaises(ValueError):
            _grounded(_claim(), source_id="src-nope")
        with self.assertRaises(ValueError):
            _grounded(_claim(), research_hash="short")

    def test_claim_without_snippets_rejected(self):
        claim = _claim()
        bare = claim.model_copy(update={"evidence_snippets": []})
        with self.assertRaises(ValueError):
            _grounded(bare)


# ------------------------------------------------------------------
# Basic projection
# ------------------------------------------------------------------


class BasicProjectionTests(unittest.TestCase):
    def test_product_claim_yields_vulnerability_pattern(self):
        patterns = project_claim(_grounded(_claim()))
        self.assertEqual(len(patterns), 1)
        pattern = patterns[0]
        self.assertIsInstance(pattern, VulnerabilityPattern)
        self.assertEqual(
            [product.product for product in pattern.facts.products],
            ["FooCMS"],
        )

    def test_attack_technique_claim_yields_attack_pattern(self):
        patterns = project_claim(_grounded(_attack_claim()))
        kinds = {type(pattern) for pattern in patterns}
        self.assertEqual(
            kinds, {VulnerabilityPattern, AttackPattern}
        )
        attack = next(
            item
            for item in patterns
            if isinstance(item, AttackPattern)
        )
        self.assertEqual(
            attack.facts.technique, "stored_xss_via_profile_field"
        )
        self.assertIn("html_body", attack.facts.sink_characteristics)
        self.assertIn(
            "free-text profile input",
            attack.facts.input_characteristics,
        )

    def test_insufficient_claim_yields_no_pattern(self):
        claim = _claim(
            title="vague security concern",
            summary="this vulnerability may be exploitable",
            technologies=(),
            techniques=(),
            snippet="this vulnerability may be exploitable",
        )
        result = project_claims([_grounded(claim)])
        self.assertEqual(result.patterns, ())
        self.assertEqual(len(result.skipped), 1)
        self.assertEqual(
            result.skipped[0].reason, "insufficient_information"
        )

    def test_technique_without_sink_or_observable_yields_no_attack(
        self,
    ):
        claim = _claim(
            technologies=(),
            techniques=("some_technique",),
            snippet="some_technique",
        )
        patterns = project_claim(_grounded(claim))
        self.assertEqual(patterns, [])

    def test_strongly_implied_claim_projects(self):
        claim = _claim(
            evidence_class="STRONGLY_IMPLIED", confidence=0.7
        )
        patterns = project_claim(_grounded(claim))
        self.assertEqual(len(patterns), 1)
        self.assertIsInstance(patterns[0], VulnerabilityPattern)

    def test_store_claim_form_projects(self):
        claim = KnowledgeSourceClaims(
            title="FooCMS stored XSS",
            summary="FooCMS renders the bio field without encoding",
            technologies=["FooCMS"],
            techniques=["stored_xss_via_profile_field"],
            contexts=["html_body"],
            verification_patterns=["stored marker executes on read"],
            evidence_quality="HIGH_CONFIDENCE",
            confidence=0.9,
        )
        grounded = _grounded(claim)
        patterns = project_claim(grounded)
        self.assertEqual(len(patterns), 2)
        self.assertEqual(
            patterns[0].provenance.claim_ids, [_CLM]
        )

    def test_multiple_techniques_yield_one_pattern_each(self):
        claim = _attack_claim(
            techniques=("technique_b", "technique_a"),
        )
        patterns = project_claim(_grounded(claim))
        attacks = [
            item
            for item in patterns
            if isinstance(item, AttackPattern)
        ]
        self.assertEqual(len(attacks), 2)
        self.assertEqual(
            sorted(item.facts.technique for item in attacks),
            ["technique_a", "technique_b"],
        )


# ------------------------------------------------------------------
# Provenance
# ------------------------------------------------------------------


class ProvenanceTests(unittest.TestCase):
    def test_all_provenance_ids_preserved(self):
        patterns = project_claim(_grounded(_attack_claim()))
        for pattern in patterns:
            self.assertEqual(pattern.provenance.claim_ids, [_CLM])
            self.assertEqual(pattern.provenance.knowledge_ids, [_KB])
            self.assertEqual(pattern.provenance.source_ids, [_SRC])
            self.assertEqual(pattern.provenance.research_hashes, [_HASH])

    def test_optional_provenance_may_be_absent(self):
        grounded = _grounded(
            _claim(),
            knowledge_id=None,
            source_id=None,
            research_hash=None,
        )
        patterns = project_claim(grounded)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].provenance.claim_ids, [_CLM])
        self.assertEqual(patterns[0].provenance.knowledge_ids, [])

    def test_duplicate_claims_normalize_provenance(self):
        grounded = _grounded(_claim())
        result = project_claims([grounded, grounded])
        self.assertEqual(len(result.patterns), 1)
        self.assertEqual(
            result.patterns[0].provenance.claim_ids, [_CLM]
        )
        self.assertEqual(result.skipped, ())

    def test_multi_claim_merge_combines_provenance(self):
        first = _grounded(_claim(), claim_id=_CLM)
        second = _grounded(_claim(), claim_id=_CLM2)
        result = project_claims([first, second])
        self.assertEqual(len(result.patterns), 1)
        self.assertEqual(
            result.patterns[0].provenance.claim_ids,
            sorted([_CLM, _CLM2]),
        )

    def test_same_semantic_different_provenance_keys_differ(self):
        first = project_claims([_grounded(_claim(), claim_id=_CLM)])
        second = project_claims([_grounded(_claim(), claim_id=_CLM2)])
        self.assertEqual(
            first.patterns[0].semantic_key,
            second.patterns[0].semantic_key,
        )
        self.assertNotEqual(
            first.patterns[0].pattern_id,
            second.patterns[0].pattern_id,
        )


# ------------------------------------------------------------------
# Determinism and order independence
# ------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    def test_same_input_same_output(self):
        first = project_claim(_grounded(_attack_claim()))
        second = project_claim(_grounded(_attack_claim()))
        self.assertEqual(
            [item.pattern_id for item in first],
            [item.pattern_id for item in second],
        )
        self.assertEqual(
            [item.idempotency_key for item in first],
            [item.idempotency_key for item in second],
        )

    def test_input_order_does_not_change_output(self):
        first = _grounded(_attack_claim(), claim_id=_CLM)
        second = _grounded(
            _claim(technologies=("BarCMS",)),
            claim_id=_CLM2,
        )
        forward = project_claims([first, second])
        backward = project_claims([second, first])
        self.assertEqual(
            [item.pattern_id for item in forward.patterns],
            [item.pattern_id for item in backward.patterns],
        )
        self.assertEqual(
            [item.semantic_key for item in forward.patterns],
            [item.semantic_key for item in backward.patterns],
        )

    def test_list_order_inside_claim_does_not_change_output(self):
        claim_a = _attack_claim(
            technologies=("FooCMS", "BarCMS"),
            techniques=("technique_b", "technique_a"),
        )
        claim_b = _attack_claim(
            technologies=("BarCMS", "FooCMS"),
            techniques=("technique_a", "technique_b"),
        )
        first = project_claims([_grounded(claim_a)])
        second = project_claims([_grounded(claim_b)])
        self.assertEqual(
            sorted(item.semantic_key for item in first.patterns),
            sorted(item.semantic_key for item in second.patterns),
        )

    def test_repeated_claim_produces_no_semantic_duplicate(self):
        grounded = _grounded(_attack_claim())
        result = project_claims([grounded, grounded, grounded])
        semantics = [
            item.semantic_key for item in result.patterns
        ]
        self.assertEqual(len(semantics), len(set(semantics)))

    def test_one_bad_claim_does_not_poison_batch(self):
        good = _grounded(_claim(), claim_id=_CLM)
        bad_claim = _claim(
            technologies=("<script>alert(1)</script>",),
        )
        bad = GroundedClaim(
            claim=bad_claim,
            claim_id=_CLM2,
            knowledge_id=_KB,
            source_id=_SRC,
            research_hash=_HASH2,
        )
        result = project_claims([good, bad])
        self.assertEqual(len(result.patterns), 1)
        self.assertEqual(
            result.patterns[0].provenance.claim_ids, [_CLM]
        )
        self.assertEqual(len(result.skipped), 1)
        self.assertEqual(result.skipped[0].claim_id, _CLM2)


# ------------------------------------------------------------------
# Trust: interpretation never becomes fact
# ------------------------------------------------------------------


class TrustBoundaryTests(unittest.TestCase):
    def test_rationale_stays_in_interpretation(self):
        claim = _claim(
            rationale="Likely stored XSS with high impact",
            technologies=("FooCMS",),
        )
        patterns = project_claim(_grounded(claim))
        pattern = patterns[0]
        self.assertIn(
            "Likely stored XSS", pattern.interpretation.rationale
        )
        facts_blob = pattern.facts.model_dump_json()
        self.assertNotIn("Likely stored XSS", facts_blob)

    def test_confidence_stays_in_interpretation(self):
        claim = _claim(confidence=0.85)
        patterns = project_claim(_grounded(claim))
        self.assertEqual(
            patterns[0].interpretation.confidence, 0.85
        )
        facts_blob = patterns[0].facts.model_dump_json()
        self.assertNotIn("0.85", facts_blob)

    def test_verdict_wording_does_not_escalate(self):
        claim = _claim(
            summary="confirmed critical vulnerability, verified exploit",
            snippet="confirmed critical vulnerability",
        )
        patterns = project_claim(_grounded(claim))
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].status, "ACTIVE")

    def test_unprojectable_metadata_never_reaches_facts(self):
        claim = _claim(
            xss_types=("reflected",),
            wafs=("Strict WAF",),
            tags=("crowded-priority",),
        )
        patterns = project_claim(_grounded(claim))
        facts_blob = patterns[0].facts.model_dump_json()
        self.assertNotIn("Strict WAF", facts_blob)
        self.assertNotIn("crowded-priority", facts_blob)
        hints = patterns[0].interpretation.classification_hints
        self.assertTrue(
            any("Strict WAF" in hint for hint in hints)
        )


# ------------------------------------------------------------------
# Versions are represented, never compared or guessed
# ------------------------------------------------------------------


class VersionHandlingTests(unittest.TestCase):
    def test_no_version_constraints_invented(self):
        patterns = project_claim(_grounded(_claim()))
        pattern = patterns[0]
        self.assertIsInstance(pattern, VulnerabilityPattern)
        self.assertEqual(pattern.facts.version_constraints, [])

    def test_version_like_technology_preserved_verbatim(self):
        claim = _claim(technologies=("FooCMS 4.2.1",))
        patterns = project_claim(_grounded(claim))
        self.assertEqual(
            patterns[0].facts.products[0].product, "FooCMS 4.2.1"
        )
        self.assertEqual(
            patterns[0].facts.version_constraints, []
        )


# ------------------------------------------------------------------
# Attack surface: constrained, non-executable
# ------------------------------------------------------------------


class AttackSurfaceTests(unittest.TestCase):
    def test_no_executable_surface_fields(self):
        patterns = project_claim(_grounded(_attack_claim()))
        for pattern in patterns:
            if isinstance(pattern, VulnerabilityPattern):
                self.assertEqual(pattern.facts.attack_surface, [])

    def test_newline_in_label_rejected(self):
        claim = _attack_claim(techniques=("bad\ntechnique",))
        result = project_claims([_grounded(claim)])
        self.assertEqual(result.patterns, ())
        self.assertEqual(len(result.skipped), 1)

    def test_url_like_label_creates_no_url_field(self):
        claim = _claim(
            technologies=("https://evil.example/callback",),
        )
        patterns = project_claim(_grounded(claim))
        self.assertEqual(len(patterns), 1)
        blob = patterns[0].model_dump(mode="json")
        self.assertNotIn("callback", blob["facts"])
        self.assertNotIn("url", str(type(blob)).lower())


# ------------------------------------------------------------------
# Malicious inputs fail closed
# ------------------------------------------------------------------


class MaliciousInputTests(unittest.TestCase):
    def _skipped(self, **claim_kwargs) -> object:
        claim = _attack_claim(**claim_kwargs)
        return project_claims([_grounded(claim)])

    def test_script_tag_rejected(self):
        result = self._skipped(techniques=("<script>alert(1)</script>",))
        self.assertEqual(result.patterns, ())
        self.assertEqual(result.skipped[0].reason, "forbidden_content")

    def test_javascript_url_rejected(self):
        # NOTE: verification_patterns with executable constructs are
        # already rejected by the ingestion schema itself
        # (IngestionError); the projector must independently reject
        # the same construct arriving through a non-scanned field.
        result = self._skipped(
            techniques=("x javascript:alert(1)",),
        )
        self.assertEqual(result.patterns, ())
        self.assertEqual(result.skipped[0].reason, "forbidden_content")

    def test_eval_construct_rejected(self):
        result = self._skipped(techniques=("eval(payload)",))
        self.assertEqual(result.patterns, ())
        self.assertEqual(result.skipped[0].reason, "forbidden_content")

    def test_event_handler_rejected(self):
        result = self._skipped(contexts=("x onload=evil",))
        self.assertEqual(result.patterns, ())
        self.assertEqual(result.skipped[0].reason, "forbidden_content")

    def test_inert_security_words_carry_no_authority(self):
        for word in (
            "confirmed",
            "verified",
            "verdict",
            "evidence",
            "scope_allowed",
            "target_affected",
            "subprocess",
            "tool_call",
            "exec",
            "shell",
            "command",
        ):
            claim = _attack_claim(techniques=(word,))
            result = project_claims([_grounded(claim)])
            for pattern in result.patterns:
                self.assertEqual(pattern.status, "ACTIVE")
                blob = pattern.model_dump(mode="json")
                self.assertNotIn("scope_allowed", blob)
                self.assertNotIn("target_affected", blob)
                self.assertNotIn("verdict", blob)
                self.assertNotIn("command", blob)
                self.assertNotIn("tool_call", blob)

    def test_forbidden_title_rejected(self):
        claim = _claim(title="<script>alert(1)</script>")
        result = project_claims([_grounded(claim)])
        self.assertEqual(result.patterns, ())
        self.assertEqual(len(result.skipped), 1)


# ------------------------------------------------------------------
# Phase 2A validation remains fail-closed
# ------------------------------------------------------------------


class FailClosedTests(unittest.TestCase):
    def test_factory_validation_errors_propagate(self):
        from ai.schemas.research_pattern import (
            build_vulnerability_pattern,
        )
        from ai.schemas.hypothesis import ResearchProvenance

        provenance = ResearchProvenance(claim_ids=[_CLM])
        with self.assertRaises(ValidationError):
            build_vulnerability_pattern(
                pattern_kind="PRODUCT_VULNERABILITY",
                title="t",
                description="d",
                facts={},
                provenance=provenance,
            )

    def test_tampered_pattern_identity_rejected(self):
        patterns = project_claim(_grounded(_claim()))
        pattern = patterns[0]
        with self.assertRaises(ValidationError):
            VulnerabilityPattern.model_validate(
                {
                    **pattern.model_dump(mode="json"),
                    "semantic_key": "0" * 64,
                }
            )

    def test_empty_batch_returns_empty_result(self):
        result = project_claims([])
        self.assertEqual(result.patterns, ())
        self.assertEqual(result.skipped, ())


if __name__ == "__main__":
    unittest.main()
