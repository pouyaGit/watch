"""EPIC6 Part 3: specialist contracts, capability matching, opinions."""

from __future__ import annotations

import unittest

from aec.specialists.models import SpecialistProfile
from aec.specialists.registry import (
    EVIDENCE_LEVELS, default_registry, lookup, match_category)
from aec.specialists.analysis import (
    OPINION_OUTCOMES, AnalysisRefusal, Disagreement, Opinion,
    analyze, detect_disagreement)

EXPECTED_ROLES = (
    "authorization-researcher",
    "input-researcher",
    "server-researcher",
    "technology-researcher",
    "general-researcher",
)


def evidence(coverage: str, **overrides):
    item = {"coverage": coverage, "fields": ("x",)}
    item.update(overrides)
    return item


class TestRegistry(unittest.TestCase):
    def test_five_roles(self):
        registry = default_registry()
        self.assertEqual(
            tuple(profile.role for profile in registry), EXPECTED_ROLES)

    def test_no_role_can_confirm(self):
        for profile in default_registry():
            self.assertNotIn("confirmed", profile.output_schema)

    def test_every_profile_declares_contract(self):
        for profile in default_registry():
            self.assertTrue(profile.capabilities)
            self.assertTrue(profile.accepted_inputs)
            self.assertTrue(profile.output_schema)
            self.assertTrue(profile.confidence_levels)
            self.assertTrue(profile.refusals)
            self.assertTrue(profile.fallback)

    def test_output_schema_uniform(self):
        schemas = {profile.output_schema for profile in default_registry()}
        self.assertEqual(len(schemas), 1)

    def test_evidence_levels_exact(self):
        self.assertEqual(EVIDENCE_LEVELS, ("NONE", "PARTIAL", "READY"))

    def test_lookup_known_role(self):
        profile = lookup(default_registry(), "input-researcher")
        self.assertEqual(profile.role, "input-researcher")

    def test_lookup_unknown_role_raises(self):
        with self.assertRaises(ValueError):
            lookup(default_registry(), "exploit-researcher")

    def test_match_category_specific(self):
        registry = default_registry()
        self.assertEqual(
            match_category(registry, "IDOR_CANDIDATE").role,
            "authorization-researcher")
        self.assertEqual(
            match_category(registry, "XSS_CANDIDATE").role,
            "input-researcher")
        self.assertEqual(
            match_category(registry, "SSRF_CANDIDATE").role,
            "server-researcher")
        self.assertEqual(
            match_category(registry, "TECH_CANDIDATE").role,
            "technology-researcher")

    def test_match_category_unknown_falls_to_generalist(self):
        registry = default_registry()
        self.assertEqual(
            match_category(registry, "UNKNOWN_CATEGORY").role,
            "general-researcher")

    def test_generalist_accepts_any(self):
        generalist = lookup(default_registry(), "general-researcher")
        self.assertTrue(generalist.can_handle("EVERYTHING"))

    def test_can_handle_respects_categories(self):
        profile = lookup(default_registry(), "input-researcher")
        self.assertTrue(profile.can_handle("XSS_CANDIDATE"))
        self.assertFalse(profile.can_handle("SSRF_CANDIDATE"))

    def test_required_evidence_partial_for_specialists(self):
        registry = default_registry()
        for profile in registry:
            if profile.role != "general-researcher":
                self.assertEqual(profile.required_evidence, "PARTIAL")

    def test_generalist_requires_none(self):
        generalist = lookup(default_registry(), "general-researcher")
        self.assertEqual(generalist.required_evidence, "NONE")

    def test_refusals_closed(self):
        allowed = {"UNSUPPORTED_INPUT", "BELOW_EVIDENCE_LEVEL"}
        for profile in default_registry():
            self.assertLessEqual(set(profile.refusals), allowed)

    def test_fallbacks_are_observation_dependent(self):
        registry = default_registry()
        for profile in registry:
            if profile.role != "general-researcher":
                self.assertEqual(profile.fallback, "REQUIRES_OBSERVATION")

    def test_profile_to_dict(self):
        profile = lookup(default_registry(), "server-researcher")
        document = profile.to_dict()
        self.assertEqual(document["role"], "server-researcher")
        self.assertIn("server-surface-review", document["capabilities"])


class TestOpinions(unittest.TestCase):
    def test_outcomes_closed(self):
        self.assertEqual(OPINION_OUTCOMES, (
            "NO_SIGNAL", "INSUFFICIENT_EVIDENCE", "REQUIRES_OBSERVATION",
            "POTENTIAL", "REVIEW_REQUIRED"))

    def test_no_confirmed_outcome_capable(self):
        self.assertNotIn("CONFIRMED", OPINION_OUTCOMES)

    def test_insufficient_evidence_when_below_level(self):
        profile = lookup(default_registry(), "input-researcher")
        opinion = analyze(profile, {
            "job_id": "job-1", "category": "XSS_CANDIDATE",
            "evidence_level": "NONE",
        }, [evidence("PARTIAL")])
        self.assertEqual(opinion.outcome, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(opinion.confidence, "high")

    def test_no_records_uses_fallback(self):
        profile = lookup(default_registry(), "input-researcher")
        opinion = analyze(profile, {
            "job_id": "job-1", "category": "XSS_CANDIDATE",
            "evidence_level": "PARTIAL",
        }, [])
        self.assertEqual(opinion.outcome, "REQUIRES_OBSERVATION")

    def test_complete_coverage_review_required(self):
        profile = lookup(default_registry(), "input-researcher")
        opinion = analyze(profile, {
            "job_id": "job-1", "category": "XSS_CANDIDATE",
            "evidence_level": "PARTIAL",
        }, [evidence("COMPLETE")])
        self.assertEqual(opinion.outcome, "REVIEW_REQUIRED")

    def test_partial_coverage_potential(self):
        profile = lookup(default_registry(), "input-researcher")
        opinion = analyze(profile, {
            "job_id": "job-1", "category": "XSS_CANDIDATE",
            "evidence_level": "PARTIAL",
        }, [evidence("PARTIAL")])
        self.assertEqual(opinion.outcome, "POTENTIAL")
        self.assertEqual(opinion.confidence, "low")

    def test_no_signal_on_empty_coverage(self):
        profile = lookup(default_registry(), "general-researcher")
        opinion = analyze(profile, {
            "job_id": "job-1", "category": "MISC",
            "evidence_level": "NONE",
        }, [evidence("")])
        self.assertEqual(opinion.outcome, "NO_SIGNAL")

    def test_opinion_fields(self):
        profile = lookup(default_registry(), "input-researcher")
        opinion = analyze(profile, {
            "job_id": "job-9", "category": "XSS_CANDIDATE",
            "evidence_level": "PARTIAL",
        }, [evidence("COMPLETE")])
        self.assertEqual(opinion.job_id, "job-9")
        self.assertEqual(opinion.role, "input-researcher")
        self.assertTrue(opinion.rationale)

    def test_unsupported_category_refused(self):
        profile = lookup(default_registry(), "input-researcher")
        with self.assertRaises(AnalysisRefusal):
            analyze(profile, {
                "job_id": "job-1", "category": "SSRF_CANDIDATE",
                "evidence_level": "PARTIAL",
            }, [evidence("COMPLETE")])

    def test_non_mapping_job_refused(self):
        profile = lookup(default_registry(), "general-researcher")
        with self.assertRaises(AnalysisRefusal):
            analyze(profile, "not-a-job", [])

    def test_missing_job_id_refused(self):
        profile = lookup(default_registry(), "general-researcher")
        with self.assertRaises(AnalysisRefusal):
            analyze(profile, {"category": "MISC"}, [])

    def test_missing_category_refused(self):
        profile = lookup(default_registry(), "general-researcher")
        with self.assertRaises(AnalysisRefusal):
            analyze(profile, {"job_id": "job-1"}, [])

    def test_opinion_to_dict(self):
        profile = lookup(default_registry(), "input-researcher")
        opinion = analyze(profile, {
            "job_id": "job-1", "category": "XSS_CANDIDATE",
            "evidence_level": "PARTIAL",
        }, [evidence("COMPLETE")])
        document = opinion.to_dict()
        self.assertEqual(sorted(document), [
            "confidence", "job_id", "outcome", "rationale", "role"])

    def test_opinion_never_upgrades(self):
        profile = lookup(default_registry(), "input-researcher")
        for coverage in ("COMPLETE", "PARTIAL", ""):
            opinion = analyze(profile, {
                "job_id": "job-1", "category": "XSS_CANDIDATE",
                "evidence_level": "PARTIAL",
            }, [evidence(coverage)])
            self.assertNotIn(opinion.outcome, ("CONFIRMED", "CONFIRMED_VULN"))


class TestDisagreement(unittest.TestCase):
    def opinions(self, *outcomes):
        result = []
        for index, outcome in enumerate(outcomes):
            result.append(Opinion(
                job_id="job-1", role=f"r{index}", outcome=outcome,
                confidence="medium", rationale="test"))
        return result

    def test_agreement_no_review(self):
        comparison = detect_disagreement([
            Opinion("job-1", "a", "POTENTIAL", "low", "x"),
            Opinion("job-1", "b", "POTENTIAL", "low", "x")])
        self.assertFalse(comparison.disagree)
        self.assertFalse(comparison.review_required)

    def test_disagreement_forces_review(self):
        comparison = detect_disagreement(self.opinions(
            "REVIEW_REQUIRED", "NO_SIGNAL"))
        self.assertTrue(comparison.disagree)
        self.assertTrue(comparison.review_required)

    def test_empty_opinions_refused(self):
        with self.assertRaises(AnalysisRefusal):
            detect_disagreement([])

    def test_disagreement_fields(self):
        comparison = detect_disagreement(self.opinions(
            "POTENTIAL", "REQUIRES_OBSERVATION"))
        self.assertEqual(comparison.job_id, "job-1")
        self.assertEqual(
            comparison.outcomes, ("POTENTIAL", "REQUIRES_OBSERVATION"))

    def test_disagreement_to_dict(self):
        comparison = detect_disagreement(self.opinions(
            "POTENTIAL", "REQUIRES_OBSERVATION"))
        self.assertEqual(sorted(comparison.to_dict()), [
            "disagree", "job_id", "outcomes", "review_required"])


if __name__ == "__main__":
    unittest.main()