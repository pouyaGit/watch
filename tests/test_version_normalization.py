"""tests/test_version_normalization.py — Stage R31.7 tests.

Deterministic, offline tests for the version normalization/confidence layer:

- exact/leading-v/whitespace/leading-zero parsing with precision preservation
- conservative comparisons (MATCH / NO_MATCH / INDETERMINATE)
- inclusive/exclusive bounds, ranges, wildcards, prefixes
- unknown prose stays UNKNOWN and preserves the raw value
- bounded, deterministic, privacy-safe evidence
- adapter integration is additive and cannot promote confidence
- R30.1/R30.3/R31.5/R31.6 remain unchanged

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence.
"""
import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.knowledge import asset_cve_matching as acm_engine
from ai.knowledge import component_identity
from ai.knowledge import version_component_association as vca
from ai.knowledge import version_normalization as vn
from ai.knowledge.relevance import AssetRecord
from ai.schemas.observed_inventory import (
    EVIDENCE_PROVENANCE_RULE_VERSION,
    inventory_id_for,
)
from backend import asset_cve_matching as acm

CVE = "CVE-2026-78203"


class TestExactParsing(unittest.TestCase):
    def test_exact_versions(self):
        parsed = vn.parse_version("1.2.3")
        self.assertEqual(parsed.version_kind, vn.KIND_EXACT)
        self.assertEqual(parsed.normalized_version, "1.2.3")
        self.assertEqual(parsed.precision, 3)
        self.assertEqual(parsed.components, (1, 2, 3))
        self.assertEqual(parsed.evidence_class, vn.CLASS_EXACT_OBSERVED)
        self.assertEqual(parsed.resolution_method, vn.METHOD_EXACT_PARSE)

    def test_leading_v(self):
        for raw, expected in (("v1.2.3", "1.2.3"), ("V1.2", "1.2")):
            with self.subTest(raw=raw):
                parsed = vn.parse_version(raw)
                self.assertEqual(parsed.version_kind, vn.KIND_EXACT)
                self.assertEqual(parsed.normalized_version, expected)
                self.assertEqual(
                    parsed.evidence_class, vn.CLASS_NORMALIZED_EXACT
                )

    def test_whitespace(self):
        parsed = vn.parse_version(" 1.2.3 ")
        self.assertEqual(parsed.version_kind, vn.KIND_EXACT)
        self.assertEqual(parsed.normalized_version, "1.2.3")

    def test_leading_zeros_are_normalized_without_padding(self):
        parsed = vn.parse_version("01.0")
        self.assertEqual(parsed.version_kind, vn.KIND_EXACT)
        self.assertEqual(parsed.normalized_version, "1.0")
        self.assertEqual(parsed.precision, 2)
        self.assertEqual(parsed.components, (1, 0))

    def test_precision_preserved(self):
        self.assertEqual(vn.parse_version("1").precision, 1)
        self.assertEqual(vn.parse_version("1.2").precision, 2)
        self.assertEqual(vn.parse_version("1.2.3").precision, 3)
        # never padded, never conflated
        self.assertEqual(
            vn.parse_version("1.2").normalized_version, "1.2"
        )
        self.assertEqual(
            vn.parse_version("1.2.0").normalized_version, "1.2.0"
        )


class TestComparison(unittest.TestCase):
    def test_numeric_order(self):
        self.assertEqual(vn.compare_order("1.2.3", "1.2.3"), 0)
        self.assertEqual(vn.compare_order("1.2.3", "1.2.2"), 1)
        self.assertEqual(vn.compare_order("1.2.3", "1.3.0"), -1)

    def test_equality_comparison(self):
        self.assertEqual(
            vn.compare_versions("1.2.3", "1.2.3"), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.compare_versions("1.2.3", "1.2.2"), vn.COMPARISON_NO_MATCH
        )

    def test_different_precision_indeterminate(self):
        self.assertEqual(
            vn.compare_versions("1.2", "1.2.0"),
            vn.COMPARISON_INDETERMINATE,
        )
        self.assertEqual(
            vn.compare_versions("1", "1.0"), vn.COMPARISON_INDETERMINATE
        )
        # a non-zero extra component is a real difference
        self.assertEqual(
            vn.compare_versions("1.2.3", "1.2"), vn.COMPARISON_NO_MATCH
        )

    def test_explicit_precision_expansion_mode(self):
        self.assertEqual(
            vn.compare_versions(
                "1.2", "1.2.0", allow_precision_expansion=True
            ),
            vn.COMPARISON_MATCH,
        )

    def test_non_concrete_is_indeterminate(self):
        self.assertEqual(
            vn.compare_versions("1.x", "1.2.3"),
            vn.COMPARISON_INDETERMINATE,
        )
        self.assertEqual(
            vn.compare_versions("latest", "1.2.3"),
            vn.COMPARISON_INDETERMINATE,
        )


class TestBounds(unittest.TestCase):
    def test_upper_bounds(self):
        self.assertEqual(
            vn.matches_constraint("0.9", "<=1.0"), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.0", "<=1.0"), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.1", "<=1.0"), vn.COMPARISON_NO_MATCH
        )

    def test_lower_bounds(self):
        self.assertEqual(
            vn.matches_constraint("1.2", ">=1.0"), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.0", ">=1.0"), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("0.9", ">=1.0"), vn.COMPARISON_NO_MATCH
        )

    def test_inclusive_exclusive(self):
        self.assertEqual(
            vn.matches_constraint("1.2", "<1.2"), vn.COMPARISON_NO_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.2", "<=1.2"), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.2", ">1.2"), vn.COMPARISON_NO_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.2", ">=1.2"), vn.COMPARISON_MATCH
        )

    def test_precision_ambiguous_bound(self):
        # 1 vs 1.0 cannot be compared safely.
        self.assertEqual(
            vn.matches_constraint("1", "<=1.0"),
            vn.COMPARISON_INDETERMINATE,
        )

    def test_prose_bounds(self):
        before = vn.parse_version("before 1.2")
        self.assertEqual(before.version_kind, vn.KIND_UPPER_BOUND)
        self.assertFalse(before.upper_inclusive)
        self.assertEqual(
            vn.matches_constraint("1.1", before), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.2", before), vn.COMPARISON_NO_MATCH
        )
        upto = vn.parse_version("up to 1.4")
        self.assertEqual(upto.version_kind, vn.KIND_UPPER_BOUND)
        self.assertTrue(upto.upper_inclusive)
        self.assertEqual(
            vn.matches_constraint("1.4", upto), vn.COMPARISON_MATCH
        )


class TestRanges(unittest.TestCase):
    def test_hyphen_range(self):
        parsed = vn.parse_version("1.0 - 1.5")
        self.assertEqual(parsed.version_kind, vn.KIND_RANGE)
        self.assertEqual(parsed.normalized_version, "1.0 - 1.5")
        self.assertEqual(
            vn.matches_constraint("1.0", parsed), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.5", parsed), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("2.1", parsed), vn.COMPARISON_NO_MATCH
        )

    def test_en_dash_range(self):
        parsed = vn.parse_version("1.0\u20131.5")
        self.assertEqual(parsed.version_kind, vn.KIND_RANGE)
        self.assertEqual(
            vn.matches_constraint("1.2", parsed), vn.COMPARISON_MATCH
        )

    def test_to_range(self):
        parsed = vn.parse_version("1.0 to 1.5")
        self.assertEqual(parsed.version_kind, vn.KIND_RANGE)
        self.assertEqual(
            vn.matches_constraint("1.4.9", parsed), vn.COMPARISON_MATCH
        )

    def test_reversed_range_is_unknown(self):
        parsed = vn.parse_version("2.0 - 1.0")
        self.assertEqual(parsed.version_kind, vn.KIND_UNKNOWN)

    def test_ascii_hyphen_without_spaces_is_not_a_range(self):
        parsed = vn.parse_version("1.0-1.5")
        self.assertEqual(parsed.version_kind, vn.KIND_UNKNOWN)


class TestWildcards(unittest.TestCase):
    def test_major_wildcard(self):
        parsed = vn.parse_version("1.x")
        self.assertEqual(parsed.version_kind, vn.KIND_WILDCARD)
        self.assertEqual(parsed.wildcard_prefix, (1,))
        self.assertEqual(
            vn.matches_constraint("1.2.3", parsed), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.0", parsed), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("2.0", parsed), vn.COMPARISON_NO_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("10.0", parsed), vn.COMPARISON_NO_MATCH
        )

    def test_minor_wildcard(self):
        parsed = vn.parse_version("1.2.x")
        self.assertEqual(parsed.version_kind, vn.KIND_WILDCARD)
        self.assertEqual(parsed.wildcard_prefix, (1, 2))
        self.assertEqual(
            vn.matches_constraint("1.2.5", parsed), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.2", parsed), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.3.0", parsed), vn.COMPARISON_NO_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1", parsed),
            vn.COMPARISON_INDETERMINATE,
        )

    def test_star_component_and_prefix_forms(self):
        star = vn.parse_version("1.2.*")
        self.assertEqual(star.version_kind, vn.KIND_WILDCARD)
        self.assertEqual(
            vn.matches_constraint("1.2.9", star), vn.COMPARISON_MATCH
        )
        prefix = vn.parse_version("1.2*")
        self.assertEqual(prefix.version_kind, vn.KIND_PREFIX)
        self.assertEqual(
            vn.matches_constraint("1.2.9", prefix), vn.COMPARISON_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("1.20", prefix), vn.COMPARISON_NO_MATCH
        )

    def test_bare_wildcard_is_unknown(self):
        self.assertEqual(vn.parse_version("*").version_kind, vn.KIND_UNKNOWN)
        self.assertEqual(vn.parse_version("x").version_kind, vn.KIND_UNKNOWN)


class TestInvalidAndProse(unittest.TestCase):
    def test_invalid_versions(self):
        for raw in ("", "abc", "1..2", "1.2-", "1,2", "1.2.3.4.5.x.y"):
            with self.subTest(raw=raw):
                parsed = vn.parse_version(raw)
                self.assertEqual(parsed.version_kind, vn.KIND_UNKNOWN)
                self.assertEqual(parsed.normalized_version, "")

    def test_unknown_prose(self):
        for raw in ("latest", "affected versions", "all versions",
                    "not a version", "~1.2", ">= "):
            with self.subTest(raw=raw):
                parsed = vn.parse_version(raw)
                self.assertEqual(parsed.version_kind, vn.KIND_UNKNOWN)
                self.assertEqual(parsed.raw_version, raw.strip())

    def test_corpus_operator_with_parenthetical(self):
        parsed = vn.parse_version(
            "< 7.1.2 (confirmed against v7.1.1, commit 625a26b)"
        )
        self.assertEqual(parsed.version_kind, vn.KIND_UPPER_BOUND)
        self.assertEqual(parsed.upper_bound, (7, 1, 2))
        self.assertFalse(parsed.upper_inclusive)
        self.assertEqual(
            vn.matches_constraint("7.1.1", parsed), vn.COMPARISON_MATCH
        )


class TestDeterminism(unittest.TestCase):
    def test_repeatable_parse_and_evidence(self):
        for raw in ("1.2.3", "<=1.0", "1.2.x", "1.0 - 1.5", "latest"):
            first = vn.parse_version(raw).to_evidence()
            second = vn.parse_version(raw).to_evidence()
            self.assertEqual(first, second)

    def test_observed_permutation_does_not_change_rows(self):
        first = vn.build_version_evidence(
            cve_versions=["<=1.0"],
            observed_versions=["1.1", "0.9", "1.0"],
        )
        second = vn.build_version_evidence(
            cve_versions=["<=1.0"],
            observed_versions=["1.0", "1.1", "0.9"],
        )
        self.assertEqual(first["rows"], second["rows"])

    def test_evidence_is_json_serializable(self):
        evidence = vn.build_version_evidence(
            cve_versions=["<=1.0"], observed_versions=["0.9"]
        )
        json.dumps(evidence)


class TestEvidence(unittest.TestCase):
    def test_row_shape_and_reason(self):
        evidence = vn.build_version_evidence(
            cve_versions=["<=1.0"], observed_versions=["0.9"]
        )
        row = evidence["rows"][0]
        for key in (
            "cve_raw", "cve_normalized", "cve_kind", "cve_precision",
            "observed_raw", "observed_normalized", "observed_kind",
            "observed_precision", "comparison", "reason",
        ):
            self.assertIn(key, row)
        self.assertEqual(row["cve_kind"], vn.KIND_UPPER_BOUND)
        self.assertEqual(row["comparison"], vn.COMPARISON_MATCH)
        self.assertIn("0.9", row["reason"])

    def test_summary_counts(self):
        evidence = vn.build_version_evidence(
            cve_versions=["<=1.0", ">=2.0"],
            observed_versions=["0.9"],
        )
        self.assertEqual(evidence["counts"]["match"], 1)
        self.assertEqual(evidence["counts"]["no_match"], 1)
        self.assertEqual(evidence["counts"]["rows"], 2)
        self.assertEqual(
            evidence["rule_version"], vn.RULE_VERSION
        )

    def test_evidence_bounds(self):
        cve_versions = [f"1.{index}.0" for index in range(100)]
        observed_versions = [f"1.{index}.0" for index in range(100)]
        evidence = vn.build_version_evidence(
            cve_versions=cve_versions,
            observed_versions=observed_versions,
        )
        self.assertLessEqual(
            len(evidence["cve_versions"]), vn.MAX_VERSIONS
        )
        self.assertLessEqual(
            len(evidence["observed_versions"]), vn.MAX_VERSIONS
        )
        self.assertLessEqual(len(evidence["rows"]), vn.MAX_EVIDENCE_ROWS)
        for row in evidence["rows"]:
            self.assertLessEqual(len(row["reason"]), vn.MAX_VALUE_LEN)

    def test_privacy_url_like_versions_are_redacted(self):
        parsed = vn.parse_version("https://example.com/v1.2.3")
        self.assertEqual(parsed.version_kind, vn.KIND_UNKNOWN)
        self.assertEqual(parsed.raw_version, "[redacted]")
        blob = json.dumps(
            vn.build_version_evidence(
                cve_versions=["https://example.com/x"],
                observed_versions=["https://example.com/y"],
            )
        )
        for token in ("http://", "https://", "example.com"):
            self.assertNotIn(token, blob)

    def test_privacy_credential_like_versions_are_redacted(self):
        # Credentials, authorization headers, request data must never reach
        # version evidence (raw_version, evidence rows, summary fields).
        for raw in (
            "Authorization: Bearer xyz",
            "Bearer abc",
            "X-API-Key: secret",
            "x-api-key=abc123",
            "password=hunter2",
            "cookie: session=abc",
            "set-cookie: foo=bar",
        ):
            with self.subTest(raw=raw):
                parsed = vn.parse_version(raw)
                self.assertEqual(parsed.version_kind, vn.KIND_UNKNOWN)
                self.assertEqual(parsed.raw_version, "[redacted]")
        blob = json.dumps(
            vn.build_version_evidence(
                cve_versions=[
                    "Authorization: Bearer xyz",
                    "X-API-Key: secret",
                    "password=hunter2",
                    "cookie: session=abc",
                ],
                observed_versions=["1.0"],
            )
        )
        for token in (
            "Bearer", "Authorization", "X-API-Key", "password=",
            "cookie:", "hunter2",
        ):
            self.assertNotIn(token, blob, f"{token!r} leaked into evidence")

    def test_no_observed_versions(self):
        evidence = vn.build_version_evidence(
            cve_versions=["<=1.0"], observed_versions=[]
        )
        self.assertEqual(evidence["rows"][0]["comparison"],
                         vn.COMPARISON_INDETERMINATE)
        self.assertEqual(evidence["counts"]["observed_versions"], 0)


class TestNoSubstringOrFuzzyMatching(unittest.TestCase):
    def test_no_substring_matching(self):
        self.assertEqual(
            vn.compare_versions("1.2", "1.20"), vn.COMPARISON_NO_MATCH
        )
        self.assertEqual(
            vn.compare_versions("1.2.3", "1.2.30"), vn.COMPARISON_NO_MATCH
        )
        self.assertEqual(
            vn.matches_constraint("10.0", "1.x"),
            vn.COMPARISON_NO_MATCH,
        )

    def test_no_fuzzy_matching(self):
        # rc-suffixed values are intentionally unsupported -> conservative.
        self.assertEqual(
            vn.parse_version("1.2.3-rc1").version_kind, vn.KIND_UNKNOWN
        )
        self.assertEqual(
            vn.compare_versions("1.2.3", "1.2.3-rc1"),
            vn.COMPARISON_INDETERMINATE,
        )


# ---------------------------------------------------------------------------
# Adapter integration (backend/asset_cve_matching)
# ---------------------------------------------------------------------------


def _projection(versions):
    return {
        "inventory_id": inventory_id_for("dell"),
        "program": "dell",
        "technologies": [],
        "products": [],
        "components": [],
        "plugins": [],
        "versions": [
            {
                "value": version,
                "source": "TECHNOLOGY_INVENTORY",
                "evidence_type": "STRUCTURED_TECHNOLOGY",
            }
            for version in versions
        ],
        "version_associations": [],
        "parameters": [],
        "paths": [],
        "component_provenance": [],
        "parameter_paths": [],
        "sources": [],
        "evidence": [],
        "generated_from": {},
        "rule_version": "r30-2",
        "research_only": True,
    }


def _contexts(cve_versions):
    document = SimpleNamespace(
        components=[],
        parameters=[],
        vulnerability_types=[],
        cwes=[],
        intelligence_evidence=[],
        research_priority=None,
    )
    payload = {
        "cve": {"id": CVE, "products": [], "affected_versions": []},
        "research": {"affected_versions": list(cve_versions)},
    }
    return [
        {
            "cve": CVE,
            "document": document,
            "payload": payload,
            "assets": [AssetRecord(program="dell", asset="dell.com")],
        }
    ]


class TestAdapterIntegration(unittest.TestCase):
    def setUp(self):
        acm.clear_cache()

    def tearDown(self):
        acm.clear_cache()

    def _match(self, cve_versions, observed_versions, program="dell"):
        with mock.patch(
            "backend.observed_inventory.get_inventory",
            return_value=_projection(observed_versions),
        ), mock.patch.object(
            acm, "_contexts", return_value=_contexts(cve_versions)
        ):
            return acm.build_matches(cve=CVE, program=program)["items"][0]

    def test_adapter_attaches_version_normalization(self):
        item = self._match(["<=1.0"], ["0.9"])
        self.assertEqual(
            item["version_normalization_rule_version"], "r31-7"
        )
        evidence = item["version_normalization"]
        self.assertEqual(evidence["rule_version"], "r31-7")
        self.assertEqual(len(evidence["rows"]), 1)
        row = evidence["rows"][0]
        self.assertEqual(row["cve_kind"], vn.KIND_UPPER_BOUND)
        self.assertEqual(row["comparison"], vn.COMPARISON_MATCH)

    def test_adapter_engine_fields_unchanged(self):
        item = self._match(["<=1.0"], ["0.9"])
        engine = acm_engine.evaluate_inventory(
            cve_id=CVE,
            program="dell",
            cve_versions=["<=1.0"],
            observed_versions=["0.9"],
        )
        for field in (
            "strongest_match_type",
            "strongest_confidence",
            "asset_match_state",
            "matched_version",
            "version_state",
            "remaining_blockers",
        ):
            self.assertEqual(item[field], engine[field], field)

    def test_version_evidence_does_not_promote_confidence(self):
        item = self._match(["<=1.0"], ["0.9"])
        # A VERSION-only match stays LOW/WEAK; parsing cannot promote it.
        self.assertEqual(item["strongest_match_type"], "VERSION")
        self.assertNotEqual(item["strongest_confidence"], "HIGH")
        self.assertNotEqual(item["asset_match_state"], "CONFIRMED")

    def test_unknown_cve_version_stays_unknown(self):
        item = self._match(["latest"], ["0.9"])
        evidence = item["version_normalization"]
        self.assertEqual(evidence["rows"][0]["cve_kind"], vn.KIND_UNKNOWN)
        self.assertEqual(
            evidence["rows"][0]["comparison"],
            vn.COMPARISON_INDETERMINATE,
        )
        self.assertEqual(item["version_state"], "UNKNOWN")

    def test_corpus_parenthetical_bound(self):
        item = self._match(
            ["< 7.1.2 (confirmed against v7.1.1, commit 625a26b)"],
            ["7.1.1"],
        )
        row = item["version_normalization"]["rows"][0]
        self.assertEqual(row["cve_kind"], vn.KIND_UPPER_BOUND)
        self.assertEqual(row["observed_normalized"], "7.1.1")
        self.assertEqual(row["comparison"], vn.COMPARISON_MATCH)
        self.assertEqual(item["matched_version"], "7.1.1")


class TestCrossStageRegressions(unittest.TestCase):
    def test_r301_engine_untouched(self):
        self.assertEqual(acm_engine.RULE_VERSION, "r30-1")
        self.assertEqual(
            acm_engine.evaluate_version(["<=1.0"], ["0.9"])["state"],
            "MATCH",
        )
        self.assertEqual(
            acm_engine.evaluate_version(["1.0 - 1.5"], ["1.2"])["state"],
            "MATCH",
        )

    def test_r303_association_untouched(self):
        self.assertEqual(vca.RULE_VERSION, "r30-3")
        result = vca.evaluate_version_association(
            cve_families=["WordPress"],
            cve_components=["CKEditor"],
            cve_plugins=[],
            cve_versions=["<=1.0"],
            observed_versions=[
                {"version": "1.0", "technology_family": "WordPress",
                 "component": "CKEditor"}
            ],
        )
        self.assertEqual(result.state, "VERSION_MATCH_WITHIN_SAME_FAMILY")
        self.assertEqual(result.engine_versions, ("1.0",))

    def test_r315_provenance_rule_version_untouched(self):
        self.assertEqual(EVIDENCE_PROVENANCE_RULE_VERSION, "r31-5")

    def test_r316_identity_untouched(self):
        self.assertEqual(component_identity.RULE_VERSION, "r31-6")
        # Versions are never identities: plug-in/identity strings are
        # UNKNOWN versions, and parsing does not create identities.
        self.assertEqual(
            vn.parse_version("wordpress_automatic_plugin").version_kind,
            vn.KIND_UNKNOWN,
        )
        parsed = vn.parse_version("1.4.19")
        self.assertEqual(parsed.version_kind, vn.KIND_EXACT)
        self.assertFalse(hasattr(parsed, "identity"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
