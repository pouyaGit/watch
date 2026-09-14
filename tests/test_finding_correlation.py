"""tests/test_finding_correlation.py — Stage R54.4 tests.

Deterministic, offline tests for the finding correlation builder and APIs:

- R53 finding-intelligence -> R54 correlation result
- standalone R53 finding lists
- duplicate/related/conflicting/independent/unknown relationships
- clustering without collapsing findings
- stable finding ids, deterministic ordering and byte-identical output
- provenance/governance/limitation preservation
- empty, minimal, malformed, unsupported and ambiguous inputs
- no confidence inflation and no mutation of R53 inputs

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import copy
import hashlib
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_orchestrator import orchestrate_research
from ai.knowledge.finding_builder import build_finding_intelligence
from ai.knowledge.finding_correlation import (
    correlate,
    correlate_finding_intelligence,
    correlate_findings,
    export_finding_correlation,
)
from ai.knowledge.research_governance_export import (
    export_research_governance,
)
from ai.schemas.finding_correlation import (
    RELATIONSHIP_CONFLICTING,
    RELATIONSHIP_DUPLICATE,
    RELATIONSHIP_INDEPENDENT,
    RELATIONSHIP_RELATED,
    RELATIONSHIP_UNKNOWN,
)
from ai.schemas.finding_correlation_result import (
    CORRELATION_STATUSES,
    FINDING_SKIP_REASONS,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NO_RELATIONSHIPS,
    STATUS_PARTIAL,
)

from tests.test_finding_correlation_rules import finding, finding_id

AGENT_A = "sa-" + "a" * 16
AGENT_B = "sa-" + "b" * 16
AGENT_C = "sa-" + "c" * 16


def duplicate_findings():
    first = finding(
        "SSRF",
        AGENT_A,
        context={"server_side_fetch": "OBSERVED"},
        hypothesis_types=["SERVER_SIDE_FETCH_ANALYSIS"],
        fingerprints=["fp-shared"],
        evidence_requirements=["SERVER_FETCH_BEHAVIOR"],
        finding_id_value="fnd-" + "1" * 16,
    )
    second = finding(
        "SSRF",
        AGENT_B,
        context={"server_side_fetch": "OBSERVED"},
        hypothesis_types=["SERVER_SIDE_FETCH_ANALYSIS"],
        fingerprints=["fp-shared"],
        evidence_requirements=["SERVER_FETCH_BEHAVIOR"],
        finding_id_value="fnd-" + "2" * 16,
    )
    return first, second


def related_findings():
    first = finding(
        "JWT",
        AGENT_A,
        context={"issuer_validation": "NOT_PROVIDED"},
        hypothesis_types=["ISSUER_VALIDATION_GAP"],
        evidence_requirements=["ISSUER_CONFIGURATION"],
        finding_id_value="fnd-" + "3" * 16,
    )
    second = finding(
        "OAUTH",
        AGENT_B,
        context={"issuer_validation": "NOT_PROVIDED"},
        hypothesis_types=["ISSUER_VALIDATION_GAP"],
        evidence_requirements=["ISSUER_CONFIGURATION"],
        finding_id_value="fnd-" + "4" * 16,
    )
    return first, second


def conflicting_findings():
    first = finding(
        "JWT",
        AGENT_A,
        context={"issuer_validation": "PRESENT"},
        confidence="HIGH",
        finding_id_value="fnd-" + "5" * 16,
    )
    second = finding(
        "OAUTH",
        AGENT_B,
        context={"issuer_validation": "ABSENT"},
        confidence="LOW",
        finding_id_value="fnd-" + "6" * 16,
    )
    return first, second


def independent_findings():
    first = finding(
        "XSS",
        AGENT_A,
        context={"output_context": "HTML"},
        hypothesis_types=["REFLECTION_ANALYSIS"],
        finding_id_value="fnd-" + "7" * 16,
    )
    second = finding(
        "SQLI",
        AGENT_B,
        context={"query_context": "DATABASE_QUERY"},
        hypothesis_types=["RAW_QUERY_REVIEW"],
        finding_id_value="fnd-" + "8" * 16,
    )
    return first, second


def sparse_findings():
    first = finding("IDOR", AGENT_A, finding_id_value="fnd-" + "9" * 16)
    second = finding(
        "CVE_RESEARCH", AGENT_B, finding_id_value="fnd-" + "a" * 16
    )
    return first, second


class TestR53Integration(unittest.TestCase):
    def test_finding_intelligence_to_correlation(self):
        orchestration = orchestrate_research(
            research_context={
                "input_location": "QUERY",
                "output_context": "HTML",
                "reflection_state": "REFLECTED",
                "encoding_state": "NONE_OBSERVED",
                "framework_context": "GENERIC",
                "parameter_type": "QUERY_PARAM",
                "query_context": "DATABASE_QUERY",
                "data_flow": "RAW_QUERY",
                "token_format": "JWT",
                "signing_algorithm": "HS256",
                "flow": "AUTHORIZATION_CODE",
                "oauth_version": "2.0",
            },
            governance_plan=export_research_governance(),
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        result = correlate_finding_intelligence(intelligence)
        self.assertIn(result["status"], CORRELATION_STATUSES)
        self.assertEqual(result["rule_version"], "r54-2")
        self.assertEqual(result["relationship_rule_version"], "r54-1")
        self.assertEqual(
            result["provenance"]["finding_rule_version"], "r53-6"
        )
        self.assertEqual(
            result["provenance"]["orchestration_ids"],
            [orchestration["orchestration_id"]],
        )
        self.assertEqual(
            len(result["finding_references"]),
            len(intelligence["findings"]),
        )
        expected_ids = sorted(
            item["finding_id"] for item in intelligence["findings"]
        )
        self.assertEqual(
            [item["finding_id"] for item in result["finding_references"]],
            expected_ids,
        )
        expected_pairs = len(expected_ids) * (len(expected_ids) - 1) // 2
        self.assertEqual(len(result["relationships"]), expected_pairs)

    def test_finding_intelligence_is_not_mutated(self):
        orchestration = orchestrate_research(
            research_context={"output_context": "HTML"}
        )
        intelligence = build_finding_intelligence(
            orchestration_result=orchestration
        )
        snapshot = json.dumps(intelligence, sort_keys=True)
        correlate_finding_intelligence(intelligence)
        self.assertEqual(
            json.dumps(intelligence, sort_keys=True), snapshot
        )

    def test_correlate_findings_alias(self):
        first, second = related_findings()
        first_result = correlate_findings([first, second])
        second_result = correlate(
            findings=[first, second]
        )
        self.assertEqual(
            json.dumps(first_result, sort_keys=True),
            json.dumps(second_result, sort_keys=True),
        )

    def test_export_alias(self):
        first, second = related_findings()
        exported = export_finding_correlation(findings=[first, second])
        direct = correlate(findings=[first, second])
        self.assertEqual(
            json.dumps(exported, sort_keys=True),
            json.dumps(direct, sort_keys=True),
        )

    def test_result_contract_is_exact(self):
        first, second = related_findings()
        result = correlate_findings([first, second])
        self.assertEqual(
            set(result.keys()),
            {
                "rule_version",
                "correlation_rule_version",
                "relationship_rule_version",
                "correlation_id",
                "status",
                "finding_references",
                "relationships",
                "clusters",
                "skipped_findings",
                "errors",
                "provenance",
                "governance_summary",
                "limitations",
                "confidence_effect",
                "research_only",
                "deterministic",
            },
        )
        self.assertTrue(result["research_only"])
        self.assertTrue(result["deterministic"])
        self.assertEqual(result["confidence_effect"], "NONE")


class TestInputValidation(unittest.TestCase):
    def test_both_inputs_fail_closed(self):
        first, second = related_findings()
        result = correlate(
            finding_intelligence={"rule_version": "r53-6", "findings": []},
            findings=[first, second],
        )
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_INPUT"
        )
        self.assertEqual(result["relationships"], [])

    def test_non_mapping_intelligence_fails_closed(self):
        result = correlate(finding_intelligence="nope")
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_INPUT"
        )

    def test_non_list_findings_fails_closed(self):
        result = correlate(findings="nope")
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_INPUT"
        )

    def test_foreign_intelligence_is_rejected(self):
        result = correlate_finding_intelligence(
            {"rule_version": "r99-9", "findings": []}
        )
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_INPUT"
        )

    def test_intelligence_without_findings_list_is_rejected(self):
        result = correlate_finding_intelligence(
            {"rule_version": "r53-6", "findings": "nope"}
        )
        self.assertEqual(result["status"], STATUS_FAILED)

    def test_empty_input_is_no_relationships(self):
        result = correlate()
        self.assertEqual(result["status"], STATUS_NO_RELATIONSHIPS)
        self.assertEqual(result["finding_references"], [])
        self.assertEqual(result["relationships"], [])
        self.assertIn("CORRELATION_UNAVAILABLE", result["limitations"])

    def test_single_finding_has_no_relationships(self):
        result = correlate_findings([finding("XSS", AGENT_A)])
        self.assertEqual(result["status"], STATUS_NO_RELATIONSHIPS)
        self.assertEqual(len(result["finding_references"]), 1)
        self.assertIn("CORRELATION_UNAVAILABLE", result["limitations"])


class TestFindingNormalization(unittest.TestCase):
    def test_malformed_finding_is_skipped(self):
        result = correlate_findings(
            [
                "not-a-finding",
                {
                    "rule_version": "r99-9",
                    "identity": {
                        "finding_id": "fnd-" + "b" * 16,
                        "category": "XSS",
                    },
                },
            ]
        )
        self.assertEqual(result["finding_references"], [])
        self.assertEqual(len(result["skipped_findings"]), 2)
        for skipped in result["skipped_findings"]:
            self.assertEqual(skipped["reason"], "MALFORMED_FINDING")

    def test_unsupported_category_is_skipped(self):
        for category in ("UNKNOWN", "BOGUS"):
            raw = finding("XSS", AGENT_A)
            raw["identity"]["category"] = category
            result = correlate_findings([raw])
            self.assertEqual(
                result["skipped_findings"][0]["reason"],
                "UNSUPPORTED_CATEGORY",
                category,
            )

    def test_non_research_only_is_skipped(self):
        raw = finding("XSS", AGENT_A, research_only=False)
        result = correlate_findings([raw])
        self.assertEqual(result["finding_references"], [])
        self.assertEqual(
            result["skipped_findings"][0]["reason"], "NON_RESEARCH_ONLY"
        )
        self.assertEqual(
            result["errors"][0]["error_category"], "SAFETY_BLOCKED"
        )

    def test_unsafe_confirmation_is_skipped(self):
        raw = finding(
            "XSS", AGENT_A, confirmation_state="CONFIRMED"
        )
        result = correlate_findings([raw])
        self.assertEqual(result["finding_references"], [])
        self.assertEqual(
            result["skipped_findings"][0]["reason"],
            "UNSAFE_CONFIRMATION",
        )

    def test_duplicate_identity_is_skipped_but_first_is_kept(self):
        first = finding("XSS", AGENT_A, finding_id_value="fnd-" + "1" * 16)
        duplicate = copy.deepcopy(first)
        result = correlate_findings([first, duplicate])
        self.assertEqual(len(result["finding_references"]), 1)
        self.assertEqual(
            result["skipped_findings"][0]["reason"], "DUPLICATE_IDENTITY"
        )
        self.assertEqual(
            result["errors"][0]["error_category"], "DUPLICATE_IDENTITY"
        )

    def test_finding_limit_is_enforced(self):
        raws = [
            finding(
                "XSS",
                f"sa-{index:016x}"[:19],
                finding_id_value=f"fnd-{index:016x}"[:20],
            )
            for index in range(10)
        ]
        result = correlate_findings(raws)
        self.assertEqual(
            len(result["finding_references"]), 8
        )
        self.assertEqual(len(result["skipped_findings"]), 2)
        self.assertEqual(
            result["skipped_findings"][0]["reason"], "LIMIT_EXCEEDED"
        )

    def test_skip_reasons_are_closed(self):
        raw = finding("XSS", AGENT_A, research_only=False)
        result = correlate_findings(["bad", raw])
        for skipped in result["skipped_findings"]:
            self.assertIn(skipped["reason"], FINDING_SKIP_REASONS)


class TestClassifications(unittest.TestCase):
    def test_duplicate_relationship_and_preservation(self):
        first, second = duplicate_findings()
        result = correlate_findings([first, second])
        self.assertEqual(result["status"], STATUS_COMPLETED)
        self.assertEqual(len(result["finding_references"]), 2)
        relationship = result["relationships"][0]
        self.assertEqual(
            relationship["relationship_type"], RELATIONSHIP_DUPLICATE
        )
        self.assertEqual(
            {relationship["source_finding_id"],
             relationship["target_finding_id"]},
            {"fnd-" + "1" * 16, "fnd-" + "2" * 16},
        )
        self.assertIn(
            "DUPLICATE_RELATIONSHIP", relationship["limitations"]
        )
        self.assertEqual(relationship["confidence_effect"], "NONE")

    def test_related_relationship(self):
        first, second = related_findings()
        result = correlate_findings([first, second])
        relationship = result["relationships"][0]
        self.assertEqual(
            relationship["relationship_type"], RELATIONSHIP_RELATED
        )
        self.assertTrue(relationship["shared_context_values"])
        self.assertIn(
            "SHARED_CONTEXT", relationship["limitations"]
        )

    def test_conflicting_relationship_preserves_details(self):
        first, second = conflicting_findings()
        result = correlate_findings([first, second])
        relationship = result["relationships"][0]
        self.assertEqual(
            relationship["relationship_type"], RELATIONSHIP_CONFLICTING
        )
        self.assertIn(
            "CONFLICT_PRESENT", relationship["limitations"]
        )
        self.assertTrue(relationship["conflict_details"])
        detail = relationship["conflict_details"][0]
        self.assertEqual(detail["conflict_type"], "CONTEXT_CONFLICT")
        self.assertIn(
            "issuer_validation", detail["conflicting_fields"]
        )

    def test_independent_relationship(self):
        first, second = independent_findings()
        result = correlate_findings([first, second])
        relationship = result["relationships"][0]
        self.assertEqual(
            relationship["relationship_type"], RELATIONSHIP_INDEPENDENT
        )
        self.assertIn(
            "NO_SHARED_SIGNAL", relationship["signals"]
        )
        self.assertEqual(result["clusters"], [])

    def test_unknown_relationship_for_sparse_findings(self):
        first, second = sparse_findings()
        result = correlate_findings([first, second])
        relationship = result["relationships"][0]
        self.assertEqual(
            relationship["relationship_type"], RELATIONSHIP_UNKNOWN
        )
        self.assertIn(
            "INSUFFICIENT_STRUCTURE", relationship["signals"]
        )
        self.assertIn(
            "INSUFFICIENT_CONTEXT", relationship["limitations"]
        )

    def test_unrelated_findings_are_not_artificially_correlated(self):
        first, second = independent_findings()
        result = correlate_findings([first, second])
        self.assertEqual(result["clusters"], [])
        self.assertEqual(result["status"], STATUS_COMPLETED)


class TestClustering(unittest.TestCase):
    def test_duplicate_cluster(self):
        first, second = duplicate_findings()
        result = correlate_findings([first, second])
        self.assertEqual(len(result["clusters"]), 1)
        cluster = result["clusters"][0]
        self.assertEqual(
            cluster["relationship_type"], RELATIONSHIP_DUPLICATE
        )
        self.assertEqual(cluster["cluster_size"], 2)
        self.assertEqual(
            cluster["member_finding_ids"],
            sorted(cluster["member_finding_ids"]),
        )
        self.assertEqual(cluster["confidence_effect"], "NONE")
        self.assertIn(
            "DUPLICATE_RELATIONSHIP", cluster["limitations"]
        )

    def test_related_cluster_does_not_chain(self):
        # A-B related, B-C related: R43 singleton-merge semantics keep the
        # RELATED cluster at two members; all three findings remain present.
        first = finding(
            "JWT",
            AGENT_A,
            context={"issuer_validation": "NOT_PROVIDED"},
            finding_id_value="fnd-" + "1" * 16,
        )
        second = finding(
            "OAUTH",
            AGENT_B,
            context={"issuer_validation": "NOT_PROVIDED"},
            finding_id_value="fnd-" + "2" * 16,
        )
        third = finding(
            "OAUTH",
            AGENT_C,
            context={"issuer_validation": "NOT_PROVIDED"},
            finding_id_value="fnd-" + "3" * 16,
        )
        result = correlate_findings([first, second, third])
        self.assertEqual(len(result["finding_references"]), 3)
        related = [
            cluster
            for cluster in result["clusters"]
            if cluster["relationship_type"] == RELATIONSHIP_RELATED
        ]
        self.assertTrue(related)
        for cluster in related:
            self.assertLessEqual(cluster["cluster_size"], 2)

    def test_conflicting_cluster_merges(self):
        first = finding(
            "JWT",
            AGENT_A,
            context={"issuer_validation": "PRESENT"},
            finding_id_value="fnd-" + "4" * 16,
        )
        second = finding(
            "OAUTH",
            AGENT_B,
            context={"issuer_validation": "ABSENT"},
            finding_id_value="fnd-" + "5" * 16,
        )
        third = finding(
            "OAUTH",
            AGENT_C,
            context={"issuer_validation": "ABSENT"},
            finding_id_value="fnd-" + "6" * 16,
        )
        result = correlate_findings([first, second, third])
        conflicting = [
            cluster
            for cluster in result["clusters"]
            if cluster["relationship_type"] == RELATIONSHIP_CONFLICTING
        ]
        self.assertTrue(conflicting)
        self.assertGreaterEqual(
            conflicting[0]["cluster_size"], 2
        )
        self.assertIn(
            "CONFLICT_PRESENT", conflicting[0]["limitations"]
        )

    def test_cluster_ids_are_content_ids(self):
        first, second = duplicate_findings()
        result = correlate_findings([first, second])
        cluster = result["clusters"][0]
        self.assertTrue(cluster["cluster_id"].startswith("fcg-"))
        self.assertEqual(len(cluster["cluster_id"]), 20)
        self.assertTrue(result["correlation_id"].startswith("fci-"))

    def test_clusters_do_not_collapse_findings(self):
        first, second = duplicate_findings()
        result = correlate_findings([first, second])
        ids = {item["finding_id"] for item in result["finding_references"]}
        self.assertEqual(ids, {"fnd-" + "1" * 16, "fnd-" + "2" * 16})
        for cluster in result["clusters"]:
            for member in cluster["member_finding_ids"]:
                self.assertIn(member, ids)


class TestDeterminism(unittest.TestCase):
    def test_input_order_does_not_change_output(self):
        first, second = related_findings()
        forward = correlate_findings([first, second])
        backward = correlate_findings([second, first])
        self.assertEqual(
            json.dumps(forward, sort_keys=True),
            json.dumps(backward, sort_keys=True),
        )

    def test_repeated_runs_are_byte_identical(self):
        raw_findings = list(related_findings()) + list(
            conflicting_findings()
        )
        first = correlate_findings(copy.deepcopy(raw_findings))
        second = correlate_findings(copy.deepcopy(raw_findings))
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_ids_are_stable(self):
        first, second = related_findings()
        first_result = correlate_findings([first, second])
        second_result = correlate_findings(
            [copy.deepcopy(first), copy.deepcopy(second)]
        )
        self.assertEqual(
            first_result["correlation_id"],
            second_result["correlation_id"],
        )
        self.assertEqual(
            first_result["relationships"][0]["relationship_id"],
            second_result["relationships"][0]["relationship_id"],
        )

    def test_relationship_ordering_is_canonical(self):
        raw_findings = (
            list(independent_findings())
            + list(conflicting_findings())
            + list(related_findings())
        )
        result = correlate_findings(raw_findings)
        precedence = {
            RELATIONSHIP_CONFLICTING: 4,
            RELATIONSHIP_DUPLICATE: 3,
            RELATIONSHIP_RELATED: 2,
            RELATIONSHIP_UNKNOWN: 1,
            RELATIONSHIP_INDEPENDENT: 0,
        }
        keys = [
            (
                -precedence[item["relationship_type"]],
                item["source_finding_id"],
                item["target_finding_id"],
            )
            for item in result["relationships"]
        ]
        self.assertEqual(keys, sorted(keys))

    def test_no_runtime_identifiers(self):
        first, second = related_findings()
        result = correlate_findings([first, second])
        serialized = json.dumps(result, sort_keys=True).lower()
        for token in ("timestamp", "created_at", "updated_at", "uuid",
                      "process_id", "runtime_id", "nonce"):
            self.assertNotIn(token, serialized)


class TestPreservation(unittest.TestCase):
    def test_references_preserve_finding_metadata(self):
        first, second = related_findings()
        result = correlate_findings([first, second])
        reference = {
            item["finding_id"]: item
            for item in result["finding_references"]
        }["fnd-" + "3" * 16]
        self.assertEqual(reference["category"], "JWT")
        self.assertEqual(reference["agent_id"], AGENT_A)
        self.assertEqual(reference["state"], "RESEARCH_CANDIDATE")
        self.assertEqual(reference["confidence"], "MEDIUM")
        self.assertEqual(reference["evidence_state"], "COMPLETE")
        self.assertEqual(reference["evidence_completeness"], "COMPLETE")
        self.assertEqual(reference["evidence_origin"], "SPECIALIST_PLAN")
        self.assertEqual(reference["confirmation_state"], "NOT_CONFIRMED")
        self.assertEqual(reference["hypothesis_count"], 1)
        self.assertEqual(reference["evidence_requirement_count"], 1)
        self.assertEqual(reference["finding_rule_version"], "r53-6")

    def test_provenance_is_aggregated(self):
        first, second = related_findings()
        result = correlate_findings([first, second])
        provenance = result["provenance"]
        self.assertEqual(provenance["finding_rule_version"], "r53-6")
        self.assertEqual(provenance["finding_count"], 2)
        self.assertEqual(provenance["relationship_count"], 1)
        self.assertEqual(
            provenance["source_agent_ids"], sorted([AGENT_A, AGENT_B])
        )
        self.assertEqual(
            provenance["source_categories"], ["JWT", "OAUTH"]
        )
        self.assertEqual(
            provenance["orchestration_ids"], ["orch-" + "1" * 16]
        )

    def test_provenance_unavailable_is_disclosed(self):
        first = finding("XSS", AGENT_A, orchestration_id="")
        second = finding("SQLI", AGENT_B, orchestration_id="")
        result = correlate_findings([first, second])
        self.assertIn(
            "PROVENANCE_UNAVAILABLE", result["limitations"]
        )
        self.assertIn(
            "PROVENANCE_UNAVAILABLE",
            result["relationships"][0]["limitations"],
        )

    def test_governance_summary_consistent(self):
        first = finding(
            "JWT", AGENT_A, governance_state="REFERENCED"
        )
        first["governance"]["ready"] = True
        second = finding(
            "OAUTH", AGENT_B, governance_state="REFERENCED"
        )
        result = correlate_findings([first, second])
        summary = result["governance_summary"]
        self.assertEqual(summary["governance_state"], "CONSISTENT_REFERENCED")
        self.assertEqual(
            summary["ready_finding_ids"], [first["finding_id"]]
        )
        self.assertEqual(
            summary["not_ready_finding_ids"], [second["finding_id"]]
        )
        summary_keys = set(summary.keys())
        self.assertIn("referenced_finding_ids", summary_keys)
        self.assertIn("unknown_finding_ids", summary_keys)

    def test_governance_summary_mixed_and_unknown(self):
        referenced = finding(
            "JWT", AGENT_A, governance_state="REFERENCED"
        )
        unknown = finding("OAUTH", AGENT_B, governance_state="UNKNOWN")
        mixed = correlate_findings([referenced, unknown])
        self.assertEqual(
            mixed["governance_summary"]["governance_state"], "MIXED"
        )
        first, second = related_findings()
        unknown_result = correlate_findings([first, second])
        self.assertEqual(
            unknown_result["governance_summary"]["governance_state"],
            "UNKNOWN",
        )
        self.assertIn(
            "GOVERNANCE_UNKNOWN", unknown_result["limitations"]
        )
        self.assertIn(
            "GOVERNANCE_UNKNOWN",
            unknown_result["relationships"][0]["limitations"],
        )

    def test_evidence_incomplete_is_disclosed(self):
        first = finding(
            "SSRF",
            AGENT_A,
            context={"server_side_fetch": "OBSERVED"},
            evidence_completeness="PARTIAL",
            finding_id_value="fnd-" + "1" * 16,
        )
        second = finding(
            "SSRF",
            AGENT_B,
            context={"server_side_fetch": "OBSERVED"},
            evidence_completeness="COMPLETE",
            finding_id_value="fnd-" + "2" * 16,
        )
        result = correlate_findings([first, second])
        self.assertIn("EVIDENCE_INCOMPLETE", result["limitations"])
        self.assertIn(
            "EVIDENCE_INCOMPLETE",
            result["relationships"][0]["limitations"],
        )
        reference = result["finding_references"][0]
        self.assertEqual(reference["evidence_completeness"], "PARTIAL")

    def test_no_confidence_inflation(self):
        first, second = conflicting_findings()
        before = (
            first["assessment"]["confidence"],
            second["assessment"]["confidence"],
        )
        result = correlate_findings([first, second])
        self.assertEqual(
            (first["assessment"]["confidence"],
             second["assessment"]["confidence"]),
            before,
        )
        self.assertEqual(result["confidence_effect"], "NONE")
        for relationship in result["relationships"]:
            self.assertEqual(relationship["confidence_effect"], "NONE")
        for cluster in result["clusters"]:
            self.assertEqual(cluster["confidence_effect"], "NONE")
        self.assertIn(
            "CONFIDENCE_NOT_UPGRADED", result["limitations"]
        )

    def test_confirmation_is_never_confirmed(self):
        first, second = related_findings()
        result = correlate_findings([first, second])
        for reference in result["finding_references"]:
            self.assertEqual(
                reference["confirmation_state"], "NOT_CONFIRMED"
            )
        serialized = json.dumps(result, sort_keys=True).upper()
        self.assertNotIn("CONFIRMED_EXPLOIT", serialized)
        self.assertNotIn("VULNERABILITY_CONFIRMED", serialized)

    def test_r53_input_is_not_mutated(self):
        first, second = conflicting_findings()
        snapshot = json.dumps([first, second], sort_keys=True)
        correlate_findings([first, second])
        self.assertEqual(
            json.dumps([first, second], sort_keys=True), snapshot
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
