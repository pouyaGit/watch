"""tests/test_finding_identity.py — Stage R53.1 tests.

Deterministic, offline tests for finding identity:

- canonical category vocabulary and fixed labels
- deterministic content-addressed finding ids
- identity preservation from structured specialist entries
- malformed/unknown identity rejection
- bounded schema behavior

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.finding_reasoning import (
    build_finding_identity,
    category_label,
    compute_finding_id,
    descriptive_label,
)
from ai.schemas.finding_identity import (
    FINDING_ID_RE,
    FindingIdentityPlan,
    sanitize_finding_identity,
)
from ai.schemas.security_agent_identity import AGENT_CATEGORIES

CATEGORIES = (
    "XSS",
    "SSRF",
    "SQLI",
    "IDOR",
    "JWT",
    "OAUTH",
    "RECON",
    "CVE_RESEARCH",
)

AGENT_ID = "sa-" + "a" * 16


class TestFindingIdentity(unittest.TestCase):
    def test_supported_categories_are_canonical(self):
        for category in CATEGORIES:
            self.assertIn(category, AGENT_CATEGORIES)
            self.assertTrue(category_label(category))
            self.assertIn(
                "research finding candidate",
                descriptive_label(category),
            )

    def test_unknown_category_has_no_label(self):
        self.assertEqual(category_label("NOT_A_CATEGORY"), "")
        self.assertEqual(descriptive_label("NOT_A_CATEGORY"), "")

    def test_finding_id_is_deterministic(self):
        first = compute_finding_id(
            "XSS", AGENT_ID, "r39-5", ["REFLECTION_ANALYSIS"],
            ["REFLECTION_EVIDENCE"], "r39-2",
        )
        second = compute_finding_id(
            "XSS", AGENT_ID, "r39-5", ["REFLECTION_ANALYSIS"],
            ["REFLECTION_EVIDENCE"], "r39-2",
        )
        self.assertEqual(first, second)
        self.assertTrue(FINDING_ID_RE.match(first))

    def test_finding_id_changes_with_content(self):
        base = dict(
            category="XSS",
            agent_id=AGENT_ID,
            result_rule_version="r39-5",
            hypothesis_types=["REFLECTION_ANALYSIS"],
            evidence_items=["REFLECTION_EVIDENCE"],
            context_rule_version="r39-2",
        )
        reference = compute_finding_id(**base)
        variants = (
            dict(base, category="SQLI"),
            dict(base, agent_id="sa-" + "b" * 16),
            dict(base, result_rule_version="r40-5"),
            dict(base, hypothesis_types=["RAW_QUERY_REVIEW"]),
            dict(base, evidence_items=["QUERY_EVIDENCE"]),
            dict(base, context_rule_version="r40-2"),
        )
        for variant in variants:
            self.assertNotEqual(
                reference, compute_finding_id(**variant), variant
            )

    def test_finding_id_ignores_orchestration_and_time(self):
        # The id is a pure function of the listed structured values: it has
        # no clock, no randomness and no orchestration-id component.
        identity = build_finding_identity(
            "XSS", "xss-agent", AGENT_ID, "r39-5",
            ["REFLECTION_ANALYSIS"], ["REFLECTION_EVIDENCE"], "r39-2",
        )
        self.assertEqual(
            identity["finding_id"],
            compute_finding_id(
                "XSS", AGENT_ID, "r39-5", ["REFLECTION_ANALYSIS"],
                ["REFLECTION_EVIDENCE"], "r39-2",
            ),
        )
        serialized = json.dumps(identity, sort_keys=True).lower()
        for token in ("timestamp", "uuid", "nonce", "pid", "random"):
            self.assertNotIn(token, serialized)

    def test_identity_plan_projects_bounded_keys(self):
        identity = build_finding_identity(
            "XSS", "xss-agent", AGENT_ID, "r39-5",
            ["REFLECTION_ANALYSIS"], ["REFLECTION_EVIDENCE"], "r39-2",
        )
        plan = FindingIdentityPlan(**identity)
        projection = plan.model_dump(mode="json")
        self.assertEqual(
            sorted(projection.keys()),
            sorted(identity.keys()),
        )
        self.assertEqual(projection["category"], "XSS")
        self.assertEqual(projection["agent_id"], AGENT_ID)
        self.assertTrue(projection["research_only"])

    def test_identity_rejects_malformed_ids_and_categories(self):
        with self.assertRaises(ValidationError):
            FindingIdentityPlan(
                finding_id="not-a-finding-id", category="XSS"
            )
        with self.assertRaises(ValidationError):
            FindingIdentityPlan(
                finding_id="fnd-" + "a" * 16, category="UNKNOWN"
            )
        with self.assertRaises(ValidationError):
            FindingIdentityPlan(
                finding_id="fnd-" + "a" * 16, category="BOGUS"
            )
        with self.assertRaises(ValidationError):
            FindingIdentityPlan(
                finding_id="fnd-" + "a" * 16,
                category="XSS",
                research_only=False,
            )

    def test_identity_sanitizer_is_bounded(self):
        projected = sanitize_finding_identity(
            {
                "finding_id": "fnd-" + "c" * 16,
                "category": " xss ",
                "specialist_name": "x" * 500,
                "agent_id": "bogus",
                "category_label": "label",
                "descriptive_label": "descriptive",
            }
        )
        self.assertEqual(projected["category"], "XSS")
        self.assertEqual(len(projected["specialist_name"]), 160)
        self.assertEqual(projected["agent_id"], "")

    def test_identity_sanitizer_handles_non_dict(self):
        projected = sanitize_finding_identity(None)
        self.assertEqual(projected["category"], "")
        self.assertEqual(projected["finding_id"], "")
        self.assertTrue(projected["research_only"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
