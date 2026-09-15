"""Focused offline tests for the R69 Watch-native security skill library."""

from __future__ import annotations

import re
import unittest

from ai.knowledge.security_skills import (
    MAX_SKILLS,
    MAX_SKILL_TEXT_CHARS,
    RULE_VERSION,
    SKILLS,
    SKILL_CATEGORY_ORDER,
    SIGNAL_SKILLS,
    all_skills,
    render_skill,
    render_skills,
    select_skills,
    skill_by_id,
)

REQUIRED_FIELDS = (
    "skill_id",
    "category",
    "title",
    "applicability",
    "trigger_conditions",
    "required_evidence",
    "useful_evidence_types",
    "methodology",
    "hypothesis_patterns",
    "false_positives",
    "confidence_constraints",
    "priority_constraints",
    "rejection_cases",
    "safe_next_actions",
    "watch_signals",
)

FORBIDDEN_TEXT = (
    "payload",
    "execute",
    "send a request",
    "curl ",
    "nmap",
    "sqlmap",
    "brute force",
)

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MONGO_ID_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{24}(?![0-9a-fA-F])")


class TestSkillLibrary(unittest.TestCase):
    def test_skill_discovery(self):
        skills = all_skills()
        self.assertEqual(len(skills), len(SKILLS))
        self.assertEqual(
            len({skill["skill_id"] for skill in skills}), len(skills)
        )
        for skill in skills:
            for field in REQUIRED_FIELDS:
                self.assertIn(field, skill, skill.get("skill_id"))
            self.assertIn(skill["category"], SKILL_CATEGORY_ORDER)
            for field in (
                "trigger_conditions",
                "required_evidence",
                "methodology",
                "false_positives",
                "rejection_cases",
                "safe_next_actions",
            ):
                self.assertTrue(skill[field], (skill["skill_id"], field))
        self.assertEqual(skill_by_id("idor-bola")["category"], "IDOR")
        self.assertIsNone(skill_by_id("does-not-exist"))
        for category, skill_id in SIGNAL_SKILLS.items():
            self.assertIn(category, SKILL_CATEGORY_ORDER)
            self.assertIsNotNone(skill_by_id(skill_id), category)

    def test_signal_category_matching(self):
        for category, expected in (
            ("IDOR", "idor-bola"),
            ("SSRF", "ssrf"),
            ("XSS", "xss"),
            ("SQLI", "sqli"),
            ("JWT", "jwt"),
            ("OAUTH", "oauth"),
            ("CVE_RESEARCH", "cve-research"),
        ):
            with self.subTest(category=category):
                selected = select_skills(signals={category: {"x": "y"}})
                self.assertEqual(
                    [skill["skill_id"] for skill in selected], [expected]
                )

    def test_recon_signal_selects_recon_family_skill(self):
        selected = select_skills(signals={"RECON": {"api_type": "REST"}})
        self.assertEqual(
            [skill["skill_id"] for skill in selected], ["api-security"]
        )
        graphql = select_skills(
            signals={"RECON": {"api_type": "GRAPHQL"}},
            evidence=[{"kind": "path", "value": "/graphql"}],
        )
        self.assertEqual(
            [skill["skill_id"] for skill in graphql], ["graphql"]
        )
        redirect = select_skills(
            signals={"RECON": {"api_type": "REST"}},
            evidence=[{"kind": "parameter", "value": "continue"}],
        )
        self.assertEqual(
            [skill["skill_id"] for skill in redirect], ["open-redirect"]
        )

    def test_evidence_aware_selection(self):
        for evidence, expected in (
            (
                [{"kind": "path", "value": "/api/users/{id}/profile"}],
                "idor-bola",
            ),
            ([{"kind": "parameter", "value": "callback_url"}], None),
            ([{"kind": "parameter", "value": "url"}], "ssrf"),
            ([{"kind": "parameter", "value": "continue"}], "open-redirect"),
            ([{"kind": "parameter", "value": "jwt"}], "jwt"),
            ([{"kind": "parameter", "value": "assertion"}], "oauth"),
            ([{"kind": "parameter", "value": "price"}], "business-logic"),
            ([{"kind": "path", "value": "/graphql"}], "graphql"),
            (
                [
                    {"kind": "technology", "value": "nginx"},
                    {"kind": "version", "value": "1.24.0"},
                ],
                "cve-research",
            ),
        ):
            with self.subTest(evidence=evidence):
                selected = select_skills(evidence=evidence)
                ids = [skill["skill_id"] for skill in selected]
                if expected is None:
                    self.assertNotIn("ssrf", ids)
                else:
                    self.assertIn(expected, ids)

    def test_evidence_kind_routing_by_signal(self):
        selected = select_skills(
            evidence=[
                {
                    "kind": "derived_signal",
                    "signal": "IDOR",
                    "detail": "object_reference=PATH_PARAMETER",
                }
            ]
        )
        self.assertEqual(
            [skill["skill_id"] for skill in selected], ["idor-bola"]
        )

    def test_bounded_selection(self):
        evidence = [
            {"kind": "parameter", "value": "url"},
            {"kind": "parameter", "value": "continue"},
            {"kind": "parameter", "value": "jwt"},
            {"kind": "parameter", "value": "code"},
            {"kind": "parameter", "value": "price"},
            {"kind": "path", "value": "/graphql"},
        ]
        self.assertLessEqual(len(select_skills(evidence=evidence)), MAX_SKILLS)
        self.assertEqual(len(select_skills(evidence=evidence, limit=1)), 1)
        self.assertEqual(len(select_skills(evidence=evidence, limit=2)), 2)
        self.assertEqual(select_skills(evidence=evidence, limit=0), [])
        with self.assertRaises(ValueError):
            select_skills(evidence=evidence, limit=True)
        with self.assertRaises(ValueError):
            select_skills(evidence=evidence, limit=-1)

    def test_deterministic_selection(self):
        signals = {"IDOR": {"object_reference": "PATH_PARAMETER"}}
        evidence = [
            {"kind": "parameter", "value": "continue"},
            {"kind": "technology", "value": "nginx"},
            {"kind": "version", "value": "1.24.0"},
        ]
        first = select_skills(signals=signals, evidence=evidence)
        second = select_skills(signals=signals, evidence=evidence)
        self.assertEqual(first, second)
        reversed_evidence = list(reversed(evidence))
        third = select_skills(signals=signals, evidence=reversed_evidence)
        self.assertEqual(
            [skill["skill_id"] for skill in first],
            [skill["skill_id"] for skill in third],
        )

    def test_relevant_skill_only(self):
        selected = select_skills(
            signals={"IDOR": {"object_reference": "PATH_PARAMETER"}}
        )
        self.assertEqual(
            [skill["skill_id"] for skill in selected], ["idor-bola"]
        )

    def test_unknown_category_ignored(self):
        self.assertEqual(select_skills(signals={"MAGIC": {"x": "y"}}), [])
        self.assertEqual(
            select_skills(evidence=[{"kind": "mystery", "value": "x"}]), []
        )
        self.assertEqual(select_skills(evidence="not-evidence"), [])

    def test_rendering_is_bounded_and_safe(self):
        lines = render_skills(all_skills())
        self.assertTrue(lines)
        self.assertLessEqual(
            sum(len(line) + 1 for line in lines), MAX_SKILL_TEXT_CHARS
        )
        self.assertEqual(
            len(
                render_skills(
                    select_skills(
                        evidence=[
                            {"kind": "path", "value": "/api/users/{id}"},
                            {"kind": "parameter", "value": "url"},
                            {"kind": "parameter", "value": "price"},
                        ]
                    )
                )
            ),
            3,
        )
        text = "\n".join(render_skill(skill) for skill in all_skills())
        self.assertNotIn("://", text)
        self.assertIsNone(IPV4_RE.search(text))
        self.assertIsNone(MONGO_ID_RE.search(text))
        self.assertNotIn("sk-", text)
        lowered = text.lower()
        for forbidden in FORBIDDEN_TEXT:
            self.assertNotIn(forbidden, lowered)

    def test_false_positive_guidance_preserved(self):
        expected = {
            "idor-bola": "{id} placeholder",
            "ssrf": "URL-like parameter name is not SSRF",
            "xss": "parameter name is not XSS",
            "sqli": "are not injection evidence",
            "jwt": "sid/token/session names are not JWTs",
            "oauth": "code/state parameters alone are not OAuth",
            "api-security": "endpoint names do not prove purpose",
            "business-logic": "parameter names are not logic flaws",
            "open-redirect": "continue/next/return/url names are not open redirects",
            "graphql": "not a confirmed surface",
            "cve-research": "version string is not an exploitable CVE",
        }
        for skill_id, phrase in expected.items():
            with self.subTest(skill_id=skill_id):
                skill = skill_by_id(skill_id)
                self.assertIsNotNone(skill, skill_id)
                self.assertIn(
                    phrase, " ".join(skill["false_positives"]), skill_id
                )

    def test_rule_version_is_r69(self):
        self.assertEqual(RULE_VERSION, "r69-1")


if __name__ == "__main__":
    unittest.main()
