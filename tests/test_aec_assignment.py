"""Tests for aec/assignment (EPIC 4 Part 3: Research Assignment).

Deterministic candidate → research-role mapping. Roles name *who studies
a surface next*; assignment grants no authority, schedules no work, and
concludes nothing about any target.
"""

from __future__ import annotations

import ast
import dataclasses
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ASSIGN_DIR = Path(__file__).resolve().parents[1] / "aec" / "assignment"
MODULES = ("models.py", "rules.py")

ROLES = frozenset({
    "authorization-researcher",
    "input-researcher",
    "server-researcher",
    "general-researcher",
})

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
})


def draft(**overrides):
    candidate = {
        "candidate_id": "rc-abc123",
        "asset": "example.com",
        "endpoint": "/api/user",
        "parameters": ("id",),
        "technology": ("php",),
        "research_category": "idor",
    }
    candidate.update(overrides)
    return candidate


class TestAssign(unittest.TestCase):
    def test_idor_maps_authorization_researcher(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="idor"))
        self.assertEqual(assignment.role, "authorization-researcher")
        self.assertEqual(assignment.surface, "authorization_surface")

    def test_xss_maps_input_researcher(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="xss"))
        self.assertEqual(assignment.role, "input-researcher")
        self.assertEqual(assignment.surface, "input_surface")

    def test_file_upload_maps_input_researcher(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="file_upload"))
        self.assertEqual(assignment.role, "input-researcher")

    def test_ssrf_maps_server_researcher(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="ssrf"))
        self.assertEqual(assignment.role, "server-researcher")
        self.assertEqual(assignment.surface, "server_side_surface")

    def test_authz_maps_authorization_researcher(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="authz"))
        self.assertEqual(assignment.role, "authorization-researcher")

    def test_unknown_category_maps_general(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="cors"))
        self.assertEqual(assignment.role, "general-researcher")
        self.assertEqual(assignment.surface, "general_surface")

    def test_assignment_is_deterministic(self):
        from aec.assignment import rules

        self.assertEqual(rules.assign(draft()), rules.assign(draft()))

    def test_candidate_binding_carried(self):
        from aec.assignment import rules

        assignment = rules.assign(draft())
        self.assertEqual(assignment.candidate_id, "rc-abc123")

    def test_rationale_names_rule(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="ssrf"))
        self.assertIn("ssrf", assignment.rationale)
        self.assertIn("server-researcher", assignment.rationale)

    def test_roles_are_closed(self):
        from aec.assignment import rules

        for category in ("idor", "authz", "xss", "ssrf", "file_upload", "cors"):
            self.assertIn(rules.assign(draft(research_category=category)).role, ROLES)

    def test_assignments_are_frozen(self):
        import dataclasses
        from aec.assignment import rules

        with self.assertRaises(dataclasses.FrozenInstanceError):
            rules.assign(draft()).role = "other"


class TestSafetyGuards(unittest.TestCase):
    def test_modules_have_no_network_or_backend_imports(self):
        for name in MODULES:
            tree = ast.parse((ASSIGN_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)


class TestRuleTables(unittest.TestCase):
    def test_full_mapping_table(self):
        from aec.assignment import rules

        expected = {
            "idor": ("authorization_surface", "authorization-researcher"),
            "authz": ("authorization_surface", "authorization-researcher"),
            "xss": ("input_surface", "input-researcher"),
            "file_upload": ("input_surface", "input-researcher"),
            "ssrf": ("server_side_surface", "server-researcher"),
        }
        for category, (surface, role) in expected.items():
            assignment = rules.assign(draft(research_category=category))
            self.assertEqual(assignment.surface, surface, category)
            self.assertEqual(assignment.role, role, category)

    def test_category_case_insensitive(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="IDOR"))
        self.assertEqual(assignment.role, "authorization-researcher")

    def test_missing_category_falls_back(self):
        from aec.assignment import rules

        assignment = rules.assign({"candidate_id": "rc-1"})
        self.assertEqual(assignment.role, "general-researcher")
        self.assertIn("generalist", assignment.rationale)

    def test_non_mapping_candidate_falls_back(self):
        from aec.assignment import rules

        assignment = rules.assign(None)
        self.assertEqual(assignment.candidate_id, "")
        self.assertEqual(assignment.role, "general-researcher")

    def test_draft_object_accepted(self):
        from aec.assignment import rules
        from aec.surface import adapter

        record = {
            "program": "pilot", "subdomain": "example.com", "url": "/s?f=",
            "endpoint": "/s", "parameter": "f", "method": "GET",
            "location": "query", "technology": [], "source": "watch",
            "last_update": None,
        }
        draft_obj = adapter.adapt_record(record, default_category="ssrf").draft
        assignment = rules.assign(draft_obj)
        self.assertEqual(assignment.role, "server-researcher")
        self.assertEqual(assignment.candidate_id, draft_obj.candidate_id)

    def test_assignment_dict_keys(self):
        from aec.assignment import rules

        self.assertEqual(
            sorted(rules.assign(draft()).to_dict()),
            ["candidate_id", "rationale", "role", "surface"],
        )

    def test_fallback_rationale_names_category(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="cors"))
        self.assertIn("cors", assignment.rationale)


    def test_each_rule_rationale_names_surface(self):
        from aec.assignment import rules

        for category, surface in (
            ("idor", "authorization_surface"),
            ("xss", "input_surface"),
            ("ssrf", "server_side_surface"),
        ):
            rationale = rules.assign(draft(research_category=category)).rationale
            self.assertIn(surface, rationale, category)

    def test_whitespace_category_falls_back(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category="   "))
        self.assertEqual(assignment.role, "general-researcher")

    def test_numeric_category_falls_back(self):
        from aec.assignment import rules

        assignment = rules.assign(draft(research_category=42))
        self.assertEqual(assignment.role, "general-researcher")

    def test_public_constants(self):
        from aec.assignment import models

        self.assertEqual(len(models.ROLES), 4)
        self.assertEqual(len(models.SURFACES), 4)


if __name__ == "__main__":
    unittest.main()
