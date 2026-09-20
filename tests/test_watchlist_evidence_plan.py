"""Focused tests for the local watchlist evidence acquisition planner.

No MongoDB, no network, no VPS, no production, no real Dell watchlist
execution, no acquisition executed. The planner consumes evidence-gap
payloads produced by the existing gap layer over supplied structured data.
"""

from __future__ import annotations

import argparse
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ai.research_agent.watchlist_evidence_gaps import (
    COMPONENT_IDENTITY,
    COMPONENT_PROVENANCE,
    INSUFFICIENT_EVIDENCE,
    MISSING,
    NOT_APPLICABLE,
    PARTIAL,
    PRESENT,
    TECHNOLOGY_IDENTITY,
    VERSION_ASSOCIATION,
    VERSION_IDENTITY,
    analyze_candidate,
)
from ai.research_agent.watchlist_evidence_plan import (
    ACQUIRE_APPLICATION_RESPONSE,
    ACQUIRE_SOURCE_ASSET_EVIDENCE,
    BLOCKING,
    INSPECT_COMPONENT_PROVENANCE,
    INSPECT_INVENTORY,
    INSPECT_TECHNOLOGY_EVIDENCE,
    INSPECT_VERSION_EVIDENCE,
    METHODS,
    PLAN_NOT_REQUIRED,
    PLAN_PLANNED,
    PRIORITIES,
    REQUIRED,
    SOURCES,
    SUPPORTING,
    build_acquisition_plan,
    build_snapshot_acquisition_plan,
)


def make_entry(**overrides):
    entry = {
        "cve_id": "CVE-2020-11022",
        "program": "dell",
        "match_state": "SUPPORTED",
        "confidence": "MEDIUM",
        "strongest_match_type": "COMPONENT",
        "strongest_confidence": "MEDIUM",
        "matched_component": "jquery",
        "matched_version": "1.12.4",
        "matched_parameter": "",
        "match_summary": "Component and version observed in inventory.",
        "research_status": "NOT YET SUFFICIENT",
        "version_state": "MATCH",
        "version_association_state": "VERSION_MATCH_WITHIN_SAME_FAMILY",
        "version_association_reason": "",
        "resolved_blockers": [],
        "remaining_blockers": [],
        "missing": [],
        "match_row_count": 3,
        "match_rows": [
            {
                "match_id": "am-" + "1" * 16,
                "match_type": "TECHNOLOGY",
                "matched_value": "JavaScript",
                "confidence": "MEDIUM",
            },
            {
                "match_id": "am-" + "2" * 16,
                "match_type": "COMPONENT",
                "matched_value": "jquery",
                "confidence": "MEDIUM",
            },
            {
                "match_id": "am-" + "3" * 16,
                "match_type": "VERSION",
                "matched_value": "1.12.4",
                "confidence": "MEDIUM",
            },
        ],
        "queue": {
            "present": True,
            "queue_id": "rq-" + "a" * 16,
            "relevance": "MEDIUM",
            "relevance_score": 40,
            "priority_class": "MEDIUM_RESEARCH",
            "priority_score": 50,
            "queue_score": 45,
            "blockers": [],
            "reasons": ["technology match"],
            "unknown_factors": [],
        },
        "fingerprint": "wf-" + "0" * 16,
        "delta": "UNCHANGED",
    }
    entry.update(overrides)
    return entry


def dell_shaped_entry():
    """Static Dell-shaped fixture mirroring local snapshot content.

    WordPress technology observed via a generic-only match; no component
    binding; no version identity; family-mismatch association; CVE watch
    signal present. Mirrors the structure of local snapshot entries without
    reading production data or running watchlist logic.
    """
    return make_entry(
        cve_id="CVE-2026-1557",
        match_state="WEAK",
        strongest_match_type="TECHNOLOGY",
        matched_component="",
        matched_version="",
        matched_parameter="src",
        match_summary=(
            "Technology match exists, but affected component is not observed."
        ),
        version_state="UNKNOWN",
        version_association_state="FAMILY_MISMATCH",
        version_association_reason="observed version family mismatch",
        remaining_blockers=[
            "generic_technology_only",
            "plugin_not_observed",
            "component_not_observed",
            "version_unknown",
        ],
        missing=["PRODUCT", "COMPONENT", "PLUGIN", "VERSION", "PATH"],
        match_row_count=2,
        match_rows=[
            {
                "match_id": "am-6801b0d58e95c2d0",
                "match_type": "PARAMETER",
                "matched_value": "src",
                "confidence": "MEDIUM",
            },
            {
                "match_id": "am-2cf8fb279dde4632",
                "match_type": "TECHNOLOGY",
                "matched_value": "WordPress",
                "confidence": "MEDIUM",
            },
        ],
        queue={
            "present": True,
            "queue_id": "rq-075e9ef25c8f94a7",
            "relevance": "LOW",
            "relevance_score": 20,
            "priority_class": "CRITICAL_RESEARCH",
            "priority_score": 80,
            "queue_score": 56,
            "blockers": ["only generic technology match"],
            "reasons": ["critical research priority"],
            "unknown_factors": ["asset component/path not observed"],
        },
    )


def steps_for(plan, evidence_type):
    return [
        step for step in plan["steps"] if step["evidence_type"] == evidence_type
    ]


class TestEvidencePlan(unittest.TestCase):
    def test_01_fully_sufficient_evidence_empty_plan(self):
        plan = build_acquisition_plan(analyze_candidate(make_entry()))
        self.assertEqual(plan["steps"], [])
        self.assertEqual(plan["deferred"], [])
        self.assertEqual(plan["plan_state"], PLAN_NOT_REQUIRED)
        self.assertEqual(
            plan["priority_counts"],
            {BLOCKING: 0, REQUIRED: 0, SUPPORTING: 0},
        )

    def test_02_missing_component_plan(self):
        gap = analyze_candidate(
            make_entry(
                matched_component="",
                match_rows=[
                    {
                        "match_id": "am-" + "1" * 16,
                        "match_type": "TECHNOLOGY",
                        "matched_value": "jQuery",
                        "confidence": "MEDIUM",
                    }
                ],
                version_association_state="",
            )
        )
        plan = build_acquisition_plan(gap)
        component_steps = steps_for(plan, COMPONENT_IDENTITY)
        self.assertTrue(component_steps)
        for step in component_steps:
            self.assertEqual(step["priority"], BLOCKING)
            self.assertEqual(step["dimension_state"], MISSING)
        methods = [step["method"] for step in component_steps]
        self.assertIn(INSPECT_INVENTORY, methods)
        self.assertIn(INSPECT_TECHNOLOGY_EVIDENCE, methods)
        self.assertIn(ACQUIRE_APPLICATION_RESPONSE, methods)
        self.assertIn(ACQUIRE_SOURCE_ASSET_EVIDENCE, methods)
        self.assertEqual(plan["plan_state"], PLAN_PLANNED)
        self.assertEqual(plan["finding_readiness"], INSUFFICIENT_EVIDENCE)

    def test_03_missing_version_plan(self):
        gap = analyze_candidate(
            make_entry(
                matched_version="",
                version_state="UNKNOWN",
                version_association_state="",
                match_rows=[
                    {
                        "match_id": "am-" + "2" * 16,
                        "match_type": "COMPONENT",
                        "matched_value": "jquery",
                        "confidence": "MEDIUM",
                    }
                ],
            )
        )
        plan = build_acquisition_plan(gap)
        version_steps = steps_for(plan, VERSION_IDENTITY)
        self.assertTrue(version_steps)
        methods = [step["method"] for step in version_steps]
        self.assertIn(INSPECT_INVENTORY, methods)
        self.assertIn(INSPECT_VERSION_EVIDENCE, methods)
        self.assertEqual(version_steps[0]["priority"], BLOCKING)
        for step in version_steps:
            self.assertTrue(step["stop_condition"])

    def test_04_component_and_version_missing_ordered(self):
        gap = analyze_candidate(
            make_entry(
                matched_component="",
                matched_version="",
                version_state="UNKNOWN",
                version_association_state="",
                match_rows=[
                    {
                        "match_id": "am-" + "1" * 16,
                        "match_type": "TECHNOLOGY",
                        "matched_value": "jQuery",
                        "confidence": "MEDIUM",
                    }
                ],
            )
        )
        plan = build_acquisition_plan(gap)
        types = [step["evidence_type"] for step in plan["steps"]]
        self.assertIn(COMPONENT_IDENTITY, types)
        self.assertIn(VERSION_IDENTITY, types)
        self.assertLess(
            max(i for i, t in enumerate(types) if t == COMPONENT_IDENTITY),
            min(i for i, t in enumerate(types) if t == VERSION_IDENTITY),
        )
        ranks = {BLOCKING: 0, REQUIRED: 1, SUPPORTING: 2}
        priorities = [ranks[step["priority"]] for step in plan["steps"]]
        self.assertEqual(priorities, sorted(priorities))
        version_first = steps_for(plan, VERSION_IDENTITY)[0]
        self.assertIn(
            "component identity is deterministically bound to the observed asset",
            version_first["preconditions"],
        )

    def test_05_technology_only_wordpress_no_fabricated_result(self):
        plan = build_acquisition_plan(analyze_candidate(dell_shaped_entry()))
        blob = json.dumps(plan, sort_keys=True).lower()
        self.assertNotIn("wordpress", blob)
        self.assertNotIn("plugin is installed", blob)
        self.assertNotIn("component is present", blob)
        self.assertNotIn("exploitable", blob)
        self.assertEqual(plan["finding_readiness"], INSUFFICIENT_EVIDENCE)
        component_steps = steps_for(plan, COMPONENT_IDENTITY)
        self.assertTrue(component_steps)
        self.assertEqual(
            plan["priority_counts"][BLOCKING],
            len(component_steps) + len(steps_for(plan, VERSION_IDENTITY)),
        )
        self.assertTrue(
            all(step["dimension_state"] == MISSING for step in component_steps)
        )

    def test_06_family_association_without_ownership(self):
        plan = build_acquisition_plan(analyze_candidate(dell_shaped_entry()))
        association_steps = steps_for(plan, VERSION_ASSOCIATION)
        self.assertTrue(association_steps)
        self.assertEqual(association_steps[0]["dimension_state"], PARTIAL)
        self.assertIn(
            "identified component", association_steps[0]["stop_condition"]
        )
        # Ownership is never claimed; component identity remains a gap.
        self.assertTrue(steps_for(plan, COMPONENT_IDENTITY))
        blob = json.dumps(plan, sort_keys=True).lower()
        self.assertNotIn("ownership is established", blob)
        self.assertNotIn("ownership confirmed", blob)
        self.assertEqual(plan["finding_readiness"], INSUFFICIENT_EVIDENCE)

    def test_07_partial_evidence_targeted_steps_only(self):
        plan = build_acquisition_plan(analyze_candidate(dell_shaped_entry()))
        technology_steps = steps_for(plan, TECHNOLOGY_IDENTITY)
        self.assertEqual(len(technology_steps), 1)
        self.assertEqual(technology_steps[0]["dimension_state"], PARTIAL)
        self.assertEqual(
            technology_steps[0]["method"], INSPECT_TECHNOLOGY_EVIDENCE
        )
        self.assertEqual(technology_steps[0]["priority"], REQUIRED)
        self.assertIn("component-specific", technology_steps[0]["stop_condition"])
        match_steps = steps_for(plan, "MATCH_STATE")
        self.assertEqual(len(match_steps), 1)
        self.assertEqual(match_steps[0]["dimension_state"], PARTIAL)
        self.assertEqual(match_steps[0]["method"], ACQUIRE_APPLICATION_RESPONSE)

    def test_08_not_applicable_no_step(self):
        gap = analyze_candidate(dell_shaped_entry())
        self.assertIn(COMPONENT_PROVENANCE, gap["not_applicable"])
        plan = build_acquisition_plan(gap)
        self.assertEqual(steps_for(plan, COMPONENT_PROVENANCE), [])
        self.assertEqual(
            [item["evidence_type"] for item in plan["deferred"]],
            [],
        )
        # And a direct synthetic payload with NOT_APPLICABLE yields no step.
        payload = {
            "cve_id": "CVE-2020-0001",
            "finding_readiness": INSUFFICIENT_EVIDENCE,
            "dimensions": [
                {
                    "evidence_type": "COMPONENT_PROVENANCE",
                    "state": NOT_APPLICABLE,
                    "reason": "not applicable",
                    "acquisition_strategy": None,
                },
                {
                    "evidence_type": "VERSION_ASSOCIATION",
                    "state": NOT_APPLICABLE,
                    "reason": "not applicable",
                    "acquisition_strategy": None,
                },
            ],
        }
        plan = build_acquisition_plan(payload)
        self.assertEqual(plan["steps"], [])
        self.assertEqual(plan["deferred"], [])
        self.assertEqual(plan["plan_state"], "NO_ACTIONABLE_STEPS")

    def test_09_deterministic_output(self):
        gap = analyze_candidate(dell_shaped_entry())
        first = build_acquisition_plan(gap)
        second = build_acquisition_plan(gap)
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_10_stable_step_ids(self):
        gap = analyze_candidate(dell_shaped_entry())
        first = build_acquisition_plan(gap)
        second = build_acquisition_plan(copy.deepcopy(gap))
        ids_first = [step["step_id"] for step in first["steps"]]
        ids_second = [step["step_id"] for step in second["steps"]]
        self.assertEqual(ids_first, ids_second)
        self.assertEqual(len(ids_first), len(set(ids_first)))
        # Reordering the dimension list must not change the plan.
        shuffled = dict(gap)
        shuffled["dimensions"] = list(reversed(list(gap["dimensions"])))
        third = build_acquisition_plan(shuffled)
        self.assertEqual(ids_first, [step["step_id"] for step in third["steps"]])

    def test_11_stop_conditions_present(self):
        plan = build_acquisition_plan(analyze_candidate(dell_shaped_entry()))
        self.assertTrue(plan["steps"])
        for step in plan["steps"]:
            self.assertTrue(step["stop_condition"].strip())
            self.assertTrue(step["objective"].strip())
            self.assertIn(step["method"], METHODS)
            self.assertIn(step["source"], SOURCES)
            self.assertIn(step["priority"], PRIORITIES)

    def test_12_unknown_fields_do_not_create_steps(self):
        entry = dell_shaped_entry()
        entry["exploitable"] = True
        entry["confirmed"] = True
        entry["fake_dimensions"] = [{"evidence_type": "MADE_UP", "state": MISSING}]
        plan = build_acquisition_plan(analyze_candidate(entry))
        types = {step["evidence_type"] for step in plan["steps"]}
        self.assertNotIn("MADE_UP", types)
        blob = json.dumps(plan, sort_keys=True).lower()
        self.assertNotIn("exploitable", blob)
        self.assertNotIn("fake_dimensions", blob)
        # Direct junk dimension payloads are ignored too.
        payload = {
            "cve_id": "CVE-2020-0001",
            "finding_readiness": INSUFFICIENT_EVIDENCE,
            "dimensions": [
                {
                    "evidence_type": "MADE_UP",
                    "state": MISSING,
                    "reason": "junk",
                    "acquisition_strategy": "do something",
                }
            ],
        }
        plan = build_acquisition_plan(payload)
        self.assertEqual(plan["steps"], [])

    def test_13_empty_candidate_deterministic_plan(self):
        first = build_acquisition_plan({})
        second = build_acquisition_plan(None)
        self.assertEqual(first, second)
        self.assertEqual(first["cve_id"], "")
        self.assertGreater(first["step_count"], 0)
        self.assertEqual(first["plan_state"], PLAN_PLANNED)
        # Provenance is NOT_APPLICABLE without a component, so no step and
        # nothing deferred.
        self.assertEqual(steps_for(first, COMPONENT_PROVENANCE), [])
        self.assertEqual(first["deferred"], [])

    def test_14_snapshot_level_planning(self):
        snapshot = {
            "snapshot_id": "watch-20260918T144218Z",
            "program": "dell",
            "entries": [dell_shaped_entry(), make_entry()],
        }
        first = build_snapshot_acquisition_plan(snapshot)
        second = build_snapshot_acquisition_plan(snapshot)
        self.assertEqual(first, second)
        self.assertEqual(first["cve_count"], 2)
        self.assertEqual(
            [item["cve_id"] for item in first["candidates"]],
            sorted(item["cve_id"] for item in first["candidates"]),
        )
        self.assertEqual(
            first["plan_counts"][PLAN_PLANNED],
            1,
        )
        self.assertEqual(
            first["plan_counts"][PLAN_NOT_REQUIRED],
            1,
        )
        readied = next(
            item
            for item in first["candidates"]
            if item["cve_id"] == "CVE-2020-11022"
        )
        self.assertEqual(readied["plan_state"], PLAN_NOT_REQUIRED)

    def test_15_no_mutation_of_gap_payload(self):
        gap = analyze_candidate(dell_shaped_entry())
        before = copy.deepcopy(gap)
        build_acquisition_plan(gap)
        self.assertEqual(gap, before)

    def test_16_provenance_partial_without_component_is_deferred(self):
        payload = {
            "cve_id": "CVE-2020-0001",
            "finding_readiness": INSUFFICIENT_EVIDENCE,
            "dimensions": [
                {
                    "evidence_type": COMPONENT_IDENTITY,
                    "state": MISSING,
                    "reason": "no component identity bound",
                    "acquisition_strategy": "inspect existing inventory",
                },
                {
                    "evidence_type": COMPONENT_PROVENANCE,
                    "state": PARTIAL,
                    "reason": "component-level signal without provenance",
                    "acquisition_strategy": "inspect component provenance",
                },
            ],
        }
        plan = build_acquisition_plan(payload)
        self.assertEqual(steps_for(plan, COMPONENT_PROVENANCE), [])
        self.assertEqual(
            [item["evidence_type"] for item in plan["deferred"]],
            [COMPONENT_PROVENANCE],
        )
        self.assertTrue(steps_for(plan, COMPONENT_IDENTITY))


class TestEvidencePlanCli(unittest.TestCase):
    def _snapshot(self):
        return {
            "snapshot_id": "watch-20260918T144218Z",
            "program": "dell",
            "entries": [dell_shaped_entry()],
        }

    def test_cli_parses_evidence_plan(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(
            ["agent", "evidence-plan", "--program", "dell", "--json"]
        )
        self.assertEqual(args.command, "agent")
        self.assertEqual(args.agent_command, "evidence-plan")
        self.assertEqual(args.program, "dell")
        self.assertTrue(args.json)

    def test_cli_is_read_only(self):
        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "watchlist"
            program_dir = root / "dell"
            program_dir.mkdir(parents=True)
            (program_dir / "watch-20260918T144218Z.json").write_text(
                json.dumps(self._snapshot()), encoding="utf-8"
            )
            before = sorted(path.name for path in program_dir.iterdir())
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_evidence_plan(
                    argparse.Namespace(
                        program="dell",
                        snapshot_root=str(root),
                        snapshot_id="",
                        cve="",
                        json=True,
                    )
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["cve_count"], 1)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["cve_id"], "CVE-2026-1557")
            self.assertTrue(candidate["steps"])
            self.assertEqual(
                candidate["finding_readiness"], INSUFFICIENT_EVIDENCE
            )
            after = sorted(path.name for path in program_dir.iterdir())
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
