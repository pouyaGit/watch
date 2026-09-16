"""Focused tests for the R71 research evidence acquisition planner.

All tests are offline and pure: the R71 engine consumes an R70 action plan
built by the real R70 planner from validated-hypothesis-shaped mappings. No
provider, Mongo, network or file system access happens here.
"""

from __future__ import annotations

import json
import unittest

from ai.knowledge.research_evidence_acquisition_planner import (
    ACQUISITION_METHODS,
    ACQUISITION_SOURCES,
    DECISION_IMPACT,
    DECISION_IMPACT_STATES,
    MAX_STEPS,
    REQUIREMENT_STATUSES,
    RULE_VERSION,
    SOURCE_ACTION_RULE_VERSION,
    SOURCE_AUTHORIZED_TEST_CONTEXT,
    SOURCE_COMPONENT_METADATA,
    SOURCE_DOCUMENTATION,
    SOURCE_EXISTING_EVIDENCE,
    SOURCE_HUMAN_REVIEW,
    SOURCE_RESPONSE_OBSERVATION,
    SOURCE_VERSION_MAPPING,
    STATUS_AVAILABLE,
    STATUS_MISSING,
    ResearchEvidenceAcquisitionError,
    plan_evidence_acquisition,
)
from ai.knowledge.research_outcome_planner import (
    SAFETY_BLOCK,
    plan_research_actions,
)

PATH_OBJECT = "path:/notifications/api/{id}/getNotificationsCount"
PATH_RECON = "path:/api/v1/jobs/search"
PARAM = "parameter:client"
RESPONSE_REF = "response:jobs-response-1"
AUTH_REF = "authorization:owner-comparison-1"


def observation(ref: str, fact: str = "") -> dict:
    return {
        "ref": ref,
        "fact": fact or f"observed {ref.partition(':')[2]}",
        "source": "context",
    }


def signal(name: str, detail: str = "") -> dict:
    return {"signal": name, "detail": detail, "source": "watch_derived"}


def hypothesis(
    *,
    category: str = "IDOR",
    title: str = "Object reference may cross authorization boundaries",
    priority: str = "MEDIUM",
    confidence: str = "MEDIUM",
    observations: list[dict] | None = None,
    signals: list[dict] | None = None,
    missing: list[str] | None = None,
) -> dict:
    if observations is None:
        observations = [
            observation(PATH_OBJECT),
            observation(PARAM),
        ]
    if signals is None:
        signals = [signal("IDOR", "object_reference=PATH_PARAMETER")]
    return {
        "title": title,
        "category": category,
        "priority": priority,
        "confidence": confidence,
        "evidence": {
            "observations": observations,
            "derived_signals": signals,
        },
        "selected_evidence_refs": ["E1", "E2"],
        "inference": "Structural observation only; behavior was not observed.",
        "why_interesting": "Uncertainty depends on behavior evidence.",
        "missing_evidence": missing
        if missing is not None
        else ["Whether server-side authorization comparisons exist"],
        "next_safe_action": "Review stored records for the endpoint.",
    }


def plan_for(hypotheses, **kwargs):
    return plan_evidence_acquisition(
        plan_research_actions(hypotheses), **kwargs
    )


def requirement_status(plan: dict, kind: str) -> str:
    for entry in plan["required_evidence"]:
        if entry["requirement_kind"] == kind:
            return entry["status"]
    raise AssertionError(f"unknown requirement kind {kind}")


def plan_by_gap(result: dict, gap_id: str) -> dict:
    for plan in result["plans"]:
        if plan["gap_id"] == gap_id:
            return plan
    raise AssertionError(f"no plan for gap {gap_id}")


class TestActionToAcquisitionPlan(unittest.TestCase):
    def test_action_becomes_acquisition_plan(self):
        result = plan_for([hypothesis()])
        self.assertEqual(result["rule_version"], RULE_VERSION)
        self.assertEqual(RULE_VERSION, "r71-1")
        self.assertEqual(
            result["source_action_rule_version"], SOURCE_ACTION_RULE_VERSION
        )
        self.assertEqual(len(result["plans"]), 1)
        plan = result["plans"][0]
        self.assertEqual(plan["plan_id"], "P1")
        self.assertEqual(plan["order"], 1)
        self.assertEqual(plan["action_ref"], "A1")
        self.assertEqual(plan["gap_id"], "OBJECT_AUTHORIZATION")
        self.assertEqual(plan["category"], "IDOR")
        self.assertIn(plan["acquisition_method"], ACQUISITION_METHODS)
        for field in (
            "acquisition_goal",
            "expected_result",
            "stopping_condition",
            "decision_impact_note",
        ):
            self.assertTrue(plan[field], field)
        self.assertEqual(plan["skill_refs"], ["idor-bola"])

    def test_unknown_gap_falls_back_to_additional_evidence(self):
        action_plan = plan_research_actions([hypothesis()])
        action_plan["actions"][0]["gap_id"] = "DOES_NOT_EXIST"
        action_plan["actions"][0]["category"] = "UNKNOWN_CATEGORY"
        result = plan_evidence_acquisition(action_plan)
        self.assertEqual(result["plans"][0]["gap_id"], "ADDITIONAL_EVIDENCE")

    def test_unknown_gap_with_known_category_uses_category_gap(self):
        action_plan = plan_research_actions([hypothesis()])
        action_plan["actions"][0]["gap_id"] = "DOES_NOT_EXIST"
        result = plan_evidence_acquisition(action_plan)
        self.assertEqual(result["plans"][0]["gap_id"], "OBJECT_AUTHORIZATION")

    def test_missing_outcome_fails_safe(self):
        action_plan = plan_research_actions([hypothesis()])
        del action_plan["outcomes"]
        plan = plan_evidence_acquisition(action_plan)["plans"][0]
        for entry in plan["required_evidence"]:
            self.assertEqual(entry["status"], STATUS_MISSING, entry)
            self.assertEqual(entry["evidence"], [], entry)
        self.assertEqual(plan["currently_available_evidence"], [])

    def test_rule_and_safety_flags(self):
        result = plan_for([hypothesis()])
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        self.assertTrue(result["research_only"])
        for plan in result["plans"]:
            self.assertEqual(plan["safety"], SAFETY_BLOCK)
            self.assertEqual(plan["confirmation_state"], "NOT_CONFIRMED")
            self.assertTrue(plan["advisory"])
            self.assertTrue(plan["research_only"])
            self.assertFalse(plan["safety"]["execution_performed"])
            self.assertFalse(plan["safety"]["vulnerability_confirmed"])
            self.assertFalse(plan["safety"]["exploit_authorized"])


class TestEvidenceAvailability(unittest.TestCase):
    def test_existing_evidence_detected_as_available(self):
        plan = plan_for([hypothesis()])["plans"][0]
        self.assertEqual(
            requirement_status(plan, "OBJECT_REFERENCE"), STATUS_AVAILABLE
        )
        self.assertEqual(
            requirement_status(plan, "WATCH_SIGNAL"), STATUS_AVAILABLE
        )
        available = {
            entry["requirement_kind"]
            for entry in plan["currently_available_evidence"]
        }
        self.assertEqual(
            available, {"OBJECT_REFERENCE", "WATCH_SIGNAL"}
        )

    def test_missing_evidence_detected(self):
        plan = plan_for([hypothesis()])["plans"][0]
        self.assertEqual(
            requirement_status(plan, "AUTHORIZATION_OUTCOME"), STATUS_MISSING
        )
        self.assertEqual(
            requirement_status(plan, "OWNERSHIP_BINDING"), STATUS_MISSING
        )
        missing = {
            entry["requirement_kind"] for entry in plan["missing_evidence"]
        }
        self.assertEqual(
            missing, {"AUTHORIZATION_OUTCOME", "OWNERSHIP_BINDING"}
        )

    def test_available_evidence_is_not_requested_again(self):
        enriched = hypothesis(
            observations=[
                observation(PATH_OBJECT),
                observation(PARAM),
                observation(RESPONSE_REF),
                observation(AUTH_REF),
            ]
        )
        plan = plan_for([enriched])["plans"][0]
        for kind in (
            "OBJECT_REFERENCE",
            "AUTHORIZATION_OUTCOME",
            "OWNERSHIP_BINDING",
            "WATCH_SIGNAL",
        ):
            self.assertEqual(
                requirement_status(plan, kind), STATUS_AVAILABLE, kind
            )
        self.assertEqual(plan["missing_evidence"], [])
        self.assertEqual(plan["acquisition_sources"], [SOURCE_EXISTING_EVIDENCE])
        self.assertEqual(len(plan["acquisition_steps"]), 1)
        self.assertIn("No new acquisition is required", plan["expected_result"])
        for step in plan["acquisition_steps"][1:]:
            self.assertNotIn("AUTHORIZATION_OUTCOME", step["requirement_kinds"])

    def test_hypothesis_missing_evidence_is_carried(self):
        plan = plan_for(
            [hypothesis(missing=["Whether the id is user-controlled"])]
        )["plans"][0]
        self.assertIn(
            "Whether the id is user-controlled",
            plan["hypothesis_missing_evidence"],
        )

    def test_parameter_name_is_not_a_flow_artifact(self):
        plan = plan_for(
            [
                hypothesis(
                    category="OAUTH",
                    observations=[
                        observation("parameter:assertion"),
                        observation("path:/account/login"),
                    ],
                    signals=[],
                )
            ]
        )["plans"][0]
        self.assertEqual(
            requirement_status(plan, "FLOW_ARTIFACT"), STATUS_MISSING
        )
        self.assertIn(
            SOURCE_RESPONSE_OBSERVATION, plan["acquisition_sources"]
        )

    def test_evidence_state_is_bounded(self):
        many = hypothesis(
            observations=[
                observation(f"response:response-{index}")
                for index in range(12)
            ],
            signals=[signal("IDOR", f"detail-{index}") for index in range(8)],
        )
        plan = plan_for([many])["plans"][0]
        for entry in plan["required_evidence"]:
            self.assertLessEqual(len(entry["evidence"]), 2)
        self.assertLessEqual(len(plan["required_evidence"]), 6)


class TestCategoryHandling(unittest.TestCase):
    def test_category_aware_sources(self):
        cases = {
            "IDOR": (PATH_OBJECT, "IDOR"),
            "SSRF": ("parameter:url", "SSRF"),
            "XSS": ("parameter:q", "XSS"),
            "SQLI": ("parameter:q", "SQLI"),
            "JWT": ("token:jwt-artifact", "JWT"),
            "OAUTH": ("parameter:state", ""),
            "RECON": (PATH_RECON, "RECON"),
            "CVE_RESEARCH": ("technology:nginx", ""),
        }
        for category, (ref, signal_name) in cases.items():
            with self.subTest(category=category):
                observations = [observation(ref)]
                if category == "CVE_RESEARCH":
                    observations.append(observation("version:1.24.0"))
                signals = (
                    [signal(signal_name, "detail")] if signal_name else []
                )
                result = plan_for(
                    [hypothesis(category=category, observations=observations, signals=signals)]
                )
                plan = result["plans"][0]
                self.assertEqual(plan["category"], category)
                for source in plan["acquisition_sources"]:
                    self.assertIn(source, ACQUISITION_SOURCES)

    def test_cve_plan_never_uses_authorized_test_context(self):
        plan = plan_for(
            [
                hypothesis(
                    category="CVE_RESEARCH",
                    observations=[
                        observation("technology:nginx"),
                        observation("version:1.24.0"),
                    ],
                    signals=[],
                )
            ]
        )["plans"][0]
        self.assertIn(SOURCE_COMPONENT_METADATA, plan["acquisition_sources"])
        self.assertIn(SOURCE_VERSION_MAPPING, plan["acquisition_sources"])
        self.assertIn(SOURCE_DOCUMENTATION, plan["acquisition_sources"])
        self.assertNotIn(
            SOURCE_AUTHORIZED_TEST_CONTEXT, plan["acquisition_sources"]
        )

    def test_idor_plan_uses_behavior_sources(self):
        plan = plan_for([hypothesis()])["plans"][0]
        self.assertIn(SOURCE_RESPONSE_OBSERVATION, plan["acquisition_sources"])
        self.assertIn(
            SOURCE_AUTHORIZED_TEST_CONTEXT, plan["acquisition_sources"]
        )
        self.assertIn(SOURCE_HUMAN_REVIEW, plan["acquisition_sources"])

    def test_skill_refs_follow_category(self):
        cases = {
            "IDOR": "idor-bola",
            "SSRF": "ssrf",
            "XSS": "xss",
            "SQLI": "sqli",
            "JWT": "jwt",
            "OAUTH": "oauth",
            "RECON": "api-security",
            "CVE_RESEARCH": "cve-research",
        }
        for category, skill_id in cases.items():
            with self.subTest(category=category):
                plan = plan_for([hypothesis(category=category)])["plans"][0]
                self.assertEqual(plan["skill_refs"], [skill_id])


class TestOrderingAndCorrelation(unittest.TestCase):
    def test_shared_gap_is_correlated(self):
        result = plan_for(
            [
                hypothesis(title="First IDOR"),
                hypothesis(title="Second IDOR"),
            ]
        )
        self.assertEqual(len(result["plans"]), 1)
        plan = result["plans"][0]
        self.assertEqual(plan["hypothesis_refs"], ["H1", "H2"])
        self.assertEqual(plan["hypothesis_count"], 2)
        self.assertEqual(
            plan["acquisition_priority"]["reuse_hypotheses"], 2
        )

    def test_deterministic_ordering(self):
        hypotheses = [
            hypothesis(category="RECON", observations=[observation(PATH_RECON)], signals=[signal("RECON", "api_type=REST")]),
            hypothesis(category="CVE_RESEARCH", observations=[observation("technology:nginx"), observation("version:1.24.0")], signals=[]),
            hypothesis(),
        ]
        first = plan_for(hypotheses)
        second = plan_for(hypotheses)
        self.assertEqual(json.dumps(first), json.dumps(second))
        order = [plan["gap_id"] for plan in first["plans"]]
        self.assertEqual(
            order, ["OBJECT_AUTHORIZATION", "ENDPOINT_BEHAVIOR", "COMPONENT_MAPPING"]
        )
        self.assertEqual(
            [plan["plan_id"] for plan in first["plans"]], ["P1", "P2", "P3"]
        )

    def test_steps_are_ordered_by_gain_and_risk(self):
        plan = plan_for([hypothesis()])["plans"][0]
        steps = plan["acquisition_steps"]
        self.assertEqual(steps[0]["source"], SOURCE_EXISTING_EVIDENCE)
        self.assertEqual(steps[0]["information_gain"], 0)
        gains = [
            step["information_gain"] for step in steps[1:]
        ]
        self.assertEqual(gains, sorted(gains, reverse=True))
        for step in steps[1:]:
            self.assertLessEqual(len(step["requirement_kinds"]), 1)
            self.assertTrue(step["depends_on"])

    def test_bounds_are_enforced(self):
        hypotheses = [
            hypothesis(
                title=f"IDOR {index}",
                observations=[
                    observation(PATH_OBJECT),
                    observation(PARAM),
                    observation(f"response:r{index}"),
                    observation(f"authorization:a{index}"),
                ],
            )
            for index in range(4)
        ]
        result = plan_for(hypotheses)
        for plan in result["plans"]:
            self.assertLessEqual(len(plan["acquisition_steps"]), MAX_STEPS)
            self.assertLessEqual(
                len(plan["acquisition_sources"]), len(ACQUISITION_SOURCES)
            )
        self.assertEqual(result["summary"]["plan_count"], 1)


class TestDecisionImpactAndSafety(unittest.TestCase):
    def test_decision_impact_is_bounded_and_predictive(self):
        plan = plan_for([hypothesis()])["plans"][0]
        self.assertEqual(plan["decision_impact"], DECISION_IMPACT)
        for state in plan["decision_impact"].values():
            self.assertIn(state, DECISION_IMPACT_STATES)
        self.assertIn("Prediction only", plan["decision_impact_note"])
        self.assertIn("nothing is confirmed", plan["decision_impact_note"])

    def test_statuses_are_closed(self):
        plan = plan_for([hypothesis()])["plans"][0]
        for entry in plan["required_evidence"]:
            self.assertIn(entry["status"], REQUIREMENT_STATUSES)

    def test_stopping_condition_is_always_present(self):
        for category in (
            "IDOR",
            "SSRF",
            "XSS",
            "SQLI",
            "JWT",
            "OAUTH",
            "RECON",
            "CVE_RESEARCH",
        ):
            with self.subTest(category=category):
                plan = plan_for([hypothesis(category=category)])["plans"][0]
                self.assertTrue(plan["stopping_condition"])
                self.assertTrue(plan["expected_result"])

    def test_no_execution_vocabulary_in_output(self):
        hypotheses = [
            hypothesis(),
            hypothesis(
                category="CVE_RESEARCH",
                observations=[
                    observation("technology:nginx"),
                    observation("version:1.24.0"),
                ],
                signals=[],
            ),
        ]
        text = json.dumps(plan_for(hypotheses)).lower()
        for forbidden in (
            "payload",
            "curl ",
            "sqlmap",
            "nuclei",
            "http://",
            "https://",
            "://",
            "post /",
            "get /",
            "send a request",
            "attack ",
        ):
            self.assertNotIn(forbidden, text, forbidden)

    def test_sensitive_facts_are_redacted_and_bounded(self):
        secret_fact = "authorization token=supersecretvalue12345"
        plan = plan_for(
            [
                hypothesis(
                    observations=[
                        observation(PATH_OBJECT),
                        observation("authorization:token=supersecretvalue12345", secret_fact),
                    ]
                )
            ]
        )["plans"][0]
        text = json.dumps(plan)
        self.assertNotIn("supersecretvalue12345", text)
        self.assertIn("[redacted]", text)
        for entry in plan["required_evidence"]:
            for evidence in entry["evidence"]:
                for value in evidence.values():
                    self.assertLessEqual(len(str(value)), 320)

    def test_empty_input_is_safe(self):
        result = plan_evidence_acquisition(None)
        self.assertEqual(result["plans"], [])
        self.assertEqual(result["summary"]["plan_count"], 0)
        self.assertEqual(result["safety"], SAFETY_BLOCK)
        malformed = plan_evidence_acquisition(["not-a-mapping", 42])
        self.assertEqual(malformed["plans"], [])

    def test_limit_is_validated_and_applied(self):
        action_plan = plan_research_actions(
            [
                hypothesis(),
                hypothesis(
                    category="RECON",
                    observations=[observation(PATH_RECON)],
                    signals=[signal("RECON", "api_type=REST")],
                ),
            ]
        )
        limited = plan_evidence_acquisition(action_plan, limit=1)
        self.assertEqual(len(limited["plans"]), 1)
        self.assertEqual(limited["plans"][0]["plan_id"], "P1")
        empty = plan_evidence_acquisition(action_plan, limit=0)
        self.assertEqual(empty["plans"], [])
        with self.assertRaises(ResearchEvidenceAcquisitionError):
            plan_evidence_acquisition(action_plan, limit=-1)
        with self.assertRaises(ResearchEvidenceAcquisitionError):
            plan_evidence_acquisition(action_plan, limit=True)

    def test_summary_reports_availability(self):
        result = plan_for([hypothesis()])
        summary = result["summary"]
        self.assertEqual(summary["plan_count"], 1)
        self.assertEqual(summary["covered_actions"], 1)
        self.assertEqual(summary["covered_hypotheses"], 1)
        self.assertEqual(summary["requirements_available"], 2)
        self.assertEqual(summary["requirements_missing"], 2)
        self.assertEqual(summary["risk_bands"]["LOW"], 0)
        self.assertEqual(summary["risk_bands"]["MEDIUM"], 1)
        self.assertEqual(summary["confirmation_state"], "NOT_CONFIRMED")


if __name__ == "__main__":
    unittest.main()
