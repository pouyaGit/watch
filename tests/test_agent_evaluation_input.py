"""tests/test_agent_evaluation_input.py — Stage R42.1 tests.

Deterministic, offline tests for the agent evaluation input:

- valid R38-compatible / specialist result projection
- malformed input handling and structural flags
- required-field validation, enum validation, version validation
- research_only preservation (including False)
- provenance layer validation, non-deterministic marker detection
- explicit agent id/category overrides
- JSON serialization and idempotence

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.agent_evaluation_input import (
    build_agent_evaluation_input,
    evaluation_context_fact_count,
)
from ai.schemas import agent_evaluation_input as schema


def rich_result(**over):
    result = {
        "rule_version": "r39-5",
        "agent_identity": {
            "rule_version": "r39-1",
            "agent_id": "sa-" + "a" * 16,
            "agent_name": "xss-agent",
            "category": "XSS",
            "version": "2.0",
            "maturity": "RESEARCH",
            "supported_contexts": ["REFLECTED"],
            "supported_capabilities": ["ANALYZE_CONTEXT"],
            "lifecycle_state": "PLANNED",
            "limitations": ["NO_EXECUTION_CAPABILITY"],
            "research_only": True,
        },
        "status": "COMPLETED",
        "confidence": "HIGH",
        "context_analysis": {
            "input_location": "QUERY",
            "output_context": "HTML",
            "reflection_state": "REFLECTED",
            "encoding_state": "NONE_OBSERVED",
            "framework_context": "GENERIC",
            "context_confidence": "HIGH",
        },
        "hypotheses": [
            {
                "rule_version": "r39-3",
                "hypothesis_type": "REFLECTION_ANALYSIS",
                "supporting_signals": ["REFLECTION_OBSERVED"],
                "confidence": "HIGH",
                "priority": "HIGH",
                "limitations": [
                    "NO_EXPLOIT_CLAIM",
                    "NO_VULNERABILITY_CONFIRMATION",
                    "HYPOTHESIS_ONLY",
                    "EVIDENCE_REQUIRED",
                ],
                "research_only": True,
            }
        ],
        "evidence_plan": {
            "rule_version": "r39-4",
            "evidence_items": ["REFLECTION_CONTEXT"],
            "evidence_state": "COMPLETE",
            "confidence": "HIGH",
            "limitations": ["NO_COLLECTION_PERFORMED", "EVIDENCE_REQUIRED"],
            "research_only": True,
        },
        "limitations": [
            "NO_EXECUTION_PERFORMED",
            "NO_PAYLOAD_GENERATION",
            "NO_VULNERABILITY_CONFIRMATION",
            "HYPOTHESIS_ONLY",
            "EVIDENCE_REQUIRED",
        ],
        "provenance": {
            "rule_version": "r40-5",
            "source_layers": ["REASONING", "MEMORY"],
            "provenance_state": "PARTIAL",
            "research_only": True,
        },
        "governance_reference": {
            "rule_version": "r37-5",
            "ready": True,
            "provenance_state": "COMPLETE",
            "trace_state": "COMPLETE",
            "audit_state": "VALID",
            "explanation_state": "COMPLETE",
            "reference_state": "REFERENCED",
        },
        "research_only": True,
    }
    result.update(over)
    return result


class TestAgentEvaluationInput(unittest.TestCase):
    def test_valid_result_projection(self):
        plan = build_agent_evaluation_input(rich_result())
        self.assertEqual(plan["rule_version"], "r42-1")
        self.assertEqual(plan["agent_category"], "XSS")
        self.assertEqual(plan["agent_id"], "sa-" + "a" * 16)
        self.assertEqual(plan["agent_rule_version"], "r39-1")
        self.assertEqual(plan["result_rule_version"], "r39-5")
        self.assertEqual(plan["result_status"], "COMPLETED")
        self.assertEqual(plan["result_confidence"], "HIGH")
        self.assertEqual(len(plan["hypotheses"]), 1)
        self.assertEqual(
            plan["evidence_plan"]["evidence_state"], "COMPLETE"
        )
        self.assertEqual(
            plan["provenance"]["provenance_state"], "PARTIAL"
        )
        self.assertEqual(
            plan["governance_reference"]["reference_state"], "REFERENCED"
        )
        self.assertIs(plan["research_only"], True)
        self.assertEqual(plan["structural_flags"], [])

    def test_real_specialist_results(self):
        from ai.knowledge.ssrf_agent_result_export import (
            export_ssrf_agent_result,
        )
        from ai.knowledge.sqli_agent_result_export import (
            export_sqli_agent_result,
        )

        ssrf = build_agent_evaluation_input(export_ssrf_agent_result())
        self.assertEqual(ssrf["agent_category"], "SSRF")
        self.assertEqual(ssrf["result_rule_version"], "r40-5")
        self.assertEqual(ssrf["structural_flags"], [])

        sqli = build_agent_evaluation_input(export_sqli_agent_result())
        self.assertEqual(sqli["agent_category"], "SQLI")
        self.assertEqual(sqli["result_rule_version"], "r41-5")
        self.assertEqual(sqli["structural_flags"], [])

    def test_malformed_inputs_do_not_crash(self):
        for bad in (None, "", 42, [], "NOPE"):
            plan = build_agent_evaluation_input(bad)
            self.assertEqual(plan["agent_category"], "UNKNOWN")
            self.assertIn(
                "MISSING_REQUIRED_FIELD", plan["structural_flags"]
            )
            self.assertIs(plan["research_only"], True)

    def test_missing_required_fields_flagged(self):
        for key in ("rule_version", "status", "confidence",
                    "hypotheses", "evidence_plan", "limitations",
                    "provenance", "governance_reference"):
            raw = rich_result()
            del raw[key]
            plan = build_agent_evaluation_input(raw)
            self.assertIn(
                "MISSING_REQUIRED_FIELD",
                plan["structural_flags"],
                key,
            )

    def test_invalid_rule_version_flagged(self):
        raw = rich_result(rule_version="bogus")
        plan = build_agent_evaluation_input(raw)
        self.assertIn("INVALID_RULE_VERSION", plan["structural_flags"])
        raw = rich_result()
        raw["agent_identity"]["rule_version"] = "nope"
        plan = build_agent_evaluation_input(raw)
        self.assertIn("INVALID_RULE_VERSION", plan["structural_flags"])

    def test_invalid_enum_values_flagged(self):
        raw = rich_result(status="FINISHED", confidence="CERTAIN")
        plan = build_agent_evaluation_input(raw)
        self.assertIn("INVALID_ENUM_VALUE", plan["structural_flags"])
        raw = rich_result()
        raw["hypotheses"][0]["confidence"] = "CERTAIN"
        plan = build_agent_evaluation_input(raw)
        self.assertIn("INVALID_ENUM_VALUE", plan["structural_flags"])

    def test_unknown_and_invalid_category_flagged(self):
        raw = rich_result()
        del raw["agent_identity"]["category"]
        plan = build_agent_evaluation_input(raw)
        self.assertEqual(plan["agent_category"], "UNKNOWN")
        self.assertIn("UNKNOWN_AGENT_CATEGORY", plan["structural_flags"])

        plan = build_agent_evaluation_input(
            rich_result(), agent_category="NOPE"
        )
        self.assertEqual(plan["agent_category"], "UNKNOWN")
        self.assertIn("INVALID_ENUM_VALUE", plan["structural_flags"])

    def test_explicit_overrides(self):
        raw = rich_result()
        del raw["agent_identity"]
        plan = build_agent_evaluation_input(
            raw, agent_id="sa-" + "b" * 16, agent_category="SSRF"
        )
        self.assertEqual(plan["agent_id"], "sa-" + "b" * 16)
        self.assertEqual(plan["agent_category"], "SSRF")
        self.assertNotIn(
            "MISSING_REQUIRED_FIELD", plan["structural_flags"]
        )

    def test_malformed_hypotheses_flagged(self):
        raw = rich_result(hypotheses="nope")
        plan = build_agent_evaluation_input(raw)
        self.assertIn("MALFORMED_HYPOTHESIS", plan["structural_flags"])

        raw = rich_result(hypotheses=[{"confidence": "HIGH"}])
        plan = build_agent_evaluation_input(raw)
        self.assertIn("MALFORMED_HYPOTHESIS", plan["structural_flags"])
        self.assertEqual(plan["hypotheses"], [])

    def test_malformed_evidence_plan_flagged(self):
        raw = rich_result(evidence_plan="nope")
        plan = build_agent_evaluation_input(raw)
        self.assertIn(
            "MALFORMED_EVIDENCE_PLAN", plan["structural_flags"]
        )

    def test_malformed_limitations_flagged(self):
        raw = rich_result(limitations="nope")
        plan = build_agent_evaluation_input(raw)
        self.assertIn(
            "MALFORMED_LIMITATIONS", plan["structural_flags"]
        )

    def test_malformed_provenance_and_governance_flagged(self):
        raw = rich_result(provenance="nope")
        plan = build_agent_evaluation_input(raw)
        self.assertIn(
            "MALFORMED_PROVENANCE", plan["structural_flags"]
        )
        raw = rich_result(governance_reference="nope")
        plan = build_agent_evaluation_input(raw)
        self.assertIn(
            "MALFORMED_GOVERNANCE", plan["structural_flags"]
        )

    def test_invented_provenance_layer_flagged(self):
        raw = rich_result()
        raw["provenance"] = {
            "rule_version": "r40-5",
            "source_layers": ["REASONING", "INVENTED_LAYER"],
            "provenance_state": "PARTIAL",
            "research_only": True,
        }
        plan = build_agent_evaluation_input(raw)
        self.assertIn(
            "PROVENANCE_INVENTED_LAYER", plan["structural_flags"]
        )
        self.assertEqual(
            plan["provenance"]["source_layers"], ["REASONING"]
        )

    def test_nondeterministic_markers_flagged(self):
        raw = rich_result()
        raw["evaluated_at"] = "now"
        plan = build_agent_evaluation_input(raw)
        self.assertIn(
            "NON_DETERMINISTIC_OUTPUT", plan["structural_flags"]
        )
        raw = rich_result()
        raw["hypotheses"][0]["runtime_id"] = "abc"
        plan = build_agent_evaluation_input(raw)
        self.assertIn(
            "NON_DETERMINISTIC_OUTPUT", plan["structural_flags"]
        )

    def test_research_only_preserved(self):
        plan = build_agent_evaluation_input(
            rich_result(research_only=False)
        )
        self.assertIs(plan["research_only"], False)

    def test_deterministic_and_idempotent(self):
        raw = rich_result()
        first = build_agent_evaluation_input(raw)
        second = build_agent_evaluation_input(raw)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        third = build_agent_evaluation_input(raw)
        self.assertEqual(first["structural_flags"],
                         third["structural_flags"])

    def test_json_serializable(self):
        plan = build_agent_evaluation_input(rich_result())
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_context_fact_count(self):
        self.assertEqual(evaluation_context_fact_count(None), 0)
        self.assertEqual(evaluation_context_fact_count({}), 0)
        self.assertEqual(
            evaluation_context_fact_count(
                {"input_location": "QUERY",
                 "output_context": "UNKNOWN",
                 "rule_version": "r39-2",
                 "research_only": True}
            ),
            1,
        )
        self.assertEqual(
            evaluation_context_fact_count(
                {"a": "X", "b": "UNKNOWN", "c": 1, "d": True,
                 "e": ["x"], "f": []}
            ),
            4,
        )

    def test_schema_rejects_bad_values_and_extra(self):
        base = {
            "agent_id": "sa-" + "a" * 16,
            "agent_category": "XSS",
            "agent_rule_version": "r39-1",
            "result_rule_version": "r39-5",
            "result_status": "COMPLETED",
            "result_confidence": "HIGH",
        }
        for key, value in (
            ("agent_category", "NOPE"),
            ("result_status", "FINISHED"),
            ("result_confidence", "CERTAIN"),
        ):
            with self.assertRaises(ValidationError):
                schema.AgentEvaluationInputPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.AgentEvaluationInputPlan(**base, payload="x")

    def test_schema_forces_rule_version(self):
        plan = schema.AgentEvaluationInputPlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r42-1")

    def test_exact_rule_version(self):
        self.assertEqual(
            build_agent_evaluation_input(rich_result())["rule_version"],
            "r42-1",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
