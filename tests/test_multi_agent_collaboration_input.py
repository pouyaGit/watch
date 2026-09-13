"""tests/test_multi_agent_collaboration_input.py — Stage R43.1 tests.

Deterministic, offline tests for the collaboration input contract:

- valid specialist result projection and attribution
- malformed input handling and structured diagnostics
- deterministic collaboration id handling
- no invented identity, no silent discard
- evaluation result projection and matching
- extra-field rejection, JSON serialization, determinism

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.multi_agent_collaboration_input import (
    build_multi_agent_collaboration_input,
)
from ai.knowledge.sqli_agent_result_export import (
    export_sqli_agent_result,
)
from ai.knowledge.ssrf_agent_result_export import (
    export_ssrf_agent_result,
)
from ai.schemas import multi_agent_collaboration_input as schema


def ssrf_result():
    return export_ssrf_agent_result()


def sqli_result():
    return export_sqli_agent_result()


def diagnostic_codes(plan):
    return [
        entry["diagnostic_code"]
        for entry in plan["collaboration_diagnostics"]
    ]


class TestMultiAgentCollaborationInput(unittest.TestCase):
    def test_valid_input_projection(self):
        ssrf = ssrf_result()
        sqli = sqli_result()
        plan = build_multi_agent_collaboration_input([ssrf, sqli])
        self.assertEqual(plan["rule_version"], "r43-1")
        self.assertEqual(plan["collaboration_rule_version"], "r43-1")
        self.assertTrue(schema.COLLABORATION_ID_RE.match(
            plan["collaboration_id"]
        ))
        self.assertEqual(len(plan["participating_agents"]), 2)
        self.assertEqual(
            [agent["agent_category"]
             for agent in plan["participating_agents"]],
            ["SSRF", "SQLI"],
        )
        self.assertEqual(len(plan["specialist_results"]), 2)
        self.assertEqual(plan["collaboration_diagnostics"], [])
        self.assertIs(plan["research_only"], True)

    def test_agent_attribution_preserved(self):
        ssrf = ssrf_result()
        plan = build_multi_agent_collaboration_input([ssrf])
        agent = plan["participating_agents"][0]
        identity = ssrf["agent_identity"]
        self.assertEqual(agent["agent_id"], identity["agent_id"])
        self.assertEqual(agent["agent_category"], "SSRF")
        self.assertEqual(
            agent["agent_rule_version"], identity["rule_version"]
        )
        self.assertEqual(
            agent["result_rule_version"], ssrf["rule_version"]
        )

    def test_r39_attribution_wrapper(self):
        from ai.knowledge.xss_agent_identity import (
            plan_xss_agent_identity,
        )
        from ai.knowledge.xss_agent_result_export import (
            export_xss_agent_result,
        )

        identity = plan_xss_agent_identity(maturity="RESEARCH")
        wrapped = {
            "specialist_result": export_xss_agent_result(),
            "agent_id": identity["agent_id"],
            "agent_category": "XSS",
        }
        plan = build_multi_agent_collaboration_input([wrapped])
        self.assertEqual(
            plan["participating_agents"][0]["agent_category"], "XSS"
        )
        self.assertEqual(
            plan["participating_agents"][0]["agent_id"],
            identity["agent_id"],
        )
        self.assertNotIn(
            "UNKNOWN_AGENT_CATEGORY", diagnostic_codes(plan)
        )

    def test_malformed_inputs_do_not_crash(self):
        plan = build_multi_agent_collaboration_input(
            [None, "", 42, [], "NOPE"]
        )
        self.assertEqual(len(plan["specialist_results"]), 5)
        codes = diagnostic_codes(plan)
        self.assertIn("MALFORMED_SPECIALIST_RESULT", codes)
        for result in plan["specialist_results"]:
            self.assertEqual(result["agent_category"], "UNKNOWN")

    def test_missing_results_diagnostic(self):
        plan = build_multi_agent_collaboration_input([])
        self.assertIn(
            "MISSING_SPECIALIST_RESULTS", diagnostic_codes(plan)
        )
        self.assertEqual(plan["specialist_results"], [])

    def test_missing_identity_and_category(self):
        plan = build_multi_agent_collaboration_input([{}])
        codes = diagnostic_codes(plan)
        self.assertIn("MISSING_AGENT_IDENTITY", codes)
        self.assertIn("UNKNOWN_AGENT_CATEGORY", codes)

    def test_duplicate_agent_id_diagnostic(self):
        first = ssrf_result()
        second = json.loads(json.dumps(ssrf_result()))
        plan = build_multi_agent_collaboration_input([first, second])
        self.assertIn("DUPLICATE_AGENT_ID", diagnostic_codes(plan))
        self.assertEqual(len(plan["specialist_results"]), 2)
        self.assertEqual(len(plan["participating_agents"]), 1)

    def test_missing_provenance_diagnostic(self):
        ssrf = ssrf_result()
        del ssrf["provenance"]
        plan = build_multi_agent_collaboration_input([ssrf])
        self.assertIn("MISSING_PROVENANCE", diagnostic_codes(plan))

    def test_non_deterministic_marker_diagnostic(self):
        ssrf = ssrf_result()
        ssrf["created_at"] = "now"
        plan = build_multi_agent_collaboration_input([ssrf])
        self.assertIn(
            "NON_DETERMINISTIC_INPUT", diagnostic_codes(plan)
        )

    def test_collaboration_id_deterministic(self):
        results = [ssrf_result(), sqli_result()]
        first = build_multi_agent_collaboration_input(results)
        second = build_multi_agent_collaboration_input(results)
        self.assertEqual(
            first["collaboration_id"], second["collaboration_id"]
        )
        different = build_multi_agent_collaboration_input(
            [sqli_result(), ssrf_result()]
        )
        self.assertEqual(
            first["collaboration_id"], different["collaboration_id"]
        )

    def test_caller_collaboration_id_accepted(self):
        provided = "collab-" + "a" * 16
        plan = build_multi_agent_collaboration_input(
            [ssrf_result()], collaboration_id=provided
        )
        self.assertEqual(plan["collaboration_id"], provided)

    def test_invalid_collaboration_id_recomputed(self):
        plan = build_multi_agent_collaboration_input(
            [ssrf_result()], collaboration_id="not-a-collaboration-id"
        )
        self.assertTrue(schema.COLLABORATION_ID_RE.match(
            plan["collaboration_id"]
        ))

    def test_evaluation_projection_and_match(self):
        from ai.knowledge.agent_evaluation_export import (
            evaluate_agent_result,
        )

        ssrf = ssrf_result()
        evaluation = evaluate_agent_result(ssrf)
        plan = build_multi_agent_collaboration_input(
            [ssrf], evaluation_results=[evaluation]
        )
        self.assertEqual(len(plan["evaluation_results"]), 1)
        entry = plan["evaluation_results"][0]
        self.assertEqual(
            entry["agent_id"], ssrf["agent_identity"]["agent_id"]
        )
        self.assertEqual(entry["agent_category"], "SSRF")
        self.assertIs(entry["present"], True)
        self.assertNotIn(
            "EVALUATION_AGENT_MISMATCH", diagnostic_codes(plan)
        )

    def test_evaluation_mismatch_and_invalid(self):
        from ai.knowledge.agent_evaluation_export import (
            evaluate_agent_result,
        )

        ssrf = ssrf_result()
        sqli = sqli_result()
        evaluation = evaluate_agent_result(sqli)
        plan = build_multi_agent_collaboration_input(
            [ssrf],
            evaluation_results=[evaluation, "nope"],
        )
        codes = diagnostic_codes(plan)
        self.assertIn("EVALUATION_AGENT_MISMATCH", codes)
        self.assertIn("INVALID_EVALUATION_RESULT", codes)

    def test_deterministic_output(self):
        results = [ssrf_result(), sqli_result()]
        first = build_multi_agent_collaboration_input(results)
        second = build_multi_agent_collaboration_input(results)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertNotIn("timestamp", json.dumps(first).lower())
        self.assertNotIn("uuid", json.dumps(first).lower())

    def test_json_serializable(self):
        plan = build_multi_agent_collaboration_input([ssrf_result()])
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_schema_rejects_bad_values_and_extra(self):
        with self.assertRaises(ValidationError):
            schema.MultiAgentCollaborationInputPlan(unexpected="x")
        with self.assertRaises(ValidationError):
            schema.MultiAgentCollaborationInputPlan(research_only=False)
        plan = schema.MultiAgentCollaborationInputPlan(
            rule_version="r99-9", collaboration_rule_version="r99-9"
        )
        self.assertEqual(plan.rule_version, "r43-1")
        self.assertEqual(plan.collaboration_rule_version, "r43-1")

    def test_schema_drops_unknown_diagnostic_codes(self):
        plan = schema.MultiAgentCollaborationInputPlan(
            collaboration_diagnostics=[
                {
                    "diagnostic_code": "NOT_A_CODE",
                    "severity": "LOW",
                    "agent_reference": "",
                    "message": "",
                }
            ]
        )
        self.assertEqual(plan.collaboration_diagnostics, [])

    def test_exact_rule_version(self):
        plan = build_multi_agent_collaboration_input([])
        self.assertEqual(plan["rule_version"], "r43-1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
