"""tests/test_agent_orchestrator.py — Stage R52 orchestration behavior tests.

Deterministic, offline tests for the agent orchestrator:

- automatic and explicit orchestration
- deterministic ordering and output structure
- specialist invocation through the existing structured APIs
- specialist failure and continue-on-error semantics
- R42 evaluation, R43 collaboration and R44 feedback integration
- optional R45/R51 advisory (disabled, enabled, provider failure, rejection)
- governance and provenance preservation
- resource limits, stage limits and recursive-orchestration prevention
- no eligible specialists and empty context
- R39-R50 interoperability
- backend non-integration

No real LLM calls, no network, no subprocess, no sockets, no browser, no SQL,
no database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_orchestrator import (
    orchestrate_research,
)
from ai.knowledge.llm_provider import AdvisoryProviderError, MockLLMProvider
from ai.knowledge.research_governance_export import (
    export_research_governance,
)
from ai.knowledge.specialist_invoker import SpecialistInvocationError
from ai.schemas.agent_orchestrator_result import (
    AGENT_ORCHESTRATOR_RESULT_RULE_VERSION,
    ORCHESTRATION_ERROR_CATEGORIES,
    ORCHESTRATION_STATUSES,
    SPECIALIST_SKIP_REASONS,
)


ROOT = Path(__file__).resolve().parents[1]

R52_MODULES = (
    "ai/schemas/agent_orchestrator_registry.py",
    "ai/schemas/agent_orchestrator_context.py",
    "ai/schemas/agent_orchestrator_policy.py",
    "ai/schemas/agent_orchestrator_result.py",
    "ai/knowledge/specialist_registry.py",
    "ai/knowledge/specialist_eligibility.py",
    "ai/knowledge/orchestration_policy.py",
    "ai/knowledge/specialist_invoker.py",
    "ai/knowledge/agent_orchestrator.py",
)

SPECIALIST_RESULT_RULE_VERSIONS = {
    "XSS": "r39-5",
    "SSRF": "r40-5",
    "SQLI": "r41-5",
    "IDOR": "r46-5",
    "JWT": "r47-5",
    "OAUTH": "r48-5",
    "RECON": "r49-5",
    "CVE_RESEARCH": "r50-5",
}


def xss_context():
    return {
        "input_location": "QUERY",
        "output_context": "HTML",
        "reflection_state": "REFLECTED",
        "encoding_state": "NONE_OBSERVED",
        "framework_context": "GENERIC",
    }


def xss_sqli_context():
    return {
        "output_context": "HTML",
        "reflection_state": "REFLECTED",
        "parameter_type": "QUERY_PARAM",
        "query_context": "DATABASE_QUERY",
    }


def multi_context():
    return {
        "input_location": "QUERY",
        "output_context": "HTML",
        "reflection_state": "REFLECTED",
        "encoding_state": "NONE_OBSERVED",
        "framework_context": "GENERIC",
        "parameter_type": "QUERY_PARAM",
        "query_context": "DATABASE_QUERY",
        "data_flow": "RAW_QUERY",
        "object_reference": "OBSERVED",
        "resource_type": "OBJECT",
        "token_format": "JWT",
        "signing_algorithm": "HS256",
        "flow": "AUTHORIZATION_CODE",
        "oauth_version": "2.0",
        "api_type": "REST",
        "api_versioning": "URL",
        "cve_metadata": "CVE-2021-44228",
        "affected_product": "log4j",
    }


def specialist_context(category):
    return {
        "XSS": xss_context(),
        "SSRF": {"server_side_fetch": "OBSERVED", "url_handling": "FULL_URL"},
        "SQLI": {"query_context": "DATABASE_QUERY"},
        "IDOR": {"object_reference": "OBSERVED"},
        "JWT": {"token_format": "JWT", "signing_algorithm": "HS256"},
        "OAUTH": {"flow": "AUTHORIZATION_CODE", "oauth_version": "2.0"},
        "RECON": {"api_type": "REST", "api_versioning": "URL"},
        "CVE_RESEARCH": {"cve_metadata": "CVE-2021-44228"},
    }[category]


class UnsafeProvider:
    """Deterministic fake provider returning unsafe advisory content."""

    provider_kind = "MOCK"

    def __init__(self):
        self.calls = 0

    def complete(self, request=None):
        self.calls += 1
        return {
            "advisory_id": (request or {}).get("advisory_id"),
            "advisory_mode": (request or {}).get("advisory_mode"),
            "summary": "The vulnerability is confirmed; exploit the target.",
            "insights": [],
            "recommendations": [],
        }


class FailingProvider:
    """Deterministic fake provider raising before returning any content."""

    provider_kind = "MOCK"

    def __init__(self):
        self.calls = 0

    def complete(self, request=None):
        self.calls += 1
        raise AdvisoryProviderError("provider unavailable", {})


class TestOrchestrationSelection(unittest.TestCase):
    def test_automatic_orchestration_xss_only(self):
        result = orchestrate_research(research_context=xss_context())
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["mode"], "AUTOMATIC")
        self.assertEqual(result["selected_specialists"], ["XSS"])
        self.assertEqual(
            [entry["category"] for entry in result["specialist_results"]],
            ["XSS"],
        )
        self.assertTrue(result["research_only"])
        self.assertTrue(result["deterministic"])
        self.assertEqual(
            result["rule_version"], AGENT_ORCHESTRATOR_RESULT_RULE_VERSION
        )

    def test_automatic_orchestration_is_canonically_ordered(self):
        result = orchestrate_research(research_context=multi_context())
        self.assertEqual(
            result["selected_specialists"],
            ["XSS", "SQLI", "IDOR", "JWT", "OAUTH", "RECON", "CVE_RESEARCH"],
        )
        categories = [
            entry["category"] for entry in result["specialist_results"]
        ]
        self.assertEqual(categories, result["selected_specialists"])

    def test_explicit_orchestration(self):
        result = orchestrate_research(
            research_context=xss_sqli_context(),
            policy={
                "mode": "EXPLICIT",
                "allowed_categories": ["SQLI", "XSS"],
            },
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["mode"], "EXPLICIT")
        self.assertEqual(result["selected_specialists"], ["XSS", "SQLI"])
        reasons = {
            item["category"]: item["reason"]
            for item in result["skipped_specialists"]
        }
        self.assertEqual(reasons["SSRF"], "NOT_REQUESTED")

    def test_explicit_unknown_category_fails_closed(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={
                "mode": "EXPLICIT",
                "allowed_categories": ["NOT_A_CATEGORY"],
            },
        )
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["specialist_results"], [])
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_POLICY"
        )

    def test_explicit_ineligible_category_fails_closed(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={
                "mode": "EXPLICIT",
                "allowed_categories": ["SSRF"],
            },
        )
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(
            result["errors"][0]["error_category"],
            "SPECIALIST_SELECTION_ERROR",
        )
        self.assertEqual(
            result["errors"][0]["specialist_category"], "SSRF"
        )

    def test_explicit_mode_does_not_add_specialists(self):
        result = orchestrate_research(
            research_context=multi_context(),
            policy={
                "mode": "EXPLICIT",
                "allowed_categories": ["XSS"],
            },
        )
        self.assertEqual(result["selected_specialists"], ["XSS"])
        self.assertEqual(len(result["specialist_results"]), 1)

    def test_empty_context_has_no_eligible_specialists(self):
        result = orchestrate_research(research_context={})
        self.assertEqual(result["status"], "NO_ELIGIBLE_SPECIALISTS")
        self.assertEqual(result["selected_specialists"], [])
        self.assertEqual(result["specialist_results"], [])
        self.assertIn("NO_ELIGIBLE_SPECIALISTS", result["limitations"])
        self.assertEqual(
            result["errors"][0]["error_category"],
            "NO_ELIGIBLE_SPECIALISTS",
        )

    def test_shared_keyword_context_is_not_confirmation(self):
        for keyword in (
            {"input_location": "QUERY"},
            {"authentication_mechanism": "BEARER"},
        ):
            result = orchestrate_research(research_context=keyword)
            self.assertEqual(
                result["status"], "NO_ELIGIBLE_SPECIALISTS"
            )
            self.assertEqual(result["specialist_results"], [])

    def test_default_policy_disables_advisory(self):
        result = orchestrate_research(research_context=xss_context())
        self.assertIsNone(result["advisory_result"])
        self.assertIn("ADVISORY_DISABLED", result["limitations"])


class TestSpecialistInvocation(unittest.TestCase):
    def test_invocation_reuses_existing_specialist_export(self):
        from ai.knowledge.xss_agent_result_export import (
            export_xss_agent_result,
        )

        result = orchestrate_research(research_context=xss_context())
        entry = result["specialist_results"][0]
        direct = export_xss_agent_result(**xss_context())
        self.assertEqual(entry["result"], direct)
        self.assertEqual(entry["result"]["rule_version"], "r39-5")

    def test_invocation_results_are_category_specific(self):
        for category, version in SPECIALIST_RESULT_RULE_VERSIONS.items():
            result = orchestrate_research(
                research_context=specialist_context(category)
            )
            self.assertEqual(
                result["selected_specialists"], [category]
            )
            entry = result["specialist_results"][0]
            self.assertEqual(entry["result"]["rule_version"], version)
            self.assertEqual(entry["agent_id"] != "", True)
            self.assertEqual(
                entry["evaluation_reference"]["reference_state"],
                "REFERENCED",
            )
            self.assertEqual(
                entry["result"]["research_only"], True
            )

    def test_specialist_failure_is_structured_and_not_fabricated(self):
        with mock.patch(
            "ai.knowledge.agent_orchestrator.invoke_specialist",
            side_effect=SpecialistInvocationError("XSS", "boom"),
        ):
            result = orchestrate_research(research_context=xss_context())
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["specialist_results"], [])
        self.assertIsNone(result["collaboration_result"])
        self.assertEqual(
            result["errors"][0]["error_category"],
            "SPECIALIST_EXECUTION_ERROR",
        )
        self.assertEqual(
            result["errors"][0]["specialist_category"], "XSS"
        )
        self.assertIn("SPECIALIST_ERRORS", result["limitations"])
        self.assertEqual(result["provenance"]["provenance_state"], "UNKNOWN")

    def test_continue_on_specialist_error(self):
        original = __import__(
            "ai.knowledge.specialist_invoker", fromlist=["invoke_specialist"]
        ).invoke_specialist

        def flaky(category, *args, **kwargs):
            if category == "XSS":
                raise SpecialistInvocationError("XSS", "boom")
            return original(category, *args, **kwargs)

        with mock.patch(
            "ai.knowledge.agent_orchestrator.invoke_specialist",
            side_effect=flaky,
        ):
            result = orchestrate_research(
                research_context=xss_sqli_context(),
                policy={"continue_on_specialist_error": True},
            )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(
            [entry["category"] for entry in result["specialist_results"]],
            ["SQLI"],
        )
        self.assertEqual(
            result["provenance"]["provenance_state"], "PARTIAL"
        )

    def test_stop_on_specialist_error(self):
        original = __import__(
            "ai.knowledge.specialist_invoker", fromlist=["invoke_specialist"]
        ).invoke_specialist

        def flaky(category, *args, **kwargs):
            if category == "XSS":
                raise SpecialistInvocationError("XSS", "boom")
            return original(category, *args, **kwargs)

        with mock.patch(
            "ai.knowledge.agent_orchestrator.invoke_specialist",
            side_effect=flaky,
        ):
            result = orchestrate_research(
                research_context=xss_sqli_context(),
                policy={"continue_on_specialist_error": False},
            )
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["specialist_results"], [])
        stopped = [
            item
            for item in result["skipped_specialists"]
            if item["reason"] == "STOPPED_AFTER_ERROR"
        ]
        self.assertEqual([item["category"] for item in stopped], ["SQLI"])

    def test_unknown_error_is_structured(self):
        with mock.patch(
            "ai.knowledge.agent_orchestrator._orchestrate",
            side_effect=RuntimeError("unexpected"),
        ):
            result = orchestrate_research(research_context=xss_context())
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(
            result["errors"][0]["error_category"], "UNKNOWN_ERROR"
        )
        self.assertEqual(result["specialist_results"], [])


class TestEvaluationCollaborationFeedback(unittest.TestCase):
    def test_r42_evaluation_runs_for_every_result(self):
        result = orchestrate_research(research_context=multi_context())
        self.assertEqual(len(result["evaluation_results"]), 7)
        for evaluation in result["evaluation_results"]:
            self.assertEqual(evaluation["research_only"], True)
            self.assertEqual(evaluation["deterministic"], True)
            self.assertIn(evaluation["safety_state"], ("PASS", "DEGRADED"))
            self.assertIsInstance(evaluation["overall_score"], int)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertNotIn("EVALUATION", result["provenance"]["skipped_stages"])

    def test_evaluation_can_be_disabled_by_policy(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"evaluate_results": False},
        )
        self.assertEqual(result["evaluation_results"], [])
        self.assertIn("EVALUATION", result["provenance"]["skipped_stages"])
        self.assertEqual(
            result["specialist_results"][0]["evaluation_reference"][
                "reference_state"
            ],
            "UNKNOWN",
        )

    def test_evaluation_failure_is_preserved_not_treated_as_pass(self):
        with mock.patch(
            "ai.knowledge.agent_orchestrator.evaluate_agent_result",
            side_effect=RuntimeError("evaluation failed"),
        ):
            result = orchestrate_research(research_context=xss_context())
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["evaluation_results"], [])
        self.assertEqual(
            result["errors"][0]["error_category"], "EVALUATION_ERROR"
        )
        self.assertIn("EVALUATION_ERRORS", result["limitations"])

    def test_r43_collaboration_runs_for_multiple_results(self):
        result = orchestrate_research(research_context=multi_context())
        collaboration = result["collaboration_result"]
        self.assertIsNotNone(collaboration)
        self.assertEqual(
            collaboration["rule_version"], "r43-6"
        )
        self.assertEqual(len(collaboration["participating_agents"]), 7)
        self.assertEqual(
            len(collaboration["collaboration_rankings"]), 7
        )
        self.assertEqual(
            collaboration["collaboration_id"][:7], "collab-"
        )
        for entry in result["specialist_results"]:
            self.assertEqual(
                entry["collaboration_reference"]["reference_state"],
                "REFERENCED",
            )
            self.assertEqual(
                entry["collaboration_reference"]["collaboration_id"],
                collaboration["collaboration_id"],
            )

    def test_single_specialist_skips_collaboration(self):
        result = orchestrate_research(research_context=xss_context())
        self.assertIsNone(result["collaboration_result"])
        self.assertIn("COLLABORATION", result["provenance"]["skipped_stages"])
        self.assertIn("COLLABORATION_SKIPPED", result["limitations"])

    def test_collaboration_failure_is_preserved(self):
        with mock.patch(
            "ai.knowledge.agent_orchestrator.export_multi_agent_collaboration",
            side_effect=RuntimeError("collaboration failed"),
        ):
            result = orchestrate_research(research_context=multi_context())
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIsNone(result["collaboration_result"])
        self.assertEqual(
            result["errors"][0]["error_category"], "COLLABORATION_ERROR"
        )

    def test_r44_feedback_aggregation(self):
        result = orchestrate_research(research_context=multi_context())
        feedback = result["feedback_result"]
        self.assertIsNotNone(feedback)
        self.assertEqual(feedback["rule_version"], "r52-5")
        self.assertEqual(len(feedback["events"]), 7)
        self.assertEqual(len(feedback["classifications"]), 7)
        self.assertEqual(len(feedback["learning_signals"]), 7)
        self.assertGreaterEqual(len(feedback["recommendations"]), 1)
        self.assertTrue(feedback["research_only"])
        for event in feedback["events"]:
            self.assertTrue(event["feedback_id"].startswith("fb-"))
        for entry in result["specialist_results"]:
            self.assertEqual(
                entry["feedback_reference"]["reference_state"],
                "REFERENCED",
            )

    def test_feedback_can_be_disabled_by_policy(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"generate_feedback": False},
        )
        self.assertIsNone(result["feedback_result"])
        self.assertIn("FEEDBACK", result["provenance"]["skipped_stages"])
        self.assertEqual(
            result["specialist_results"][0]["feedback_reference"][
                "reference_state"
            ],
            "UNKNOWN",
        )

    def test_feedback_failure_is_preserved(self):
        with mock.patch(
            "ai.knowledge.agent_orchestrator.build_research_feedback_event",
            side_effect=RuntimeError("feedback failed"),
        ):
            result = orchestrate_research(research_context=xss_context())
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIsNone(result["feedback_result"])
        self.assertEqual(
            result["errors"][0]["error_category"], "FEEDBACK_ERROR"
        )

    def test_mixed_specialists_collaborate(self):
        result = orchestrate_research(
            research_context=xss_sqli_context()
        )
        self.assertEqual(
            result["selected_specialists"], ["XSS", "SQLI"]
        )
        collaboration = result["collaboration_result"]
        self.assertIsNotNone(collaboration)
        categories = {
            agent["agent_category"]
            for agent in collaboration["participating_agents"]
        }
        self.assertEqual(categories, {"XSS", "SQLI"})


class TestAdvisoryIntegration(unittest.TestCase):
    def test_advisory_disabled_makes_no_provider_call(self):
        with mock.patch(
            "ai.knowledge.agent_orchestrator.export_real_llm_advisory"
        ) as bridge:
            result = orchestrate_research(research_context=xss_context())
        bridge.assert_not_called()
        self.assertIsNone(result["advisory_result"])
        self.assertIn("ADVISORY_DISABLED", result["limitations"])

    def test_advisory_enabled_uses_mock_provider(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={
                "advisory_enabled": True,
                "advisory_provider_kind": "MOCK",
            },
        )
        self.assertEqual(result["status"], "COMPLETED")
        advisory = result["advisory_result"]
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory["provider_state"], "OK")
        self.assertEqual(advisory["provider_kind"], "MOCK")
        self.assertEqual(
            advisory["advisory_result"]["validation_state"], "PASS"
        )
        self.assertEqual(
            result["specialist_results"][0]["advisory_reference"][
                "reference_state"
            ],
            "REFERENCED",
        )
        self.assertNotIn("ADVISORY_DISABLED", result["limitations"])

    def test_advisory_enabled_with_injected_provider_object(self):
        provider = MockLLMProvider()
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"advisory_enabled": True},
            advisory_provider=provider,
        )
        self.assertEqual(result["advisory_result"]["provider_state"], "OK")

    def test_provider_failure_propagates_as_structured_error(self):
        provider = FailingProvider()
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"advisory_enabled": True},
            advisory_provider=provider,
        )
        self.assertEqual(provider.calls, 1)
        self.assertEqual(result["status"], "PARTIAL")
        advisory = result["advisory_result"]
        self.assertEqual(advisory["provider_state"], "ERROR")
        self.assertIsNone(advisory["advisory_result"])
        self.assertEqual(
            result["errors"][0]["error_category"], "ADVISORY_ERROR"
        )
        self.assertIn("ADVISORY_ERRORS", result["limitations"])
        self.assertEqual(result["specialist_results"][0]
                         ["advisory_reference"]["reference_state"],
                         "UNKNOWN")

    def test_unsafe_provider_output_is_rejected_not_sanitized(self):
        provider = UnsafeProvider()
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"advisory_enabled": True},
            advisory_provider=provider,
        )
        self.assertEqual(provider.calls, 1)
        advisory = result["advisory_result"]
        self.assertEqual(advisory["provider_state"], "REJECTED")
        rejected = advisory["advisory_result"]
        self.assertEqual(rejected["validation_state"], "REJECTED")
        self.assertEqual(rejected["safety_state"], "FAILED")
        self.assertEqual(rejected["summary"], "")
        self.assertEqual(rejected["insights"], [])
        self.assertEqual(rejected["recommendations"], [])
        self.assertTrue(rejected["validation_diagnostics"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("exploit the target", serialized)
        self.assertNotIn("vulnerability is confirmed", serialized)
        self.assertEqual(
            result["errors"][0]["error_category"], "SAFETY_ERROR"
        )

    def test_advisory_output_remains_advisory_metadata(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"advisory_enabled": True},
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["specialist_results"][0]["result"]["status"],
                         "COMPLETED")
        self.assertNotIn("advisory", result["specialist_results"][0]["result"])

    def test_bridge_exception_is_structured(self):
        with mock.patch(
            "ai.knowledge.agent_orchestrator.export_real_llm_advisory",
            side_effect=RuntimeError("bridge exploded"),
        ):
            result = orchestrate_research(
                research_context=xss_context(),
                policy={"advisory_enabled": True},
            )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIsNone(result["advisory_result"])
        self.assertEqual(
            result["errors"][0]["error_category"], "ADVISORY_ERROR"
        )


class TestGovernanceProvenanceDeterminism(unittest.TestCase):
    def test_missing_governance_stays_unknown(self):
        result = orchestrate_research(research_context=xss_context())
        governance = result["governance"]
        self.assertEqual(governance["reference_state"], "UNKNOWN")
        self.assertFalse(governance["ready"])
        self.assertIn("GOVERNANCE_UNKNOWN", result["limitations"])

    def test_r37_governance_reference_is_preserved(self):
        governance_plan = export_research_governance()
        result = orchestrate_research(
            research_context=xss_context(),
            governance_plan=governance_plan,
        )
        governance = result["governance"]
        self.assertEqual(governance["reference_state"], "REFERENCED")
        self.assertEqual(governance["rule_version"], "r37-5")
        self.assertNotIn("GOVERNANCE_UNKNOWN", result["limitations"])
        specialist_governance = result["specialist_results"][0]["result"][
            "governance_reference"
        ]
        self.assertEqual(specialist_governance["reference_state"], "REFERENCED")

    def test_foreign_governance_plan_is_not_claimed(self):
        result = orchestrate_research(
            research_context=xss_context(),
            governance_plan={"rule_version": "r99-9"},
        )
        self.assertEqual(
            result["governance"]["reference_state"], "UNKNOWN"
        )

    def test_provenance_preserves_origin_and_stage(self):
        result = orchestrate_research(research_context=multi_context())
        provenance = result["provenance"]
        self.assertEqual(provenance["rule_version"], "r52-6")
        self.assertEqual(
            provenance["stages"],
            [
                "SELECTION",
                "INVOCATION",
                "EVALUATION",
                "COLLABORATION",
                "FEEDBACK",
            ],
        )
        self.assertEqual(
            [origin["category"] for origin in provenance["specialist_origins"]],
            result["selected_specialists"],
        )
        for origin in provenance["specialist_origins"]:
            self.assertEqual(origin["stage"], "INVOCATION")
            self.assertTrue(origin["agent_id"])
            self.assertTrue(origin["specialist_name"])
        self.assertEqual(provenance["provenance_state"], "COMPLETE")

    def test_provenance_references_match_run_outputs(self):
        result = orchestrate_research(research_context=multi_context())
        for entry in result["specialist_results"]:
            self.assertEqual(
                entry["evaluation_reference"]["reference_state"],
                "REFERENCED",
            )
            self.assertTrue(
                entry["advisory_reference"]["reference_state"]
                in ("REFERENCED", "UNKNOWN")
            )
            self.assertTrue(
                entry["feedback_reference"]["reference_state"],
                "REFERENCED",
            )
            self.assertEqual(
                entry["collaboration_reference"]["reference_state"],
                "REFERENCED",
            )

    def test_deterministic_output_for_identical_input(self):
        first = orchestrate_research(
            research_context=multi_context(),
            policy={"advisory_enabled": True},
            advisory_provider=MockLLMProvider(),
        )
        second = orchestrate_research(
            research_context=multi_context(),
            policy={"advisory_enabled": True},
            advisory_provider=MockLLMProvider(),
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        self.assertEqual(first["orchestration_id"],
                         second["orchestration_id"])
        self.assertEqual(first["orchestration_id"][:5], "orch-")

    def test_output_has_no_runtime_identifiers(self):
        result = orchestrate_research(research_context=multi_context())

        def collect_keys(value, out):
            if isinstance(value, dict):
                for key, child in value.items():
                    name = str(key).lower()
                    out.add(name)
                    collect_keys(child, out)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    collect_keys(item, out)

        keys = set()
        collect_keys(result, keys)
        for token in (
            "timestamp",
            "created_at",
            "updated_at",
            "started_at",
            "finished_at",
            "evaluated_at",
            "uuid",
            "pid",
            "process_id",
            "runtime_id",
            "nonce",
            "random",
        ):
            self.assertNotIn(token, keys)
        self.assertRegex(
            result["orchestration_id"], r"^orch-[0-9a-f]{16}$"
        )
        self.assertEqual(
            result["provenance"]["rule_version"], "r52-6"
        )
        self.assertEqual(
            result["provenance"]["specialist_origins"][0]["stage"],
            "INVOCATION",
        )

    def test_input_is_not_mutated(self):
        context = multi_context()
        snapshot = dict(context)
        policy = {
            "mode": "AUTOMATIC",
            "advisory_enabled": True,
        }
        policy_snapshot = dict(policy)
        governance_plan = export_research_governance()
        governance_snapshot = json.dumps(governance_plan, sort_keys=True)
        shared_context = {"rule_version": "r43-2"}
        shared_snapshot = dict(shared_context)
        orchestrate_research(
            research_context=context,
            policy=policy,
            governance_plan=governance_plan,
            shared_context=shared_context,
        )
        self.assertEqual(context, snapshot)
        self.assertEqual(policy, policy_snapshot)
        self.assertEqual(
            json.dumps(governance_plan, sort_keys=True), governance_snapshot
        )
        self.assertEqual(shared_context, shared_snapshot)


class TestLimitsAndFailureSemantics(unittest.TestCase):
    def test_max_specialists_limit(self):
        result = orchestrate_research(
            research_context=multi_context(),
            policy={"max_specialists": 2},
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(len(result["selected_specialists"]), 2)
        self.assertEqual(len(result["specialist_results"]), 2)
        self.assertEqual(
            result["errors"][0]["error_category"], "LIMIT_EXCEEDED"
        )
        self.assertIn("SELECTION_LIMITED", result["limitations"])
        exceeded = [
            item
            for item in result["skipped_specialists"]
            if item["reason"] == "MAX_SPECIALISTS_EXCEEDED"
        ]
        self.assertTrue(exceeded)

    def test_stage_limit(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"max_orchestration_stages": 1},
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["specialist_results"], [])
        self.assertEqual(result["provenance"]["stages"], ["SELECTION"])
        self.assertIn("STAGE_LIMIT", result["limitations"])

    def test_hypothesis_resource_limit(self):
        result = orchestrate_research(
            research_context={
                "token_format": "JWT",
                "signing_algorithm": "HS256",
            },
            policy={"max_hypotheses_processed": 1},
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(
            result["errors"][0]["error_category"], "LIMIT_EXCEEDED"
        )
        self.assertIn("RESOURCE_LIMIT", result["limitations"])
        self.assertEqual(result["evaluation_results"], [])

    def test_evidence_resource_limit(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"max_evidence_items_processed": 1},
        )
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIn("RESOURCE_LIMIT", result["limitations"])

    def test_recursive_orchestration_is_rejected(self):
        result = orchestrate_research(
            research_context=xss_context(),
            policy={"max_orchestration_depth": 2},
        )
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(
            result["errors"][0]["error_category"], "INVALID_POLICY"
        )
        self.assertEqual(result["specialist_results"], [])

    def test_invalid_policy_is_rejected(self):
        cases = (
            {"mode": "BOGUS"},
            {"mode": "EXPLICIT", "allowed_categories": []},
            {"mode": "AUTOMATIC", "allowed_categories": ["XSS"]},
            {"max_specialists": 0},
            {"max_specialists": 99},
            {"max_specialists": "many"},
            {"advisory_enabled": True, "max_advisory_requests": 0},
            {"evaluate_results": "yes"},
            {"max_orchestration_stages": 0},
            {"max_orchestration_stages": 99},
        )
        for policy in cases:
            result = orchestrate_research(
                research_context=xss_context(), policy=policy
            )
            self.assertEqual(result["status"], "FAILED", policy)
            self.assertIn(
                result["errors"][0]["error_category"],
                ("INVALID_POLICY",),
                policy,
            )

    def test_invalid_inputs_are_rejected(self):
        cases = (
            {"research_context": "not-a-mapping"},
            {"security_agent_input": "not-a-mapping"},
            {"governance_plan": "not-a-mapping"},
            {"shared_context": "not-a-mapping"},
        )
        for case in cases:
            result = orchestrate_research(**case)
            self.assertEqual(result["status"], "FAILED", case)
            self.assertEqual(
                result["errors"][0]["error_category"],
                "INVALID_INPUT",
                case,
            )

    def test_error_categories_and_statuses_are_closed(self):
        result = orchestrate_research(research_context=multi_context())
        for error in result["errors"]:
            self.assertIn(
                error["error_category"], ORCHESTRATION_ERROR_CATEGORIES
            )
        self.assertIn(result["status"], ORCHESTRATION_STATUSES)
        for item in result["skipped_specialists"]:
            self.assertIn(item["reason"], SPECIALIST_SKIP_REASONS)

    def test_result_contract_is_exact(self):
        result = orchestrate_research(research_context=xss_context())
        self.assertEqual(
            set(result.keys()),
            {
                "rule_version",
                "orchestration_id",
                "status",
                "mode",
                "selected_specialists",
                "skipped_specialists",
                "specialist_results",
                "evaluation_results",
                "collaboration_result",
                "feedback_result",
                "advisory_result",
                "errors",
                "provenance",
                "governance",
                "limitations",
                "research_only",
                "deterministic",
            },
        )
        self.assertIsInstance(json.loads(json.dumps(result)), dict)


class TestInteroperability(unittest.TestCase):
    def test_r39_r40_r41_interoperability(self):
        for category in ("XSS", "SSRF", "SQLI"):
            result = orchestrate_research(
                research_context=specialist_context(category)
            )
            self.assertEqual(result["status"], "COMPLETED", category)
            self.assertEqual(
                result["selected_specialists"], [category], category
            )
            self.assertTrue(
                result["evaluation_results"], category
            )

    def test_r46_r50_interoperability(self):
        for category in (
            "IDOR",
            "JWT",
            "OAUTH",
            "RECON",
            "CVE_RESEARCH",
        ):
            result = orchestrate_research(
                research_context=specialist_context(category)
            )
            self.assertEqual(result["status"], "COMPLETED", category)
            self.assertEqual(
                result["selected_specialists"], [category], category
            )
            entry = result["specialist_results"][0]
            self.assertEqual(
                entry["result"]["rule_version"],
                SPECIALIST_RESULT_RULE_VERSIONS[category],
                category,
            )

    def test_backend_does_not_import_r52(self):
        backend = ROOT / "backend"
        if not backend.exists():
            self.skipTest("backend directory absent")
        for path in backend.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("agent_orchestrator", text, str(path))
            self.assertNotIn("specialist_registry", text, str(path))
            self.assertNotIn("orchestrate_research", text, str(path))

    def test_specialist_modules_do_not_import_the_orchestrator(self):
        for path in sorted((ROOT / "ai" / "knowledge").glob("*.py")):
            if path.name in (
                "agent_orchestrator.py",
                "specialist_registry.py",
                "specialist_eligibility.py",
                "specialist_invoker.py",
                "orchestration_policy.py",
            ):
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("agent_orchestrator", text, path.name)
            self.assertNotIn("specialist_invoker", text, path.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
