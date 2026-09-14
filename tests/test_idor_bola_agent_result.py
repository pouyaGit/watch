"""tests/test_idor_bola_agent_result.py — Stage R46.5 tests.

Deterministic, offline tests for the IDOR/BOLA agent result:

- exact result contract and status/confidence derivation
- provenance and governance preservation without invention
- observed behavior preservation and no fabrication
- R42 / R43 / R44 / R45 compatibility through generic contracts
- forbidden payload/attack output scan
- deterministic serialization and repeated execution equality
- R46 AST safety scan and standalone backend decision

No network, no LLM, no subprocess, no sockets, no browser, no SQL, no
database, no payloads, no Mongo writes, no persistence, no execution of any
kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.idor_bola_agent_identity import (
    plan_idor_bola_agent_identity,
)
from ai.knowledge.idor_bola_agent_result_export import (
    build_governance_reference,
    export_idor_bola_agent_result,
    idor_bola_agent_result_to_r38,
)
from ai.knowledge.learning_signal_extractor import extract_learning_signals
from ai.knowledge.llm_advisory_export import export_llm_advisory
from ai.knowledge.multi_agent_collaboration_export import (
    export_multi_agent_collaboration,
)
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import build_research_feedback_event
from ai.knowledge.research_governance_export import export_research_governance
from ai.knowledge.security_agent_input_validator import (
    validate_security_agent_input,
)
from ai.knowledge.sqli_agent_result_export import export_sqli_agent_result
from ai.knowledge.ssrf_agent_result_export import export_ssrf_agent_result
from ai.knowledge.xss_agent_identity import plan_xss_agent_identity
from ai.knowledge.xss_agent_result_export import export_xss_agent_result
from ai.schemas import idor_bola_agent_result as schema
from ai.schemas.agent_evaluation_score import (
    EVALUATION_RATINGS,
    HARD_GATE_STATES,
    SAFETY_STATES,
)


ROOT = Path(__file__).resolve().parents[1]

R46_MODULES = (
    "ai/schemas/idor_bola_agent_identity.py",
    "ai/schemas/idor_bola_context_analysis.py",
    "ai/schemas/idor_bola_hypothesis.py",
    "ai/schemas/idor_bola_evidence_plan.py",
    "ai/schemas/idor_bola_agent_result.py",
    "ai/schemas/idor_bola_agent.py",
    "ai/knowledge/idor_bola_agent_identity.py",
    "ai/knowledge/idor_bola_context_analyzer.py",
    "ai/knowledge/idor_bola_hypothesis_planner.py",
    "ai/knowledge/idor_bola_evidence_planner.py",
    "ai/knowledge/idor_bola_agent_result_export.py",
    "ai/knowledge/idor_bola_agent.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "asyncio", "threading", "multiprocessing", "concurrent",
    "importlib", "ctypes", "shutil", "ssl", "os", "dns", "selenium",
    "playwright", "pyppeteer", "paramiko", "sqlite3", "sqlalchemy",
    "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap", "nuclei",
    "curl", "pycurl", "openai", "ollama", "litellm", "anthropic",
    "openrouter",
}

FORBIDDEN_CALLS = {"__import__", "eval", "exec", "compile", "open"}

FORBIDDEN_CALL_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "importlib.",
    "socket.",
    "urllib.",
    "requests.",
    "httpx.",
    "sqlite3.",
    "sqlalchemy.",
    "psycopg2.",
    "pymysql.",
    "openai.",
)

FORBIDDEN_OUTPUT_TOKENS = (
    "payload:",
    "<script",
    "union select",
    "or 1=1",
    "execute this",
    "run this command",
    "bypass authentication",
    "attack plan",
    "attack sequence",
    "exploit the target",
    "send this payload",
    "api_key",
    "authorization: bearer",
)


def dotted_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def scan_module(relative_path):
    tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
    imports = set()
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                name = dotted_name(node.func)
                if name.startswith(FORBIDDEN_CALL_PREFIXES):
                    calls.add(name)
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)
    return imports, calls


def rich_result(**over):
    base = {
        "object_reference": "PATH_PARAMETER",
        "resource_type": "ORDER",
        "identifier_type": "SEQUENTIAL_INTEGER",
        "ownership_relationship": "OWNER_RECORDED",
        "tenant_boundary": "TENANT_RECORDED",
        "role_boundary": "ROLE_RECORDED",
        "authorization_control": "POLICY_ENFORCEMENT_PRESENT",
        "authorization_location": "SERVER_SIDE",
        "object_lookup": "LOOKUP_BY_IDENTIFIER",
        "authorization_behavior": "OWN_OBJECT_ONLY_OBSERVED",
        "route_context": "RESOURCE_ROUTE",
    }
    base.update(over)
    return export_idor_bola_agent_result(**base)


def gap_result():
    return export_idor_bola_agent_result(
        object_reference="PATH_PARAMETER",
        resource_type="ORDER",
        identifier_type="SEQUENTIAL_INTEGER",
        ownership_relationship="OWNER_RECORDED",
        object_lookup="LOOKUP_BY_IDENTIFIER",
        authorization_control="AUTHORIZATION_ABSENT",
    )


class TestIDORBOLAAgentResult(unittest.TestCase):
    def test_key_set_is_exact(self):
        result = export_idor_bola_agent_result()
        self.assertEqual(
            set(result.keys()),
            {"rule_version", "agent_name", "agent_identity", "status",
             "context_analysis", "hypotheses", "evidence_plan",
             "confidence", "limitations", "governance_reference",
             "provenance", "research_only"},
        )
        self.assertEqual(result["rule_version"], "r46-5")
        self.assertIs(result["research_only"], True)

    def test_identity_embedded(self):
        result = export_idor_bola_agent_result()
        identity = result["agent_identity"]
        self.assertEqual(identity["category"], "IDOR")
        self.assertEqual(identity["agent_name"], "idor-bola-specialist")
        self.assertEqual(identity["rule_version"], "r46-1")
        self.assertEqual(result["agent_name"], "idor-bola-specialist")

    def test_status_derivation(self):
        self.assertEqual(
            export_idor_bola_agent_result()["status"], "CREATED"
        )
        self.assertEqual(gap_result()["status"], "ANALYZING")
        self.assertEqual(rich_result()["status"], "COMPLETED")

    def test_confidence_calibration_through_result(self):
        self.assertEqual(
            export_idor_bola_agent_result()["confidence"], "UNKNOWN"
        )
        self.assertEqual(gap_result()["confidence"], "LOW")
        self.assertEqual(rich_result()["confidence"], "HIGH")

    def test_hypotheses_bounded(self):
        result = rich_result()
        self.assertLessEqual(
            len(result["hypotheses"]), schema.MAX_HYPOTHESES
        )
        self.assertTrue(result["hypotheses"])

    def test_observed_behavior_preserved(self):
        result = export_idor_bola_agent_result(
            object_reference="PATH_PARAMETER",
            authorization_behavior="CROSS_USER_ACCESS_OBSERVED",
        )
        self.assertEqual(
            result["context_analysis"]["authorization_behavior"],
            "CROSS_USER_ACCESS_OBSERVED",
        )
        default = export_idor_bola_agent_result(
            object_reference="PATH_PARAMETER"
        )
        self.assertEqual(
            default["context_analysis"]["authorization_behavior"],
            "UNKNOWN",
        )

    def test_no_fabricated_observed_behavior(self):
        serialized = json.dumps(gap_result(), sort_keys=True)
        self.assertNotIn("CROSS_USER_ACCESS_OBSERVED", serialized)
        self.assertNotIn("CROSS_TENANT_ACCESS_OBSERVED", serialized)

    def test_provenance_unknown_by_default(self):
        provenance = export_idor_bola_agent_result()["provenance"]
        self.assertEqual(provenance["provenance_state"], "UNKNOWN")
        self.assertEqual(provenance["source_layers"], [])

    def test_provenance_preserved_from_r38_input(self):
        bounded = validate_security_agent_input(
            research_context={"topic": "r31"},
            memory_context={"prior": "r32"},
            authorization_context={"scope": "research"},
        )
        result = export_idor_bola_agent_result(
            security_agent_input=bounded,
            object_reference="PATH_PARAMETER",
        )
        self.assertEqual(
            result["provenance"]["source_layers"],
            ["REASONING", "MEMORY", "AUTHORIZATION"],
        )
        self.assertEqual(
            result["provenance"]["provenance_state"], "PARTIAL"
        )

    def test_provenance_complete_for_all_layers(self):
        bounded = validate_security_agent_input(
            research_context={"a": 1},
            memory_context={"b": 2},
            strategy_context={"c": 3},
            orchestration_context={"d": 4},
            authorization_context={"e": 5},
            governance_context={"f": 6},
        )
        result = export_idor_bola_agent_result(
            security_agent_input=bounded
        )
        self.assertEqual(
            result["provenance"]["source_layers"],
            ["REASONING", "MEMORY", "STRATEGY", "ORCHESTRATION",
             "AUTHORIZATION", "GOVERNANCE"],
        )
        self.assertEqual(
            result["provenance"]["provenance_state"], "COMPLETE"
        )

    def test_provenance_records_governance_reference(self):
        result = export_idor_bola_agent_result(
            governance_plan=export_research_governance()
        )
        self.assertEqual(
            result["provenance"]["source_layers"], ["GOVERNANCE"]
        )

    def test_governance_unknown_by_default(self):
        result = export_idor_bola_agent_result()
        reference = result["governance_reference"]
        self.assertEqual(reference["reference_state"], "UNKNOWN")
        self.assertIs(reference["ready"], False)
        self.assertIn("GOVERNANCE_UNKNOWN", result["limitations"])

    def test_governance_reference_integration(self):
        result = export_idor_bola_agent_result(
            governance_plan=export_research_governance()
        )
        reference = result["governance_reference"]
        self.assertEqual(reference["rule_version"], "r37-5")
        self.assertEqual(reference["reference_state"], "REFERENCED")
        self.assertNotIn("GOVERNANCE_UNKNOWN", result["limitations"])

    def test_governance_rejects_foreign_or_malformed(self):
        for bad in (
            None,
            "",
            42,
            [],
            {"rule_version": "r40-5", "ready": True},
            {"rule_version": "r37-5"},
            {"rule_version": "r37-5", "reference_state": "REFERENCED",
             "ready": True},
        ):
            reference = build_governance_reference(bad)
            self.assertEqual(
                reference["reference_state"], "UNKNOWN", repr(bad)
            )
            self.assertIs(reference["ready"], False, repr(bad))

    def test_r42_compatibility(self):
        result = gap_result()
        evaluation = evaluate_agent_result(result)
        self.assertEqual(
            evaluation["evaluated_agent_category"], "IDOR"
        )
        self.assertEqual(
            evaluation["evaluated_result_rule_version"], "r46-5"
        )
        self.assertIn(evaluation["overall_rating"], EVALUATION_RATINGS)
        self.assertIn(evaluation["hard_gate_state"], HARD_GATE_STATES)
        self.assertIn(evaluation["safety_state"], SAFETY_STATES)
        self.assertGreaterEqual(evaluation["overall_score"], 0)
        self.assertLessEqual(evaluation["overall_score"], 100)
        explicit = evaluate_agent_result(
            result,
            agent_id=result["agent_identity"]["agent_id"],
            agent_category="IDOR",
        )
        self.assertEqual(explicit["evaluated_agent_category"], "IDOR")
        self.assertEqual(
            explicit["evaluated_agent_id"],
            result["agent_identity"]["agent_id"],
        )

    def test_r43_mixed_collaboration(self):
        xss_identity = plan_xss_agent_identity(maturity="RESEARCH")
        collaboration = export_multi_agent_collaboration(
            [
                {
                    "specialist_result": export_xss_agent_result(),
                    "agent_id": xss_identity["agent_id"],
                    "agent_category": "XSS",
                },
                export_ssrf_agent_result(),
                export_sqli_agent_result(),
                gap_result(),
            ]
        )
        categories = {
            agent["agent_category"]
            for agent in collaboration["participating_agents"]
        }
        self.assertEqual(
            categories, {"XSS", "SSRF", "SQLI", "IDOR"}
        )
        idor_agents = [
            agent
            for agent in collaboration["participating_agents"]
            if agent["agent_category"] == "IDOR"
        ]
        self.assertEqual(len(idor_agents), 1)
        self.assertEqual(
            idor_agents[0]["result_rule_version"], "r46-5"
        )
        self.assertTrue(collaboration["hypothesis_groups"])
        self.assertEqual(
            len(collaboration["collaboration_rankings"]), 4
        )
        self.assertIn(
            "merged_evidence", collaboration
        )
        self.assertIn(
            collaboration["governance_summary"]["governance_state"],
            ("CONSISTENT_REFERENCED", "MIXED", "UNKNOWN"),
        )
        self.assertIn(
            collaboration["provenance_summary"]["provenance_state"],
            ("COMPLETE", "PARTIAL", "UNKNOWN"),
        )

    def test_r44_feedback_compatibility(self):
        evaluation = evaluate_agent_result(gap_result())
        event = build_research_feedback_event(
            evaluation_result=evaluation
        )
        self.assertEqual(event["source_category"], "IDOR")
        classifications = classify_research_feedback_events([event])
        self.assertEqual(len(classifications), 1)
        self.assertEqual(classifications[0]["subject"], "IDOR")

    def test_r44_calibration_example(self):
        event = build_research_feedback_event(
            source_agent="sa-" + "a" * 16,
            source_category="IDOR",
            outcome_type="CONFIDENCE_OBSERVATION",
            observed_issue="ISSUE_HIGH_CONFIDENCE_WEAK_EVIDENCE",
        )
        classifications = classify_research_feedback_events([event])
        self.assertEqual(
            classifications[0]["classification"],
            "CONFIDENCE_CALIBRATION",
        )
        signals = extract_learning_signals(classifications)
        self.assertEqual(signals[0]["signal_type"], "REDUCE_CONFIDENCE")

    def test_r44_provenance_example(self):
        event = build_research_feedback_event(
            source_agent="sa-" + "a" * 16,
            source_category="IDOR",
            outcome_type="QUALITY_OBSERVATION",
            observed_issue="ISSUE_MISSING_PROVENANCE",
        )
        classifications = classify_research_feedback_events([event])
        self.assertEqual(
            classifications[0]["classification"], "PROVENANCE_ISSUE"
        )

    def test_r44_authorization_control_success_pattern(self):
        result = rich_result()
        self.assertIn(
            "AUTHORIZATION_CONTROL_PRESENT",
            [
                hypothesis["hypothesis_type"]
                for hypothesis in result["hypotheses"]
            ],
        )
        event = build_research_feedback_event(
            source_agent="sa-" + "a" * 16,
            source_category="IDOR",
            outcome_type="SUCCESS_OBSERVATION",
            observed_success="SUCCESS_SAFE_RESEARCH",
        )
        classifications = classify_research_feedback_events([event])
        self.assertEqual(
            classifications[0]["classification"], "SUCCESS_PATTERN"
        )
        signals = extract_learning_signals(classifications)
        self.assertEqual(
            signals[0]["signal_type"], "PRESERVE_SUCCESS_PATTERN"
        )

    def test_r45_advisory_compatibility(self):
        evaluation = evaluate_agent_result(gap_result())
        event = build_research_feedback_event(
            evaluation_result=evaluation
        )
        signals = extract_learning_signals(
            classify_research_feedback_events([event])
        )
        advisory = export_llm_advisory(
            evaluation_result=evaluation,
            learning_signals=signals,
        )
        self.assertEqual(advisory["validation_state"], "PASS")
        self.assertIs(advisory["research_only"], True)
        self.assertIn(
            {"layer": "R42", "reference": "r42-5"},
            advisory["source_refs"],
        )
        self.assertNotEqual(advisory["summary"], "")

    def test_forbidden_payload_or_attack_output(self):
        serialized = json.dumps(
            rich_result(), sort_keys=True
        ).lower()
        for token in FORBIDDEN_OUTPUT_TOKENS:
            self.assertNotIn(token.lower(), serialized)

    def test_result_limitations(self):
        result = export_idor_bola_agent_result()
        for limitation in (
            "NO_EXECUTION_PERFORMED",
            "NO_NETWORK_REQUESTS",
            "NO_AUTHORIZATION_BYPASS",
            "NO_PAYLOAD_GENERATION",
            "NO_VULNERABILITY_CONFIRMATION",
            "NO_TARGET_MODIFICATION",
            "HYPOTHESIS_ONLY",
            "EVIDENCE_REQUIRED",
        ):
            self.assertIn(limitation, result["limitations"])

    def test_r38_result_projection(self):
        projection = idor_bola_agent_result_to_r38(gap_result())
        self.assertEqual(projection["status"], "ANALYZING")
        self.assertEqual(projection["findings_summary"], "NO_FINDINGS")
        self.assertEqual(projection["evidence_summary"], "EVIDENCE_PARTIAL")
        self.assertEqual(projection["confidence"], "LOW")
        self.assertIs(projection["research_only"], True)

    def test_deterministic_serialization(self):
        first = json.dumps(rich_result(), sort_keys=True)
        second = json.dumps(rich_result(), sort_keys=True)
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())
        self.assertNotIn("runtime_id", first.lower())

    def test_repeated_execution_equality(self):
        runs = [gap_result() for _ in range(3)]
        first = json.dumps(runs[0], sort_keys=True)
        for run in runs[1:]:
            self.assertEqual(json.dumps(run, sort_keys=True), first)

    def test_json_serializable(self):
        self.assertIsInstance(
            json.loads(json.dumps(rich_result())), dict
        )

    def test_result_model_rejects_bad_values_and_extra(self):
        base = gap_result()
        with self.assertRaises(ValidationError):
            schema.IDORBOLAAgentResultPlan(
                **{**base, "status": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAAgentResultPlan(
                **{**base, "confidence": "NOPE"}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAAgentResultPlan(
                **{**base, "limitations": ["NOPE"]}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAAgentResultPlan(
                **{**base, "research_only": False}
            )
        with self.assertRaises(ValidationError):
            schema.IDORBOLAAgentResultPlan(**{**base, "payload": "x"})

    def test_result_model_forces_rule_version(self):
        plan = schema.IDORBOLAAgentResultPlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r46-5")

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R46_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("idor_bola", backend_source)
        self.assertNotIn("IDOR_BOLA", backend_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
