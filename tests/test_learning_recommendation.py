"""tests/test_learning_recommendation.py — Stage R44.5 tests.

Deterministic, offline tests for learning recommendations:

- closed recommendation vocabulary and signal mapping
- deterministic generation, ordering and deduplication
- attribution preservation and advisory limitations
- R42/R43 integration through feedback events
- XSS/SSRF/SQLi feedback examples
- R44 AST safety scan, determinism and backend decision

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

from ai.knowledge.learning_recommendation_generator import (
    RECOMMENDATION_TEXT,
    SIGNAL_TO_RECOMMENDATION,
    generate_learning_recommendations,
)
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import (
    build_research_feedback_event,
)
from ai.knowledge.learning_signal_extractor import extract_learning_signals
from ai.schemas import learning_recommendation as schema


ROOT = Path(__file__).resolve().parents[1]

R44_MODULES = (
    "ai/schemas/research_feedback_event.py",
    "ai/schemas/research_feedback_classification.py",
    "ai/schemas/learning_signal.py",
    "ai/schemas/research_learning_memory.py",
    "ai/schemas/learning_recommendation.py",
    "ai/knowledge/research_feedback_event.py",
    "ai/knowledge/research_feedback_classifier.py",
    "ai/knowledge/learning_signal_extractor.py",
    "ai/knowledge/research_learning_memory_export.py",
    "ai/knowledge/learning_recommendation_generator.py",
)

FORBIDDEN_MODULES = {
    "subprocess", "socket", "http", "urllib", "requests", "httpx",
    "aiohttp", "asyncio", "threading", "multiprocessing", "concurrent",
    "importlib", "ctypes", "shutil", "ssl", "os", "dns", "selenium",
    "playwright", "pyppeteer", "paramiko", "sqlite3", "sqlalchemy",
    "psycopg", "psycopg2", "pymysql", "MySQLdb", "sqlmap", "nuclei",
    "curl", "pycurl",
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


def event(category="XSS", agent=None, **over):
    kwargs = {
        "source_agent": agent or ("sa-" + "a" * 16),
        "source_category": category,
        "outcome_type": "QUALITY_OBSERVATION",
    }
    kwargs.update(over)
    return build_research_feedback_event(**kwargs)


def signal(signal_type, category="XSS", agent="sa-" + "a" * 16,
           classification="EVIDENCE_GAP"):
    return {
        "rule_version": "r44-3",
        "signal_type": signal_type,
        "subject": category,
        "source_agent": agent,
        "source_classification": classification,
        "recommendation": "text",
        "supporting_signals": [],
        "confidence": "MEDIUM",
        "limitations": [],
        "research_only": True,
    }


class TestLearningRecommendation(unittest.TestCase):
    def test_recommendation_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.LEARNING_RECOMMENDATION_TYPES),
            {"PRIORITIZE_EVIDENCE_PLANNING", "CALIBRATE_CONFIDENCE",
             "IMPROVE_CONTEXT_CAPTURE", "PRESERVE_SUCCESSFUL_PATTERN",
             "DEDUPLICATE_HYPOTHESES",
             "REVIEW_GOVERNANCE_REFERENCES", "PRESERVE_PROVENANCE",
             "STRENGTHEN_HYPOTHESES", "RESTORE_SAFETY_BOUNDARY",
             "UNKNOWN"},
        )

    def test_signal_mapping_is_exact(self):
        self.assertEqual(
            SIGNAL_TO_RECOMMENDATION,
            {
                "REQUIRE_MORE_EVIDENCE": "PRIORITIZE_EVIDENCE_PLANNING",
                "REDUCE_CONFIDENCE": "CALIBRATE_CONFIDENCE",
                "IMPROVE_CONTEXT_COLLECTION": "IMPROVE_CONTEXT_CAPTURE",
                "PRESERVE_SUCCESS_PATTERN": (
                    "PRESERVE_SUCCESSFUL_PATTERN"
                ),
                "AVOID_DUPLICATION": "DEDUPLICATE_HYPOTHESES",
                "REVIEW_GOVERNANCE": "REVIEW_GOVERNANCE_REFERENCES",
                "REVIEW_PROVENANCE": "PRESERVE_PROVENANCE",
                "IMPROVE_HYPOTHESIS_QUALITY": "STRENGTHEN_HYPOTHESES",
                "IMPROVE_SAFETY_BOUNDARY": "RESTORE_SAFETY_BOUNDARY",
                "UNKNOWN": "UNKNOWN",
            },
        )
        for signal_type, recommendation_type in (
            SIGNAL_TO_RECOMMENDATION.items()
        ):
            self.assertTrue(
                RECOMMENDATION_TEXT[recommendation_type]
            )

    def test_generate_from_events(self):
        events = [
            event(observed_issue="ISSUE_MISSING_EVIDENCE_REQUIREMENT",
                  outcome_type="EVIDENCE_OBSERVATION"),
        ]
        recommendations = generate_learning_recommendations(events)
        self.assertEqual(len(recommendations), 1)
        self.assertEqual(
            recommendations[0]["recommendation_type"],
            "PRIORITIZE_EVIDENCE_PLANNING",
        )
        self.assertEqual(recommendations[0]["related_category"], "XSS")
        self.assertEqual(
            recommendations[0]["source_classification"], "EVIDENCE_GAP"
        )
        self.assertTrue(
            schema.RECOMMENDATION_ID_RE.match(
                recommendations[0]["recommendation_id"]
            )
        )

    def test_generate_from_signals(self):
        recommendations = generate_learning_recommendations(
            signals=[signal("IMPROVE_SAFETY_BOUNDARY")]
        )
        self.assertEqual(
            recommendations[0]["recommendation_type"],
            "RESTORE_SAFETY_BOUNDARY",
        )
        self.assertEqual(
            recommendations[0]["recommendation"],
            RECOMMENDATION_TEXT["RESTORE_SAFETY_BOUNDARY"],
        )

    def test_deterministic_and_ordered(self):
        signals = [
            signal("IMPROVE_SAFETY_BOUNDARY", classification="SAFETY_ISSUE"),
            signal("REQUIRE_MORE_EVIDENCE"),
        ]
        first = generate_learning_recommendations(signals=signals)
        second = generate_learning_recommendations(signals=signals)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        order = [
            schema.RECOMMENDATION_ORDER[
                recommendation["recommendation_type"]
            ]
            for recommendation in first
        ]
        self.assertEqual(order, sorted(order))

    def test_deduplication(self):
        signals = [
            signal("REQUIRE_MORE_EVIDENCE"),
            signal("REQUIRE_MORE_EVIDENCE"),
        ]
        recommendations = generate_learning_recommendations(signals=signals)
        self.assertEqual(len(recommendations), 1)

    def test_distinct_agents_not_deduplicated(self):
        signals = [
            signal("REQUIRE_MORE_EVIDENCE", agent="sa-" + "1" * 16),
            signal("REQUIRE_MORE_EVIDENCE", agent="sa-" + "2" * 16),
        ]
        recommendations = generate_learning_recommendations(signals=signals)
        self.assertEqual(len(recommendations), 2)

    def test_advisory_limitations(self):
        recommendations = generate_learning_recommendations(
            signals=[signal("REVIEW_GOVERNANCE")]
        )
        limitations = recommendations[0]["limitations"]
        for code in (
            "NO_EXECUTION_PERFORMED",
            "NO_AGENT_MODIFICATION",
            "NO_RULE_MODIFICATION",
            "NO_AUTOMATIC_STRATEGY_CHANGE",
            "ADVISORY_ONLY",
        ):
            self.assertIn(code, limitations)
        self.assertIs(recommendations[0]["research_only"], True)

    def test_specialist_examples(self):
        examples = {
            "XSS": "ISSUE_MISSING_PROVENANCE",
            "SSRF": "ISSUE_MISSING_EVIDENCE_REQUIREMENT",
            "SQLI": "ISSUE_NO_HYPOTHESES",
        }
        events = [
            event(
                category=category,
                agent="sa-" + str(index) * 16,
                outcome_type="EVIDENCE_OBSERVATION",
                observed_issue=issue,
            )
            for index, (category, issue) in enumerate(examples.items(), 1)
        ]
        recommendations = generate_learning_recommendations(events)
        categories = {
            recommendation["related_category"]
            for recommendation in recommendations
        }
        self.assertEqual(categories, {"XSS", "SSRF", "SQLI"})

    def test_full_pipeline_helpers_agree(self):
        events = [event(observed_issue="ISSUE_NO_HYPOTHESES",
                        outcome_type="HYPOTHESIS_OBSERVATION")]
        classifications = classify_research_feedback_events(events)
        signals = extract_learning_signals(classifications)
        from_signals = generate_learning_recommendations(signals=signals)
        from_events = generate_learning_recommendations(events)
        self.assertEqual(
            json.dumps(from_signals, sort_keys=True),
            json.dumps(from_events, sort_keys=True),
        )

    def test_malformed_input(self):
        self.assertEqual(
            generate_learning_recommendations(signals=[None, 42, "x"]), []
        )
        self.assertEqual(
            generate_learning_recommendations(signals=None, events=None), []
        )

    def test_determinism_no_runtime_identity(self):
        events = [
            event(category="SQLI", agent="sa-" + "9" * 16,
                  outcome_type="SUCCESS_OBSERVATION",
                  observed_success="SUCCESS_STRONG_EVALUATION"),
        ]
        first = json.dumps(
            generate_learning_recommendations(events), sort_keys=True
        )
        second = json.dumps(
            generate_learning_recommendations(events), sort_keys=True
        )
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first.lower())
        self.assertNotIn("uuid", first.lower())
        self.assertNotIn("runtime_id", first.lower())

    def test_json_serializable(self):
        recommendations = generate_learning_recommendations(
            signals=[signal("REDUCE_CONFIDENCE",
                            classification="CONFIDENCE_CALIBRATION")]
        )
        self.assertIsInstance(json.loads(json.dumps(recommendations)), list)

    def test_schema_rejects_bad_values(self):
        with self.assertRaises(ValidationError):
            schema.LearningRecommendationPlan(
                recommendation_type="NOT_A_TYPE"
            )
        with self.assertRaises(ValidationError):
            schema.LearningRecommendationPlan(related_category="NOPE")
        with self.assertRaises(ValidationError):
            schema.LearningRecommendationPlan(research_only=False)
        with self.assertRaises(ValidationError):
            schema.LearningRecommendationPlan(unexpected="x")

    def test_schema_forces_rule_version(self):
        plan = schema.LearningRecommendationPlan(rule_version="r99-9")
        self.assertEqual(plan.rule_version, "r44-5")
        recommendations = generate_learning_recommendations(
            signals=[signal("REQUIRE_MORE_EVIDENCE")]
        )
        self.assertEqual(recommendations[0]["rule_version"], "r44-5")

    def test_no_forbidden_imports_or_calls(self):
        for relative_path in R44_MODULES:
            imports, calls = scan_module(relative_path)
            self.assertEqual(
                imports & FORBIDDEN_MODULES, set(), relative_path
            )
            self.assertEqual(calls & FORBIDDEN_CALLS, set(), relative_path)

    def test_backend_integration_decision_is_standalone(self):
        backend_source = (
            ROOT / "backend" / "asset_cve_matching.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("research_feedback", backend_source)
        self.assertNotIn("learning_recommendation", backend_source)
        self.assertNotIn("research_learning_memory", backend_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
