"""tests/test_security_agent_result.py — Stage R38.5 tests.

Deterministic, offline tests for the security agent result contract:

- exact status/findings/evidence/limitation vocabularies
- result validation and confidence mapping per status
- overclaim prevention (UNKNOWN forces UNKNOWN; FAILED downgrades/suppresses)
- malformed and empty input handling
- JSON serialization, schema validation
- research_only always true, no payload/exploit/execution output

No network, no DNS, no LLM, no subprocess, no target interaction, no Mongo
writes, no persistence, no execution of any kind.
"""
import json
import sys
import unittest

sys.path.insert(0, "/opt/watch")

from pydantic import ValidationError

from ai.knowledge import security_agent_result_validator as validator
from ai.schemas import security_agent_result as schema
from ai.schemas.evidence_confidence import CONFIDENCE_LEVELS


class TestSecurityAgentResult(unittest.TestCase):
    def test_status_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.AGENT_RESULT_STATUSES),
            {"CREATED", "ANALYZING", "COMPLETED", "FAILED", "UNKNOWN"},
        )

    def test_findings_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.FINDINGS_SUMMARIES),
            {"NO_FINDINGS", "OBSERVATIONS_RECORDED",
             "HYPOTHESES_RECORDED", "UNKNOWN"},
        )

    def test_evidence_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.EVIDENCE_SUMMARIES),
            {"EVIDENCE_NONE", "EVIDENCE_PARTIAL", "EVIDENCE_SUFFICIENT",
             "UNKNOWN"},
        )

    def test_limitation_vocabulary_is_exact(self):
        self.assertEqual(
            set(schema.RESULT_LIMITATIONS),
            {"RESULT_UNKNOWN", "CONFIDENCE_DOWNGRADED",
             "FINDINGS_SUPPRESSED", "NO_EXECUTION_PERFORMED"},
        )

    def test_confidence_uses_shared_closed_vocabulary(self):
        self.assertEqual(
            set(CONFIDENCE_LEVELS),
            {"HIGH", "MEDIUM", "LOW", "UNKNOWN"},
        )

    def test_completed_result_preserved(self):
        plan = validator.validate_security_agent_result(
            agent_name="xss-agent",
            status="COMPLETED",
            confidence="MEDIUM",
            findings_summary="HYPOTHESES_RECORDED",
            evidence_summary="EVIDENCE_PARTIAL",
        )
        self.assertEqual(plan["status"], "COMPLETED")
        self.assertEqual(plan["confidence"], "MEDIUM")
        self.assertEqual(plan["findings_summary"], "HYPOTHESES_RECORDED")
        self.assertEqual(plan["evidence_summary"], "EVIDENCE_PARTIAL")
        self.assertEqual(plan["limitations"],
                         ["NO_EXECUTION_PERFORMED"])

    def test_unknown_status_forces_unknown(self):
        plan = validator.validate_security_agent_result(
            status="UNKNOWN",
            confidence="HIGH",
            findings_summary="HYPOTHESES_RECORDED",
            evidence_summary="EVIDENCE_SUFFICIENT",
        )
        self.assertEqual(plan["confidence"], "UNKNOWN")
        self.assertEqual(plan["findings_summary"], "UNKNOWN")
        self.assertEqual(plan["evidence_summary"], "UNKNOWN")
        self.assertIn("RESULT_UNKNOWN", plan["limitations"])

    def test_malformed_status_becomes_unknown(self):
        for value in (None, "", "DONE", 42):
            plan = validator.validate_security_agent_result(status=value)
            self.assertEqual(plan["status"], "UNKNOWN", repr(value))

    def test_confidence_mapping_completed(self):
        for value in ("HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            plan = validator.validate_security_agent_result(
                status="COMPLETED", confidence=value
            )
            self.assertEqual(plan["confidence"], value)

    def test_failed_downgrades_confidence(self):
        for source, expected in (("HIGH", "LOW"), ("MEDIUM", "LOW")):
            plan = validator.validate_security_agent_result(
                status="FAILED", confidence=source
            )
            self.assertEqual(plan["confidence"], expected, source)
            self.assertIn("CONFIDENCE_DOWNGRADED", plan["limitations"])

    def test_failed_low_confidence_not_downgraded(self):
        plan = validator.validate_security_agent_result(
            status="FAILED", confidence="LOW"
        )
        self.assertEqual(plan["confidence"], "LOW")
        self.assertNotIn("CONFIDENCE_DOWNGRADED", plan["limitations"])

    def test_failed_suppresses_findings(self):
        plan = validator.validate_security_agent_result(
            status="FAILED",
            confidence="HIGH",
            findings_summary="HYPOTHESES_RECORDED",
        )
        self.assertEqual(plan["findings_summary"], "NO_FINDINGS")
        self.assertIn("FINDINGS_SUPPRESSED", plan["limitations"])

    def test_pending_statuses_suppress_findings(self):
        for status in ("CREATED", "ANALYZING"):
            plan = validator.validate_security_agent_result(
                status=status,
                confidence="MEDIUM",
                findings_summary="OBSERVATIONS_RECORDED",
            )
            self.assertEqual(plan["confidence"], "MEDIUM", status)
            self.assertEqual(plan["findings_summary"], "NO_FINDINGS",
                             status)
            self.assertIn("FINDINGS_SUPPRESSED", plan["limitations"])

    def test_invalid_confidence_becomes_unknown(self):
        plan = validator.validate_security_agent_result(
            status="COMPLETED", confidence="CERTAIN"
        )
        self.assertEqual(plan["confidence"], "UNKNOWN")

    def test_invalid_findings_and_evidence_become_unknown(self):
        plan = validator.validate_security_agent_result(
            status="COMPLETED",
            findings_summary="CONFIRMED_VULN",
            evidence_summary="PROVEN",
        )
        self.assertEqual(plan["findings_summary"], "UNKNOWN")
        self.assertEqual(plan["evidence_summary"], "UNKNOWN")

    def test_limitations_deduped_and_filtered(self):
        plan = validator.validate_security_agent_result(
            status="FAILED",
            confidence="HIGH",
            limitations=[
                "FINDINGS_SUPPRESSED",
                "FINDINGS_SUPPRESSED",
                "NOT_A_CODE",
                "RESULT_UNKNOWN",
            ],
        )
        self.assertEqual(plan["limitations"].count("FINDINGS_SUPPRESSED"),
                         1)
        self.assertEqual(plan["limitations"].count("RESULT_UNKNOWN"), 1)
        self.assertNotIn("NOT_A_CODE", plan["limitations"])

    def test_empty_input(self):
        plan = validator.validate_security_agent_result()
        self.assertEqual(plan["agent_name"], "")
        self.assertEqual(plan["status"], "UNKNOWN")
        self.assertEqual(plan["confidence"], "UNKNOWN")
        self.assertIs(plan["research_only"], True)

    def test_fixed_key_set_no_execution_logs(self):
        plan = validator.validate_security_agent_result()
        self.assertEqual(
            set(plan.keys()),
            {"rule_version", "agent_name", "status", "confidence",
             "findings_summary", "evidence_summary", "limitations",
             "research_only"},
        )
        for key in ("payload", "exploit", "request", "response",
                    "timestamp", "logs"):
            self.assertNotIn(key, plan)

    def test_deterministic_output(self):
        kwargs = {
            "agent_name": "xss-agent",
            "status": "COMPLETED",
            "confidence": "HIGH",
            "findings_summary": "OBSERVATIONS_RECORDED",
            "evidence_summary": "EVIDENCE_PARTIAL",
        }
        first = validator.validate_security_agent_result(**kwargs)
        second = validator.validate_security_agent_result(**kwargs)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_json_serializable(self):
        plan = validator.validate_security_agent_result(status="COMPLETED")
        self.assertIsInstance(json.loads(json.dumps(plan)), dict)

    def test_research_only_always_true(self):
        plan = validator.validate_security_agent_result()
        self.assertIs(plan["research_only"], True)

    def test_no_execution_content(self):
        blob = json.dumps(
            [
                validator.validate_security_agent_result(
                    status=status, confidence="HIGH"
                )
                for status in schema.AGENT_RESULT_STATUSES
            ]
        ).lower()
        for marker in (
            "http://", "https://", "payload", "fuzz", "nuclei",
            "sqlmap", "subprocess", "shell", "browser", "worker",
            "scheduler", "docker", "systemd", "timestamp", "request(",
        ):
            self.assertNotIn(marker, blob)

    def test_schema_rejects_bad_values(self):
        base = {
            "agent_name": "xss-agent",
            "status": "COMPLETED",
            "confidence": "HIGH",
            "findings_summary": "OBSERVATIONS_RECORDED",
            "evidence_summary": "EVIDENCE_PARTIAL",
            "limitations": [],
        }
        for key, value in (
            ("status", "DONE"),
            ("confidence", "CERTAIN"),
            ("findings_summary", "CONFIRMED"),
            ("evidence_summary", "PROVEN"),
            ("limitations", ["NOT_A_CODE"]),
        ):
            with self.assertRaises(ValidationError):
                schema.SecurityAgentResultPlan(**{**base, key: value})
        with self.assertRaises(ValidationError):
            schema.SecurityAgentResultPlan(
                **base, payload="<script>alert(1)</script>"
            )

    def test_schema_forces_rule_version_and_research_only(self):
        plan = schema.SecurityAgentResultPlan(
            rule_version="r99-9",
            agent_name="xss-agent",
            status="UNKNOWN",
            confidence="UNKNOWN",
            findings_summary="UNKNOWN",
            evidence_summary="UNKNOWN",
            research_only=True,
        )
        self.assertEqual(plan.rule_version, "r38-5")
        with self.assertRaises(ValidationError):
            schema.SecurityAgentResultPlan(
                agent_name="xss-agent",
                status="UNKNOWN",
                confidence="UNKNOWN",
                findings_summary="UNKNOWN",
                evidence_summary="UNKNOWN",
                research_only=False,
            )

    def test_exact_rule_version(self):
        self.assertEqual(
            validator.SECURITY_AGENT_RESULT_VALIDATOR_RULE_VERSION,
            "r38-5",
        )
        self.assertEqual(
            validator.validate_security_agent_result()["rule_version"],
            "r38-5",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
