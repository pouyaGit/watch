"""tests/test_llm_provider_integration.py — Stage R51 integration tests.

Deterministic, offline integration tests for the R51 advisory bridge:

- R45 compatibility through the unmodified advisory export/validator
- R42 evaluation, R43 collaboration and R44 learning inputs
- specialist interoperability (R46-R50 structured results)
- single bounded provider call per bridge invocation
- deterministic envelope, mock compatibility and fail-closed selection
- no orchestrator dispatch and no real network transport use

No real API calls, no network, no LLM, no subprocess, no sockets, no
browser, no SQL, no database, no payloads, no Mongo writes, no
persistence, no execution of any kind.
"""
import ast
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from ai.knowledge.agent_evaluation_export import evaluate_agent_result
from ai.knowledge.api_security_agent_result_export import (
    export_api_security_agent_result,
)
from ai.knowledge.cve_research_agent_result_export import (
    export_cve_research_agent_result,
)
from ai.knowledge.idor_bola_agent_result_export import (
    export_idor_bola_agent_result,
)
from ai.knowledge.jwt_authentication_agent_result_export import (
    export_jwt_authentication_agent_result,
)
from ai.knowledge.learning_signal_extractor import extract_learning_signals
from ai.knowledge.llm_advisory_export import export_llm_advisory
from ai.knowledge.multi_agent_collaboration_export import (
    export_multi_agent_collaboration,
)
from ai.knowledge.oauth_agent_result_export import (
    export_oauth_agent_result,
)
from ai.knowledge.research_feedback_classifier import (
    classify_research_feedback_events,
)
from ai.knowledge.research_feedback_event import build_research_feedback_event
from ai.providers import (
    BRIDGE_KEYS,
    export_real_llm_advisory,
    HttpTransport,
    HttpResponseSpec,
)
from ai.providers.http_transport import UrllibHttpTransport


ROOT = Path(__file__).resolve().parents[1]

SECRET = "not-a-real-integration-credential"


class RecordingTransport(HttpTransport):
    transport_kind = "RECORDING"

    def __init__(self, content=None, status=200):
        self.status = status
        self.content = content if content is not None else success_content()
        self.requests = []

    def send(self, spec):
        self.requests.append(spec)
        return HttpResponseSpec(
            status_code=self.status,
            body_text=json.dumps(
                {"choices": [{"message": {"content": self.content}}]}
            ),
        )


def success_content():
    return json.dumps(
        {
            "summary": "Bounded advisory summary.",
            "insights": [
                {
                    "insight_code": "ADVISORY_SCOPE",
                    "text": "Advisory explanation only.",
                }
            ],
            "recommendations": [],
        }
    )


def provider_environ():
    return {
        "OPENROUTER_API_KEY": SECRET,
        "OPENROUTER_MODEL": "vendor/model",
    }


def cve_result():
    return export_cve_research_agent_result(
        cve_metadata="OBSERVED",
        version_match="MATCH_OBSERVED",
    )


def api_result():
    return export_api_security_agent_result(
        api_type="REST",
        api_authentication="ABSENT_OBSERVED",
    )


def collaboration_result():
    return export_multi_agent_collaboration(
        [
            export_jwt_authentication_agent_result(
                token_mechanism="JWT",
                signature_verification="ABSENT_OBSERVED",
            ),
            export_oauth_agent_result(
                oauth_version="OAUTH2",
                flow="AUTHORIZATION_CODE_PKCE",
                client_type="PUBLIC_CLIENT",
                state_validation="ABSENT_OBSERVED",
            ),
        ]
    )


def learning_signals():
    evaluation = evaluate_agent_result(cve_result())
    event = build_research_feedback_event(evaluation_result=evaluation)
    return extract_learning_signals(
        classify_research_feedback_events([event])
    )


def run_bridge(**over):
    defaults = {
        "evaluation_result": evaluate_agent_result(cve_result()),
        "provider_kind": "OPENROUTER",
        "transport": RecordingTransport(),
        "environ": provider_environ(),
    }
    defaults.update(over)
    return export_real_llm_advisory(**defaults)


class TestProviderIntegration(unittest.TestCase):
    def test_envelope_key_set_is_exact(self):
        result = run_bridge()
        self.assertEqual(set(result.keys()), set(BRIDGE_KEYS))
        self.assertIs(result["research_only"], True)
        self.assertIs(result["deterministic"], True)

    def test_r45_compatibility(self):
        result = run_bridge()
        advisory = result["advisory_result"]
        self.assertEqual(
            set(advisory.keys()),
            {"rule_version", "advisory_rule_version", "advisory_id",
             "advisory_mode", "summary", "insights", "recommendations",
             "source_refs", "provenance", "governance", "validation_state",
             "validation_diagnostics", "safety_state", "limitations",
             "research_only", "deterministic"},
        )
        self.assertEqual(advisory["validation_state"], "PASS")
        self.assertEqual(advisory["safety_state"], "PASS")
        self.assertEqual(advisory["provenance"]["research_only"], True)
        self.assertEqual(
            advisory["governance"]["governance_state"], "UNKNOWN"
        )

    def test_r42_evaluation_input(self):
        evaluation = evaluate_agent_result(cve_result())
        result = run_bridge(evaluation_result=evaluation)
        self.assertEqual(result["provider_state"], "OK")
        telemetry = result["provider_telemetry"]
        self.assertEqual(telemetry["advisory_mode"], "EXPLANATION")
        self.assertEqual(telemetry["validation_state"], "PASS")

    def test_r43_collaboration_input(self):
        result = run_bridge(
            collaboration_result=collaboration_result()
        )
        self.assertEqual(result["provider_state"], "OK")
        self.assertEqual(
            result["advisory_result"]["validation_state"], "PASS"
        )

    def test_r44_learning_input(self):
        signals = learning_signals()
        self.assertTrue(signals)
        result = run_bridge(learning_signals=signals)
        self.assertEqual(result["provider_state"], "OK")
        self.assertEqual(
            result["advisory_result"]["validation_state"], "PASS"
        )

    def test_specialist_interoperability(self):
        specialists = (
            export_idor_bola_agent_result(
                object_reference="PATH_PARAMETER",
                ownership_relationship="OWNER_RECORDED",
                object_lookup="LOOKUP_BY_IDENTIFIER",
                authorization_control="AUTHORIZATION_ABSENT",
            ),
            export_jwt_authentication_agent_result(
                token_mechanism="JWT",
                signature_verification="ABSENT_OBSERVED",
            ),
            export_oauth_agent_result(
                oauth_version="OAUTH2",
                flow="AUTHORIZATION_CODE_PKCE",
                client_type="PUBLIC_CLIENT",
                state_validation="ABSENT_OBSERVED",
            ),
            api_result(),
            cve_result(),
        )
        for specialist in specialists:
            evaluation = evaluate_agent_result(specialist)
            result = run_bridge(evaluation_result=evaluation)
            self.assertEqual(result["provider_state"], "OK")
            self.assertEqual(
                result["advisory_result"]["validation_state"], "PASS"
            )

    def test_full_chain_evaluation_collaboration_learning_advisory(self):
        evaluation = evaluate_agent_result(api_result())
        collaboration = collaboration_result()
        signals = learning_signals()
        result = run_bridge(
            evaluation_result=evaluation,
            collaboration_result=collaboration,
            learning_signals=signals,
        )
        self.assertEqual(result["provider_state"], "OK")
        refs = {
            (ref["layer"], ref["reference"])
            for ref in result["advisory_result"]["source_refs"]
        }
        self.assertIn(("R42", "r42-5"), refs)
        self.assertIn(("R43", "r43-6"), refs)
        self.assertIn(("R44", "r44-3"), refs)

    def test_single_provider_call_per_bridge(self):
        transport = RecordingTransport()
        result = run_bridge(transport=transport)
        self.assertEqual(result["provider_state"], "OK")
        self.assertEqual(len(transport.requests), 1)

    def test_bridge_is_deterministic_for_identical_provider_output(self):
        first = run_bridge()
        second = run_bridge()
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )

    def test_bridge_telemetry_safe_fields(self):
        result = run_bridge()
        telemetry = result["provider_telemetry"]
        self.assertEqual(telemetry["provider_kind"], "OPENROUTER")
        self.assertEqual(telemetry["model"], "vendor/model")
        self.assertEqual(telemetry["attempt_count"], 1)
        self.assertEqual(telemetry["retry_count"], 0)
        self.assertIs(telemetry["external_provider"], True)
        self.assertIs(telemetry["network_access"], True)
        self.assertIs(telemetry["content_deterministic"], False)
        self.assertIs(result["content_deterministic"], False)

    def test_bridge_unknown_kind_is_structured_error(self):
        result = run_bridge(provider_kind="OLLAMA", transport=None)
        self.assertEqual(result["provider_state"], "ERROR")
        self.assertEqual(
            result["provider_error"]["error_code"], "CONFIG_UNSUPPORTED_KIND"
        )
        self.assertIsNone(result["advisory_result"])

    def test_bridge_missing_credentials_is_structured_error(self):
        result = run_bridge(environ={})
        self.assertEqual(result["provider_state"], "ERROR")
        self.assertEqual(
            result["provider_error"]["error_code"],
            "CONFIG_MISSING_CREDENTIAL",
        )

    def test_bridge_mock_provider_compatibility(self):
        result = export_real_llm_advisory(
            evaluation_result=evaluate_agent_result(cve_result()),
            provider_kind="MOCK",
        )
        self.assertEqual(result["provider_state"], "OK")
        self.assertEqual(
            result["advisory_result"]["validation_state"], "PASS"
        )
        self.assertIs(result["provider_telemetry"]["network_access"], False)

    def test_bridge_injected_mock_provider(self):
        from ai.knowledge.llm_provider import MockLLMProvider

        result = export_real_llm_advisory(
            evaluation_result=evaluate_agent_result(cve_result()),
            provider=MockLLMProvider(),
        )
        self.assertEqual(result["provider_state"], "OK")
        self.assertEqual(result["provider_kind"], "MOCK")

    def test_no_real_transport_use_in_tests(self):
        original = UrllibHttpTransport.send

        def forbidden(self, spec):  # pragma: no cover - guard
            raise AssertionError("real network transport was invoked")

        UrllibHttpTransport.send = forbidden
        try:
            result = run_bridge()
            self.assertEqual(result["provider_state"], "OK")
        finally:
            UrllibHttpTransport.send = original

    def test_export_llm_advisory_mock_unchanged(self):
        result = export_llm_advisory(
            evaluation_result=evaluate_agent_result(cve_result())
        )
        self.assertEqual(result["validation_state"], "PASS")
        self.assertEqual(result["safety_state"], "PASS")

    def test_no_orchestrator_or_specialist_dispatch(self):
        source = (
            ROOT / "ai" / "providers" / "advisory_bridge.py"
        ).read_text(encoding="utf-8")
        for token in (
            "agent_result_export",
            "xss_agent",
            "ssrf_agent",
            "sqli_agent",
            "idor_bola",
            "jwt_authentication",
            "oauth_",
            "api_security",
            "cve_research",
        ):
            self.assertNotIn(token, source)

    def test_provider_layer_has_no_execution_claims(self):
        for path in (ROOT / "ai" / "providers").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        self.assertNotIn(
                            node.func.id,
                            {"eval", "exec", "compile", "__import__"},
                            str(path),
                        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
