"""tests/test_research_agent_r24_11.py — Stage R24.11 LLM reliability tests.

Offline, fake-only. Covers deterministic failure classification, secret-free
errors, safe fallback, budget-bounded retries, response-format handling,
deterministic-evidence survival across every LLM failure, and unchanged R24.6
safety (attribution/verdict/target exclusion) + discovery=false.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

import httpx

from ai.llm.openrouter import OpenRouterProvider
from ai.research_agent.discovery_contract import (
    DiscoveredSource,
    SourceCategory,
    TrustTier,
    discovered_source_id,
)
from ai.research_agent.llm_loop import (
    FetchedSource,
    LoopBudgets,
    run_llm_research_loop,
)
from ai.research_agent.llm_reliability import (
    LLM_AUTH_CONFIG_ERROR,
    LLM_EMPTY_CHOICES,
    LLM_HTTP_ERROR,
    LLM_MALFORMED_RESPONSE,
    LLM_RATE_LIMIT,
    LLM_SUCCESS,
    LLM_TIMEOUT,
    LLM_UNKNOWN_ERROR,
    call_llm,
    classify_llm_error,
    is_fallback_eligible,
    is_retry_eligible,
    sanitize_llm_error,
)
from ai.research_agent.queries import CVEResearchMetadata

CVE = "CVE-2026-1557"
META = CVEResearchMetadata(
    cve_id=CVE,
    product="WP Responsive Images",
    version="1.0",
    cwe="CWE-22",
    vulnerability_type="Path Traversal",
)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + CVE

VALID_ANALYSIS = json.dumps(
    {
        "summary": "public advisory summary",
        "supported_claims": [],
        "inferences": [],
        "unknowns": [],
        "contradictions": [],
        "gaps": [],
        "suggested_queries": [],
    }
)


class FakeProvider:
    def __init__(self, *, content=None, exc=None, model="fake-model"):
        self.content = content
        self.exc = exc
        self.model = model
        self.calls = 0

    def generate(self, prompt):
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        return self.content


class FlakyProvider:
    def __init__(self, *, fail_times=1, content=VALID_ANALYSIS, model="flaky"):
        self.fail_times = fail_times
        self.content = content
        self.model = model
        self.calls = 0

    def generate(self, prompt):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("OpenRouter response has no choices")
        return self.content


class _Registry:
    def __init__(self, sources):
        self._sources = sources

    def discover(self, provider_id, query):
        return list(self._sources)


def _nvd_source():
    return DiscoveredSource(
        source_id=discovered_source_id(NVD_URL),
        url=NVD_URL,
        category=SourceCategory.NVD_CVE,
        tier=TrustTier.TRUSTED,
        source_quality=0.82,
        discovery_provider="nvd",
        discovery_query=CVE,
        discovery_template_id="r24-cve-id",
    )


def _fetcher(url):
    return FetchedSource(
        url=url,
        content="Public advisory for " + CVE + " describes the issue.",
        final_url=url,
        redirect_chain=(url,),
    )


def _budgets(calls=1):
    return LoopBudgets(
        max_rounds=1,
        max_queries_per_plan=3,
        round2_reserve=0,
        max_queries_per_run=3,
        max_discovered=5,
        max_fetched_per_plan=3,
        max_fetched_per_run=3,
        max_bytes_per_run=4_000_000,
        max_llm_calls_per_plan=calls,
        max_llm_calls_per_run=calls,
    )


def _run(llm, *, fallback=None, max_retries=0, calls=1):
    return run_llm_research_loop(
        plan={"plan_id": "r22-38d26f10681e9a0f", "cve_id": CVE},
        metadata=META,
        registry=_Registry([_nvd_source()]),
        fetcher=_fetcher,
        llm=llm,
        llm_enabled=True,
        llm_fallback=fallback,
        llm_max_retries=max_retries,
        budgets=_budgets(calls),
    )


class TestClassification(unittest.TestCase):
    def test_failure_kinds(self):
        cases = {
            "OpenRouter response has no choices": LLM_EMPTY_CHOICES,
            "OpenRouter response has no message content": LLM_EMPTY_CHOICES,
            "OpenRouter connection error: APITimeoutError": LLM_TIMEOUT,
            "OpenRouter returned HTTP 429: APIStatusError": LLM_RATE_LIMIT,
            "OpenRouter returned HTTP 401: APIStatusError": LLM_AUTH_CONFIG_ERROR,
            "OpenRouter returned HTTP 403": LLM_AUTH_CONFIG_ERROR,
            "OpenRouter returned HTTP 500": LLM_HTTP_ERROR,
            "OpenRouter response content is not a string: list": LLM_MALFORMED_RESPONSE,
            "OPENROUTER_API_KEY is not configured": LLM_AUTH_CONFIG_ERROR,
            "totally unexpected": LLM_UNKNOWN_ERROR,
        }
        for message, kind in cases.items():
            with self.subTest(message=message):
                self.assertEqual(classify_llm_error(message), kind)

    def test_eligibility(self):
        for kind in (
            LLM_EMPTY_CHOICES,
            LLM_MALFORMED_RESPONSE,
            LLM_TIMEOUT,
            LLM_HTTP_ERROR,
            LLM_RATE_LIMIT,
            LLM_UNKNOWN_ERROR,
        ):
            self.assertTrue(is_fallback_eligible(kind))
            self.assertTrue(is_retry_eligible(kind))
        self.assertFalse(is_fallback_eligible(LLM_AUTH_CONFIG_ERROR))
        self.assertFalse(is_retry_eligible(LLM_AUTH_CONFIG_ERROR))

    def test_sanitize_redacts_secrets(self):
        text = sanitize_llm_error(
            "auth failed sk-abcdef123456 Authorization: Bearer abc.def"
        )
        self.assertNotIn("sk-abcdef123456", text)
        self.assertNotIn("Bearer abc.def", text)
        self.assertIn("[redacted]", text)
        self.assertLessEqual(len(text), 200)

    def test_call_llm_outcomes(self):
        ok = call_llm(FakeProvider(content='{"a":1}'), "p")
        self.assertEqual(ok.kind, LLM_SUCCESS)
        self.assertEqual(ok.content, '{"a":1}')

        empty = call_llm(FakeProvider(content="   "), "p")
        self.assertEqual(empty.kind, LLM_EMPTY_CHOICES)

        exc = call_llm(
            FakeProvider(exc=RuntimeError("OpenRouter response has no choices")), "p"
        )
        self.assertEqual(exc.kind, LLM_EMPTY_CHOICES)
        none_provider = call_llm(None, "p")
        self.assertEqual(none_provider.kind, LLM_AUTH_CONFIG_ERROR)
        self.assertEqual(none_provider.content, "")


class TestFallbackAndRetry(unittest.TestCase):
    def test_fallback_disabled_by_default(self):
        primary = FakeProvider(exc=RuntimeError("OpenRouter response has no choices"))
        result = _run(primary, fallback=None, calls=2)
        self.assertEqual(result.llm_status, "failed")
        self.assertEqual(result.llm_failure_kind, LLM_EMPTY_CHOICES)
        self.assertEqual(primary.calls, 1)

    def test_fallback_configured_used_within_budget(self):
        primary = FakeProvider(exc=RuntimeError("OpenRouter response has no choices"))
        fallback = FakeProvider(content=VALID_ANALYSIS, model="fb")
        result = _run(primary, fallback=fallback, calls=2)
        self.assertEqual(result.llm_status, "ok")
        self.assertEqual(primary.calls, 1)
        self.assertEqual(fallback.calls, 1)
        self.assertEqual(result.llm_model, "fb")

    def test_max_llm_calls_one_prevents_second_call(self):
        primary = FakeProvider(exc=RuntimeError("OpenRouter response has no choices"))
        fallback = FakeProvider(content=VALID_ANALYSIS)
        result = _run(primary, fallback=fallback, calls=1)
        self.assertEqual(result.llm_status, "failed")
        self.assertEqual(primary.calls, 1)
        self.assertEqual(fallback.calls, 0)
        self.assertEqual(result.rounds[0].evidence_count, 1)

    def test_retry_default_zero(self):
        primary = FakeProvider(exc=RuntimeError("OpenRouter response has no choices"))
        result = _run(primary, max_retries=0, calls=3)
        self.assertEqual(primary.calls, 1)
        self.assertEqual(result.llm_status, "failed")

    def test_retry_consumes_budget_and_can_succeed(self):
        primary = FlakyProvider(fail_times=1)
        result = _run(primary, max_retries=1, calls=2)
        self.assertEqual(primary.calls, 2)
        self.assertEqual(result.llm_status, "ok")

    def test_auth_error_not_retried_or_failed_over(self):
        primary = FakeProvider(
            exc=RuntimeError("OPENROUTER_API_KEY is not configured")
        )
        fallback = FakeProvider(content=VALID_ANALYSIS)
        result = _run(primary, fallback=fallback, max_retries=2, calls=3)
        self.assertEqual(primary.calls, 1)
        self.assertEqual(fallback.calls, 0)
        self.assertEqual(result.llm_failure_kind, LLM_AUTH_CONFIG_ERROR)

    def test_response_format_incompatibility_fail_soft(self):
        primary = FakeProvider(
            exc=RuntimeError(
                "OpenRouter returned HTTP 400: APIStatusError (response_format unsupported)"
            )
        )
        result = _run(primary, max_retries=0, calls=1)
        self.assertEqual(result.llm_status, "failed")
        self.assertEqual(result.llm_failure_kind, LLM_HTTP_ERROR)
        self.assertEqual(result.rounds[0].evidence_count, 1)

    def test_evidence_survives_every_failure_kind(self):
        for kind, exc in (
            (LLM_EMPTY_CHOICES, RuntimeError("OpenRouter response has no choices")),
            (LLM_MALFORMED_RESPONSE, RuntimeError("invalid json")),
            (LLM_TIMEOUT, RuntimeError("connection error: APITimeoutError")),
            (LLM_HTTP_ERROR, RuntimeError("OpenRouter returned HTTP 500")),
            (LLM_RATE_LIMIT, RuntimeError("OpenRouter returned HTTP 429")),
            (LLM_AUTH_CONFIG_ERROR, RuntimeError("OPENROUTER_API_KEY is not configured")),
            (LLM_UNKNOWN_ERROR, RuntimeError("boom")),
        ):
            with self.subTest(kind=kind):
                result = _run(FakeProvider(exc=exc), calls=1)
                self.assertEqual(result.llm_status, "failed")
                self.assertEqual(result.llm_failure_kind, kind)
                self.assertEqual(result.rounds[0].evidence_count, 1)
                self.assertFalse(result.production_finding)
                self.assertTrue(result.public_research_only)
                self.assertNotIn("VERIFIED", result.status)


class TestSafetyUnchanged(unittest.TestCase):
    def test_attribution_and_verdict_filtering(self):
        ctx_source = _nvd_source()
        # claim with invented source id + forbidden verdict -> dropped
        payload = json.dumps(
            {
                "summary": "the target is VULNERABLE",
                "supported_claims": [
                    {"claim": "invented", "source_ids": ["ds-invented"]},
                    {"claim": "verified target issue", "source_ids": [ctx_source.source_id]},
                ],
                "inferences": [],
                "unknowns": [],
                "contradictions": [],
                "gaps": [],
                "suggested_queries": [],
            }
        )
        result = _run(FakeProvider(content=payload), calls=1)
        self.assertEqual(result.llm_status, "ok")
        self.assertEqual(result.analysis.summary, "")
        self.assertEqual(result.analysis.supported_claims, [])

    def test_target_token_exclusion_unchanged(self):
        from ai.research_agent.llm_research import build_llm_context

        source = _nvd_source().model_copy(update={"title": "dell internal note"})
        # build a block via the loop to get a real context source
        from ai.research_agent.evidence import integrate_discovery

        block = integrate_discovery(
            [source], {source.source_id: "content"}, discovery_enabled=True
        )
        ctx = build_llm_context(
            block, META, content_by_source_id={source.source_id: "content"},
            forbidden_tokens=["dell"],
        )
        blob = json.dumps(ctx.model_dump(mode="json")).lower()
        self.assertNotIn("dell", blob)
        self.assertGreaterEqual(ctx.excluded_forbidden, 1)

    def test_no_secrets_in_errors(self):
        secret = "sk-supersecret123456"
        primary = FakeProvider(
            exc=RuntimeError(f"auth failed {secret} Authorization: Bearer tok")
        )
        result = _run(primary, calls=1)
        self.assertNotIn(secret, json.dumps(result.model_dump(mode="json")))
        self.assertNotIn("Bearer tok", result.llm_error or "")

    def test_discovery_false_unchanged(self):
        from ai import research_cli
        from ai.research_agent.agent import ResearchAgent
        from ai.research_agent.discovery_runner import DiscoveryResearchAgent
        from ai.research_agent.scheduler import SchedulerConfig

        agent = research_cli._build_research_agent(SchedulerConfig())
        self.assertIsInstance(agent, ResearchAgent)
        self.assertNotIsInstance(agent, DiscoveryResearchAgent)


class TestOpenRouterResponseFormat(unittest.TestCase):
    def _payload(self):
        return {
            "id": "r1",
            "model": "m",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": '{"ok":1}'}}
            ],
        }

    def test_response_format_toggle(self):
        captured = {}

        def handler(request):
            captured["body"] = json.loads(request.content.decode())
            return httpx.Response(200, json=self._payload())

        client = httpx.Client(transport=httpx.MockTransport(handler))
        default = OpenRouterProvider(api_key="k", model="m", http_client=client)
        default.generate("p")
        self.assertEqual(captured["body"]["response_format"], {"type": "json_object"})

        captured.clear()
        compat = OpenRouterProvider(
            api_key="k", model="m", http_client=client, response_format_json=False
        )
        compat.generate("p")
        self.assertNotIn("response_format", captured["body"])


class TestSchedulerLlmConfig(unittest.TestCase):
    def test_defaults_safe(self):
        from ai.research_agent.scheduler import SchedulerConfig

        cfg = SchedulerConfig.from_env({})
        self.assertEqual(cfg.llm_fallback_model, "")
        self.assertEqual(cfg.llm_max_retries, 0)
        self.assertEqual(cfg.llm_response_format, "json")
        self.assertFalse(cfg.discovery)

    def test_env_overrides(self):
        from ai.research_agent.scheduler import SchedulerConfig

        cfg = SchedulerConfig.from_env(
            {
                "WATCH_RESEARCH_LLM_MODEL": "primary/model",
                "WATCH_RESEARCH_LLM_FALLBACK_MODEL": "fallback/model",
                "WATCH_RESEARCH_LLM_MAX_RETRIES": "1",
                "WATCH_RESEARCH_LLM_RESPONSE_FORMAT": "text",
            }
        )
        self.assertEqual(cfg.llm_model, "primary/model")
        self.assertEqual(cfg.llm_fallback_model, "fallback/model")
        self.assertEqual(cfg.llm_max_retries, 1)
        self.assertEqual(cfg.llm_response_format, "text")


if __name__ == "__main__":
    unittest.main()
