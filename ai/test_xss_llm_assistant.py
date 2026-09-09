"""Stage R7 tests: LLM-assisted XSS research assistant.

All provider interactions use a mock/stub LLMProvider — no real
LLM/network calls. Deterministic candidates come from the real
persisted artifacts loaded into a temp KnowledgeStore (isolated copy),
mirroring the R6 E2E setup. Guards: the real ai_data tree is read-only
input and its hashes must not change.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ai.llm.base import LLMProvider, LLMResult
from ai.researcher.xss_llm_assistant import (
    XSSLLMResearchAssistant,
    XSSLLMResearchError,
    _build_prompt,
    persist_research,
)
from ai.schemas.xss import XSSLLMResearchAssistantResult

REAL_RESEARCH_DIR = Path("ai_data/research")
REAL_KB_DIR = Path("ai_data/knowledge")
REAL_XSS_DIR = REAL_RESEARCH_DIR / "xss"

CVE = "CVE-2026-1557"
XSS_QUERY = "reflected XSS wordpress plugin parameter"
XSS_CANDIDATE_ID = "xss-488f639165085224"
KB_ID = "kb-609f38e9c57c0592"


class StubLLM:
    """Mock LLMProvider returning a configured body (or raising)."""

    def __init__(self, content: str) -> None:
        self._content = content
        self.call_count = 0
        self.last_prompt: str | None = None

    def complete(self, prompt: str) -> LLMResult:
        self.call_count += 1
        self.last_prompt = prompt
        return LLMResult(content=self._content, request_id="or-stub", model="stub/model")


class FailingLLM(Exception):
    pass


class RaisingLLM:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def complete(self, prompt: str) -> LLMResult:
        raise self._exc


class GenerateOnlyLLM(LLMProvider):
    """Provider implementing ONLY the abstract ``generate`` interface.

    Proves the provider-agnostic boundary: the base-class
    :meth:`LLMProvider.complete` default wraps ``generate`` into an
    :class:`LLMResult`, so a minimal non-OpenRouter provider can be
    swapped in through configuration/DI without touching the XSS
    research layer.
    """

    def __init__(self, content: str) -> None:
        self._content = content
        self.calls = 0
        self.last_prompt: str | None = None

    def generate(self, prompt: str) -> str:
        self.calls += 1
        self.last_prompt = prompt
        return self._content


def _snapshot(paths: list[Path]) -> dict[str, str]:
    out: dict[str, str] = {}
    for root in paths:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file():
                out[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def _valid_llm_body(candidate: dict) -> dict:
    """A structurally valid model response.

    The model is NOT asked for content_hash (verifier-derived binding),
    so the fixture deliberately omits it — this is the R9.3 regression
    fixture that would have caught the R9 failure mode.
    """
    return {
        "candidate_id": candidate["candidate_id"],
        "status": candidate["status"],
        "confidence": candidate["confidence"],
        "explanation": (
            "The supplied evidence indicates reflected XSS in an HTML "
            "attribute context. Actual exploitation is not established "
            "by the supplied evidence."
        ),
        "likely_attack_surface": "wordpress plugin parameter",
        "relevant_context": "html_attribute",
        "supporting_reasoning": [
            "exact xss_type match on a supplied seed document"
        ],
        "missing_evidence": [
            "live reflection: not observed (no target contacted)"
        ],
        "suggested_test_idea": None,
        "references_used": [KB_ID],
        "evidence": [
            {
                "kind": "EVIDENCE",
                "text": "The supplied KB evidence states reflected XSS "
                "in a quoted HTML attribute.",
                "knowledge_ids": [KB_ID],
            },
            {
                "kind": "UNKNOWN",
                "text": "Cookie theft is not established by the supplied evidence.",
                "knowledge_ids": [],
            },
        ],
    }


class XSSLLMResearchAssistantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ai.knowledge.ingestion import ingest_research
        from ai.knowledge.store import KnowledgeStore
        from ai.researcher.xss_agent import build_candidate

        cls.tmp = TemporaryDirectory()
        root = Path(cls.tmp.name)
        rdir = root / "research"
        rdir.mkdir(parents=True)
        shutil.copyfile(
            REAL_RESEARCH_DIR / f"{CVE}.cli.json",
            rdir / f"{CVE}.cli.json",
        )
        cls.store = KnowledgeStore(root / "knowledge")
        cls.research_dir = rdir
        cls.xss_dir = root / "xss"
        ingest_research(CVE, cls.store, research_dir=rdir)
        from ai.researcher.xss_agent import persist_candidate

        cls.candidate_obj = build_candidate(XSS_QUERY, store=cls.store)
        cls.candidate_path = persist_candidate(
            cls.candidate_obj, research_dir=cls.xss_dir
        )
        cls.candidate_digest = hashlib.sha256(
            cls.candidate_path.read_bytes()
        ).hexdigest()
        cls.candidate = cls.candidate_obj.model_dump(mode="json")
        from ai.researcher.xss_llm_assistant import _candidate_content_hash

        cls.candidate["content_hash"] = _candidate_content_hash(cls.candidate)
        cls._before = _snapshot([REAL_KB_DIR, REAL_XSS_DIR])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def tearDown(self):
        self.assertEqual(
            _snapshot([REAL_KB_DIR, REAL_XSS_DIR]),
            self.__class__._before,
            "tests must not write to the real ai_data tree",
        )

    def _assistant(self, body: str) -> tuple[XSSLLMResearchAssistant, StubLLM]:
        stub = StubLLM(body)
        return XSSLLMResearchAssistant(stub), stub

    def test_deterministic_candidate_authority_status_unchanged(self):
        body = _valid_llm_body(self.candidate)
        assistant, _ = self._assistant(json.dumps(body))
        result = assistant.research(self.candidate, self.store)
        self.assertEqual(result.status, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result.confidence, 0.35)

    def test_rejected_cannot_become_candidate(self):
        rejected = dict(self.candidate)
        rejected["status"] = "REJECTED"
        rejected["confidence"] = 0.0
        rejected["references"] = []
        body = _valid_llm_body(rejected)
        body["status"] = "REJECTED"
        body["confidence"] = 0.0
        body["references_used"] = []
        body["evidence"] = []
        assistant, _ = self._assistant(json.dumps(body))
        # REJECTED has no evidence → fails closed, no LLM call.
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(rejected, self.store)

    def test_insufficient_cannot_upgrade_to_candidate(self):
        body = _valid_llm_body(self.candidate)
        body["status"] = "RESEARCH_CANDIDATE"  # attempted upgrade
        assistant, _ = self._assistant(json.dumps(body))
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(self.candidate, self.store)

    def test_confidence_cannot_be_overridden(self):
        body = _valid_llm_body(self.candidate)
        body["confidence"] = 0.9
        assistant, _ = self._assistant(json.dumps(body))
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(self.candidate, self.store)

    def test_status_downgrade_rejected(self):
        body = _valid_llm_body(self.candidate)
        body["status"] = "REJECTED"  # attempted downgrade
        assistant, _ = self._assistant(json.dumps(body))
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(self.candidate, self.store)

    # -- R9.3 content_hash binding fix ----------------------------------

    def test_valid_response_without_content_hash_succeeds(self):
        """A: model output without content_hash must pass (R9 regression)."""
        body = _valid_llm_body(self.candidate)
        self.assertNotIn("content_hash", body)
        assistant, _ = self._assistant(json.dumps(body))
        result = assistant.research(self.candidate, self.store)
        self.assertEqual(result.status, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result.confidence, 0.35)
        # B: the verifier-derived hash is stamped onto the result.
        self.assertEqual(result.content_hash, self.candidate["content_hash"])

    def test_model_supplied_wrong_content_hash_ignored(self):
        """C+D: a model-supplied content_hash can never override the binding."""
        body = _valid_llm_body(self.candidate)
        body["content_hash"] = "0" * 64  # model guesses wildly wrong
        assistant, _ = self._assistant(json.dumps(body))
        result = assistant.research(self.candidate, self.store)
        self.assertEqual(result.content_hash, self.candidate["content_hash"])

    def test_model_supplied_correct_content_hash_also_ignored(self):
        """Model echo of the exact hash is discarded too (never trusted)."""
        body = _valid_llm_body(self.candidate)
        body["content_hash"] = self.candidate["content_hash"]
        assistant, _ = self._assistant(json.dumps(body))
        result = assistant.research(self.candidate, self.store)
        self.assertEqual(result.content_hash, self.candidate["content_hash"])

    def test_prompt_hides_hash_and_does_not_ask_for_it(self):
        """E+F: prompt neither exposes nor requests content_hash."""
        assistant, stub = self._assistant(
            json.dumps(_valid_llm_body(self.candidate))
        )
        assistant.research(self.candidate, self.store)
        self.assertNotIn(self.candidate["content_hash"], stub.last_prompt)
        self.assertNotIn("content_hash", stub.last_prompt)

    def test_changed_candidate_different_content_hash(self):
        """G: a different candidate payload produces a different hash."""
        from ai.researcher.xss_llm_assistant import _candidate_content_hash

        changed = dict(self.candidate)
        changed["confidence"] = 0.4
        self.assertNotEqual(
            _candidate_content_hash(changed),
            _candidate_content_hash(self.candidate),
        )

    def test_r9_failure_mode_impossible(self):
        """L: the R9 real-failure mode (mismatched hash on valid output) is gone.

        Full pipeline with a content_hash-less, structurally valid model
        response now succeeds and the persisted record carries the
        verifier-stamped binding.
        """
        import argparse

        from ai.research_cli import run_xss_llm_research

        stub = StubLLM(json.dumps(_valid_llm_body(self.candidate)))
        args = argparse.Namespace(candidate_id=XSS_CANDIDATE_ID, output=None)
        rc = run_xss_llm_research(
            args,
            store=self.store,
            research_dir=self.xss_dir,
            llm=stub,
        )
        self.assertEqual(rc, 0)
        persisted = json.loads(
            (self.xss_dir / "llm" / f"{XSS_CANDIDATE_ID}.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(persisted["content_hash"], self.candidate["content_hash"])
        self.assertEqual(persisted["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(persisted["confidence"], 0.35)

    def test_cli_success_path_persists(self):
        import argparse

        from ai.research_cli import run_xss_llm_research

        stub = StubLLM(json.dumps(_valid_llm_body(self.candidate)))
        args = argparse.Namespace(
            candidate_id=XSS_CANDIDATE_ID,
            output=None,
        )
        rc = run_xss_llm_research(
            args,
            store=self.store,
            research_dir=self.xss_dir,
            llm=stub,
        )
        self.assertEqual(rc, 0)
        out = self.xss_dir / "llm" / f"{XSS_CANDIDATE_ID}.json"
        self.assertTrue(out.exists())
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(payload["confidence"], 0.35)

    def test_cli_provider_failure_exits_nonzero_no_partial(self):
        """Provider construction failure → clear ERROR, exit 1, no file."""
        import argparse
        from unittest import mock

        from ai.research_cli import run_xss_llm_research

        args = argparse.Namespace(
            candidate_id=XSS_CANDIDATE_ID,
            output=None,
        )
        with mock.patch(
            "ai.llm.openrouter.OpenRouterProvider",
            side_effect=XSSLLMResearchError("provider not configured"),
        ):
            rc = run_xss_llm_research(args, store=self.store, research_dir=self.xss_dir)
        self.assertEqual(rc, 1)
        self.assertFalse((self.xss_dir / "llm" / f"{XSS_CANDIDATE_ID}.json").exists())

    def test_cli_inflight_provider_failure_clean_error_no_leak(self):
        """R9.1: in-flight provider failure → clean ERROR, exit 1.

        Mocks an in-flight OpenRouterProviderError (with a chained cause
        carrying fake account metadata, mimicking the R9 leak mechanism)
        and verifies: exit code 1, clean ERROR output, no traceback, no
        API key, no user_id/account metadata, no persisted output.
        """
        import argparse
        import io
        import os
        from contextlib import redirect_stderr
        from unittest import mock

        from ai.llm.openrouter import OpenRouterProviderError
        from ai.research_cli import run_xss_llm_research

        args = argparse.Namespace(
            candidate_id=XSS_CANDIDATE_ID,
            output=None,
        )
        failure = OpenRouterProviderError(
            "OpenRouter returned HTTP 404: NotFoundError"
        )
        # Chained raw-provider body carrying account metadata, as in R9.
        failure.__cause__ = ValueError(
            "response body: {'user_id': 'user_SENTINEL9XQ2', "
            "'key': 'sk-or-SENTINELKEY9XQ2'}"
        )
        with mock.patch.dict(
            os.environ, {"OPENROUTER_API_KEY": "sk-or-SENTINELKEY9XQ2"}
        ):
            buf = io.StringIO()
            with redirect_stderr(buf):
                rc = run_xss_llm_research(
                    args,
                    store=self.store,
                    research_dir=self.xss_dir,
                    llm=RaisingLLM(failure),
                )
        err = buf.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("ERROR:", err)
        self.assertIn("OpenRouterProviderError", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("user_SENTINEL9XQ2", err)
        self.assertNotIn("user_id", err)
        self.assertNotIn("sk-or-SENTINELKEY9XQ2", err)
        self.assertNotIn("OPENROUTER_API_KEY", err)
        self.assertNotIn("WATCH_MONGO_URI", err)
        self.assertFalse(
            (self.xss_dir / "llm" / f"{XSS_CANDIDATE_ID}.json").exists()
        )

    def test_evidence_inference_unknown_separation(self):
        body = _valid_llm_body(self.candidate)
        # UNKNOWN carries knowledge_ids → rejected (inference laundering).
        body["evidence"][1]["knowledge_ids"] = [KB_ID]
        assistant, _ = self._assistant(json.dumps(body))
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(self.candidate, self.store)

    def test_evidence_must_carry_supplied_knowledge_id(self):
        body = _valid_llm_body(self.candidate)
        body["evidence"][0]["knowledge_ids"] = ["kb-deadbeefdeadbeef"]
        assistant, _ = self._assistant(json.dumps(body))
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(self.candidate, self.store)

    def test_no_arbitrary_urls_accepted(self):
        body = _valid_llm_body(self.candidate)
        body["explanation"] = "See https://evil.example/steal for the PoC"
        assistant, _ = self._assistant(json.dumps(body))
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(self.candidate, self.store)

    def test_references_must_be_supplied(self):
        body = _valid_llm_body(self.candidate)
        body["references_used"] = ["kb-deadbeefdeadbeef"]
        assistant, _ = self._assistant(json.dumps(body))
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(self.candidate, self.store)

    def test_bounded_prompt(self):
        assistant, stub = self._assistant(json.dumps(_valid_llm_body(self.candidate)))
        assistant.research(self.candidate, self.store)
        self.assertLessEqual(len(stub.last_prompt), 21000)
        # input minimization: no secrets, no absolute paths beyond artifact refs
        for banned in ("OPENROUTER_API_KEY", "sk-or-", "WATCH_MONGO_URI", "API_KEY"):
            self.assertNotIn(banned, stub.last_prompt)

    def test_malformed_json_rejected(self):
        assistant, stub = self._assistant("this is not json")
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(self.candidate, self.store)
        self.assertEqual(stub.call_count, 1)

    def test_provider_failure_no_partial_output(self):
        assistant = XSSLLMResearchAssistant(
            RaisingLLM(TimeoutError("provider timeout"))
        )
        with self.assertRaises(TimeoutError):
            assistant.research(self.candidate, self.store)

    def test_generate_only_provider_swap_works(self):
        """Stage R10: the provider boundary is genuinely swappable.

        A provider implementing ONLY the abstract ``generate``
        interface (no ``complete``, no OpenRouter) works end-to-end
        through the research assistant via the base-class
        ``complete`` default. No provider metadata is invented."""

        provider = GenerateOnlyLLM(
            json.dumps(_valid_llm_body(self.candidate))
        )
        assistant = XSSLLMResearchAssistant(provider)

        result = assistant.research(self.candidate, self.store)

        self.assertEqual(provider.calls, 1)
        self.assertEqual(
            result.candidate_id, self.candidate["candidate_id"]
        )
        # Minimal interface yields no provider metadata: stays None,
        # never fabricated.
        self.assertIsNone(result.model)
        self.assertIsNone(result.raw_response_id)

    def test_missing_candidate_fails_closed(self):
        """CLI path: unknown candidate id → clear error, no LLM call."""
        import argparse

        from ai.research_cli import run_xss_llm_research

        stub = StubLLM(json.dumps(_valid_llm_body(self.candidate)))
        args = argparse.Namespace(
            candidate_id="xss-0000000000000000",
            output=None,
        )
        rc = run_xss_llm_research(
            args,
            store=self.store,
            research_dir=self.xss_dir,
            llm=stub,
        )
        self.assertEqual(rc, 1)
        self.assertEqual(stub.call_count, 0)

    def test_missing_kb_evidence_fails_closed_no_llm_call(self):
        candidate = dict(self.candidate)
        candidate["references"] = []
        assistant, stub = self._assistant(json.dumps(_valid_llm_body(self.candidate)))
        with self.assertRaises(XSSLLMResearchError):
            assistant.research(candidate, self.store)
        self.assertEqual(stub.call_count, 0)

    def test_persistence_idempotent_and_candidate_unchanged(self):
        llm_dir = self.xss_dir / "llm"
        assistant, _ = self._assistant(json.dumps(_valid_llm_body(self.candidate)))
        result1 = assistant.research(self.candidate, self.store)
        path1 = persist_research(result1, research_dir=llm_dir)
        digest1 = hashlib.sha256(path1.read_bytes()).hexdigest()
        self.assertEqual(path1.name, f"{XSS_CANDIDATE_ID}.json")

        result2 = assistant.research(self.candidate, self.store)
        path2 = persist_research(result2, research_dir=llm_dir)
        self.assertEqual(hashlib.sha256(path2.read_bytes()).hexdigest(), digest1)
        # exactly one record
        self.assertEqual(len(list(llm_dir.glob("*.json"))), 1)

        persisted = json.loads(path1.read_text(encoding="utf-8"))
        self.assertEqual(persisted["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(persisted["confidence"], 0.35)
        self.assertEqual(persisted["content_hash"], self.candidate["content_hash"])

        # deterministic candidate JSON was never rewritten by the LLM layer
        # (persistence lives only under <research_dir>/llm/<candidate_id>.json);
        # the candidate file created in setUpClass is byte-identical.
        self.assertEqual(
            hashlib.sha256(self.candidate_path.read_bytes()).hexdigest(),
            self.candidate_digest,
        )

    def test_result_schema_round_trip(self):
        """Persisted schema still requires content_hash; the verifier stamps it.

        A raw model body (without content_hash) is NOT a complete result:
        validation fails until the verifier binding is attached.
        """
        from pydantic import ValidationError

        raw_model_body = _valid_llm_body(self.candidate)
        self.assertNotIn("content_hash", raw_model_body)
        with self.assertRaises(ValidationError):
            XSSLLMResearchAssistantResult.model_validate(raw_model_body)

        stamped = dict(raw_model_body)
        stamped["content_hash"] = self.candidate["content_hash"]
        result = XSSLLMResearchAssistantResult.model_validate(stamped)
        data = result.model_dump(mode="json")
        self.assertEqual(data["content_hash"], self.candidate["content_hash"])
        self.assertEqual(data["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(data["evidence"][1]["kind"], "UNKNOWN")

    def test_secret_redaction_in_prompt(self):
        assistant, stub = self._assistant(json.dumps(_valid_llm_body(self.candidate)))
        assistant.research(self.candidate, self.store)
        prompt = stub.last_prompt
        for banned in (
            "OPENROUTER_API_KEY",
            "sk-or-",
            "WATCH_MONGO_URI",
            "api_key=",
            "api-key",
        ):
            self.assertNotIn(banned, prompt)

    def test_authoritative_candidate_unchanged_after_llm_research(self):
        before = json.dumps(self.candidate, sort_keys=True)
        assistant, _ = self._assistant(json.dumps(_valid_llm_body(self.candidate)))
        assistant.research(self.candidate, self.store)
        after = json.dumps(self.candidate, sort_keys=True)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()