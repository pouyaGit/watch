"""backend/research_agents/runtime.py — Agent Runtime v1 worker.

Phases 3/5/6/7/8/11 of the AI Agent Runtime v1 epic:

* claim → lease → execute → complete, with heartbeat, sweep/recovery,
  retry policy, cancellation and timeout (real runtime state only);
* authorization verified before any observation (fail-closed);
* observations requested ONLY through an injected
  :class:`ObservationProvider` — this module never opens a socket, never
  imports an HTTP client and never shells out; the production provider
  reads Watch's own Mongo stores read-only (the observation boundary);
* analysis through deterministic rules over authorized observations,
  optionally corroborated by an LLM behind the existing fail-closed
  provider abstraction (:func:`ai.providers.provider_registry.select_provider`
  + :func:`ai.research_agent.llm_reliability.call_llm`).  An unavailable
  provider fails/retries the job — it never pretends analysis happened;
* knowledge loaded from the real knowledge base, with every actual read
  recorded (`knowledge_use`) — nothing counts as "read" otherwise;
* evidence recorded separately from observations; a case is created only
  when the capability's evidence rules pass (Phase 8 gates);
* results, evidence, cases, activity and audit events persist in
  :mod:`backend.research_agents.runtime_store`.

Fixture vs production is explicit: ``execution_mode`` stamps every job,
result, evidence row and case, so a fixture run can never be presented as
production execution.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from backend.research_agents.capabilities import (
    CAPABILITIES,
    SpecialistCapability,
    capability_for,
)
from backend.research_agents.llm_guard import (
    FREE_MODEL,
    FreeOnlyViolation,
    resolve_free_config,
)
from backend.research_agents.models import (
    JobStatus,
    ResearchJob,
    ResearchResult,
)
from backend.research_agents.runtime_store import (
    RuntimeStore,
    TransitionError,
    default_store,
    utcnow,
)

RUNTIME_RULE_VERSION = "agent-runtime-v1-worker"
SCHEMA_NAME = "structured-analysis-v1"


def prompt_version_for(capability: SpecialistCapability) -> str:
    """Versioned prompt identifier persisted with every LLM analysis."""

    return f"{capability.agent_name}-analysis-v1.2"

MODE_PRODUCTION = "production"
MODE_FIXTURE = "fixture"


# ---------------------------------------------------------------- errors
class AuthorizationDenied(Exception):
    """Job rejected before any observation (fail-closed)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ObservationUnavailable(Exception):
    """The observation provider could not return authorized data."""


class AnalysisUnavailable(Exception):
    """LLM-backed analysis failed; the job must fail/retry, never pretend."""


class JobDeadlineExceeded(Exception):
    """Job wall-clock timeout (maps to the TIMEOUT lifecycle state)."""


class NoCapability(Exception):
    """Job category has no capability definition — refuse to execute."""


# ------------------------------------------------------------ config
@dataclass(frozen=True)
class RuntimeConfig:
    lease_seconds: int = 30
    job_timeout: int = 120
    max_jobs_per_run: int = 5
    worker_ttl: int = 120
    observation_limit: int = 50
    knowledge_limit: int = 5
    worker_id: str = ""
    execution_mode: str = MODE_PRODUCTION
    # LLM (Phase 6): empty kind == not configured -> deterministic only
    llm_provider_kind: str = ""
    llm_model: str = ""
    llm_timeout: int = 30
    # Phase 4: outbound-context budget (the provider allowlist also caps
    # at 4000 chars before any prompt is built).
    context_max_chars: int = 4000

    def resolved_worker_id(self) -> str:
        return self.worker_id or f"agent-worker-{os.getpid()}"


# ------------------------------------------------- observation boundary
class ObservationProvider(Protocol):
    """Authorized observation source. Implementations never contact targets."""

    def observe(self, job: ResearchJob) -> list[dict[str, Any]]:
        ...


def _bounded_text(value: object, limit: int = 200) -> str:
    text = str(value if value is not None else "")
    text = " ".join(text.split())
    return text[:limit]


# sensitive header lines never leave the store, and never reach an LLM
_SENSITIVE_HEADER_MARKERS = ("cookie", "set-cookie", "authorization",
                             "x-api-key", "api-key", "token")


def _clean_row(row: dict[str, Any]) -> dict[str, Any]:
    """Project one observation row to the shared bounded schema."""

    out: dict[str, Any] = {}
    for key in ("source", "ref", "url", "method", "status", "title"):
        if key in row and row[key] not in (None, ""):
            out[key] = (_bounded_text(row[key], 300) if key != "status"
                        else int(row[key]) if str(row[key]).isdigit()
                        else row[key])
    params = row.get("params")
    if isinstance(params, (list, tuple)):
        out["params"] = [_bounded_text(p, 80) for p in params][:40]
    snippet = _bounded_text(row.get("headers_snippet", ""), 400).lower()
    if snippet and not any(m in snippet for m in _SENSITIVE_HEADER_MARKERS):
        out["headers_snippet"] = _bounded_text(row.get("headers_snippet"), 400)
    elif row.get("jwt_shaped"):
        out["jwt_shaped"] = True
    for key in ("db_error_style", "tech"):
        if row.get(key):
            out[key] = _bounded_text(row[key], 120)
    return out


class FixtureObservations:
    """Deterministic fixture rows for tests (execution_mode=fixture jobs).

    Rows are keyed by job id; missing key yields an empty observation set
    (which honestly produces an insufficient-evidence result).
    """

    def __init__(self, rows_by_job: dict[str, list[dict[str, Any]]]):
        self.rows_by_job = dict(rows_by_job)

    def observe(self, job: ResearchJob) -> list[dict[str, Any]]:
        rows = self.rows_by_job.get(job.id, [])
        return [_clean_row(dict(r)) for r in rows]


class ReadStoreObservations:
    """Production provider: read Watch's own stores, bounded, read-only.

    This is the entire observation boundary: no target contact, no
    outbound requests — only Mongo reads through the existing models.
    """

    def __init__(self, limit: int = 50):
        self.limit = int(limit)

    def observe(self, job: ResearchJob) -> list[dict[str, Any]]:
        """Read the models that actually hold each row shape.

        Field mapping follows the deployed schema: ``Http`` carries
        ``status_code``/``title``/``tech``/``headers`` (no params field);
        parameter rows come from ``Urls.params`` and ``Endpoints.params``
        (the capability's declared ``parameter-rows`` observation type).
        No method column exists in any of these models, so no method is
        claimed for a row.
        """
        try:
            from database import db
        except Exception as exc:  # pragma: no cover - env dependent
            raise ObservationUnavailable(
                f"observation store unavailable: {exc.__class__.__name__}"
            ) from exc
        scope = (job.subdomain or "").strip()
        if not scope:
            raise ObservationUnavailable("no subdomain scope on job")
        rows: list[dict[str, Any]] = []
        try:
            for doc in db.Urls.objects(subdomain=scope)[: self.limit]:
                rows.append(_clean_row({
                    "source": "urls",
                    "ref": str(doc.id),
                    "url": getattr(doc, "url", ""),
                    "path": getattr(doc, "path", ""),
                    "status": getattr(doc, "status_code", 0) or 0,
                    "params": list(getattr(doc, "params", None) or [])[:40],
                }))
            for doc in db.Endpoints.objects(subdomain=scope)[
                    : max(0, self.limit - len(rows))]:
                rows.append(_clean_row({
                    "source": "endpoints",
                    "ref": str(doc.id),
                    "url": (getattr(doc, "example_url", "")
                            or getattr(doc, "path", "")),
                    "path": getattr(doc, "path", ""),
                    "params": list(getattr(doc, "params", None) or [])[:40],
                }))
            for doc in db.Http.objects(subdomain=scope)[
                    : max(0, self.limit - len(rows))]:
                headers = getattr(doc, "headers", None)
                snippet = ""
                if isinstance(headers, dict) and headers:
                    snippet = " | ".join(
                        f"{k}: {v}" for k, v in list(headers.items())[:12])
                rows.append(_clean_row({
                    "source": "http",
                    "ref": str(doc.id),
                    "url": getattr(doc, "url", ""),
                    "status": getattr(doc, "status_code", 0) or 0,
                    "title": getattr(doc, "title", ""),
                    "tech": getattr(doc, "tech", ""),
                    "headers_snippet": snippet,
                }))
        except Exception as exc:
            raise ObservationUnavailable(
                f"observation read failed: {exc.__class__.__name__}"
            ) from exc
        return rows


# ------------------------------------------------------- authorization
class AuthorizationChecker:
    """Fail-closed scope check executed before every observation request."""

    def verify(self, job: ResearchJob) -> str:
        ref = (job.authorization_ref or "").strip()
        if not ref:
            raise AuthorizationDenied("missing_authorization_ref")
        mode = job.execution_mode
        if mode == MODE_FIXTURE:
            if not ref.startswith("fixture:"):
                raise AuthorizationDenied("fixture_job_without_fixture_scope")
            return ref
        if not ref.startswith("watch:scope:"):
            raise AuthorizationDenied("authorization_ref_not_watch_scope")
        scope = ref[len("watch:scope:"):]
        if not (job.program or job.subdomain):
            raise AuthorizationDenied("missing_scope")
        # target must sit inside the recorded scope
        target = (job.url or "").lower()
        sub = (job.subdomain or "").lower()
        if target and sub and sub not in target:
            raise AuthorizationDenied("target_out_of_scope")
        if job.subdomain and job.program:
            if job.program not in scope and job.subdomain not in scope:
                raise AuthorizationDenied("scope_mismatch")
        return ref


# ---------------------------------------------------------- knowledge
class KnowledgeLoader:
    """Loads relevant knowledge and records every real read (Phase 7)."""

    def __init__(self, limit: int = 5):
        self.limit = int(limit)

    def load(self, store: RuntimeStore, job: ResearchJob,
             capability: SpecialistCapability) -> list[dict[str, Any]]:
        try:
            from backend import research_data as rd
        except Exception:
            return []
        docs: list[dict[str, Any]] = []
        seen: set[str] = set()
        for topic in capability.knowledge_requirements[:3]:
            if len(docs) >= self.limit:
                break
            try:
                payload = rd.list_kb(q=topic, limit=self.limit)
            except Exception:
                continue
            for item in (payload or {}).get("items", []) or []:
                if len(docs) >= self.limit:
                    break
                doc_id = _bounded_text(item.get("knowledge_id")
                                       or item.get("id") or item.get("title"), 80)
                if not doc_id or doc_id in seen:
                    continue
                seen.add(doc_id)
                title = _bounded_text(item.get("title"), 160)
                docs.append({"id": doc_id, "title": title,
                             "topic": topic,
                             "summary": _bounded_text(item.get("summary"),
                                                        400)})
                # a source counts as read only when the runtime records it
                store.record_knowledge_use({
                    "job_id": job.id,
                    "agent": job.assigned_agent,
                    "category": job.agent_category,
                    "document_id": doc_id,
                    "title": title,
                    "topic": topic,
                    "mode": job.execution_mode,
                })
        return docs


# ---------------------------------------------------------- analysis
_DB_ERROR_MARKERS = ("sql", "syntax", "mysql", "postgres", "sqlite", "ora-",
                     "pg_", "pdo", "jdbc")
_URL_PARAM_NAMES = ("url", "uri", "target", "dest", "endpoint", "host",
                    "callback", "next", "redirect", "path")
_ID_PATTERNS = ("/id/", "?id=", "/uid/", "user_id", "/order/", "/item/",
                "/profile/", "account_id")


def deterministic_analysis(capability: SpecialistCapability,
                           job: ResearchJob,
                           observations: list[dict[str, Any]],
                           knowledge: list[dict[str, Any]]) -> dict[str, Any]:
    """Structural analysis over authorized observations — no conjecture.

    Returns the capability's output schema exactly.  ``confidence`` only
    rises to ``high`` when two or more independent observation rows carry
    the category's structural signal.
    """

    signals: list[str] = []
    hypotheses: list[dict[str, str]] = []
    evidence: list[dict[str, Any]] = []
    cat = capability.category

    def add_signal(name: str, row: dict[str, Any], detail: str) -> None:
        signals.append(name)
        evidence.append({
            "type": "observation",
            "observation_ref": f"{row.get('source', '?')}:{row.get('ref', '?')}",
            "signal": name,
            "detail": _bounded_text(detail, 200),
        })

    if not observations:
        return {
            "summary": "no authorized observations available for this scope",
            "signals": [],
            "hypotheses": [],
            "confidence": "insufficient",
            "insufficient_evidence": True,
            "blockers": ["no_authorized_observations"],
            "evidence_candidates": [],
            "knowledge_used": [d["id"] for d in knowledge],
        }

    for row in observations:
        params = [str(p).lower() for p in (row.get("params") or [])]
        url = str(row.get("url", "")).lower()
        title = str(row.get("title", "")).lower()
        snippet = str(row.get("headers_snippet", "")).lower()
        status = row.get("status")

        if cat == "XSS" and params:
            marker = "reflection-capable parameter inventory"
            if url:
                marker = f"{url} carries {len(params)} parameter(s)"
            add_signal("xss_parameter_inventory", row, marker)
            hypotheses.append({
                "endpoint": str(row.get("url", "")),
                "hypothesis": "stored inputs present; payload testing is "
                              "out of scope for this runtime",
            })
        elif cat == "SSRF":
            hits = [p for p in params if any(n in p for n in _URL_PARAM_NAMES)]
            if hits:
                add_signal("ssrf_url_parameter", row,
                           f"url-accepting parameter(s): {', '.join(hits[:5])}")
                hypotheses.append({
                    "endpoint": str(row.get("url", "")),
                    "hypothesis": f"parameter(s) {', '.join(hits[:3])} accept "
                                  "URL-like input",
                })
        elif cat == "SQLI":
            errorish = (row.get("db_error_style")
                        or any(m in title or m in snippet
                               for m in _DB_ERROR_MARKERS)
                        or (isinstance(status, int) and status >= 500))
            if errorish:
                add_signal("sqli_error_style_observation", row,
                           f"status={status} title/db marker present")
                hypotheses.append({
                    "endpoint": str(row.get("url", "")),
                    "hypothesis": "error-style response recorded in an "
                                  "authorized observation",
                })
        elif cat == "IDOR":
            if any(pat in url for pat in _ID_PATTERNS) or any(
                    p in _ID_PATTERNS for p in params):
                add_signal("idor_object_reference_pattern", row,
                           "id-like object reference in stored endpoint")
                hypotheses.append({
                    "endpoint": str(row.get("url", "")),
                    "hypothesis": "object reference pattern — no access "
                                  "attempt was made",
                })
        elif cat == "JWT":
            if row.get("jwt_shaped") or " eyj" in snippet or \
                    "eyJ" in str(row.get("headers_snippet", "")):
                add_signal("jwt_shaped_token_observed", row,
                           "JWT-shaped token recorded in stored observation")
                hypotheses.append({
                    "endpoint": str(row.get("url", "")),
                    "hypothesis": "token structure observed — no cracking or "
                                  "replay attempted",
                })
        elif cat == "OAUTH":
            if any(part in url for part in ("/oauth", "/authorize",
                                            "/token", "auth/callback")):
                add_signal("oauth_endpoint_observed", row,
                           "oauth-style endpoint in stored observation")
                hypotheses.append({
                    "endpoint": str(row.get("url", "")),
                    "hypothesis": "oauth endpoint present — flow not "
                                  "initiated",
                })
        elif cat == "RECON":
            add_signal("surface_row", row,
                       f"status={status} url={url[:80]}")
        elif cat == "CVE_RESEARCH":
            tech = str(row.get("tech", ""))
            if tech:
                add_signal("technology_signal", row, f"technology: {tech}")
                hypotheses.append({
                    "endpoint": str(row.get("url", "")),
                    "hypothesis": f"technology '{tech[:60]}' recorded — "
                                  "correlate with knowledge base",
                })

    kb_hits = [d for d in knowledge
               if any(t.lower() in d.get("title", "").lower()
                      for t in capability.knowledge_requirements)]
    for doc in kb_hits[:3]:
        evidence.append({
            "type": "knowledge",
            "observation_ref": doc["id"],
            "signal": "knowledge_reference",
            "detail": doc.get("title", "")[:160],
        })

    strong_sources = {e["observation_ref"] for e in evidence
                      if e["type"] == "observation"}
    if len(strong_sources) >= 2:
        confidence = "high"
    elif strong_sources:
        confidence = "medium"
    elif signals:
        confidence = "low"
    else:
        confidence = "insufficient"

    insufficient = confidence == "insufficient"
    blockers: list[str] = []
    if insufficient:
        blockers.append("no_category_signal_in_authorized_observations")
    if not knowledge:
        blockers.append("no_knowledge_documents_matched")

    return {
        "summary": (f"{capability.category}: {len(signals)} signal(s) across "
                    f"{len(observations)} authorized observation(s)"),
        "signals": signals[:20],
        "hypotheses": hypotheses[:10],
        "confidence": confidence,
        "insufficient_evidence": insufficient,
        "blockers": blockers,
        "evidence_candidates": evidence[:20],
        "knowledge_used": [d["id"] for d in knowledge],
    }


def _no_secret(value: object) -> str:
    """Bounded text with the OpenRouter key redacted if it ever appears."""

    text = _bounded_text(value, 200)
    key = str(os.environ.get("OPENROUTER_API_KEY", "") or "")
    if key and key in text:
        text = text.replace(key, "***")
    return text


def _advisory_request(capability: SpecialistCapability,
                      job: ResearchJob,
                      observations: list[dict[str, Any]],
                      knowledge: list[dict[str, Any]],
                      determin: dict[str, Any],
                      prompt_version: str) -> dict[str, Any]:
    """Allowlist-shaped advisory request (R51 contract), Phase 4/5/7.

    Carries ONLY the authorized bounded context: specialization, mission,
    relevant observations, knowledge excerpts already read, and the
    deterministic state.  Structural/secret validation is enforced by
    ``ai.providers.context_allowlist.sanitize_provider_context`` inside
    the provider — credentials can never ride along.
    """

    instruction = (
        f"{prompt_version}: {capability.agent_name} "
        f"({capability.category}). Mission: "
        f"{_bounded_text(job.mission, 24)}. "
        "Raw JSON, no markdown, exactly: "
        '{"summary":"<=150 chars",'
        '"insights":[{"insight_code":"UPPER_SNAKE_CASE","text":"<=200"}],'
        '"recommendations":[{"recommendation_code":"UPPER_SNAKE_CASE",'
        '"text":"<=200"}]}'
        " only these keys, max 6+6. Never confirm vulns; give the next "
        "authorized observation. No payloads or credentials."
    )[:400]

    signals: list[dict[str, Any]] = []
    for row in observations[:4]:
        # No URL may leave the boundary (R45 rule: never repeat URLs) —
        # carry only structural facts: internal ref, parameter names,
        # status code.
        params = ", ".join(_bounded_text(p, 40)
                           for p in (row.get("params") or [])[:6])
        subject = _bounded_text(
            f"ref={row.get('ref') or row.get('_id') or 'n/a'} "
            f"params=[{params}] status={row.get('status') or 'n/a'}", 200)
        signals.append({
            "signal_type": "AUTHORIZED_OBSERVATION",
            "subject": subject,
            "source_agent": capability.agent_name,
            "source_classification": capability.category,
            "confidence": "not_evaluated",
            "research_only": True,
        })
    for doc in knowledge[:3]:
        signals.append({
            "signal_type": "KNOWLEDGE_REFERENCE",
            "subject": _bounded_text(doc.get("title"), 200),
            "source_agent": capability.agent_name,
            "source_classification": "knowledge",
            "recommendation": _bounded_text(doc.get("summary"), 400),
            "confidence": "not_evaluated",
            "research_only": True,
        })

    sections: dict[str, Any] = {
        "research_context": {
            "research_question": _bounded_text(
                f"{capability.category} structural review of the "
                "authorized in-scope target", 240),
            "research_focus": _bounded_text(
                ", ".join(capability.output_schema[:3]) or capability.category,
                240),
            "context_fact_count": int(len(observations) + len(knowledge)),
            "source_layers": "MULTI",
            "research_only": True,
        },
        "learning_signals": signals[:8],
    }
    return {
        "advisory_id": "",
        "advisory_mode": "EXPLANATION",
        "provider_kind": "OPENROUTER",
        "source_layer": "MULTI",
        "instruction": instruction,
        "sections": sections,
        "research_only": True,
        "deterministic": True,
    }


def _classify_from_parts(*parts: Any) -> str:
    """Deterministic classification from plan/exception fields (Phase 8)."""

    blob = " ".join(str(p) for p in parts if p).upper()
    if "TIMEOUT" in blob or "TIMED_OUT" in blob:
        return "timeout"
    if "RATE" in blob or "429" in blob:
        return "rate_limit"
    if "AUTHENTICATION" in blob or "AUTHORIZATION" in blob \
            or "INVALID_CREDENTIAL" in blob or "AUTHZ" in blob \
            or "401" in blob or "403" in blob:
        return "auth"
    if "CONFIGURATION" in blob or "MISSING_CREDENTIAL" in blob \
            or "MISSING_MODEL" in blob or "UNSUPPORTED_KIND" in blob:
        return "configuration"
    if "EMPTY" in blob:
        return "empty_response"
    if "SAFETY" in blob or "UNSAFE" in blob or "CONTEXT_REJECTED" in blob:
        return "context_rejected"
    if "INVALID_RESPONSE" in blob or "INVALID_PROVIDER" in blob \
            or "MALFORMED" in blob:
        return "schema_failure"
    if "NETWORK" in blob or "CONNECTION" in blob or "TRANSIENT" in blob \
            or "502" in blob or "503" in blob:
        return "provider_unavailable"
    if "PROVIDER" in blob or "HTTP_ERROR" in blob or "REJECTED" in blob:
        return "provider_error"
    return "provider_error"


def _classify_provider_error(err: Any, exc: Any = None) -> str:
    """Map provider error plans/exceptions to auditable failure kinds."""

    if isinstance(err, dict):
        kind = _classify_from_parts(
            err.get("error_category"), err.get("error_code"),
            err.get("status_code"), json.dumps(err, default=str))
        if kind != "provider_error":
            return kind
    if exc is not None:
        kind = _classify_from_parts(
            getattr(exc, "error_category", ""),
            getattr(exc, "error_code", None)
            or getattr(exc, "code", None),
            getattr(exc, "status_code", None), type(exc).__name__)
        if kind != "provider_error":
            return kind
        blob = " ".join(str(v) for v in (
            getattr(exc, "error_category", ""),
            str(exc), type(exc).__name__)).lower()
        if "timeout" in blob:
            return "timeout"
        if "rate" in blob or "429" in blob:
            return "rate_limit"
        if "auth" in blob or "credential" in blob or "401" in blob:
            return "auth"
        if "empty" in blob:
            return "empty_response"
        if "invalid" in blob or "malformed" in blob or "missing" in blob:
            return "schema_failure"
        if "network" in blob or "connection" in blob or "unavailable" in blob:
            return "provider_unavailable"
        if "context" in blob or "safety" in blob or "rejected" in blob:
            return "context_rejected"
    if isinstance(err, dict):
        kind = _classify_from_parts(json.dumps(err, default=str))
        if kind != "provider_error":
            return kind
    return "provider_error"


def _err_text(err: Any, exc: Any = None) -> str:
    """Never-empty bounded reason text (Phase 8 auditability)."""

    text = ""
    if isinstance(err, dict):
        text = str(err.get("safe_message") or err.get("message")
                   or err.get("error") or err.get("error_code")
                   or err.get("code") or "")
        if not text:
            try:
                text = json.dumps(err, default=str)
            except (TypeError, ValueError):
                text = ""
    elif err is not None:
        text = str(err)
    if not text and exc is not None:
        text = str(getattr(exc, "safe_message", "") or "") or str(exc)
    if not text and exc is not None:
        text = type(exc).__name__
    if not text:
        text = "provider returned no usable response"
    return _no_secret(text)


def _map_advisory_response(response: Any,
                           capability: SpecialistCapability,
                           determin: dict[str, Any],
                           observations: list[dict[str, Any]],
                           prompt_version: str) -> dict[str, Any]:
    """Validate the provider's structured response (Phase 3).

    The R45/R51 response contract is the project's structured-output
    convention: ``{summary, insights[{insight_code,text}],
    recommendations[{recommendation_code,text}]}``, strictly validated.
    The mapping into the specialist analysis schema is deterministic; the
    LLM never supplies gate fields.
    """

    def _schema_fail(reason: str) -> AnalysisUnavailable:
        return AnalysisUnavailable(f"schema_failure: {reason}")

    if not isinstance(response, dict):
        raise _schema_fail("response is not an object")
    summary = response.get("summary")
    insights = response.get("insights")
    recommendations = response.get("recommendations")
    if not isinstance(summary, str) or not summary.strip():
        raise _schema_fail("summary missing")

    def _items(value: Any, code_key: str) -> list[dict[str, str]]:
        if not isinstance(value, list):
            raise _schema_fail(f"{code_key} items are not a list")
        out: list[dict[str, str]] = []
        for item in value[:8]:
            if not isinstance(item, dict) \
                    or set(item.keys()) != {code_key, "text"}:
                raise _schema_fail(f"{code_key} item shape invalid")
            text = item.get("text")
            if not isinstance(text, str) or not text.strip():
                raise _schema_fail(f"{code_key} item text missing")
            out.append({code_key: _bounded_text(item.get(code_key), 80),
                        "text": _bounded_text(text, 400)})
        return out

    llm_insights = _items(insights, "insight_code")
    llm_recs = _items(recommendations, "recommendation_code")

    evidence_refs = [
        _bounded_text(c.get("observation_ref"), 120)
        for c in (determin.get("evidence_candidates") or [])
    ]
    obs_refs = [
        (f"urls:{r.get('_id')}" if r.get("_id")
         else _bounded_text(r.get("url") or r.get("ref"), 120))
        for r in observations[:8]
    ]
    gate_conf = str(determin.get("confidence", "insufficient"))
    if gate_conf == "high" and len(evidence_refs) >= 2:
        verdict = "evidence_sufficient_for_review"
    elif obs_refs:
        verdict = "needs_more_observation"
    else:
        verdict = "insufficient_evidence"

    return {
        "schema": SCHEMA_NAME,
        "prompt_version": prompt_version,
        "hypothesis": (_bounded_text(llm_insights[0]["text"], 400)
                       if llm_insights else ""),
        "vulnerability_class": f"{capability.category}-class patterns",
        "observations_considered": obs_refs,
        "evidence_required":
            list(capability.evidence_requirements.required_types),
        "evidence_present": evidence_refs[:8],
        # deterministic gate value: the LLM cannot set confidence
        "confidence": gate_conf,
        "blockers": [_bounded_text(b, 120)
                     for b in (determin.get("blockers") or [])[:8]],
        "reasoning_summary": _bounded_text(summary, 400),
        "recommended_next_observation": (
            _bounded_text(llm_recs[0]["text"], 400) if llm_recs else ""),
        "verdict": verdict,
        "llm_insights": llm_insights,
        "llm_recommendations": llm_recs,
        "requested_model": FREE_MODEL,
    }


def llm_analysis(config: RuntimeConfig, capability: SpecialistCapability,
                 job: ResearchJob, observations: list[dict[str, Any]],
                 knowledge: list[dict[str, Any]],
                 determin: dict[str, Any] | None = None
                 ) -> tuple[dict[str, Any], dict[str, Any]]:
    """Free-only LLM analysis through the existing provider abstraction.

    Phase 1 cost guard: only ``OPENROUTER`` + ``openrouter/free`` is ever
    accepted; any other model/provider/key/mode configuration fails closed
    with :class:`AnalysisUnavailable` — there is no fallback branch, paid
    or otherwise.  Returns ``(merged_analysis, llm_meta)``.  The LLM output
    is INPUT: confidence, blockers and evidence candidates stay
    deterministic, so the case gate remains authoritative (Phase 12).
    """

    from ai.providers.provider_registry import select_provider

    try:
        guard = resolve_free_config(config.llm_provider_kind,
                                    config.llm_model,
                                    int(config.llm_timeout))
    except FreeOnlyViolation as exc:
        raise AnalysisUnavailable(f"free_only: {exc.reason}")

    if determin is None:
        determin = deterministic_analysis(capability, job,
                                          observations, knowledge)
    merged_base = dict(determin)
    prompt_version = prompt_version_for(capability)
    request = _advisory_request(capability, job, observations, knowledge,
                                determin, prompt_version)
    payload = json.dumps(request.get("sections", {}), sort_keys=True,
                          default=str)
    if len(payload) > int(config.context_max_chars):
        raise AnalysisUnavailable(
            f"context_too_large: outbound context exceeds "
            f"{int(config.context_max_chars)} chars")

    try:
        provider = select_provider(
            guard["provider_kind"],
            model=guard["requested_model"],
            timeout_seconds=guard["timeout_seconds"],
            max_retries=0,
            retry_backoff_seconds=0,
        )
    except Exception as exc:
        raise AnalysisUnavailable(f"provider_configuration: {_no_secret(exc)}")

    t0 = time.monotonic()
    try:
        # R51 contract: complete_with_status() returns the envelope
        # {response, error, telemetry, _exception}; complete() returns the
        # FLAT success projection and RAISES ProviderCallError on failure.
        status_call = getattr(provider, "complete_with_status", None)
        if callable(status_call):
            outcome = status_call(request)
        else:
            outcome = provider.complete(request)
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        kind = _classify_provider_error(None, exc)
        raise AnalysisUnavailable(
            f"llm_{kind}: {_err_text(None, exc)}") from None
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    if not isinstance(outcome, dict):
        raise AnalysisUnavailable(
            "llm_provider_error: unexpected outcome type "
            f"{type(outcome).__name__}")

    if ("summary" in outcome or "insights" in outcome) \
            and "response" not in outcome:
        # flat success projection from complete()
        response: Any = outcome
        err: Any = None
        telemetry: dict[str, Any] = {}
    else:
        err = outcome.get("error")
        response = outcome.get("response")
        telemetry = (outcome.get("telemetry")
                     if isinstance(outcome.get("telemetry"), dict) else {})
    if err is not None or response is None:
        exc = outcome.get("_exception")
        kind = _classify_provider_error(err, exc)
        raise AnalysisUnavailable(f"llm_{kind}: {_err_text(err, exc)}")
    structured = _map_advisory_response(response, capability, determin,
                                        observations, prompt_version)

    usage = telemetry.get("usage") if isinstance(
        telemetry.get("usage"), dict) else None
    resolved = _bounded_text(telemetry.get("model")
                             or (response.get("model")
                                 if isinstance(response, dict) else ""),
                             80) or "not_exposed_by_contract"
    meta: dict[str, Any] = {
        "provider": "OPENROUTER",
        "provider_label": guard["provider_label"],
        "requested_model": guard["requested_model"],
        "resolved_model": resolved,
        "prompt_version": prompt_version,
        "schema": SCHEMA_NAME,
        "analysis_ms": elapsed_ms,
        "usage": usage,
        "request_id": _bounded_text(telemetry.get("request_id"), 64) or None,
        "attempts": int(telemetry.get("attempts") or 1),
        "free_only_rule": guard["rule_version"],
    }
    structured["resolved_model"] = resolved
    structured["usage"] = usage
    structured["latency_ms"] = elapsed_ms

    # Merge: LLM supplies reasoning TEXT only.  Confidence, blockers and
    # evidence candidates remain deterministic (Phase 12 — an LLM
    # hypothesis is not a finding and cannot move the gate).
    merged = merged_base
    if structured.get("reasoning_summary"):
        merged["summary"] = _bounded_text(structured["reasoning_summary"], 400)
    hypothesis = structured.get("hypothesis") or ""
    if hypothesis:
        merged["hypotheses"] = [
            {"endpoint": capability.category,
             "hypothesis": _bounded_text(hypothesis, 300)}
        ] + list(determin.get("hypotheses") or [])
    merged["structured"] = structured
    merged["llm"] = meta
    merged["prompt_version"] = prompt_version
    merged["analysis_via"] = "llm"
    return merged, meta


# ------------------------------------------------- case creation gate
@dataclass(frozen=True)
class CaseDecision:
    create: bool
    reason: str
    case: dict[str, Any] | None = None


def evaluate_case_creation(capability: SpecialistCapability,
                           job: ResearchJob,
                           analysis: dict[str, Any],
                           evidence_rows: list[dict[str, Any]]) -> CaseDecision:
    """Phase 8: a research result is NOT automatically a finding."""

    req = capability.evidence_requirements
    if analysis.get("insufficient_evidence") or \
            analysis.get("confidence") == "insufficient":
        return CaseDecision(False, "insufficient_evidence")
    relevant = [e for e in evidence_rows
                if e.get("job_id") == job.id]
    if len(relevant) < int(req.min_evidence_refs):
        return CaseDecision(False, "evidence_threshold_not_met")
    if req.require_high_confidence and \
            analysis.get("confidence") != "high":
        return CaseDecision(False, "confidence_below_threshold")
    have_types = {e.get("type") for e in relevant}
    missing = [t for t in req.required_types if t not in have_types]
    if missing:
        return CaseDecision(False, f"missing_evidence_type:{missing[0]}")
    hypotheses = analysis.get("hypotheses") or []
    if not hypotheses:
        return CaseDecision(False, "no_hypothesis")
    case = {
        "job_id": job.id,
        "target": job.subdomain or job.program,
        "endpoint": job.url or "",
        "specialist": job.assigned_agent,
        "category": job.agent_category,
        "hypothesis": _bounded_text(hypotheses[0].get("hypothesis"), 400),
        "evidence_refs": [e["id"] for e in relevant
                          if e.get("type") in ("observation", "knowledge")][:10],
        "observation_refs": [e.get("observation_ref", "")
                            for e in relevant][:10],
        "analysis": _bounded_text(analysis.get("summary"), 500),
        "confidence": analysis.get("confidence", "low"),
        "authorization_context": job.authorization_ref,
        "execution_mode": job.execution_mode,
        "rule_version": RUNTIME_RULE_VERSION,
    }
    return CaseDecision(True, "evidence_rules_met", case)


# ------------------------------------------------------------- worker
class AgentWorker:
    """Bounded worker: claim → verify → observe → analyze → persist."""

    def __init__(self, config: RuntimeConfig | None = None,
                 store: RuntimeStore | None = None,
                 observations: ObservationProvider | None = None,
                 knowledge: KnowledgeLoader | None = None,
                 auth: AuthorizationChecker | None = None,
                 llm_enabled: bool | None = None):
        self.config = config or RuntimeConfig()
        self.store = store or default_store()
        self.observations = observations or ReadStoreObservations(
            limit=self.config.observation_limit)
        self.knowledge = knowledge or KnowledgeLoader(
            limit=self.config.knowledge_limit)
        self.auth = auth or AuthorizationChecker()
        self.worker_id = self.config.resolved_worker_id()
        self.categories = tuple(CAPABILITIES.keys())
        if llm_enabled is None:
            llm_enabled = bool(self.config.llm_provider_kind)
        self.llm_enabled = bool(llm_enabled)

    # -- one bounded unit of work -----------------------------------------

    def run_once(self) -> ResearchJob | None:
        self.store.sweep()
        self.store.heartbeat_worker(self.worker_id,
                                    mode=self.config.execution_mode,
                                    ttl_seconds=self.config.worker_ttl)
        job = self.store.claim_next(self.worker_id, self.categories,
                                    lease_seconds=self.config.lease_seconds)
        if job is None:
            return None
        self.execute(job)
        return job

    def run(self, max_jobs: int | None = None,
            stop: Callable[[], bool] | None = None) -> dict[str, int]:
        limit = int(max_jobs if max_jobs is not None
                    else self.config.max_jobs_per_run)
        stats = {"claimed": 0, "processed": 0}
        for _ in range(max(0, limit)):
            if stop is not None and stop():
                break
            job = self.run_once()
            if job is None:
                break
            stats["claimed"] += 1
            stats["processed"] += 1
        return stats

    # -- execution ---------------------------------------------------------

    def execute(self, job: ResearchJob) -> ResearchJob:
        cfg = self.config
        started = time.monotonic()
        self._transition(job.id, JobStatus.RUNNING.value,
                         event="job_started", reason=job.mission or "started",
                         started_at=utcnow())
        try:
            return self._run_phases(job, started)
        except AuthorizationDenied as exc:
            return self._terminal_failure(job, f"authorization_denied:{exc.reason}",
                                          event="job_rejected")
        except JobDeadlineExceeded:
            return self._timeout_failure(job)
        except NoCapability as exc:
            return self._terminal_failure(job, str(exc),
                                          event="job_rejected")
        except (ObservationUnavailable, AnalysisUnavailable) as exc:
            return self._retryable_failure(job, f"{exc.__class__.__name__}:"
                                           f"{exc}", started)
        except TransitionError:
            raise
        except Exception as exc:  # noqa: BLE001 - bounded, sanitized
            return self._retryable_failure(
                job, f"unexpected_{exc.__class__.__name__}", started)

    def _run_phases(self, job: ResearchJob, started: float) -> ResearchJob:
        cfg = self.config

        def check_deadline() -> None:
            if time.monotonic() - started > cfg.job_timeout:
                raise JobDeadlineExceeded()

        check_deadline()
        self.auth.verify(job)

        capability = capability_for(job.agent_category)
        if capability is None:
            raise NoCapability(f"no_capability:{job.agent_category}")

        knowledge = self.knowledge.load(self.store, job, capability)
        check_deadline()
        rows = self.observations.observe(job)
        self.store.record_activity({
            "job_id": job.id, "agent": job.assigned_agent,
            "category": job.agent_category, "action": "observations_loaded",
            "detail": f"{len(rows)} authorized observations",
            "mode": job.execution_mode})
        if not rows and job.execution_mode == MODE_PRODUCTION:
            # honest empty-input completion handled below via analysis
            pass
        self.store.heartbeat(job.id, self.worker_id,
                             lease_seconds=cfg.lease_seconds)
        check_deadline()

        analysis = deterministic_analysis(capability, job, rows, knowledge)
        provider_kind, model, prompt_version = "", "", ""
        analysis_ms = 0
        if self.llm_enabled:
            prompt_version = prompt_version_for(capability)
            self.store.record_activity({
                "job_id": job.id, "agent": job.assigned_agent,
                "category": job.agent_category,
                "action": "llm_analysis_started",
                "detail": f"OpenRouter {FREE_MODEL} {prompt_version}",
                "llm": FREE_MODEL, "mode": job.execution_mode})
            try:
                analysis, llm_meta = llm_analysis(
                    cfg, capability, job, rows, knowledge, analysis)
            except AnalysisUnavailable as exc:
                self.store.record_activity({
                    "job_id": job.id, "agent": job.assigned_agent,
                    "category": job.agent_category,
                    "action": "llm_analysis_failed",
                    "detail": _bounded_text(str(exc), 200),
                    "llm": FREE_MODEL, "mode": job.execution_mode})
                raise
            provider_kind = str(llm_meta.get("provider") or "")
            model = str(llm_meta.get("requested_model") or "")
            prompt_version = str(llm_meta.get("prompt_version") or "")
            analysis_ms = int(llm_meta.get("analysis_ms") or 0)
            self.store.record_activity({
                "job_id": job.id, "agent": job.assigned_agent,
                "category": job.agent_category,
                "action": "llm_analysis_completed",
                "detail": (f"resolved={llm_meta.get('resolved_model', '')} "
                           f"latency_ms={analysis_ms} "
                           f"usage={'yes' if llm_meta.get('usage') else 'n/a'} "
                           f"prompt={prompt_version}"),
                "llm": model, "mode": job.execution_mode})
            check_deadline()

        # evidence (Phase 8): candidates become recorded evidence rows
        evidence_rows: list[dict[str, Any]] = []
        for cand in (analysis.get("evidence_candidates") or [])[:20]:
            ev_id = self.store.record_evidence({
                "job_id": job.id,
                "agent": job.assigned_agent,
                "category": job.agent_category,
                "type": cand.get("type", "observation"),
                "observation_ref": cand.get("observation_ref", ""),
                "signal": cand.get("signal", ""),
                "detail": _bounded_text(cand.get("detail"), 200),
                "confidence": analysis.get("confidence", "low"),
                "execution_mode": job.execution_mode,
            })
            evidence_rows.append({"id": ev_id, "type": cand.get("type"),
                                  "observation_ref":
                                      cand.get("observation_ref", ""),
                                  "job_id": job.id})
        # refresh job (evidence_refs updated by store)
        job = self.store.get(job.id) or job

        decision = evaluate_case_creation(capability, job, analysis,
                                          evidence_rows)
        self.store.record_activity({
            "job_id": job.id, "agent": job.assigned_agent,
            "category": job.agent_category,
            "action": "evidence_gate_evaluated",
            "detail": (f"decision={'case' if decision.create else 'no_case'} "
                       f"reason={decision.reason} "
                       f"gate_confidence={analysis.get('confidence')}"),
            "case_reason": decision.reason,
            "llm": provider_kind or "not_configured",
            "mode": job.execution_mode})
        case_id = ""
        if decision.create and decision.case:
            case_id = self.store.record_case(decision.case)

        findings = tuple(_bounded_text(h.get("hypothesis"), 200)
                         for h in (analysis.get("hypotheses") or [])[:10])
        blockers = tuple(_bounded_text(b, 120)
                         for b in (analysis.get("blockers") or [])[:10])
        signals = tuple(_bounded_text(s, 120)
                        for s in (analysis.get("signals") or [])[:20])
        result = ResearchResult(
            job_id=job.id,
            agent_name=job.assigned_agent,
            confidence=str(analysis.get("confidence", "insufficient")),
            findings=findings,
            evidence_required=capability.evidence_requirements.required_types,
            blockers=blockers,
            created_at=utcnow(),
            signals=signals,
            status=JobStatus.COMPLETED.value,
            provider=provider_kind,
            model=model,
            prompt_version=prompt_version,
            analysis_ms=analysis_ms,
            execution_mode=job.execution_mode,
            structured=analysis.get("structured") or {},
        )
        self.store.put_result(result)
        self.store.record_activity({
            "job_id": job.id, "agent": job.assigned_agent,
            "category": job.agent_category, "action": "analysis_completed",
            "detail": (f"{result.confidence} confidence, "
                       f"{len(evidence_rows)} evidence, "
                       f"case={'yes' if case_id else 'no'}"
                       f" ({decision.reason})"),
            "confidence": result.confidence,
            "evidence": len(evidence_rows),
            "case_id": case_id,
            "case_reason": decision.reason,
            "llm": provider_kind or "not_configured",
            "mode": job.execution_mode,
        })
        self._transition(job.id, JobStatus.COMPLETED.value,
                         event="job_completed",
                         reason=(analysis.get("summary") or "completed"),
                         completed_at=utcnow(), result_ref=job.id,
                         lease_owner="", lease_expires_at=None,
                         error="")
        return self.store.get(job.id) or job

    # -- failure policy ----------------------------------------------------

    def _transition(self, job_id: str, status: str, **kw: Any) -> None:
        self.store.transition(job_id, status, worker=self.worker_id, **kw)

    def _retryable_failure(self, job: ResearchJob, error: str,
                           started: float) -> ResearchJob:
        current = self.store.get(job.id) or job
        # job timeout discovered inside a phase -> TIMEOUT path
        if time.monotonic() - started > self.config.job_timeout:
            return self._timeout_failure(current)
        if current.status == JobStatus.COMPLETED.value:
            return current
        if current.status != JobStatus.FAILED.value:
            try:
                self._transition(current.id, JobStatus.FAILED.value,
                                 event="job_failed", reason=error,
                                 error=error[:300], lease_owner="",
                                 lease_expires_at=None)
            except TransitionError:
                pass
        outcome = self.store.retry_or_terminal(current.id, error=error[:300],
                                               worker=self.worker_id)
        self.store.record_activity({
            "job_id": current.id, "agent": current.assigned_agent,
            "category": current.agent_category, "action": "job_failed",
            "detail": f"{error[:160]} -> {outcome}",
            "mode": current.execution_mode,
        })
        return self.store.get(current.id) or current

    def _timeout_failure(self, job: ResearchJob) -> ResearchJob:
        current = self.store.get(job.id) or job
        if current.status == JobStatus.RUNNING.value:
            try:
                self._transition(current.id, JobStatus.TIMEOUT.value,
                                 event="job_timeout",
                                 reason=f"exceeded {self.config.job_timeout}s",
                                 error="timeout", lease_owner="",
                                 lease_expires_at=None)
            except TransitionError:
                pass
        return self._finish_timeout(current)

    def _finish_timeout(self, job: ResearchJob) -> ResearchJob:
        current = self.store.get(job.id) or job
        if current.status == JobStatus.COMPLETED.value:
            return current
        if int(current.attempt_count or 0) < int(current.max_attempts or 3):
            if current.status == JobStatus.TIMEOUT.value:
                self._transition(current.id, JobStatus.QUEUED.value,
                                 event="job_retry", reason="timeout retry",
                                 lease_owner="", lease_expires_at=None)
        elif current.status == JobStatus.TIMEOUT.value:
            self._transition(current.id, JobStatus.TERMINAL_FAILED.value,
                             event="job_terminal_failed",
                             reason="timeouts exhausted", error="timeout")
        return self.store.get(current.id) or current

    def _terminal_failure(self, job: ResearchJob, reason: str,
                          event: str = "job_rejected") -> ResearchJob:
        current = self.store.get(job.id) or job
        if current.status in (JobStatus.CLAIMED.value,
                              JobStatus.RUNNING.value):
            try:
                self._transition(current.id, JobStatus.FAILED.value,
                                 event=event, reason=reason,
                                 error=reason[:300], lease_owner="",
                                 lease_expires_at=None)
            except TransitionError:
                pass
        if self.store.get(current.id).status == JobStatus.FAILED.value:
            self._transition(current.id, JobStatus.TERMINAL_FAILED.value,
                             event=event, reason=reason,
                             error=reason[:300])
        self.store.record_activity({
            "job_id": current.id, "agent": current.assigned_agent,
            "category": current.agent_category, "action": "job_rejected",
            "detail": reason[:160], "mode": current.execution_mode,
        })
        return self.store.get(current.id) or current


# ------------------------------------------------- snapshots (Phase 11)
def runtime_snapshot(store: RuntimeStore | None = None,
                     now_ts: float | None = None) -> dict[str, Any]:
    """Runtime observability payload; honest absence when nothing exists."""

    try:
        st = store or default_store()
        if not st.state_path.exists() and not st.worker_path.exists():
            return {
                "rule_version": RUNTIME_RULE_VERSION,
                "deployed": False,
                "worker": {"alive": False,
                           "reason": "no runtime state exists yet"},
                "counts": {}, "queue": 0, "running": 0, "total": 0,
                "completed": 0, "failed": 0, "retries": 0, "leases": [],
                "last_success": "", "last_failure": "",
                "last_activity": "", "runtime_errors": [],
                "cases": 0, "evidence": 0,
            }
        snap = st.snapshot(now_ts)
        snap["rule_version"] = RUNTIME_RULE_VERSION
        snap["deployed"] = True
        return snap
    except Exception as exc:  # never hide failure behind a lie
        return {
            "rule_version": RUNTIME_RULE_VERSION,
            "deployed": False,
            "worker": {"alive": False,
                       "reason": f"runtime snapshot failed: "
                                 f"{exc.__class__.__name__}"},
            "counts": {}, "queue": 0, "running": 0, "total": 0,
            "completed": 0, "failed": 0, "retries": 0, "leases": [],
            "last_success": "", "last_failure": "", "last_activity": "",
            "runtime_errors": [f"snapshot:{exc.__class__.__name__}"],
            "cases": 0, "evidence": 0,
        }


def agent_runtime_states(store: RuntimeStore | None = None
                         ) -> dict[str, dict[str, Any]]:
    """Per-specialist runtime status (Phase 9 input) from real state.

    PLANNED  — no live worker (runtime cannot accept work)
    READY    — live worker, no jobs for this agent yet
    IDLE     — live worker, past jobs, none executing
    ACTIVE   — a job is CLAIMED/RUNNING/WAITING for this agent now
    FAILED   — live worker, no active job, last outcome terminal failure
    """

    st = store or default_store()
    snap = runtime_snapshot(st)
    worker_alive = bool(snap.get("worker", {}).get("alive"))
    jobs = st.list_jobs(limit=1000)
    activity = st.list_activity(limit=200)
    out: dict[str, dict[str, Any]] = {}
    for cat in CAPABILITIES:
        mine = [j for j in jobs if j.agent_category.upper() == cat]
        queue = sum(1 for j in mine if j.status == JobStatus.QUEUED.value)
        active = [j for j in mine
                  if j.status in (JobStatus.CLAIMED.value,
                                  JobStatus.RUNNING.value,
                                  JobStatus.WAITING_EVIDENCE.value)]
        recent_terminal_failed = any(
            j.status == JobStatus.TERMINAL_FAILED.value for j in mine
        ) and not active
        if not worker_alive:
            status = "PLANNED"
        elif active:
            status = "ACTIVE"
        elif not mine:
            status = "READY"
        elif recent_terminal_failed:
            status = "FAILED"
        else:
            status = "IDLE"
        last_job = max(mine, key=lambda j: j.updated_at) if mine else None
        cat_activity = [a for a in activity
                        if str(a.get("category", "")).upper() == cat]
        out[cat.lower()] = {
            "status": status,
            "worker_alive": worker_alive,
            "queue": queue,
            "active_jobs": len(active),
            "job_count": len(mine),
            "available": worker_alive,
            "last_job": ({"id": last_job.id, "status": last_job.status,
                          "at": last_job.updated_at,
                          "mode": last_job.execution_mode}
                         if last_job else None),
            "last_activity": (cat_activity[-1]["at"] if cat_activity else ""),
            "completed": sum(1 for j in mine
                             if j.status == JobStatus.COMPLETED.value),
            "failed": sum(1 for j in mine
                          if j.status in (JobStatus.FAILED.value,
                                          JobStatus.TERMINAL_FAILED.value,
                                          JobStatus.TIMEOUT.value)),
        }
    return out


def runtime_activity(limit: int = 30) -> list[dict[str, Any]]:
    """Newest-first runtime activity for the SOC Activity page."""

    try:
        st = default_store()
        if not st.state_path.exists():
            return []
        rows = st.list_activity(limit=limit)
        return list(reversed(rows))
    except Exception:
        return []


__all__ = [
    "AgentWorker",
    "AnalysisUnavailable",
    "AuthorizationChecker",
    "AuthorizationDenied",
    "CaseDecision",
    "FixtureObservations",
    "JobDeadlineExceeded",
    "KnowledgeLoader",
    "MODE_FIXTURE",
    "MODE_PRODUCTION",
    "NoCapability",
    "ObservationProvider",
    "ObservationUnavailable",
    "PROMPT_VERSION",
    "ReadStoreObservations",
    "RUNTIME_RULE_VERSION",
    "RuntimeConfig",
    "agent_runtime_states",
    "deterministic_analysis",
    "evaluate_case_creation",
    "llm_analysis",
    "runtime_activity",
    "runtime_snapshot",
]
