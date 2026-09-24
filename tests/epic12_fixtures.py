"""EPIC12 — shared offline fixtures.

Everything here is offline and deterministic: no network, no Mongo, no model.
The row builders mirror the REAL persisted evidence shape (the same shape
``tests/finding_fixtures.py`` uses for the EPIC11 suites) so the chain engine is
exercised against production-shaped input.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.finding.integrity import contracts as ct  # noqa: E402
from backend.research_agents.verification import store as vs  # noqa: E402

SCOPE = "watch:scope:dell/www.dell.com"
FIXTURE_SCOPE = "fixture:epic12/target.test"
TARGET = "https://www.dell.com/support"
CANDIDATE_ID = "cand-7c229c48c455"          # the mandatory regression fixture
SOURCE_JOB = "job-xss-49b9d40fd5"           # its REAL source job id
VERIFY_JOB = "job-xss-ffe3afca68"           # the REAL verification job id
AUTH_ID = "auth-epic12-1"


def authorization(scope: str = SCOPE) -> ct.AuthorizationContext:
    return ct.AuthorizationContext(
        scope_ref=scope, authorization_ref=scope,
        authorization_ids=(AUTH_ID,), execution_mode="production")


def row(signal: str, *, ref: str, job: str = SOURCE_JOB,
        category: str = "XSS", **extra: Any) -> dict[str, Any]:
    """One persisted evidence row (production shape)."""
    payload = {"id": f"ev-{signal}-{ref}", "job_id": job, "type": "observation",
               "signal": signal, "category": category, "confidence": "high",
               "observation_ref": ref, "detail": f"{signal} {ref}"}
    payload.update(extra)
    return payload


def negative_row(signal: str, *, ref: str, job: str = VERIFY_JOB,
                 category: str = "XSS") -> dict[str, Any]:
    """A negative observation row (``type=negative``)."""
    return {"id": f"ev-neg-{signal}-{ref}", "job_id": job, "type": "negative",
            "signal": signal, "category": category, "confidence": "high",
            "observation_ref": ref, "detail": f"{signal} {ref}",
            "not_observed": f"{signal} was not observed"}


def not_tested_row(signal: str, *, ref: str, job: str = VERIFY_JOB,
                   category: str = "XSS") -> dict[str, Any]:
    return {"id": f"ev-nt-{signal}-{ref}", "job_id": job, "type": "observation",
            "signal": signal, "category": category, "confidence": "unknown",
            "observation_ref": ref, "detail": f"{signal} {ref}",
            "not_observed": f"{signal} was never attempted"}


def inventory_rows(count: int = 20, **kw: Any) -> list[dict[str, Any]]:
    """The real cand-7c229c48c455 evidence: parameter inventory only."""
    return [row("xss_parameter_inventory", ref=f"inv-{i}",
                parameter=f"p{i}", **kw) for i in range(count)]


def stage_rows() -> list[dict[str, Any]]:
    """controlled input + reflection + context (stage 2/3 evidence)."""
    return [
        row("controlled_input_sent", ref="ctl-1", job=VERIFY_JOB),
        row("reflection_observed", ref="ref-1", job=VERIFY_JOB),
        row("output_context_identified", ref="ctx-1", job=VERIFY_JOB),
    ]


def confirmation_rows() -> list[dict[str, Any]]:
    """Stage-4 confirmation evidence (execution + exploitability + authz)."""
    return [
        row("payload_execution", ref="exec-1", job=VERIFY_JOB),
        row("exploitability_established", ref="expl-1", job=VERIFY_JOB),
        row("authorization_confirmed", ref="authz-1", job=VERIFY_JOB),
    ]


def full_chain_rows() -> list[dict[str, Any]]:
    return inventory_rows(3) + stage_rows() + confirmation_rows()


def marker_body(marker: str, *, context: str = "javascript") -> str:
    """A recorded response body with the marker in a chosen context."""
    if context == "javascript":
        return f'<html><body><script>var x = "{marker}";</script></body></html>'
    if context == "html_text":
        return f"<html><body><p>{marker}</p></body></html>"
    if context == "html_attribute":
        return f'<html><body><div title="{marker}">t</div></body></html>'
    if context == "url":
        return f'<html><body><a href="/x?q={marker}">l</a></body></html>'
    return f"<html><body>{marker}</body></html>"


def dom_document(*, source: bool = True, sink: bool = True) -> str:
    parts = ["<html><body><div id='out'></div><script>"]
    if source:
        parts.append("var v = location.hash;")
    else:
        parts.append("var v = 'constant';")
    if sink:
        parts.append("document.getElementById('out').innerHTML = v;")
    parts.append("</script></body></html>")
    return "".join(parts)


def make_verification_store() -> vs.VerificationActionStore:
    return vs.VerificationActionStore(tempfile.mkdtemp(prefix="epic12-store-"))


def fake_llm(payload: Any) -> Any:
    """A stub provider call returning a fixed payload."""
    return payload


def advisor_returning(payload: Any):
    def _call(_request: dict) -> Any:
        return payload
    return _call


def advisor_raising(exc: Exception):
    def _call(_request: dict) -> Any:
        raise exc
    return _call
