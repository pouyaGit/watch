"""EPIC15 fixtures: served documents, harnesses and the attack surface.

Two things stay strictly apart:

* ``REAL_*`` — documents and offline-harness outcomes that represent
  genuine observations the runtime could make;
* ``FAKE_*`` — the things that must never become execution or sink
  evidence: HTML script text, a screenshot, a reflected marker, an LLM
  claim, a forged evidence row.
"""
from __future__ import annotations

from typing import Any

SCOPE_REF = "watch:scope:dell/www.dell.com"
TARGET = "https://www.dell.com/support/search?q=test"
PARAMETER = "q"
MARKER = "HERMES_REFLECT_epic15"
AUTH_ID = "authz-epic15-1"
CANDIDATE_ID = "cand-7c229c48c455"
OBJECTIVE_ID = "vo-epic15-1"


def authorization(expired: bool = False) -> dict[str, Any]:
    return {"authorization_ids": [AUTH_ID], "authorization_id": AUTH_ID,
            "scope_ref": SCOPE_REF, "expired": expired}


def authorized_hosts() -> tuple[str, ...]:
    return ("www.dell.com",)


# ---------------------------------------------------------------- documents

def document_lineage(parameter: str = PARAMETER) -> str:
    """A genuine lineage-bound source→sink flow in the served document."""
    return (
        "<html><body><div id='out'></div>\n"
        "<script>\n"
        f"  var {parameter} = new URLSearchParams(location.search)"
        f".get('{parameter}');\n"
        f"  document.getElementById('out').innerHTML = {parameter};\n"
        "</script></body></html>")


def document_lineage_eval() -> str:
    return ("<html><body><script>\n"
            "var p = location.hash.substring(1);\n"
            "eval(p);\n"
            "</script></body></html>")


def document_lineage_write() -> str:
    return ("<html><body><script>\n"
            "var p = location.search;\n"
            "document.write(p);\n"
            "</script></body></html>")


def document_no_lineage() -> str:
    """A sink and a source that are not connected to the parameter."""
    return ("<html><body><script>\n"
            "var safe = 'static';\n"
            "document.getElementById('out').innerHTML = safe;\n"
            "var unrelated = location.search;\n"
            "</script></body></html>")


def document_presence_only() -> str:
    """Source mentioned, no dangerous sink at all."""
    return ("<html><body><script>\n"
            "console.log(location.hash);\n"
            "</script><div innerHTML='x'></div></body></html>")


def document_sink_only() -> str:
    """A dangerous sink with no DOM source anywhere."""
    return ("<html><body><script>\n"
            "document.getElementById('out').innerHTML = 'static';\n"
            "</script></body></html>")


def document_script_text_only(marker: str = MARKER) -> str:
    """The marker appears inside a <script> block as text, never executed."""
    return (f"<html><body><pre>&lt;script&gt;{marker}&lt;/script&gt;</pre>"
            f"<script>var note = '{marker}';</script></body></html>")


def document_reflection_only(marker: str = MARKER) -> str:
    """A reflected marker in HTML text: reflection, never execution."""
    return f"<html><body><div>You searched for {marker}</div></body></html>"


def document_wrong_parameter() -> str:
    """A lineage flow, but bound to a different parameter than observed."""
    return document_lineage("other")


def document_huge() -> str:
    """A document larger than the frozen DOM observation ceiling."""
    return document_lineage() + ("<!--" + ("x" * 40000) + "-->")


# ----------------------------------------------------------------- harnesses

def harness_executed() -> dict[str, Any]:
    return {"instrumented": True, "execution_observed": True,
            "sink_observed": True, "reason": "controlled_marker_executed",
            "navigations": 1, "redirects": 0, "duration_seconds": 0.4,
            "instrumentation_method": "offline_harness",
            "instrumentation_version": "epic15-test-1"}


def harness_sink_only() -> dict[str, Any]:
    return {"instrumented": True, "execution_observed": False,
            "sink_observed": True, "reason": "sink_reached_no_execution",
            "navigations": 1, "redirects": 0, "duration_seconds": 0.3,
            "instrumentation_method": "offline_harness",
            "instrumentation_version": "epic15-test-1"}


def harness_not_executed() -> dict[str, Any]:
    return {"instrumented": True, "execution_observed": False,
            "sink_observed": False, "reason": "instrumented_run_observed_none",
            "navigations": 1, "redirects": 0, "duration_seconds": 0.2,
            "instrumentation_method": "offline_harness",
            "instrumentation_version": "epic15-test-1"}


def harness_no_instrumentation() -> dict[str, Any]:
    return {"instrumented": False, "execution_observed": False,
            "sink_observed": False, "reason": "no_hooks_installed"}


def harness_timeout() -> dict[str, Any]:
    return {"instrumented": True, "timed_out": True,
            "execution_observed": False, "sink_observed": False,
            "reason": "wall_clock_exceeded"}


def harness_raising(**_: Any):
    raise RuntimeError("browser process died")


def harness_redirected_out_of_scope() -> dict[str, Any]:
    return {"instrumented": True, "execution_observed": False,
            "sink_observed": False, "redirected_to": "http://127.0.0.1/",
            "reason": "redirect_left_the_authorized_scope"}


def runner(outcome: dict[str, Any]):
    """A deterministic offline harness returning one fixed outcome."""
    def _run(**_: Any) -> dict[str, Any]:
        return dict(outcome)
    return _run


# ------------------------------------------------------------------ forgery

def forged_execution_row() -> dict[str, Any]:
    """A hand-written row claiming execution (EPIC14 boundary applies)."""
    return {"id": "ev-forged-exec", "type": "observation",
            "signal": "payload_execution", "category": "XSS",
            "job_id": "job-forged", "observation_ref": "obs-forged",
            "detail": "claimed execution"}


def forged_sink_stamp_row() -> dict[str, Any]:
    """The core metadata attack: a parameter row stamped as a DOM sink."""
    return {"id": "ev-forged-sink", "type": "observation",
            "signal": "xss_parameter_inventory", "category": "XSS",
            "evidence_type": "DOM_SINK_IDENTIFIED", "job_id": "job-forged",
            "observation_ref": "obs-forged-2", "detail": "claimed sink"}


def llm_execution_claim() -> dict[str, Any]:
    """An advisory row asserting execution (never authoritative)."""
    return {"id": "ev-llm-exec", "type": "llm_insight",
            "signal": "payload_execution", "category": "XSS",
            "advisory_id": "adv-1", "detail": "the model says XSS confirmed"}


def screenshot_evidence() -> dict[str, Any]:
    """A screenshot artifact: not execution evidence."""
    return {"id": "ev-shot", "type": "observation",
            "signal": "screenshot_captured", "category": "XSS",
            "detail": "screenshot of the rendered page"}


def html_script_text_evidence(marker: str = MARKER) -> dict[str, Any]:
    """Script text in the response: not execution evidence."""
    return {"id": "ev-script-text", "type": "observation",
            "signal": "response_observed", "category": "XSS",
            "detail": f"response contained <script>{marker}</script>"}
