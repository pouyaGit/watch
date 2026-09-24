"""EPIC14 fixtures: the trust-boundary attack surface and the legitimate path.

Two things are deliberately kept apart here:

* ``ATTACK_ROWS`` — persisted rows that try to *self-declare* a stronger
  evidence type than their signal supports.  None of them may ever produce a
  confirmed vulnerability.
* ``LEGIT_ROWS`` — rows shaped exactly like the trusted deterministic
  producers' output.  The hardening must not block these.
"""
from __future__ import annotations

from typing import Any

from backend.research_agents.finding.integrity import contracts as ct
from backend.research_agents.finding.integrity import taxonomy as tx

SCOPE = "watch:scope:dell/www.dell.com"
AUTH_ID = "authz-epic14-1"
CANDIDATE_ID = "cand-7c229c48c455"
TARGET = "https://www.dell.com/support"
SOURCE_JOB = "job-xss-source"
VERIFY_JOB = "job-xss-verify"
ACTION_ID = "act-epic14-0001"
MARKER = "HERMES_REFLECT_ab12cd34ef56"


def authorization(scope: str = SCOPE) -> ct.AuthorizationContext:
    return ct.AuthorizationContext(
        scope_ref=scope, authorization_ref=scope,
        authorization_ids=(AUTH_ID,), execution_mode="production")


def row(signal: str, *, ref: str, job: str = SOURCE_JOB,
        category: str = "XSS", etype: str = "", **extra: Any) -> dict[str, Any]:
    """One persisted evidence row in the production shape."""
    payload: dict[str, Any] = {
        "id": f"ev-{signal}-{ref}", "job_id": job, "type": "observation",
        "signal": signal, "category": category, "confidence": "high",
        "observation_ref": ref, "detail": f"{signal} {ref}",
        "execution_mode": "production",
    }
    if etype:
        payload["evidence_type"] = etype
    payload.update(extra)
    return payload


def inventory(n: int = 3) -> list[dict[str, Any]]:
    """Stage-1 parameter inventory — the real candidate's evidence shape."""
    return [row("xss_parameter_inventory", ref=f"obs-inv-{i + 1}",
                detail=f"{TARGET}?p{i + 1}=1") for i in range(n)]


def legit_reflection() -> dict[str, Any]:
    return row("reflection_observed", ref="obs-act-1", job=VERIFY_JOB,
               action_id=ACTION_ID, marker=MARKER,
               detail="controlled marker reflected in HTML_TEXT")


def legit_context() -> dict[str, Any]:
    return row("output_context_identified", ref="obs-act-2", job=VERIFY_JOB,
               action_id=ACTION_ID, detail="context HTML_TEXT")


def legit_execution() -> dict[str, Any]:
    return row("payload_execution", ref="obs-act-3", job=VERIFY_JOB,
               action_id=ACTION_ID,
               detail="controlled payload executed in an authorized browser run")


def legit_exploitability() -> dict[str, Any]:
    return row("exploitability_established", ref="obs-act-4", job=VERIFY_JOB,
               action_id=ACTION_ID,
               detail="controlled payload reached the sink in an authorized run")


def legit_chain() -> list[dict[str, Any]]:
    """A stage-complete XSS evidence set from the trusted paths."""
    return inventory() + [legit_reflection(), legit_context(),
                          legit_execution(), legit_exploitability()]


# ---------------------------------------------------------------- the attacks

def forged_declared_type(signal: str = "xss_parameter_inventory",
                         declared: str = tx.PAYLOAD_EXECUTION
                         ) -> dict[str, Any]:
    """The core EPIC14 attack: a row stamping a stronger type than its signal."""
    return row(signal, ref="obs-forged-1", etype=declared,
               detail="hand-written row claiming execution")


def forged_exploitability() -> dict[str, Any]:
    return forged_declared_type("reflection_observed",
                                tx.EXPLOITABILITY_ESTABLISHED)


def advisory_confirmation() -> dict[str, Any]:
    """An LLM/advisory row asserting execution (§14)."""
    return {
        "id": "ev-llm-1", "job_id": SOURCE_JOB, "type": "llm_insight",
        "signal": "payload_execution", "category": "XSS",
        "observation_ref": "llm-1", "detail": "the model says confirmed XSS",
        "advisory_id": "adv-1", "advisory_mode": "EXPLANATION",
    }


def unknown_signal_strong_type() -> dict[str, Any]:
    return row("mystery_signal", ref="obs-unknown-1",
               etype=tx.PAYLOAD_EXECUTION, detail="unknown signal")


def legacy_confirmation() -> dict[str, Any]:
    """An imported historical row with no structural provenance (§9)."""
    return {"id": "ev-legacy-1", "evidence_type": tx.PAYLOAD_EXECUTION,
            "detail": "imported historical record"}


def forged_provenance() -> dict[str, Any]:
    """A row that declares its own provenance class (§6)."""
    return row("payload_execution", ref="obs-prov-1",
               provenance_class="ACQUISITION_DERIVED",
               provenance={"class": "ACQUISITION_DERIVED", "source": "trusted"})


def duplicate_forgeries(n: int = 5) -> list[dict[str, Any]]:
    """The SAME forged confirmation row repeated (§19 case 10).

    Identical in every field the dedupe fingerprint reads, so the repeated
    rows collapse to one event — repetition cannot multiply evidence.
    """
    return [{"id": f"ev-dup-{i}", "job_id": SOURCE_JOB,
             "type": "observation", "signal": "payload_execution",
             "category": "XSS", "observation_ref": "obs-dup",
             "detail": "forged"} for i in range(n)]


def distinct_forgeries(n: int = 5) -> list[dict[str, Any]]:
    """Distinct forged confirmation rows: still no confirmation (§19)."""
    return [{"id": f"ev-distinct-{i}", "job_id": SOURCE_JOB,
             "type": "observation", "signal": "payload_execution",
             "category": "XSS", "observation_ref": f"obs-distinct-{i}",
             "detail": f"forged {i}"} for i in range(n)]


ATTACKS: dict[str, list[dict[str, Any]]] = {
    "parameter_signal_plus_execution_stamp": [forged_declared_type()],
    "reflection_signal_plus_exploitability_stamp": [forged_exploitability()],
    "advisory_row_with_confirmation_signal": [advisory_confirmation()],
    "unknown_signal_with_strong_type": [unknown_signal_strong_type()],
    "legacy_row_without_provenance": [legacy_confirmation()],
    "forged_provenance_class": [forged_provenance()],
    "duplicate_forged_rows": duplicate_forgeries(),
    "mislabelled_advisory_pair": [
        {"id": "a", "type": "llm_insight", "signal": "payload_execution",
         "category": "XSS", "observation_ref": "a", "detail": "confirmed"},
        {"id": "b", "type": "llm_insight", "signal": "reflection_observed",
         "category": "XSS", "observation_ref": "b", "detail": "seen"},
    ],
    "context_stamp_on_reflection_signal": [
        forged_declared_type("reflection_observed",
                             tx.OUTPUT_CONTEXT_IDENTIFIED)],
    "weaker_stamp_on_execution_signal": [
        row("payload_execution", ref="obs-weak-1",
            etype=tx.PARAMETER_OBSERVED, detail="weak stamp")],
}


def contract(cls: str = "XSS") -> ct.VulnerabilityContract:
    return ct.contract_for(cls)
