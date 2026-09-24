"""EPIC12 — the advisory (LLM) role in deep verification (§14).

The advisor may suggest *which already-allowed verification step is most useful
next*.  It may not do anything else: it cannot declare a vulnerability, cannot
add evidence, cannot widen a scope, cannot introduce an action the chain does not
already allow, and cannot change a verdict.

Design:

* the outbound request is a bounded, structural envelope (the same shape the
  project's finding advisor already uses) — no URLs, no payloads, no
  credentials, hard-capped at 4000 characters;
* the response is schema-validated and then passed through
  :func:`backend.research_agents.finding.advisor.validate_recommendation`, the
  project's existing closed-set + scope-expansion check, so the verification
  layer reuses that boundary instead of restating it;
* any response that asserts a confirmation/verdict is rejected outright
  (``advisor_may_not_confirm``), and free text is bounded;
* a rejected or failed advisory leaves the hint empty, and the deterministic
  planner proceeds on its own — an LLM failure is never a verification result.

``make_chain_advisor(call_llm)`` returns the callable the loop expects; the
provider call itself is injected, so this module is fully testable offline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from backend.research_agents.finding.advisor import (
    MAX_CONTEXT_CHARS,
    validate_recommendation,
)
from backend.research_agents.verification import actions as ac
from backend.research_agents.verification import chains as ch

ADVISOR_RULE_VERSION = "epic12-chain-advisor-1"
CHAIN_ADVISOR_PROMPT_VERSION = "epic12-chain-advisor-v1"

#: The only model the advisor may use (free-only, fail closed, no fallback).
ADVISOR_MODEL = "openrouter/free"

ADVISORY_LIMITATIONS: tuple[str, ...] = (
    "advisory only: the deterministic chain policy decides what may execute",
    "the advisor cannot confirm a vulnerability, add evidence or widen scope",
    "suggestions are limited to actions the current chain stage already allows",
    "no confirmation claim in an advisory response is ever accepted",
)

#: Phrases that mean the advisor is trying to be authoritative.
_CONFIRMATION_MARKERS: tuple[str, ...] = (
    "confirmed", "confirmed xss", "vulnerability confirmed", "exploitable",
    "exploitability", "verified", "verified vulnerability", "proof of exploit",
    "exploit proven", "severity: critical", "cvss",
    # execution-claim language: an advisory may never smuggle a payload claim
    "payload_execution", "payload executed", "script executed", "alert(",
    "proof of concept", "poc:", "rce", "code execution",
)

MAX_RATIONALE_CHARS = 400


@dataclass
class ChainAdvice:
    """A validated, bounded advisory hint (never authoritative)."""

    hint_action: str = ""
    rationale: str = ""
    missing_evidence: tuple[str, ...] = ()
    accepted: bool = False
    rejected_reason: str = ""
    model_requested: str = ADVISOR_MODEL
    model_resolved: str = ""
    latency_ms: int = 0
    prompt_version: str = CHAIN_ADVISOR_PROMPT_VERSION
    error: str = ""
    raw_keys: tuple[str, ...] = ()
    rule_version: str = ADVISOR_RULE_VERSION

    @property
    def advisory_only(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "hint_action": self.hint_action,
            "rationale": self.rationale,
            "missing_evidence": list(self.missing_evidence),
            "accepted": self.accepted,
            "rejected_reason": self.rejected_reason,
            "model_requested": self.model_requested,
            "model_resolved": self.model_resolved,
            "latency_ms": self.latency_ms,
            "prompt_version": self.prompt_version,
            "error": self.error,
            "raw_keys": list(self.raw_keys),
            "advisory_only": True,
            "rule_version": self.rule_version,
        }


def _bounded(value: Any, limit: int = MAX_RATIONALE_CHARS) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit]


def build_chain_request(
    *,
    vulnerability_class: str,
    chain_state: Mapping[str, Any],
    missing_evidence: Iterable[str] = (),
    allowed_actions: Iterable[str] = (),
    budget: Mapping[str, Any] | None = None,
    candidate_id: str = "",
) -> dict[str, Any]:
    """The bounded, structural advisory request (no URLs, no payloads)."""
    stages = []
    for stage in (chain_state.get("stages") or [])[:8]:
        if not isinstance(stage, Mapping):
            continue
        stages.append({
            "signal_type": "CHAIN_STAGE",
            "stage": _bounded(stage.get("key"), 40),
            "status": _bounded(stage.get("status"), 20),
            "missing": [_bounded(t, 40)
                        for t in (stage.get("missing_types") or [])][:6],
        })
    signals: list[dict[str, Any]] = [
        {"signal_type": "CHAIN_SUMMARY",
         "vulnerability_class": _bounded(vulnerability_class, 40),
         "capability": _bounded(chain_state.get("capability"), 20),
         "satisfied_stages": int(chain_state.get("satisfied_count") or 0),
         "stage_count": int(chain_state.get("stage_count") or 0),
         "next_stage": _bounded(chain_state.get("next_stage"), 40)},
        {"signal_type": "MISSING_EVIDENCE",
         "types": [_bounded(t, 40) for t in missing_evidence][:8]},
        {"signal_type": "ALLOWED_ACTIONS",
         "actions": [_bounded(a, 40) for a in allowed_actions][:8]},
        {"signal_type": "SAFETY_CONSTRAINTS",
         "active_payload_allowed": False,
         "network_allowed": False,
         "note": "read-only derivations only unless an authorization exists"},
    ]
    signals.extend(stages)
    if budget:
        signals.append({
            "signal_type": "BUDGET_STATE",
            "remaining": {str(k): int(v)
                          for k, v in (budget.get("remaining") or {}).items()},
        })
    request: dict[str, Any] = {
        "instruction": (
            "Given the verification chain state, name the single most useful "
            "NEXT verification action from the allowed list, or 'NONE'. "
            "You cannot confirm anything."),
        "sections": {"learning_signals": signals},
        "source_refs": ([{"layer": "verification_chain",
                          "ref": _bounded(candidate_id, 40)}]
                        if candidate_id else []),
        "limitations": list(ADVISORY_LIMITATIONS),
        "research_only": True,
        "deterministic": False,
    }
    blob = json.dumps(request, sort_keys=True)
    while len(blob) > MAX_CONTEXT_CHARS:
        stage_rows = [s for s in request["sections"]["learning_signals"]
                      if s.get("signal_type") == "CHAIN_STAGE"]
        if len(stage_rows) > 1:
            request["sections"]["learning_signals"].remove(stage_rows[-1])
        elif len(request["instruction"]) > 120:
            request["instruction"] = request["instruction"][:120]
        else:
            break
        blob = json.dumps(request, sort_keys=True)
    return request


def validate_chain_advice(
    response: Any,
    *,
    allowed_actions: Iterable[str],
    candidate_id: str = "",
    objective_id: str = "",
    scope_ref: str = "",
) -> ChainAdvice:
    """Schema-validate + bound an advisory response.  Fail closed."""
    advice = ChainAdvice()
    if response is None:
        advice.rejected_reason = "empty_response"
        return advice
    if not isinstance(response, Mapping):
        advice.rejected_reason = "response_not_a_mapping"
        return advice
    advice.raw_keys = tuple(sorted(str(k) for k in response))[:12]

    text_blob = json.dumps({k: v for k, v in response.items()
                            if isinstance(v, (str, int, float))},
                           sort_keys=True).lower()
    for marker in _CONFIRMATION_MARKERS:
        if marker in text_blob:
            advice.rejected_reason = "advisor_may_not_confirm"
            return advice

    declared_scope = str(response.get("scope_ref")
                         or response.get("scope") or "").strip()
    if declared_scope and str(scope_ref or "").strip() and (
            declared_scope != str(scope_ref).strip()):
        advice.rejected_reason = "scope_expansion"
        return advice

    raw_action = str(
        response.get("next_action") or response.get("action")
        or response.get("observation_type") or "").strip().upper()
    if not raw_action or raw_action == "NONE":
        advice.rejected_reason = "no_action_suggested"
        return advice

    allowed = {str(a).strip().upper() for a in allowed_actions}
    ok, reason = validate_recommendation(
        raw_action, allowed_types=allowed, candidate_id=candidate_id,
        verification_id=objective_id, scope_ref=str(scope_ref or ""),
        expected_scope=str(scope_ref or ""))
    if not ok:
        advice.rejected_reason = reason
        return advice
    if raw_action not in ac.ACTION_SPECS:
        advice.rejected_reason = f"unknown_action_type:{raw_action[:40]}"
        return advice

    advice.hint_action = raw_action
    advice.rationale = _bounded(response.get("rationale")
                                or response.get("reasoning") or "")
    advice.missing_evidence = tuple(
        _bounded(t, 40) for t in (response.get("missing_evidence") or [])
        if str(t).strip())[:6]
    advice.accepted = True
    return advice


def make_chain_advisor(
    call_llm: Callable[[dict[str, Any]], Any],
    *,
    model: str = ADVISOR_MODEL,
) -> Callable[..., tuple[str, dict[str, Any]]]:
    """Build the advisor callable the verification loop expects.

    ``call_llm(request) -> response`` is injected: in production it is the
    project's free-only provider call; in tests it is a stub.  The returned
    callable yields ``(hint_action, advice_dict)`` and never raises for an
    advisory failure — the loop continues deterministically.
    """
    def advisor(*, candidate_id: str = "", chain_state: Mapping[str, Any] | None
                = None, missing_evidence: Iterable[str] = (),
                allowed_actions: Iterable[str] = (),
                budget: Mapping[str, Any] | None = None,
                objective_id: str = "", scope_ref: str = "", **_: Any
                ) -> tuple[str, dict[str, Any]]:
        state = dict(chain_state or {})
        request = build_chain_request(
            vulnerability_class=str(state.get("vulnerability_class") or ""),
            chain_state=state, missing_evidence=missing_evidence,
            allowed_actions=allowed_actions, budget=budget,
            candidate_id=candidate_id)
        try:
            response = call_llm(request)
        except Exception as exc:  # noqa: BLE001 - advisory failure is not a result
            advice = ChainAdvice(error=f"advisor_call_failed:"
                                       f"{type(exc).__name__}",
                                 model_requested=model)
            return "", advice.to_dict()
        advice = validate_chain_advice(
            response, allowed_actions=allowed_actions,
            candidate_id=candidate_id, objective_id=objective_id,
            scope_ref=scope_ref)
        advice.model_requested = model
        if isinstance(response, Mapping):
            advice.model_resolved = str(response.get("model") or "")
            try:
                advice.latency_ms = int(response.get("latency_ms") or 0)
            except (TypeError, ValueError):
                advice.latency_ms = 0
        return (advice.hint_action if advice.accepted else ""), advice.to_dict()

    return advisor


def chain_advisor_catalog() -> list[dict[str, Any]]:
    """Every chain action type the advisor may ever name."""
    out: list[dict[str, Any]] = []
    for cls in sorted(ch.CHAINS):
        out.append({
            "vulnerability_class": cls,
            "capability": ch.CHAINS[cls].capability,
            "allowed_actions": list(ch.action_types_for(cls)),
        })
    return out


__all__ = [
    "ADVISOR_MODEL", "ADVISOR_RULE_VERSION", "ADVISORY_LIMITATIONS",
    "CHAIN_ADVISOR_PROMPT_VERSION", "ChainAdvice", "MAX_RATIONALE_CHARS",
    "build_chain_request", "chain_advisor_catalog", "make_chain_advisor",
    "validate_chain_advice",
]
