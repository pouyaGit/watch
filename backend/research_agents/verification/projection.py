"""EPIC12 — SOC projection of a verification chain (§19).

The projection is what an analyst reads.  Its single hardest rule: **it must
never show an optimistic "Verified" badge when the deterministic chain is
incomplete.**  So the badge is derived from the EPIC11 verdict *and* the chain's
own completeness, and an inconsistency between the two is surfaced as
``INCONSISTENT`` — never as a green badge.

The projection is a pure function of persisted state: chain state, the actions
that ran, the observations they produced and the loop outcome.  It adds no facts
of its own.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from backend.research_agents.verification import chains as ch
from backend.research_agents.verification.engine import ChainState, chain_matrix

PROJECTION_RULE_VERSION = "epic12-chain-projection-1"

BADGE_VERIFIED = "VERIFIED"
BADGE_PENDING = "VERIFICATION_PENDING"
BADGE_BLOCKED = "BLOCKED"
BADGE_REJECTED = "NOT_CONFIRMED"
BADGE_UNKNOWN = "UNKNOWN"
BADGE_INCONSISTENT = "INCONSISTENT"

BADGE_LABELS: dict[str, str] = {
    BADGE_VERIFIED: "Verified (chain complete)",
    BADGE_PENDING: "Not confirmed \u2014 verification pending",
    BADGE_BLOCKED: "Not confirmed \u2014 blocked",
    BADGE_REJECTED: "Not confirmed \u2014 evidence contradicts",
    BADGE_UNKNOWN: "No verification chain state",
    BADGE_INCONSISTENT: "Inconsistent state \u2014 do not trust a badge",
}


def _required_stages_satisfied(state: ChainState) -> bool:
    """Every stage the confirmation contract needs is satisfied (or n/a)."""
    for stage in state.stages:
        if not stage.required_for_confirmation:
            continue
        if stage.status == ch.STAGE_SATISFIED:
            continue
        if stage.status == ch.STAGE_NOT_APPLICABLE:
            continue
        return False
    return True


def _trust_boundary(state_dict: Mapping[str, Any]) -> dict[str, Any]:
    """The EPIC14 trust-boundary view of one evidence set (§5).

    Reports every declared-vs-authoritative mismatch and every
    confirmation-capable row the authoritative layer refused to count, so the
    SOC sees evidence that lied about its own type instead of a clean set.
    """
    mismatches = [dict(m) for m in (state_dict.get("evidence_mismatches")
                                    or [])]
    excluded = [dict(x) for x in (state_dict.get("excluded_evidence") or [])]
    return {
        "authoritative": True,
        "classifier_version": str(state_dict.get("classifier_version") or ""),
        "mismatch_count": len(mismatches),
        "mismatch_classes": sorted({str(m.get("class") or "")
                                    for m in mismatches if m.get("class")}),
        "mismatches": mismatches[:20],
        "excluded_confirmation_count": len(excluded),
        "excluded_confirmation": excluded[:20],
        "clean": not (mismatches or excluded),
        "statement": ("evidence strength is determined by authoritative "
                      "provenance and signal classification, not by a "
                      "persisted row's self-declared evidence type"),
    }


def badge_for(state: ChainState | Mapping[str, Any] | None) -> dict[str, Any]:
    """The analyst badge — never optimistic."""
    if state is None:
        return {"state": BADGE_UNKNOWN, "label": BADGE_LABELS[BADGE_UNKNOWN],
                "optimistic": False, "reason": "no_chain_state"}
    if isinstance(state, Mapping):
        verdict = str(state.get("verdict") or "")
        confirmed = bool(state.get("confirmed"))
        required_ok = all(
            (s.get("status") in (ch.STAGE_SATISFIED, ch.STAGE_NOT_APPLICABLE))
            for s in (state.get("stages") or [])
            if s.get("required_for_confirmation"))
        return _badge(verdict, confirmed, required_ok,
                      len(state.get("evidence_mismatches") or []))
    return _badge(state.verdict, state.confirmed,
                  _required_stages_satisfied(state),
                  len(state.evidence_mismatches))


def _badge(verdict: str, confirmed: bool, required_ok: bool,
           mismatches: int = 0) -> dict[str, Any]:
    if verdict == "VERIFIED" and mismatches:
        # the verdict did not lean on the mismatched rows (they cannot
        # support a claim), but the evidence set is not clean and the badge
        # must never present it as if it were
        return {"state": BADGE_INCONSISTENT,
                "label": BADGE_LABELS[BADGE_INCONSISTENT],
                "optimistic": False,
                "reason": "evidence_set_contains_type_mismatch"}
    if verdict == "VERIFIED" and not (confirmed and required_ok):
        return {"state": BADGE_INCONSISTENT,
                "label": BADGE_LABELS[BADGE_INCONSISTENT],
                "optimistic": False,
                "reason": "verified_verdict_without_complete_chain"}
    if verdict == "VERIFIED":
        return {"state": BADGE_VERIFIED, "label": BADGE_LABELS[BADGE_VERIFIED],
                "optimistic": False, "reason": "claim_supported"}
    if verdict == "BLOCKED":
        return {"state": BADGE_BLOCKED, "label": BADGE_LABELS[BADGE_BLOCKED],
                "optimistic": False, "reason": "blocked"}
    if verdict == "REJECTED":
        return {"state": BADGE_REJECTED, "label": BADGE_LABELS[BADGE_REJECTED],
                "optimistic": False, "reason": "contradicted"}
    if verdict == "VERIFICATION_PENDING":
        return {"state": BADGE_PENDING, "label": BADGE_LABELS[BADGE_PENDING],
                "optimistic": False, "reason": "evidence_missing"}
    return {"state": BADGE_UNKNOWN, "label": BADGE_LABELS[BADGE_UNKNOWN],
            "optimistic": False, "reason": "no_verdict"}


def project_chain(
    state: ChainState | Mapping[str, Any] | None,
    *,
    actions: Iterable[Mapping[str, Any]] = (),
    observations: Iterable[Mapping[str, Any]] = (),
    loop: Mapping[str, Any] | None = None,
    authorization: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project one verification chain for the SOC UI."""
    if state is None:
        return {
            "available": False,
            "rule_version": PROJECTION_RULE_VERSION,
            "badge": badge_for(None),
            "stages": [],
            "evidence_used": [],
            "evidence_missing": [],
            "negative_results": [],
            "actions": [],
            "requests": [],
            "authorization": dict(authorization or {}),
            "why_not_confirmed": ["no_chain_state"],
            "trust_boundary": _trust_boundary({}),
            "limitations": ["no verification chain state is persisted yet"],
        }

    state_dict = state.to_dict() if isinstance(state, ChainState) else dict(state)
    stages = (chain_matrix(state) if isinstance(state, ChainState)
              else list(state_dict.get("stages") or []))

    evidence_used: list[dict[str, Any]] = []
    negative_results: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    for observation in observations:
        row = dict(observation)
        entry = {
            "observation_id": row.get("observation_id"),
            "signal": row.get("signal"),
            "evidence_class": row.get("evidence_class")
            or row.get("evidence_type"),
            "where": row.get("where"),
            "under_input": row.get("under_input"),
            "under_request": row.get("under_request"),
            "observed": row.get("observed"),
            "not_observed": row.get("not_observed"),
            "context": row.get("context"),
            "confidence": row.get("confidence"),
            "observed_at": row.get("observed_at"),
        }
        if row.get("negative") or row.get("not_tested"):
            negative_results.append(entry)
        else:
            evidence_used.append(entry)
        if row.get("request_ref") or row.get("response_ref"):
            requests.append({
                "observation_id": row.get("observation_id"),
                "request_ref": row.get("request_ref"),
                "response_ref": row.get("response_ref"),
                "where": row.get("where"),
            })

    action_rows = []
    for action in actions:
        row = dict(action)
        action_rows.append({
            "action_id": row.get("action_id"),
            "action_type": row.get("action_type"),
            "label": row.get("label"),
            "state": row.get("state"),
            "safety": row.get("safety"),
            "target": row.get("target"),
            "authorization_id": row.get("authorization_id"),
            "executor": row.get("executor"),
            "attempt": row.get("attempt"),
            "error": row.get("error"),
            "blocked_reason": row.get("blocked_reason"),
            "observation_count": len(row.get("observation_ids") or []),
            "created_at": row.get("created_at"),
        })

    return {
        "available": True,
        "rule_version": PROJECTION_RULE_VERSION,
        "trust_boundary": _trust_boundary(state_dict),
        "chain_id": state_dict.get("chain_id"),
        "vulnerability_class": state_dict.get("vulnerability_class"),
        "capability": state_dict.get("capability"),
        "contract_id": state_dict.get("contract_id"),
        "verdict": state_dict.get("verdict"),
        "verdict_reason": state_dict.get("verdict_reason"),
        "verdict_source": state_dict.get("verdict_source"),
        "badge": badge_for(state),
        "stages": stages,
        "stage_count": state_dict.get("stage_count"),
        "satisfied_count": state_dict.get("satisfied_count"),
        "next_stage": state_dict.get("next_stage"),
        "next_stage_label": state_dict.get("next_stage_label"),
        "next_stage_missing_types": list(
            state_dict.get("next_stage_missing_types") or []),
        "evidence_used": evidence_used,
        "evidence_missing": list(state_dict.get("missing_evidence") or []),
        "evidence_missing_types": list(
            state_dict.get("missing_evidence_types") or []),
        "negative_results": negative_results,
        "contradictions": list(state_dict.get("contradictions") or []),
        "actions": action_rows,
        "requests": requests,
        "authorization": dict(authorization or {
            "satisfied": state_dict.get("authorization_satisfied"),
        }),
        "why_not_confirmed": list(state_dict.get("why_not_confirmed") or []),
        "blockers": list(state_dict.get("blockers") or []),
        "loop": dict(loop or {}),
        "limitations": list(
            (loop or {}).get("limitations")
            or ["the chain explains; only the EPIC11 gate decides"]),
    }


def chain_projection_for_candidate(
    *,
    candidate_id: str,
    vulnerability_class: str,
    store: Any,
    rows: Iterable[Mapping[str, Any]] = (),
    authorization: Any = None,
) -> dict[str, Any]:
    """Project a candidate's chain from persisted verification state."""
    from backend.research_agents.verification import engine as en
    state = en.evaluate_chain(vulnerability_class, rows,
                              authorization=authorization)
    actions = []
    observations = []
    loop = None
    if store is not None:
        try:
            actions = store.actions_for_candidate(candidate_id)
            observations = store.observations_for_candidate(candidate_id)
            loop = store.latest_loop(candidate_id)
        except Exception:  # noqa: BLE001 - a broken store shows no chain data
            actions, observations, loop = [], [], None
    return project_chain(state, actions=actions, observations=observations,
                         loop=loop)


def deep_verification_block(result: Any = None) -> dict[str, Any]:
    """The SOC view of deep verification (EPIC15 §27).

    Deliberately explicit about the four states an analyst must not
    conflate: ``NOT_OBSERVED`` (instrumented, nothing seen),
    ``NOT_TESTED`` (never attempted), ``BLOCKED`` (authorization/scope/
    budget) and ``CAPABILITY_UNAVAILABLE`` (no safe lane exists here).
    """
    from backend.research_agents.verification import deep as dp
    if result is None:
        lanes = dp.capability_document()
        return {
            "deep_verification": True,
            "state": dp.DEEP_NOT_TESTED,
            "browser": ("available" if lanes["lanes"]["browser"]["live_switch"]
                        else "unavailable"),
            "browser_blockers": lanes["lanes"]["browser"]["blockers"],
            "dom_analysis": lanes["lanes"]["dom"]["capability"],
            "authorization": "not_evaluated",
            "source": "", "sink": "",
            "execution": "unavailable",
            "exploitability": "not_established",
            "evidence": [],
            "next_step": ("run a deep verification against an authorized, "
                          "in-scope candidate"),
            "rule_version": dp.DEEP_VERIFICATION_VERSION,
        }
    return dp.project_deep(result)


__all__ = [
    "_trust_boundary",
    "deep_verification_block",
    "BADGE_BLOCKED", "BADGE_INCONSISTENT", "BADGE_LABELS", "BADGE_PENDING",
    "BADGE_REJECTED", "BADGE_UNKNOWN", "BADGE_VERIFIED", "PROJECTION_RULE_VERSION",
    "badge_for", "chain_projection_for_candidate", "project_chain",
]
