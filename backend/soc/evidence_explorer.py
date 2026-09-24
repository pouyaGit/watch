"""backend/soc/evidence_explorer.py — EPIC17 Analyst Evidence Explorer v1.

PROJECTION ONLY (EPIC17 §Hard rule).  This module adds **no** gate, no
lifecycle, no taxonomy, no authorization model and no evidence rule.  It
reads the authoritative EPIC11/EPIC12/EPIC15/EPIC16 projections and
re-shapes them into the five analyst surfaces an Evidence Explorer page
needs:

    1. verification chain steps   (``chain.stages`` — EPIC12 projection)
    2. observation vs proof       (derived *labels* only)
    3. why this state             (deterministic sentences)
    4. evidence summary           (counts + capability cells)
    5. analyst decision panel     (YES / NO / REVIEW + reasons)

Nothing here decides anything.  The verification verdict, the badge and
every evidence classification come from the existing projections:

  * ``backend.research_agents.verification.projection`` (EPIC12/15/16)
        ``chain_projection_for_candidate`` -> stages, evidence_used,
        evidence_missing, blockers, authorization, why_not_confirmed,
        trust_boundary, badge, verdict, limitations
  * ``backend.soc.findings._integrity_block`` (EPIC11 analyst view)
        authoritative_state, gate_reason, missing evidence types,
        unique observations, duplicates
  * ``backend.research_agents.verification.deep`` (EPIC15)
        the four-state deep block (NOT_TESTED / BLOCKED / ...) and the
        DOM flow verdict (SOURCE_ONLY, SOURCE_AND_SINK_LINEAGE, ...)

Two invariants are enforced by construction and asserted by
``tests/test_epic17_evidence_explorer.py``:

  * **the UI can never make a state** — the banner is
    ``chain["badge"]``, whose ``optimistic`` flag is always ``False``
    and which cannot read VERIFIED unless the authoritative chain
    confirms (EPIC12 ``badge_for``);
  * **evidence count never becomes evidence quality** — raw and unique
    counts are reported side by side, and ``strength_digest()`` covers
    only the strength surface (badge, proven stages, unique
    observations, missing evidence types), so duplicating evidence
    cannot move it.

An LLM advisory is never consulted: ``build()`` takes no LLM input and
the deterministic sentences below are assembled from projection fields.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

RULE_VERSION = "epic17-analyst-evidence-explorer-1"

# ---- chain step states (labels only, never a new taxonomy) ---------------
STEP_SATISFIED = "SATISFIED"
STEP_NOT_PROVEN = "NOT_PROVEN"
STEP_UNAVAILABLE = "UNAVAILABLE"
STEP_NOT_TESTED = "NOT_TESTED"
STEP_PENDING = "PENDING"

# ---- analyst decision (interpretation of the authoritative state) --------
DECISION_YES = "YES"
DECISION_NO = "NO"
DECISION_REVIEW = "REVIEW"

DECISION_NOTE = ("Interpretation of the persisted verification state only. "
                 "This panel is not a verdict and cannot confirm anything.")

# The two confirmation-capable evidence types (EPIC11 vocabulary, imported
# never redefined here).
from backend.research_agents.finding.integrity import taxonomy as _tx  # noqa: E402

CONFIRMATION_EVIDENCE = _tx.CONFIRMATION_EVIDENCE

# EPIC15 DOM flow verdicts (read-only import).
from backend.research_agents.verification.deep import dom as _dom  # noqa: E402

FLOW_LINEAGE = _dom.FLOW_LINEAGE
FLOW_SOURCE_ONLY = _dom.FLOW_SOURCE_ONLY

_TEXT_LIMIT = 160


def _text(value: Any, limit: int = _TEXT_LIMIT) -> str:
    if value is None:
        return ""
    return str(value)[:limit]


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


# --------------------------------------------------------------- read path
def _stores(fs: Any = None, runtime: Any = None) -> tuple[Any, Any]:
    """Reuse the existing SOC store resolution (no second store model)."""
    if fs is not None and runtime is not None:
        return fs, runtime
    from backend.soc import findings as soc_findings

    resolved_fs, resolved_runtime = soc_findings._store()
    return fs if fs is not None else resolved_fs, (
        runtime if runtime is not None else resolved_runtime)


def build(candidate_id: str, *, fs: Any = None, runtime: Any = None,
          advisor: dict[str, Any] | None = None) -> dict[str, Any]:
    """Assemble the analyst Evidence Explorer view for one candidate.

    Deterministic and side-effect free: it reads persisted rows through
    the same helpers the finding page uses and returns the projection.
    An unknown candidate yields an explicit ``available: False`` view
    instead of raising.
    """
    candidate_id = _text(candidate_id, 80)
    if not candidate_id:
        return _unavailable("no_candidate_id")
    try:
        fs, runtime = _stores(fs, runtime)
        cand = fs.get_candidate(candidate_id)
        if cand is None:
            return _unavailable("candidate_not_found")
        from backend.soc import findings as soc_findings

        vers = fs.list_verifications(candidate_id=candidate_id)
        ver = vers[-1] if vers else None
        case = fs.cases_for_candidate(candidate_id)
        mapped, raw_rows = soc_findings.evidence_payload(cand, ver, runtime)
        ver_job = ver.job_id if ver is not None else cand.source_job
        auth_ids = list(getattr(ver, "authorization_ids", None) or []) or \
            soc_findings._runtime_auth_ids(runtime, ver_job)
        integrity_block = soc_findings._integrity_block(
            cand, case, _as_dict(advisor), ver, mapped)
        from backend.research_agents.finding.integrity import contracts as ct
        from backend.research_agents.verification import projection as pj

        # EPIC17: authorization lineage is READ from persisted rows using
        # the same derivation the EPIC11 projection uses (never invented,
        # never an LLM input). The gate stays authoritative for whether
        # authorization was satisfied.
        auth_context = ct.AuthorizationContext(
            scope_ref=_text(getattr(cand, "scope_ref", "")),
            authorization_ref=_text(getattr(cand, "scope_ref", "")),
            authorization_ids=tuple(str(x) for x in auth_ids),
            execution_mode=_text(
                _as_dict(getattr(ver, "provenance", None)).get("execution_mode")),
            provenance={"source": "epic17_persisted_projection"})
        chain = pj.chain_projection_for_candidate(
            candidate_id=candidate_id,
            vulnerability_class=_text(getattr(cand, "vulnerability_class", "")),
            store=runtime,
            rows=raw_rows,
            authorization=auth_context,
        )
        claim_integrity = _as_dict(getattr(cand, "claim_integrity", None))
        deep = pj.deep_verification_block(
            claim_integrity.get("deep_verification") or None)
    except Exception as exc:  # noqa: BLE001 - an honest unavailable view
        return _unavailable(f"projection_error:{type(exc).__name__}")

    integrity = _integrity_view(integrity_block)
    steps = chain_steps(chain)
    capability = _capability_block(chain, deep, cand)
    summary = evidence_summary(chain, integrity, mapped, raw_rows, deep,
                               capability)
    decision = analyst_decision(chain, integrity, deep, steps, capability)
    why = why_this_state(chain, integrity, deep, steps, capability, decision)
    view: dict[str, Any] = {
        "available": True,
        "rule_version": RULE_VERSION,
        "candidate_id": candidate_id,
        "vulnerability_class": _text(getattr(cand, "vulnerability_class", "")),
        "banner": banner(chain),
        "chain": {
            "available": bool(chain.get("available")),
            "rule_version": _text(chain.get("rule_version")),
            "chain_id": _text(chain.get("chain_id")),
            "vulnerability_class": _text(chain.get("vulnerability_class")),
            "capability": _text(chain.get("capability")),
            "contract_id": _text(chain.get("contract_id")),
            "verdict": _text(chain.get("verdict")),
            "verdict_reason": _text(chain.get("verdict_reason")),
            "verdict_source": _text(chain.get("verdict_source")),
            # the authoritative badge, verbatim: the banner above is just
            # this value (the UI has no state of its own)
            "badge": banner(chain),
            "stage_count": chain.get("stage_count"),
            "satisfied_count": chain.get("satisfied_count"),
            "next_stage": _text(chain.get("next_stage")),
            "next_stage_label": _text(chain.get("next_stage_label")),
            "next_stage_missing_types": [
                _text(x) for x in _as_list(chain.get("next_stage_missing_types"))],
            "steps": steps,
            "evidence_used": [
                {"observation_id": _text(r.get("observation_id")),
                 "signal": _text(r.get("signal")),
                 "evidence_class": _text(r.get("evidence_class")),
                 "where": _text(r.get("where")),
                 "context": _text(r.get("context")),
                 "confidence": _text(r.get("confidence")),
                 "observed_at": _text(r.get("observed_at"))}
                for r in _as_list(chain.get("evidence_used"))[:40]
                if isinstance(r, dict)],
            "evidence_missing": [
                _text(x) for x in _as_list(chain.get("evidence_missing"))],
            "evidence_missing_types": [
                _text(x) for x in _as_list(chain.get("evidence_missing_types"))],
            "negative_results": [
                _text(x) for x in _as_list(chain.get("negative_results"))],
            "contradictions": [
                _text(x) for x in _as_list(chain.get("contradictions"))],
            "authorization": _authorization_view(chain, auth_ids),
            "why_not_confirmed": [
                _text(x) for x in _as_list(chain.get("why_not_confirmed"))],
            "blockers": [_text(x) for x in _as_list(chain.get("blockers"))],
            "trust_boundary": _trust_view(chain.get("trust_boundary")),
            "limitations": [
                _text(x) for x in _as_list(chain.get("limitations"))],
        },
        "integrity": integrity,
        "deep": deep,
        "capability_cells": capability,
        "observation_vs_proof": observation_vs_proof(steps, capability),
        "evidence_summary": summary,
        "why": why,
        "decision": decision,
        "sources": {
            "chain_projection": _text(chain.get("rule_version")),
            "integrity_projection": integrity.get("rule_version", ""),
            "deep_projection": _text(_as_dict(deep).get("rule_version")),
            "explorer": RULE_VERSION,
            "read_path": "persisted rows -> EPIC11 gate -> EPIC12/15/16 "
                         "projection (no recalculation in the UI layer)",
        },
    }
    view["strength_digest"] = strength_digest(view)
    return view


def _unavailable(reason: str) -> dict[str, Any]:
    """Honest degradation: no projection, no implied state."""
    return {
        "available": False,
        "rule_version": RULE_VERSION,
        "reason": _text(reason),
        "banner": {"state": "UNKNOWN", "label": "NO PROJECTION",
                   "optimistic": False, "reason": _text(reason)},
        "chain": {"available": False, "steps": [], "evidence_missing": [],
                  "blockers": [], "authorization": {"satisfied": False,
                                                    "ids": [], "source": ""},
                  "why_not_confirmed": [_text(reason)]},
        "integrity": _integrity_view({}),
        "deep": {},
        "capability_cells": {},
        "observation_vs_proof": {"observation": [], "proof": []},
        "evidence_summary": {},
        "why": [("No verification projection is available for this record; "
                 "no state is implied.")],
        "decision": {"can_report": DECISION_REVIEW, "reasons": [_text(reason)],
                     "note": DECISION_NOTE},
        "sources": {"explorer": RULE_VERSION},
        "strength_digest": "",
    }


# ------------------------------------------------------------- sub-views
def _trust_view(raw: Any) -> dict[str, Any]:
    trust = _as_dict(raw)
    if not trust:
        return {}
    return {
        "authoritative": trust.get("authoritative"),
        "classifier_version": _text(trust.get("classifier_version")),
        "mismatch_count": trust.get("mismatch_count"),
        "mismatch_classes": [_text(x) for x in _as_list(
            trust.get("mismatch_classes"))],
        "excluded_confirmation_count": trust.get("excluded_confirmation_count"),
        "clean": trust.get("clean"),
        "statement": _text(trust.get("statement"), 300),
    }


def _authorization_view(chain: dict[str, Any], auth_ids: list[str],
                        ) -> dict[str, Any]:
    raw = _as_dict(chain.get("authorization"))
    ids = [_text(x) for x in _as_list(raw.get("ids"))] or [
        _text(x) for x in auth_ids]
    satisfied = bool(raw.get("satisfied"))
    if satisfied and ids:
        display = "GRANTED"
    elif satisfied:
        # the gate counted authorization evidence, but no authorization
        # row is recorded — the analyst must see that gap, not a grant
        display = "SATISFIED WITHOUT A RECORDED GRANT"
    else:
        display = "NOT GRANTED"
    return {
        "satisfied": satisfied,
        "ids": ids,
        "source": _text(raw.get("source")),
        "display": display,
    }


def _integrity_view(block: Any) -> dict[str, Any]:
    """Advisor-independent slice of the EPIC11 analyst block.

    The legacy LLM advisory never reaches this view (§7): only the
    authoritative state, the gate reason, the missing evidence types and
    the evidence basis counters are carried.
    """
    block = _as_dict(block)
    if not block:
        return {"available": False, "rule_version": "", "recorded": False,
                "authoritative_state": "", "confirmation_status": "",
                "confirmed": False, "gate_reason": "", "stage_reached": None,
                "stage_label": "", "missing_evidence_types": [],
                "missing_evidence_reasons": [], "unique_observations": None,
                "duplicate_events": None, "matrix_counts": {},
                "matrix": [], "source": "",
                "note": "no claim/evidence contract recorded"}
    matrix = []
    for row in _as_list(block.get("claim_evidence_matrix")):
        if not isinstance(row, dict):
            continue
        matrix.append({
            "claim_type": _text(row.get("claim_type")),
            "statement": _text(row.get("statement"), 240),
            "status": _text(row.get("status")),
            "evidence_ids": [_text(x) for x in _as_list(row.get("evidence_ids"))],
        })
    # presentation tally of the authoritative matrix rows (no re-evaluation)
    counts = {"supported": 0, "missing": 0, "contradicted": 0, "total": len(matrix)}
    for row in matrix:
        status = row["status"].upper()
        if status.startswith("SUPPORT"):
            counts["supported"] += 1
        elif status.startswith("CONTRADICT"):
            counts["contradicted"] += 1
        else:
            counts["missing"] += 1
    basis = _as_dict(block.get("evidence_basis"))
    gate_reason = _text(block.get("gate_reason")) or _text(
        block.get("verification_gate_reason"))
    return {
        "available": bool(block.get("recorded")),
        "recorded": bool(block.get("recorded")),
        "rule_version": _text(block.get("rule_version")),
        "authoritative_state": _text(block.get("authoritative_state")),
        "confirmation_status": _text(block.get("confirmation_status")),
        "confirmed": bool(block.get("confirmed")),
        "gate_reason": gate_reason,
        "stage_reached": block.get("stage_reached"),
        "stage_label": _text(block.get("stage_label")),
        "missing_evidence_types": [
            _text(x) for x in _as_list(block.get("missing_evidence_types"))],
        "missing_evidence_reasons": [
            _text(x) for x in _as_list(block.get("missing_evidence_reasons"))],
        "unique_observations": (block.get("unique_observations")
                                if block.get("unique_observations")
                                is not None else basis.get("unique_observations")),
        "duplicate_events": (block.get("duplicate_events")
                             if block.get("duplicate_events") is not None
                             else basis.get("duplicate_events")),
        "matrix_counts": counts,
        "matrix": matrix,
        "source": _text(block.get("source"), 240),
        "note": ("claim/evidence contract recorded" if block.get("recorded")
                 else "no claim/evidence contract recorded for this record"),
    }


def banner(chain: dict[str, Any]) -> dict[str, Any]:
    """The ONLY analyst-facing state banner source (EPIC17 decision 1).

    The value is the authoritative EPIC12 badge verbatim — this module
    never computes a state of its own, so the UI cannot manufacture
    VERIFIED.
    """
    badge = _as_dict(chain.get("badge"))
    return {
        "state": _text(badge.get("state")) or "UNKNOWN",
        "label": _text(badge.get("label")),
        "optimistic": False if badge.get("optimistic") in (None, False) else True,
        "reason": _text(badge.get("reason")),
        "verdict": _text(chain.get("verdict")),
        "verdict_source": _text(chain.get("verdict_source")),
        "rule_version": _text(chain.get("rule_version")),
    }


def _chain_definition(vulnerability_class: str) -> Any:
    """The EPIC12 chain definition for a class (authoritative, read-only).

    Used to name each step's required evidence type(s); nothing is
    derived from it that the chain does not already declare.
    """
    if not vulnerability_class:
        return None
    try:
        from backend.research_agents.verification import chains as ch

        return ch.CHAINS.get(vulnerability_class.upper())
    except Exception:  # noqa: BLE001 - a missing definition shows no names
        return None


def chain_steps(chain: dict[str, Any]) -> list[dict[str, Any]]:
    """One entry per chain stage, with an honest step state.

    The projection supplies the evaluation (status, glyph, missing
    evidence, reason); the EPIC12 chain definition supplies the declared
    required evidence type(s) and whether the stage is
    confirmation-required.  A stage is never shown as passed unless the
    authoritative projection says SATISFIED, and a conditional stage
    that was not evaluated is NOT_PROVEN rather than pending.
    """
    definition = _chain_definition(_text(chain.get("vulnerability_class")))
    declared: dict[str, Any] = {}
    if definition is not None:
        for stage in getattr(definition, "stages", ()):
            declared[str(getattr(stage, "key", ""))] = stage
    steps: list[dict[str, Any]] = []
    for raw in _as_list(chain.get("stages")):
        row = _as_dict(raw)
        key = _text(row.get("key"))
        stage = declared.get(key)
        status = _text(row.get("status")).upper()
        satisfied = status == "SATISFIED"
        conditional = bool(getattr(stage, "conditional", False))
        required = [_text(x) for x in _as_list(
            getattr(stage, "required_evidence_types", ()))]
        if status in ("NOT_APPLICABLE", "UNAVAILABLE"):
            state = STEP_UNAVAILABLE
        elif satisfied:
            state = STEP_SATISFIED
        elif conditional:
            state = STEP_NOT_PROVEN
        else:
            state = STEP_PENDING
        steps.append({
            "key": key,
            "stage": " / ".join(required) or key.upper(),
            "label": _text(getattr(stage, "label", "")
                           or row.get("stage") or key),
            "stage_label": _text(getattr(stage, "stage_label", "")),
            "status": status,
            "glyph": _text(row.get("glyph")),
            "satisfied": satisfied,
            "conditional": conditional,
            "required_for_confirmation": bool(
                row.get("required_for_confirmation")
                if row.get("required_for_confirmation") is not None
                else getattr(stage, "required_for_confirmation", False)),
            "state": state,
            "required_evidence_types": required,
            "evidence_count": row.get("evidence_count") or len(
                _as_list(row.get("evidence"))),
            "missing": [_text(x) for x in _as_list(row.get("missing"))],
            "reason": _text(row.get("reason")),
            "not_applicable_reason": _text(row.get("not_applicable_reason")),
            "next_actions": [_text(x) for x in _as_list(
                row.get("next_actions"))],
        })
    return steps


def _capability_block(chain: dict[str, Any], deep: dict[str, Any],
                      cand: Any) -> dict[str, Any]:
    """Capability cells the analyst reads before trusting a gap."""
    deep = _as_dict(deep)
    dom = _as_dict(deep.get("dom"))
    flow = _text(dom.get("flow"))
    return {
        "vulnerability_class": (_text(chain.get("vulnerability_class"))
                                or _text(getattr(cand, "vulnerability_class", ""))),
        "chain_capability": _text(chain.get("capability")),
        "deep_state": _text(deep.get("state")),
        "deep_reason": _text(deep.get("reason")),
        "dom_flow": flow,
        "dom_display": {
            "": "NOT TESTED",
            FLOW_LINEAGE: "SOURCE_AND_SINK_LINEAGE",
            FLOW_SOURCE_ONLY: "SOURCE_ONLY",
        }.get(flow, flow or "NOT TESTED"),
        "dom_source": _text(dom.get("source")),
        "dom_sink": _text(dom.get("sink")),
        "execution": _text(deep.get("execution")) or "unavailable",
        "exploitability": _text(deep.get("exploitability")) or "not_established",
        "browser": _text(deep.get("browser")),
    }


def observation_vs_proof(steps: list[dict[str, Any]], capability: dict[str, Any],
                         ) -> dict[str, list[dict[str, Any]]]:
    """Split the chain into *observed* and *proven* (labels only).

    Observation = a stage that was satisfied by real evidence.
    Proof       = a confirmation-capable stage that was satisfied (or the
                  DOM lineage verdict, which is an EPIC15 proof-shaped
                  result).
    """
    observation: list[dict[str, Any]] = []
    proof: list[dict[str, Any]] = []
    for step in steps:
        entry = {
            "stage": step["stage"],
            "label": step["label"] or step["stage"],
            "state": step["state"],
            "satisfied": step["satisfied"],
            "conditional": step["conditional"],
            "required_for_confirmation": step.get("required_for_confirmation"),
        }
        if not step["satisfied"]:
            continue
        if _is_proof_step(step):
            proof.append(entry)
        else:
            observation.append(entry)
    dom_entry = {
        "stage": "DOM_SINK_LINEAGE",
        "label": "DOM sink reached by the parameter (served document)",
        "state": (STEP_SATISFIED
                  if capability.get("dom_flow") == FLOW_LINEAGE
                  else STEP_NOT_PROVEN),
        "satisfied": capability.get("dom_flow") == FLOW_LINEAGE,
        "detail": capability.get("dom_display", ""),
    }
    if dom_entry["satisfied"]:
        proof.append(dom_entry)
    else:
        observation.append({
            **dom_entry, "state": STEP_NOT_TESTED,
            "note": "no lineage-bound DOM flow is proven",
        })
    return {"observation": observation, "proof": proof}


def _is_proof_step(step: dict[str, Any]) -> bool:
    """Confirmation-capable step, by EPIC11 evidence type only."""
    types = set(step.get("required_evidence_types") or [])
    if types & set(CONFIRMATION_EVIDENCE):
        return True
    return bool(step.get("required_for_confirmation")) and bool(
        set(step.get("required_evidence_types") or []) &
        set(CONFIRMATION_EVIDENCE))


def _present(rows: list[dict[str, Any]], needle: str) -> bool:
    needle = needle.lower()
    for row in rows:
        signal = _text(row.get("signal") or row.get("evidence_class")).lower()
        where = _text(row.get("where")).lower()
        ctx = _text(row.get("context")).lower()
        if needle in signal or needle in where or needle in ctx:
            return True
    return False


def evidence_summary(chain: dict[str, Any], integrity: dict[str, Any],
                     mapped: list[dict[str, Any]], raw_rows: list[dict[str, Any]],
                     deep: dict[str, Any], capability: dict[str, Any],
                     ) -> dict[str, Any]:
    """Counts AND quality — a count never stands in for quality (§4)."""
    used = [r for r in _as_list(chain.get("evidence_used")) if isinstance(r, dict)]
    signals = [str(r.get("signal") or "") for r in raw_rows]
    raw_count = len(raw_rows)
    unique_count = integrity.get("unique_observations")
    duplicates = integrity.get("duplicate_events")
    return {
        "raw_observations": raw_count,
        "unique_observations": unique_count,
        "duplicate_events": duplicates,
        "evidence_items_used_by_chain": len(used),
        "distinct_signals": sorted({s for s in signals if s}),
        "reflection": ("YES" if _present(raw_rows, "reflection")
                       else "NO"),
        "context": _context_label(mapped, raw_rows),
        "dom_lineage": capability.get("dom_display") or "NOT TESTED",
        "payload_execution": ("OBSERVED"
                              if _present(raw_rows, "payload_execution")
                              or _stage_satisfied(chain, "PAYLOAD_EXECUTION")
                              else "NO"),
        "exploitability": ("ESTABLISHED"
                           if _stage_satisfied(chain,
                                               "EXPLOITABILITY_ESTABLISHED")
                           else "NOT ESTABLISHED"),
        "authorization": _authorization_view(
            chain, [])["display"],
        "negative_results": len(_as_list(chain.get("negative_results"))),
        "contradictions": len(_as_list(chain.get("contradictions"))),
        "counts_are_not_strength": True,
    }


def _context_label(mapped: list[dict[str, Any]],
                   raw_rows: list[dict[str, Any]]) -> str:
    for row in list(mapped) + list(raw_rows):
        if not isinstance(row, dict):
            continue
        signal = _text(row.get("signal") or row.get("evidence_class")).lower()
        if "context" not in signal:
            continue
        detail = _text(row.get("detail") or row.get("label") or row.get("where"))
        if detail:
            return detail
    for row in list(mapped) + list(raw_rows):
        if not isinstance(row, dict):
            continue
        signal = _text(row.get("signal") or row.get("evidence_class")).lower()
        if "reflection" in signal:
            detail = _text(row.get("detail") or row.get("label"))
            if detail:
                return detail
    return "NOT CLASSIFIED"


def _stage_satisfied(chain: dict[str, Any], evidence_type: str) -> bool:
    """Whether the stage requiring ``evidence_type`` was satisfied."""
    steps = chain_steps(chain)
    for step in steps:
        if evidence_type in (step.get("required_evidence_types") or []):
            return bool(step.get("satisfied"))
    return False


def analyst_decision(chain: dict[str, Any], integrity: dict[str, Any],
                     deep: dict[str, Any], steps: list[dict[str, Any]],
                     capability: dict[str, Any]) -> dict[str, Any]:
    """Can this be reported?  Deterministic interpretation, never a verdict."""
    reasons: list[str] = []
    badge = _as_dict(chain.get("badge"))
    state = _text(badge.get("state"))
    verdict = _text(chain.get("verdict"))
    blockers = [_text(x) for x in _as_list(chain.get("blockers"))]
    missing_types = [_text(x) for x in _as_list(chain.get("evidence_missing_types"))]
    if not missing_types:
        missing_types = [_text(x) for x in
                         _as_list(integrity.get("missing_evidence_types"))]
    unsatisfied = [s["stage"] for s in steps if not s["satisfied"]]
    auth = _as_dict(chain.get("authorization"))

    if state == "VERIFIED" and not blockers:
        # the badge already required: gate verdict VERIFIED, chain flagged
        # confirmed, every confirmation-required stage satisfied, no
        # evidence-type mismatch. This panel only interprets it.
        reasons = ["the authoritative verdict is VERIFIED and every "
                   "confirmation-required stage is satisfied",
                   "no evidence-type mismatch was recorded for this set"]
        if integrity.get("recorded"):
            reasons.append("the persisted EPIC11 claim/evidence contract "
                           "records the confirmation rules met")
        else:
            reasons.append("no persisted EPIC11 claim/evidence contract is "
                           "recorded; the verdict is derived from the rows")
        return {"can_report": DECISION_YES, "reasons": reasons,
                "missing_stages": unsatisfied, "note": DECISION_NOTE}
    if state in ("BLOCKED",) or blockers or not auth.get("satisfied"):
        if not auth.get("satisfied"):
            reasons.append("authorization unavailable for active verification")
        reasons.extend(blockers[:6])
        if not reasons:
            reasons.append("the verification chain is blocked")
        for stage in ("PAYLOAD_EXECUTION", "EXPLOITABILITY_ESTABLISHED"):
            if stage in unsatisfied:
                reasons.append(f"{stage.lower()} not established")
        return {"can_report": DECISION_NO, "reasons": reasons,
                "missing_stages": unsatisfied, "note": DECISION_NOTE}
    if state in ("NOT_CONFIRMED",):
        reasons = [f"missing {t}" for t in missing_types[:6]] or [
            "required evidence was not observed"]
        reasons.extend(f"{s.lower()} not established" for s in unsatisfied[:4])
        return {"can_report": DECISION_NO, "reasons": reasons,
                "missing_stages": unsatisfied, "note": DECISION_NOTE}
    reasons = [f"missing {t}" for t in missing_types[:6]] or [
        "the required evidence set is not complete"]
    reasons.extend(f"{s.lower()} not satisfied" for s in unsatisfied[:4])
    return {
        "can_report": DECISION_REVIEW if verdict else DECISION_REVIEW,
        "reasons": reasons + ["a human decides whether the chain should be "
                              "extended"],
        "missing_stages": unsatisfied, "note": DECISION_NOTE,
    }


def why_this_state(chain: dict[str, Any], integrity: dict[str, Any],
                   deep: dict[str, Any], steps: list[dict[str, Any]],
                   capability: dict[str, Any],
                   decision: dict[str, Any]) -> list[str]:
    """Deterministic 'why this state?' sentences (never LLM-generated)."""
    why: list[str] = []
    badge = _as_dict(chain.get("badge"))
    state = _text(badge.get("state")) or "UNKNOWN"
    verdict = _text(chain.get("verdict"))
    reason = _text(badge.get("reason"))
    why.append(f"state {state} comes from the authoritative chain projection"
               f" ({_text(chain.get('rule_version'))}); verdict "
               f"{verdict or 'none'} from "
               f"{_text(chain.get('verdict_source')) or 'no source'}"
               f"{f'; reason {reason}' if reason else ''}.")
    auth_view = _authorization_view(chain, [])
    why.append("authorization: " + auth_view["display"] + (
        " (" + ", ".join(auth_view["ids"][:4]) + ")" if auth_view["ids"] else "")
        + ("" if auth_view["satisfied"] else
           " — active verification is blocked, so no live stage can be "
           "attempted"))
    satisfied = [s["stage"] for s in steps if s["satisfied"]]
    unsatisfied = [s["stage"] for s in steps if not s["satisfied"]]
    why.append("stages satisfied: " + (", ".join(satisfied) or "none"))
    why.append("stages not proven: " + (", ".join(unsatisfied) or "none"))
    if capability.get("deep_state"):
        why.append(f"deep verification: {_text(capability.get('deep_state'))}"
                   f" ({_text(capability.get('deep_reason'))}); DOM flow "
                   f"{capability.get('dom_display')}")
    if deep.get("browser_blockers"):
        why.append("deep lane blockers: " + ", ".join(
            _text(x) for x in _as_list(deep.get("browser_blockers"))[:4]))
    integrity_state = _text(integrity.get("authoritative_state"))
    if integrity_state:
        why.append(f"EPIC11 claim/evidence state {integrity_state}"
                   f" (gate reason {_text(integrity.get('gate_reason')) or '—'})"
                   f" — confirmed={bool(integrity.get('confirmed'))}")
    else:
        why.append("no EPIC11 claim/evidence contract is recorded for this "
                   "candidate, so no claim is implied")
    if decision.get("can_report") == DECISION_NO:
        why.append("reportable: NO — " + "; ".join(
            _text(x) for x in _as_list(decision.get("reasons"))[:3]))
    elif decision.get("can_report") == DECISION_YES:
        why.append("reportable: YES — the authoritative gate recorded the "
                   "confirmation rules met")
    else:
        why.append("reportable: REVIEW — a human decides")
    return why


def strength_digest(view: dict[str, Any]) -> str:
    """Digest of the *strength* surface only.

    Counts of duplicated raw rows are deliberately excluded: duplicating
    evidence may raise ``raw_observations`` but must never move the
    badge, the proven stages, the unique observation count or the
    missing evidence set — and therefore never this digest.
    """
    chain = _as_dict(view.get("chain"))
    integrity = _as_dict(view.get("integrity"))
    summary = _as_dict(view.get("evidence_summary"))
    decision = _as_dict(view.get("decision"))
    payload = {
        "rule_version": view.get("rule_version"),
        "candidate_id": view.get("candidate_id"),
        "banner": _as_dict(view.get("banner")).get("state"),
        "verdict": chain.get("verdict"),
        "satisfied_count": chain.get("satisfied_count"),
        "proven": sorted(
            s.get("stage", "") for s in _as_list(
                _as_dict(view.get("observation_vs_proof")).get("proof"))
            if isinstance(s, dict)),
        "evidence_missing_types": sorted(chain.get("evidence_missing_types") or []),
        "authorization": summary.get("authorization"),
        "unique_observations": summary.get("unique_observations"),
        "integrity_state": integrity.get("authoritative_state"),
        "confirmed": integrity.get("confirmed"),
        "can_report": decision.get("can_report"),
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "RULE_VERSION",
    "STEP_SATISFIED", "STEP_NOT_PROVEN", "STEP_UNAVAILABLE",
    "STEP_NOT_TESTED", "STEP_PENDING",
    "DECISION_YES", "DECISION_NO", "DECISION_REVIEW", "DECISION_NOTE",
    "build", "banner", "chain_steps", "observation_vs_proof",
    "evidence_summary", "analyst_decision", "why_this_state",
    "strength_digest",
]
