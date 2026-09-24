"""EPIC12 — the deterministic verification-chain engine.

The engine answers three questions, deterministically, from persisted evidence:

1. **Where is the chain?**  Every stage is ``SATISFIED``, ``MISSING``,
   ``NOT_TESTED``, ``CONTRADICTED`` or ``NOT_APPLICABLE`` — with the evidence
   ids that satisfy it and the evidence types still missing.
2. **What is next?**  The first stage that still needs evidence (or ``None``
   when the chain is contradicted / complete).
3. **What is the verdict?**  *Never computed here*: the EPIC11 claim evaluator
   and gate produce it (``VERIFIED`` / ``VERIFICATION_PENDING`` / ``BLOCKED`` /
   ``REJECTED``), and the engine only reports it.

Invariants (pinned by tests):

* a stage is never ``SATISFIED`` without a unique EPIC11 evidence item of the
  required type — missing stages are never inferred;
* duplicate observations never satisfy two different stages, and never count as
  more than one unique observation;
* a conditional stage is ruled ``NOT_APPLICABLE`` only by an explicit
  deterministic rule, and the reason is recorded — never silently satisfied;
* the verdict always comes from the EPIC11 gate over the raw rows, so a chain
  can never upgrade a claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from backend.research_agents.finding.integrity import claims as cl
from backend.research_agents.finding.integrity import contracts as ct
from backend.research_agents.finding.integrity import gate as ig
from backend.research_agents.finding.integrity import taxonomy as tx
from backend.research_agents.verification import chains as ch

CHAIN_ENGINE_RULE_VERSION = "epic12-chain-engine-1"

#: Tokens that carry no targeting information when matching a negative
#: observation to the stage it contradicts.
_GENERIC_TOKENS: frozenset[str] = frozenset(
    {"observed", "established", "identified", "sent", "url", "output", "input",
     "not", "the", "and", "value"})

#: Per evidence type, the tokens that identify a stage-targeting negative.
_TYPE_TOKENS: dict[str, tuple[str, ...]] = {
    tx.PARAMETER_OBSERVED: ("parameter", "param"),
    tx.URL_OBSERVED: ("url",),
    tx.REQUEST_OBSERVED: ("request",),
    tx.RESPONSE_OBSERVED: ("response",),
    tx.CONTROLLED_INPUT_SENT: ("controlled", "marker"),
    tx.REFLECTION_OBSERVED: ("reflection", "reflected", "marker"),
    tx.OUTPUT_CONTEXT_IDENTIFIED: ("context",),
    tx.DOM_SINK_IDENTIFIED: ("sink", "dom"),
    tx.PAYLOAD_EXECUTION: ("payload", "execution", "executed"),
    tx.EXPLOITABILITY_ESTABLISHED: ("exploitability", "exploit"),
    tx.IMPACT_ESTABLISHED: ("impact",),
}

VERDICT_SOURCE = "epic11_integrity_gate"


@dataclass(frozen=True)
class StageState:
    """One stage's deterministic state."""

    key: str
    label: str
    order: int
    stage: int
    claim_type: str
    status: str
    required_evidence_types: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    missing_types: tuple[str, ...] = ()
    reason: str = ""
    not_applicable_reason: str = ""
    conditional: bool = False
    required_for_confirmation: bool = False
    allowed_actions: tuple[str, ...] = ()

    @property
    def satisfied(self) -> bool:
        return self.status == ch.STAGE_SATISFIED

    @property
    def glyph(self) -> str:
        """Analyst-facing glyph (§19): tick, cross, question or n/a."""
        return {
            ch.STAGE_SATISFIED: "\u2713",
            ch.STAGE_CONTRADICTED: "\u2717",
            ch.STAGE_NOT_APPLICABLE: "n/a",
        }.get(self.status, "?")

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "order": self.order,
            "stage": self.stage,
            "stage_label": tx.STAGE_LABELS.get(self.stage, "auxiliary"),
            "claim_type": self.claim_type,
            "status": self.status,
            "glyph": self.glyph,
            "satisfied": self.satisfied,
            "required_evidence_types": list(self.required_evidence_types),
            "evidence_ids": list(self.evidence_ids),
            "missing_types": list(self.missing_types),
            "reason": self.reason,
            "not_applicable_reason": self.not_applicable_reason,
            "conditional": self.conditional,
            "required_for_confirmation": self.required_for_confirmation,
            "allowed_actions": list(self.allowed_actions),
        }


@dataclass(frozen=True)
class ChainState:
    """The full deterministic chain state for one candidate's evidence."""

    vulnerability_class: str
    chain_id: str
    contract_id: str
    capability: str
    stages: tuple[StageState, ...] = ()
    satisfied_count: int = 0
    stage_count: int = 0
    furthest_stage: int = 0
    next_stage: str = ""
    next_stage_label: str = ""
    next_stage_missing_types: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    missing_evidence_types: tuple[str, ...] = ()
    negative_evidence: tuple[dict[str, Any], ...] = ()
    contradictions: tuple[dict[str, Any], ...] = ()
    unsupported_claims: tuple[str, ...] = ()
    verdict: str = ""
    verdict_reason: str = ""
    verdict_source: str = VERDICT_SOURCE
    blockers: tuple[str, ...] = ()
    why_not_confirmed: tuple[str, ...] = ()
    authorization_satisfied: bool = False
    chain_terminated: bool = False
    termination_reason: str = ""
    #: Non-empty when the AUTHORITATIVE verdict cannot be explained by the
    #: chain's own evidence view (e.g. the gate counted a row the chain view
    #: refuses to read as evidence).  A divergence is never smoothed over: the
    #: projection turns it into an INCONSISTENT badge, never a green one.
    divergence: tuple[str, ...] = ()
    inadmissible_row_count: int = 0
    rule_version: str = CHAIN_ENGINE_RULE_VERSION

    @property
    def confirmed(self) -> bool:
        return self.verdict == ig.VERIFIED

    @property
    def blocked(self) -> bool:
        return self.verdict == ig.BLOCKED

    @property
    def pending(self) -> bool:
        return self.verdict == ig.VERIFICATION_PENDING

    @property
    def rejected(self) -> bool:
        return self.verdict == ig.REJECTED

    def stage(self, key: str) -> StageState | None:
        for item in self.stages:
            if item.key == key:
                return item
        return None

    @property
    def unsatisfied_stages(self) -> tuple[StageState, ...]:
        return tuple(s for s in self.stages
                     if s.status in (ch.STAGE_MISSING, ch.STAGE_NOT_TESTED)
                     and not s.not_applicable_reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "rule_version": self.rule_version,
            "vulnerability_class": self.vulnerability_class,
            "contract_id": self.contract_id,
            "capability": self.capability,
            "stages": [s.to_dict() for s in self.stages],
            "stage_count": self.stage_count,
            "satisfied_count": self.satisfied_count,
            "furthest_stage": self.furthest_stage,
            "next_stage": self.next_stage,
            "next_stage_label": self.next_stage_label,
            "next_stage_missing_types": list(self.next_stage_missing_types),
            "missing_evidence": list(self.missing_evidence),
            "missing_evidence_types": list(self.missing_evidence_types),
            "negative_evidence": [dict(r) for r in self.negative_evidence],
            "contradictions": [dict(r) for r in self.contradictions],
            "unsupported_claims": list(self.unsupported_claims),
            "verdict": self.verdict,
            "verdict_reason": self.verdict_reason,
            "verdict_source": self.verdict_source,
            "blockers": list(self.blockers),
            "why_not_confirmed": list(self.why_not_confirmed),
            "divergence": list(self.divergence),
            "inadmissible_row_count": self.inadmissible_row_count,
            "authorization_satisfied": self.authorization_satisfied,
            "chain_terminated": self.chain_terminated,
            "termination_reason": self.termination_reason,
            "confirmed": self.confirmed,
        }


def stage_tokens(evidence_type: str) -> tuple[str, ...]:
    """Deterministic targeting tokens for one evidence type."""
    declared = _TYPE_TOKENS.get(evidence_type)
    if declared:
        return declared
    tokens = [t for t in str(evidence_type or "").lower().split("_")
              if t and t not in _GENERIC_TOKENS]
    return tuple(tokens)


def negative_targets_stage(signal: str, evidence_type: str) -> bool:
    """Whether a negative/NOT_TESTED observation contradicts a stage.

    Deterministic: the signal must contain one of the stage's targeting tokens.
    """
    text = str(signal or "").lower()
    return any(token in text for token in stage_tokens(evidence_type))


def _items_for_stage(unique: list[tx.EvidenceItem],
                     stage: ch.ChainStage) -> list[tx.EvidenceItem]:
    wanted = set(stage.required_evidence_types)
    return [i for i in unique
            if i.evidence_type in wanted and i.is_stage_evidence]


def _negative_for_stage(all_items: list[tx.EvidenceItem],
                        stage: ch.ChainStage) -> list[tx.EvidenceItem]:
    out: list[tx.EvidenceItem] = []
    for item in all_items:
        if item.evidence_type != tx.NEGATIVE_EVIDENCE:
            continue
        if any(negative_targets_stage(item.raw_signal or item.raw_type, t)
               for t in stage.required_evidence_types):
            out.append(item)
    return out


def _authorization_satisfied(
    decision: ig.IntegrityDecision,
    authorization: Any,
    unique: list[tx.EvidenceItem],
    evidence_confirmed_authorization: bool,
) -> bool:
    """Whether EPIC11 considered authorization satisfied for this evidence.

    The gate is authoritative: its ``verification_not_authorized`` blocker means
    *not satisfied*, and a ``VERIFIED`` verdict is impossible without it.  Only
    when the gate says neither (an early-stage pending candidate) do we mirror
    EPIC11's own predicate from ``contracts.evaluate_contract`` over exactly the
    same inputs — a pin test asserts the two agree wherever the gate speaks.
    """
    if ig.BLOCKER_MISSING_AUTHORIZATION in tuple(decision.blockers):
        return False
    if decision.authoritative_state == ig.VERIFIED:
        return True
    if evidence_confirmed_authorization:
        return True
    if authorization is not None and (getattr(authorization, "confirmed", False)
                                      or getattr(authorization, "present", False)):
        return True
    return any(i.evidence_type == tx.AUTHORIZATION_CONFIRMED for i in unique)


def _dom_evidence_present(unique: list[tx.EvidenceItem]) -> bool:
    return any(i.evidence_type == tx.DOM_SINK_IDENTIFIED for i in unique)


#: Rows that record model/advisory output are NEVER evidence, whatever signal
#: they carry (hard principle: LLM output is never authoritative evidence).
#: EPIC11's classifier reads the *signal*, so a mislabelled advisory row could
#: otherwise classify as a real observation.  The chain view refuses such rows;
#: if the authoritative gate nevertheless reaches a different verdict, the
#: projection reports the divergence as INCONSISTENT rather than smoothing it.
INADMISSIBLE_ROW_TYPES: frozenset[str] = frozenset({
    "llm_insight", "llm_output", "llm_response", "model_output", "advisor",
    "advisor_recommendation", "advisor_output", "prior_recommendation",
    "recommendation", "prose", "narrative", "summary",
})


def _row_type(row: Any) -> str:
    if not isinstance(row, Mapping):
        return ""
    return str(row.get("type") or "").strip().lower()


def inadmissible_rows(rows: Iterable[Mapping[str, Any]]) -> list[Any]:
    """The rows the chain view refuses to read as evidence."""
    return [r for r in (rows or ())
            if isinstance(r, Mapping) and _row_type(r) in INADMISSIBLE_ROW_TYPES]


def admissible_rows(rows: Iterable[Mapping[str, Any]]) -> list[Any]:
    """Drop model/advisory rows and non-rows; keep every real observation."""
    return [r for r in (rows or ())
            if isinstance(r, Mapping) and _row_type(r) not in INADMISSIBLE_ROW_TYPES]


def evaluate_chain(
    vulnerability_class: Any,
    rows: Iterable[dict[str, Any]],
    *,
    authorization: Any = None,
    chain: ch.VerificationChain | None = None,
    runtime_gate_reason: str = "",
    runtime_gate_claimed_case: bool = False,
    evidence_confirmed_authorization: bool = False,
) -> ChainState:
    """Evaluate a verification chain over persisted evidence rows.

    ``rows`` are the raw persisted evidence rows for the candidate (and its
    verification job).  The verdict is produced by the EPIC11 gate over exactly
    those rows.
    """
    raw_rows = list(rows or [])
    normalized = ch.normalize_class(vulnerability_class)
    chain = chain or ch.chain_for(normalized)

    # ---- authoritative EPIC11 evaluation (never re-implemented here) ------
    evaluation = cl.evaluate_rows(
        normalized, raw_rows, authorization=authorization,
        evidence_confirmed_authorization=evidence_confirmed_authorization)
    decision = ig.decide(
        evaluation, runtime_gate_reason=runtime_gate_reason,
        runtime_gate_claimed_case=runtime_gate_claimed_case)

    inadmissible = inadmissible_rows(raw_rows)
    items = tx.classify_rows(admissible_rows(raw_rows))
    unique = tx.unique_items(items)
    by_type = tx.items_by_type(unique)

    if chain is None:
        # No chain declared: report the contract outcome honestly and say so.
        return ChainState(
            vulnerability_class=normalized,
            chain_id=f"chain-{normalized.lower()}",
            contract_id=evaluation.contract_id,
            capability=ch.CAPABILITY_NOT_IMPLEMENTED,
            stages=(),
            stage_count=0,
            missing_evidence=tuple(evaluation.missing_evidence),
            missing_evidence_types=tuple(evaluation.missing_evidence_types),
            negative_evidence=tuple(evaluation.negative_evidence),
            contradictions=tuple(evaluation.contradictions),
            unsupported_claims=tuple(evaluation.unsupported_claims),
            verdict=decision.authoritative_state,
            verdict_reason=decision.gate_reason,
            blockers=tuple(decision.blockers),
            authorization_satisfied=_authorization_satisfied(
                decision, authorization, unique,
                evidence_confirmed_authorization),
            why_not_confirmed=tuple(
                list(decision.missing_reasons)
                or list(decision.missing_evidence)
                or [decision.gate_reason]),
        )

    # ---- stage-by-stage state --------------------------------------------
    stages: list[StageState] = []
    for stage in chain.ordered():
        stage_items = _items_for_stage(unique, stage)
        negatives = _negative_for_stage(items, stage)
        not_tested = [n for n in negatives if n.negative_kind == tx.NOT_TESTED]
        contradicted = [n for n in negatives
                        if n.negative_kind != tx.NOT_TESTED]
        missing_types = tuple(
            group[0] for group in stage.required_groups
            if not any(t in by_type for t in group))
        satisfied = not missing_types

        status = ch.STAGE_SATISFIED if satisfied else ch.STAGE_MISSING
        reason = ""
        na_reason = ""
        if satisfied:
            reason = "evidence_observed"
        elif contradicted:
            status = ch.STAGE_CONTRADICTED
            reason = "contradicting_evidence"
        elif not_tested and not stage_items:
            status = ch.STAGE_NOT_TESTED
            reason = "verification_not_performed"
        elif (stage.conditional and not _dom_evidence_present(unique)
              and any(s.key == "context" and s.satisfied
                      for s in stages)):
            # explicit, recorded rule — never a silent pass
            status = ch.STAGE_NOT_APPLICABLE
            na_reason = ch.NOT_APPLICABLE_REFLECTED_ONLY
            reason = "conditional_stage_not_applicable"

        stages.append(StageState(
            key=stage.key, label=stage.label, order=stage.order,
            stage=stage.stage, claim_type=stage.claim_type, status=status,
            required_evidence_types=stage.required_evidence_types,
            evidence_ids=tuple(i.evidence_id for i in stage_items),
            missing_types=missing_types, reason=reason,
            not_applicable_reason=na_reason, conditional=stage.conditional,
            required_for_confirmation=stage.required_for_confirmation,
            allowed_actions=stage.allowed_actions))

    satisfied_count = sum(1 for s in stages if s.satisfied)
    furthest = max((s.stage for s in stages if s.satisfied), default=0)
    contradicted_required = [s for s in stages
                             if s.status == ch.STAGE_CONTRADICTED
                             and s.required_for_confirmation]
    next_stage = next(
        (s for s in stages
         if s.required_for_confirmation and not s.satisfied
         and s.status != ch.STAGE_NOT_APPLICABLE), None)

    terminated = bool(contradicted_required) or decision.authoritative_state == ig.REJECTED
    termination_reason = ""
    if contradicted_required:
        termination_reason = "required_stage_contradicted"
    elif decision.authoritative_state == ig.REJECTED:
        termination_reason = "evidence_contradicted"
    elif decision.authoritative_state == ig.VERIFIED:
        terminated = True
        termination_reason = "confirmed"

    why: list[str] = []
    if not decision.authoritative_state == ig.VERIFIED:
        for stage in stages:
            if stage.status == ch.STAGE_CONTRADICTED:
                why.append(f"{stage.key}:{stage.reason}")
            elif stage.status == ch.STAGE_NOT_TESTED:
                why.append(f"{stage.key}:not_tested")
            elif stage.status == ch.STAGE_MISSING and stage.required_for_confirmation:
                why.append(f"{stage.key}:missing_{'_or_'.join(stage.missing_types)}")
        why.extend(decision.missing_reasons or decision.missing_evidence)

    return ChainState(
        vulnerability_class=normalized,
        chain_id=chain.chain_id,
        contract_id=chain.contract_id,
        capability=chain.capability,
        stages=tuple(stages),
        satisfied_count=satisfied_count,
        stage_count=len(stages),
        furthest_stage=furthest,
        next_stage=next_stage.key if next_stage else "",
        next_stage_label=next_stage.label if next_stage else "",
        next_stage_missing_types=(next_stage.missing_types
                                  if next_stage else ()),
        missing_evidence=tuple(evaluation.missing_evidence),
        missing_evidence_types=tuple(evaluation.missing_evidence_types),
        negative_evidence=tuple(evaluation.negative_evidence),
        contradictions=tuple(evaluation.contradictions),
        unsupported_claims=tuple(evaluation.unsupported_claims),
        verdict=decision.authoritative_state,
        verdict_reason=decision.gate_reason,
        blockers=tuple(decision.blockers),
        why_not_confirmed=tuple(dict.fromkeys(why)),
        authorization_satisfied=_authorization_satisfied(
            decision, authorization, unique, evidence_confirmed_authorization),
        chain_terminated=terminated,
        termination_reason=termination_reason,
        divergence=tuple(_divergence(
            decision.authoritative_state, stages, len(inadmissible),
            _row_type_mismatches(rows))),
        inadmissible_row_count=len(inadmissible),
    )


def _row_type_mismatches(rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """Rows whose declared evidence type disagrees with their own signal.

    The EPIC11 gate resolves a row's class from its signal, but honours a
    row-supplied ``evidence_type`` when that type is inside the closed set.
    A row whose signal says one thing and whose type says another is therefore
    *admissible* to the gate.  EPIC13 reports every such row as a divergence:
    the chain never presents it as a clean piece of evidence, and a verdict
    that leans on one is visibly inconsistent instead of silently trusted.

    This detects; it does not decide.  The gate remains authoritative.
    """
    out: list[str] = []
    for row in rows or []:
        try:
            declared = str(row.get("evidence_type") or "").strip().upper()
            signal = str(row.get("signal") or "").strip()
        except AttributeError:  # not a mapping at all
            continue
        if not declared or not signal:
            continue
        mapped = str(tx.SIGNAL_TO_TYPE.get(signal) or "").strip().upper()
        if mapped and mapped != declared:
            out.append(f"evidence_type_mismatch:{signal}->{declared}")
    return list(dict.fromkeys(out))


def _divergence(verdict: str, stages: Iterable[StageState],
                inadmissible_count: int,
                mismatches: Iterable[str] = ()) -> list[str]:
    """Explain any gap between the authoritative verdict and the chain view."""
    out: list[str] = list(mismatches)
    if verdict != ig.VERIFIED:
        return out
    unmet = [s.key for s in stages
             if s.required_for_confirmation
             and s.status not in (ch.STAGE_SATISFIED, ch.STAGE_NOT_APPLICABLE)]
    if unmet:
        out.append("verified_without_required_stage:" + ",".join(unmet))
        if inadmissible_count:
            out.append(
                "authoritative_verdict_reads_"
                f"{inadmissible_count}_inadmissible_row(s)")
    return out


def chain_matrix(state: ChainState) -> list[dict[str, Any]]:
    """Analyst-facing chain matrix (§19): stage, status, evidence, gaps."""
    out: list[dict[str, Any]] = []
    for stage in state.stages:
        out.append({
            "order": stage.order,
            "stage": stage.label,
            "key": stage.key,
            "status": stage.status,
            "glyph": stage.glyph,
            "evidence": list(stage.evidence_ids[:5]),
            "evidence_count": len(stage.evidence_ids),
            "missing": list(stage.missing_types),
            "reason": stage.reason,
            "not_applicable_reason": stage.not_applicable_reason,
            "required_for_confirmation": stage.required_for_confirmation,
            "next_actions": (list(stage.allowed_actions)
                             if stage.status in (ch.STAGE_MISSING,
                                                 ch.STAGE_NOT_TESTED) else []),
        })
    return out


__all__ = [
    "_row_type_mismatches",
    "CHAIN_ENGINE_RULE_VERSION", "VERDICT_SOURCE", "ChainState", "StageState",
    "chain_matrix", "evaluate_chain", "negative_targets_stage", "stage_tokens",
]
