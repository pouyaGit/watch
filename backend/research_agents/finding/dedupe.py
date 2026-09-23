"""Deterministic deduplication (Phase 5).

Repeated research must not create unlimited duplicate cases.  When a
duplicate is detected:

- the new evidence is PRESERVED (on the duplicate candidate),
- the duplicate LINKS to a canonically chosen candidate,
- source provenance is preserved,
- correlation metadata is updated,
- nothing is ever silently deleted,
- conflicting evidence is never merged.

Canonical selection is deterministic: earliest ``created_at`` wins; ties
break on lexicographically smallest ``candidate_id``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from backend.research_agents.finding.correlate import CorrelationResult
from backend.research_agents.finding.models import (
    DEDUPE_STATES,
    CandidateFinding,
    FindingStoreError,
    utcnow,
)


@dataclass
class DedupeResult:
    canonical_id: str
    duplicate_id: str
    relation: str
    reasons: list[str]
    preserved_evidence: list[str]
    action: str        # "linked_duplicate" | "kept_independent" | "already_canonical"


def canonical_of(group: Iterable[CandidateFinding]) -> CandidateFinding:
    """Deterministic canonical choice: oldest created, then lowest id."""
    items = sorted(group, key=lambda c: (c.created_at, c.candidate_id))
    if not items:
        raise FindingStoreError("canonical_of() requires a non-empty group")
    return items[0]


def deduplicate(store: Any,
                candidate: CandidateFinding,
                others: Iterable[CandidateFinding],
                results: list[CorrelationResult]) -> DedupeResult:
    """Link `candidate` to its canonical twin when the correlation says so.

    The store is only mutated when the relation is dup-class
    (SAME_CANDIDATE / POSSIBLE_DUPLICATE); everything else stays
    independent.  Evidence and provenance are never rewritten.
    """
    dup_class = [r for r in results
                 if r.relation in ("SAME_CANDIDATE", "POSSIBLE_DUPLICATE")
                 and candidate.candidate_id in (r.left_id, r.right_id)]
    if not dup_class:
        return DedupeResult(candidate.candidate_id, "",
                            "INDEPENDENT", ["no_dup_class_correlation"],
                            list(candidate.evidence_refs), "kept_independent")

    # Round-2 production fix: callers pass candidates captured from an
    # earlier snapshot (the executor's `existing` cache holds entries as
    # they were when first appended).  Rank and demotion must use
    # PERSISTED truth: a verification-bound twin must never be demoted,
    # and stale objects must never be written back over live rows (that
    # clobbered case back-links in production).
    def _fresh(c: CandidateFinding) -> CandidateFinding:
        return store.get_candidate(c.candidate_id) or c

    candidate = _fresh(candidate)
    pool = [_fresh(o) for o in others]
    by_id = {o.candidate_id: o for o in pool
             if o.candidate_id != candidate.candidate_id}
    pair = dup_class[0]
    other_id = (pair.right_id if pair.left_id == candidate.candidate_id
                else pair.left_id)
    other = by_id.get(other_id)
    if other is None:
        return DedupeResult(candidate.candidate_id, "", pair.relation,
                            pair.reasons, list(candidate.evidence_refs),
                            "kept_independent")

    # never dedupe against an already-DUPLICATE candidate: climb to canonical
    target = other
    hops = 0
    while target.duplicate_of and hops < 5:
        parent = by_id.get(target.duplicate_of)
        if parent is None:
            break
        target = parent
        hops += 1

    group = [candidate, target]

    # Deterministic, LIFECYCLE-AWARE canonical choice: a candidate already
    # bound to the verification pipeline (or otherwise past the dedupable
    # window) must never be demoted to DUPLICATE — fresh research can be
    # folded into it, not the other way around.  Ties keep the classic
    # oldest-created rule.  Only candidates in DEDUPE_STATES may ever be
    # mutated to DUPLICATE; every other state is preserved as history.
    def _rank(c: CandidateFinding) -> tuple:
        # tier 0 = already past the dedupable window (verification-bound
        # or terminal): PREFERRED canonical, never mutated.  tier 1 =
        # still dedupable: may be folded under a committed twin.
        tier = 0 if c.lifecycle_state not in DEDUPE_STATES else 1
        return (tier, c.created_at, c.candidate_id)

    winner = min(group, key=_rank)
    loser = (target if winner.candidate_id == candidate.candidate_id
             else candidate)
    if loser.lifecycle_state not in DEDUPE_STATES:
        # never mutate an in-flight/terminal candidate: record the
        # correlation metadata only, keep both rows truthful
        reasons_l = list(pair.reasons) + [
            f"loser_state:{loser.lifecycle_state}_not_dedupable"]
        store.record_correlation({
            "left_id": candidate.candidate_id,
            "right_id": target.candidate_id,
            "canonical_id": winner.candidate_id,
            "relation": pair.relation,
            "reasons": reasons_l,
            "provenance": pair.provenance,
        })
        return DedupeResult(winner.candidate_id, "", pair.relation,
                            reasons_l, list(candidate.evidence_refs),
                            "kept_independent")

    if winner.candidate_id == candidate.candidate_id:
        # existing candidate becomes the linked duplicate
        reasons = list(pair.reasons) + ["canonical_retained"]
        preserved = list(loser.evidence_refs or [])
        winner_meta = dict(candidate.correlation or {})
        winner_meta.update({
            "relation": pair.relation,
            "linked_duplicates": sorted(set(
                list(winner_meta.get("linked_duplicates") or [])
                + [loser.candidate_id])),
            "reasons": reasons,
            "rule_version": pair.provenance.get("rule_version", ""),
            "at": utcnow(),
        })
        store.record_correlation({
            "left_id": loser.candidate_id,
            "right_id": winner.candidate_id,
            "canonical_id": winner.candidate_id,
            "relation": pair.relation,
            "reasons": reasons,
            "provenance": pair.provenance,
        })
        if loser.lifecycle_state != "DUPLICATE":
            # preserve evidence + provenance; add link metadata only
            loser.duplicate_of = winner.candidate_id
            loser.canonical_id = winner.candidate_id
            loser.correlation = {**(loser.correlation or {}),
                                 "relation": pair.relation,
                                 "reasons": reasons,
                                 "canonical_id": winner.candidate_id,
                                 "at": utcnow()}
            loser.updated_at = utcnow()
            store.save_candidate(loser)          # never deleted
            store.transition_candidate(
                loser.candidate_id, "DUPLICATE",
                reason=f"duplicate_of:{winner.candidate_id}",
                detail=",".join(reasons[:6]))
        candidate.correlation = winner_meta
        store.save_candidate(candidate)
        return DedupeResult(winner.candidate_id, loser.candidate_id,
                            pair.relation, reasons, preserved,
                            "linked_duplicate")

    # the OTHER candidate is canonical: this candidate becomes the duplicate
    reasons = list(pair.reasons) + ["older_canonical:" + winner.candidate_id]
    preserved = list(candidate.evidence_refs or [])
    store.record_correlation({
        "left_id": candidate.candidate_id,
        "right_id": winner.candidate_id,
        "canonical_id": winner.candidate_id,
        "relation": pair.relation,
        "reasons": reasons,
        "provenance": pair.provenance,
    })
    # enrich canonical with linked metadata (evidence stays where it is)
    winner.correlation = {**(winner.correlation or {}),
                          "linked_duplicates": sorted(set(
                              list((winner.correlation or {}).get(
                                  "linked_duplicates") or [])
                              + [candidate.candidate_id])),
                          "at": utcnow()}
    store.save_candidate(winner)
    if candidate.lifecycle_state != "DUPLICATE":
        candidate.duplicate_of = winner.candidate_id
        candidate.canonical_id = winner.candidate_id
        candidate.correlation = {**(candidate.correlation or {}),
                                 "relation": pair.relation,
                                 "reasons": reasons,
                                 "canonical_id": winner.candidate_id,
                                 "at": utcnow()}
        candidate.updated_at = utcnow()
        store.save_candidate(candidate)
        store.transition_candidate(
            candidate.candidate_id, "DUPLICATE",
            reason=f"duplicate_of:{winner.candidate_id}",
            detail=",".join(reasons[:6]))
    return DedupeResult(winner.candidate_id, candidate.candidate_id,
                        pair.relation, reasons, preserved, "linked_duplicate")
