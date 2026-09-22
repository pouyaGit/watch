"""Deterministic missing-evidence engine (Phase 2).

Given the authoritative research state — observed rows, deterministic
analysis, capability evidence requirements, prior research, specialist
and scope — produce the list of evidence the hunt still needs, each item
with priority, reason, the hypothesis it affects, a HEURISTIC expected
information gain (never claimed exact), the authorization requirements
and the registry observation types that could produce it.

The engine is deterministic: same inputs -> same items, same order.
The LLM may suggest, but items here come only from real state.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.research_agents.hunt.registry import (
    CATEGORY_SIGNAL_TYPES,
    REGISTRY,
)

MISSING_EVIDENCE_RULE_VERSION = "hunt-missing-evidence-v1"

# Priority 1 (highest) .. 5 (lowest).
PRIORITY_CRITICAL = 1
PRIORITY_HIGH = 2
PRIORITY_MEDIUM = 3
PRIORITY_LOW = 4


@dataclass(frozen=True)
class MissingEvidenceItem:
    item_id: str
    item_code: str
    priority: int
    reason: str
    hypothesis_affected: str
    expected_information_gain: float   # heuristic, 0..1
    gain_label: str                    # always "heuristic"
    authorization_requirements: tuple[str, ...]
    observation_type_suggestions: tuple[str, ...]
    satisfiable: bool
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "item_code": self.item_code,
            "priority": int(self.priority),
            "reason": self.reason,
            "hypothesis_affected": self.hypothesis_affected,
            "expected_information_gain":
                round(float(self.expected_information_gain), 4),
            "gain_label": self.gain_label,
            "authorization_requirements": list(self.authorization_requirements),
            "observation_type_suggestions":
                list(self.observation_type_suggestions),
            "satisfiable": bool(self.satisfiable),
            "provenance": dict(self.provenance),
        }


def _item_id(code: str, hypothesis: str) -> str:
    blob = f"{code}|{hypothesis}"
    return "mev-" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


def _auth_reqs(scope_ref: str) -> tuple[str, ...]:
    return (scope_ref or "watch:scope", "capability_observation_allowlist")


def _gain(n_required_satisfied: int, n_total_required: int,
          priority: int) -> float:
    """Heuristic information gain: coverage-weighted priority value.

    Labelled 'heuristic' everywhere it surfaces — this is a transparent
    deterministic score, not a computed Shannon information gain.
    """
    coverage = (n_required_satisfied / n_total_required
                if n_total_required else 0.0)
    priority_value = (6 - max(1, min(5, priority))) / 5.0
    return round(min(1.0, 0.6 * coverage + 0.4 * priority_value), 4)


def compute_missing_evidence(
    *,
    capability: Any,
    scope_ref: str,
    analysis: dict[str, Any],
    observed_types: Iterable[str],
    knowledge_ids: Iterable[str],
    evidence_requirement_types: Iterable[str] | None = None,
    prior_research: Iterable[Any] = (),
    hypothesis: str = "",
    unsatisfiable_allowed: Iterable[str] = (),
) -> list[MissingEvidenceItem]:
    """Deterministic missing-evidence computation.

    ``observed_types``   observation types already read this objective.
    ``unsatisfiable_allowed`` allowed-but-consumed types (cannot be read
    again productively) — items only suggesting those are unsatisfiable.
    """
    category = str(getattr(capability, "category", "") or "")
    allowed = tuple(str(t) for t in
                    (getattr(capability, "allowed_observation_types", ()) or ()))
    seen = {str(t) for t in observed_types}
    unread = tuple(t for t in allowed if t not in seen)
    consumed = set(seen) | {str(t) for t in unsatisfiable_allowed}

    req = getattr(capability, "evidence_requirements", None)
    required_types = tuple(
        evidence_requirement_types if evidence_requirement_types is not None
        else (getattr(req, "required_types", ()) or ()))
    min_refs = int(getattr(req, "min_evidence_refs", 2) or 2)
    need_high = bool(getattr(req, "require_high_confidence", True))

    candidates = list(analysis.get("evidence_candidates") or [])
    present_types = {str(c.get("type") or "") for c in candidates}
    observation_refs = {str(c.get("observation_ref") or "")
                        for c in candidates
                        if str(c.get("type") or "") == "observation"}
    confidence = str(analysis.get("confidence") or "insufficient")
    blockers = [str(b) for b in (analysis.get("blockers") or [])]
    signals = [str(s) for s in (analysis.get("signals") or [])]
    hyp = (hypothesis
           or _first_hypothesis(analysis)
           or f"{category} hypothesis over {scope_ref}")

    items: list[MissingEvidenceItem] = []

    def suggest(*wanted: str) -> tuple[str, ...]:
        """Registry-valid, capability-allowed, unread types preferred."""
        out = [t for t in wanted if t in REGISTRY and t in allowed]
        unread_first = tuple(t for t in out if t not in seen)
        rest = tuple(t for t in out if t in seen)
        return unread_first + rest

    # 1. required evidence types absent from present candidates
    n_req = max(1, len(required_types))
    for rtype in required_types:
        if rtype in present_types:
            continue
        if rtype == "knowledge":
            opts = suggest("kb-rows")
            code = "missing_knowledge_evidence"
            prio = PRIORITY_HIGH
        else:
            opts = suggest(*CATEGORY_SIGNAL_TYPES.get(category, ()),
                           *allowed)
            code = f"missing_{rtype}_evidence"
            prio = PRIORITY_CRITICAL
        items.append(MissingEvidenceItem(
            item_id=_item_id(code, hyp),
            item_code=code,
            priority=prio,
            reason=(f"required evidence type '{rtype}' is not present in "
                    f"the current candidates "
                    f"({len(observation_refs)} observation ref(s) recorded)"),
            hypothesis_affected=hyp,
            expected_information_gain=_gain(1, n_req, prio),
            gain_label="heuristic",
            authorization_requirements=_auth_reqs(scope_ref),
            observation_type_suggestions=opts,
            satisfiable=any(t not in consumed for t in opts),
            provenance={"source": "capability_evidence_requirements",
                        "scope_ref": scope_ref},
        ))

    # 2. confidence below the capability's required gate confidence
    if need_high and confidence != "high":
        code = "confidence_below_required_high"
        prio = PRIORITY_HIGH
        opts = suggest(*CATEGORY_SIGNAL_TYPES.get(category, ()), *allowed)
        items.append(MissingEvidenceItem(
            item_id=_item_id(code, hyp),
            item_code=code,
            priority=prio,
            reason=(f"deterministic confidence is '{confidence}'; the gate "
                    f"requires 'high' (>=2 independent observation refs with "
                    f"the category signal)"),
            hypothesis_affected=hyp,
            expected_information_gain=_gain(1, n_req, prio),
            gain_label="heuristic",
            authorization_requirements=_auth_reqs(scope_ref),
            observation_type_suggestions=opts,
            satisfiable=any(t not in consumed for t in opts),
            provenance={"source": "gate_confidence_rule",
                        "scope_ref": scope_ref},
        ))

    # 3. observation-count gap against min_evidence_refs
    obs_needed = max(0, min_refs - len(observation_refs))
    if obs_needed > 0:
        code = "observation_evidence_count_gap"
        prio = PRIORITY_MEDIUM
        opts = suggest(*allowed)
        items.append(MissingEvidenceItem(
            item_id=_item_id(code, hyp),
            item_code=code,
            priority=prio,
            reason=(f"{obs_needed} more independent authorized observation "
                    f"ref(s) needed to reach min_evidence_refs={min_refs}"),
            hypothesis_affected=hyp,
            expected_information_gain=_gain(1, n_req, prio),
            gain_label="heuristic",
            authorization_requirements=_auth_reqs(scope_ref),
            observation_type_suggestions=opts,
            satisfiable=any(t not in consumed for t in opts),
            provenance={"source": "min_evidence_refs",
                        "scope_ref": scope_ref},
        ))

    # 4. no category signal anywhere yet
    if "no_category_signal_in_authorized_observations" in blockers \
            or not signals:
        code = "category_signal_absent"
        prio = PRIORITY_CRITICAL
        opts = suggest(*CATEGORY_SIGNAL_TYPES.get(category, ()), *allowed)
        items.append(MissingEvidenceItem(
            item_id=_item_id(code, hyp),
            item_code=code,
            priority=prio,
            reason=(f"no {category} structural signal appears in the "
                    f"observed rows so far"),
            hypothesis_affected=hyp,
            expected_information_gain=_gain(2, n_req, prio),
            gain_label="heuristic",
            authorization_requirements=_auth_reqs(scope_ref),
            observation_type_suggestions=opts,
            satisfiable=any(t not in consumed for t in opts),
            provenance={"source": "deterministic_analysis_blocker",
                        "scope_ref": scope_ref},
        ))

    # 5. category-specific structural signals
    if category == "CVE_RESEARCH" and "technology_signal" not in signals:
        code = "technology_signal_missing"
        prio = PRIORITY_CRITICAL
        opts = suggest("http-rows")
        items.append(MissingEvidenceItem(
            item_id=_item_id(code, hyp),
            item_code=code,
            priority=prio,
            reason=("no stored HTTP row with a technology signal has been "
                    "observed yet — CVE correlation needs at least one "
                    "observed technology"),
            hypothesis_affected=hyp,
            expected_information_gain=_gain(2, n_req, prio),
            gain_label="heuristic",
            authorization_requirements=_auth_reqs(scope_ref),
            observation_type_suggestions=opts,
            satisfiable=any(t not in consumed for t in opts),
            provenance={"source": "cve_capability_strategy",
                        "scope_ref": scope_ref},
        ))
        if signals and "technology_signal" in signals:
            pass  # handled by item 6 below when technology observed
    if category == "CVE_RESEARCH" and "technology_signal" in signals:
        # technology observed but no knowledge correlation yet
        if "knowledge_reference" not in {str(c.get("signal") or "")
                                         for c in candidates}:
            code = "knowledge_correlation_missing"
            prio = PRIORITY_HIGH
            opts = suggest("kb-rows")
            tech_tokens = _tech_tokens(analysis)
            items.append(MissingEvidenceItem(
                item_id=_item_id(code, hyp),
                item_code=code,
                priority=prio,
                reason=("technology signal observed but no knowledge-base "
                        "document correlates with it yet"),
                hypothesis_affected=hyp,
                expected_information_gain=_gain(2, n_req, prio),
                gain_label="heuristic",
                authorization_requirements=_auth_reqs(scope_ref),
                observation_type_suggestions=opts,
                satisfiable=any(t not in consumed for t in opts),
                provenance={"source": "cve_correlation_rule",
                            "query_hint_tokens": tech_tokens[:4],
                            "scope_ref": scope_ref},
            ))

    if category == "XSS":
        has_param_signal = any(s.startswith("xss_parameter_inventory")
                               for s in signals)
        if not has_param_signal:
            code = "reflection_capable_parameter_inventory_missing"
            prio = PRIORITY_HIGH
            opts = suggest("parameter-rows", "url-rows", "endpoint-rows")
            items.append(MissingEvidenceItem(
                item_id=_item_id(code, hyp),
                item_code=code,
                priority=prio,
                reason=("no stored parameter inventory has been observed "
                        "for the scope (reflection-capable inputs unknown)"),
                hypothesis_affected=hyp,
                expected_information_gain=_gain(2, n_req, prio),
                gain_label="heuristic",
                authorization_requirements=_auth_reqs(scope_ref),
                observation_type_suggestions=opts,
                satisfiable=any(t not in consumed for t in opts),
                provenance={"source": "xss_capability_strategy",
                            "scope_ref": scope_ref},
            ))

    # 6. allowed observation types never read (coverage debt)
    for otype in unread:
        spec = REGISTRY.get(otype)
        if spec is None:
            continue
        code = f"observation_type_unread:{otype}"
        prio = PRIORITY_LOW
        items.append(MissingEvidenceItem(
            item_id=_item_id(code, hyp),
            item_code=code,
            priority=prio,
            reason=(f"allowed observation type '{otype}' has not been read "
                    f"for this objective ({spec.description[:80]})"),
            hypothesis_affected=hyp,
            expected_information_gain=_gain(1, n_req + len(unread), prio),
            gain_label="heuristic",
            authorization_requirements=_auth_reqs(scope_ref),
            observation_type_suggestions=(otype,),
            satisfiable=True,
            provenance={"source": "observation_type_coverage",
                        "scope_ref": scope_ref},
        ))

    # stable order: priority, then code
    items.sort(key=lambda i: (i.priority, i.item_code, i.item_id))
    # dedup by id
    seen_ids: set[str] = set()
    unique: list[MissingEvidenceItem] = []
    for item in items:
        if item.item_id in seen_ids:
            continue
        seen_ids.add(item.item_id)
        unique.append(item)
    return unique[:12]


def _first_hypothesis(analysis: dict[str, Any]) -> str:
    for hyp in (analysis.get("hypotheses") or []):
        text = str((hyp or {}).get("hypothesis") or "").strip()
        if text:
            return text[:300]
    return ""


def _tech_tokens(analysis: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for ev in (analysis.get("evidence_candidates") or []):
        detail = str((ev or {}).get("detail") or "")
        if detail.lower().startswith("technology:"):
            out.append(detail.split(":", 1)[1].strip()[:60])
    return out[:6]


def any_satisfiable(items: Iterable[MissingEvidenceItem]) -> bool:
    return any(i.satisfiable for i in items)


def unsatisfiable_codes(items: Iterable[MissingEvidenceItem]) -> list[str]:
    return [i.item_code for i in items if not i.satisfiable]


__all__ = [
    "MISSING_EVIDENCE_RULE_VERSION",
    "MissingEvidenceItem",
    "PRIORITY_CRITICAL",
    "PRIORITY_HIGH",
    "PRIORITY_LOW",
    "PRIORITY_MEDIUM",
    "any_satisfiable",
    "compute_missing_evidence",
    "unsatisfiable_codes",
]
