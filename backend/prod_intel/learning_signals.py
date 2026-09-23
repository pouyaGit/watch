"""backend/prod_intel/learning_signals.py — recurring research signals.

Read-only projections OVER the existing Research Memory/Learning system
(``intelligence.memory`` heads) plus persisted hunt/finding repetition
counts. Hard rules:

* signals are DERIVED — their state is at most ``INFERRED`` even when
  built from ``REJECTED``/``OBSERVED`` items: this layer never promotes
  inferred learning to verified fact and never writes memory items
  (the runtime learning loop stays the only producer of memory);
* every signal carries ``kind`` (validated against MEMORY_KINDS),
  ``state`` (validated against MEMORY_STATES), source, provenance refs
  (the contributing item/objective ids) and a deterministic time window
  derived from the contributors — no wall-clock fields, so two builds
  over the same data are identical;
* OBSERVED / INFERRED / RESEARCHED / VERIFIED / REJECTED semantics are
  preserved: a REJECTED pattern stays REJECTED; only the pattern
  *detection* layer is tagged INFERRED.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from backend.prod_intel import sources
from backend.prod_intel.semantics import (
    DEFAULT_WINDOW_HOURS,
    NOT_OBSERVED,
    OK,
    UNAVAILABLE,
    metric,
    window_bounds,
)

MIN_PATTERN_REPEATS = 2        # a "recurring" signal needs ≥2 occurrences


def _kind_ok(kind: str) -> bool:
    try:
        from backend.research_agents.intelligence.memory import MEMORY_KINDS
        return kind in MEMORY_KINDS
    except Exception:
        return False


def _signal(*, kind: str, state: str, pattern: str, count: int,
            refs: list[str], source: str, earliest: str, latest: str,
            target: str = "", detail: str = "") -> dict[str, Any] | None:
    """Validate + assemble one learning signal; None when illegal."""
    if not _kind_ok(kind):
        return None
    try:
        from backend.research_agents.intelligence.memory import MEMORY_STATES
        if state not in MEMORY_STATES:
            return None
    except Exception:
        return None
    return {
        "kind": kind,
        "state": state,                    # derived layer caps at INFERRED
        "pattern": pattern[:400],
        "count": int(count),
        "confidence": "inferred_pattern",
        "source": source,
        "provenance": {"refs": refs[:12], "source": source,
                       "contributor_count": int(count)},
        "time_range": {"earliest": earliest, "latest": latest,
                       "kind": "contributor_derived"},
        "target": target,
        "detail": detail[:400],
        "rule_version": "production-intelligence-v1",
    }


def learning_signals(*, hours: float | int | None = DEFAULT_WINDOW_HOURS
                     ) -> dict[str, Any]:
    """Recurring patterns across memory, hunt blocks and duplicates."""
    _, window = window_bounds(hours)
    signals: list[dict[str, Any]] = []
    unavailable: list[str] = []

    # ---- 1. recurring memory patterns (kind+state heads) -----------------
    mem_env = sources.memory_heads()
    if mem_env["state"] != "ok":
        unavailable.append(mem_env["reason"])
    else:
        heads = mem_env["data"]
        by_pattern: dict[tuple[str, str, str], list[Any]] = {}
        for item in heads:
            # group by kind + state + normalized subject text
            key = (str(item.kind), str(item.state),
                   str(item.subject_key or item.text)[:120])
            by_pattern.setdefault(key, []).append(item)
        for (kind, state, subject), items in by_pattern.items():
            if len(items) < MIN_PATTERN_REPEATS:
                continue
            # derived layer never exceeds INFERRED for a *pattern*, and
            # never re-states a REJECTED/VERIFIED head as its opposite
            derived_state = ("REJECTED" if state == "REJECTED"
                             else "INFERRED")
            times = sorted(str(i.updated_at or i.created_at or "")
                           for i in items)
            sig = _signal(
                kind=kind, state=derived_state,
                pattern=f"recurring {kind}: {subject}",
                count=len(items),
                refs=[i.id for i in items],
                source="intelligence.memory heads",
                earliest=times[0], latest=times[-1],
                target=str(items[0].target or ""),
                detail=f"state={state} observed across {len(items)} "
                       f"memory items")
            if sig:
                signals.append(sig)

    # ---- 2. repeated hunt block patterns ---------------------------------
    hunt_env = sources.hunt_objectives()
    if hunt_env["state"] != "ok":
        unavailable.append(hunt_env["reason"])
    else:
        blocks = Counter()
        refs_map: dict[str, list[str]] = {}
        times_map: dict[str, list[str]] = {}
        targets_map: dict[str, str] = {}
        for o in hunt_env["data"]:
            if str(o.state) != "BLOCKED":
                continue
            reason = str(o.termination_reason or "blocked")[:80]
            blocks[reason] += 1
            refs_map.setdefault(reason, []).append(o.objective_id)
            times_map.setdefault(reason, []).append(
                str(o.updated_at or o.created_at or ""))
            if not targets_map.get(reason):
                ctx = (o.target_context if isinstance(o.target_context, dict)
                       else {})
                targets_map[reason] = str(ctx.get("subdomain", ""))
        for reason, n in blocks.items():
            if n < MIN_PATTERN_REPEATS:
                continue
            times = sorted(t for t in times_map[reason] if t)
            sig = _signal(
                kind="evidence_requirement", state="INFERRED",
                pattern=f"repeated blocked objective: {reason}",
                count=n, refs=refs_map[reason], source="hunt.store",
                earliest=times[0] if times else "",
                latest=times[-1] if times else "",
                target=targets_map.get(reason, ""),
                detail="objectives repeatedly terminated BLOCKED with this "
                       "reason — a recurring evidence/authorization gap, "
                       "not a proven cause")
            if sig:
                signals.append(sig)

    # ---- 3. repeated duplicate-candidate patterns -------------------------
    cand_env = sources.candidates()
    corr_env = sources.correlations()
    if cand_env["state"] != "ok":
        unavailable.append(cand_env["reason"])
    else:
        dup_targets = Counter()
        dup_refs: dict[str, list[str]] = {}
        dup_times: dict[str, list[str]] = {}
        for c in cand_env["data"]:
            if str(c.lifecycle_state) == "DUPLICATE":
                key = f"{c.vulnerability_class}@{c.target}"
                dup_targets[key] += 1
                dup_refs.setdefault(key, []).append(c.candidate_id)
                dup_times.setdefault(key, []).append(
                    str(c.updated_at or c.created_at or ""))
        for key, n in dup_targets.items():
            if n < MIN_PATTERN_REPEATS:
                continue
            times = sorted(t for t in dup_times[key] if t)
            reasons = []
            if corr_env["state"] == "ok":
                for row in corr_env["data"]:
                    for r in (row.get("reasons") or [])[:6]:
                        if r not in reasons:
                            reasons.append(str(r))
            sig = _signal(
                kind="observed_behavior", state="INFERRED",
                pattern=f"recurring duplicate candidates: {key}",
                count=n, refs=dup_refs[key],
                source="finding.store candidates + correlations",
                earliest=times[0] if times else "",
                latest=times[-1] if times else "",
                target=key.split("@")[-1],
                detail=f"{n} candidates folded as DUPLICATE; correlation "
                       f"reasons seen: {', '.join(reasons[:6]) or 'n/a'}")
            if sig:
                signals.append(sig)

    signals.sort(key=lambda s: (s["time_range"]["latest"],
                                s["count"]), reverse=True)
    # an unreadable source must read unavailable, never not_observed —
    # a down memory store is NOT evidence that no patterns exist
    state = UNAVAILABLE if unavailable else (
        OK if signals else NOT_OBSERVED)
    return metric(
        signals[:50], source="intelligence.memory + hunt.store + "
                             "finding.store",
        population="persisted memory heads and state records grouped into "
                   f"patterns with ≥{MIN_PATTERN_REPEATS} occurrences",
        aggregation="count per pattern; derived state capped at INFERRED "
                    "(REJECTED preserved); deterministic contributor "
                    "window", time_range=window, state=state,
        unavailable_sources=unavailable)
