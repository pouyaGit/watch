"""EPIC9 §7/§8: deterministic, explainable prioritization + bounded
fairness. No opaque AI score; no security-quality ranking; ordering is a
documented total order over persisted facts only.

Exact ordering key (ascending — smaller runs first):

    1. class rank        RUNTIME_JOB (0) < FINDING_PIPELINE (1)
                         < CAMPAIGN_OBJECTIVE (2)
                         Rationale: queued runtime jobs are already
                         fully gated claims; finding pipeline units are
                         single-job bounded; campaign objectives are the
                         heaviest orchestration units.
    2. -priority         existing explicit priority (operator-set)
                         descending — jobs use priority_score, campaign
                         objectives use priority.
    3. created_at        older first (ISO-8601 string compare; empty = ""
                         sorts first — undiscovered age is not invented,
                         empty simply never beats a real timestamp? see
                         note: "" < any date would put ageless items
                         first; we instead sort empty LAST via
                         (created == "", created) tuple.)
    4. scope_ref         stable target tie-break
    5. work_id           final deterministic tie-break

Selection (bounded fairness, §8): walk the ordered list and take an item
only while every budget holds — total work budget (``max_work``),
per-target budget (``max_per_target``) and per-campaign budget
(``max_per_campaign``). Items skipped solely because a budget was
exhausted are returned as deferred with reason ``BUDGET_DEFERRED`` —
they stay discovered/truthful and are eligible again next tick, which
prevents one target or campaign from monopolizing the window while
guaranteeing equally-eligible work rotates (a capped group's overflow
falls through to the next group in the same pass).
"""

from __future__ import annotations

from typing import Iterable

from backend.ai_ops.config import DispatcherConfig
from backend.ai_ops.discovery import (
    BUDGET_DEFERRED,
    CLASS_CAMPAIGN,
    CLASS_FINDING,
    CLASS_JOB,
    WorkItem,
)

CLASS_RANK = {
    CLASS_JOB: 0,
    CLASS_FINDING: 1,
    CLASS_CAMPAIGN: 2,
}


def order_key(item: WorkItem) -> tuple:
    """The documented total order (§7). Never an opaque score."""
    created = str(item.created_at or "")
    return (
        CLASS_RANK.get(item.work_class, 9),
        -int(item.priority or 0),
        (created == "", created),   # ageless last, then oldest first
        str(item.scope_ref or ""),
        str(item.work_id or ""),
    )


def prioritize(items: Iterable[WorkItem]) -> list[WorkItem]:
    """Stable deterministic ordering; same input -> byte-identical order."""
    return sorted(items, key=order_key)


def select_bounded(items: list[WorkItem],
                   config: DispatcherConfig,
                   ) -> tuple[list[WorkItem], list[WorkItem]]:
    """Apply budgets: returns (selected, deferred BUDGET_DEFERRED)."""
    ordered = prioritize([i for i in items if i.executable])
    selected: list[WorkItem] = []
    deferred: list[WorkItem] = []
    per_target: dict[str, int] = {}
    per_campaign: dict[str, int] = {}
    for item in ordered:
        if len(selected) >= config.max_work:
            deferred.append(_defer(item, "work budget"))
            continue
        target = item.target or item.scope_ref or item.work_id
        campaign = item.campaign_id or ""
        if per_target.get(target, 0) >= config.max_per_target:
            deferred.append(_defer(item, "target budget"))
            continue
        if campaign and per_campaign.get(campaign, 0) \
                >= config.max_per_campaign:
            deferred.append(_defer(item, "campaign budget"))
            continue
        selected.append(item)
        per_target[target] = per_target.get(target, 0) + 1
        if campaign:
            per_campaign[campaign] = per_campaign.get(campaign, 0) + 1
    return selected, deferred


def _defer(item: WorkItem, why: str) -> WorkItem:
    """Annotate why the item lost its slot; the dispatcher reports the
    closed reason BUDGET_DEFERRED with this budget detail."""
    item.meta["deferred_by"] = why
    return item
