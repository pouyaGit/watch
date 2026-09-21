"""EPIC6 Part 9: deterministic specialist queues."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from aec.specialists.registry import (
    default_registry as _default_registry,
    match_category,
)

BAND_PRIORITY = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

_ENTRY_KEYS = (
    "case_id", "category", "band", "attempts", "refused",
    "duplicate_of", "host", "family", "waiting_ticks",
)


@dataclass(frozen=True)
class SpecialistQueue:
    """Deterministic queue over specialist-matched jobs."""

    queue_id: str
    entries: tuple[dict[str, Any], ...]
    total: int
    queued_count: int
    refusals: tuple[str, ...]
    metrics: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "queue_id": self.queue_id,
            "entries": [dict(item) for item in self.entries],
            "total": self.total,
            "metrics": dict(self.metrics),
        }


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def band_priority(band: object) -> int:
    """Explicit priority mapping: HIGH < MEDIUM < LOW (lower first)."""
    return BAND_PRIORITY.get(_text(band), 3)


def _entry_sort_key(entry: dict[str, Any]) -> tuple:
    attempts = entry.get("attempts", 0)
    if not isinstance(attempts, int):
        attempts = 0 if attempts == "" else int(attempts or 0)
    return (attempts, band_priority(entry.get("band")), entry.get("case_id", ""))


def default_registry() -> tuple:
    """Alias so callers need one import surface."""
    return _default_registry()


def build_specialist_queue(
    jobs: Sequence[Mapping[str, Any]],
    registry: tuple,
    starvation_threshold: int = 10,
    host_budget: int | None = None,
    family_budget: int | None = None,
) -> SpecialistQueue:
    """Order jobs deterministically, match specialists, flag anomalies."""
    host_used: dict[str, int] = {}
    family_used: dict[str, int] = {}
    entries: list[dict[str, Any]] = []
    seen_cases: set[str] = set()
    refusals: list[str] = []
    total = 0
    duplicates = 0

    ordered = sorted(
        (dict(job) for job in jobs if isinstance(job, Mapping)),
        key=_entry_sort_key,
    )
    for job in ordered:
        total += 1
        case_id = _text(job.get("case_id"))
        category = _text(job.get("category"))
        host = _text(job.get("host"))
        family = _text(job.get("family"))
        refused = _text(job.get("refused"))
        attempts_raw = job.get("attempts", 0)
        attempts = attempts_raw if isinstance(attempts_raw, int) else 0
        duplicate_of = _text(job.get("duplicate_of"))
        waiting = job.get("waiting_ticks", 0)
        waiting = waiting if isinstance(waiting, int) else 0

        if case_id and case_id in seen_cases:
            duplicates += 1
            duplicate_of = case_id
        if case_id:
            seen_cases.add(case_id)

        try:
            profile = match_category(registry, category)
            specialist = profile.role
            capabilities = tuple(profile.capabilities)
        except ValueError:
            specialist = "general-researcher"
            capabilities = ("general-surface-review",)

        if refused:
            refusals.append(refused)

        budget = "OK"
        if host and host_budget is not None:
            used = host_used.get(host, 0)
            if used >= host_budget:
                budget = "OVER"
            else:
                host_used[host] = used + 1
        if budget == "OK" and family and family_budget is not None:
            used = family_used.get(family, 0)
            if used >= family_budget:
                budget = "OVER"
            else:
                family_used[family] = used + 1

        starvation = ("STARVED" if waiting > starvation_threshold
                      else "NORMAL")
        retry_class = "RETRY" if attempts > 0 else "FIRST_ATTEMPT"

        entries.append({
            "case_id": case_id,
            "category": category,
            "band": _text(job.get("band")),
            "attempts": attempts,
            "refused": refused,
            "duplicate_of": duplicate_of,
            "host": host,
            "family": family,
            "specialist": specialist,
            "capabilities": list(capabilities),
            "budget": budget,
            "retry_class": retry_class,
            "starvation": starvation,
        })

    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    queued = sum(1 for item in entries
                 if not item["duplicate_of"] and not item["refused"])
    queue_id = ("specq:" + hashlib.sha256(
        canonical.encode("utf-8")).hexdigest()[:12])
    metrics = {
        "total": total,
        "queued": queued,
        "duplicates": duplicates,
        "refusals": len(refusals),
    }
    return SpecialistQueue(
        queue_id=queue_id,
        entries=tuple(entries),
        total=total,
        queued_count=queued,
        refusals=tuple(refusals),
        metrics=metrics,
    )


__all__ = ["BAND_PRIORITY", "SpecialistQueue", "band_priority",
           "build_specialist_queue", "default_registry"]