"""backend/attack_surface/service.py — orchestration, queue and payloads.

Ties the pure layers together and exposes the shapes consumed by the Command
Center and the JSON API:

- :func:`build_candidates` classifies + scores every normalized record into
  deterministic :class:`~backend.attack_surface.models.AttackSurfaceCandidate`
  values.
- :func:`build_discovery` / :func:`summarize_candidates` produce the bounded
  discovery and candidate counters.
- :func:`build_priority_queue` produces the ranked "investigate next" queue.
- :func:`attack_surface_payload` is the stable Command Center / API contract
  ``{summary, discovery, candidates, priority_queue}``.
- :class:`CandidateQueue` implements the Phase 4 lifecycle
  (NEW -> TRIAGED -> ASSIGNED -> VERIFYING -> CONFIRMED -> REPORTED) with
  deterministic, validated transitions. It is in-memory by default; an
  explicit ``path`` enables a small JSON artifact store (never used by the
  read-only Command Center path).

No writes, no network, no LLM, no target interaction. A candidate is a research
hypothesis, never a confirmed vulnerability.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path

from backend.attack_surface import repository
from backend.attack_surface.classifier import classify
from backend.attack_surface.models import (
    CANDIDATE_CATEGORIES,
    CANDIDATE_STATUS_FLOW,
    CANDIDATE_STATUSES,
    CONFIDENCE_LEVELS,
    RULE_VERSION,
    AttackSurfaceCandidate,
    AttackSurfaceSnapshot,
    CandidateCategory,
    CandidateStatus,
    Confidence,
    candidate_id_for,
    canonical_category,
)
from backend.attack_surface.scorer import score

DEFAULT_PRIORITY_LIMIT = 10

#: Short labels used by the Command Center counters.
CATEGORY_SHORT: dict[str, str] = {
    CandidateCategory.XSS.value: "XSS",
    CandidateCategory.IDOR.value: "IDOR",
    CandidateCategory.SSRF.value: "SSRF",
    CandidateCategory.FILE_UPLOAD.value: "UPLOAD",
}

_CONFIDENCE_RANK = {
    Confidence.HIGH.value: 2,
    Confidence.MEDIUM.value: 1,
    Confidence.LOW.value: 0,
}


def _text(value: object, limit: int = 512) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


# ---------------------------------------------------------------------------
# Candidate construction
# ---------------------------------------------------------------------------


def build_candidates(
    snapshot: AttackSurfaceSnapshot,
    *,
    now: str | None = None,
) -> list[AttackSurfaceCandidate]:
    """Deterministically classify + score a snapshot into candidates.

    ``now`` is the fallback ``created_at`` when a record carries no observed
    timestamp; passing a fixed value keeps tests reproducible.
    """

    out: list[AttackSurfaceCandidate] = []
    seen: set[str] = set()
    for record in snapshot.records:
        for classification in classify(record):
            category = canonical_category(classification.category)
            scored = score(record, classification)
            candidate_id = candidate_id_for(
                record.program,
                record.endpoint,
                record.parameter,
                record.method,
                category,
            )
            if candidate_id in seen:
                continue
            seen.add(candidate_id)
            out.append(
                AttackSurfaceCandidate(
                    id=candidate_id,
                    category=category,
                    confidence=scored.confidence,
                    score=scored.score,
                    endpoint=record.endpoint,
                    parameter=record.parameter,
                    method=record.method,
                    reasons=scored.reasons,
                    status=CandidateStatus.NEW.value,
                    created_at=record.last_update or now,
                    program=record.program,
                    subdomain=record.subdomain,
                    url=record.url,
                    location=record.location,
                    technology=record.technology,
                    source=record.source,
                    rule_version=RULE_VERSION,
                )
            )
    out.sort(
        key=lambda item: (
            -item.score,
            -_CONFIDENCE_RANK.get(item.confidence, 0),
            item.category,
            item.endpoint,
            item.parameter,
            item.id,
        )
    )
    return out


def build_discovery(snapshot: AttackSurfaceSnapshot) -> dict:
    """Discovery counters: domains, URLs, endpoints, parameters."""

    return {
        "domains": len(snapshot.domains),
        "urls": int(snapshot.url_count),
        "endpoints": int(snapshot.endpoint_count),
        "parameters": int(snapshot.parameter_count),
        "programs": list(snapshot.programs),
        "domain_sample": list(snapshot.domains[:24]),
    }


def summarize_candidates(candidates: list[AttackSurfaceCandidate]) -> dict:
    """Bounded candidate counters by category and confidence."""

    by_category = {name: 0 for name in CANDIDATE_CATEGORIES}
    by_confidence = {name: 0 for name in CONFIDENCE_LEVELS}
    short = {label: 0 for label in CATEGORY_SHORT.values()}
    for candidate in candidates:
        by_category[candidate.category] = by_category.get(candidate.category, 0) + 1
        by_confidence[candidate.confidence] = (
            by_confidence.get(candidate.confidence, 0) + 1
        )
        label = CATEGORY_SHORT.get(candidate.category)
        if label:
            short[label] += 1
    return {
        "available": bool(candidates),
        "total": len(candidates),
        "by_category": by_category,
        "by_confidence": by_confidence,
        "short": short,
        "rule_version": RULE_VERSION,
    }


def build_priority_queue(
    candidates: list[AttackSurfaceCandidate],
    *,
    limit: int = DEFAULT_PRIORITY_LIMIT,
) -> list[dict]:
    """Ranked priority queue (highest score first, deterministic tie-break)."""

    ordered = sorted(
        candidates,
        key=lambda item: (
            -item.score,
            -_CONFIDENCE_RANK.get(item.confidence, 0),
            item.endpoint,
            item.parameter,
            item.category,
            item.id,
        ),
    )
    queue: list[dict] = []
    for rank, candidate in enumerate(ordered[: max(limit, 0)], start=1):
        row = candidate.to_dict()
        row["rank"] = rank
        row["label"] = CATEGORY_SHORT.get(candidate.category, candidate.category)
        queue.append(row)
    return queue


def attack_surface_payload(
    program: str | None = None,
    *,
    records: dict | None = None,
    snapshot: AttackSurfaceSnapshot | None = None,
    now: str | None = None,
    priority_limit: int = DEFAULT_PRIORITY_LIMIT,
    max_programs: int = repository.DEFAULT_MAX_PROGRAMS,
) -> dict:
    """Stable ``{summary, discovery, candidates, priority_queue}`` contract.

    Read-only and fail-soft: an unavailable snapshot yields an honest empty
    payload with ``available: false`` and zeroed counters.
    """

    if snapshot is None:
        snapshot = repository.load_snapshot(
            program, records=records, max_programs=max_programs
        )
    candidates = build_candidates(snapshot, now=now)
    discovery = build_discovery(snapshot)
    summary = summarize_candidates(candidates)
    summary.update(
        {
            "generated_from": snapshot.generated_from,
            "programs": list(snapshot.programs),
            "truncated": bool(snapshot.truncated),
            "record_count": len(snapshot.records),
        }
    )
    return {
        "available": bool(snapshot.available),
        "rule_version": RULE_VERSION,
        "summary": summary,
        "discovery": discovery,
        "candidates": summary,
        "priority_queue": build_priority_queue(
            candidates, limit=priority_limit
        ),
    }


# ---------------------------------------------------------------------------
# Candidate lifecycle queue (Phase 4)
# ---------------------------------------------------------------------------


class CandidateQueueError(ValueError):
    """Invalid lifecycle transition or malformed queue artifact."""


@dataclass
class CandidateQueue:
    """In-memory candidate lifecycle with optional JSON persistence.

    The queue is deliberately read/write *in memory* only; the Command Center
    and API never write production data. Supplying an explicit ``path`` opts
    into a small JSON artifact store for tests or a future dedicated worker.
    """

    path: Path | None = None
    _items: dict[str, AttackSurfaceCandidate] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._items is None:
            self._items = {}
        if self.path is not None:
            self._load()

    # -- persistence -------------------------------------------------------
    def _load(self) -> None:
        path = Path(self.path)
        if not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CandidateQueueError(f"unreadable queue artifact {path}") from exc
        if not isinstance(payload, list):
            raise CandidateQueueError("queue artifact must be a list")
        for row in payload:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            self._items[str(row["id"])] = AttackSurfaceCandidate(
                id=str(row["id"]),
                category=_text(row.get("category"), 64),
                confidence=_text(row.get("confidence"), 16),
                score=int(row.get("score") or 0),
                endpoint=_text(row.get("endpoint"), 512),
                parameter=_text(row.get("parameter"), 128),
                method=_text(row.get("method"), 16) or "GET",
                reasons=tuple(row.get("reasons") or ()),
                status=_text(row.get("status"), 16)
                or CandidateStatus.NEW.value,
                created_at=row.get("created_at"),
                program=_text(row.get("program"), 128),
                subdomain=_text(row.get("subdomain"), 256),
                url=_text(row.get("url"), 1024),
                location=_text(row.get("location"), 16) or "query",
                technology=tuple(row.get("technology") or ()),
                source=_text(row.get("source"), 32) or "watch",
                rule_version=_text(row.get("rule_version"), 64) or RULE_VERSION,
            )

    def save(self) -> None:
        if self.path is None:
            return
        path = Path(self.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_list(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    # -- lifecycle ---------------------------------------------------------
    def add(self, candidate: AttackSurfaceCandidate) -> AttackSurfaceCandidate:
        """Insert a candidate, preserving an existing status (idempotent)."""

        existing = self._items.get(candidate.id)
        if existing is not None:
            return existing
        self._items[candidate.id] = candidate
        return candidate

    def add_many(
        self, candidates: list[AttackSurfaceCandidate]
    ) -> list[AttackSurfaceCandidate]:
        return [self.add(candidate) for candidate in candidates]

    def get(self, candidate_id: str) -> AttackSurfaceCandidate | None:
        return self._items.get(str(candidate_id))

    def all(self) -> list[AttackSurfaceCandidate]:
        return list(self._items.values())

    def by_status(self, status: str) -> list[AttackSurfaceCandidate]:
        wanted = _text(status, 16).upper()
        return [item for item in self._items.values() if item.status == wanted]

    def transition(
        self, candidate_id: str, status: str
    ) -> AttackSurfaceCandidate:
        """Validate and apply one lifecycle transition."""

        candidate = self._items.get(str(candidate_id))
        if candidate is None:
            raise CandidateQueueError(f"unknown candidate {candidate_id}")
        target = _text(status, 16).upper()
        if target not in CANDIDATE_STATUSES:
            raise CandidateQueueError(f"unknown status {status!r}")
        if target == candidate.status:
            return candidate
        allowed = CANDIDATE_STATUS_FLOW.get(candidate.status, ())
        if target not in allowed:
            raise CandidateQueueError(
                f"illegal transition {candidate.status} -> {target}"
            )
        updated = replace(candidate, status=target)
        self._items[candidate.id] = updated
        return updated

    def to_list(self) -> list[dict]:
        return [
            item.to_dict()
            for item in sorted(
                self._items.values(),
                key=lambda row: (
                    -row.score,
                    row.endpoint,
                    row.parameter,
                    row.category,
                    row.id,
                ),
            )
        ]

    def summary(self) -> dict:
        counts = {status: 0 for status in CANDIDATE_STATUSES}
        for item in self._items.values():
            counts[item.status] = counts.get(item.status, 0) + 1
        return {"total": len(self._items), "by_status": counts}


__all__ = [
    "DEFAULT_PRIORITY_LIMIT",
    "CATEGORY_SHORT",
    "CandidateQueue",
    "CandidateQueueError",
    "build_candidates",
    "build_discovery",
    "summarize_candidates",
    "build_priority_queue",
    "attack_surface_payload",
]
