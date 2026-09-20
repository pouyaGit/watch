"""backend/attack_surface/models.py — normalized attack-surface vocabulary.

Pure, dependency-free data structures shared by the repository, classifier,
scorer and service layers. Nothing here performs IO: models are inert values
so every rule can be tested in isolation.

Two object families are defined:

- :class:`AttackSurfaceRecord` -- one *observed* (endpoint, parameter) pair
  normalized from existing Watch recon rows. ``source`` is always ``watch``;
  ``technology`` carries observed technology names only (versions are never
  parsed here).
- :class:`AttackSurfaceCandidate` -- one *research hypothesis* produced by the
  deterministic classifier/scorer. A candidate is never a confirmed
  vulnerability; ``status`` follows the lifecycle in
  :data:`CANDIDATE_STATUS_FLOW`.

``AttackSurfaceSnapshot`` is the bounded, read-only view of the surface that
the repository hands to the service layer.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

#: Stable identifier for the deterministic rules shipped in v1.
RULE_VERSION = "attack-surface-1"

#: Canonical data source label for normalized records.
SOURCE_WATCH = "watch"


class CandidateCategory(str, Enum):
    """Research categories the classifier can assign (Phase 2)."""

    XSS = "XSS_CANDIDATE"
    IDOR = "IDOR_CANDIDATE"
    SSRF = "SSRF_CANDIDATE"
    FILE_UPLOAD = "FILE_UPLOAD_CANDIDATE"


class Confidence(str, Enum):
    """Explainable confidence buckets derived purely from the score."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CandidateStatus(str, Enum):
    """Candidate lifecycle statuses (Phase 4)."""

    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ASSIGNED = "ASSIGNED"
    VERIFYING = "VERIFYING"
    CONFIRMED = "CONFIRMED"
    REPORTED = "REPORTED"


CANDIDATE_CATEGORIES: tuple[str, ...] = tuple(
    category.value for category in CandidateCategory
)
CONFIDENCE_LEVELS: tuple[str, ...] = tuple(
    level.value for level in Confidence
)
CANDIDATE_STATUSES: tuple[str, ...] = tuple(
    status.value for status in CandidateStatus
)

#: Allowed lifecycle transitions. A status may always stay the same (handled
#: by the queue before the map is consulted). ``CONFIRMED`` here means a
#: research candidate reached the confirmation *stage*; it is never emitted by
#: the read-only classifier, which only ever produces ``NEW`` candidates.
CANDIDATE_STATUS_FLOW: dict[str, tuple[str, ...]] = {
    CandidateStatus.NEW.value: (CandidateStatus.TRIAGED.value,),
    CandidateStatus.TRIAGED.value: (
        CandidateStatus.ASSIGNED.value,
        CandidateStatus.NEW.value,
    ),
    CandidateStatus.ASSIGNED.value: (
        CandidateStatus.VERIFYING.value,
        CandidateStatus.TRIAGED.value,
    ),
    CandidateStatus.VERIFYING.value: (
        CandidateStatus.CONFIRMED.value,
        CandidateStatus.ASSIGNED.value,
    ),
    CandidateStatus.CONFIRMED.value: (
        CandidateStatus.REPORTED.value,
        CandidateStatus.VERIFYING.value,
    ),
    CandidateStatus.REPORTED.value: (),
}


def _text(value: object, limit: int = 512) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


@dataclass(frozen=True)
class AttackSurfaceRecord:
    """One observed (endpoint, parameter) pair normalized from Watch data.

    ``url`` is deliberately *relative* (``/api/user?id=``): the module never
    needs or exposes the target host, and no URL is ever fetched.
    """

    program: str = ""
    subdomain: str = ""
    url: str = ""
    endpoint: str = ""
    parameter: str = ""
    method: str = "GET"
    location: str = "query"
    technology: tuple[str, ...] = ()
    source: str = SOURCE_WATCH
    last_update: str | None = None

    def to_dict(self) -> dict:
        return {
            "program": self.program,
            "subdomain": self.subdomain,
            "url": self.url,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "location": self.location,
            "technology": list(self.technology),
            "source": self.source,
            "last_update": self.last_update,
        }


@dataclass(frozen=True)
class AttackSurfaceSnapshot:
    """Bounded, read-only view of the observed attack surface."""

    programs: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    url_count: int = 0
    endpoint_count: int = 0
    parameter_count: int = 0
    records: tuple[AttackSurfaceRecord, ...] = ()
    available: bool = False
    generated_from: str = ""
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "programs": list(self.programs),
            "domains": list(self.domains),
            "discovery": {
                "domains": len(self.domains),
                "urls": self.url_count,
                "endpoints": self.endpoint_count,
                "parameters": self.parameter_count,
            },
            "record_count": len(self.records),
            "available": self.available,
            "truncated": self.truncated,
            "generated_from": self.generated_from,
        }


# ---------------------------------------------------------------------------
# Candidate ids
# ---------------------------------------------------------------------------


def candidate_id_for(
    program: object,
    endpoint: object,
    parameter: object,
    method: object,
    category: object,
) -> str:
    """Deterministic, stable candidate id (``asc-`` + 16 hex chars).

    The id is a pure hash of the identifying tuple so the same observation +
    category always yields the same candidate, which makes the queue and the
    API idempotent across restarts.
    """

    seed = "\x1f".join(
        _text(value, 256).lower()
        for value in (program, endpoint, parameter, method, category)
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return "asc-" + digest[:16]


def canonical_category(value: object) -> str:
    """Normalize an enum/value into its canonical uppercase string."""

    if isinstance(value, CandidateCategory):
        return value.value
    return _text(value, 64).upper()


@dataclass(frozen=True)
class AttackSurfaceCandidate:
    """One prioritized research candidate (a hypothesis, not a finding)."""

    id: str
    category: str
    confidence: str
    score: int
    endpoint: str
    parameter: str
    method: str
    reasons: tuple[str, ...]
    status: str = CandidateStatus.NEW.value
    created_at: str | None = None
    program: str = ""
    subdomain: str = ""
    url: str = ""
    location: str = "query"
    technology: tuple[str, ...] = ()
    source: str = SOURCE_WATCH
    rule_version: str = RULE_VERSION

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "confidence": self.confidence,
            "score": int(self.score),
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "reasons": list(self.reasons),
            "status": self.status,
            "created_at": self.created_at,
            "program": self.program,
            "subdomain": self.subdomain,
            "url": self.url,
            "location": self.location,
            "technology": list(self.technology),
            "source": self.source,
            "rule_version": self.rule_version,
        }


__all__ = [
    "RULE_VERSION",
    "SOURCE_WATCH",
    "CandidateCategory",
    "Confidence",
    "CandidateStatus",
    "CANDIDATE_CATEGORIES",
    "CONFIDENCE_LEVELS",
    "CANDIDATE_STATUSES",
    "CANDIDATE_STATUS_FLOW",
    "AttackSurfaceRecord",
    "AttackSurfaceSnapshot",
    "AttackSurfaceCandidate",
    "candidate_id_for",
    "canonical_category",
]
