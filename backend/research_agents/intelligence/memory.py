"""backend/research_agents/intelligence/memory.py — Phase 1 research memory.

Persistent, provenance-carrying research knowledge for the AI Agent
Runtime.  One append-only JSONL file (``memory.jsonl``) next to the
runtime state; readers fold by item id (last write wins), so state
evolution (INFERRED -> VERIFIED, INFERRED -> REJECTED) keeps a full
append history while queries see only the current head.

Hard boundaries:

- Every item MUST carry provenance (job id, source, refs, timestamp);
  there is no provenance-free constructor.
- The five states OBSERVED / INFERRED / RESEARCHED / VERIFIED / REJECTED
  are distinct and never collapsed.  VERIFIED may only be produced by the
  deterministic evidence gate path (``learning.py`` is the sole writer of
  VERIFIED items); the LLM can at most reach INFERRED.
- Text is scrubbed of secret-shaped values before it can ever persist;
  malformed items are rejected (``ValueError``) and never written.
- Storage failure raises ``MemoryUnavailable`` — callers degrade
  honestly, never fabricate memory.

This module has no knowledge of the runtime pipeline (no imports from
``runtime``) so it can be reused by any specialist edge.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from backend.research_agents.runtime_store import runtime_base_dir, utcnow

MEMORY_RULE_VERSION = "research-memory-v1"

MEMORY_STATES: tuple[str, ...] = (
    "OBSERVED",
    "INFERRED",
    "RESEARCHED",
    "VERIFIED",
    "REJECTED",
)

MEMORY_KINDS: tuple[str, ...] = (
    "security_concept",
    "vulnerability_class",
    "technology",
    "attack_surface_pattern",
    "endpoint_pattern",
    "parameter_pattern",
    "observed_behavior",
    "hypothesis",
    "evidence_requirement",
    "negative_evidence",
    "confirmed_historical_result",
    "rejected_hypothesis",
    "research_recommendation",
    "source_reference",
)

# Dedup/evolution rules: research may advance along this ladder; REJECTED
# is its own terminal track that a later VERIFIED outcome may supersede.
_STATE_RANK = {"OBSERVED": 1, "INFERRED": 2, "RESEARCHED": 3,
               "VERIFIED": 4, "REJECTED": 0}

# States allowed to supersede an existing head for the same id.
_SUPERSEDE_OK = {
    ("INFERRED", "VERIFIED"), ("INFERRED", "REJECTED"),
    ("OBSERVED", "RESEARCHED"), ("OBSERVED", "VERIFIED"),
    ("OBSERVED", "REJECTED"), ("RESEARCHED", "VERIFIED"),
    ("RESEARCHED", "REJECTED"), ("REJECTED", "VERIFIED"),
}

_SECRET_PATTERNS = (
    re.compile(r"sk-or-v1-[A-Za-z0-9_-]{6,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)openrouter_api_key\s*=\s*\S+"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9._-]{8,}"),
    re.compile(r"(?i)authorization\s*[:=]\s*\S+"),
)

MAX_TEXT = 400
MAX_SUBJECT = 160


class MemoryUnavailable(Exception):
    """Persistent research memory cannot be read/written right now."""


def scrub_text(value: object, limit: int = MAX_TEXT) -> str:
    """Bounded whitespace-normalized text with secrets redacted."""
    text = " ".join(str(value if value is not None else "").split())
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("***", text)
    return text[:limit]


def memory_id(kind: str, category: str, target: str, subject_key: str) -> str:
    """Stable identity so repeated learning converges instead of piling up."""
    raw = "|".join((kind, category, target, subject_key))
    return "mem-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class MemoryItem:
    id: str
    kind: str
    state: str
    subject_key: str
    text: str
    category: str
    agent: str
    target: str
    program: str
    confidence: str
    provenance: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    supersedes: str = ""
    rule_version: str = MEMORY_RULE_VERSION
    limitations: str = "advisory research memory; not evidence"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "state": self.state,
            "subject_key": self.subject_key, "text": self.text,
            "category": self.category, "agent": self.agent,
            "target": self.target, "program": self.program,
            "confidence": self.confidence,
            "provenance": dict(self.provenance),
            "created_at": self.created_at, "updated_at": self.updated_at,
            "supersedes": self.supersedes,
            "rule_version": self.rule_version,
            "limitations": self.limitations,
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "MemoryItem":
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in row.items() if k in known})


def make_item(
    *,
    kind: str,
    state: str,
    subject_key: str,
    text: str,
    category: str,
    agent: str = "",
    target: str = "",
    program: str = "",
    confidence: str = "not_evaluated",
    provenance_job: str = "",
    provenance_source: str = "",
    provenance_refs: Iterable[str] = (),
    supersedes: str = "",
    limitations: str = "",
    now: str | None = None,
) -> MemoryItem:
    """Build one validated memory item.  Provenance is mandatory."""
    if kind not in MEMORY_KINDS:
        raise ValueError(f"unknown memory kind: {kind!r}")
    if state not in MEMORY_STATES:
        raise ValueError(f"unknown memory state: {state!r}")
    subject = scrub_text(subject_key, MAX_SUBJECT)
    if not subject:
        raise ValueError("memory item requires a subject_key")
    provenance_source = scrub_text(provenance_source, 80)
    if not provenance_job or not provenance_source:
        raise ValueError("memory item requires provenance (job + source)")
    refs = [scrub_text(r, 120) for r in provenance_refs if str(r).strip()][:8]
    stamp = now or utcnow()
    provenance = {
        "job_id": scrub_text(provenance_job, 80),
        "source": provenance_source,
        "refs": refs,
        "created_at": stamp,
    }
    clean = scrub_text(text)
    if not clean:
        raise ValueError("memory item requires text")
    return MemoryItem(
        id=memory_id(kind, category, target, subject),
        kind=kind, state=state, subject_key=subject, text=clean,
        category=scrub_text(category, 40), agent=scrub_text(agent, 60),
        target=scrub_text(target, 120), program=scrub_text(program, 120),
        confidence=scrub_text(confidence, 40),
        provenance=provenance, created_at=stamp, updated_at=stamp,
        supersedes=scrub_text(supersedes, 40),
        limitations=scrub_text(limitations, 200)
        or "advisory research memory; not evidence",
    )


class MemoryStore:
    """Append-only JSONL memory with fold-by-id reads.

    Failure model: any OSError on read/write raises
    ``MemoryUnavailable`` (fail closed for writes, honest for reads) —
    callers degrade to deterministic behavior without inventing memory.
    """

    def __init__(self, base_dir: str | Path | None = None):
        self.base = Path(base_dir) if base_dir else runtime_base_dir()
        self.path = self.base / "memory.jsonl"

    def append(self, items: list[MemoryItem]) -> int:
        """Persist new item heads (deduped against current heads);
        returns how many rows were actually written."""
        if not items:
            return 0
        try:
            self.base.mkdir(parents=True, exist_ok=True)
            heads = {item.id: item for item in self.heads()}
            fresh = [item for item in items
                     if should_append(heads.get(item.id), item)]
            if not fresh:
                return 0
            with open(self.path, "a", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                written = 0
                for item in fresh:
                    fh.write(json.dumps(item.to_dict(), sort_keys=True) + "\n")
                    written += 1
                fh.flush()
                os.fsync(fh.fileno())
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            return written
        except (OSError, ValueError) as exc:
            raise MemoryUnavailable(
                f"memory store unavailable: {exc.__class__.__name__}"
            ) from exc

    def all_raw(self) -> tuple[list[MemoryItem], int]:
        """Full append history (order preserved) + corrupt-line count."""
        if not self.path.exists():
            return [], 0
        rows: list[MemoryItem] = []
        corrupt = 0
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(MemoryItem.from_dict(json.loads(line)))
                    except (ValueError, TypeError):
                        corrupt += 1
        except OSError as exc:
            raise MemoryUnavailable(
                f"memory store unavailable: {exc.__class__.__name__}"
            ) from exc
        return rows, corrupt

    def heads(self) -> list[MemoryItem]:
        """Fold append history to current heads (id -> last row wins)."""
        rows, _ = self.all_raw()
        by_id: dict[str, MemoryItem] = {}
        for row in rows:
            by_id[row.id] = row
        return list(by_id.values())

    def query(
        self,
        *,
        category: str = "",
        target: str = "",
        program: str = "",
        kinds: tuple[str, ...] | None = None,
        states: tuple[str, ...] | None = None,
        limit: int = 12,
    ) -> list[MemoryItem]:
        """Deterministic bounded retrieval for a new research job."""
        limit = max(0, int(limit))
        out: list[MemoryItem] = []
        for item in self.heads():
            if category and item.category != category:
                continue
            if target and item.target and item.target != target:
                continue
            if program and item.program and item.program != program:
                continue
            if kinds and item.kind not in kinds:
                continue
            if states and item.state not in states:
                continue
            out.append(item)
        out.sort(key=lambda i: (-_STATE_RANK.get(i.state, 0),
                                i.created_at or "", i.id))
        return out[:limit] if limit else []

    def stats(self, items: list[MemoryItem] | None = None) -> dict[str, int]:
        rows = self.heads() if items is None else items
        counts = {state: 0 for state in MEMORY_STATES}
        for item in rows:
            if item.state in counts:
                counts[item.state] += 1
        counts["total"] = len(rows)
        return counts


def should_append(head: MemoryItem | None, new: MemoryItem) -> bool:
    """Dedup rule: identical head is skipped; legitimate evolution and
    provenance changes append (readers keep the newest head)."""
    if head is None:
        return True
    if head.state == new.state and head.text == new.text \
            and head.provenance.get("job_id") == new.provenance.get("job_id"):
        return False
    if head.state == new.state:
        # same-state refresh only when provenance grew (new job observed it)
        return head.provenance.get("job_id") != new.provenance.get("job_id")
    transition = (head.state, new.state)
    if transition in _SUPERSEDE_OK:
        return True
    # same-id items must never silently demote research progress
    return False


__all__ = [
    "MEMORY_KINDS",
    "MEMORY_RULE_VERSION",
    "MEMORY_STATES",
    "MemoryItem",
    "MemoryStore",
    "MemoryUnavailable",
    "make_item",
    "memory_id",
    "scrub_text",
    "should_append",
]
