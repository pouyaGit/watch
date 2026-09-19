"""Operational standing CVE watchlist over the existing local corpus (job).

This module is one small operational job, not a new research architecture. It
answers, for one program (default ``dell``):

    "What does the UNCHANGED R30.1 asset/CVE matcher currently report for every
     CVE the existing R18 research queue already associates with this program,
     and what changed since the previous persisted snapshot?"

Existing components only (composed read-only, never reimplemented):

- CVE discovery: the R18 research queue (``backend.research_data.
  list_research_queue``) is the existing authority for "CVE x program
  candidates with deterministic positive relevance". Queue rows for the
  requested program are deduplicated into a sorted CVE list. Nothing else
  decides relevance.
- Matching: one ``backend.asset_cve_matching.build_matches(cve=..., program=...)``
  call per discovered CVE. The matcher, component inference, version ownership,
  aliases and evidence semantics are untouched; the expensive unfiltered
  ``build_matches(program=...)`` sweep is never used.
- Research state: the queue row for the same CVE/program is carried into the
  snapshot (relevance/queue scores, blockers) so a queue-level change is part
  of the snapshot identity.
- Persistence: the existing ``ai/research_agent/storage.py`` conventions
  (atomic temp-file + ``os.replace``; never overwrite an existing artifact)
  applied to ``<snapshot_root>/<program>/watch-<UTC>.json``. Historical
  snapshots are immutable; each run adds at most one new file.

Delta semantics (deterministic, timestamp-free identity):

- Every entry carries a ``fingerprint`` derived only from the meaningful
  matcher/queue fields (never the run timestamp).
- An entry is ``NEW`` when the CVE was not present in the previous persisted
  snapshot, ``CHANGED`` when its fingerprint differs, ``UNCHANGED`` otherwise.
- A repeated identical run therefore reports zero NEW/CHANGED regardless of
  the timestamp; a same-timestamp rerun is a replay (no write).

Hard boundaries encoded here:

- Read-only with respect to sources: the default loaders read the local KB
  corpus and the existing matcher (whose inventory read path is read-only).
  This module never writes Mongo, never performs target interaction, DNS,
  HTTP, LLM, subprocess or scanning, and never fabricates evidence.
- No new evidence vocabulary: ``match_state`` is the existing R30.1 state
  (CONFIRMED/SUPPORTED/WEAK/UNKNOWN), confidence and blockers are the existing
  matcher fields, research state is the existing R18 queue row.
- Research-only: every snapshot and outcome forces ``NOT_CONFIRMED`` and is
  advisory. A watchlist entry is never a vulnerability finding.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

RULE_VERSION = "watchlist-1"
SNAPSHOT_VERSION = "watchlist-1"

DEFAULT_PROGRAM = "dell"
DEFAULT_SNAPSHOT_ROOT = Path("ai_data/research/watchlist")

MAX_CVES = 100
MAX_MATCH_ROWS = 16
MAX_BLOCKERS = 8
MAX_REASONS = 8
MAX_TEXT_CHARS = 240
MAX_VALUE_CHARS = 128
MAX_REASON_CHARS = 160

# Workflow status vocabulary for one run (never a security classification).
STATUS_COMPLETED = "COMPLETED"
STATUS_REPLAYED = "REPLAYED"
STATUS_NO_CVES = "NO_CVES"
STATUS_ERROR = "ERROR"

# Bounded delta vocabulary.
DELTA_NEW = "NEW"
DELTA_CHANGED = "CHANGED"
DELTA_UNCHANGED = "UNCHANGED"
DELTA_CLASSES: tuple[str, ...] = (DELTA_NEW, DELTA_CHANGED, DELTA_UNCHANGED)

REASON_INVALID_PROGRAM = "INVALID_PROGRAM"
REASON_NO_DISCOVERED_CVES = "NO_DISCOVERED_CVES"
REASON_WRITE_FAILED = "WRITE_FAILED"

_SNAPSHOT_ID_RE = re.compile(r"^watch-[0-9]{8}T[0-9]{6}Z$")
_SAFE_SEGMENT_RE = re.compile(r"[^a-z0-9_-]+")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

_EMPTY_MATCH_SUMMARY = "No deterministic asset match."
_EMPTY_RESEARCH_STATUS = "NOT YET SUFFICIENT"

QueueLoader = Callable[[], object]
MatchLoader = Callable[[str], object]

#: Entry fields that define the deterministic snapshot identity. Order is
#: irrelevant (canonical JSON); a new meaningful field must be added here.
_FINGERPRINT_FIELDS: tuple[str, ...] = (
    "cve_id",
    "program",
    "match_state",
    "confidence",
    "strongest_match_type",
    "strongest_confidence",
    "matched_component",
    "matched_version",
    "matched_parameter",
    "match_summary",
    "research_status",
    "version_state",
    "version_association_state",
    "version_association_reason",
    "resolved_blockers",
    "remaining_blockers",
    "missing",
    "match_row_count",
    "match_rows",
    "queue",
)


# ---------------------------------------------------------------------------
# Bounded deterministic helpers (mirrors the existing module conventions)
# ---------------------------------------------------------------------------


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    text = _CONTROL_RE.sub(" ", str(value if value is not None else ""))
    return " ".join(text.split())[:limit]


def _upper(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    return _text(value, limit).upper()


def _block(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _bounded_list(value: object, limit: int, width: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = _text(item, width)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _canonical(payload: object) -> str:
    return json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def _digest(payload: object) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[:16]


def _atomic_write_text(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, dest)


def _program_segment(program: str) -> str:
    return _SAFE_SEGMENT_RE.sub("_", program.lower()).strip("_") or "unknown"


# ---------------------------------------------------------------------------
# Default read-only loaders (existing authorities; no new logic)
# ---------------------------------------------------------------------------


def default_queue_loader() -> list[dict]:
    """Existing R18 research queue rows (read-only; ``[]`` when unavailable)."""

    try:
        from backend import research_data as rd

        result = rd.list_research_queue(limit=MAX_CVES, offset=0)
    except Exception:
        return []
    items = result.get("items") if isinstance(result, Mapping) else None
    return [dict(item) for item in _mapping_items(items)]


def default_match_loader(program: str) -> MatchLoader:
    """Existing R30.1 matcher bound to one program (read-only; fail-soft)."""

    def load(cve: str) -> dict:
        try:
            from backend import asset_cve_matching

            result = asset_cve_matching.build_matches(
                cve=str(cve), program=str(program)
            )
        except Exception:
            return {}
        return result if isinstance(result, Mapping) else {}

    return load


# ---------------------------------------------------------------------------
# Discovery (existing queue rows -> sorted CVE list for one program)
# ---------------------------------------------------------------------------


def discover_cves(queue_rows: object, program: str) -> list[str]:
    """Sorted, deduplicated CVE ids the R18 queue associates with ``program``."""

    program_text = _text(program, 64)
    out: list[str] = []
    if not program_text:
        return out
    for row in _mapping_items(queue_rows):
        if _text(row.get("program"), 64) != program_text:
            continue
        cve = _upper(row.get("cve"), 64)
        if cve and cve not in out:
            out.append(cve)
    return sorted(out)


def queue_rows_by_cve(queue_rows: object, program: str) -> dict[str, dict]:
    """Bounded R18 queue state per CVE for ``program`` (first row wins)."""

    program_text = _text(program, 64)
    out: dict[str, dict] = {}
    for row in _mapping_items(queue_rows):
        if _text(row.get("program"), 64) != program_text:
            continue
        cve = _upper(row.get("cve"), 64)
        if not cve or cve in out:
            continue
        out[cve] = _queue_block(row)
    return out


def _queue_block(row: Mapping) -> dict:
    return {
        "present": True,
        "queue_id": _text(row.get("queue_id"), 32),
        "relevance": _upper(row.get("relevance"), 32) or "UNKNOWN",
        "relevance_score": _int(row.get("relevance_score")),
        "priority_class": _upper(row.get("priority_class"), 40),
        "priority_score": _int(row.get("priority_score")),
        "queue_score": _int(row.get("queue_score")),
        "blockers": _bounded_list(row.get("blockers"), MAX_BLOCKERS, 96),
        "reasons": _bounded_list(row.get("reasons"), MAX_REASONS, 160),
        "unknown_factors": _bounded_list(
            row.get("unknown_factors"), MAX_BLOCKERS, 96
        ),
    }


def _empty_queue_block() -> dict:
    return {
        "present": False,
        "queue_id": "",
        "relevance": "UNKNOWN",
        "relevance_score": 0,
        "priority_class": "",
        "priority_score": 0,
        "queue_score": 0,
        "blockers": [],
        "reasons": [],
        "unknown_factors": [],
    }


# ---------------------------------------------------------------------------
# Entry construction and deterministic identity
# ---------------------------------------------------------------------------


def _program_item(data: object, program: str) -> Mapping | None:
    for item in _mapping_items(_block(data).get("items")):
        if _text(item.get("program"), 64) == program:
            return item
    return None


def _match_rows(item: Mapping) -> list[dict]:
    rows: list[dict] = []
    for row in _mapping_items(item.get("all_matches")):
        rows.append(
            {
                "match_id": _text(row.get("match_id"), 32),
                "match_type": _upper(row.get("match_type"), 32),
                "matched_value": _text(row.get("matched_value"), MAX_VALUE_CHARS),
                "confidence": _upper(row.get("confidence"), 16) or "NONE",
            }
        )
    rows.sort(
        key=lambda entry: (
            entry["match_type"],
            entry["matched_value"],
            entry["match_id"],
        )
    )
    return rows[:MAX_MATCH_ROWS]


def build_entry(
    cve: str, program: str, item: object, queue_row: object = None
) -> dict:
    """One bounded, deterministic watchlist entry for one CVE/program pair."""

    cve_text = _upper(cve, 64)
    program_text = _text(program, 64)
    queue = (
        _queue_block(queue_row)
        if isinstance(queue_row, Mapping)
        else _empty_queue_block()
    )
    entry: dict = {
        "cve_id": cve_text,
        "program": program_text,
        "match_state": "UNKNOWN",
        "confidence": "NONE",
        "strongest_match_type": "",
        "strongest_confidence": "",
        "matched_component": "",
        "matched_version": "",
        "matched_parameter": "",
        "match_summary": _EMPTY_MATCH_SUMMARY,
        "research_status": _EMPTY_RESEARCH_STATUS,
        "version_state": "UNKNOWN",
        "version_association_state": "",
        "version_association_reason": "",
        "resolved_blockers": [],
        "remaining_blockers": [],
        "missing": [],
        "match_row_count": 0,
        "match_rows": [],
        "queue": queue,
    }
    if isinstance(item, Mapping) and item:
        rows = _match_rows(item)
        entry.update(
            {
                "match_state": _upper(item.get("asset_match_state"), 32)
                or "UNKNOWN",
                "confidence": _upper(item.get("asset_match_confidence"), 16)
                or "NONE",
                "strongest_match_type": _upper(
                    item.get("strongest_match_type"), 32
                ),
                "strongest_confidence": _upper(
                    item.get("strongest_confidence"), 16
                ),
                "matched_component": _text(
                    item.get("matched_component"), MAX_VALUE_CHARS
                ),
                "matched_version": _text(
                    item.get("matched_version"), MAX_VALUE_CHARS
                ),
                "matched_parameter": _text(
                    item.get("matched_parameter"), MAX_VALUE_CHARS
                ),
                "match_summary": _text(item.get("match_summary"))
                or _EMPTY_MATCH_SUMMARY,
                "research_status": _upper(item.get("research_status"), 40)
                or _EMPTY_RESEARCH_STATUS,
                "version_state": _upper(item.get("version_state"), 32)
                or "UNKNOWN",
                "version_association_state": _upper(
                    item.get("version_association_state"), 48
                ),
                "version_association_reason": _text(
                    item.get("version_association_reason"), MAX_REASON_CHARS
                ),
                "resolved_blockers": _bounded_list(
                    item.get("resolved_blockers"), MAX_BLOCKERS, 96
                ),
                "remaining_blockers": _bounded_list(
                    item.get("remaining_blockers"), MAX_BLOCKERS, 96
                ),
                "missing": _bounded_list(item.get("missing"), MAX_BLOCKERS, 64),
                "match_row_count": len(
                    [row for row in _mapping_items(item.get("all_matches"))]
                ),
                "match_rows": rows,
            }
        )
    entry["fingerprint"] = entry_fingerprint(entry)
    return entry


def entry_fingerprint(entry: Mapping) -> str:
    """Timestamp-free deterministic identity of the meaningful entry fields."""

    payload = {key: entry.get(key) for key in _FINGERPRINT_FIELDS}
    return "wf-" + _digest(payload)


# ---------------------------------------------------------------------------
# Snapshot persistence (existing storage conventions: atomic, no overwrite)
# ---------------------------------------------------------------------------


def utc_moment(now: datetime | None = None) -> datetime:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def snapshot_id_for(now: datetime | None = None) -> str:
    return "watch-" + utc_moment(now).strftime("%Y%m%dT%H%M%SZ")


def utc_text_for(now: datetime | None = None) -> str:
    return utc_moment(now).strftime("%Y-%m-%dT%H:%M:%SZ")


def snapshot_dir(snapshot_root: object, program: str) -> Path:
    return Path(snapshot_root) / _program_segment(program)


def snapshot_path(
    snapshot_root: object, program: str, snapshot_id: str
) -> Path:
    safe_id = _text(snapshot_id, 32)
    if not _SNAPSHOT_ID_RE.match(safe_id):
        raise ValueError(f"invalid snapshot id: {snapshot_id!r}")
    return snapshot_dir(snapshot_root, program) / f"{safe_id}.json"


def list_snapshots(snapshot_root: object, program: str) -> list[dict]:
    """Persisted snapshots for one program, oldest first (read-only)."""

    directory = snapshot_dir(snapshot_root, program)
    if not directory.is_dir():
        return []
    out: list[dict] = []
    for path in sorted(directory.glob("watch-*.json")):
        if not _SNAPSHOT_ID_RE.match(path.stem):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(payload, Mapping) and payload.get("snapshot_id"):
            out.append(dict(payload))
    out.sort(key=lambda item: _text(item.get("snapshot_id"), 32))
    return out


def load_previous_snapshot(
    snapshot_root: object, program: str, snapshot_id: str
) -> dict | None:
    """Latest persisted snapshot at or before ``snapshot_id`` (or ``None``)."""

    previous: dict | None = None
    for payload in list_snapshots(snapshot_root, program):
        if _text(payload.get("snapshot_id"), 32) <= snapshot_id:
            previous = payload
    return previous


def write_snapshot(
    payload: Mapping, snapshot_root: object, program: str
) -> tuple[Path, bool]:
    """Atomic, no-overwrite snapshot write; returns ``(path, written)``."""

    dest = snapshot_path(snapshot_root, program, _text(payload.get("snapshot_id"), 32))
    if dest.exists():
        return dest, False
    _atomic_write_text(
        dest, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    )
    return dest, True


# ---------------------------------------------------------------------------
# Delta classification (previous persisted snapshot only)
# ---------------------------------------------------------------------------


def classify_deltas(entries: list[dict], previous: object) -> dict[str, int]:
    """Set ``entry['delta']`` from the previous snapshot's fingerprints."""

    previous_entries: dict[str, Mapping] = {}
    for entry in _mapping_items(_block(previous).get("entries")):
        cve = _upper(entry.get("cve_id"), 64)
        if cve and cve not in previous_entries:
            previous_entries[cve] = entry
    counts = {kind: 0 for kind in DELTA_CLASSES}
    for entry in entries:
        previous_entry = previous_entries.get(entry["cve_id"])
        if previous_entry is None:
            delta = DELTA_NEW
        elif _text(previous_entry.get("fingerprint"), 32) == entry["fingerprint"]:
            delta = DELTA_UNCHANGED
        else:
            delta = DELTA_CHANGED
        entry["delta"] = delta
        counts[delta] += 1
    return counts


# ---------------------------------------------------------------------------
# Watchlist run
# ---------------------------------------------------------------------------


def build_snapshot(
    program: str,
    entries: list[dict],
    *,
    snapshot_id: str,
    created_utc: str,
    previous_snapshot_id: str = "",
) -> dict:
    state_counts: dict[str, int] = {}
    for entry in entries:
        state = _text(entry.get("match_state"), 32) or "UNKNOWN"
        state_counts[state] = state_counts.get(state, 0) + 1
    delta_counts = {kind: 0 for kind in DELTA_CLASSES}
    for entry in entries:
        delta_counts[entry["delta"]] = delta_counts.get(entry["delta"], 0) + 1
    return {
        "watchlist_version": SNAPSHOT_VERSION,
        "rule_version": RULE_VERSION,
        "snapshot_id": snapshot_id,
        "created_utc": created_utc,
        "program": program,
        "cve_count": len(entries),
        "match_state_counts": dict(sorted(state_counts.items())),
        "delta_counts": delta_counts,
        "previous_snapshot_id": previous_snapshot_id,
        "entries": entries,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def run_watchlist(
    program: str = DEFAULT_PROGRAM,
    *,
    snapshot_root: object = None,
    queue_loader: QueueLoader | None = None,
    match_loader: MatchLoader | None = None,
    now: datetime | None = None,
    write: bool = False,
    limit: int = MAX_CVES,
) -> dict:
    """One bounded watchlist run for one program.

    Discovers CVEs from the existing R18 queue, calls the existing matcher
    once per CVE, classifies NEW/CHANGED/UNCHANGED against the previous
    persisted snapshot and (only with ``write``) persists one atomic
    timestamped snapshot. Never mutates any source.
    """

    started = time.monotonic()
    program_text = _text(program, 64)
    root = (
        Path(snapshot_root) if snapshot_root is not None else DEFAULT_SNAPSHOT_ROOT
    )
    snapshot_id = snapshot_id_for(now)
    created_utc = utc_text_for(now)
    outcome: dict = {
        "rule_version": RULE_VERSION,
        "watchlist_version": SNAPSHOT_VERSION,
        "status": STATUS_ERROR,
        "reason": "",
        "program": program_text,
        "snapshot_id": snapshot_id,
        "created_utc": created_utc,
        "snapshot_path": "",
        "previous_snapshot_id": "",
        "written": False,
        "cve_count": 0,
        "delta_counts": {kind: 0 for kind in DELTA_CLASSES},
        "match_state_counts": {},
        "timings": {"total_ms": 0.0, "per_cve_ms": {}},
        "snapshot": None,
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }
    if not program_text:
        outcome["reason"] = REASON_INVALID_PROGRAM
        return outcome

    rows = queue_loader() if queue_loader is not None else default_queue_loader()
    cap = max(_int(limit, MAX_CVES), 0)
    cves = discover_cves(rows, program_text)[:cap]
    if not cves:
        outcome["status"] = STATUS_NO_CVES
        outcome["reason"] = REASON_NO_DISCOVERED_CVES
        outcome["timings"]["total_ms"] = round(
            (time.monotonic() - started) * 1000, 1
        )
        return outcome

    queue_by_cve = queue_rows_by_cve(rows, program_text)
    loader = match_loader or default_match_loader(program_text)
    entries: list[dict] = []
    per_cve_ms: dict[str, float] = {}
    for cve in cves:
        cve_started = time.monotonic()
        try:
            data = loader(cve)
        except Exception:
            data = {}
        item = _program_item(data, program_text)
        entries.append(
            build_entry(cve, program_text, item, queue_by_cve.get(cve))
        )
        per_cve_ms[cve] = round((time.monotonic() - cve_started) * 1000, 1)
    entries.sort(key=lambda entry: entry["cve_id"])

    previous = load_previous_snapshot(root, program_text, snapshot_id)
    previous_id = (
        _text(_block(previous).get("snapshot_id"), 32) if previous else ""
    )
    delta_counts = classify_deltas(entries, previous)
    snapshot = build_snapshot(
        program_text,
        entries,
        snapshot_id=snapshot_id,
        created_utc=created_utc,
        previous_snapshot_id=previous_id,
    )
    if previous:
        previous_cves = {
            _upper(entry.get("cve_id"), 64)
            for entry in _mapping_items(_block(previous).get("entries"))
        }
        snapshot["missing_from_current"] = sorted(
            cve for cve in previous_cves if cve and cve not in set(cves)
        )

    outcome.update(
        {
            "status": STATUS_COMPLETED,
            "cve_count": len(entries),
            "delta_counts": delta_counts,
            "match_state_counts": snapshot["match_state_counts"],
            "previous_snapshot_id": previous_id,
            "snapshot": snapshot,
            "timings": {
                "total_ms": round((time.monotonic() - started) * 1000, 1),
                "per_cve_ms": per_cve_ms,
            },
        }
    )
    if not write:
        return outcome
    try:
        dest, written = write_snapshot(snapshot, root, program_text)
    except (OSError, ValueError):
        outcome["status"] = STATUS_ERROR
        outcome["reason"] = REASON_WRITE_FAILED
        return outcome
    outcome["snapshot_path"] = dest.name
    outcome["written"] = written
    if not written:
        outcome["status"] = STATUS_REPLAYED
    return outcome


__all__ = [
    "RULE_VERSION",
    "SNAPSHOT_VERSION",
    "DEFAULT_PROGRAM",
    "DEFAULT_SNAPSHOT_ROOT",
    "MAX_CVES",
    "STATUS_COMPLETED",
    "STATUS_REPLAYED",
    "STATUS_NO_CVES",
    "STATUS_ERROR",
    "DELTA_NEW",
    "DELTA_CHANGED",
    "DELTA_UNCHANGED",
    "DELTA_CLASSES",
    "REASON_INVALID_PROGRAM",
    "REASON_NO_DISCOVERED_CVES",
    "REASON_WRITE_FAILED",
    "default_queue_loader",
    "default_match_loader",
    "discover_cves",
    "queue_rows_by_cve",
    "build_entry",
    "entry_fingerprint",
    "snapshot_id_for",
    "snapshot_dir",
    "snapshot_path",
    "list_snapshots",
    "load_previous_snapshot",
    "write_snapshot",
    "classify_deltas",
    "build_snapshot",
    "run_watchlist",
]
