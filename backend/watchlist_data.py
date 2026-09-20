"""backend/watchlist_data.py — read-only data access for the standing CVE
watchlist (Command Center).

Single place for all watchlist-artifact filesystem logic. Backs the
read-only Command Center router (``backend/routers/command_center.py``) with
small, capped, source-aware loaders over the existing local watchlist
artifacts produced by ``ai.research_agent.watchlist`` and its downstream
stages:

- ``ai_data/research/watchlist/<program>/watch-<UTC>.json``   (sweep snapshots)
- ``ai_data/research/watchlist/<program>/delta-*.json``       (delta artifacts)
- ``ai_data/research/watchlist/evidence/<program>/wev-*.json`` (acquired evidence)

READ-ONLY: no writes, no Mongo, no network, no subprocess, no LLM, no
matcher invocation, no target interaction. Deterministic ordering
everywhere; missing values are omitted, never invented. Evidence readiness
is the existing deterministic ``watchlist_evidence_gaps`` projection, not a
new verdict. The conservative evidence vocabulary is preserved verbatim:
match states, readiness states, blockers and gaps are surfaced exactly as
the existing stages produce them and are never upgraded or downgraded here.
Path security: every snapshot/delta/evidence id is validated against a fixed
regex before it is read.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WATCHLIST_ROOT = PROJECT_ROOT / "ai_data" / "research" / "watchlist"

_SNAPSHOT_BASENAME_RE = re.compile(r"^watch-\d{8}T\d{6}Z$")
_DELTA_BASENAME_RE = re.compile(r"^delta-[A-Za-z0-9_.-]+$")
_EVIDENCE_BASENAME_RE = re.compile(r"^wev-[0-9a-f]{16}$")

# Bounded collection caps: the Command Center never loads an unbounded
# history into memory.
DEFAULT_PROGRAM_LIMIT = 24
DEFAULT_CANDIDATE_LIMIT = 200
DEFAULT_ACTIVITY_LIMIT = 40
DEFAULT_SNAPSHOT_SCAN = 60

#: Evidence-gap dimension order is owned by the existing stage; imported
#: lazily so a missing/broken stage degrades to no gap enrichment rather
#: than taking down the page.
MAX_TEXT_CHARS = 240


class WatchlistDataError(ValueError):
    """Malformed watchlist artifact (caller renders an honest empty state)."""


def watchlist_root() -> Path:
    """Resolve the watchlist data root deterministically.

    Honors the same environment overrides the watchlist CLI/scheduler use:
    ``WATCH_RESEARCH_WATCHLIST_DIR`` (explicit) or ``WATCH_RESEARCH_RESEARCH_DIR``
    (the canonical ``<research_dir>/watchlist``). Relative values resolve
    against the project root. Falls back to the local default.
    """

    override = (os.environ.get("WATCH_RESEARCH_WATCHLIST_DIR") or "").strip()
    if override:
        candidate = Path(override)
        return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
    research = (os.environ.get("WATCH_RESEARCH_RESEARCH_DIR") or "").strip()
    if research:
        candidate = Path(research)
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return candidate / "watchlist"
    return DEFAULT_WATCHLIST_ROOT


def _root(root: object = None) -> Path:
    return Path(root) if root is not None else watchlist_root()


def _text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _upper(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    return _text(value, limit).upper()


def _bounded_list(value: object, limit: int = 24, width: int = 96) -> list[str]:
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


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WatchlistDataError(f"unreadable artifact {path.name}") from exc


def parse_utc(text: object) -> datetime | None:
    """Parse a persisted UTC timestamp into an aware UTC datetime.

    The watchlist stages persist ``created_utc``/``collected_at`` as
    ``YYYY-MM-DDTHH:MM:SSZ``. Returns ``None`` for anything unparseable so a
    malformed stamp never becomes an invented time.
    """

    value = _text(text, 64)
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Program / snapshot discovery (read-only)
# ---------------------------------------------------------------------------


def list_programs(root: object = None) -> list[str]:
    """Programs with at least one persisted sweep snapshot (sorted).

    The watchlist root is discovered from the filesystem; ``evidence`` is a
    sibling artifact directory, not a program.
    """

    base = _root(root)
    if not base.is_dir():
        return []
    out: list[str] = []
    try:
        for entry in sorted(base.iterdir()):
            if not entry.is_dir() or entry.name == "evidence":
                continue
            if _has_snapshot(entry):
                out.append(entry.name)
    except OSError:
        return []
    return out


def _has_snapshot(directory: Path) -> bool:
    try:
        for path in directory.glob("watch-*.json"):
            if _SNAPSHOT_BASENAME_RE.match(path.stem):
                return True
    except OSError:
        return False
    return False


def snapshot_paths(directory: Path) -> list[Path]:
    """Validated snapshot files for one program dir, oldest first."""

    try:
        paths = sorted(
            p for p in directory.glob("watch-*.json")
            if _SNAPSHOT_BASENAME_RE.match(p.stem)
        )
    except OSError:
        return []
    return paths


def read_snapshots(directory: Path, limit: int = DEFAULT_SNAPSHOT_SCAN) -> list[dict]:
    """Bounded oldest-first list of valid persisted snapshots.

    Only the newest ``limit`` files are parsed (the Command Center never
    needs the full history); the returned list is still oldest-first.
    """

    paths = snapshot_paths(directory)
    if limit and limit > 0:
        paths = paths[-limit:]
    out: list[dict] = []
    for path in paths:
        try:
            payload = _read_json(path)
        except WatchlistDataError:
            continue
        if isinstance(payload, Mapping) and payload.get("snapshot_id"):
            out.append(dict(payload))
    return out


# ---------------------------------------------------------------------------
# Candidate / program projections
# ---------------------------------------------------------------------------


def _match_state_counts(snapshot: Mapping) -> dict:
    counts: dict[str, int] = {}
    raw = snapshot.get("match_state_counts")
    if isinstance(raw, Mapping):
        for key, value in raw.items():
            try:
                counts[_upper(key, 32)] = int(value)
            except (TypeError, ValueError):
                continue
        return dict(sorted(counts.items()))
    for entry in _entries(snapshot):
        state = _upper(entry.get("match_state"), 32) or "UNKNOWN"
        counts[state] = counts.get(state, 0) + 1
    return dict(sorted(counts.items()))


def _delta_counts(snapshot: Mapping) -> dict:
    counts = {"NEW": 0, "CHANGED": 0, "UNCHANGED": 0}
    raw = snapshot.get("delta_counts")
    if isinstance(raw, Mapping):
        for key in counts:
            try:
                counts[key] = int(raw.get(key, 0))
            except (TypeError, ValueError):
                counts[key] = 0
        return counts
    for entry in _entries(snapshot):
        delta = _upper(entry.get("delta"), 16) or "UNCHANGED"
        if delta in counts:
            counts[delta] += 1
    return counts


def _entries(snapshot: Mapping) -> list[Mapping]:
    raw = snapshot.get("entries")
    if not isinstance(raw, (list, tuple)):
        return []
    return [entry for entry in raw if isinstance(entry, Mapping)]


def _gap_for(entry: Mapping) -> dict:
    """Existing deterministic evidence-gap projection for one candidate."""

    try:
        from ai.research_agent.watchlist_evidence_gaps import analyze_candidate

        return analyze_candidate(entry)
    except Exception:
        return {}


def _strongest_match_value(entry: Mapping, strongest_type: str) -> str:
    """Value of the strongest observed match row (real matcher output only)."""

    rows = entry.get("match_rows")
    if not isinstance(rows, (list, tuple)):
        return ""
    ordered = [row for row in rows if isinstance(row, Mapping)]
    for row in ordered:
        if _upper(row.get("match_type"), 32) == strongest_type:
            return _text(row.get("matched_value"), 128)
    if ordered:
        return _text(ordered[0].get("matched_value"), 128)
    return ""


def _candidate_view(entry: Mapping, snapshot_at: datetime | None) -> dict:
    gap = _gap_for(entry)
    queue = entry.get("queue") if isinstance(entry.get("queue"), Mapping) else {}
    dimensions = []
    for dimension in gap.get("dimensions") or []:
        if not isinstance(dimension, Mapping):
            continue
        dimensions.append({
            "name": _upper(dimension.get("evidence_type"), 48),
            "state": _upper(dimension.get("state"), 24),
            "reason": _text(dimension.get("reason"), 160),
            "strategy": _text(dimension.get("acquisition_strategy"), 120),
        })
    acquisition_plan = []
    for step in gap.get("acquisition_plan") or []:
        if not isinstance(step, Mapping):
            continue
        acquisition_plan.append({
            "evidence_type": _upper(step.get("evidence_type"), 48),
            "strategy": _text(step.get("acquisition_strategy"), 120),
        })
    strongest_type = _upper(entry.get("strongest_match_type"), 32)
    return {
        "cve_id": _upper(entry.get("cve_id"), 64),
        "program": _text(entry.get("program"), 64),
        "match_state": _upper(entry.get("match_state"), 32) or "UNKNOWN",
        "confidence": _upper(entry.get("confidence"), 16) or "NONE",
        "strongest_match_type": strongest_type,
        "strongest_match_value": _strongest_match_value(entry, strongest_type),
        "matched_component": _text(entry.get("matched_component"), 128),
        "matched_version": _text(entry.get("matched_version"), 128),
        "matched_parameter": _text(entry.get("matched_parameter"), 128),
        "match_summary": _text(entry.get("match_summary"), 240),
        "research_status": _upper(entry.get("research_status"), 40),
        "version_state": _upper(entry.get("version_state"), 32) or "UNKNOWN",
        "version_association_state": _upper(
            entry.get("version_association_state"), 48
        ),
        "version_association_reason": _text(
            entry.get("version_association_reason"), 200
        ),
        "remaining_blockers": _bounded_list(entry.get("remaining_blockers")),
        "resolved_blockers": _bounded_list(entry.get("resolved_blockers")),
        "missing": _bounded_list(entry.get("missing"), width=64),
        "match_row_count": int(entry.get("match_row_count") or 0),
        "delta": _upper(entry.get("delta"), 16) or "UNCHANGED",
        "queue_present": bool(queue.get("present")),
        "queue_relevance": _upper(queue.get("relevance"), 32) or "UNKNOWN",
        "queue_priority_class": _upper(queue.get("priority_class"), 40),
        "queue_score": int(queue.get("queue_score") or 0),
        "evidence_state": _upper(gap.get("evidence_state"), 32),
        "finding_readiness": _upper(gap.get("finding_readiness"), 32)
        or "UNKNOWN",
        "gap_dimensions": dimensions,
        "gap_present": _bounded_list(gap.get("present"), width=48),
        "gap_partial": _bounded_list(gap.get("partial"), width=48),
        "gap_missing": _bounded_list(gap.get("missing"), width=48),
        "gap_not_applicable": _bounded_list(gap.get("not_applicable"), width=48),
        "acquisition_plan": acquisition_plan,
        "snapshot_at": snapshot_at,
    }


def _snapshot_created(snapshot: Mapping) -> datetime | None:
    return parse_utc(snapshot.get("created_utc"))


def _readiness_counts(snapshot: Mapping) -> dict:
    """Aggregate deterministic evidence readiness for every candidate."""

    try:
        from ai.research_agent.watchlist_evidence_gaps import analyze_snapshot

        counts = analyze_snapshot(snapshot).get("readiness_counts") or {}
    except Exception:
        return {}
    return {
        _upper(key, 40): int(value)
        for key, value in counts.items()
        if isinstance(value, int)
    }


def _latest_changes(previous: Mapping | None, current: Mapping | None) -> list[dict]:
    """Non-UNCHANGED semantic changes between the two newest snapshots."""

    if not previous or not current:
        return []
    try:
        from ai.research_agent.watchlist_delta import compare_snapshots

        result = compare_snapshots(previous, current)
    except Exception:
        return []
    out = []
    for change in result.get("changes") or []:
        if not isinstance(change, Mapping):
            continue
        change_type = _upper(change.get("change_type"), 32)
        if change_type == "UNCHANGED":
            continue
        out.append({
            "cve_id": _upper(change.get("cve_id"), 64),
            "change_type": change_type,
        })
        if len(out) >= 24:
            break
    return out


def program_view(
    program: str,
    directory: Path,
    *,
    candidate_limit: int = DEFAULT_CANDIDATE_LIMIT,
) -> dict:
    """One program's latest watchlist state + candidates (read-only)."""

    snapshots = read_snapshots(directory)
    snapshot_count = len(snapshot_paths(directory))
    program_name = _text(program, 64)
    if not snapshots:
        return {
            "program": program_name,
            "available": False,
            "snapshot_id": "",
            "created_utc": None,
            "previous_snapshot_id": "",
            "cve_count": 0,
            "snapshot_count": 0,
            "delta_counts": {"NEW": 0, "CHANGED": 0, "UNCHANGED": 0},
            "match_state_counts": {},
            "readiness_counts": {},
            "latest_changes": [],
            "candidates": [],
        }
    current = snapshots[-1]
    if current.get("program"):
        program_name = _text(current.get("program"), 64)
    previous = snapshots[-2] if len(snapshots) > 1 else None
    created_at = _snapshot_created(current)
    candidates = [
        _candidate_view(entry, created_at)
        for entry in _entries(current)[: max(candidate_limit, 0)]
    ]
    return {
        "program": program_name,
        "available": True,
        "snapshot_id": _text(current.get("snapshot_id"), 32),
        "created_utc": created_at,
        "previous_snapshot_id": _text(current.get("previous_snapshot_id"), 32),
        "cve_count": len(_entries(current)),
        "snapshot_count": snapshot_count,
        "delta_counts": _delta_counts(current),
        "match_state_counts": _match_state_counts(current),
        "readiness_counts": _readiness_counts(current),
        "latest_changes": _latest_changes(previous, current),
        "candidates": candidates,
    }


def overview(
    root: object = None,
    *,
    program: str | None = None,
    candidate_limit: int = DEFAULT_CANDIDATE_LIMIT,
) -> dict:
    """Command Center watchlist payload (deterministic, bounded, read-only).

    ``available`` is ``False`` when no watchlist root/snapshot exists; the
    caller renders an honest empty state instead of invented numbers.
    """

    base = _root(root)
    root_exists = base.is_dir()
    programs = list_programs(base)
    wanted = _text(program, 64).lower()
    if wanted:
        programs = [name for name in programs if name.lower() == wanted]
    programs = programs[:DEFAULT_PROGRAM_LIMIT]

    views = [program_view(name, base / name, candidate_limit=candidate_limit)
             for name in programs]

    totals = {
        "programs": len(views),
        "cves": sum(view["cve_count"] for view in views),
        "delta": {"NEW": 0, "CHANGED": 0, "UNCHANGED": 0},
        "match_state": {},
        "readiness": {},
    }
    for view in views:
        for key in totals["delta"]:
            totals["delta"][key] += view["delta_counts"].get(key, 0)
        for key, value in view["match_state_counts"].items():
            totals["match_state"][key] = totals["match_state"].get(key, 0) + value
        for key, value in view["readiness_counts"].items():
            totals["readiness"][key] = totals["readiness"].get(key, 0) + value
    totals["match_state"] = dict(sorted(totals["match_state"].items()))
    totals["readiness"] = dict(sorted(totals["readiness"].items()))

    return {
        "available": bool(views),
        "root_available": root_exists,
        "programs": views,
        "totals": totals,
    }


# ---------------------------------------------------------------------------
# Recent activity (real artifacts only)
# ---------------------------------------------------------------------------


def _snapshot_activities(directory: Path, program: str,
                         limit: int) -> list[dict]:
    out: list[dict] = []
    for path in snapshot_paths(directory)[-limit:]:
        try:
            payload = _read_json(path)
        except WatchlistDataError:
            continue
        if not isinstance(payload, Mapping):
            continue
        at = _snapshot_created(payload)
        delta = _delta_counts(payload)
        cve_count = len(_entries(payload))
        out.append({
            "kind": "WATCHLIST_RUN",
            "source": "Watchlist sweep",
            "program": _text(payload.get("program") or program, 64),
            "ref": _text(payload.get("snapshot_id"), 32),
            "status": "COMPLETED",
            "at": at,
            "detail": (
                f"{cve_count} CVE(s) · NEW {delta['NEW']} · "
                f"CHANGED {delta['CHANGED']} · UNCHANGED {delta['UNCHANGED']}"
            ),
        })
    return out


def _delta_activities(directory: Path, program: str) -> list[dict]:
    out: list[dict] = []
    try:
        paths = sorted(directory.glob("delta-*.json"))
    except OSError:
        return []
    for path in paths:
        if not _DELTA_BASENAME_RE.match(path.stem):
            continue
        try:
            payload = _read_json(path)
        except WatchlistDataError:
            continue
        if not isinstance(payload, Mapping):
            continue
        summary = payload.get("summary") if isinstance(
            payload.get("summary"), Mapping) else {}
        counts = ", ".join(
            f"{_upper(key, 32)} {int(value)}"
            for key, value in sorted(summary.items())
            if isinstance(value, int) and value
        )
        out.append({
            "kind": "WATCHLIST_DELTA",
            "source": "Delta evaluation",
            "program": _text(payload.get("program") or program, 64),
            "ref": _text(payload.get("delta_id"), 64),
            "status": "COMPLETED",
            "at": parse_utc(payload.get("created_utc")),
            "detail": counts or "no meaningful change",
        })
    return out


def _evidence_activities(directory: Path, program: str) -> list[dict]:
    out: list[dict] = []
    try:
        paths = sorted(directory.glob("wev-*.json"))
    except OSError:
        return []
    for path in paths:
        if not _EVIDENCE_BASENAME_RE.match(path.stem):
            continue
        try:
            payload = _read_json(path)
        except WatchlistDataError:
            continue
        if not isinstance(payload, Mapping):
            continue
        out.append({
            "kind": "EVIDENCE_ACQUISITION",
            "source": "Evidence acquisition",
            "program": _text(payload.get("program") or program, 64),
            "ref": _text(path.stem, 64),
            "status": _upper(payload.get("state"), 32) or "UNKNOWN",
            "at": parse_utc(payload.get("collected_at")),
            "detail": (
                f"{_upper(payload.get('evidence_type'), 48) or 'EVIDENCE'} · "
                f"{_upper(payload.get('method'), 24) or 'METHOD'}"
            ),
        })
    return out


def recent_activity(
    root: object = None,
    *,
    limit: int = DEFAULT_ACTIVITY_LIMIT,
) -> list[dict]:
    """Newest-first real watchlist activity (sweeps, deltas, acquisitions).

    Never fabricates an entry: only persisted artifacts produce a row. The
    optional operation/research activity is merged by the router layer.
    """

    base = _root(root)
    items: list[dict] = []
    for program in list_programs(base):
        directory = base / program
        items.extend(_snapshot_activities(directory, program, limit))
        items.extend(_delta_activities(directory, program))
        items.extend(_evidence_activities(base / "evidence" / program, program))
    items.sort(key=lambda item: item.get("at") or datetime.min.replace(
        tzinfo=timezone.utc), reverse=True)
    return items[: max(limit, 0)]


__all__ = [
    "PROJECT_ROOT",
    "DEFAULT_WATCHLIST_ROOT",
    "WatchlistDataError",
    "watchlist_root",
    "parse_utc",
    "list_programs",
    "snapshot_paths",
    "read_snapshots",
    "program_view",
    "overview",
    "recent_activity",
]
