"""Local watchlist delta intelligence (structural comparison only).

Compares two standing CVE watchlist snapshots (see
``ai/research_agent/watchlist.py``) and explains WHAT changed between them.

Pure deterministic structural layer:

- No network, no MongoDB, no LLM, no subprocess, no target interaction.
- No security significance is inferred; no vulnerability confirmation.
- No evidence is invented; only field-level before/after differences.
- Semantic comparison only: ``created_utc``, ``snapshot_id``,
  ``fingerprint``, JSON key ordering and dictionary ordering are ignored.
- Output is deterministic: changes are sorted by ``(cve_id, change_type)``
  and every mapping is rendered with sorted keys by the caller.

Change categories (all preserved per CVE, never collapsed):

- ``NEW_CVE``: CVE exists in current but not previous.
- ``REMOVED_CVE``: CVE exists in previous but not current.
- ``STATE_CHANGED``: ``match_state`` / confirmation-relevant state changed.
- ``MATCH_CHANGED``: match rows, matched version, matched component,
  matched parameter, match type, or equivalent matching evidence changed.
- ``EVIDENCE_CHANGED``: evidence-related fields changed, including
  ``confidence``, ``version_state``, ``version_association_state``,
  ``research_status``, ``resolved_blockers``, ``remaining_blockers``,
  ``missing``, ``strongest_match_type``, ``strongest_confidence``.
- ``BLOCKERS_CHANGED``: blockers changed (may co-occur with
  ``EVIDENCE_CHANGED``; both are preserved).
- ``UNCHANGED``: no meaningful watchlist content changed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

NEW_CVE = "NEW_CVE"
REMOVED_CVE = "REMOVED_CVE"
STATE_CHANGED = "STATE_CHANGED"
MATCH_CHANGED = "MATCH_CHANGED"
EVIDENCE_CHANGED = "EVIDENCE_CHANGED"
BLOCKERS_CHANGED = "BLOCKERS_CHANGED"
UNCHANGED = "UNCHANGED"

CHANGE_TYPES: tuple[str, ...] = (
    NEW_CVE,
    REMOVED_CVE,
    STATE_CHANGED,
    MATCH_CHANGED,
    EVIDENCE_CHANGED,
    BLOCKERS_CHANGED,
    UNCHANGED,
)

# Entry-level keys that are never meaningful content.
IGNORED_ENTRY_KEYS: frozenset[str] = frozenset(
    {
        "fingerprint",
        "delta",
    }
)

# Snapshot-level metadata keys that are never meaningful content.
IGNORED_SNAPSHOT_KEYS: frozenset[str] = frozenset(
    {
        "snapshot_id",
        "created_utc",
        "previous_snapshot_id",
        "cve_count",
        "match_state_counts",
        "delta_counts",
        "missing_from_current",
        "timings",
        "snapshot_path",
        "written",
        "status",
        "reason",
        "watchlist_version",
        "rule_version",
        "advisory",
        "research_only",
        "confirmation_state",
        "program",
        "generated_at",
        "created_at",
        "fingerprint",
    }
)

# Confirmation-relevant state fields (entry level).
STATE_FIELDS: tuple[str, ...] = ("match_state", "confirmation_state")

# Matching-evidence fields (entry level scalars; match_rows handled separately).
MATCH_SCALAR_FIELDS: tuple[str, ...] = (
    "matched_component",
    "matched_version",
    "matched_parameter",
    "match_summary",
    "match_row_count",
)

# Evidence fields (entry level scalars/lists; queue handled separately).
EVIDENCE_SCALAR_FIELDS: tuple[str, ...] = (
    "confidence",
    "version_state",
    "version_association_state",
    "version_association_reason",
    "research_status",
    "strongest_match_type",
    "strongest_confidence",
)

EVIDENCE_LIST_FIELDS: tuple[str, ...] = (
    "resolved_blockers",
    "remaining_blockers",
    "missing",
)

_SNAPSHOT_ID_RE = re.compile(r"^watch-[0-9]{8}T[0-9]{6}Z$")


# ---------------------------------------------------------------------------
# Canonicalization (semantic content, ordering-free)
# ---------------------------------------------------------------------------


def _canonical(value: object) -> str:
    """Deterministic canonical JSON for semantic comparison."""

    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def _normalize_list(value: object) -> list:
    """Order-insensitive normalization for blocker/missing style lists."""

    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return sorted((_canonical(item) for item in value))
    return [_canonical(value)]


def _normalize_match_rows(value: object) -> str:
    """Canonical form of match rows (ordering-free, semantic only)."""

    if not isinstance(value, (list, tuple)):
        return _canonical([])
    rows: list[str] = []
    for item in value:
        if isinstance(item, Mapping):
            rows.append(
                _canonical(
                    {
                        key: item.get(key)
                        for key in (
                            "match_type",
                            "matched_value",
                            "confidence",
                            "match_id",
                        )
                    }
                )
            )
        else:
            rows.append(_canonical(item))
    rows.sort()
    return _canonical(rows)


def _entry_key(entry: Mapping) -> str:
    return str(entry.get("cve_id") or "").strip().upper()


def _entries_by_cve(snapshot: Mapping | None) -> dict[str, Mapping]:
    """Index snapshot entries by upper-cased CVE id (first wins, sorted)."""

    out: dict[str, Mapping] = {}
    if not isinstance(snapshot, Mapping):
        return out
    entries = snapshot.get("entries")
    if not isinstance(entries, (list, tuple)):
        return out
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        cve = _entry_key(entry)
        if cve and cve not in out:
            out[cve] = entry
    return out


def _queue_block(entry: Mapping) -> Mapping:
    queue = entry.get("queue")
    return queue if isinstance(queue, Mapping) else {}


def _queue_canonical(entry: Mapping) -> str:
    return _canonical(dict(_queue_block(entry)))


def _queue_blockers(entry: Mapping) -> list:
    queue = _queue_block(entry)
    blockers = queue.get("blockers")
    if isinstance(blockers, (list, tuple)):
        return [str(item) for item in blockers]
    return []


def _string_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value]


def _public_entry(entry: Mapping) -> dict:
    """Entry content without volatile identity keys (never mutates input)."""

    return {
        key: copy.deepcopy(value)
        for key, value in dict(entry).items()
        if key not in IGNORED_ENTRY_KEYS
    }


# ---------------------------------------------------------------------------
# Per-category comparison
# ---------------------------------------------------------------------------


def _state_details(previous: Mapping, current: Mapping) -> dict:
    diff: dict[str, dict] = {}
    for field in STATE_FIELDS:
        before = previous.get(field)
        after = current.get(field)
        if _canonical(before) != _canonical(after):
            diff[field] = {"before": before, "after": after}
    return diff


def _match_details(previous: Mapping, current: Mapping) -> dict:
    diff: dict[str, dict] = {}
    for field in MATCH_SCALAR_FIELDS:
        before = previous.get(field)
        after = current.get(field)
        if _canonical(before) != _canonical(after):
            diff[field] = {"before": before, "after": after}
    before_rows = _normalize_match_rows(previous.get("match_rows"))
    after_rows = _normalize_match_rows(current.get("match_rows"))
    if before_rows != after_rows:
        diff["match_rows"] = {
            "before": copy.deepcopy(previous.get("match_rows")),
            "after": copy.deepcopy(current.get("match_rows")),
        }
        # Keep scalar row-count diff explicit when it also changed but the
        # rows key already captures the semantic change; the scalar loop
        # above already recorded match_row_count when relevant.
    return diff


def _evidence_details(previous: Mapping, current: Mapping) -> dict:
    diff: dict[str, dict] = {}
    for field in EVIDENCE_SCALAR_FIELDS:
        before = previous.get(field)
        after = current.get(field)
        if _canonical(before) != _canonical(after):
            diff[field] = {"before": before, "after": after}
    for field in EVIDENCE_LIST_FIELDS:
        before = _normalize_list(previous.get(field))
        after = _normalize_list(current.get(field))
        if before != after:
            diff[field] = {
                "before": copy.deepcopy(previous.get(field)),
                "after": copy.deepcopy(current.get(field)),
            }
    if _queue_canonical(previous) != _queue_canonical(current):
        diff["queue"] = {
            "before": copy.deepcopy(dict(_queue_block(previous))),
            "after": copy.deepcopy(dict(_queue_block(current))),
        }
    return diff


def _blocker_set(entry: Mapping) -> list[str]:
    """Combined blocker identity (order-insensitive, deterministic)."""

    combined: list[str] = []
    combined.extend(_string_list(entry.get("resolved_blockers")))
    combined.extend(_string_list(entry.get("remaining_blockers")))
    combined.extend(_string_list(entry.get("blockers")))
    combined.extend(_queue_blockers(entry))
    return sorted(combined)


def _blockers_details(previous: Mapping, current: Mapping) -> dict:
    diff: dict[str, dict] = {}
    for field in ("resolved_blockers", "remaining_blockers", "blockers"):
        before = _normalize_list(previous.get(field))
        after = _normalize_list(current.get(field))
        # Only record fields present on at least one side for "blockers"
        # (a top-level alias that older snapshots may lack entirely).
        if field == "blockers" and "blockers" not in previous and (
            "blockers" not in current
        ):
            continue
        if before != after:
            diff[field] = {
                "before": copy.deepcopy(previous.get(field)),
                "after": copy.deepcopy(current.get(field)),
            }
    before_queue = sorted(_queue_blockers(previous))
    after_queue = sorted(_queue_blockers(current))
    if before_queue != after_queue:
        diff["queue.blockers"] = {"before": before_queue, "after": after_queue}
    return diff


def _meaningful_equal(previous: Mapping, current: Mapping) -> bool:
    """True when no meaningful watchlist content differs (ignores metadata)."""

    previous_public = {
        key: value
        for key, value in dict(previous).items()
        if key not in IGNORED_ENTRY_KEYS
    }
    current_public = {
        key: value
        for key, value in dict(current).items()
        if key not in IGNORED_ENTRY_KEYS
    }
    # Normalize ordering-sensitive lists before comparison.
    for key in ("match_rows",):
        previous_public[key] = _normalize_match_rows(previous_public.get(key))
        current_public[key] = _normalize_match_rows(current_public.get(key))
    for key in (
        "resolved_blockers",
        "remaining_blockers",
        "missing",
        "blockers",
    ):
        if key in previous_public or key in current_public:
            previous_public[key] = _normalize_list(previous_public.get(key))
            current_public[key] = _normalize_list(current_public.get(key))
    if "queue" in previous_public or "queue" in current_public:
        previous_public["queue"] = _queue_canonical(previous)
        current_public["queue"] = _queue_canonical(current)
    return _canonical(previous_public) == _canonical(current_public)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compare_snapshots(previous: Mapping | None, current: Mapping | None) -> dict:
    """Compare two watchlist snapshot dictionaries deterministically.

    Neither input is mutated. Semantic content is compared (never
    serialization, key ordering, ``snapshot_id``, ``created_utc`` or
    ``fingerprint``). One CVE may yield several change records; output is
    sorted by ``(cve_id, change_type)``.
    """

    previous_snapshot: Mapping = (
        previous if isinstance(previous, Mapping) else {}
    )
    current_snapshot: Mapping = current if isinstance(current, Mapping) else {}

    previous_entries = _entries_by_cve(previous_snapshot)
    current_entries = _entries_by_cve(current_snapshot)

    previous_id = str(previous_snapshot.get("snapshot_id") or "")
    current_id = str(current_snapshot.get("snapshot_id") or "")

    changes: list[dict] = []
    summary: dict[str, int] = {kind: 0 for kind in CHANGE_TYPES}

    for cve in sorted(set(previous_entries) | set(current_entries)):
        in_previous = cve in previous_entries
        in_current = cve in current_entries
        if in_current and not in_previous:
            changes.append(
                {
                    "cve_id": cve,
                    "change_type": NEW_CVE,
                    "details": {
                        "current_entry": _public_entry(current_entries[cve])
                    },
                }
            )
            summary[NEW_CVE] += 1
            continue
        if in_previous and not in_current:
            changes.append(
                {
                    "cve_id": cve,
                    "change_type": REMOVED_CVE,
                    "details": {
                        "previous_entry": _public_entry(previous_entries[cve])
                    },
                }
            )
            summary[REMOVED_CVE] += 1
            continue

        old = previous_entries[cve]
        new = current_entries[cve]

        state_diff = _state_details(old, new)
        match_diff = _match_details(old, new)
        evidence_diff = _evidence_details(old, new)
        blockers_diff = _blockers_details(old, new)

        emitted = False
        if state_diff:
            changes.append(
                {
                    "cve_id": cve,
                    "change_type": STATE_CHANGED,
                    "details": {"fields": state_diff},
                }
            )
            summary[STATE_CHANGED] += 1
            emitted = True
        if match_diff:
            changes.append(
                {
                    "cve_id": cve,
                    "change_type": MATCH_CHANGED,
                    "details": {"fields": match_diff},
                }
            )
            summary[MATCH_CHANGED] += 1
            emitted = True
        if evidence_diff:
            changes.append(
                {
                    "cve_id": cve,
                    "change_type": EVIDENCE_CHANGED,
                    "details": {"fields": evidence_diff},
                }
            )
            summary[EVIDENCE_CHANGED] += 1
            emitted = True
        if blockers_diff:
            changes.append(
                {
                    "cve_id": cve,
                    "change_type": BLOCKERS_CHANGED,
                    "details": {"fields": blockers_diff},
                }
            )
            summary[BLOCKERS_CHANGED] += 1
            emitted = True

        if not emitted:
            # Belt-and-braces: per-category diffs found nothing AND the
            # full meaningful content is equal -> UNCHANGED. If a future
            # entry field falls outside every category but differs, fall
            # through to a conservative EVIDENCE_CHANGED instead of
            # silently reporting UNCHANGED.
            if _meaningful_equal(old, new):
                changes.append(
                    {"cve_id": cve, "change_type": UNCHANGED, "details": {}}
                )
                summary[UNCHANGED] += 1
            else:
                changes.append(
                    {
                        "cve_id": cve,
                        "change_type": EVIDENCE_CHANGED,
                        "details": {
                            "fields": {
                                "entry": {
                                    "before": _public_entry(old),
                                    "after": _public_entry(new),
                                }
                            }
                        },
                    }
                )
                summary[EVIDENCE_CHANGED] += 1

    changes.sort(key=lambda item: (item["cve_id"], item["change_type"]))

    return {
        "previous_snapshot_id": previous_id,
        "current_snapshot_id": current_id,
        "summary": summary,
        "changes": changes,
    }


# ---------------------------------------------------------------------------
# Local snapshot helpers (read-only; atomic/no-overwrite writes only)
# ---------------------------------------------------------------------------


def delta_id_for(previous_snapshot_id: str, current_snapshot_id: str) -> str:
    """Deterministic delta artifact id for two snapshot ids."""

    safe_previous = re.sub(r"[^A-Za-z0-9_-]+", "_", previous_snapshot_id or "none")
    safe_current = re.sub(r"[^A-Za-z0-9_-]+", "_", current_snapshot_id or "none")
    digest = hashlib.sha256(
        f"{previous_snapshot_id}\x00{current_snapshot_id}".encode("utf-8")
    ).hexdigest()[:12]
    return f"delta-{safe_previous}_to_{safe_current}-{digest}"


def delta_path(snapshot_root: object, program: str, delta_id: str) -> Path:
    """Delta artifact path under the existing local watchlist data directory."""

    from ai.research_agent.watchlist import snapshot_dir

    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", delta_id)
    if not safe_id or safe_id in (".", ".."):
        raise ValueError(f"invalid delta id: {delta_id!r}")
    return Path(snapshot_dir(snapshot_root, program)) / f"{safe_id}.json"


def two_most_recent_snapshots(
    snapshot_root: object, program: str
) -> tuple[dict | None, dict | None]:
    """Return ``(previous, current)`` local snapshots for ``program``.

    Read-only. Returns ``(None, None)`` when fewer than one snapshot exists,
    ``(None, current)`` for a single snapshot, and the two most recent
    (oldest first) otherwise. Never touches MongoDB or the network.
    """

    from ai.research_agent.watchlist import list_snapshots

    snapshots = list_snapshots(snapshot_root, program)
    if not snapshots:
        return None, None
    if len(snapshots) == 1:
        return None, snapshots[0]
    return snapshots[-2], snapshots[-1]


def write_delta_snapshot(
    payload: Mapping,
    snapshot_root: object,
    program: str,
    delta_id: str,
) -> tuple[Path, bool]:
    """Atomic, no-overwrite delta write; returns ``(path, written)``."""

    dest = delta_path(snapshot_root, program, delta_id)
    if dest.exists():
        return dest, False
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        )
    os.replace(tmp, dest)
    return dest, True


def build_delta_payload(
    previous: Mapping | None,
    current: Mapping | None,
    *,
    program: str = "",
) -> dict:
    """Wrap :func:`compare_snapshots` with delta identity metadata."""

    result = compare_snapshots(previous, current)
    delta_id = delta_id_for(
        result["previous_snapshot_id"], result["current_snapshot_id"]
    )
    return {
        "delta_version": "watchlist-delta-1",
        "rule_version": "watchlist-delta-1",
        "delta_id": delta_id,
        "program": str(program or ""),
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "previous_snapshot_id": result["previous_snapshot_id"],
        "current_snapshot_id": result["current_snapshot_id"],
        "summary": result["summary"],
        "changes": result["changes"],
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "NEW_CVE",
    "REMOVED_CVE",
    "STATE_CHANGED",
    "MATCH_CHANGED",
    "EVIDENCE_CHANGED",
    "BLOCKERS_CHANGED",
    "UNCHANGED",
    "CHANGE_TYPES",
    "IGNORED_ENTRY_KEYS",
    "IGNORED_SNAPSHOT_KEYS",
    "compare_snapshots",
    "delta_id_for",
    "delta_path",
    "two_most_recent_snapshots",
    "write_delta_snapshot",
    "build_delta_payload",
]
