"""backend/soc/_util.py — tiny shared helpers for the SOC adapters.

Kept stdlib-only and deterministic.  No I/O beyond the bounded reads the
adapter modules perform; no secrets pass through here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def _text(value: Any, limit: int = 256) -> str:
    """Collapse whitespace and bound length (never raise)."""
    if value is None:
        return ""
    return " ".join(str(value).split())[:limit]


def _slug(key: str) -> str:
    """agent key -> url slug (xss -> xss-agent)."""
    key = str(key or "").strip().lower()
    return f"{key}-agent" if key else key


def _key_from_slug(slug: str) -> str:
    """url slug -> agent key (xss-agent -> xss); '' when malformed."""
    slug = str(slug or "").strip().lower()
    if slug.endswith("-agent") and len(slug) > len("-agent"):
        return slug[: -len("-agent")]
    return ""


def _bounded(seq: Sequence[Any], limit: int) -> list[Any]:
    return list(seq)[: max(int(limit), 0)]


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, (str, bytes)):
        return [value]
    return []


def _clean_case(row: Mapping[str, Any], extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Normalize one AEC case-explorer row for the SOC case list."""
    out = {
        "case_id": _text(row.get("case_id")),
        "target": _text(row.get("target")),
        "category": _text(row.get("category")),
        "research_state": _text(row.get("research_state")),
        "evidence_state": _text(row.get("evidence_state")),
        "specialist": _text(row.get("specialist")),
        "next_action": _text(row.get("next_action")),
        "badge": _text(row.get("badge")),
    }
    if extra:
        out.update({k: v for k, v in extra.items() if v is not None})
    return out