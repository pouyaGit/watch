"""EPIC13 §5 — deterministic controlled markers.

A marker is the *only* thing EPIC13 ever puts into a target parameter.  It is
therefore constrained on purpose:

* **inert** — the alphabet is ``[A-Z0-9_]``.  A marker can never contain ``<``,
  ``>``, ``"``, ``'``, ``(``, ``)``, ``;``, ``&``, ``=``, ``/``, ``\\`` or any
  other metacharacter, so it cannot break out of an HTML text node, an
  attribute, a script string or a URL on its own.  This is a security
  requirement (§15: no automatic exploit payloads), not a formatting choice.
* **unique per action** — derived from the action id, so two actions never
  share a marker and a response can be attributed to exactly one action.
* **traceable** — the marker is persisted on the action that sent it, and the
  same derivation reproduces it from the action id, so a marker found in a
  response is always resolvable to its action.
* **bounded** — fixed 12 hex characters of digest, so the marker length is
  constant and small.

Markers are never random: the same action always produces the same marker, so
re-planning is idempotent and a replay is detectable (§18).
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

MARKER_RULE_VERSION = "epic13-marker-1"

#: the fixed, inert prefix.
MARKER_PREFIX = "HERMES_REFLECT_"

#: 12 uppercase hex characters of digest.
_MARKER_BODY_LENGTH = 12

#: the complete marker alphabet — inert by construction.
MARKER_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

#: matches a marker, with its body captured.
MARKER_RE = re.compile(r"HERMES_REFLECT_([0-9A-F]{12})")

#: the documented maximum marker length (also the ``validate`` default).
MAX_MARKER_LENGTH = 64

#: any character a marker must never contain (HTML / JS / URL / SQL metas).
FORBIDDEN_MARKER_CHARS = frozenset(
    "<>\"'`(){}[];,&=+/\\|!$%*?#: \t\r\n-")


class MarkerError(ValueError):
    """A marker could not be produced or is not inert."""


def marker_body(action_id: str, parameter: str = "", attempt: int = 1) -> str:
    """The deterministic 12-hex body of one action's marker."""
    seed = "|".join([str(action_id or ""), str(parameter or ""),
                     str(int(attempt))])
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return digest[:_MARKER_BODY_LENGTH].upper()


def marker_for(action_id: str, parameter: str = "", attempt: int = 1,
               *, limits: dict[str, int] | None = None) -> str:
    """Build the marker for one acquisition action.

    Deterministic and idempotent: the same action always yields the same
    marker.  Raises when the result would be empty, over-long, or not inert.
    """
    if not str(action_id or "").strip():
        raise MarkerError("a marker requires an action id")
    marker = MARKER_PREFIX + marker_body(action_id, parameter, attempt)
    return validate(marker, limits=limits)


def validate(marker: str, *, limits: dict[str, int] | None = None) -> str:
    """Prove a marker is well-formed, inert and bounded.  Fail closed."""
    text = str(marker or "")
    if not text:
        raise MarkerError("empty marker")
    if not text.startswith(MARKER_PREFIX):
        raise MarkerError(f"marker must start with {MARKER_PREFIX!r}")
    if not MARKER_RE.fullmatch(text):
        raise MarkerError("marker body must be 12 uppercase hex characters")
    bad = sorted(set(text) & FORBIDDEN_MARKER_CHARS)
    if bad:
        raise MarkerError(f"marker is not inert (contains {bad})")
    if set(text) - set(MARKER_ALPHABET):
        raise MarkerError("marker uses characters outside the inert alphabet")
    limit = int((limits or {}).get("max_marker_length", MAX_MARKER_LENGTH))
    if len(text) > limit:
        raise MarkerError(
            f"marker length {len(text)} exceeds max_marker_length {limit}")
    return text


def is_marker(value: Any) -> bool:
    """True when the value is exactly one well-formed marker."""
    try:
        validate(str(value or ""))
    except MarkerError:
        return False
    return True


def occurrences(text: str, marker: str) -> list[int]:
    """Every offset at which the marker occurs, in order (no overlap)."""
    haystack = str(text or "")
    needle = str(marker or "")
    if not needle:
        return []
    out: list[int] = []
    start = 0
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return out
        out.append(index)
        start = index + len(needle)


def marker_lineage(marker: str, action_id: str, parameter: str = "",
                   attempt: int = 1) -> dict[str, Any]:
    """The persisted provenance of a marker (stored on the action, §5)."""
    return {
        "marker": str(marker),
        "marker_rule_version": MARKER_RULE_VERSION,
        "action_id": str(action_id),
        "parameter": str(parameter or ""),
        "attempt": int(attempt),
        "reproducible": marker == marker_for(action_id, parameter, attempt),
        "inert_alphabet": True,
    }


def marker_document() -> dict[str, Any]:
    """The marker scheme, for the report and the docs."""
    return {
        "rule_version": MARKER_RULE_VERSION,
        "prefix": MARKER_PREFIX,
        "body": f"{_MARKER_BODY_LENGTH} uppercase hex characters",
        "alphabet": MARKER_ALPHABET,
        "forbidden_characters": "".join(sorted(FORBIDDEN_MARKER_CHARS)),
        "derivation": "sha256(action_id|parameter|attempt)[:12] uppercased",
        "properties": ["deterministic", "unique-per-action", "traceable",
                       "inert", "bounded", "persisted-with-the-action"],
    }


__all__ = [
    "FORBIDDEN_MARKER_CHARS", "MARKER_ALPHABET", "MARKER_PREFIX", "MARKER_RE",
    "MARKER_RULE_VERSION", "MarkerError", "is_marker", "marker_body",
    "marker_document", "marker_for", "marker_lineage", "occurrences",
    "validate",
]
