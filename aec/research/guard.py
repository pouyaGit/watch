"""Production-claim guard (EPIC 6 Part 7).

v1 policy: no record is automatically promotable to a production
finding. Promotion requires an authorized-evidence path that does not
exist yet, so promotable_to_production() is always False and every
fixture-origin record is explicitly non-promotable.
"""

from __future__ import annotations

from typing import Any, Mapping

_CLAIM_MARKERS = frozenset({
    "confirmed", "vulnerable", "exploitable", "finding", "verdict",
})


def is_production_claim(document: Mapping[str, Any]) -> bool:
    """True when a mapping claims a production-grade result."""
    for value in document.values():
        if isinstance(value, str) and value.strip().lower() in _CLAIM_MARKERS:
            return True
    return False


def ensure_no_production_claim(document: Mapping[str, Any], context: str) -> None:
    """Raise ValueError when a document carries a production claim."""
    if is_production_claim(document):
        raise ValueError(f"production claim refused in {context}")


def promotable_to_production(document: Mapping[str, Any]) -> bool:
    """Whether a record may become a production finding. Always False."""
    _ = document
    return False


def same_source_mode(first: str, second: str) -> bool:
    """True when two source-mode labels match."""
    return first == second


__all__ = [
    "ensure_no_production_claim",
    "is_production_claim",
    "promotable_to_production",
    "same_source_mode",
]
