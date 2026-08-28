from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any


_BASE64_BLOB_MIN_LENGTH = 200


def normalize_for_grounding(value: str) -> str:
    """
    Normalize a string for deterministic, case-insensitive,
    whitespace-tolerant substring matching.

    The transformation is intentionally narrow:

    - Unicode is preserved (NFKC canonical form so visually
      equivalent characters compare equal, but no characters are
      stripped or transliterated to ASCII).
    - The string is lowercased using Unicode case folding so
      accented and non-Latin scripts are case-insensitive too.
    - Whitespace is collapsed: any run of Unicode whitespace
      (per ``str.isspace``) is reduced to a single ASCII space,
      and leading / trailing whitespace is stripped.
    - Punctuation is NOT removed. Aggressive punctuation
      stripping would collapse values like ``"html_attribute"``
      into ``"htmlattribute"``, which is exactly the kind of
      false-positive grounding we need to avoid.

    The result is deterministic: equal inputs always produce
    equal outputs.
    """

    if not value:
        return ""

    canonical = unicodedata.normalize("NFKC", value)
    folded = canonical.casefold()

    pieces: list[str] = []
    last_was_space = True
    for character in folded:
        if character.isspace():
            if not last_was_space:
                pieces.append(" ")
            last_was_space = True
        else:
            pieces.append(character)
            last_was_space = False

    normalized = "".join(pieces)
    return normalized.strip()


def value_grounded(value: str, content: str) -> bool:
    """
    Return True iff ``value`` is supported by ``content`` under
    the normalization defined in :func:`normalize_for_grounding`.

    Empty values are never grounded. Empty content grounds
    nothing.
    """

    if value is None or content is None:
        return False

    if not value or not content:
        return False

    needle = normalize_for_grounding(value)
    if not needle:
        return False

    haystack = normalize_for_grounding(content)
    if not haystack:
        return False

    return needle in haystack


FORBIDDEN_PAYLOAD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(
        r"\bon(?:error|load|click|mouseover|focus|blur|submit|"
        r"change|keydown|keyup|keypress|toggle|animationend|"
        r"mouseenter|mouseleave|mousedown|mouseup|resize)\s*=",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:src|href|formaction|action|xlink:href|poster)\s*="
        r"\s*[\"']?\s*javascript\s*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdata\s*:\s*text/html",
        re.IGNORECASE,
    ),
    re.compile(
        r"\beval\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdocument\s*\.\s*write(?:ln)?\s*\(",
        re.IGNORECASE,
    ),
)


def _base64_blob_pattern(min_length: int) -> re.Pattern[str]:
    return re.compile(
        rf"\b[A-Za-z0-9+/]{{{min_length},}}={{0,2}}\b"
    )


def _iter_base64_blob_patterns() -> Iterable[re.Pattern[str]]:
    yield _base64_blob_pattern(_BASE64_BLOB_MIN_LENGTH)


def contains_forbidden(value: str) -> bool:
    """
    Return True iff ``value`` looks like an executable payload
    fragment or an unusually large base64-style blob.

    The check is intentionally conservative: it rejects
    constructs that would actually execute in a browser
    (script tags, ``javascript:`` URLs, event-handler
    attributes) and very long base64-like blobs, but it does
    NOT reject ordinary research terminology like
    ``"onerror bypass technique"`` or ``"script context"``.
    """

    if not value:
        return False

    for pattern in FORBIDDEN_PAYLOAD_PATTERNS:
        if pattern.search(value):
            return True

    for pattern in _iter_base64_blob_patterns():
        if pattern.search(value):
            return True

    return False


def _canonical_claim_payload(claim: Mapping[str, Any]) -> str:
    serializable: dict[str, Any] = {}
    for key in sorted(claim.keys()):
        value = claim[key]
        if isinstance(value, (list, tuple, set)):
            serializable[key] = sorted(
                str(item) for item in value
            )
        elif value is None or isinstance(value, (bool, int, float, str)):
            serializable[key] = value
        else:
            serializable[key] = str(value)

    return json.dumps(
        serializable,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def claim_fingerprint(claim: Mapping[str, Any]) -> str:
    """
    Return a deterministic, order-independent fingerprint of a
    claim-like mapping.

    The fingerprint is the SHA-256 hex digest of the canonical
    JSON serialization of the claim. Lists are sorted before
    serialization so that two claims differing only in list
    order produce the same fingerprint. Materially different
    claims produce different fingerprints.
    """

    canonical = _canonical_claim_payload(claim)
    digest = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()
    return digest
