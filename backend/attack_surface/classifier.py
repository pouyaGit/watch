"""backend/attack_surface/classifier.py — deterministic candidate classification.

A pure, rule-based engine (no LLM, no external API, no network) that turns one
normalized :class:`~backend.attack_surface.models.AttackSurfaceRecord` into zero
or more research-category hypotheses:

======================  =====================================================
Category                Signals (v1)
======================  =====================================================
``XSS_CANDIDATE``       parameter names: q, query, search, name, message,
                        input, redirect, return, next
``IDOR_CANDIDATE``      parameter names: id, uid, user, user_id, account,
                        profile, object, item; endpoint segments: user, users,
                        account, profile, order
``SSRF_CANDIDATE``      parameter names: url, uri, target, callback, webhook,
                        proxy, destination
``FILE_UPLOAD_CANDIDATE``  parameter names: upload, file, image, attachment,
                        import
======================  =====================================================

Every match is explainable: the returned :class:`Classification` records the
matched signal, whether the match was exact or heuristic, and the human-readable
reasons that the scorer later expands. Heuristic matches are token/prefix/suffix
based and deterministic; short signals (<= 3 chars) require an exact or token
match so ``q`` never matches unrelated parameter names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from backend.attack_surface.models import (
    CandidateCategory,
    canonical_category,
)

XSS_PARAM_SIGNALS: tuple[str, ...] = (
    "q", "query", "search", "name", "message", "input", "redirect", "return",
    "next",
)
IDOR_PARAM_SIGNALS: tuple[str, ...] = (
    "id", "uid", "user", "user_id", "account", "profile", "object", "item",
)
IDOR_ENDPOINT_SIGNALS: tuple[str, ...] = (
    "user", "users", "account", "profile", "order",
)
SSRF_PARAM_SIGNALS: tuple[str, ...] = (
    "url", "uri", "target", "callback", "webhook", "proxy", "destination",
)
FILE_UPLOAD_PARAM_SIGNALS: tuple[str, ...] = (
    "upload", "file", "image", "attachment", "import",
)

#: Parameter-name shapes treated as an object identifier for the IDOR reason.
IDENTIFIER_PARAM_SIGNALS: frozenset[str] = frozenset({"id", "uid", "user_id"})

#: Signals shorter than this require an exact or whole-token match.
_MIN_HEURISTIC_LENGTH = 4

_TOKEN_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class Classification:
    """One explainable category match for a normalized record."""

    category: str
    param_signal: str = ""
    param_match: str = ""  # "exact" | "heuristic" | ""
    endpoint_signal: str = ""
    identifier: bool = False
    reasons: tuple[str, ...] = ()

    @property
    def matched(self) -> bool:
        return bool(self.param_signal or self.endpoint_signal)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "param_signal": self.param_signal,
            "param_match": self.param_match,
            "endpoint_signal": self.endpoint_signal,
            "identifier": self.identifier,
            "reasons": list(self.reasons),
        }


def normalize_parameter(name: object) -> str:
    """Lowercase/trim a parameter name and drop a trailing ``[]`` suffix."""

    text = " ".join(str(name if name is not None else "").split()).strip()
    text = text.lower()
    while text.endswith("[]"):
        text = text[:-2]
    return text


def _tokens(name: str) -> list[str]:
    return [token for token in _TOKEN_RE.split(name) if token]


def match_parameter(name: object, signals: tuple[str, ...]) -> tuple[str, str]:
    """Return ``(signal, kind)`` for the strongest parameter-name match.

    ``kind`` is ``"exact"`` for an exact name match, ``"heuristic"`` for a
    whole-token / prefix / suffix match, or ``""`` when nothing matches.
    """

    normalized = normalize_parameter(name)
    if not normalized:
        return "", ""
    for signal in signals:
        if normalized == signal:
            return signal, "exact"
    tokens = _tokens(normalized)
    for signal in signals:
        if signal in tokens:
            return signal, "heuristic"
    for signal in signals:
        if len(signal) < _MIN_HEURISTIC_LENGTH:
            continue
        for token in tokens:
            if token.startswith(signal) or token.endswith(signal):
                return signal, "heuristic"
    return "", ""


def match_endpoint(path: object, signals: tuple[str, ...]) -> str:
    """Return the matched endpoint segment, or ``""``."""

    normalized = str(path if path is not None else "").strip().lower()
    if not normalized:
        return ""
    segments = [segment for segment in _TOKEN_RE.split(normalized) if segment]
    for signal in signals:
        if signal in segments:
            return signal
    return ""


def _xss(record) -> Classification | None:
    signal, kind = match_parameter(record.parameter, XSS_PARAM_SIGNALS)
    if not signal:
        return None
    reasons = ["user controlled input name", "reflection possibility"]
    if kind == "heuristic":
        reasons.append(
            f"parameter name resembles a user input field ({signal})"
        )
    return Classification(
        category=CandidateCategory.XSS.value,
        param_signal=signal,
        param_match=kind,
        reasons=tuple(reasons),
    )


def _idor(record) -> Classification | None:
    signal, kind = match_parameter(record.parameter, IDOR_PARAM_SIGNALS)
    endpoint_signal = match_endpoint(record.endpoint, IDOR_ENDPOINT_SIGNALS)
    if not signal and not endpoint_signal:
        return None
    identifier = bool(
        signal in IDENTIFIER_PARAM_SIGNALS
        or (signal and normalize_parameter(record.parameter).endswith("_id"))
    )
    reasons: list[str] = []
    if signal:
        reasons.append("object identifier parameter")
        if kind == "heuristic":
            reasons.append(
                f"parameter name resembles an object reference ({signal})"
            )
    if endpoint_signal:
        reasons.append("resource reference")
    if identifier:
        reasons.append("numeric identifier parameter")
    return Classification(
        category=CandidateCategory.IDOR.value,
        param_signal=signal,
        param_match=kind,
        endpoint_signal=endpoint_signal,
        identifier=identifier,
        reasons=tuple(reasons),
    )


def _ssrf(record) -> Classification | None:
    signal, kind = match_parameter(record.parameter, SSRF_PARAM_SIGNALS)
    if not signal:
        return None
    reasons = ["remote resource input"]
    if kind == "heuristic":
        reasons.append(
            f"parameter name resembles a remote resource field ({signal})"
        )
    return Classification(
        category=CandidateCategory.SSRF.value,
        param_signal=signal,
        param_match=kind,
        reasons=tuple(reasons),
    )


def _file_upload(record) -> Classification | None:
    signal, kind = match_parameter(record.parameter, FILE_UPLOAD_PARAM_SIGNALS)
    if not signal:
        return None
    reasons = ["file handling functionality"]
    if kind == "heuristic":
        reasons.append(
            f"parameter name resembles a file handling field ({signal})"
        )
    return Classification(
        category=CandidateCategory.FILE_UPLOAD.value,
        param_signal=signal,
        param_match=kind,
        reasons=tuple(reasons),
    )


#: Deterministic evaluation order; a record may match several categories.
_RULES = (_xss, _idor, _ssrf, _file_upload)


def classify(record) -> tuple[Classification, ...]:
    """Classify one normalized record into deterministic category matches."""

    out: list[Classification] = []
    for rule in _RULES:
        result = rule(record)
        if result is not None:
            out.append(result)
    return tuple(out)


def classify_record(record) -> list[dict]:
    """JSON-friendly classification for one record."""

    return [item.to_dict() for item in classify(record)]


def category_for(value: object) -> str:
    """Canonical category string (kept for callers/tests)."""

    return canonical_category(value)


__all__ = [
    "XSS_PARAM_SIGNALS",
    "IDOR_PARAM_SIGNALS",
    "IDOR_ENDPOINT_SIGNALS",
    "SSRF_PARAM_SIGNALS",
    "FILE_UPLOAD_PARAM_SIGNALS",
    "IDENTIFIER_PARAM_SIGNALS",
    "Classification",
    "normalize_parameter",
    "match_parameter",
    "match_endpoint",
    "classify",
    "classify_record",
    "category_for",
]
