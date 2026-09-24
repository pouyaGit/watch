"""EPIC13 §7 — deterministic reflection detection.

Given one controlled marker and one real response body, decide — with no
heuristics that upgrade ambiguity — which of the required distinctions holds:

1. ``ABSENT``            the marker is not in the body
2. ``PRESENT``           exactly one raw occurrence
3. ``MULTIPLE``          more than one raw occurrence
4. ``TRANSFORMED``       the marker appears case-changed (a closed set)
5. ``ENCODED``           the marker appears in a recognised encoded form
6. ``DECODED``           the body is encoded as a whole and decoding reveals it
7.  context ``HTML_TEXT`` / 8. ``HTML_ATTRIBUTE`` / 9. ``SCRIPT`` /
10. ``URL``              where it landed (see :mod:`context`)
11. ``BODY_UNAVAILABLE`` no body was provided at all

Anything the detector cannot prove is reported as ``ABSENT`` with
``conclusive=False`` — never as a weaker "probably reflected".  A truncated
body is the important case: absence in a truncated body is *not* evidence of
absence, so the result is non-conclusive and the caller must not record
negative evidence from it (§10).

The detector is pure: no I/O, no network, no clock, no randomness.  It never
calls an occurrence "XSS"; a reflection is a reflection.
"""
from __future__ import annotations

import base64

from backend.research_agents.verification.acquisition import limits as lm
import re
from dataclasses import dataclass, field
from typing import Any

from . import context as cx

DETECTOR_RULE_VERSION = "epic13-reflection-detector-1"

BODY_UNAVAILABLE = "BODY_UNAVAILABLE"
ABSENT = "ABSENT"
PRESENT = "PRESENT"
MULTIPLE = "MULTIPLE"
TRANSFORMED = "TRANSFORMED"
ENCODED = "ENCODED"
DECODED = "DECODED"

DETECTION_STATUSES: tuple[str, ...] = (
    BODY_UNAVAILABLE, ABSENT, PRESENT, MULTIPLE, TRANSFORMED, ENCODED, DECODED,
)

#: closed set of recognised transformations (never extended by inference).
TRANSFORMATION_LOWERCASED = "lowercased"

#: closed set of recognised encodings.
ENCODING_UNICODE_ESCAPED = "unicode_escaped"
ENCODING_HTML_NUMERIC_ENTITY = "html_numeric_entity"
ENCODING_BASE64 = "base64"

#: closed set of recognised whole-body encodings.
BODY_ENCODING_PERCENT = "percent"
BODY_ENCODING_HTML_ENTITY = "html_entity"

_ENCODINGS: tuple[str, ...] = (
    ENCODING_UNICODE_ESCAPED, ENCODING_HTML_NUMERIC_ENTITY, ENCODING_BASE64,
)
_BODY_ENCODINGS: tuple[str, ...] = (
    BODY_ENCODING_PERCENT, BODY_ENCODING_HTML_ENTITY,
)

_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")
_NUMERIC_ENTITY_RE = re.compile(r"&#(?:x([0-9A-Fa-f]{1,6})|([0-9]{1,7}));")


@dataclass
class ReflectionDetection:
    """The structured result of one reflection check (§7)."""

    status: str
    marker: str = ""
    occurrence_count: int = 0
    offsets: list[int] = field(default_factory=list)
    context: str = ""
    transformation: str = ""
    encoding: str = ""
    body_encoding: str = ""
    evidence_location: str = ""
    detector_version: str = DETECTOR_RULE_VERSION
    conclusive: bool = True
    truncated: bool = False
    reason: str = ""
    bytes_checked: int = 0
    limits_applied: dict[str, int] = field(default_factory=dict)

    @property
    def reflected(self) -> bool:
        """True when the marker was found, in any recognised form."""
        return self.status in (PRESENT, MULTIPLE, TRANSFORMED, ENCODED,
                              DECODED)

    @property
    def raw(self) -> bool:
        """True when the marker was found verbatim."""
        return self.status in (PRESENT, MULTIPLE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "marker": self.marker,
            "occurrence_count": self.occurrence_count,
            "offsets": list(self.offsets),
            "context": self.context,
            "transformation": self.transformation,
            "encoding": self.encoding,
            "body_encoding": self.body_encoding,
            "evidence_location": self.evidence_location,
            "detector_version": self.detector_version,
            "conclusive": self.conclusive,
            "truncated": self.truncated,
            "reason": self.reason,
            "bytes_checked": self.bytes_checked,
            "limits_applied": dict(self.limits_applied),
            "reflected": self.reflected,
            "raw": self.raw,
        }


def _decode_numeric_entities(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        hex_digits, dec_digits = match.group(1), match.group(2)
        try:
            code = int(hex_digits, 16) if hex_digits else int(dec_digits)
        except (TypeError, ValueError):
            return match.group(0)
        if code <= 0 or code > 0x10FFFF:
            return match.group(0)
        try:
            return chr(code)
        except ValueError:
            return match.group(0)

    return _NUMERIC_ENTITY_RE.sub(replace, text)


def _decode_unicode_escapes(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except (TypeError, ValueError):
            return match.group(0)

    return _UNICODE_ESCAPE_RE.sub(replace, text)


def _decode_percent(text: str) -> str:
    from urllib.parse import unquote

    try:
        return unquote(text, errors="replace")
    except Exception:  # noqa: BLE001 - a bad escape is not a detection
        return text


def _find(text: str, needle: str, limit: int) -> list[int]:
    out: list[int] = []
    start = 0
    while len(out) < limit:
        index = text.find(needle, start)
        if index < 0:
            break
        out.append(index)
        start = index + len(needle)
    return out


def _location(context_class: str, offset: int) -> str:
    return f"{context_class.lower()}@offset:{offset}" if context_class else \
        f"offset:{offset}"


def detect(body: Any, marker: str, *, truncated: bool = False,
           limits: dict[str, int] | None = None) -> ReflectionDetection:
    """Detect one marker in one response body.  Deterministic and bounded."""
    bounds = dict(lm.limits_for(limits))
    max_occurrences = int(bounds.get("max_occurrences_recorded", 8))
    # §10: the analysis window is bounded.  A marker that could only exist
    # beyond the window is never reported as a conclusive absence.
    window = int(bounds.get("max_response_bytes", 0) or 0)
    truncated_by_window = False
    needle = str(marker or "")
    if body is None:
        return ReflectionDetection(
            status=BODY_UNAVAILABLE, marker=needle, conclusive=False,
            reason="no response body was available",
            limits_applied=bounds)
    if isinstance(body, (bytes, bytearray)):
        # a transport hands bytes; the marker is ASCII so a lossy decode can
        # never hide it, and the decode is where bytes stop being a body.
        text = bytes(body).decode("utf-8", errors="replace")
    elif isinstance(body, str):
        text = body
    else:
        # anything else is not a response body: fail closed rather than
        # reporting an absence that was never actually observed.
        return ReflectionDetection(
            status=BODY_UNAVAILABLE, marker=needle, conclusive=False,
            reason=f"the response body is not text ({type(body).__name__})",
            limits_applied=bounds)
    if window > 0 and len(text) > window:
        text = text[:window]
        truncated_by_window = True
        truncated = True
    if not needle:
        return ReflectionDetection(
            status=ABSENT, marker="", conclusive=False,
            reason="no marker was supplied", bytes_checked=len(text),
            limits_applied=bounds)

    offsets = _find(text, needle, max_occurrences + 1)
    if offsets:
        count = len(offsets)
        status = MULTIPLE if count > 1 else PRESENT
        # the class is the most security-relevant occurrence's class (the
        # platform classifier's semantics); the reported offset is that
        # occurrence, so the evidence location never points at a different one.
        klass, index = cx.classify_with_offset(text, needle)
        if index < 0:
            index = offsets[0]
        return ReflectionDetection(
            status=status, marker=needle, occurrence_count=count,
            offsets=offsets[:max_occurrences], context=klass,
            evidence_location=_location(klass, index),
            conclusive=True, truncated=truncated,
            bytes_checked=len(text), limits_applied=bounds,
            reason=f"marker present verbatim ({count} occurrence(s))")

    # ---- recognised transformations (closed set, checked in a fixed order) --
    lowered = _find(text, needle.lower(), max_occurrences + 1)
    if lowered:
        index = lowered[0]
        klass = cx.classify(text, needle.lower(), offset=index)
        return ReflectionDetection(
            status=TRANSFORMED, marker=needle, occurrence_count=len(lowered),
            offsets=lowered[:max_occurrences], context=klass,
            transformation=TRANSFORMATION_LOWERCASED,
            evidence_location=_location(klass, index), conclusive=True,
            truncated=truncated, bytes_checked=len(text), limits_applied=bounds,
            reason="marker present with its case transformed")

    # ---- recognised encodings (the marker itself is encoded) ---------------
    unicode_escaped = "".join(f"\\u{ord(ch):04x}" for ch in needle)
    unicode_escaped_upper_hex = "".join(f"\\u{ord(ch):04X}" for ch in needle)
    encoded_forms = (
        (ENCODING_UNICODE_ESCAPED, unicode_escaped),
        (ENCODING_UNICODE_ESCAPED, unicode_escaped_upper_hex),
        (ENCODING_UNICODE_ESCAPED, unicode_escaped.upper()),
        (ENCODING_HTML_NUMERIC_ENTITY,
         "".join(f"&#{ord(ch)};" for ch in needle)),
        (ENCODING_HTML_NUMERIC_ENTITY,
         "".join(f"&#x{ord(ch):x};" for ch in needle)),
        (ENCODING_BASE64,
         base64.b64encode(needle.encode("utf-8")).decode("ascii")),
    )
    for name, form in encoded_forms:
        if form and form in text:
            index = text.find(form)
            return ReflectionDetection(
                status=ENCODED, marker=needle, occurrence_count=1,
                offsets=[index], context="", encoding=name,
                evidence_location=f"{name}@offset:{index}", conclusive=True,
                truncated=truncated, bytes_checked=len(text),
                limits_applied=bounds,
                reason=f"marker present in a recognised encoded form ({name})")

    # ---- whole-body encodings (the marker appears after decoding) ----------
    percent = _decode_percent(text)
    if percent != text and needle in percent:
        index = percent.find(needle)
        klass = cx.classify(percent, needle, offset=index)
        return ReflectionDetection(
            status=DECODED, marker=needle, occurrence_count=1, offsets=[index],
            context=klass, body_encoding=BODY_ENCODING_PERCENT,
            evidence_location=_location(klass, index), conclusive=True,
            truncated=truncated, bytes_checked=len(text), limits_applied=bounds,
            reason="marker revealed by decoding a percent-encoded body")

    entities = _decode_numeric_entities(text)
    if entities != text and needle in entities:
        index = entities.find(needle)
        klass = cx.classify(entities, needle, offset=index)
        return ReflectionDetection(
            status=DECODED, marker=needle, occurrence_count=1, offsets=[index],
            context=klass, body_encoding=BODY_ENCODING_HTML_ENTITY,
            evidence_location=_location(klass, index), conclusive=True,
            truncated=truncated, bytes_checked=len(text), limits_applied=bounds,
            reason="marker revealed by decoding an HTML-entity body")

    unescaped = _decode_unicode_escapes(text)
    if unescaped != text and needle in unescaped:
        index = unescaped.find(needle)
        klass = cx.classify(unescaped, needle, offset=index)
        return ReflectionDetection(
            status=DECODED, marker=needle, occurrence_count=1, offsets=[index],
            context=klass, body_encoding=ENCODING_UNICODE_ESCAPED,
            evidence_location=_location(klass, index), conclusive=True,
            truncated=truncated, bytes_checked=len(text), limits_applied=bounds,
            reason="marker revealed by decoding unicode escapes")

    # ---- absent ------------------------------------------------------------
    if truncated_by_window:
        reason = (f"marker absent within the first {window} bytes analysed, "
                  f"but the body was longer so absence is not conclusive")
    elif truncated:
        reason = "marker absent, but the body was truncated so absence is not conclusive"
    else:
        reason = "marker not present in the body"
    return ReflectionDetection(
        status=ABSENT, marker=needle, occurrence_count=0,
        conclusive=not truncated, truncated=truncated,
        bytes_checked=len(text), limits_applied=bounds, reason=reason)


def detector_document() -> dict[str, Any]:
    """The detector's contract, for docs and reports."""
    return {
        "rule_version": DETECTOR_RULE_VERSION,
        "statuses": list(DETECTION_STATUSES),
        "transformations": [TRANSFORMATION_LOWERCASED],
        "encodings": list(_ENCODINGS),
        "body_encodings": list(_BODY_ENCODINGS),
        "context_classes": list(cx.CONTEXT_CLASSES),
        "closed": True,
        "properties": [
            "deterministic",
            "bounded (max_occurrences_recorded)",
            "never upgrades ambiguity",
            "truncated absence is not conclusive",
            "a reflection is not a vulnerability",
        ],
    }


__all__ = [
    "ABSENT", "BODY_ENCODING_HTML_ENTITY", "BODY_ENCODING_PERCENT",
    "BODY_UNAVAILABLE", "DECODED", "DETECTION_STATUSES",
    "DETECTOR_RULE_VERSION", "ENCODED", "ENCODING_BASE64",
    "ENCODING_HTML_NUMERIC_ENTITY", "ENCODING_UNICODE_ESCAPED", "MULTIPLE",
    "PRESENT", "ReflectionDetection", "TRANSFORMED",
    "TRANSFORMATION_LOWERCASED", "detect", "detector_document",
]
