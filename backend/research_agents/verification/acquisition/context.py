"""EPIC13 §8 — deterministic output-context classification.

The question this answers is narrow and must not be overstated:

    *where in the response document did the controlled marker land?*

It does **not** answer whether a browser would parse that location as
executable, and it does **not** answer whether a DOM sink is reachable.  The
distinction is mandatory and is enforced here:

    SERVER_REFLECTION != DOM_SINK != EXECUTION

The vocabulary is closed:

``HTML_TEXT`` · ``HTML_ATTRIBUTE`` · ``SCRIPT`` · ``STYLE`` · ``URL`` ·
``JSON`` · ``COMMENT`` · ``UNKNOWN``

``DOM_ANALYSIS_UNAVAILABLE`` is reported separately whenever a caller asks for
DOM/sink information, because this runtime has no browser and must never infer
a DOM sink from a server-side reflection.

The structural decision for ``URL`` / ``HTML_ATTRIBUTE`` / script blocks is
delegated to the platform's own deterministic classifier
(``ai.verification.deterministic.http.classify_reflection_location``) so this
layer cannot disagree with the promoted verifier about what a location is; the
classes the platform classifier does not express (``STYLE``, ``JSON``,
``COMMENT``, ``UNKNOWN``) are resolved by a deterministic structural scan here.
"""
from __future__ import annotations

import re
from typing import Any

CONTEXT_RULE_VERSION = "epic13-context-1"

HTML_TEXT = "HTML_TEXT"
HTML_ATTRIBUTE = "HTML_ATTRIBUTE"
SCRIPT = "SCRIPT"
STYLE = "STYLE"
URL = "URL"
JSON_CONTEXT = "JSON"
COMMENT = "COMMENT"
UNKNOWN = "UNKNOWN"

CONTEXT_CLASSES: tuple[str, ...] = (
    HTML_TEXT, HTML_ATTRIBUTE, SCRIPT, STYLE, URL, JSON_CONTEXT, COMMENT,
    UNKNOWN,
)

#: the honest capability statement for this runtime.
DOM_ANALYSIS_UNAVAILABLE = "DOM_ANALYSIS_UNAVAILABLE"

#: classes that carry the platform's "meaningful location" weight.
#: They are still not exploitability — see the module docstring.
CONTEXTS_REQUIRING_REVIEW = frozenset({HTML_ATTRIBUTE, SCRIPT, URL})

_TOKEN_RE = re.compile(
    r"<!--.*?-->"
    r"|<script\b[^>]*>.*?</script\s*>"
    r"|<style\b[^>]*>.*?</style\s*>"
    r"|<[a-zA-Z/!][^>]*>",
    re.IGNORECASE | re.DOTALL)

_JSON_SCRIPT_RE = re.compile(
    r"<script\b[^>]*type\s*=\s*[\"']application/(?:ld\+)?json[\"'][^>]*>"
    r"(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)

_JSON_STRING_RE = re.compile(r"\"(?:[^\"\\]|\\.)*\"")


def _platform_classify(sample: str, marker: str) -> str:
    """The promoted verifier's own location classifier (reused, never forked)."""
    try:
        from ai.verification.deterministic.http import (
            classify_reflection_location)
    except Exception:  # noqa: BLE001 - absence must not become a guess
        return "ABSENT"
    try:
        return str(classify_reflection_location(sample, marker))
    except Exception:  # noqa: BLE001
        return "ABSENT"


def _spans(pattern: re.Pattern[str], text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in pattern.finditer(text)]


def _inside(spans: list[tuple[int, int]], offset: int) -> bool:
    return any(start <= offset < end for start, end in spans)


def _attribute_span(sample: str, marker: str, offset: int) -> bool:
    """True when the offset sits inside a tag's quoted attribute value."""
    for match in _TOKEN_RE.finditer(sample):
        if not (match.start() <= offset < match.end()):
            continue
        token = match.group(0)
        if not token.startswith("<") or token.startswith(("<!--", "<script",
                                                          "<style")):
            return False
        return any(m.start() <= offset < m.end()
                   for m in _JSON_STRING_RE.finditer(token))
    return False


def _json_region(sample: str, offset: int) -> bool:
    """True when the offset is inside a JSON document or JSON script block."""
    for match in _JSON_SCRIPT_RE.finditer(sample):
        if match.start(1) <= offset < match.end(1):
            return True
    stripped = sample.lstrip()
    if stripped[:1] in ("{", "[") and offset >= len(sample) - len(stripped):
        for match in _JSON_STRING_RE.finditer(stripped):
            if match.start() <= offset - (len(sample) - len(stripped)) \
                    < match.end():
                return True
    return False


def classify(sample: str, marker: str, *,
             offset: int | None = None) -> str:
    """Classify the context the marker landed in.  Deterministic; fail closed.

    Returns one of ``CONTEXT_CLASSES`` or ``""`` when the marker is absent.
    """
    text = str(sample or "")
    needle = str(marker or "")
    if not needle:
        return ""
    if offset is None:
        index = text.find(needle)
        if index < 0:
            return ""
    else:
        index = int(offset)
        if not (0 <= index < len(text)) or not text.startswith(needle, index):
            return ""

    # a JSON document (or a JSON script block) is data, not code: it is
    # decided before the platform classifier, which has no JSON vocabulary and
    # would report the enclosing <script> as SCRIPT.
    if _json_region(text, index):
        return JSON_CONTEXT

    # the platform classifier decides everything else it can express
    platform = _platform_classify(text, needle)
    if platform == "ABSENT":
        # the marker is present but the platform classifier cannot see it in
        # the sample it was given (e.g. an offset-only view) -> do not guess.
        return ""
    if platform in ("JAVASCRIPT_STRING", "SCRIPT_BLOCK"):
        return SCRIPT
    if platform in ("URL", "HTML_ATTRIBUTE"):
        # a comment or style block may still contain the marker text; those
        # constructs are checked first because the platform classifier has no
        # vocabulary for them and would report HTML_BODY only.
        if _inside(_spans(re.compile(r"<!--.*?-->", re.DOTALL), text), index):
            return COMMENT
        if _inside(_spans(re.compile(r"<style\b[^>]*>.*?</style\s*>",
                                     re.IGNORECASE | re.DOTALL), text), index):
            return STYLE
        return platform

    # platform said HTML_BODY (or something unrecognised): refine structurally
    if _inside(_spans(re.compile(r"<!--.*?-->", re.DOTALL), text), index):
        return COMMENT
    if _inside(_spans(re.compile(r"<style\b[^>]*>.*?</style\s*>",
                                 re.IGNORECASE | re.DOTALL), text), index):
        return STYLE
    if _inside(_spans(_TOKEN_RE, text), index):
        # inside a tag but not in a quoted attribute value: the location is
        # structurally ambiguous (unquoted attribute, tag name, event handler
        # text) and is reported as such rather than upgraded.
        return UNKNOWN if not _attribute_span(text, needle, index) else \
            HTML_ATTRIBUTE
    return HTML_TEXT


def classify_with_offset(sample: str, marker: str) -> tuple[str, int]:
    """Classify *and* report the offset the class was decided at.

    The reported class is the most security-relevant occurrence's class (the
    platform classifier's own semantics: a marker anywhere inside a script
    block is a script context).  This returns the offset of the first
    occurrence for which :func:`classify` yields that class, so an evidence
    location is always consistent with the reported class.
    """
    klass = classify(sample, marker)
    if not klass:
        return "", -1
    text = str(sample or "")
    start = 0
    while True:
        index = text.find(str(marker or ""), start)
        if index < 0:
            break
        if classify(text, marker, offset=index) == klass:
            return klass, index
        start = index + 1
    return klass, text.find(str(marker or ""))


def classification_document() -> dict[str, Any]:
    """The context vocabulary and its honest limits, for docs and reports."""
    return {
        "rule_version": CONTEXT_RULE_VERSION,
        "classes": list(CONTEXT_CLASSES),
        "meaningful_locations_reused_from_platform":
            sorted(CONTEXTS_REQUIRING_REVIEW),
        "dom_analysis": DOM_ANALYSIS_UNAVAILABLE,
        "distinctions": [
            "SERVER_REFLECTION != DOM_SINK",
            "DOM_SINK != EXECUTION",
            "a context class is not exploitability",
        ],
        "delegates_to": "ai.verification.deterministic.http."
                        "classify_reflection_location",
    }


__all__ = [
    "classify_with_offset",
    "COMMENT", "CONTEXT_CLASSES", "CONTEXTS_REQUIRING_REVIEW",
    "CONTEXT_RULE_VERSION", "DOM_ANALYSIS_UNAVAILABLE", "HTML_ATTRIBUTE",
    "HTML_TEXT", "JSON_CONTEXT", "SCRIPT", "STYLE", "UNKNOWN", "URL",
    "classification_document", "classify",
]
