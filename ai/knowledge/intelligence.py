"""Deterministic vulnerability-intelligence extraction (Stage R12).

Pure, offline, bounded rule engine. No LLM, no network, no subprocess,
no target execution, no scoring, and no inference beyond explicit
deterministic textual or structured evidence.

Every extracted non-empty field carries bounded provenance:
``source_artifact``, ``source_url`` (when the evidence comes from a
reference; otherwise the research artifact), a bounded verbatim
``evidence`` snippet, and a stable ``rule_id``/``rule_version`` pair.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field

INTELLIGENCE_RULE_VERSION = "r12-2"

# Keep both input scanning and verbatim snippets bounded. These caps are
# time/space guards, not semantic truncation points in the rules.
MAX_INTELLIGENCE_TEXT_CHARS = 50_000
MAX_EVIDENCE_SNIPPET_CHARS = 240
MAX_EVIDENCE_WINDOW_CHARS = 90

# Small, conservative identifier-shaped vocabulary for extracted names.
_PARAMETER_RE = r"[A-Za-z_][A-Za-z0-9_.\-]{0,63}"
_NON_PARAMETER_NAMES = frozenset(
    {
        "a", "after", "all", "also", "an", "and", "another", "any", "are",
        "as", "at", "be", "been", "before", "being", "both", "but", "by",
        "can", "caused", "causes", "could", "did", "does", "during",
        "each", "exists", "false", "for", "found", "from", "had", "has",
        "have", "here", "how", "if", "in", "into", "is", "it", "its",
        "leads", "less", "many", "may", "might", "more", "most", "must",
        "no", "none", "not", "null", "of", "on", "or", "other", "others",
        "parameter", "parameters", "passed", "plus", "present", "provided",
        "rendered", "reflected", "echoed", "encoded", "decoded", "sanitized",
        "validated", "vulnerable", "exploited", "triggered", "inserted",
        "injected", "escaped", "unescaped", "processed", "displayed",
        "executed", "occurs", "called", "named",
        "should", "since", "some", "such", "supplied", "than", "that",
        "the", "their", "them", "then", "there", "these", "they", "this",
        "those", "to", "true", "underlying", "unknown", "until", "used",
        "using", "via", "was", "we", "were", "when", "where", "whether",
        "which", "while", "who", "will", "with", "without", "would",
        "you",
    }
)

_CWE_PATTERN = re.compile(r"\bCWE-(?P<number>\d{1,4})\b", re.IGNORECASE)

# Every CVE identifier literally present in a document, with positions.
# Used by the attribution engine: on a page that names multiple CVEs,
# only the identifier nearest to a match may attribute the phrase, so
# feed/aggregator lines about a different CVE are never credited here.
_ANY_CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Product/vendor terms must be meaningful before they can structurally
# attribute an otherwise CVE-silent reference document.
_MIN_PRODUCT_TERM_CHARS = 5


@dataclass(frozen=True)
class IntelligenceEvidence:
    """One verbatim provenance record for one extracted value."""

    field: str
    value: str
    source_artifact: str
    source_url: str | None
    source_type: str
    evidence: str
    rule_id: str
    rule_version: str = INTELLIGENCE_RULE_VERSION


@dataclass
class ExtractedIntelligence:
    """Deterministic extraction result, including bounded provenance."""

    vulnerability_types: list[str] = dataclass_field(default_factory=list)
    cwes: list[str] = dataclass_field(default_factory=list)
    xss_types: list[str] = dataclass_field(default_factory=list)
    contexts: list[str] = dataclass_field(default_factory=list)
    parameters: list[str] = dataclass_field(default_factory=list)
    evidence: list[IntelligenceEvidence] = dataclass_field(default_factory=list)

# Maps an explicit textual vulnerability phrase to a normalized type.
# Each rule requires the full phrase shown below; a solitary weak token
# (for example, "injection") is intentionally insufficient.
VULNERABILITY_TYPE_TEXT_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "vulnerability-type-sql-injection",
        "sql_injection",
        r"\b(?:sql\s+injection|sqli)\b",
    ),
    (
        "vulnerability-type-cross-site-scripting",
        "xss",
        r"\bcross[-\s]?site\s+script(?:ing)?\b|\bxss\b",
    ),
    (
        "vulnerability-type-path-traversal",
        "path_traversal",
        r"\b(?:path|directory)\s+traversal\b",
    ),
    (
        "vulnerability-type-authentication-bypass",
        "authentication_bypass",
        r"\bauthentication\s+bypass\b",
    ),
    (
        "vulnerability-type-code-injection",
        "code_injection",
        r"\bcode\s+injection\b",
    ),
    (
        "vulnerability-type-command-injection",
        "command_injection",
        r"\b(?:os\s+)?command\s+injection\b",
    ),
    (
        "vulnerability-type-cross-site-request-forgery",
        "csrf",
        r"\bcross[-\s]?site\s+request\s+forgery\b|\bcsrf\b",
    ),
    (
        "vulnerability-type-server-side-request-forgery",
        "ssrf",
        r"\bserver[-\s]?side\s+request\s+forgery\b|\bssrf\b",
    ),
    (
        "vulnerability-type-xml-external-entity",
        "xxe",
        r"\bxml\s+external\s+entit(?:y|ies)\b|\bxxe\b",
    ),
    (
        "vulnerability-type-local-file-inclusion",
        "local_file_inclusion",
        r"\blocal\s+file\s+inclusion\b|\blfi\b",
    ),
    (
        "vulnerability-type-remote-code-execution",
        "remote_code_execution",
        r"\bremote\s+code\s+execution\b|\brce\b",
    ),
)

# Maps unambiguous NVD weakness identifiers to normalized types.
# CWE alone never implies an XSS subtype or an injection context.
VULNERABILITY_TYPE_CWE_RULES: tuple[tuple[str, str, str], ...] = (
    ("vulnerability-type-cwe-79", "xss", "79"),
    ("vulnerability-type-cwe-89", "sql_injection", "89"),
    ("vulnerability-type-cwe-22", "path_traversal", "22"),
    ("vulnerability-type-cwe-352", "csrf", "352"),
    ("vulnerability-type-cwe-611", "xxe", "611"),
    ("vulnerability-type-cwe-78", "command_injection", "78"),
    ("vulnerability-type-cwe-94", "code_injection", "94"),
    ("vulnerability-type-cwe-918", "ssrf", "918"),
)

# XSS subtypes require their explicit identifying phrases. Generic XSS
# wording therefore supports vulnerability_type=xss but never an XSS
# subtype. Case is ignored by the compiled expressions below.
XSS_TYPE_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "xss-type-reflected",
        "reflected",
        r"\breflected\s+(?:cross[-\s]?site\s+)?script(?:ing)?\b|\breflected\s+xss\b",
    ),
    (
        "xss-type-stored",
        "stored",
        r"\b(?:stored|persistent)\s+(?:cross[-\s]?site\s+)?script(?:ing)?\b"
        r"|\b(?:stored|persistent)\s+xss\b",
    ),
    (
        "xss-type-dom",
        "dom",
        r"\bdom(?:[-\s]?based)?\s+(?:cross[-\s]?site\s+)?script(?:ing)?\b"
        r"|\bdom(?:[-\s]?based)?\s+xss\b",
    ),
)

# Injection/sink contexts require explicit context wording. The query
# or artifact being XSS-adjacent is not enough.
CONTEXT_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "injection-context-html-attribute",
        "html_attribute",
        r"\bhtml\s+attributes?\b|\battribute\s+contexts?\b|\bquoted\s+attributes?\b"
        r"|\bevent\s+handlers?\b",
    ),
    (
        "injection-context-script",
        "script",
        r"\bscript\s+contexts?\b|\bwithin\s+a\s+script\b|\binside\s+a\s+script\b"
        r"|\bscript\s+blocks?\b",
    ),
    (
        "injection-context-javascript",
        "javascript",
        r"\bjavascript\s+(?:contexts?|code)\b|\bjs\s+contexts?\b",
    ),
    (
        "injection-context-url",
        "url",
        r"\burl\s+contexts?\b|\burl[-\s]?based\s+contexts?\b|\bin\s+the\s+url\b",
    ),
)

# Named injection parameters require either the conventional quoted
# "the <name> parameter" construction or an explicit request-source
# qualifier ("GET/POST/URL parameter <name>"). Generic reports that a
# vulnerability merely has parameters cannot identify a name.
PARAMETER_RULES: tuple[tuple[str, str], ...] = (
    (
        "parameter-named-explicit",
        rf"\bthe\s+[`'\"‘’“”]?({_PARAMETER_RE})[`'\"‘’“”]?\s+"
        r"(?:get|post|http|url|query|request|form|cookie)?\s*"
        r"(?:parameter|argument|field)\b",
    ),
    (
        "parameter-request-qualified",
        rf"\b(?:get|post|http|url|query|request|form|cookie)\s+"
        rf"(?:parameter|argument|field|variable)\s+[`'\"‘’“”]?({_PARAMETER_RE})",
    ),
    (
        "parameter-name-first",
        rf"\bparameter\s+[`'\"‘’“”]?({_PARAMETER_RE})",
    ),
)

_VULNERABILITY_TEXT_PATTERNS = tuple(
    (rule_id, value, re.compile(pattern, re.IGNORECASE))
    for rule_id, value, pattern in VULNERABILITY_TYPE_TEXT_RULES
)
_XSS_PATTERNS = tuple(
    (rule_id, value, re.compile(pattern, re.IGNORECASE))
    for rule_id, value, pattern in XSS_TYPE_RULES
)
_CONTEXT_PATTERNS = tuple(
    (rule_id, value, re.compile(pattern, re.IGNORECASE))
    for rule_id, value, pattern in CONTEXT_RULES
)
_PARAMETER_PATTERNS = tuple(
    (rule_id, re.compile(pattern, re.IGNORECASE))
    for rule_id, pattern in PARAMETER_RULES
)


def _ordered_unique(values: list[str]) -> list[str]:
    """Return values once each, preserving deterministic first-seen order."""

    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def _normalize_parameter_name(name: str | None) -> str | None:
    """Normalize a candidate parameter and reject generic wording."""

    if not name:
        return None
    normalized = name.strip().strip("`'\"‘’“”").strip().lower()
    normalized = normalized.rstrip("=:,;")
    if not re.fullmatch(_PARAMETER_RE, normalized, re.IGNORECASE):
        return None
    if normalized in _NON_PARAMETER_NAMES:
        return None
    if normalized.startswith(("http", "www", "cve-", "file-")):
        return None
    return normalized


def _mentions_cve_id(text: str, cve_id: str) -> bool:
    """Check whether text names this CVE (case-insensitive)."""

    normalized_cve = (cve_id or "").strip().lower()
    return bool(normalized_cve) and normalized_cve in text.lower()


def _window_mentions_cve_id(
    text: str, match: re.Match[str], cve_id: str
) -> bool:
    """Require the same CVE near the extraction match (bounded)."""

    window = text[
        max(0, match.start() - MAX_EVIDENCE_WINDOW_CHARS) : min(
            len(text), match.end() + MAX_EVIDENCE_WINDOW_CHARS
        )
    ].lower()
    return _mentions_cve_id(window, cve_id)


class _Attributor:
    """Decide which CVE a matched phrase belongs to (deterministic).

    Attribution modes, in strictness order, evaluated per document text:

    - ``structural``: the text comes from this CVE's own research
      artifact whose ``cve.id`` equals this CVE; every match in it is
      about this CVE by construction.
    - Multi-CVE document (names a CVE other than ours): a match is
      attributable only when our CVE is the unique nearest CVE
      identifier and lies within the bounded evidence window. A tie in
      distance rejects (ambiguous).
    - Single-CVE document (names only ours): bounded-window adjacency
      to one of our CVE mentions (as before).
    - CVE-silent document (names no CVE id): attributable only when a
      normalized product/vendor term of this CVE literally occurs in
      the document, linking the page to this CVE's NVD identity.
      Conservative: the same explicit-phrase rules still gate every
      extracted value; no CVE id anywhere means no subtype can be
      invented unless the subtype phrase itself is literally present.
    """

    __slots__ = ("cve_id", "ours", "others", "product_terms", "structural")

    def __init__(
        self,
        cve_id: str,
        text: str,
        *,
        product_terms: tuple[str, ...] = (),
        structural: bool = False,
    ) -> None:
        self.cve_id = (cve_id or "").strip().lower()
        self.structural = structural
        self.ours: list[tuple[int, int]] = []
        self.others: list[tuple[int, int]] = []
        for match in _ANY_CVE_ID_PATTERN.finditer(text):
            if match.group(0).lower() == self.cve_id and self.cve_id:
                self.ours.append((match.start(), match.end()))
            else:
                self.others.append((match.start(), match.end()))
        lowered = text.lower()
        self.product_terms = tuple(
            term
            for term in (t.lower() for t in product_terms)
            if len(term) >= _MIN_PRODUCT_TERM_CHARS and term in lowered
        )

    @staticmethod
    def _distance(match: re.Match[str], spans: list[tuple[int, int]]) -> int:
        best = None
        for start, end in spans:
            if end <= match.start():
                delta = match.start() - end
            elif start >= match.end():
                delta = start - match.end()
            else:
                delta = 0
            if best is None or delta < best:
                best = delta
        return -1 if best is None else best

    def accepts(self, text: str, match: re.Match[str]) -> bool:
        if self.structural:
            return True
        ours_distance = self._distance(match, self.ours)
        others_distance = self._distance(match, self.others)
        if self.ours and self.others:
            if ours_distance < 0 or ours_distance > MAX_EVIDENCE_WINDOW_CHARS:
                return False
            if others_distance >= 0 and others_distance <= ours_distance:
                return False
            return True
        if self.ours:
            return _window_mentions_cve_id(text, match, self.cve_id)
        return bool(self.product_terms)


def _evidence_window(text: str, start: int, end: int) -> str:
    """Return one bounded verbatim window around a regex match."""

    window_start = max(0, start - MAX_EVIDENCE_WINDOW_CHARS)
    window_end = min(len(text), end + MAX_EVIDENCE_WINDOW_CHARS)
    snippet = " ".join(text[window_start:window_end].split())
    if len(snippet) > MAX_EVIDENCE_SNIPPET_CHARS:
        snippet = snippet[:MAX_EVIDENCE_SNIPPET_CHARS].rstrip()
    return snippet


def _record(
    result: ExtractedIntelligence,
    *,
    field: str,
    value: str,
    text: str,
    start: int,
    end: int,
    source_artifact: str,
    source_url: str | None,
    source_type: str,
    rule_id: str,
) -> None:
    result.evidence.append(
        IntelligenceEvidence(
            field=field,
            value=value,
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=source_type,
            evidence=_evidence_window(text, start, end),
            rule_id=rule_id,
        )
    )

def _texts_from_research(payload: dict[str, object]) -> dict[str, str]:
    """Collect explicit research text without manufacturing prose."""

    research = payload.get("research")
    research_map = research if isinstance(research, dict) else {}
    texts: dict[str, str] = {}
    for key in (
        "title",
        "summary",
        "vulnerability_type",
        "root_cause",
        "description",
    ):
        value = research_map.get(key)
        if isinstance(value, str) and value.strip():
            texts[f"research.{key}"] = value
    for key in ("evidence", "references", "impact", "attack_requirements"):
        value = research_map.get(key)
        if isinstance(value, list):
            joined = "\n".join(
                str(item).strip() for item in value if str(item).strip()
            )
            if joined:
                texts[f"research.{key}"] = joined
    return texts


def _cwes_from_research(payload: dict[str, object]) -> list[str]:
    """Collect explicit NVD/CVE weakness identifiers when present."""

    candidates: list[str] = []
    for container in (payload.get("cve"), payload.get("metadata")):
        if not isinstance(container, dict):
            continue
        for key in ("cwes", "weaknesses", "cwe"):
            value = container.get(key)
            if isinstance(value, str):
                candidates.append(value)
            elif isinstance(value, list):
                candidates.extend(str(item) for item in value)
    cwes: list[str] = []
    for candidate in candidates:
        cwes.extend(
            f"CWE-{match.group('number')}"
            for match in _CWE_PATTERN.finditer(candidate)
        )
    return _ordered_unique(cwes)


def _extract_cwe_types(
    result: ExtractedIntelligence,
    cwes: list[str],
    *,
    source_artifact: str,
    source_url: str | None,
    source_type: str,
) -> None:
    """Map only unambiguous weakness identifiers to broad types."""

    for candidate in cwes:
        number = candidate.upper().replace("CWE-", "", 1)
        for rule_id, value, rule_number in VULNERABILITY_TYPE_CWE_RULES:
            if number != rule_number:
                continue
            result.vulnerability_types.append(value)
            result.cwes.append(candidate.upper())
            _record(
                result,
                field="vulnerability_type",
                value=value,
                text=candidate,
                start=0,
                end=len(candidate),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )
            _record(
                result,
                field="cwe",
                value=candidate.upper(),
                text=candidate,
                start=0,
                end=len(candidate),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )


def _extract_types_from_text(
    result: ExtractedIntelligence,
    text: str,
    attributor: _Attributor,
    *,
    source_artifact: str,
    source_url: str | None,
    source_type: str,
) -> None:
    """Apply explicit vulnerability, subtype, and context phrases.

    Attribution is decided by the ``_Attributor`` for this document:
    evidence about a neighboring CVE (or page chrome naming another
    CVE) is never credited to this CVE's intelligence.
    """

    bounded = text[:MAX_INTELLIGENCE_TEXT_CHARS]
    for rule_id, value, pattern in _VULNERABILITY_TEXT_PATTERNS:
        for match in pattern.finditer(bounded):
            if not attributor.accepts(bounded, match):
                continue
            result.vulnerability_types.append(value)
            _record(
                result,
                field="vulnerability_type",
                value=value,
                text=bounded,
                start=match.start(),
                end=match.end(),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )
    for rule_id, value, pattern in _XSS_PATTERNS:
        for match in pattern.finditer(bounded):
            if not attributor.accepts(bounded, match):
                continue
            result.xss_types.append(value)
            _record(
                result,
                field="xss_type",
                value=value,
                text=bounded,
                start=match.start(),
                end=match.end(),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )
    for rule_id, value, pattern in _CONTEXT_PATTERNS:
        for match in pattern.finditer(bounded):
            if not attributor.accepts(bounded, match):
                continue
            result.contexts.append(value)
            _record(
                result,
                field="context",
                value=value,
                text=bounded,
                start=match.start(),
                end=match.end(),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )
    for rule_id, pattern in _PARAMETER_PATTERNS:
        for match in pattern.finditer(bounded):
            name = _normalize_parameter_name(match.group(1))
            if name is None:
                continue
            if not attributor.accepts(bounded, match):
                continue
            result.parameters.append(name)
            _record(
                result,
                field="parameter",
                value=name,
                text=bounded,
                start=match.start(),
                end=match.end(),
                source_artifact=source_artifact,
                source_url=source_url,
                source_type=source_type,
                rule_id=rule_id,
            )

def _reference_sources(
    records: object,
) -> list[tuple[str, str | None, str]]:
    """Return deterministic (text, URL, type) reference evidence."""

    if not isinstance(records, list):
        return []
    sources: list[tuple[str, str | None, str]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        url = record.get("source_url")
        source_url = str(url).strip() if str(url or "").strip() else None
        source_type = str(record.get("source_type") or "reference").strip()
        parts: list[str] = []
        title = record.get("title")
        if isinstance(title, str) and title.strip():
            parts.append(title.strip())
        # Stage R13: normalized extracted body, when persisted, is
        # explicit reference evidence. R12 rules themselves are
        # untouched; this only widens the text the rules run over.
        body = record.get("body")
        if isinstance(body, str) and body.strip():
            parts.append(body.strip()[:MAX_INTELLIGENCE_TEXT_CHARS])
        chunks = record.get("context_chunks")
        if isinstance(chunks, list):
            for chunk in chunks:
                text = str(chunk or "").strip()
                if text:
                    parts.append(text)
        exact = record.get("exact_record")
        if isinstance(exact, str) and exact.strip():
            parts.append(exact.strip())
        text = "\n".join(parts).strip()
        if text:
            sources.append(
                (text[:MAX_INTELLIGENCE_TEXT_CHARS], source_url, source_type)
            )
    # Lexicographic source order keeps repeated runs deterministic when
    # callers pass the same records in any order.
    sources.sort(key=lambda item: ((item[1] or ""), item[2], item[0]))
    return sources


def product_terms_from_payload(payload: dict[str, object]) -> tuple[str, ...]:
    """Normalized vendor/product names stated by the CVE record itself."""

    cve = payload.get("cve")
    cve_map = cve if isinstance(cve, dict) else {}
    terms: list[str] = []
    for key in ("products", "product", "vendor"):
        value = cve_map.get(key)
        items = value if isinstance(value, list) else [value]
        for item in items:
            text = " ".join(str(item or "").lower().split())
            if len(text) >= _MIN_PRODUCT_TERM_CHARS:
                terms.append(text)
    return tuple(sorted(set(terms)))


def extract_research_intelligence(
    cve_id: str,
    payload: dict[str, object],
    records: object,
    *,
    product_terms: tuple[str, ...] | None = None,
) -> ExtractedIntelligence:
    """Extract intelligence only from explicit persisted evidence."""

    result = ExtractedIntelligence()
    normalized_cve = (cve_id or "").strip()
    source_artifact = f"{normalized_cve or 'UNKNOWN'}.cli.json"
    payload_map = payload if isinstance(payload, dict) else {}
    terms = product_terms if product_terms is not None else product_terms_from_payload(
        payload_map
    )

    _extract_cwe_types(
        result,
        _cwes_from_research(payload_map),
        source_artifact=source_artifact,
        source_url=None,
        source_type="research",
    )
    if isinstance(payload, dict):
        payload_cve = payload_map.get("cve")
        payload_cve_id = (
            str(payload_cve.get("id") or "").strip().lower()
            if isinstance(payload_cve, dict)
            else ""
        )
        structural = bool(
            normalized_cve and payload_cve_id == normalized_cve.lower()
        )
        for _source, text in sorted(_texts_from_research(payload).items()):
            bounded = text[:MAX_INTELLIGENCE_TEXT_CHARS]
            _extract_types_from_text(
                result,
                bounded,
                _Attributor(
                    normalized_cve, bounded, product_terms=terms,
                    structural=structural,
                ),
                source_artifact=source_artifact,
                source_url=None,
                source_type="research",
            )

    for text, source_url, source_type in _reference_sources(records):
        bounded = text[:MAX_INTELLIGENCE_TEXT_CHARS]
        _extract_types_from_text(
            result,
            bounded,
            _Attributor(
                normalized_cve, bounded, product_terms=terms,
            ),
            source_artifact=source_artifact,
            source_url=source_url,
            source_type=source_type,
        )

    result.vulnerability_types = _ordered_unique(result.vulnerability_types)
    result.cwes = _ordered_unique(result.cwes)
    result.xss_types = _ordered_unique(result.xss_types)
    result.contexts = _ordered_unique(result.contexts)
    result.parameters = _ordered_unique(result.parameters)
    result.evidence.sort(
        key=lambda item: (
            item.field,
            item.value,
            item.rule_id,
            item.source_url or "",
            item.evidence,
        )
    )
    return result
