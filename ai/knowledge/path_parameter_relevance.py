"""Stage R31.8 deterministic path/parameter relevance evidence (pure engine).

Answers, for research-side Asset<->CVE matching: *does an observed
endpoint/path/parameter provide meaningful evidence that the observed asset is
relevant to this CVE's vulnerability surface?*

This is supporting evidence only. It never proves exploitability, never
executes anything, and never changes confidence by itself. R30.1 confidence,
R31.5 component scope/provenance, R31.6 identity and R31.7 version evidence
remain authoritative.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no persistence, no execution.
- Deterministic: exact normalized set/dict membership and documented
  component-boundary prefix checks. No substring, token-intersection or fuzzy
  matching.
- Conservative: unsupported/ambiguous research paths are ``UNKNOWN`` /
  ``AMBIGUOUS``; nothing is invented from CVE prose.
- Path-only and name-only evidence: query strings, fragments and parameter
  values are dropped during normalization and never stored. Credential-like
  material (userinfo, bearer tokens, secret-like key=value pairs) is redacted
  before anything reaches an evidence structure.
- Bounded: evidence rows and value lengths are capped deterministically.

Only CVE-side structured data is consulted (the adapter passes the same
research paths/parameters already used by the matching input); the module never
scans arbitrary text for routes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ai.knowledge.asset_cve_matching import (
    normalize_parameter as normalize_parameter_name,
)

RULE_VERSION = "r31-8"

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

ET_EXACT_PATH = "EXACT_PATH"
ET_PATH_PREFIX = "PATH_PREFIX"
ET_PATH_PATTERN = "PATH_PATTERN"
ET_EXACT_PARAMETER = "EXACT_PARAMETER"
ET_PARAMETER_SET = "PARAMETER_SET"
ET_HTTP_METHOD = "HTTP_METHOD"
ET_NO_EVIDENCE = "NO_EVIDENCE"
ET_AMBIGUOUS = "AMBIGUOUS"
ET_UNKNOWN = "UNKNOWN"

EVIDENCE_TYPES: tuple[str, ...] = (
    ET_EXACT_PATH,
    ET_PATH_PREFIX,
    ET_PATH_PATTERN,
    ET_EXACT_PARAMETER,
    ET_PARAMETER_SET,
    ET_HTTP_METHOD,
    ET_NO_EVIDENCE,
    ET_AMBIGUOUS,
    ET_UNKNOWN,
)

COMPARISON_MATCH = "MATCH"
COMPARISON_NO_MATCH = "NO_MATCH"
COMPARISON_INDETERMINATE = "INDETERMINATE"

COMPARISONS: tuple[str, ...] = (
    COMPARISON_MATCH,
    COMPARISON_NO_MATCH,
    COMPARISON_INDETERMINATE,
)

# Aggregate state when no research dimension exists at all.
STATE_NO_EVIDENCE = "NO_EVIDENCE"
RELEVANCE_STATES: tuple[str, ...] = COMPARISONS + (STATE_NO_EVIDENCE,)

METHOD_EXACT = "EXACT"
METHOD_NORMALIZED = "NORMALIZED"
METHOD_PREFIX = "PREFIX"
METHOD_PATTERN = "PATTERN"
METHOD_PARAMETER_EXACT = "PARAMETER_EXACT"
METHOD_METHOD_EXACT = "METHOD_EXACT"
METHOD_NONE = "NO_METHOD"

RESOLUTION_METHODS: tuple[str, ...] = (
    METHOD_EXACT,
    METHOD_NORMALIZED,
    METHOD_PREFIX,
    METHOD_PATTERN,
    METHOD_PARAMETER_EXACT,
    METHOD_METHOD_EXACT,
    METHOD_NONE,
)

HTTP_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
)

MAX_VALUE_LEN = 256
MAX_EVIDENCE_ROWS = 64
MAX_RESEARCH_ITEMS = 256

_MULTI_SLASH_RE = re.compile(r"/{2,}")
_SINGLE_LINE_RE = re.compile(r"[\x00-\x1f\x7f]+")
_AMBIGUOUS_PATH_RE = re.compile(r"[{}\s]")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*([^&\s;]+)"
)
_SENSITIVE_QUERY_RE = re.compile(
    r"(?i)([?&](?:password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|auth)=)"
    r"([^&#\s]+)"
)


# ---------------------------------------------------------------------------
# Sanitization (credentials / secret-like material never enters evidence)
# ---------------------------------------------------------------------------


def _sanitize(value: object) -> str:
    """Collapse control characters, bound length, redact credentials."""

    text = _SINGLE_LINE_RE.sub(" ", str(value if value is not None else ""))
    text = " ".join(text.split())
    if not text:
        return ""
    text = _USERINFO_RE.sub("://[redacted]@", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _SECRET_PAIR_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]", text
    )
    text = _SENSITIVE_QUERY_RE.sub(
        lambda match: f"{match.group(1)}[redacted]", text
    )
    return text[:MAX_VALUE_LEN]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_path(value: object) -> str:
    """Deterministic path-only normalization.

    - strips scheme/host (full URLs keep only the path),
    - drops query string and fragment,
    - collapses repeated slashes,
    - forces a leading slash and strips a trailing slash (root stays "/"),
    - preserves case and path characters (no URL decoding, no lowercasing).
    """

    text = _sanitize(value)
    if not text:
        return ""
    if "://" in text or text.startswith("//"):
        try:
            text = urlsplit(text).path or ""
        except ValueError:
            return ""
    text = text.split("?", 1)[0].split("#", 1)[0]
    text = _MULTI_SLASH_RE.sub("/", text).strip()
    if not text:
        return ""
    if not text.startswith("/"):
        text = "/" + text
    text = text.rstrip("/") or "/"
    return text[:MAX_VALUE_LEN]


@dataclass(frozen=True)
class _ResearchPath:
    raw: str
    root: str
    kind: str  # exact | prefix | pattern | ambiguous | unknown


def _research_path(value: object) -> _ResearchPath:
    raw = _sanitize(value)
    if not raw:
        return _ResearchPath("", "", ET_UNKNOWN)
    if _AMBIGUOUS_PATH_RE.search(raw):
        return _ResearchPath(raw, "", ET_AMBIGUOUS)
    is_pattern = raw.endswith("/*")
    is_prefix = raw.endswith("/") or is_pattern
    if is_pattern:
        raw = raw[: -len("/*")]
    root = normalize_path(raw)
    if not root or root == "/":
        return _ResearchPath(raw, "", ET_UNKNOWN)
    kind = ET_PATH_PATTERN if is_pattern else (
        ET_PATH_PREFIX if is_prefix else ET_EXACT_PATH
    )
    return _ResearchPath(raw, root, kind)


def normalize_parameter(value: object) -> tuple[str, str]:
    """Return (normalized_key, display_name) for one parameter.

    Only the name is kept: ``?file=secret`` -> ``("file", "file")``. Values
    are discarded before any comparison or evidence.
    """

    text = _sanitize(value)
    if not text:
        return "", ""
    text = text.strip().lstrip("?&")
    if "=" in text:
        text = text.split("=", 1)[0]
    display = text.strip()
    key = normalize_parameter_name(display)
    return key, display


def normalize_method(value: object) -> str:
    text = _sanitize(value).strip().upper()
    return text if text in HTTP_METHODS else ""


# ---------------------------------------------------------------------------
# Observed index
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservedRelevanceIndex:
    """Pre-normalized observed lookup structures (O(1) research lookups)."""

    paths: dict
    path_prefixes: frozenset
    parameters: dict
    parameter_paths: dict
    methods: frozenset


def _directory_prefixes(normalized_paths: object) -> frozenset:
    prefixes: set[str] = set()
    for path in normalized_paths:
        parts = [part for part in path.split("/") if part]
        for index in range(1, len(parts)):
            prefixes.add("/" + "/".join(parts[:index]))
    return frozenset(prefixes)


def build_observed_relevance_index(
    *,
    paths: object = (),
    parameters: object = (),
    parameter_locations: object = None,
    methods: object = (),
) -> ObservedRelevanceIndex:
    """Build the deterministic observed index once per evaluation."""

    path_map: dict[str, str] = {}
    for value in paths or ():
        key = normalize_path(value)
        if key and key not in path_map:
            # Evidence stays path-only: the display is the normalized path
            # (query/fragment/credentials already removed).
            path_map[key] = key

    parameter_map: dict[str, str] = {}
    for value in parameters or ():
        key, display = normalize_parameter(value)
        if key and key not in parameter_map:
            parameter_map[key] = display

    location_map: dict[str, frozenset] = {}
    if isinstance(parameter_locations, dict):
        for raw_name, locations in parameter_locations.items():
            key, _ = normalize_parameter(raw_name)
            if not key:
                continue
            normalized = {
                normalize_path(location)
                for location in (locations or ())
                if normalize_path(location)
            }
            if normalized:
                location_map[key] = frozenset(normalized)

    method_set = frozenset(
        method
        for method in (normalize_method(value) for value in methods or ())
        if method
    )
    return ObservedRelevanceIndex(
        paths=path_map,
        path_prefixes=_directory_prefixes(path_map),
        parameters=parameter_map,
        parameter_paths=location_map,
        methods=method_set,
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

_EVIDENCE_ORDER: dict[str, int] = {
    ET_EXACT_PATH: 0,
    ET_EXACT_PARAMETER: 1,
    ET_HTTP_METHOD: 2,
    ET_PATH_PREFIX: 3,
    ET_PARAMETER_SET: 4,
    ET_PATH_PATTERN: 5,
    ET_NO_EVIDENCE: 6,
    ET_AMBIGUOUS: 7,
    ET_UNKNOWN: 8,
}

_RESULT_ORDER: dict[str, int] = {
    COMPARISON_MATCH: 0,
    COMPARISON_INDETERMINATE: 1,
    COMPARISON_NO_MATCH: 2,
}


def _in_scope(path: str, scope: str) -> bool:
    if not path or not scope:
        return False
    normalized_scope = normalize_path(scope)
    if not normalized_scope:
        return False
    return path == normalized_scope or path.startswith(
        normalized_scope.rstrip("/") + "/"
    )


def _row(
    *,
    result: str,
    evidence_type: str,
    resolution_method: str,
    reason: str,
    observed_path: str = "",
    research_path: str = "",
    observed_parameter: str = "",
    research_parameter: str = "",
    observed_method: str = "",
    research_method: str = "",
    component_scoped: bool = False,
) -> dict:
    return {
        "result": result,
        "evidence_type": evidence_type,
        "resolution_method": resolution_method,
        "observed_path": _sanitize(observed_path),
        "research_path": _sanitize(research_path),
        "observed_parameter": _sanitize(observed_parameter),
        "research_parameter": _sanitize(research_parameter),
        "observed_method": _sanitize(observed_method),
        "research_method": _sanitize(research_method),
        "component_scoped": bool(component_scoped),
        "reason": reason[:MAX_VALUE_LEN],
        "rule_version": RULE_VERSION,
    }


def _path_rows(
    research_paths: object,
    index: ObservedRelevanceIndex,
    scopes: tuple[str, ...],
) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for value in list(research_paths or ())[:MAX_RESEARCH_ITEMS]:
        parsed = _research_path(value)
        if not parsed.raw or parsed.raw in seen:
            continue
        seen.add(parsed.raw)
        if parsed.kind in (ET_AMBIGUOUS, ET_UNKNOWN):
            rows.append(
                _row(
                    result=COMPARISON_INDETERMINATE,
                    evidence_type=(
                        ET_AMBIGUOUS if parsed.kind == ET_AMBIGUOUS
                        else ET_UNKNOWN
                    ),
                    resolution_method=METHOD_NONE,
                    research_path=parsed.raw,
                    reason=(
                        "research path syntax is ambiguous or unsupported; "
                        "raw value preserved"
                    ),
                )
            )
            continue
        if parsed.kind == ET_EXACT_PATH:
            observed = index.paths.get(parsed.root, "")
            if observed:
                scoped = any(_in_scope(parsed.root, s) for s in scopes)
                rows.append(
                    _row(
                        result=COMPARISON_MATCH,
                        evidence_type=ET_EXACT_PATH,
                        resolution_method=(
                            METHOD_NORMALIZED
                            if _sanitize(value) != parsed.root
                            else METHOD_EXACT
                        ),
                        observed_path=observed,
                        research_path=parsed.raw,
                        component_scoped=scoped,
                        reason=(
                            "observed path exactly matches the research "
                            f"path {parsed.root}"
                        ),
                    )
                )
            else:
                rows.append(
                    _row(
                        result=COMPARISON_NO_MATCH,
                        evidence_type=ET_EXACT_PATH,
                        resolution_method=METHOD_EXACT,
                        research_path=parsed.raw,
                        reason=(
                            "no observed path exactly matches the research "
                            f"path {parsed.root}"
                        ),
                    )
                )
            continue
        # Explicit subtree: prefix or trailing-wildcard pattern.
        in_index = (
            parsed.root in index.paths
            or parsed.root in index.path_prefixes
        )
        if in_index:
            scoped = any(_in_scope(parsed.root, s) for s in scopes)
            rows.append(
                _row(
                    result=COMPARISON_MATCH,
                    evidence_type=parsed.kind,
                    resolution_method=(
                        METHOD_PATTERN if parsed.kind == ET_PATH_PATTERN
                        else METHOD_PREFIX
                    ),
                    research_path=parsed.raw,
                    component_scoped=scoped,
                    reason=(
                        "observed endpoints exist under the research "
                        f"subtree {parsed.root}"
                    ),
                )
            )
        else:
            rows.append(
                _row(
                    result=COMPARISON_NO_MATCH,
                    evidence_type=parsed.kind,
                    resolution_method=(
                        METHOD_PATTERN if parsed.kind == ET_PATH_PATTERN
                        else METHOD_PREFIX
                    ),
                    research_path=parsed.raw,
                    reason=(
                        "no observed endpoint exists under the research "
                        f"subtree {parsed.root}"
                    ),
                )
            )
    return rows


def _parameter_rows(
    research_parameters: object,
    index: ObservedRelevanceIndex,
    scopes: tuple[str, ...],
) -> list[dict]:
    rows: list[dict] = []
    matched: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    items = list(research_parameters or ())[:MAX_RESEARCH_ITEMS]
    for value in items:
        key, display = normalize_parameter(value)
        if not key or key in seen:
            continue
        seen.add(key)
        observed = index.parameters.get(key, "")
        if not observed:
            rows.append(
                _row(
                    result=COMPARISON_NO_MATCH,
                    evidence_type=ET_EXACT_PARAMETER,
                    resolution_method=METHOD_PARAMETER_EXACT,
                    research_parameter=display,
                    reason=(
                        f"no observed parameter is named {display!r}"
                    ),
                )
            )
            continue
        locations = index.parameter_paths.get(key, frozenset())
        scoped = any(
            _in_scope(location, scope)
            for location in locations
            for scope in scopes
        )
        matched.append((display, observed, scoped))
        rows.append(
            _row(
                result=COMPARISON_MATCH,
                evidence_type=ET_EXACT_PARAMETER,
                resolution_method=METHOD_PARAMETER_EXACT,
                observed_parameter=observed,
                research_parameter=display,
                component_scoped=scoped,
                reason=(
                    f"observed parameter {observed!r} exactly matches the "
                    f"research parameter {display!r}"
                ),
            )
        )
    if len(seen) > 1:
        rows.append(
            _row(
                result=(
                    COMPARISON_MATCH if matched else COMPARISON_NO_MATCH
                ),
                evidence_type=ET_PARAMETER_SET,
                resolution_method=METHOD_PARAMETER_EXACT,
                component_scoped=any(item[2] for item in matched),
                reason=(
                    f"{len(matched)} of {len(seen)} research parameters "
                    "were observed"
                ),
            )
        )
    return rows


def _method_rows(
    research_methods: object,
    index: ObservedRelevanceIndex,
) -> tuple[list[dict], dict]:
    research = []
    seen: set[str] = set()
    for value in list(research_methods or ())[:MAX_RESEARCH_ITEMS]:
        method = normalize_method(value)
        if method and method not in seen:
            seen.add(method)
            research.append(method)
    summary = {
        "research": research,
        "observed": sorted(index.methods),
        "result": COMPARISON_INDETERMINATE,
        "evidence_type": ET_NO_EVIDENCE,
    }
    if not research:
        summary["reason"] = "research does not specify an HTTP method"
        return [], summary
    rows: list[dict] = []
    if not index.methods:
        summary["evidence_type"] = ET_HTTP_METHOD
        summary["reason"] = "no observed HTTP method evidence is available"
        return rows, summary
    matched = [method for method in research if method in index.methods]
    for method in research:
        rows.append(
            _row(
                result=(
                    COMPARISON_MATCH if method in index.methods
                    else COMPARISON_NO_MATCH
                ),
                evidence_type=ET_HTTP_METHOD,
                resolution_method=METHOD_METHOD_EXACT,
                research_method=method,
                reason=(
                    f"research method {method} "
                    + (
                        "was observed"
                        if method in index.methods
                        else "was not observed"
                    )
                ),
            )
        )
    summary["evidence_type"] = ET_HTTP_METHOD
    summary["result"] = (
        COMPARISON_MATCH if matched else COMPARISON_NO_MATCH
    )
    summary["reason"] = (
        f"{len(matched)} of {len(research)} research methods observed"
    )
    return rows, summary


def evaluate_path_parameter_relevance(
    *,
    research_paths: object = (),
    research_parameters: object = (),
    research_methods: object = (),
    observed_paths: object = (),
    observed_parameters: object = (),
    parameter_locations: object = None,
    observed_methods: object = (),
    component_scopes: object = (),
    index: ObservedRelevanceIndex | None = None,
    max_evidence: int = MAX_EVIDENCE_ROWS,
) -> dict:
    """Deterministic bounded relevance evidence for one CVE/program pair.

    Complexity is O(observed_paths + observed_parameters + research_items):
    the observed side is indexed once (sets/dicts) and each research item is an
    O(1) lookup; there is no path x parameter cross scan.
    """

    observed_index = index or build_observed_relevance_index(
        paths=observed_paths,
        parameters=observed_parameters,
        parameter_locations=parameter_locations,
        methods=observed_methods,
    )
    scopes = tuple(
        scope
        for scope in (
            normalize_path(value) for value in component_scopes or ()
        )
        if scope
    )

    rows = _path_rows(research_paths, observed_index, scopes)
    rows.extend(
        _parameter_rows(research_parameters, observed_index, scopes)
    )
    method_rows, method_summary = _method_rows(
        research_methods, observed_index
    )
    rows.extend(method_rows)

    rows.sort(
        key=lambda row: (
            _EVIDENCE_ORDER.get(row["evidence_type"], len(_EVIDENCE_ORDER)),
            _RESULT_ORDER.get(row["result"], len(_RESULT_ORDER)),
            row["observed_path"],
            row["research_path"],
            row["observed_parameter"],
            row["research_parameter"],
            row["observed_method"],
            row["research_method"],
        )
    )
    limit = max(1, int(max_evidence))
    rows = rows[:limit]

    counts = {
        COMPARISON_MATCH: 0,
        COMPARISON_NO_MATCH: 0,
        COMPARISON_INDETERMINATE: 0,
        "rows": len(rows),
    }
    for row in rows:
        counts[row["result"]] = counts.get(row["result"], 0) + 1

    if any(row["result"] == COMPARISON_MATCH for row in rows):
        overall = COMPARISON_MATCH
    elif any(
        row["result"] == COMPARISON_INDETERMINATE for row in rows
    ):
        overall = COMPARISON_INDETERMINATE
    elif rows:
        overall = COMPARISON_NO_MATCH
    else:
        overall = STATE_NO_EVIDENCE

    return {
        "rule_version": RULE_VERSION,
        "evidence": rows,
        "summary": {
            "result": overall,
            "evidence_types": sorted(
                {row["evidence_type"] for row in rows}
            ),
            "component_scoped": any(
                row["component_scoped"] for row in rows
            ),
            "path_match": any(
                row["result"] == COMPARISON_MATCH
                and row["evidence_type"]
                in (ET_EXACT_PATH, ET_PATH_PREFIX, ET_PATH_PATTERN)
                for row in rows
            ),
            "parameter_match": any(
                row["result"] == COMPARISON_MATCH
                and row["evidence_type"]
                in (ET_EXACT_PARAMETER, ET_PARAMETER_SET)
                for row in rows
            ),
            "method": method_summary,
            "counts": counts,
        },
    }


__all__ = [
    "RULE_VERSION",
    "EVIDENCE_TYPES",
    "COMPARISONS",
    "RELEVANCE_STATES",
    "RESOLUTION_METHODS",
    "HTTP_METHODS",
    "ET_EXACT_PATH",
    "ET_PATH_PREFIX",
    "ET_PATH_PATTERN",
    "ET_EXACT_PARAMETER",
    "ET_PARAMETER_SET",
    "ET_HTTP_METHOD",
    "ET_NO_EVIDENCE",
    "ET_AMBIGUOUS",
    "ET_UNKNOWN",
    "COMPARISON_MATCH",
    "COMPARISON_NO_MATCH",
    "COMPARISON_INDETERMINATE",
    "STATE_NO_EVIDENCE",
    "METHOD_EXACT",
    "METHOD_NORMALIZED",
    "METHOD_PREFIX",
    "METHOD_PATTERN",
    "METHOD_PARAMETER_EXACT",
    "METHOD_METHOD_EXACT",
    "METHOD_NONE",
    "ObservedRelevanceIndex",
    "normalize_path",
    "normalize_parameter",
    "normalize_method",
    "build_observed_relevance_index",
    "evaluate_path_parameter_relevance",
]
