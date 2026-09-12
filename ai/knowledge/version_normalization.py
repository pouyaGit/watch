"""Stage R31.7 deterministic version normalization and confidence (pure).

R31.6 strengthened component/plugin identity, but CVE-side affected versions
and observed versions still arrive as free-form strings (``<=1.0``,
``v1.2``, ``1.2.x``, ``< 7.1.2 (confirmed against v7.1.1, ...)``). This module
parses those strings into a small structured result so downstream code can see
*kind*, *precision*, *bounds* and a conservative comparison instead of an
ambiguous token.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no persistence, no execution.
- Conservative: unsupported prose is ``UNKNOWN`` and the raw value is
  preserved; nothing is silently converted into an exact version.
- No substring or fuzzy matching: wildcard/prefix comparisons are exact
  component-prefix checks; ``1.x`` never matches ``10.x``.
- Precision is preserved: ``1.2`` and ``1.2.0`` are distinct; comparisons
  across different precision return ``INDETERMINATE`` unless the caller
  explicitly opts into zero-padding (``allow_precision_expansion``).
- No confidence inflation: the result is evidence only. Parsing a version
  never promotes a match; the R30.1 engine and R31.5 support gates remain the
  authorities.

The module is additive: nothing here is imported by the R30.1 engine
(``ai/knowledge/asset_cve_matching.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

RULE_VERSION = "r31-7"

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

KIND_EXACT = "EXACT"
KIND_PREFIX = "PREFIX"
KIND_RANGE = "RANGE"
KIND_LOWER_BOUND = "LOWER_BOUND"
KIND_UPPER_BOUND = "UPPER_BOUND"
KIND_WILDCARD = "WILDCARD"
KIND_UNKNOWN = "UNKNOWN"

VERSION_KINDS: tuple[str, ...] = (
    KIND_EXACT,
    KIND_PREFIX,
    KIND_RANGE,
    KIND_LOWER_BOUND,
    KIND_UPPER_BOUND,
    KIND_WILDCARD,
    KIND_UNKNOWN,
)

# Parsing/evidence confidence (NOT vulnerability confidence).
CLASS_EXACT_OBSERVED = "EXACT_OBSERVED"
CLASS_NORMALIZED_EXACT = "NORMALIZED_EXACT"
CLASS_EXPLICIT_RANGE = "EXPLICIT_RANGE"
CLASS_WILDCARD_RANGE = "WILDCARD_RANGE"
CLASS_AMBIGUOUS = "AMBIGUOUS"
CLASS_UNKNOWN = "UNKNOWN"

EVIDENCE_CLASSES: tuple[str, ...] = (
    CLASS_EXACT_OBSERVED,
    CLASS_NORMALIZED_EXACT,
    CLASS_EXPLICIT_RANGE,
    CLASS_WILDCARD_RANGE,
    CLASS_AMBIGUOUS,
    CLASS_UNKNOWN,
)

COMPARISON_MATCH = "MATCH"
COMPARISON_NO_MATCH = "NO_MATCH"
COMPARISON_INDETERMINATE = "INDETERMINATE"

COMPARISONS: tuple[str, ...] = (
    COMPARISON_MATCH,
    COMPARISON_NO_MATCH,
    COMPARISON_INDETERMINATE,
)

METHOD_EXACT_PARSE = "EXACT_PARSE"
METHOD_NORMALIZED = "NORMALIZED"
METHOD_OPERATOR_PARSE = "OPERATOR_PARSE"
METHOD_RANGE_PARSE = "RANGE_PARSE"
METHOD_WILDCARD_PARSE = "WILDCARD_PARSE"
METHOD_NO_METHOD = "NO_METHOD"

RESOLUTION_METHODS: tuple[str, ...] = (
    METHOD_EXACT_PARSE,
    METHOD_NORMALIZED,
    METHOD_OPERATOR_PARSE,
    METHOD_RANGE_PARSE,
    METHOD_WILDCARD_PARSE,
    METHOD_NO_METHOD,
)

# Deterministic bounds.
MAX_VALUE_LEN = 128
MAX_VERSIONS = 64
MAX_EVIDENCE_ROWS = 64
MAX_EVIDENCE_LINES = 4

_WS_RE = re.compile(r"\s+")
_PARENTHETICAL_RE = re.compile(r"\([^)]*\)")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_EXACT_RE = re.compile(r"^\d+(?:\.\d+)*$")
_COMPARATOR_RE = re.compile(r"^(<=|>=|==|=|<|>)\s*(.+)$")
_PROSE_OPERATOR_RE = re.compile(r"^(before|up to|upto)\s+(.+)$", re.IGNORECASE)
_RANGE_RE = re.compile(r"^(.+?)\s+(?:-|to)\s+(.+)$", re.IGNORECASE)

# Privacy: credentials, authorization headers, request data must never reach
# the version output. Real version syntax (``1.2.3``, ``<=1.0``, ``1.x``,
# ``1.2*``, ranges, ``< 7.1.2``) never contains these tokens; any input that
# does is treated like a URL and fully redacted before parsing.
_CREDENTIAL_RE = re.compile(
    r"(?i)(?:authorization\s*[:=]|bearer\s+[A-Za-z0-9._\-]+|"
    r"x-api-key|x-auth-token|password\s*=|passwd\s*=|"
    r"cookie\s*[:=]|set-cookie|session\s*=|"
    r"access_token|refresh_token|"
    r"aws_access_key_id|aws_secret_access_key)"
)


# ---------------------------------------------------------------------------
# Structured result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VersionParse:
    """One deterministic version/constraint parse.

    ``raw_version`` is always preserved (bounded, control-char free).
    ``normalized_version`` is empty for ``UNKNOWN``. Bounds are stored as
    concrete component tuples for safe comparison; ``to_evidence()`` renders
    them as dotted strings.
    """

    raw_version: str
    normalized_version: str
    version_kind: str
    evidence_class: str
    resolution_method: str
    comparison_operator: str = ""
    components: tuple[int, ...] = ()
    wildcard_prefix: tuple[int, ...] = ()
    lower_bound: tuple[int, ...] | None = None
    upper_bound: tuple[int, ...] | None = None
    lower_inclusive: bool = True
    upper_inclusive: bool = True
    precision: int = 0
    reason: str = ""
    evidence: tuple[str, ...] = ()

    @property
    def is_concrete(self) -> bool:
        return self.version_kind == KIND_EXACT and bool(
            self.normalized_version
        )

    def to_evidence(self) -> dict:
        return {
            "raw_version": self.raw_version,
            "normalized_version": self.normalized_version,
            "version_kind": self.version_kind,
            "comparison_operator": self.comparison_operator,
            "lower_bound": _render(self.lower_bound),
            "upper_bound": _render(self.upper_bound),
            "lower_inclusive": self.lower_inclusive,
            "upper_inclusive": self.upper_inclusive,
            "precision": self.precision,
            "evidence_class": self.evidence_class,
            "resolution_method": self.resolution_method,
            "reason": self.reason,
            "evidence": list(self.evidence[:MAX_EVIDENCE_LINES]),
        }


def _render(components: tuple[int, ...] | None) -> str:
    if not components:
        return ""
    return ".".join(str(part) for part in components)


def _bounded(text: object, limit: int = MAX_VALUE_LEN) -> str:
    value = _CONTROL_RE.sub(" ", str(text if text is not None else ""))
    value = _WS_RE.sub(" ", value).strip()
    return value[:limit]


def _clean_raw(raw: object) -> tuple[str, bool]:
    """Return (cleaned raw, is_url_like). URL-like / credential-like values
    are redacted before any parsing so the resolver never emits
    ``http://``, ``example.com``, ``Bearer``, ``Authorization:``,
    ``X-API-Key``, ``password=``, cookies or request headers.
    """

    text = _bounded(raw)
    if "://" in text or text.startswith("//"):
        return "[redacted]", True
    if _CREDENTIAL_RE.search(text):
        return "[redacted]", True
    return text, False


def _clean_text(text: str) -> str:
    """Conservative cleaning: strip parentheticals, normalize dashes."""

    text = _PARENTHETICAL_RE.sub(" ", text)
    text = text.replace("\u2013", " - ").replace("\u2014", " - ")
    text = text.replace("\u2212", "-")
    text = _WS_RE.sub(" ", text).strip()
    return text.rstrip(" ;,.")


def _components(text: str) -> tuple[int, ...] | None:
    """Parse a concrete numeric version (optional leading v) or None."""

    candidate = text.strip()
    if candidate[:1] in ("v", "V"):
        candidate = candidate[1:].strip()
    if not _EXACT_RE.match(candidate):
        return None
    try:
        return tuple(int(part) for part in candidate.split("."))
    except ValueError:  # pragma: no cover - defensive
        return None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _unknown_parse(raw: str, reason: str) -> VersionParse:
    evidence_class = (
        CLASS_AMBIGUOUS if raw and raw != "[redacted]" else CLASS_UNKNOWN
    )
    return VersionParse(
        raw_version=raw,
        normalized_version="",
        version_kind=KIND_UNKNOWN,
        evidence_class=evidence_class,
        resolution_method=METHOD_NO_METHOD,
        reason=reason,
        evidence=(reason,),
    )


def _exact_parse(
    raw: str, components: tuple[int, ...], *, method: str
) -> VersionParse:
    normalized = _render(components)
    normalized_changed = normalized != raw
    evidence_class = (
        CLASS_NORMALIZED_EXACT
        if normalized_changed
        else CLASS_EXACT_OBSERVED
    )
    evidence: list[str] = []
    if normalized_changed:
        evidence.append(f"normalized '{raw}' to '{normalized}'")
    else:
        evidence.append(f"exact numeric version '{normalized}'")
    return VersionParse(
        raw_version=raw,
        normalized_version=normalized,
        version_kind=KIND_EXACT,
        evidence_class=evidence_class,
        resolution_method=method,
        comparison_operator="=",
        components=components,
        precision=len(components),
        reason=f"concrete numeric version {normalized}",
        evidence=tuple(evidence),
    )


def _parse_wildcard(text: str) -> VersionParse | None:
    if not re.fullmatch(r"[0-9xX*.]+", text):
        return None
    if not any(ch in "xX*" for ch in text):
        return None
    parts = text.split(".")
    last = parts[-1]
    # Trailing star appended to a numeric component: "1.2*" -> PREFIX.
    if last.endswith("*") and last != "*":
        head = last[:-1]
        if not head.isdigit():
            return None
        parts = parts[:-1] + [head]
        if not all(part.isdigit() for part in parts):
            return None
        components = tuple(int(part) for part in parts)
        normalized = _render(components) + "*"
        return VersionParse(
            raw_version=text,
            normalized_version=normalized,
            version_kind=KIND_PREFIX,
            evidence_class=CLASS_WILDCARD_RANGE,
            resolution_method=METHOD_WILDCARD_PARSE,
            wildcard_prefix=components,
            precision=len(components),
            reason=f"numeric prefix constraint {normalized}",
            evidence=(f"prefix components {_render(components)}",),
        )
    if last in ("x", "X", "*"):
        fixed = parts[:-1]
        if not fixed or not all(part.isdigit() for part in fixed):
            return None
        components = tuple(int(part) for part in fixed)
        normalized = _render(components) + ".x"
        return VersionParse(
            raw_version=text,
            normalized_version=normalized,
            version_kind=KIND_WILDCARD,
            evidence_class=CLASS_WILDCARD_RANGE,
            resolution_method=METHOD_WILDCARD_PARSE,
            wildcard_prefix=components,
            precision=len(components),
            reason=f"wildcard constraint {normalized}",
            evidence=(f"fixed wildcard components {_render(components)}",),
        )
    return None


def _parse_range(text: str) -> VersionParse | None:
    match = _RANGE_RE.match(text)
    if match is None:
        return None
    low_text, high_text = match.group(1).strip(), match.group(2).strip()
    low = _components(low_text)
    high = _components(high_text)
    if low is None or high is None:
        return None
    comparison = _compare_components(low, high)
    if comparison is not None and comparison > 0:
        return None
    normalized = f"{_render(low)} - {_render(high)}"
    return VersionParse(
        raw_version=text,
        normalized_version=normalized,
        version_kind=KIND_RANGE,
        evidence_class=CLASS_EXPLICIT_RANGE,
        resolution_method=METHOD_RANGE_PARSE,
        lower_bound=low,
        upper_bound=high,
        lower_inclusive=True,
        upper_inclusive=True,
        precision=min(len(low), len(high)),
        reason=f"inclusive range {normalized}",
        evidence=(f"range from {_render(low)} to {_render(high)}",),
    )


def _parse_operator(text: str) -> VersionParse | None:
    prose = _PROSE_OPERATOR_RE.match(text)
    if prose is not None:
        word = prose.group(1).lower()
        bound = _components(prose.group(2).strip())
        if bound is None:
            return None
        inclusive = word != "before"
        operator = "<=" if inclusive else "<"
        return VersionParse(
            raw_version=text,
            normalized_version=operator + _render(bound),
            version_kind=KIND_UPPER_BOUND,
            evidence_class=CLASS_EXPLICIT_RANGE,
            resolution_method=METHOD_OPERATOR_PARSE,
            comparison_operator=operator,
            upper_bound=bound,
            upper_inclusive=inclusive,
            precision=len(bound),
            reason=(
                f"upper bound {'<=' if inclusive else '<'} "
                f"{_render(bound)}"
            ),
            evidence=(f"prose operator '{word}' parsed conservatively",),
        )
    match = _COMPARATOR_RE.match(text)
    if match is None:
        return None
    operator, rest = match.group(1), match.group(2).strip()
    bound = _components(rest)
    if bound is None:
        return None
    if operator in ("=", "=="):
        return _exact_parse(text, bound, method=METHOD_OPERATOR_PARSE)
    if operator in ("<", "<="):
        return VersionParse(
            raw_version=text,
            normalized_version=operator + _render(bound),
            version_kind=KIND_UPPER_BOUND,
            evidence_class=CLASS_EXPLICIT_RANGE,
            resolution_method=METHOD_OPERATOR_PARSE,
            comparison_operator=operator,
            upper_bound=bound,
            upper_inclusive=operator == "<=",
            precision=len(bound),
            reason=f"upper bound {operator}{_render(bound)}",
            evidence=(f"operator '{operator}' parsed as upper bound",),
        )
    return VersionParse(
        raw_version=text,
        normalized_version=operator + _render(bound),
        version_kind=KIND_LOWER_BOUND,
        evidence_class=CLASS_EXPLICIT_RANGE,
        resolution_method=METHOD_OPERATOR_PARSE,
        comparison_operator=operator,
        lower_bound=bound,
        lower_inclusive=operator == ">=",
        precision=len(bound),
        reason=f"lower bound {operator}{_render(bound)}",
        evidence=(f"operator '{operator}' parsed as lower bound",),
    )


def parse_version(raw: object) -> VersionParse:
    """Deterministically parse one version/constraint string."""

    raw_text, url_like = _clean_raw(raw)
    if url_like:
        return _unknown_parse("[redacted]", "url-like value rejected")
    if not raw_text:
        return _unknown_parse("", "empty value")
    text = _clean_text(raw_text)
    if not text:
        return _unknown_parse(
            raw_text, "value reduced to empty after cleaning"
        )

    parsed = _parse_wildcard(text)
    if parsed is None:
        parsed = _parse_range(text)
    if parsed is None:
        parsed = _parse_operator(text)
    if parsed is None:
        components = _components(text)
        if components is not None:
            normalized = _render(components)
            method = (
                METHOD_EXACT_PARSE
                if normalized == raw_text
                else METHOD_NORMALIZED
            )
            parsed = _exact_parse(raw_text, components, method=method)
    if parsed is None:
        return _unknown_parse(
            raw_text, "unsupported version syntax; raw value preserved"
        )
    # Preserve the original (bounded) raw text, not the cleaned variant.
    if parsed.raw_version == text and raw_text != text:
        parsed = VersionParse(
            raw_version=raw_text,
            normalized_version=parsed.normalized_version,
            version_kind=parsed.version_kind,
            evidence_class=parsed.evidence_class,
            resolution_method=parsed.resolution_method,
            comparison_operator=parsed.comparison_operator,
            components=parsed.components,
            wildcard_prefix=parsed.wildcard_prefix,
            lower_bound=parsed.lower_bound,
            upper_bound=parsed.upper_bound,
            lower_inclusive=parsed.lower_inclusive,
            upper_inclusive=parsed.upper_inclusive,
            precision=parsed.precision,
            reason=parsed.reason,
            evidence=parsed.evidence,
        )
    return parsed


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _compare_components(
    left: tuple[int, ...], right: tuple[int, ...]
) -> int | None:
    """Compare component tuples; None when only trailing-zero precision
    differs.

    ``1.0.1`` vs ``1.0`` -> ``1`` (a non-zero extra component is meaningful);
    ``1.2`` vs ``1.2.0`` -> ``None`` (precision ambiguity).
    """

    common = min(len(left), len(right))
    for index in range(common):
        if left[index] != right[index]:
            return -1 if left[index] < right[index] else 1
    if len(left) == len(right):
        return 0
    longer, sign = (left, 1) if len(left) > len(right) else (right, -1)
    extra = longer[common:]
    if any(part != 0 for part in extra):
        return sign
    return None


def _as_parse(value: object) -> VersionParse:
    if isinstance(value, VersionParse):
        return value
    return parse_version(value)


def compare_order(
    left: object,
    right: object,
    *,
    allow_precision_expansion: bool = False,
) -> int | None:
    """Order two concrete versions; None means INDETERMINATE."""

    left_parse = _as_parse(left)
    right_parse = _as_parse(right)
    if not left_parse.is_concrete or not right_parse.is_concrete:
        return None
    if allow_precision_expansion:
        length = max(
            len(left_parse.components), len(right_parse.components)
        )
        left_components = left_parse.components + (0,) * (
            length - len(left_parse.components)
        )
        right_components = right_parse.components + (0,) * (
            length - len(right_parse.components)
        )
        return _compare_components(left_components, right_components)
    return _compare_components(
        left_parse.components, right_parse.components
    )


def compare_versions(
    left: object,
    right: object,
    *,
    allow_precision_expansion: bool = False,
) -> str:
    """Equality-class comparison: MATCH / NO_MATCH / INDETERMINATE.

    Different precision without explicit expansion is INDETERMINATE
    (``1.2`` vs ``1.2.0``); a non-zero extra component is a real difference
    (``1.2.3`` vs ``1.2`` -> NO_MATCH).
    """

    order = compare_order(
        left,
        right,
        allow_precision_expansion=allow_precision_expansion,
    )
    if order is None:
        return COMPARISON_INDETERMINATE
    return COMPARISON_MATCH if order == 0 else COMPARISON_NO_MATCH


def _bound_comparison(
    components: tuple[int, ...],
    bound: tuple[int, ...],
    *,
    inclusive: bool,
    lower: bool,
) -> str:
    order = _compare_components(components, bound)
    if order is None:
        return COMPARISON_INDETERMINATE
    if lower:
        if order > 0:
            return COMPARISON_MATCH
        if order < 0:
            return COMPARISON_NO_MATCH
        return (
            COMPARISON_MATCH if inclusive else COMPARISON_NO_MATCH
        )
    if order < 0:
        return COMPARISON_MATCH
    if order > 0:
        return COMPARISON_NO_MATCH
    return COMPARISON_MATCH if inclusive else COMPARISON_NO_MATCH


def _wildcard_comparison(
    components: tuple[int, ...], prefix: tuple[int, ...]
) -> str:
    if len(components) < len(prefix):
        return COMPARISON_INDETERMINATE
    if tuple(components[: len(prefix)]) == tuple(prefix):
        return COMPARISON_MATCH
    return COMPARISON_NO_MATCH


def matches_constraint(observed: object, constraint: object) -> str:
    """Evaluate one concrete observed version against one constraint parse."""

    observed_parse = _as_parse(observed)
    constraint_parse = _as_parse(constraint)
    if not observed_parse.is_concrete:
        return COMPARISON_INDETERMINATE
    components = observed_parse.components
    kind = constraint_parse.version_kind
    if kind == KIND_EXACT:
        return _equal_comparison(
            components, constraint_parse.components
        )
    if kind == KIND_LOWER_BOUND:
        if constraint_parse.lower_bound is None:
            return COMPARISON_INDETERMINATE
        return _bound_comparison(
            components,
            constraint_parse.lower_bound,
            inclusive=constraint_parse.lower_inclusive,
            lower=True,
        )
    if kind == KIND_UPPER_BOUND:
        if constraint_parse.upper_bound is None:
            return COMPARISON_INDETERMINATE
        return _bound_comparison(
            components,
            constraint_parse.upper_bound,
            inclusive=constraint_parse.upper_inclusive,
            lower=False,
        )
    if kind == KIND_RANGE:
        if (
            constraint_parse.lower_bound is None
            or constraint_parse.upper_bound is None
        ):
            return COMPARISON_INDETERMINATE
        lower_result = _bound_comparison(
            components,
            constraint_parse.lower_bound,
            inclusive=constraint_parse.lower_inclusive,
            lower=True,
        )
        upper_result = _bound_comparison(
            components,
            constraint_parse.upper_bound,
            inclusive=constraint_parse.upper_inclusive,
            lower=False,
        )
        if (
            lower_result == COMPARISON_NO_MATCH
            or upper_result == COMPARISON_NO_MATCH
        ):
            return COMPARISON_NO_MATCH
        if (
            lower_result == COMPARISON_MATCH
            and upper_result == COMPARISON_MATCH
        ):
            return COMPARISON_MATCH
        return COMPARISON_INDETERMINATE
    if kind in (KIND_WILDCARD, KIND_PREFIX):
        return _wildcard_comparison(
            components, constraint_parse.wildcard_prefix
        )
    return COMPARISON_INDETERMINATE


def _equal_comparison(
    left: tuple[int, ...], right: tuple[int, ...]
) -> str:
    order = _compare_components(left, right)
    if order is None:
        return COMPARISON_INDETERMINATE
    return COMPARISON_MATCH if order == 0 else COMPARISON_NO_MATCH


# ---------------------------------------------------------------------------
# Structured evidence
# ---------------------------------------------------------------------------


def _reason(
    constraint: VersionParse, observed: VersionParse, comparison: str
) -> str:
    if not observed.normalized_version:
        return "no concrete observed version available"
    if constraint.version_kind == KIND_UNKNOWN:
        return (
            f"affected version {constraint.raw_version!r} is unsupported; "
            "raw value preserved"
        )
    if comparison == COMPARISON_INDETERMINATE:
        return (
            f"observed {observed.normalized_version} cannot be compared "
            f"safely with "
            f"{constraint.normalized_version or constraint.raw_version}"
        )
    if constraint.version_kind == KIND_EXACT:
        verb = "equals" if comparison == COMPARISON_MATCH else "does not equal"
        return (
            f"observed {observed.normalized_version} {verb} affected "
            f"version {constraint.normalized_version}"
        )
    if constraint.version_kind == KIND_UPPER_BOUND:
        if comparison == COMPARISON_MATCH:
            return (
                f"observed {observed.normalized_version} is within "
                f"{constraint.normalized_version}"
            )
        return (
            f"observed {observed.normalized_version} exceeds "
            f"{constraint.normalized_version}"
        )
    if constraint.version_kind == KIND_LOWER_BOUND:
        if comparison == COMPARISON_MATCH:
            return (
                f"observed {observed.normalized_version} is within "
                f"{constraint.normalized_version}"
            )
        return (
            f"observed {observed.normalized_version} is below "
            f"{constraint.normalized_version}"
        )
    if constraint.version_kind == KIND_RANGE:
        if comparison == COMPARISON_MATCH:
            return (
                f"observed {observed.normalized_version} is inside range "
                f"{constraint.normalized_version}"
            )
        return (
            f"observed {observed.normalized_version} is outside range "
            f"{constraint.normalized_version}"
        )
    if constraint.version_kind in (KIND_WILDCARD, KIND_PREFIX):
        if comparison == COMPARISON_MATCH:
            return (
                f"observed {observed.normalized_version} matches "
                f"{constraint.normalized_version}"
            )
        return (
            f"observed {observed.normalized_version} does not match "
            f"{constraint.normalized_version}"
        )
    return "no comparison performed"


def _evidence_row(
    constraint: VersionParse,
    observed: VersionParse | None,
    comparison: str,
) -> dict:
    observed_parse = observed or parse_version("")
    return {
        "cve_raw": constraint.raw_version,
        "cve_normalized": constraint.normalized_version,
        "cve_kind": constraint.version_kind,
        "cve_precision": constraint.precision,
        "cve_evidence_class": constraint.evidence_class,
        "observed_raw": observed_parse.raw_version,
        "observed_normalized": observed_parse.normalized_version,
        "observed_kind": observed_parse.version_kind,
        "observed_precision": observed_parse.precision,
        "comparison": comparison,
        "reason": _bounded(_reason(constraint, observed_parse, comparison)),
    }


def build_version_evidence(
    *,
    cve_versions: object = (),
    observed_versions: object = (),
    max_versions: int = MAX_VERSIONS,
    max_rows: int = MAX_EVIDENCE_ROWS,
) -> dict:
    """Deterministic bounded evidence for CVE vs observed versions.

    One row per CVE affected-version constraint (bounded), with a canonical
    representative observed version chosen deterministically:

    MATCH > INDETERMINATE > NO_MATCH, first in canonical order.
    """

    limit = max(1, int(max_versions))
    cve_parses = [
        parse_version(value) for value in list(cve_versions or ())[:limit]
    ]
    observed_parses = [
        parse_version(value)
        for value in list(observed_versions or ())[:limit]
    ]
    concrete_observed = sorted(
        (parse for parse in observed_parses if parse.is_concrete),
        key=lambda parse: (parse.normalized_version, parse.raw_version),
    )

    rows: list[dict] = []
    counts = {
        COMPARISON_MATCH: 0,
        COMPARISON_NO_MATCH: 0,
        COMPARISON_INDETERMINATE: 0,
    }
    for constraint in cve_parses[: max(1, int(max_rows))]:
        representatives: list[tuple[str, VersionParse]] = []
        for observed in concrete_observed:
            comparison = matches_constraint(observed, constraint)
            representatives.append((comparison, observed))
        chosen: tuple[str, VersionParse] | None = None
        for wanted in (
            COMPARISON_MATCH,
            COMPARISON_INDETERMINATE,
            COMPARISON_NO_MATCH,
        ):
            chosen = next(
                (item for item in representatives if item[0] == wanted),
                None,
            )
            if chosen is not None:
                break
        if chosen is None:
            comparison = COMPARISON_INDETERMINATE
            row = _evidence_row(constraint, None, comparison)
        else:
            comparison, observed = chosen
            row = _evidence_row(constraint, observed, comparison)
        counts[comparison] = counts.get(comparison, 0) + 1
        rows.append(row)

    return {
        "rule_version": RULE_VERSION,
        "cve_versions": [parse.to_evidence() for parse in cve_parses],
        "observed_versions": [
            parse.to_evidence() for parse in observed_parses
        ],
        "rows": rows,
        "counts": {
            "cve_versions": len(cve_parses),
            "observed_versions": len(observed_parses),
            "rows": len(rows),
            "match": counts[COMPARISON_MATCH],
            "no_match": counts[COMPARISON_NO_MATCH],
            "indeterminate": counts[COMPARISON_INDETERMINATE],
        },
    }


__all__ = [
    "RULE_VERSION",
    "VERSION_KINDS",
    "EVIDENCE_CLASSES",
    "COMPARISONS",
    "RESOLUTION_METHODS",
    "KIND_EXACT",
    "KIND_PREFIX",
    "KIND_RANGE",
    "KIND_LOWER_BOUND",
    "KIND_UPPER_BOUND",
    "KIND_WILDCARD",
    "KIND_UNKNOWN",
    "COMPARISON_MATCH",
    "COMPARISON_NO_MATCH",
    "COMPARISON_INDETERMINATE",
    "VersionParse",
    "parse_version",
    "compare_order",
    "compare_versions",
    "matches_constraint",
    "build_version_evidence",
]
