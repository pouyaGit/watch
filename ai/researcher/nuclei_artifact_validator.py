"""Deterministic Nuclei artifact safety + specificity gates (Phase 4C).

Implements the H1/H2 gates from the adversarial review. PURE and
DETERMINISTIC:

- NO LLM calls, NO embeddings, NO model imports.
- NO network access (fixtures are local DATA; URLs are parsed
  with stdlib only and never fetched).
- NO subprocess, NO database, NO scope policy, NO verifiers,
  NO executors, NO findings, NO verdicts.

H1 (specificity): ``validate_nuclei_specificity`` proves on local
fixtures that a template's matching logic is specific enough that
a benign fixture does NOT match, and (where provided) a
vulnerable fixture DOES match. A broad matcher that also matches
the benign fixture can never be marked VALID. The gate only says
"this artifact's matching logic passed local specificity
validation" — never "the target is vulnerable".

H2 (safety normalization): ``validate_nuclei_safety`` enforces
deterministic deny rules over attacker-influenced request fields
(path, headers, query values, body) plus destructive-method,
unsafe-target, callback-endpoint, and embedded-script rules. When
uncertain it rejects (fail closed).

Artifact content model: the canonical Nuclei artifact is UTF-8
JSON bytes of :class:`NucleiTemplateContent` (strict schema,
``extra="forbid"`). Hashing operates on exact bytes; mapping
inputs are canonicalized via sorted-keys JSON so validation is
independent of dictionary order.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ------------------------------------------------------------------
# Typed content + fixture contracts
# ------------------------------------------------------------------


class NucleiMatcher(BaseModel):
    """One local matcher clause (structure only, never executed)."""

    model_config = ConfigDict(extra="forbid")

    matcher_type: Literal["word", "regex", "dsl", "status"]
    values: list[str] = Field(default_factory=list)
    part: Literal["body", "header", "status"] = "body"

    @field_validator("values")
    @classmethod
    def _values(cls, items: list[str]) -> list[str]:
        if not items:
            raise ValueError("matcher values must be non-empty")
        for item in items:
            if not isinstance(item, str) or not item:
                raise ValueError("matcher values must be non-empty strings")
            if len(item) > 1024:
                raise ValueError("matcher value exceeds 1024 characters")
            if "\n" in item or "\r" in item or "\0" in item:
                raise ValueError("matcher values must be single-line")
        return items


class NucleiTemplateContent(BaseModel):
    """Canonical Nuclei artifact content (request + matchers).

    Relative-path request parts only (the existing
    ``NucleiTemplateGenerator`` builds ``METHOD <relative-path>
    HTTP/1.1`` raw requests). No executable, script, shell, or
    tool-call field exists.
    """

    model_config = ConfigDict(extra="forbid")

    template_id: str
    method: Literal["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS", "DELETE"] = "GET"
    path: str = "/"
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    matchers: list[NucleiMatcher] = Field(default_factory=list)

    @field_validator("template_id")
    @classmethod
    def _template_id(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("template_id must be a non-empty string")
        if len(value) > 256:
            raise ValueError("template_id exceeds 256 characters")
        if "\n" in value or "\r" in value:
            raise ValueError("template_id must be single-line")
        return value

    @field_validator("matchers")
    @classmethod
    def _matchers(cls, items: list[NucleiMatcher]) -> list[NucleiMatcher]:
        if not items:
            raise ValueError("at least one matcher is required")
        if len(items) > 16:
            raise ValueError("too many matchers (max 16)")
        return items


class NucleiFixture(BaseModel):
    """Minimal local response/request data for specificity testing.

    No network URLs, no real HTTP. ``body`` plus ``headers`` plus
    ``status`` is the entire observable surface a matcher may be
    evaluated against.
    """

    model_config = ConfigDict(extra="forbid")

    fixture_kind: Literal["benign", "vulnerable"]
    status: int = 200
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""

    @field_validator("status")
    @classmethod
    def _status(cls, value: int) -> int:
        if not isinstance(value, bool) and 100 <= value <= 599:
            return value
        raise ValueError("status must be an HTTP status (100..599)")

    @field_validator("body")
    @classmethod
    def _body(cls, value: str) -> str:
        if len(value) > 65536:
            raise ValueError("fixture body exceeds 65536 characters")
        return value


# ------------------------------------------------------------------
# H2 deny rules
# ------------------------------------------------------------------

DESTRUCTIVE_METHODS = frozenset({"DELETE"})

CREDENTIAL_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "proxy-authenticate",
    }
)

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,127}$")

_SHELL_SUBSTRINGS = (
    "$(",
    "`",
    "${",
)

_SHELL_KEYWORDS_RE = re.compile(
    r"(?:^|[\s;|&])(?:curl|wget|powershell|cmd\.exe|bash|sh\s+-c|nc\s+-e|/bin/)",
    re.IGNORECASE,
)

_COMMANDLIKE_RE = re.compile(
    r"\b(?:cat|ls|whoami|chmod|chown|rm|cp|mv|echo|export|env|sleep|ping|id)\b\s+[/\w]"
    r"|/etc/(?:passwd|shadow|hosts)",
    re.IGNORECASE,
)

_CREDENTIAL_VALUE_RE = re.compile(
    r"\b(?:bearer\s+\S+|basic\s+[A-Za-z0-9+/=]{4,})", re.IGNORECASE
)

_ABSOLUTE_URL_RE = re.compile(r"https?://", re.IGNORECASE)

_CALLBACK_DOMAIN_SUBSTRINGS = (
    "burpcollaborator",
    "interactsh",
    "oastify",
    "ngrok",
    "webhook.site",
    "requestbin",
    "pipedream",
    "canarytokens",
    "dnslog",
)

_SCRIPT_PATTERNS_RE = re.compile(
    r"<\s*script\b|javascript\s*:|\bdata\s*:\s*text/html|<\s*iframe\b|<\s*object\b|<\s*embed\b",
    re.IGNORECASE,
)

_EVENT_HANDLER_RE = re.compile(r"\bon\w+\s*=", re.IGNORECASE)

_METADATA_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google",
        "metadata.google.internal",
        "instance-data",
        "instance-data.compute.internal",
    }
)


def _has_control_chars(value: str, *, allow_tab: bool = False) -> bool:
    for char in value:
        code = ord(char)
        if char in ("\n", "\r", "\0"):
            return True
        if code < 32 and not (allow_tab and char == "\t"):
            return True
        if code == 127:
            return True
    return False


def _host_is_unsafe(host: str) -> bool:
    candidate = host.strip().strip("[]").casefold()
    if not candidate:
        return False
    if candidate in _METADATA_HOSTNAMES:
        return True
    if candidate == "localhost":
        return True
    if candidate.startswith("metadata.google"):
        return True
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    if str(parsed) == "169.254.169.254":
        return True
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


def _urls_in_text(text: str) -> list[str]:
    return _ABSOLUTE_URL_RE.split(text)[1:]


def _extract_hosts(text: str) -> list[str]:
    hosts: list[str] = []
    for fragment in _urls_in_text(text):
        host = fragment.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host = host.split("@")[-1].split(":")[0]
        if host:
            hosts.append(host)
    return hosts


def _check_unsafe_targeting(value: str, *, field: str, errors: list[str]) -> None:
    lowered = value.casefold()
    for marker in _CALLBACK_DOMAIN_SUBSTRINGS:
        if marker in lowered:
            errors.append(
                f"{field} targets an arbitrary callback endpoint "
                f"({marker!r}); rejected"
            )
    for host in _extract_hosts(value):
        if _host_is_unsafe(host):
            errors.append(
                f"{field} targets an unsafe host ({host!r}); rejected"
            )


def validate_nuclei_path(path: object, errors: list[str]) -> None:
    """Relative-path rules (fail closed)."""

    if not isinstance(path, str) or not path:
        errors.append("path must be a non-empty string")
        return
    if not path.startswith("/"):
        errors.append("path must be relative (must start with '/')")
    if len(path) > 2048:
        errors.append("path exceeds 2048 characters")
    if "\n" in path or "\r" in path or "\0" in path:
        errors.append("path must not contain CR/LF/NUL")
    if _has_control_chars(path):
        errors.append("path must not contain control characters")
    if _ABSOLUTE_URL_RE.search(path):
        errors.append("path must not contain an absolute URL")
    for token in _SHELL_SUBSTRINGS:
        if token in path:
            errors.append(f"path contains shell construct ({token!r})")
    if ";" in path or "|" in path:
        errors.append("path contains shell syntax (';' or '|')")
    if _COMMANDLIKE_RE.search(path):
        errors.append("path contains command-like content")
    if _SHELL_KEYWORDS_RE.search(path):
        errors.append("path contains a shell/command keyword")
    if _SCRIPT_PATTERNS_RE.search(path) or _EVENT_HANDLER_RE.search(path):
        errors.append("path contains embedded script content")
    _check_unsafe_targeting(path, field="path", errors=errors)


def validate_nuclei_headers(headers: object, errors: list[str]) -> None:
    """Header name/value rules (fail closed)."""

    if not isinstance(headers, dict):
        errors.append("headers must be a mapping")
        return
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            errors.append("header names and values must be strings")
            continue
        if not _HEADER_NAME_RE.match(name):
            errors.append(f"malformed header name: {name!r}")
        if name.casefold() in CREDENTIAL_HEADERS:
            errors.append(
                f"credential header is not permitted: {name!r}"
            )
        if _has_control_chars(name) or _has_control_chars(value):
            errors.append(
                f"header {name!r} must not contain CR/LF/control characters"
            )
        for token in _SHELL_SUBSTRINGS:
            if token in value:
                errors.append(
                    f"header {name!r} contains shell construct ({token!r})"
                )
        if _CREDENTIAL_VALUE_RE.search(value):
            errors.append(
                f"header {name!r} carries credential content; rejected"
            )
        if _SHELL_KEYWORDS_RE.search(value):
            errors.append(
                f"header {name!r} contains a shell/command keyword"
            )
        if _SCRIPT_PATTERNS_RE.search(value):
            errors.append(
                f"header {name!r} contains embedded script content"
            )
        _check_unsafe_targeting(value, field=f"header {name!r}", errors=errors)


def validate_nuclei_query_params(params: object, errors: list[str]) -> None:
    """Parameter name/value rules (fail closed)."""

    if not isinstance(params, dict):
        errors.append("query_params must be a mapping")
        return
    for name, value in params.items():
        if not isinstance(name, str) or not isinstance(value, str):
            errors.append("parameter names and values must be strings")
            continue
        if not name or len(name) > 128:
            errors.append(f"malformed parameter name: {name!r}")
        if _has_control_chars(name) or _has_control_chars(value):
            errors.append(
                f"parameter {name!r} must not contain CR/LF/control characters"
            )
        for token in _SHELL_SUBSTRINGS:
            if token in value:
                errors.append(
                    f"parameter {name!r} contains shell construct ({token!r})"
                )
        if ";" in value or "|" in value:
            errors.append(
                f"parameter {name!r} contains shell syntax (';' or '|')"
            )
        if _COMMANDLIKE_RE.search(value):
            errors.append(
                f"parameter {name!r} contains command-like interpolation"
            )
        if _SHELL_KEYWORDS_RE.search(value):
            errors.append(
                f"parameter {name!r} contains a shell/command keyword"
            )
        if _SCRIPT_PATTERNS_RE.search(value):
            errors.append(
                f"parameter {name!r} contains embedded script content"
            )
        _check_unsafe_targeting(value, field=f"parameter {name!r}", errors=errors)


def validate_nuclei_body(body: object, errors: list[str]) -> None:
    """Body rules: bounded plain data only (fail closed)."""

    if body is None:
        return
    if not isinstance(body, str):
        errors.append("body must be a string or null")
        return
    if len(body) > 16384:
        errors.append("body exceeds 16384 characters")
    if "\0" in body:
        errors.append("body must not contain NUL")
    if _has_control_chars(body, allow_tab=True):
        # CR/LF inside a template body would smuggle extra raw
        # request lines; reject conservatively.
        errors.append("body must not contain CR/LF/control characters")
    for token in _SHELL_SUBSTRINGS:
        if token in body:
            errors.append(f"body contains shell construct ({token!r})")
    if ";" in body or "|" in body:
        errors.append("body contains shell syntax (';' or '|')")
    if _SHELL_KEYWORDS_RE.search(body) or _COMMANDLIKE_RE.search(body):
        errors.append("body contains a shell/command keyword")
    if _SCRIPT_PATTERNS_RE.search(body) or _EVENT_HANDLER_RE.search(body):
        errors.append("body contains embedded script content")
    _check_unsafe_targeting(body, field="body", errors=errors)


def validate_nuclei_safety(content: NucleiTemplateContent) -> list[str]:
    """H2 gate: deterministic safety normalization (fail closed).

    Returns the list of violations (empty means the request
    structure passed). Never executes, fetches, or resolves
    anything.
    """

    errors: list[str] = []
    if content.method in DESTRUCTIVE_METHODS:
        errors.append(
            f"method {content.method!r} is destructive and not permitted "
            "by the artifact contract"
        )
    validate_nuclei_path(content.path, errors)
    validate_nuclei_headers(content.headers, errors)
    validate_nuclei_query_params(content.query_params, errors)
    validate_nuclei_body(content.body, errors)
    return errors


# ------------------------------------------------------------------
# H1 specificity gate
# ------------------------------------------------------------------

#: Word/regex values at or below this length prove nothing: they
#: match benign content by construction.
MIN_SPECIFIC_TOKEN_LENGTH = 4

#: Detection values that are too generic to prove specificity.
GENERIC_TOKENS = frozenset(
    {
        "200", "404", "error", "errors", "success", "ok",
        "html", "content", "true", "false", "test", "hello",
        "welcome", "page", "null", "undefined",
    }
)


def _matcher_matches(matcher: NucleiMatcher, fixture: NucleiFixture) -> bool:
    """Local matcher evaluation against one fixture (no network)."""

    haystack_body = fixture.body or ""
    haystack_headers = "\n".join(
        f"{name}: {value}" for name, value in fixture.headers.items()
    )
    if matcher.matcher_type == "status":
        wanted: set[int] = set()
        for item in matcher.values:
            try:
                wanted.add(int(item.strip()))
            except ValueError:
                continue
        return fixture.status in wanted
    if matcher.matcher_type == "word":
        target = (
            haystack_headers if matcher.part == "header" else haystack_body
        )
        return any(item in target for item in matcher.values)
    if matcher.matcher_type == "regex":
        target = (
            haystack_headers if matcher.part == "header" else haystack_body
        )
        for item in matcher.values:
            try:
                if re.search(item, target):
                    return True
            except re.error:
                continue
        return False
    if matcher.matcher_type == "dsl":
        # Conservative local reading of Nuclei DSL: a clause matches
        # when any quoted literal inside it appears in the response,
        # or when a status_code==NNN clause equals the fixture
        # status. Clauses we cannot parse locally NEVER match (fail
        # closed toward "no positive proof" rather than guessing).
        for item in matcher.values:
            status_hits = re.findall(r"status_code\s*==\s*(\d{3})", item)
            if status_hits and any(
                int(code) == fixture.status for code in status_hits
            ):
                return True
            literals = re.findall(r"'([^']*)'|\"([^\"]*)\"", item)
            flat = [first or second for first, second in literals]
            flat = [token for token in flat if token]
            if flat and any(
                token in haystack_body or token in haystack_headers
                for token in flat
            ):
                return True
            stripped = item.strip()
            if (
                not flat
                and not status_hits
                and stripped
                and (
                    stripped in haystack_body
                    or stripped in haystack_headers
                )
            ):
                return True
        return False
    return False


def _static_specificity_errors(content: NucleiTemplateContent) -> list[str]:
    """Reject matchers that cannot prove specificity statically."""

    errors: list[str] = []
    for index, matcher in enumerate(content.matchers):
        if matcher.matcher_type in ("word", "regex", "dsl"):
            for value in matcher.values:
                probe = value.strip().casefold()
                literals = (
                    [token for token in
                     re.findall(r"'([^']*)'|\"([^\"]*)\"", value)
                     if (token[0] or token[1])]
                    if matcher.matcher_type == "dsl"
                    else None
                )
                candidates = (
                    [first or second for first, second in literals]
                    if literals is not None
                    else [value]
                )
                for candidate in candidates:
                    text = candidate.strip().casefold()
                    if not text:
                        continue
                    if len(text) < MIN_SPECIFIC_TOKEN_LENGTH:
                        errors.append(
                            f"matcher[{index}] value is too generic "
                            f"(shorter than {MIN_SPECIFIC_TOKEN_LENGTH} "
                            "chars); no specificity proof"
                        )
                    elif text in GENERIC_TOKENS:
                        errors.append(
                            f"matcher[{index}] value {candidate!r} is a "
                            "generic token; no specificity proof"
                        )
        elif matcher.matcher_type == "status":
            errors.append(
                f"matcher[{index}] is status-only; status alone proves "
                "no specificity"
            )
    return errors


@dataclass(frozen=True)
class SpecificityResult:
    """Outcome of the H1 specificity gate (local fixtures only)."""

    passed: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


def validate_nuclei_specificity(
    template: object,
    fixtures: object,
) -> SpecificityResult:
    """H1 gate: prove matcher specificity on local fixtures.

    Rules (all fail closed):

    1. ``template`` must be :class:`NucleiTemplateContent` and
       ``fixtures`` a non-empty list/tuple of
       :class:`NucleiFixture`; anything else raises ``TypeError``.
    2. At least one ``benign`` fixture is required; without it
       specificity cannot be established (deterministic
       unsupported → ``passed=False``).
    3. Matchers that are statically generic (short/generic tokens,
       status-only) are rejected without needing a fixture hit.
    4. If ANY matcher matches the benign fixture, ``passed=False``
       (a broad matcher matching benign content is unsafe).
    5. Where vulnerable fixtures exist, EVERY vulnerable fixture
       must be matched by at least one matcher, else
       ``passed=False`` (no positive proof).
    6. Malformed fixtures (wrong types) raise ``TypeError``;
       empty fixture lists yield ``passed=False``.

    Never states anything about a real target.
    """

    if not isinstance(template, NucleiTemplateContent):
        raise TypeError(
            "validate_nuclei_specificity accepts only "
            "NucleiTemplateContent, not "
            f"{type(template).__name__}; raw dicts are never coerced"
        )
    if not isinstance(fixtures, (list, tuple)):
        raise TypeError(
            "fixtures must be a list or tuple of NucleiFixture, not "
            f"{type(fixtures).__name__}"
        )
    for item in fixtures:
        if not isinstance(item, NucleiFixture):
            raise TypeError(
                "fixtures must be NucleiFixture, not "
                f"{type(item).__name__}; raw dicts are never coerced"
            )
    if not fixtures:
        return SpecificityResult(
            passed=False,
            reasons=("no fixtures supplied; specificity unproven",),
        )
    benign = [item for item in fixtures if item.fixture_kind == "benign"]
    vulnerable = [
        item for item in fixtures if item.fixture_kind == "vulnerable"
    ]
    if not benign:
        return SpecificityResult(
            passed=False,
            reasons=(
                "missing benign fixture for a specificity-sensitive "
                "matcher; specificity unproven",
            ),
        )
    static_errors = _static_specificity_errors(template)
    if static_errors:
        return SpecificityResult(
            passed=False, reasons=tuple(static_errors)
        )
    for target in benign:
        for matcher in template.matchers:
            if _matcher_matches(matcher, target):
                return SpecificityResult(
                    passed=False,
                    reasons=(
                        "matcher matches the benign fixture; "
                        "specificity gate fails closed",
                    ),
                )
    for target in vulnerable:
        if not any(
            _matcher_matches(matcher, target)
            for matcher in template.matchers
        ):
            return SpecificityResult(
                passed=False,
                reasons=(
                    "vulnerable fixture has no matching matcher; "
                    "expected positive proof missing",
                ),
            )
    return SpecificityResult(
        passed=True,
        reasons=(
            "matchers are statically specific, no benign fixture "
            "matched, and every vulnerable fixture matched",
        ),
    )


def parse_template_content(content: bytes) -> NucleiTemplateContent:
    """Parse canonical JSON artifact bytes into typed content.

    Rejects non-UTF-8, non-JSON, non-object, and unknown-field
    payloads fail-closed. No fuzzy parsing.
    """

    if not isinstance(content, (bytes, bytearray)):
        raise TypeError(
            "parse_template_content accepts only bytes, not "
            f"{type(content).__name__}"
        )
    try:
        text = bytes(content).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"artifact bytes are not UTF-8: {exc}") from exc
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"artifact bytes are not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("artifact content must be a JSON object")
    return NucleiTemplateContent.model_validate(payload)


def canonical_template_bytes(content: NucleiTemplateContent) -> bytes:
    """Canonical bytes of typed content (sorted-keys JSON, UTF-8)."""

    return json.dumps(
        content.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


__all__ = [
    "DESTRUCTIVE_METHODS",
    "GENERIC_TOKENS",
    "MIN_SPECIFIC_TOKEN_LENGTH",
    "NucleiFixture",
    "NucleiMatcher",
    "NucleiTemplateContent",
    "SpecificityResult",
    "canonical_template_bytes",
    "parse_template_content",
    "validate_nuclei_path",
    "validate_nuclei_headers",
    "validate_nuclei_query_params",
    "validate_nuclei_body",
    "validate_nuclei_safety",
    "validate_nuclei_specificity",
]
