"""Closed-spec Nuclei executor (Phase 5F v1).

FAIL-CLOSED posture: this module performs NO live execution, NO live
transport, NO name resolution, and NO process creation. The live gate
is explicit in code (not a comment):

- ``LIVE_NUCLEI`` is ``False`` and no code path in this module can set
  it to ``True`` (literal constant; not configurable).
- ``LiveNucleiRunner.launch`` always raises
  ``ExecutorError(NUCLEI_EXECUTION_BLOCKED)`` before any process
  primitive. This module does not import any process-creation,
  transport, or name-resolution facility.
- Offline execution proceeds only through the injected
  ``FakeNucleiRunner`` (deterministic, scripted, no I/O).

Target authority is ``IssuedExecutionAuthorization`` +
``TargetResolution`` + ``ScopeEvaluation`` + validated artifact. The
template supplies an HTTP path/query/body only (DATA); it never
supplies scheme, host, authority, port, destination address, target
string, or callback destination. Any attempt fails closed.

Frozen contracts reused (never duplicated):

- 5B: ``IssuedExecutionAuthorization`` liveness, CAS consume,
  artifact identity (``artifact_id_for``).
- 5C: ``TargetResolution``, canonical target tuple, dial coherence,
  resolution identity (``canonical_target_hash_for``).
- 5D: ``ScopeEvaluation``, ``require_allowed()``.
- 4C/H1+H2: ``NucleiTemplateContent``, ``validate_nuclei_safety``,
  ``validate_nuclei_specificity``, ``parse_template_content``,
  ``canonical_template_bytes``, ``build_validated_reference``,
  ``GENERIC_TOKENS``, ``MIN_SPECIFIC_TOKEN_LENGTH``.
- 5H-core: ``EvidenceRecord``, ``NucleiObservation``,
  ``EvidenceBuilder``, scrubber, hashing, ledger, audit, ceilings,
  crash semantics.

This module is OFFLINE and DETERMINISTIC (caller-supplied clocks
only): no process creation, no transport, no database driver, no LLM,
no browser, no verdicts, no severity, no confirmation state.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from ai.audit.trail import AuditRecord, gap_record
from ai.evidence import hashing as hash_mod
from ai.evidence import scrubber
from ai.evidence.builder import EvidenceBuilder
from ai.limits.ceilings import CEILINGS
from ai.resolver.canonicalization import (
    CanonicalizationError,
    canonicalize_host,
)
from ai.schemas import evidence as ev
from ai.schemas.artifact import (
    MAX_NUCLEI_TEMPLATE_BYTES,
    ArtifactReference,
    artifact_id_for,
    content_hash_for_bytes,
)
from ai.schemas.execution_authorization import (
    ALLOWED_METHODS,
    AuthzError,
    IssuedExecutionAuthorization,
)
from ai.schemas.scope_evaluation import ScopeEvaluation
from ai.schemas.target_resolution import (
    TargetResolution,
    canonical_target_hash_for,
)
from ai.scope.evaluator import require_allowed
from ai.researcher.artifact_validator import build_validated_reference
from ai.researcher.nuclei_artifact_validator import (
    GENERIC_TOKENS,
    MIN_SPECIFIC_TOKEN_LENGTH,
    NucleiTemplateContent,
    canonical_template_bytes,
    parse_template_content,
    validate_nuclei_safety,
    validate_nuclei_specificity,
)

__all__ = [
    "LIVE_NUCLEI",
    "B1_STATUS",
    "B2_STATUS",
    "B3_STATUS",
    "SCHEMA_VERSION",
    "SERVER_CONTROLLED_NUCLEI_BINARY",
    "PINNED_NUCLEI_VERSION",
    "PINNED_NUCLEI_VERSION_EVIDENCE",
    "SUPPORTED_NUCLEI_FLAGS",
    "parse_nuclei_version",
    "require_pinned_nuclei_version",
    "check_nuclei_runtime",
    "assert_frozen_argv_supported",
    "EXECUTOR_ERROR_CODES",
    "ExecutorError",
    "TemplateSafetyReport",
    "validate_nuclei_safety_template",
    "NucleiExecutionSpec",
    "ResourceLimitsSpec",
    "default_resource_limits",
    "build_target_string",
    "build_nuclei_argv",
    "build_nuclei_environment",
    "NucleiRunResult",
    "NucleiRunner",
    "FakeNucleiRunner",
    "LiveNucleiRunner",
    "B3NetnsNucleiRunner",
    "NucleiExecutorDeps",
    "NucleiExecutionResult",
    "execute_nuclei",
]

# ------------------------------------------------------------------
# Live gate (explicit, B1+B2+B3 blockers)
# ------------------------------------------------------------------

#: Master live-execution switch. Frozen ``False`` for Phase 5F v1.
#: Literal constant: no configuration, constructor argument, artifact
#: value, CLI flag, database value, or caller input can change it.
LIVE_NUCLEI = False

#: B1 BLOCKED (live execution): production ``AddressSource``
#: selection + review deferred. Only injected deterministic fakes
#: supply resolution facts; nothing performs live resolution here.
B1_STATUS = "BLOCKED: production AddressSource selection/review deferred"

#: B2 BLOCKED (live/multi-worker): production adapters for the
#: authorization store, execution ledger, audit backend, and evidence
#: backend (plus orphan sweep) remain pending. Semantics frozen;
#: mechanism deferred.
B2_STATUS = (
    "BLOCKED: production authorization/ledger/audit/evidence "
    "adapters + sweep deferred"
)

#: B3 BLOCKED: the future sandbox/egress boundary (isolated network
#: namespace, egress control, resource enforcement inside the
#: boundary) remains pending under separate review. Until B3 closes,
#: the offline harness is the only runner and live execution is
#: refused before any process primitive.
B3_STATUS = "BLOCKED: Nuclei sandbox/egress boundary remains pending"

#: Executor schema version for the closed execution specification.
SCHEMA_VERSION = "nuclei_executor/v1"

#: Server-controlled binary reference. Not constructor-injected, not
#: artifact-derived, not caller-supplied. Because live process
#: creation is blocked in 5F v1, this constant only enters the pure
#: argv builder and the argv digest; it is never resolved or started.
SERVER_CONTROLLED_NUCLEI_BINARY = "/usr/bin/nuclei"

# ------------------------------------------------------------------
# Pinned Nuclei version contract (Phase 5K-live B6-A).
#
# Exactly one Nuclei release is supported. "latest" is never
# accepted: the frozen argv below is proven flag-by-flag against the
# pinned release only. Any other version (older, newer, or
# undeterminable) fails closed via ``NUCLEI_RUNTIME_UNSUPPORTED``.
#
# Local authoritative evidence for the pin (no network involved):
#
# - ``nuclei -version`` on the environment binary reports
#   ``Nuclei Engine Version: v3.11.1``.
# - ``nuclei -h`` on the same binary lists the exact flag table used
#   below (CONFIGURATIONS / INTERACTSH / RATE-LIMIT / OPTIMIZATIONS /
#   UPDATE sections).
# - Per-flag acceptance probes on the same binary (each flag alone,
#   offline, no target):
#     accepted: -disable-update-check, -disable-redirects,
#       -no-interactsh, -silent, -no-color, -stats-interval,
#       -jsonl, -bulk-size, -concurrency, -timeout, -retries,
#       -restrict-local-network-access, -t, -u, -nc
#     rejected ("flag provided but not defined"): -no-redirects,
#       -disable-interactsh, -json
#   (B4 pinned the three rejected spellings; they never constrained
#   any real Nuclei release and are corrected by B6-B.)
# ------------------------------------------------------------------

#: The single supported Nuclei release (exact, never "latest").
PINNED_NUCLEI_VERSION = "v3.11.1"

#: Provenance of the pin (static description, never caller input).
PINNED_NUCLEI_VERSION_EVIDENCE = (
    "local nuclei -version/-h + per-flag acceptance probes, "
    "Nuclei Engine Version: v3.11.1"
)

#: Exact CLI flag tokens the pinned release accepts AND the frozen
#: argv below is allowed to carry. Anything else on a command line
#: is ``NUCLEI_RUNTIME_UNSUPPORTED``. Proven per flag on v3.11.1
#: (see the contract note above); never extended by caller input.
SUPPORTED_NUCLEI_FLAGS = frozenset(
    {
        "-t",
        "-u",
        "-disable-update-check",
        "-disable-redirects",
        "-no-interactsh",
        "-silent",
        "-no-color",
        "-stats-interval",
        "-jsonl",
        "-bulk-size",
        "-concurrency",
        "-timeout",
        "-retries",
        "-restrict-local-network-access",
        "-nc",
    }
)

#: Redirect-enabling flags that must never appear alongside the
#: frozen argv (redirect budget is zero: disable only, no budget).
_FORBIDDEN_NUCLEI_FLAGS = frozenset(
    {
        "-follow-redirects",
        "-fr",
        "-follow-host-redirects",
        "-fhr",
        "-max-redirects",
        "-mr",
    }
)

#: Strict version-line match for ``nuclei -version`` output.
_VERSION_LINE_RE = re.compile(
    r"Nuclei Engine Version:\s*v(\d+\.\d+\.\d+)"
)


def parse_nuclei_version(output: object) -> str:
    """Extract the ``vX.Y.Z`` release from ``nuclei -version`` output.

    Pure function (no process creation: the caller supplies captured
    output). Anything unparseable — missing binary output, empty
    text, wrapped errors, partial lines — fails closed with
    ``NUCLEI_RUNTIME_UNSUPPORTED``. The input text is never reflected
    into the error (secret-free by construction).
    """

    if not isinstance(output, str) or not output:
        raise ExecutorError(
            "NUCLEI_RUNTIME_UNSUPPORTED", "nuclei version indeterminable"
        )
    match = _VERSION_LINE_RE.search(output)
    if match is None:
        raise ExecutorError(
            "NUCLEI_RUNTIME_UNSUPPORTED", "nuclei version indeterminable"
        )
    return f"v{match.group(1)}"


def require_pinned_nuclei_version(output: object) -> str:
    """Return the pinned version iff captured output proves it.

    Mismatch fails closed with ``NUCLEI_RUNTIME_UNSUPPORTED``: an
    older, newer, or unparsable release never inherits the frozen
    argv (flag semantics belong to the pinned release alone). The
    caller never chooses the version; the pin is server-side.
    """

    detected = parse_nuclei_version(output)
    if detected != PINNED_NUCLEI_VERSION:
        raise ExecutorError(
            "NUCLEI_RUNTIME_UNSUPPORTED", "nuclei version not pinned"
        )
    return detected


def check_nuclei_runtime(
    *, binary_present: bool, version_output: object
) -> str:
    """Fail-closed runtime gate: presence + pinned version.

    ``binary_present`` answers only whether the server-controlled
    binary exists (the launcher probes the filesystem; this function
    stays pure). Missing binary, indeterminable version, or version
    skew all raise ``NUCLEI_RUNTIME_UNSUPPORTED``. Returns the pinned
    version string on success.
    """

    if binary_present is not True:
        raise ExecutorError(
            "NUCLEI_RUNTIME_UNSUPPORTED", "nuclei binary unavailable"
        )
    return require_pinned_nuclei_version(version_output)

# ------------------------------------------------------------------
# Frozen ceilings (reused from 5H-core, never redefined)
# ------------------------------------------------------------------

_NUCLEI_WALL = CEILINGS["nuclei_wall_seconds"]
_NUCLEI_CPU = CEILINGS["subprocess_cpu_seconds"]
_NUCLEI_MEMORY = CEILINGS["subprocess_memory_bytes"]
_NUCLEI_OUTPUT_MAX = CEILINGS["nuclei_output_bytes"]
_TEMP_STORAGE = CEILINGS["temp_storage_bytes"]
_DNS_ANSWERS_MAX = CEILINGS["dns_answers"]

#: Per-template matcher value bound (inherited from the H1/H2 typed
#: schema: matcher values are single-line strings <= 1024 chars).
MAX_MATCHER_VALUE_LENGTH = 1024

#: Bound on the total regex surface of one template (NFA-size guard).
MAX_REGEX_COMPLEXITY = 4 * 4096

#: Bound on one reconstructed raw request line (single request line
#: in the single allowed exchange; no multiline smuggling).
MAX_RAW_REQUEST_LINE_LENGTH = 1024

#: Bound on variable values when a ``variables`` block is present.
MAX_VARIABLE_VALUE_LENGTH = 1024

#: Scratch-file identity root (pure string derivation; no filesystem
#: access occurs in 5F v1).
_SCRATCH_ROOT = "/srv/watch/scratch/nuclei"

_DEFAULT_PORTS = {"http": 80, "https": 443}

# ------------------------------------------------------------------
# Closed error vocabulary (deterministic, secret-free)
# ------------------------------------------------------------------

EXECUTOR_ERROR_CODES = frozenset(
    {
        "TEMPLATE_REJECTED",
        "TEMPLATE_UNSAFE",
        "ARTIFACT_REVALIDATION_FAILED",
        "AUTHZ_NOT_FOUND",
        "AUTHZ_NOT_LIVE",
        "AUTHZ_BINDING_MISMATCH",
        "TARGET_BINDING_MISMATCH",
        "RESOLUTION_BINDING_MISMATCH",
        "DIAL_BINDING_MISMATCH",
        "TARGET_NOT_IN_SCOPE",
        "TARGET_EXCLUDED",
        "SCOPE_DRIFT",
        "EXECUTION_ALREADY_CONSUMED",
        "EXECUTION_REPLAY",
        "OUTCOME_UNKNOWN",
        "AUDIT_GAP",
        "SUBPROCESS_OUTPUT_LIMIT",
        "SUBPROCESS_TIMEOUT",
        "SUBPROCESS_KILLED",
        "NUCLEI_EXECUTION_BLOCKED",
        "NUCLEI_RUNTIME_UNSUPPORTED",
        "NETWORK_BINDING_FAILURE",
        "OOB_NOT_AUTHORIZED",
        "TARGET_EXPANSION_DENIED",
        "REQUEST_LIMIT",
        "EVIDENCE_SEAL_FAILED",
    }
)


class ExecutorError(ValueError):
    """Bounded, secret-free 5F failure with an explicit closed code."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in EXECUTOR_ERROR_CODES:
            raise ValueError(f"unknown executor error code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("executor error detail must be single-line")
        if scrubber.contains_secret_shape(safe_detail):
            raise ValueError(
                "executor error detail carries suspected secret material"
            )
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


# ------------------------------------------------------------------
# 5F.3 — executor-time template safety gate
# ------------------------------------------------------------------

#: Top-level artifact keys the 5F gate denies outright. The canonical
#: typed content (``NucleiTemplateContent``) carries exactly one HTTP
#: exchange (method/path/headers/query/body) plus matchers; anything
#: outside the allowlist below is a foreign execution feature and is
#: denied fail-closed (unknown blocks are never tolerated).
_DENIED_TEMPLATE_KEYS = frozenset(
    {
        "dns",
        "network",
        "tcp",
        "ssl",
        "file",
        "code",
        "headless",
        "javascript",
        "browser",
        "workflow",
        "workflows",
        "interactsh",
        "oast",
        "oastify",
        "fuzz",
        "fuzzing",
        "payloads",
        "attack",
        "attacks",
        "cluster",
        "clustering",
        "extractors",
        "extract",
        "callback",
        "callbacks",
        "redirects",
        "max-redirects",
        "raw",
        "http",
        "websocket",
        "variables",
        "oob",
    }
)

#: Top-level keys the 5F gate permits (typed single-exchange shape).
#: ``variables`` is denied in 5F v1: the frozen typed content
#: (``NucleiTemplateContent``, ``extra="forbid"``) carries no
#: variables field, so any variables block fails closed here with an
#: explicit feature name instead of a generic parse error.
_ALLOWED_TEMPLATE_KEYS = frozenset(
    {
        "template_id",
        "method",
        "path",
        "headers",
        "query_params",
        "body",
        "matchers",
    }
)

#: Header names that must never be supplied by the template
#: (authority identity or ambient credentials; transport owns them).
_FORBIDDEN_TEMPLATE_HEADERS = frozenset(
    {
        "host",
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "proxy-authenticate",
    }
)

#: Substrings marking an out-of-band / callback destination. Any
#: occurrence in any template string value denies the template.
_OOB_MARKERS = (
    "interactsh",
    "oast",
    "burpcollaborator",
    "oastify",
    "dnslog",
    "canarytokens",
    "webhook.site",
    "requestbin",
    "ngrok",
    "pipedream",
)

_ABSOLUTE_URL_RE = re.compile(r"https?://", re.IGNORECASE)

_VARIABLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

#: Text-level finding-like signal. Observation only: presence sets
#: ``finding_like_text_present`` on the sealed observation and never
#: becomes a verdict, severity, or confirmation.
_FINDING_LIKE_RE = re.compile(
    r"\b(vulnerable|exploited|confirmed|critical|high\s+severity"
    r"|matched|\[vulnerability\])\b",
    re.IGNORECASE,
)


def _has_controls(value: str) -> bool:
    for char in value:
        code = ord(char)
        if char in ("\n", "\r", "\0") or code < 32 or code == 127:
            return True
    return False


def _iter_string_values(payload: Any) -> list[str]:
    """Collect every string leaf of a JSON mapping (deterministic)."""
    found: list[str] = []
    if isinstance(payload, str):
        return [payload]
    if isinstance(payload, dict):
        for key, item in payload.items():
            if isinstance(key, str):
                found.append(key)
            found.extend(_iter_string_values(item))
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            found.extend(_iter_string_values(item))
    return found


@dataclass(frozen=True)
class TemplateSafetyReport:
    """Deterministic outcome of the 5F executor-time template gate.

    ``decision`` is ``ALLOW`` only when every 5F deny rule passes on
    top of the reused H1/H2 gates. ``reasons`` carries short
    deterministic explanations; ``denied_features`` names the closed
    deny-list entries that fired. A denied template never reaches
    execution-spec construction.
    """

    decision: str
    template_id: str
    template_hash: str
    reasons: tuple[str, ...] = ()
    denied_features: tuple[str, ...] = ()


def validate_nuclei_safety_template(
    template_bytes: object,
    *,
    fixtures: object = None,
) -> TemplateSafetyReport:
    """5F executor-time template safety gate (pure, fail-closed).

    Reuses the frozen H1/H2 validators (``validate_nuclei_safety``,
    ``validate_nuclei_specificity``, ``parse_template_content``) and
    adds the executor-time deny list: foreign execution blocks,
    extractor blocks, workflow blocks, OOB/callback markers, absolute
    URLs / authority overrides, forbidden identity headers, shell or
    control smuggling in the reconstructed request line, matcher
    specificity floors, and resource bounds. Any violation denies.
    """
    if not isinstance(template_bytes, (bytes, bytearray)):
        raise TypeError(
            "template validation accepts only bytes, "
            f"not {type(template_bytes).__name__}"
        )
    raw = bytes(template_bytes)
    reasons: list[str] = []
    denied: list[str] = []

    def _deny(feature: str, reason: str) -> None:
        denied.append(feature)
        reasons.append(reason)

    if len(raw) > MAX_NUCLEI_TEMPLATE_BYTES:
        _deny(
            "template-size",
            f"template exceeds {MAX_NUCLEI_TEMPLATE_BYTES} bytes",
        )
        return TemplateSafetyReport(
            decision="DENY",
            template_id="",
            template_hash=content_hash_for_bytes(raw),
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _deny("encoding", "template bytes are not utf-8")
        return TemplateSafetyReport(
            decision="DENY",
            template_id="",
            template_hash=content_hash_for_bytes(raw),
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    try:
        payload = json.loads(text)
    except ValueError:
        _deny("encoding", "template bytes are not json")
        return TemplateSafetyReport(
            decision="DENY",
            template_id="",
            template_hash=content_hash_for_bytes(raw),
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    if not isinstance(payload, dict):
        _deny("encoding", "template content is not an object")
        return TemplateSafetyReport(
            decision="DENY",
            template_id="",
            template_hash=content_hash_for_bytes(raw),
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    lowered_keys = {
        key.casefold() for key in payload if isinstance(key, str)
    }
    for blocked in sorted(_DENIED_TEMPLATE_KEYS):
        if blocked in lowered_keys:
            _deny(blocked, f"forbidden execution block: {blocked!r}")
    for key in payload:
        if isinstance(key, str) and key.casefold() not in (
            _ALLOWED_TEMPLATE_KEYS | _DENIED_TEMPLATE_KEYS
        ):
            _deny("unknown-block", f"unknown template block: {key!r}")
    # Variables block: denied in 5F v1 (see allowlist above). The
    # literal-shape checks below are defense in depth so that any
    # future relaxation still bounds names and values.
    variables = None
    for key in payload:
        if isinstance(key, str) and key.casefold() == "variables":
            variables = payload[key]
            break
    if variables is not None:
        if not isinstance(variables, dict):
            _deny("variables", "variables block must be a mapping")
        else:
            for name, value in variables.items():
                if not isinstance(name, str) or not _VARIABLE_NAME_RE.match(
                    name
                ):
                    _deny("variables", "variable name rejected")
                    continue
                if not isinstance(value, str):
                    _deny("variables", "variable value must be a literal")
                    continue
                if len(value) > MAX_VARIABLE_VALUE_LENGTH:
                    _deny("variables", "variable value over cap")
                    continue
                if "{{" in value or "}}" in value:
                    _deny("variables", "variable interpolation denied")
                    continue
                if (
                    "$(" in value
                    or "`" in value
                    or "${" in value
                ):
                    _deny("variables", "variable substitution denied")
                    continue
    # OOB / callback markers anywhere in template string values.
    for leaf in _iter_string_values(payload):
        folded = leaf.casefold()
        for marker in _OOB_MARKERS:
            if marker in folded:
                _deny("oob-callback", f"oob marker denied: {marker!r}")
                break
    try:
        content = parse_template_content(raw)
    except (ValueError, TypeError) as exc:
        _deny("malformed-content", f"malformed template content: {exc}")
        return TemplateSafetyReport(
            decision="DENY",
            template_id="",
            template_hash=content_hash_for_bytes(raw),
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    digest = content_hash_for_bytes(
        canonical_template_bytes(content)
    )
    if content.method not in ALLOWED_METHODS:
        _deny(
            "destructive-method",
            f"method {content.method!r} denied at executor gate",
        )
    # Reused H2 safety gate (path/headers/query/body deny rules).
    for violation in validate_nuclei_safety(content):
        _deny("h2-safety", violation)
    # 5F authority gate: identity headers the template must not set.
    for name in content.headers:
        folded = name.strip().casefold()
        if folded in _FORBIDDEN_TEMPLATE_HEADERS or folded.startswith(
            "proxy-"
        ):
            _deny(
                "authority-override",
                f"forbidden header denied: {name!r}",
            )
    # 5F authority gate: no absolute URL / authority component in any
    # DATA field (path, query values, header values, body). The
    # path/query/body are DATA and never authority.
    data_fields: list[tuple[str, str]] = [("path", content.path)]
    for name, value in content.query_params.items():
        data_fields.append((f"query:{name}", value))
    for name, value in content.headers.items():
        data_fields.append((f"header:{name}", value))
    if content.body is not None:
        data_fields.append(("body", content.body))
    for label, value in data_fields:
        if _ABSOLUTE_URL_RE.search(value):
            _deny(
                "absolute-url",
                f"absolute url denied in {label}",
            )
    if "@" in content.path:
        _deny("authority-override", "userinfo marker denied in path")
    if content.path.startswith("//"):
        _deny("authority-override", "authority-form path denied")
    if content.body is not None:
        for line in content.body.split("\n"):
            if line.strip().casefold().startswith("host:"):
                _deny(
                    "authority-override",
                    "host line denied in body",
                )
                break
    # Raw-request gate: exactly one reconstructed request line, HTTP
    # only, bounded, relative, no controls, no shell syntax.
    request_line = f"{content.method} {content.path} HTTP/1.1"
    if len(request_line) > MAX_RAW_REQUEST_LINE_LENGTH:
        _deny("raw-request", "request line over cap")
    if _has_controls(request_line):
        _deny("raw-request", "request line controls denied")
    for token in ("$(", "`", "${"):
        if token in request_line:
            _deny("raw-request", "request line substitution denied")
            break
    if ";" in content.path or "|" in content.path:
        _deny("raw-request", "request line shell syntax denied")
    # Matcher resource + static-specificity floors (no-fixture half of
    # H1; the fixture half runs below when fixtures are supplied).
    if len(content.matchers) > 16:
        _deny("matcher-count", "too many matchers")
    regex_total = 0
    for index, matcher in enumerate(content.matchers):
        if matcher.matcher_type == "status":
            _deny(
                "status-only-matcher",
                f"matcher[{index}] is status-only; denied",
            )
        for value in matcher.values:
            if len(value) > MAX_MATCHER_VALUE_LENGTH:
                _deny("matcher-size", "matcher value over cap")
            if matcher.matcher_type == "regex":
                regex_total += len(value)
            probe = value.strip().casefold()
            if probe and (
                len(probe) < MIN_SPECIFIC_TOKEN_LENGTH
                or probe in GENERIC_TOKENS
            ):
                _deny(
                    "generic-matcher",
                    f"matcher[{index}] value proves no specificity",
                )
    if regex_total > MAX_REGEX_COMPLEXITY:
        _deny("regex-complexity", "regex surface over cap")
    # Fixture half of H1 when the caller supplies fixtures.
    if fixtures is not None:
        if not isinstance(fixtures, (list, tuple)):
            raise TypeError(
                "fixtures must be a list or tuple, "
                f"not {type(fixtures).__name__}"
            )
        result = validate_nuclei_specificity(content, fixtures)
        if not result.passed:
            for reason in result.reasons:
                _deny("specificity", reason)
    if denied:
        return TemplateSafetyReport(
            decision="DENY",
            template_id=content.template_id,
            template_hash=digest,
            reasons=tuple(reasons),
            denied_features=tuple(denied),
        )
    return TemplateSafetyReport(
        decision="ALLOW",
        template_id=content.template_id,
        template_hash=digest,
        reasons=("template passed executor-time safety gate",),
        denied_features=(),
    )


# ------------------------------------------------------------------
# 5F.1 — closed execution specification
# ------------------------------------------------------------------

#: Closed stdin policy: the runner never inherits or pipes input.
STDIN_POLICY_CLOSED = "closed"


@dataclass(frozen=True)
class ResourceLimitsSpec:
    """Future process-boundary constraints as a typed record (5F.7).

    Values reuse the frozen 5H-core ceilings (wall time, CPU,
    memory, file size, output caps, scratch storage); the descriptor
    counts (file descriptors, process count) are 5F-specified. No
    active enforcement lives here: enforcement belongs to the future
    B3 boundary. The 5F runtime fails closed rather than running
    without these recorded limits.
    """

    wall_seconds: int
    cpu_seconds: int
    memory_bytes: int
    fd_limit: int
    proc_limit: int
    file_size_bytes: int
    stdout_cap_bytes: int
    stderr_cap_bytes: int
    scratch_bytes: int


def default_resource_limits() -> ResourceLimitsSpec:
    """Record the frozen limit set (values from 5H-core ceilings)."""
    return ResourceLimitsSpec(
        wall_seconds=_NUCLEI_WALL,
        cpu_seconds=_NUCLEI_CPU,
        memory_bytes=_NUCLEI_MEMORY,
        fd_limit=64,
        proc_limit=1,
        file_size_bytes=_TEMP_STORAGE,
        stdout_cap_bytes=_NUCLEI_OUTPUT_MAX,
        stderr_cap_bytes=_NUCLEI_OUTPUT_MAX,
        scratch_bytes=_TEMP_STORAGE,
    )


@dataclass(frozen=True)
class NucleiExecutionSpec:
    """Immutable closed execution specification (5F.1).

    Carries only validated, bound values. No raw authority field, no
    arbitrary executable field, no arbitrary flags, no caller
    environment. The runner receives this record and nothing else.
    """

    execution_id: str
    authorization_id: str
    program_name: str
    canonical_host: str
    scheme: str
    effective_port: int
    target_string: str
    artifact_id: str
    template_id: str
    template_hash: str
    argv: tuple[str, ...]
    argv_digest: str
    cwd: str
    environment: tuple[tuple[str, str], ...]
    stdin_policy: str
    stdout_cap_bytes: int
    stderr_cap_bytes: int
    limits: ResourceLimitsSpec
    schema_version: str = SCHEMA_VERSION


# ------------------------------------------------------------------
# 5F.4 / 5F.5 / 5F.6 — pure deterministic builders
# ------------------------------------------------------------------

def build_target_string(
    *, scheme: str, canonical_host: str, effective_port: int
) -> str:
    """Authority-free target: scheme + canonical host + port only."""
    if scheme not in ("http", "https"):
        raise ExecutorError("TARGET_BINDING_MISMATCH", "scheme rejected")
    if not isinstance(effective_port, int) or isinstance(
        effective_port, bool
    ):
        raise ExecutorError("TARGET_BINDING_MISMATCH", "port rejected")
    if not 1 <= effective_port <= 65535:
        raise ExecutorError("TARGET_BINDING_MISMATCH", "port rejected")
    base = f"{scheme}://{canonical_host}"
    if effective_port != _DEFAULT_PORTS[scheme]:
        base += f":{effective_port}"
    return base


def build_nuclei_argv(
    *, template_path: str, target_string: str
) -> tuple[str, ...]:
    """Frozen argv shape (pure; artifact cannot influence flags).

    B6 corrected argv for the pinned release (``PINNED_NUCLEI_VERSION``,
    proven flag-by-flag on v3.11.1 — see the version-contract note):

    - update checks off: ``-disable-update-check``
    - redirects off (budget zero): ``-disable-redirects`` (B4's
      ``-no-redirects`` is not a Nuclei flag and never constrained
      any release)
    - OOB/interactsh off: ``-no-interactsh`` (B4's
      ``-disable-interactsh`` is not a Nuclei flag)
    - structured findings: ``-jsonl`` (B4's ``-json`` is not a v3
      flag)
    - one host per template invocation: ``-bulk-size 1``
    - one template stream: ``-concurrency 1``
    - per-request deadline: ``-timeout 5``
    - no failed-request retry: ``-retries 0`` (upstream default is 1)
    - binary-level SSRF guard: ``-restrict-local-network-access``
      (refuses local/private destinations inside the child)
    """
    if not isinstance(template_path, str) or not template_path.startswith(
        _SCRATCH_ROOT + "/"
    ):
        raise ExecutorError(
            "TARGET_EXPANSION_DENIED", "template path outside scratch"
        )
    if not isinstance(target_string, str) or "://" not in target_string:
        raise ExecutorError("TARGET_BINDING_MISMATCH", "target rejected")
    if _ABSOLUTE_URL_RE.search(target_string) is None:
        raise ExecutorError("TARGET_BINDING_MISMATCH", "target rejected")
    return (
        SERVER_CONTROLLED_NUCLEI_BINARY,
        "-t",
        template_path,
        "-u",
        target_string,
        "-disable-update-check",
        "-disable-redirects",
        "-no-interactsh",
        "-silent",
        "-no-color",
        "-stats-interval",
        "0",
        "-jsonl",
        "-bulk-size",
        "1",
        "-concurrency",
        "1",
        "-timeout",
        "5",
        "-retries",
        "0",
        "-restrict-local-network-access",
        "-nc",
    )


def assert_frozen_argv_supported(argv: object) -> tuple[str, ...]:
    """Cross-check one argv against the pinned-release flag contract.

    Every ``-flag`` token must belong to ``SUPPORTED_NUCLEI_FLAGS``;
    redirect-enabling flags are denied outright; the network bounds
    (``-bulk-size 1``, ``-concurrency 1``, ``-timeout 5``,
    ``-retries 0``, ``-disable-redirects``) must be present with
    their exact values. Anything else fails closed with
    ``NUCLEI_RUNTIME_UNSUPPORTED``. Values (paths, targets, numbers)
    are never treated as flags.
    """

    if not isinstance(argv, (tuple, list)) or not argv:
        raise ExecutorError(
            "NUCLEI_RUNTIME_UNSUPPORTED", "argv shape rejected"
        )
    tokens = tuple(argv)
    if tokens[0] != SERVER_CONTROLLED_NUCLEI_BINARY:
        raise ExecutorError(
            "NUCLEI_RUNTIME_UNSUPPORTED", "argv binary not controlled"
        )
    for token in tokens:
        if not isinstance(token, str) or not token:
            raise ExecutorError(
                "NUCLEI_RUNTIME_UNSUPPORTED", "argv token rejected"
            )
        if token.startswith("-") and not token[1:2].isdigit():
            if token in _FORBIDDEN_NUCLEI_FLAGS:
                raise ExecutorError(
                    "NUCLEI_RUNTIME_UNSUPPORTED", "argv redirect enabled"
                )
            if token not in SUPPORTED_NUCLEI_FLAGS:
                raise ExecutorError(
                    "NUCLEI_RUNTIME_UNSUPPORTED", "argv flag not supported"
                )
    required_pairs = (
        ("-bulk-size", "1"),
        ("-concurrency", "1"),
        ("-timeout", "5"),
        ("-retries", "0"),
    )
    for flag, value in required_pairs:
        try:
            got = tokens[tokens.index(flag) + 1]
        except (ValueError, IndexError) as exc:
            raise ExecutorError(
                "NUCLEI_RUNTIME_UNSUPPORTED", "argv bound missing"
            ) from exc
        if got != value:
            raise ExecutorError(
                "NUCLEI_RUNTIME_UNSUPPORTED", "argv bound mismatch"
            )
    if "-disable-redirects" not in tokens:
        raise ExecutorError(
            "NUCLEI_RUNTIME_UNSUPPORTED", "argv redirect not disabled"
        )
    return tokens


def argv_digest_for(argv: tuple[str, ...]) -> str:
    """SHA-256 over the canonical argv list (artifact-independent)."""
    if not isinstance(argv, (tuple, list)):
        raise TypeError(
            "argv digest accepts only a tuple or list, "
            f"not {type(argv).__name__}"
        )
    canonical = json.dumps(
        list(argv), ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_nuclei_environment(
    *, scratch_dir: str
) -> tuple[tuple[str, str], ...]:
    """Closed environment allowlist (pure; no inherited values).

    The only inputs are the validated scratch directory. There is no
    caller-environment parameter by construction: arbitrary caller
    environment cannot enter the spec.
    """
    if not isinstance(scratch_dir, str) or not scratch_dir.startswith(
        _SCRATCH_ROOT + "/"
    ):
        raise ExecutorError(
            "TARGET_EXPANSION_DENIED", "scratch dir rejected"
        )
    return (
        ("HOME", scratch_dir),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("PATH", "/usr/bin:/bin"),
        ("TMPDIR", scratch_dir),
    )


def scratch_dir_for(execution_id: str) -> str:
    """Deterministic hash-free scratch path bound to the execution."""
    if not isinstance(execution_id, str) or not re.fullmatch(
        r"ex-[0-9a-f]{32}", execution_id
    ):
        raise ExecutorError("AUTHZ_BINDING_MISMATCH", "execution id rejected")
    return f"{_SCRATCH_ROOT}/{execution_id}"


# ------------------------------------------------------------------
# 5F.2 — runner protocol + fakes + blocked live runner
# ------------------------------------------------------------------

@dataclass(frozen=True)
class NucleiRunResult:
    """Offline process facts returned by the injected runner."""

    exit_code: int | None
    timed_out: bool
    killed: bool
    stdout: str
    stderr: str
    argv_digest: str


class NucleiRunner(Protocol):
    """Injected runner seam. Receives only the closed spec."""

    def launch(self, spec: NucleiExecutionSpec) -> NucleiRunResult: ...


class FakeNucleiRunner:
    """Deterministic offline runner (the only v1 execution path).

    Never creates processes, never resolves names, never opens
    transports. Records every invocation and returns scripted
    stdout/stderr plus scripted exit/timeout/killed facts.
    """

    def __init__(
        self,
        *,
        stdout: str = "",
        stderr: str = "",
        exit_code: int | None = 0,
        timed_out: bool = False,
        killed: bool = False,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._exit_code = exit_code
        self._timed_out = timed_out
        self._killed = killed
        self.invocations: list[NucleiExecutionSpec] = []

    def launch(self, spec: NucleiExecutionSpec) -> NucleiRunResult:
        if not isinstance(spec, NucleiExecutionSpec):
            raise TypeError(
                "runner accepts only NucleiExecutionSpec, "
                f"not {type(spec).__name__}"
            )
        if LIVE_NUCLEI:
            raise ExecutorError(
                "NUCLEI_EXECUTION_BLOCKED", "live gate must stay closed"
            )
        self.invocations.append(spec)
        return NucleiRunResult(
            exit_code=self._exit_code,
            timed_out=self._timed_out,
            killed=self._killed,
            stdout=self._stdout,
            stderr=self._stderr,
            argv_digest=spec.argv_digest,
        )


class LiveNucleiRunner:
    """Permanently blocked live runner (5F v1 ships blocked).

    Raises ``NUCLEI_EXECUTION_BLOCKED`` before any process primitive.
    There is no escape hatch: no flag, constructor argument, artifact
    value, or caller input can enable process creation here.
    """

    def launch(self, spec: NucleiExecutionSpec) -> NucleiRunResult:
        raise ExecutorError(
            "NUCLEI_EXECUTION_BLOCKED",
            "live Nuclei execution blocked pending B3 review",
        )


class B3NetnsNucleiRunner:
    """Documented future live-runner interface (placeholder only).

    Represents the only acceptable future live runner shape (isolated
    network namespace with explicit egress). It cannot execute: every
    call raises ``NUCLEI_EXECUTION_BLOCKED`` until the B3 review
    lands and replaces this placeholder under that review.
    """

    def launch(self, spec: NucleiExecutionSpec) -> NucleiRunResult:
        raise ExecutorError(
            "NUCLEI_EXECUTION_BLOCKED",
            "B3 sandbox boundary not reviewed; cannot execute",
        )


# ------------------------------------------------------------------
# Deps / result
# ------------------------------------------------------------------

@dataclass
class NucleiExecutorDeps:
    """Injected executor dependencies (offline fakes in 5F v1)."""

    authz_store: Any = None
    ledger: Any = None
    audit: Any = None
    now_iso: Callable[[], str] | None = None
    monotonic: Callable[[], float] | None = None

    def now(self) -> str:
        if self.now_iso is None:
            return datetime.now(timezone.utc).isoformat()
        return self.now_iso()

    def clock(self) -> float:
        if self.monotonic is None:
            import time as _time

            return _time.monotonic()
        return self.monotonic()


@dataclass(frozen=True)
class NucleiExecutionResult:
    """Terminal execution outcome (accounting, never a verdict)."""

    execution_id: str
    authorization_id: str
    outcome: str
    error_code: str | None
    error_detail: str
    evidence: ev.EvidenceRecord | None
    spec: NucleiExecutionSpec | None
    audit_gap: bool = False


_EXECUTION_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")


# ------------------------------------------------------------------
# Internal guards
# ------------------------------------------------------------------

def _check_binding(
    *,
    authorization: IssuedExecutionAuthorization,
    resolution: TargetResolution,
    evaluation: ScopeEvaluation,
    execution_id: str,
) -> None:
    if resolution.authorization_id != authorization.authorization_id:
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "resolution authorization mismatch"
        )
    if resolution.execution_id != execution_id:
        raise ExecutorError(
            "AUTHZ_BINDING_MISMATCH", "resolution execution mismatch"
        )
    if evaluation.authorization_id != authorization.authorization_id:
        raise ExecutorError(
            "AUTHZ_BINDING_MISMATCH", "evaluation authorization mismatch"
        )
    if evaluation.execution_id != execution_id:
        raise ExecutorError(
            "AUTHZ_BINDING_MISMATCH", "evaluation execution mismatch"
        )
    if evaluation.resolution_id != resolution.resolution_id:
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "evaluation resolution mismatch"
        )
    if resolution.status != "RESOLVED":
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "resolution not resolved"
        )
    bound = authorization.target
    if resolution.program_name != bound.program_name:
        raise ExecutorError("TARGET_BINDING_MISMATCH", "program mismatch")
    try:
        authz_host, _ = canonicalize_host(bound.host)
    except (CanonicalizationError, TypeError) as exc:
        raise ExecutorError(
            "TARGET_BINDING_MISMATCH", "target not canonical"
        ) from exc
    if authz_host != resolution.canonical_host:
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "canonical host mismatch"
        )
    if (
        resolution.scheme != bound.scheme
        or resolution.effective_port != bound.effective_port
    ):
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "scheme or port mismatch"
        )
    recomputed = canonical_target_hash_for(
        program_name=resolution.program_name,
        canonical_host=resolution.canonical_host,
        scheme=resolution.scheme,
        effective_port=resolution.effective_port,
    )
    if recomputed != resolution.canonical_target_hash:
        raise ExecutorError(
            "RESOLUTION_BINDING_MISMATCH", "canonical target hash mismatch"
        )
    dial = resolution.dial
    if (
        dial is None
        or tuple(dial.addresses) != tuple(resolution.resolved_addresses)
        or dial.effective_port != resolution.effective_port
        or dial.sni_host != resolution.canonical_host
        or dial.pin_required is not True
    ):
        raise ExecutorError("DIAL_BINDING_MISMATCH", "dial binding incoherent")
    if len(resolution.resolved_addresses) == 0:
        raise ExecutorError("DIAL_BINDING_MISMATCH", "empty address set")
    if len(resolution.resolved_addresses) > _DNS_ANSWERS_MAX:
        raise ExecutorError("DIAL_BINDING_MISMATCH", "answer set over ceiling")
    if resolution.scope_lists_hash_current != bound.scope_lists_hash:
        raise ExecutorError("SCOPE_DRIFT", "resolution scope stale")


def _revalidate_artifact(
    *,
    authorization: IssuedExecutionAuthorization,
    artifact_reference: ArtifactReference,
    artifact_bytes: bytes,
    test_plan: object = None,
    fixtures: object = None,
) -> NucleiTemplateContent:
    """Exact artifact revalidation (hash + identity + H2 re-run)."""
    if not isinstance(artifact_reference, ArtifactReference):
        raise TypeError(
            "artifact revalidation accepts only ArtifactReference, "
            f"not {type(artifact_reference).__name__}"
        )
    if not isinstance(artifact_bytes, (bytes, bytearray)):
        raise TypeError(
            "artifact content must be bytes, "
            f"not {type(artifact_bytes).__name__}"
        )
    raw = bytes(artifact_bytes)
    if artifact_reference.validation_state != "VALID":
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact reference not valid"
        )
    if artifact_reference.artifact_type != "nuclei_template":
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact type not nuclei"
        )
    if content_hash_for_bytes(raw) != artifact_reference.content_hash:
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact bytes hash mismatch"
        )
    bound = authorization.artifact
    if (
        artifact_reference.artifact_id != bound.artifact_id
        or artifact_reference.content_hash != bound.content_hash
        or artifact_reference.artifact_type != bound.artifact_type
        or artifact_reference.test_plan_id != bound.test_plan_id
    ):
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact binding mismatch"
        )
    expected_id = artifact_id_for(
        artifact_type="nuclei_template",
        test_plan_id=artifact_reference.test_plan_id,
        content_hash=artifact_reference.content_hash,
    )
    if artifact_reference.artifact_id != expected_id:
        raise ExecutorError(
            "ARTIFACT_REVALIDATION_FAILED", "artifact identity mismatch"
        )
    if test_plan is not None:
        recheck = build_validated_reference(
            test_plan, raw, "nuclei_template", fixtures=fixtures or []
        )
        if recheck.state != "VALID":
            raise ExecutorError(
                "ARTIFACT_REVALIDATION_FAILED",
                "artifact failed validation recheck",
            )
    else:
        try:
            typed = parse_template_content(raw)
        except (ValueError, TypeError) as exc:
            raise ExecutorError(
                "ARTIFACT_REVALIDATION_FAILED", "artifact content malformed"
            ) from exc
        violations = validate_nuclei_safety(typed)
        if violations:
            raise ExecutorError(
                "ARTIFACT_REVALIDATION_FAILED",
                "artifact failed safety recheck",
            )
        return typed
    return parse_template_content(raw)


def _observe_stream(
    text: str, *, cap_bytes: int
) -> tuple[str, str | None]:
    """Bound, normalize, scrub, and hash one output stream.

    Returns ``(stream_hash, stored_sample)``. The hash covers exactly
    the stored (scrubbed, capped) sample bytes. Raw text never
    persists and never surfaces in exceptions.
    """
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    redacted = scrubber.scrub_text(normalized)
    encoded = redacted.encode("utf-8")
    if len(encoded) > cap_bytes:
        raise ExecutorError(
            "SUBPROCESS_OUTPUT_LIMIT", "runner output over cap"
        )
    return hash_mod.sha256_hex(encoded), redacted


# ------------------------------------------------------------------
# 5F.8 — lifecycle orchestration (exact security ordering)
# ------------------------------------------------------------------

class _NucleiExecutor:
    """Single-execution lifecycle driver (5F.8, exact 20-step order)."""

    def __init__(
        self, deps: NucleiExecutorDeps, runner: NucleiRunner
    ) -> None:
        if not isinstance(deps, NucleiExecutorDeps):
            raise TypeError(
                "executor accepts only NucleiExecutorDeps, "
                f"not {type(deps).__name__}"
            )
        for attr in ("authz_store", "ledger", "audit"):
            if getattr(deps, attr, None) is None:
                raise TypeError(f"executor deps missing: {attr}")
        if not isinstance(runner, (FakeNucleiRunner, LiveNucleiRunner,
                                   B3NetnsNucleiRunner)):
            raise TypeError(
                "executor accepts only a 5F runner, "
                f"not {type(runner).__name__}"
            )
        self._deps = deps
        self._runner = runner
        self._audit_seq = 0

    # -- audit --------------------------------------------------------

    def _audit_append(
        self,
        *,
        execution_id: str,
        authorization: IssuedExecutionAuthorization,
        transition: str,
        evidence: ev.EvidenceRecord | None = None,
        error_code: str | None = None,
        scope_decision: str | None = None,
    ) -> None:
        record = AuditRecord(
            seq=self._audit_seq,
            execution_id=execution_id,
            authorization_id=authorization.authorization_id,
            evidence_id=evidence.evidence_id if evidence is not None else None,
            transition=transition,  # type: ignore[arg-type]
            at=self._deps.now(),
            actor="nuclei-executor/5F",
            program_name=authorization.target.program_name,
            host=authorization.target.host,
            scope_decision=scope_decision,
            artifact_id=authorization.artifact.artifact_id,
            artifact_content_hash=authorization.artifact.content_hash,
            evidence_hashes=(
                {
                    "bindings_hash": evidence.bindings_hash,
                    "observations_hash": evidence.observations_hash,
                    "content_hash": evidence.content_hash,
                }
                if evidence is not None
                and evidence.bindings_hash is not None
                and evidence.observations_hash is not None
                and evidence.content_hash is not None
                else {}
            ),
            error_code=error_code,
        )
        self._deps.audit.append(record)
        self._audit_seq += 1

    def _audit_gap(
        self,
        *,
        execution_id: str,
        authorization: IssuedExecutionAuthorization,
        missing_from: str,
    ) -> None:
        try:
            self._deps.audit.append(
                gap_record(
                    seq=self._audit_seq,
                    execution_id=execution_id,
                    authorization_id=authorization.authorization_id,
                    missing_from=missing_from,
                    at=self._deps.now(),
                    actor="nuclei-executor/5F",
                )
            )
            self._audit_seq += 1
        except Exception:
            pass

    # -- ledger + consume ----------------------------------------------

    def _claim_and_consume(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        execution_id: str,
    ) -> IssuedExecutionAuthorization:
        """Ledger claim + authorization CAS + STARTED (at-most-once)."""
        from ai.authorizer.service import consume_authorization
        from ai.execution.ledger import (
            ExecutionRecord,
            LedgerError,
        )

        _ = LedgerError
        ledger = self._deps.ledger
        for method_name in (
            "put_new",
            "mark_started",
            "mark_sealed",
            "mark_incomplete",
            "mark_unknown",
        ):
            if not callable(getattr(ledger, method_name, None)):
                raise TypeError(f"ledger missing capability: {method_name}")
        now = self._deps.now()
        try:
            ledger.put_new(
                ExecutionRecord(
                    execution_id=execution_id,
                    authorization_id=authorization.authorization_id,
                    execution_stage="single",
                    idempotency_key=authorization.idempotency_key,
                )
            )
        except Exception as exc:
            if type(exc).__name__ in (
                "ReplayExecutionError",
                "DuplicateExecutionError",
                "InProgressExecutionError",
            ):
                raise ExecutorError(
                    "EXECUTION_REPLAY", "authorization already used"
                ) from exc
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "ledger claim ambiguous"
            ) from exc
        try:
            consumed = consume_authorization(
                self._deps.authz_store,
                authorization.authorization_id,
                now=now,
            )
        except AuthzError as exc:
            raise ExecutorError(
                "EXECUTION_ALREADY_CONSUMED", "authorization consume lost"
            ) from exc
        except Exception as exc:
            raise ExecutorError(
                "EXECUTION_ALREADY_CONSUMED", "authorization consume lost"
            ) from exc
        try:
            ledger.mark_started(execution_id, started_at=now)
        except Exception as exc:
            if type(exc).__name__ == "InProgressExecutionError":
                raise ExecutorError(
                    "EXECUTION_REPLAY", "execution in progress"
                ) from exc
            try:
                ledger.mark_unknown(execution_id, terminal_at=now)
            except Exception:
                pass
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "start state ambiguous"
            ) from exc
        return consumed

    # -- main -----------------------------------------------------------

    def run(
        self,
        *,
        authorization: IssuedExecutionAuthorization,
        resolution: TargetResolution,
        evaluation: ScopeEvaluation,
        artifact_reference: ArtifactReference,
        artifact_bytes: bytes,
        execution_id: str,
        test_plan: object = None,
        fixtures: object = None,
    ) -> NucleiExecutionResult:
        # 1. typed input validation.
        if not isinstance(authorization, IssuedExecutionAuthorization):
            raise TypeError(
                "executor accepts only IssuedExecutionAuthorization, "
                f"not {type(authorization).__name__}"
            )
        if not isinstance(resolution, TargetResolution):
            raise TypeError(
                "executor accepts only TargetResolution, "
                f"not {type(resolution).__name__}"
            )
        if not isinstance(evaluation, ScopeEvaluation):
            raise TypeError(
                "executor accepts only ScopeEvaluation, "
                f"not {type(evaluation).__name__}"
            )
        if not isinstance(execution_id, str) or not _EXECUTION_ID_RE.match(
            execution_id
        ):
            raise ExecutorError(
                "AUTHZ_BINDING_MISMATCH", "malformed execution id"
            )
        # 2. authorization liveness re-read (never trust the caller
        # copy; the store record is authority).
        from ai.authorizer.service import get_issued_authorization

        live = get_issued_authorization(
            self._deps.authz_store, authorization.authorization_id
        )
        if live is None:
            raise ExecutorError(
                "AUTHZ_NOT_FOUND", "unknown authorization"
            )
        if live.lifecycle != "ISSUED":
            raise ExecutorError(
                "AUTHZ_NOT_LIVE", "authorization not live"
            )
        if live.expires_at <= self._deps.now():
            raise ExecutorError("AUTHZ_NOT_LIVE", "authorization expired")
        if live.execution_class != "nuclei_scan":
            raise ExecutorError(
                "AUTHZ_BINDING_MISMATCH", "execution class not nuclei"
            )
        if live.max_executions != 1:
            raise ExecutorError(
                "AUTHZ_BINDING_MISMATCH", "max executions not one"
            )
        if (
            live.authorization_id != authorization.authorization_id
            or live.artifact.artifact_id != authorization.artifact.artifact_id
            or live.target.program_name != authorization.target.program_name
        ):
            raise ExecutorError(
                "AUTHZ_BINDING_MISMATCH", "authorization drift"
            )
        # 3. target/resolution binding validation.
        _check_binding(
            authorization=live,
            resolution=resolution,
            evaluation=evaluation,
            execution_id=execution_id,
        )
        # 4-5. fresh scope evaluation + require_allowed().
        try:
            require_allowed(
                evaluation,
                authorization_id=live.authorization_id,
                execution_id=execution_id,
                resolution_id=resolution.resolution_id,
            )
        except TypeError:
            raise
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code == "TARGET_EXCLUDED":
                raise ExecutorError(
                    "TARGET_EXCLUDED", "scope excluded target"
                ) from exc
            raise ExecutorError(
                "TARGET_NOT_IN_SCOPE", "scope did not allow target"
            ) from exc
        # 6. artifact revalidation.
        _revalidate_artifact(
            authorization=live,
            artifact_reference=artifact_reference,
            artifact_bytes=artifact_bytes,
            test_plan=test_plan,
            fixtures=fixtures,
        )
        # 7. Nuclei template safety validation (executor-time gate).
        report = validate_nuclei_safety_template(
            artifact_bytes, fixtures=fixtures
        )
        if report.decision != "ALLOW":
            raise ExecutorError(
                "TEMPLATE_REJECTED", "template denied at executor gate"
            )
        # 8. execution specification construction (closed, pure).
        target_string = build_target_string(
            scheme=resolution.scheme,
            canonical_host=resolution.canonical_host,
            effective_port=resolution.effective_port,
        )
        cwd = scratch_dir_for(execution_id)
        template_path = f"{cwd}/{report.template_hash[:16]}.json"
        argv = build_nuclei_argv(
            template_path=template_path, target_string=target_string
        )
        limits = default_resource_limits()
        spec = NucleiExecutionSpec(
            execution_id=execution_id,
            authorization_id=live.authorization_id,
            program_name=resolution.program_name,
            canonical_host=resolution.canonical_host,
            scheme=resolution.scheme,
            effective_port=resolution.effective_port,
            target_string=target_string,
            artifact_id=live.artifact.artifact_id,
            template_id=report.template_id,
            template_hash=report.template_hash,
            argv=tuple(argv),
            argv_digest=argv_digest_for(tuple(argv)),
            cwd=cwd,
            environment=build_nuclei_environment(scratch_dir=cwd),
            stdin_policy=STDIN_POLICY_CLOSED,
            stdout_cap_bytes=limits.stdout_cap_bytes,
            stderr_cap_bytes=limits.stderr_cap_bytes,
            limits=limits,
        )
        # 9-10. ledger registration + authorization CAS consume +
        # STARTED.
        consumed = self._claim_and_consume(
            authorization=live, execution_id=execution_id
        )
        # 11-12. pre-launch audit pair. Any failure here blocks the
        # runner: no launch, no process, deterministic AUDIT_GAP.
        try:
            self._audit_append(
                execution_id=execution_id,
                authorization=consumed,
                transition="AUTHORIZATION",
                scope_decision="ALLOWED",
            )
            self._audit_append(
                execution_id=execution_id,
                authorization=consumed,
                transition="EXECUTION_STARTED",
            )
        except Exception as exc:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            self._audit_gap(
                execution_id=execution_id,
                authorization=consumed,
                missing_from="EXECUTION_STARTED",
            )
            raise ExecutorError(
                "AUDIT_GAP", "pre-launch audit unavailable"
            ) from exc
        # 13-14. runner invocation (fake only; live raises blocked).
        try:
            run_result = self._runner.launch(spec)
        except ExecutorError:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise
        if not isinstance(run_result, NucleiRunResult):
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "runner returned unknown shape"
            )
        if run_result.argv_digest != spec.argv_digest:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "runner argv digest mismatch"
            )
        # 15. bounded result processing.
        if run_result.timed_out:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "SUBPROCESS_TIMEOUT", "runner wall deadline exceeded"
            )
        if run_result.killed:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "SUBPROCESS_KILLED", "runner reports killed process"
            )
        try:
            stdout_hash, stdout_sample = _observe_stream(
                run_result.stdout, cap_bytes=spec.stdout_cap_bytes
            )
            stderr_hash, stderr_sample = _observe_stream(
                run_result.stderr, cap_bytes=spec.stderr_cap_bytes
            )
        except ExecutorError as exc:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise exc
        # 16. NucleiObservation construction (observation only: never
        # a verdict, never severity, never confirmation).
        finding_like = bool(
            _FINDING_LIKE_RE.search(
                run_result.stdout.replace("\r\n", "\n").replace("\r", "\n")
            )
        )
        observation = ev.NucleiObservation(
            template_id=report.template_id,
            template_hash=report.template_hash,
            argv_digest=spec.argv_digest,
            exit_code=run_result.exit_code,
            timed_out=False,
            killed=False,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            stdout_sample=stdout_sample,
            stderr_sample=stderr_sample,
            finding_like_text_present=finding_like,
        )
        # 17. EvidenceBuilder integration + seal.
        try:
            builder = EvidenceBuilder.begin(
                authorization=consumed,
                execution_id=execution_id,
                execution_stage="single",
                execution_class="nuclei_scan",
                started_at=self._deps.now(),
            )
            builder.attach_nuclei(observation)
            evidence = builder.seal(
                finished_at=self._deps.now(),
                sealed_at=self._deps.now(),
            )
        except Exception as exc:
            try:
                self._deps.ledger.mark_unknown(
                    execution_id, terminal_at=self._deps.now()
                )
            except Exception:
                pass
            raise ExecutorError(
                "EVIDENCE_SEAL_FAILED", "evidence seal refused"
            ) from exc
        # 18-19. ledger terminal state + audit terminal state.
        try:
            self._deps.ledger.mark_sealed(
                execution_id, evidence.evidence_id,
                terminal_at=self._deps.now(),
            )
        except Exception as exc:
            raise ExecutorError(
                "OUTCOME_UNKNOWN", "ledger terminal ambiguous"
            ) from exc
        audit_gap = False
        try:
            self._audit_append(
                execution_id=execution_id,
                authorization=consumed,
                transition="EVIDENCE_SEALED",
                evidence=evidence,
            )
            self._audit_append(
                execution_id=execution_id,
                authorization=consumed,
                transition="EXECUTION_TERMINAL",
                evidence=evidence,
            )
        except Exception:
            audit_gap = True
            self._audit_gap(
                execution_id=execution_id,
                authorization=consumed,
                missing_from="EXECUTION_TERMINAL",
            )
        return NucleiExecutionResult(
            execution_id=execution_id,
            authorization_id=consumed.authorization_id,
            outcome="sealed",
            error_code=None,
            error_detail="",
            evidence=evidence,
            spec=spec,
            audit_gap=audit_gap,
        )


def execute_nuclei(
    *,
    authorization: object,
    resolution: object,
    evaluation: object,
    artifact_reference: object,
    artifact_bytes: bytes,
    execution_id: str,
    deps: NucleiExecutorDeps,
    runner: NucleiRunner,
    test_plan: object = None,
    fixtures: object = None,
) -> NucleiExecutionResult:
    """Execute one authorized Nuclei exchange (offline, fail-closed).

    Exact 20-step security ordering (see ``_NucleiExecutor.run``).
    Only the injected offline runner performs step 14; the blocked
    live runner raises ``NUCLEI_EXECUTION_BLOCKED`` before any
    process primitive.
    """
    driver = _NucleiExecutor(deps, runner)
    if not isinstance(authorization, IssuedExecutionAuthorization):
        raise TypeError(
            "execute_nuclei accepts only IssuedExecutionAuthorization, "
            f"not {type(authorization).__name__}"
        )
    if not isinstance(resolution, TargetResolution):
        raise TypeError(
            "execute_nuclei accepts only TargetResolution, "
            f"not {type(resolution).__name__}"
        )
    if not isinstance(evaluation, ScopeEvaluation):
        raise TypeError(
            "execute_nuclei accepts only ScopeEvaluation, "
            f"not {type(evaluation).__name__}"
        )
    if not isinstance(artifact_reference, ArtifactReference):
        raise TypeError(
            "execute_nuclei accepts only ArtifactReference, "
            f"not {type(artifact_reference).__name__}"
        )
    return driver.run(
        authorization=authorization,
        resolution=resolution,
        evaluation=evaluation,
        artifact_reference=artifact_reference,
        artifact_bytes=artifact_bytes,
        execution_id=execution_id,
        test_plan=test_plan,
        fixtures=fixtures,
    )


# Re-export field list guard for boundary review: this module must not
# grow verdict-shaped names. (Checked structurally by tests.)
_FORBIDDEN_MODULE_ATTRS = frozenset(
    {
        "verdict",
        "finding",
        "severity",
        "confirmed",
        "not_vulnerable",
    }
)
