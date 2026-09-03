"""Trusted execution-oracle primitives for XSS verification.

This module implements the execution-oracle infrastructure defined by
``/opt/watch/xss-oracle-design.md`` (verdict: READY FOR ORACLE
IMPLEMENTATION). It is TRUSTED Watch code:

- the LLM never sees or generates the seed, the oracle value, W, or any
  oracle payload;
- the oracle value D is NEVER placed on the wire: only the seed S travels
  inside the payload, and D can be produced only by executing the
  payload's own transform (anti-harvest property);
- everything here is deterministic: identical inputs produce identical
  seeds, values, snippets, and payloads.

Definitions (bit-identical between Python and JavaScript):

    S  = sha256(run_salt + "\\x00" + attempt_id + "\\x00" + phase)[:16]
         rendered as exactly 32 lowercase hex characters
    h1 = fnv1a32(S)
    h2 = fnv1a32(hex(h1) + ":" + S)
    D  = hex8(h1) + hex8(h2)          (exactly 16 lowercase hex characters)

``fnv1a32`` operates over UTF-16 code units (matching JavaScript's
``charCodeAt``) and uses 32-bit wrap-around multiplication, implemented in
JavaScript with ``Math.imul(...) >>> 0``. W is a deterministic execution
oracle, NOT a cryptographic PRF (see the design document, Section 7).

This module deliberately contains NO classification logic: the E1/E2/E3
predicates below are evidence predicates intended for later integration
into the confirmation state machine. Global verdict behaviour
(POTENTIAL/CONFIRMED/INCONCLUSIVE) is intentionally untouched.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import unquote, urlsplit

__all__ = [
    "ORACLE_PATH_PREFIX",
    "ORACLE_VERSION",
    "JS_W_SOURCE",
    "OraclePlan",
    "OraclePlanner",
    "PreExecutionInput",
    "anti_harvest_violations",
    "evaluate_e1_dialog",
    "evaluate_e2_network",
    "evaluate_e3_eval",
    "fnv1a32",
    "oracle_seed",
    "oracle_value_from_seed",
    "validate_oracle_pair",
]

ORACLE_VERSION = 1

# The E2 network oracle path prefix. The full oracle path is
# ``/.watch-oracle/<D>`` where D is the attempt's derived oracle value.
ORACLE_PATH_PREFIX = "/.watch-oracle/"

_FNV_OFFSET_BASIS = 0x811C9DC5
_FNV_PRIME = 0x01000193
_MASK32 = 0xFFFFFFFF


def _utf16_code_units(text: str) -> Iterable[int]:
    """Yield the UTF-16 code units of ``text``.

    JavaScript's ``String.prototype.charCodeAt`` operates on UTF-16 code
    units; encoding as UTF-16 little-endian and reading 16-bit words gives
    the identical sequence, including for non-BMP characters (which JS
    sees as surrogate pairs).
    """

    if not text:
        return
    encoded = text.encode("utf-16-le")
    yield from struct.unpack(f"<{len(encoded) // 2}H", encoded)


def fnv1a32(text: str) -> int:
    """FNV-1a 32-bit over UTF-16 code units.

    Bit-identical to the JavaScript form used by generated payloads::

        var h = 0x811c9dc5;
        for (var i = 0; i < s.length; i++) {
            h = Math.imul(h ^ s.charCodeAt(i), 16777619) >>> 0;
        }

    ``Math.imul`` performs a 32-bit wrap-around multiply and ``>>> 0``
    reinterprets the result as unsigned, which is exactly the
    ``& 0xFFFFFFFF`` here.
    """

    h = _FNV_OFFSET_BASIS
    for unit in _utf16_code_units(text):
        h = ((h ^ unit) * _FNV_PRIME) & _MASK32
    return h


def _hex8(value: int) -> str:
    """Exactly 8 lowercase hex digits (JavaScript-equivalent padding)."""

    return format(value & _MASK32, "08x")


def oracle_value_from_seed(seed: str) -> str:
    """W(S): the derived oracle value.

    h1 = fnv1a32(S)
    h2 = fnv1a32(hex8(h1) + ":" + S)
    D  = hex8(h1) + hex8(h2)

    The result is exactly 16 lowercase hex characters. The JavaScript
    runtime form (``JS_W_SOURCE``) is bit-identical; the zero padding is
    part of the definition so D is always exactly 16 characters.
    """

    h1 = fnv1a32(seed)
    h2 = fnv1a32(_hex8(h1) + ":" + seed)
    return _hex8(h1) + _hex8(h2)


def oracle_seed(run_salt: str, attempt_id: str, phase: str) -> str:
    """Trusted seed derivation.

    S = sha256(run_salt || attempt_id || phase)[:16]

    ``||`` is NUL-joined canonical concatenation so distinct field
    boundaries cannot alias (``("a","bc")`` vs ``("ab","c")``). The run
    salt MUST participate: different run salts MUST produce different
    seeds for the same attempt identity (anti-replay/run binding).

    The seed is rendered as exactly 32 lowercase hex characters.
    """

    digest = hashlib.sha256(
        f"{run_salt}\x00{attempt_id}\x00{phase}".encode("utf-8")
    ).digest()
    return digest[:16].hex()


# ----------------------------------------------------------------------
# Strict validators
# ----------------------------------------------------------------------

_HEX_DIGITS = frozenset("0123456789abcdef")


def is_valid_seed(value: object) -> bool:
    """Exactly 32 lowercase hex characters."""

    return (
        isinstance(value, str)
        and len(value) == 32
        and all(ch in _HEX_DIGITS for ch in value)
    )


def is_valid_oracle_value(value: object) -> bool:
    """Exactly 16 lowercase hex characters."""

    return (
        isinstance(value, str)
        and len(value) == 16
        and all(ch in _HEX_DIGITS for ch in value)
    )


def validate_oracle_pair(seed: str, value: str) -> None:
    """Strict pair validation; raises ``ValueError`` on any violation.

    Required properties:

    - S is exactly 32 lowercase hex chars;
    - D is exactly 16 lowercase hex chars;
    - D == W(S);
    - D != S.
    """

    if not is_valid_seed(seed):
        raise ValueError(
            f"invalid_oracle_seed:length_or_charset:{seed!r}"
        )
    if not is_valid_oracle_value(value):
        raise ValueError(
            f"invalid_oracle_value:length_or_charset:{value!r}"
        )
    expected = oracle_value_from_seed(seed)
    if value != expected:
        raise ValueError(
            "oracle_value_mismatch:"
            f"expected:{expected!r}:got:{value!r}"
        )
    if value == seed:
        raise ValueError("oracle_value_equals_seed")


# ----------------------------------------------------------------------
# JavaScript runtime form of W (used inside generated payloads)
# ----------------------------------------------------------------------

# The exact JavaScript transform embedded in oracle payloads. It MUST stay
# bit-identical to :func:`fnv1a32` / :func:`oracle_value_from_seed`:
# Math.imul for the 32-bit wrap-around multiply, >>> 0 for unsigned
# reinterpretation, and 8-digit zero padding so D is exactly 16 chars.
# Deliberately pure JS: no crypto.subtle, no secure-context dependency.
JS_W_SOURCE = r"""var s='<SEED>',a=2166136261,b=2166136261,i,t;
for(i=0;i<s.length;i++)a=Math.imul(a^s.charCodeAt(i),16777619)>>>0;
t=('00000000'+a.toString(16)).slice(-8)+':'+s;
for(i=0;i<t.length;i++)b=Math.imul(b^t.charCodeAt(i),16777619)>>>0;
var d=('00000000'+a.toString(16)).slice(-8)+('00000000'+b.toString(16)).slice(-8);"""

# Actions appended after the transform. alert() is the E1 dialog oracle;
# the same-origin image request to /.watch-oracle/<D> is the E2 network
# oracle. A 404 response is fine: the request ATTEMPT is the signal.
# Single quotes throughout: the snippet must be safe to embed inside a
# double-quoted HTML attribute.
_JS_E1_ACTION = "alert(d);"
_JS_E2_ACTION = "new Image().src='/.watch-oracle/'+d;"

_E1_ONLY_SNIPPET = JS_W_SOURCE + "\n" + _JS_E1_ACTION
_E1_E2_SNIPPET = JS_W_SOURCE + "\n" + _JS_E1_ACTION + _JS_E2_ACTION


def build_oracle_snippet(seed: str, *, network: bool = True) -> str:
    """Build the compact JS oracle snippet for ``seed``.

    The snippet contains the seed exactly once and NEVER contains the
    derived oracle value.
    """

    if not is_valid_seed(seed):
        raise ValueError(f"invalid_oracle_seed:{seed!r}")
    body = _E1_E2_SNIPPET if network else _E1_ONLY_SNIPPET
    return body.replace("<SEED>", seed)


# ----------------------------------------------------------------------
# Trusted oracle planner
# ----------------------------------------------------------------------

# Contexts the planner can host safely. Each entry maps the XSS context
# type to a canonical planner-owned delivery skeleton. ``{snippet}`` is
# substituted with the oracle snippet. Attribute-hosted contexts use
# double-quoted attributes, so the snippet's strings must stay
# single-quoted (they do).
_SUPPORTED_CONTEXTS = {
    "html_body": '<img src=x onerror="{snippet}">',
    "html_attribute": '<img src=x onerror="{snippet}">',
    "script_block": "<script>{snippet}</script>",
    "generic": "<script>{snippet}</script>",
}

_ORACLE_ATTR_CONTEXTS = frozenset({"html_body", "html_attribute"})


@dataclass
class OraclePlan:
    """Deterministic planner output for one attempt."""

    context_type: str
    supported: bool
    reason: str
    seed: str
    oracle_value: str
    snippet: str
    payload: str
    version: int
    # E3 (exact eval equality) is only possible while the full payload
    # fits inside the instrumentation's 240-char value truncation limit.
    e3_enabled: bool
    unsupported_reason: str = ""
    delivery_pattern: str = ""
    metadata: dict = field(default_factory=dict)


class OraclePlanner:
    """Trusted, deterministic oracle planner.

    The planner consumes trusted identifiers (case/attempt/pair ids,
    run salt, phase), a context type, an optional LLM delivery pattern
    (recorded for attribution ONLY — never executed, never allowed to
    control the oracle), and payload length constraints. It owns S, D,
    W, the snippet, and the composed payload.

    The LLM is untrusted: its pattern cannot alter the seed, the value,
    the snippet, or the expected oracle in any way.
    """

    E3_MAX_PAYLOAD_LENGTH = 240

    def plan(
        self,
        *,
        context_type: str,
        case_id: str,
        attempt_id: str,
        logical_pair_id: str,
        run_salt: str,
        phase: str,
        delivery_pattern: str | None = None,
        max_payload_length: int | None = None,
        network_oracle: bool = True,
    ) -> OraclePlan:
        normalized = (context_type or "").strip().lower()
        skeleton = _SUPPORTED_CONTEXTS.get(normalized)
        seed = oracle_seed(run_salt, attempt_id, phase)
        value = oracle_value_from_seed(seed)
        validate_oracle_pair(seed, value)

        if skeleton is None:
            return OraclePlan(
                context_type=normalized,
                supported=False,
                reason="unsupported_context",
                seed=seed,
                oracle_value=value,
                snippet="",
                payload="",
                version=ORACLE_VERSION,
                e3_enabled=False,
                unsupported_reason=(
                    f"context_cannot_safely_host_oracle:{normalized!r}"
                ),
                delivery_pattern=delivery_pattern or "",
            )

        snippet = build_oracle_snippet(
            seed, network=network_oracle
        )
        payload = skeleton.replace("{snippet}", snippet)

        # Attribute-hosted skeletons wrap the snippet in double quotes;
        # the snippet must not contain a double quote there. (It does
        # not: snippet strings are single-quoted.)
        if normalized in _ORACLE_ATTR_CONTEXTS and '"' in snippet:
            return OraclePlan(
                context_type=normalized,
                supported=False,
                reason="snippet_unsafe_for_attribute_context",
                seed=seed,
                oracle_value=value,
                snippet=snippet,
                payload="",
                version=ORACLE_VERSION,
                e3_enabled=False,
                unsupported_reason="double_quote_in_snippet",
                delivery_pattern=delivery_pattern or "",
            )

        limit = (
            self.E3_MAX_PAYLOAD_LENGTH
            if max_payload_length is None
            else max_payload_length
        )
        e3_enabled = len(payload) <= limit

        # Planner-side anti-harvest self-check: the payload contains the
        # seed exactly once and never the derived value.
        if payload.count(seed) != 1:
            raise ValueError(
                "oracle_seed_count_violation:"
                f"count:{payload.count(seed)}"
            )
        if value in payload:
            raise ValueError("oracle_value_on_wire_violation:payload")

        return OraclePlan(
            context_type=normalized,
            supported=True,
            reason="ok",
            seed=seed,
            oracle_value=value,
            snippet=snippet,
            payload=payload,
            version=ORACLE_VERSION,
            e3_enabled=e3_enabled,
            delivery_pattern=delivery_pattern or "",
            metadata={
                "case_id": case_id,
                "attempt_id": attempt_id,
                "logical_pair_id": logical_pair_id,
                "phase": phase,
                "network_oracle": network_oracle,
            },
        )


# ----------------------------------------------------------------------
# Evidence predicates (E1 / E2 / E3)
# ----------------------------------------------------------------------
#
# These are ISOLATED evidence predicates. They are intentionally NOT wired
# into XSSVerifier._classify: global verdict semantics
# (POTENTIAL/CONFIRMED/INCONCLUSIVE) must not change in this task. The
# integration point for the next task is documented in
# xss-oracle-implementation-report.md.

_E1_DIALOG_KINDS = frozenset({"alert", "confirm", "prompt"})


def evaluate_e1_dialog(dialog_events, expected_value: str) -> bool:
    """E1: a dialog whose message equals D exactly.

    Exact full-string equality only. These must all FAIL:
    D+suffix, D+prefix, whitespace-padded D, a longer message containing
    D as a substring, wrong case, and the seed S.
    """

    if not is_valid_oracle_value(expected_value):
        return False
    for event in dialog_events or []:
        kind = getattr(event, "kind", "")
        message = getattr(event, "message", "")
        if kind in _E1_DIALOG_KINDS and message == expected_value:
            return True
    return False


def _origin(url: str) -> tuple[str, str, str] | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host:
        return None
    port = parts.port
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return parts.scheme.lower(), host, str(port)


def evaluate_e2_network(
    oracle_events, expected_value: str, endpoint: str
) -> bool:
    """E2: a page-initiated, non-navigation, same-origin request whose
    pathname is exactly ``/.watch-oracle/<D>``.

    Matching rules (all mandatory):
    - the pathname is percent-decoded ONCE, then compared exactly;
    - the path is the prefix plus D and nothing else (no suffix, no
      prefix extensions, no second segment);
    - the query string NEVER participates in matching;
    - navigation requests and cross-origin requests never match;
    - D must be the attempt's derived oracle value.
    """

    if not is_valid_oracle_value(expected_value):
        return False
    expected_path = ORACLE_PATH_PREFIX + expected_value
    target_origin = _origin(endpoint)
    if target_origin is None:
        return False
    for event in oracle_events or []:
        if getattr(event, "is_navigation", False):
            continue
        url = getattr(event, "url", "")
        actual_origin = _origin(url)
        if actual_origin is None or actual_origin != target_origin:
            continue
        path = unquote(urlsplit(url).path or "")
        if path != expected_path:
            continue
        # Single path segment: D is lowercase hex, so it can never
        # contain '/', but the check is kept as defence in depth.
        remainder = path[len(ORACLE_PATH_PREFIX):]
        if "/" in remainder:
            continue
        return True
    return False


def evaluate_e3_eval(
    eval_invocations, payload: str
) -> bool | None:
    """E3: an eval-family invocation whose recorded value equals P exactly.

    Returns ``False`` (disabled) when ``len(payload) > 240``: the
    instrumentation truncates recorded values at 240 chars, so exact
    equality is impossible and MUST NOT be approximated by prefix
    comparison. ``new Function`` is unsupported in v1 (no hook exists).
    """

    if len(payload) > 240:
        return False
    valid_ops = frozenset({"eval", "setTimeout:string"})
    for event in eval_invocations or []:
        operator = getattr(event, "operator", "")
        value = getattr(event, "value", "")
        if operator in valid_ops and value == payload:
            return True
    return False


# ----------------------------------------------------------------------
# Anti-harvest validation
# ----------------------------------------------------------------------
#
# EVIDENCE BOUNDARY (explicit, structural):
#
#   PRE-EXECUTION / ATTACK-CONTROLLED MATERIAL
#       payload, bound input, intended/actual request URL, request
#       body, response snippet, referrer-derived strings, and any
#       other input captured BEFORE execution.
#       => D MUST NOT occur. Enforced by anti_harvest_violations.
#
#   POST-EXECUTION / EXECUTOR-OWNED ORACLE EVIDENCE
#       DialogEvent.message (E1) and NetworkOracleEvent.path (E2),
#       produced by executor-owned transport after the payload ran.
#       => D IS EXPECTED there. Validated ONLY by evaluate_e1_dialog /
#          evaluate_e2_network, never by anti-harvest.
#
# The two classes are structurally separated: the anti-harvest scanner
# accepts ONLY a PreExecutionInput, which has no field that can carry
# oracle event objects. A caller cannot accidentally feed E1/E2 oracle
# evidence into the scanner; it must consciously extract pre-execution
# strings instead.


@dataclass(frozen=True)
class PreExecutionInput:
    """Pre-execution observable material for anti-harvest validation.

    This is the ONLY evidence shape accepted by
    :func:`anti_harvest_violations`. It bundles attacker-controlled /
    pre-execution observables only: the payload, the bound input,
    intended/actual request URLs, the request body, response snippets,
    referrer-derived strings, and any other inputs captured before
    execution.

    Structural invariant: D (the derived oracle value) MUST NOT occur
    in any field. Post-execution executor-owned oracle evidence
    (``DialogEvent.message``, ``NetworkOracleEvent.path``) has NO
    representation in this type, so it CANNOT be passed to the
    anti-harvest scanner. That evidence is validated independently by
    the E1/E2 predicates, where D is the expected signal.
    """

    payload: str
    bound_input: str = ""
    intended_request_url: str = ""
    actual_request_url: str = ""
    request_body: str = ""
    response_snippet: str = ""
    referrer_derived: str = ""
    pre_execution_inputs: tuple[str, ...] = ()


def anti_harvest_violations(
    seed: str,
    oracle_value: str,
    pre: PreExecutionInput,
) -> list[str]:
    """Independently validate the anti-harvest invariant over
    PRE-EXECUTION material only.

    D (the derived oracle value) MUST NOT occur in ANY pre-execution
    observable bundled in ``pre``: the generated payload, the bound
    input, the intended or actual request URL, the request body,
    response body snippets, referrer-derived recorded strings, or any
    other known pre-execution input. S MAY occur in these locations.

    Additionally, the payload must contain the seed exactly once.

    This function deliberately re-derives everything from raw strings;
    it never trusts planner metadata. Post-execution executor-owned
    oracle evidence (dialog messages, oracle network requests) is NOT
    accepted here — it has no representation in
    :class:`PreExecutionInput` and is validated exclusively by
    :func:`evaluate_e1_dialog` / :func:`evaluate_e2_network`, where D
    is the expected signal.

    Returns a list of violation codes (empty = invariant holds).
    """

    if not isinstance(pre, PreExecutionInput):
        raise TypeError(
            "anti_harvest_violations accepts only PreExecutionInput "
            "(pre-execution material); post-execution executor-owned "
            "oracle evidence (DialogEvent / NetworkOracleEvent) must "
            "be validated by evaluate_e1_dialog / evaluate_e2_network, "
            f"not scanned here (got {type(pre).__name__})"
        )

    violations: list[str] = []
    if not is_valid_seed(seed):
        violations.append("invalid_seed")
    if not is_valid_oracle_value(oracle_value):
        violations.append("invalid_oracle_value")

    occurrences = pre.payload.count(seed) if seed else 0
    if occurrences != 1:
        violations.append(f"seed_count_in_payload:{occurrences}")

    on_wire = {
        "payload": pre.payload,
        "bound_input": pre.bound_input,
        "intended_request_url": pre.intended_request_url,
        "actual_request_url": pre.actual_request_url,
        "request_body": pre.request_body,
        "response_snippet": pre.response_snippet,
        "referrer_derived": pre.referrer_derived,
    }
    for index, extra in enumerate(pre.pre_execution_inputs or ()):
        on_wire[f"pre_execution_input:{index}"] = extra or ""

    if oracle_value:
        for name, text in on_wire.items():
            if text and oracle_value in text:
                violations.append(f"oracle_value_on_wire:{name}")

    return violations
