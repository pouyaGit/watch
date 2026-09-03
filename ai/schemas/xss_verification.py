from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ai.schemas.xss_finding import XSSFinding


class VerificationMode(str, Enum):
    """
    How an attempt's evidence was collected.

    - ``http_reflection``: the executor fetched the target
      with the injected payload and recorded the response.
    - ``browser_execution``: a browser-equivalent runtime
      loaded the response and reported observable
      JavaScript / DOM / network activity.
    """

    HTTP_REFLECTION = "http_reflection"
    BROWSER_EXECUTION = "browser_execution"


class AttemptStatus(str, Enum):
    """
    The transport-level outcome of a verification attempt.
    Distinct from the XSSFinding.status, which is the
    *interpreted* security verdict.
    """

    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    WAF_BLOCKED = "waf_blocked"
    WAF_TRANSFORMED = "waf_transformed"
    ERROR = "error"


class ReflectionLocation(str, Enum):
    """
    Where the payload was observed in the response.
    """

    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT_STRING = "javascript_string"
    SCRIPT_BLOCK = "script_block"
    URL = "url"
    NONE = "none"


class WAFObservationKind(str, Enum):
    """
    How a WAF observation should be interpreted by the
    verifier. Only ``BLOCK`` and ``TRANSFORM`` force an
    INCONCLUSIVE verdict; ``INFO`` is metadata only.
    """

    INFO = "info"
    BLOCK = "block"
    TRANSFORM = "transform"


class WAFObservation(BaseModel):
    """
    Structured WAF observation reported by the executor.

    A free-form string is no longer accepted: the executor
    must classify the observation as informational,
    blocking, or transforming. The verifier only treats
    BLOCK and TRANSFORM as proof that the payload may not
    have reached the server unmodified.
    """

    kind: WAFObservationKind
    note: str = ""


class StoredXSSPhase(str, Enum):
    """
    The phase of a stored-XSS verification round trip.

    A complete stored-XSS confirmation requires evidence
    from both ``SUBMIT`` and ``READ`` phases with matching
    correlation tokens. A single phase produces at most a
    POTENTIAL finding.
    """

    SUBMIT = "submit"
    READ = "read"


class StoredXSSPhaseObservation(BaseModel):
    """
    One phase observation in a stored-XSS round trip.

    The executor reports the phase, the deterministic
    attempt_id of the phase, and the correlation token it
    observed at that phase. The verifier correlates
    SUBMIT/READ pairs by attempt_id and confirms they
    share a correlation token.
    """

    phase: StoredXSSPhase
    attempt_id: str
    observed_correlation_token: str | None = None


def _canonical_json(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256_hex(text: str, *, length: int = 64) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[
        :length
    ]


def attempt_id_from_canonical(canonical: dict) -> str:
    """
    Deterministic SHA-256-based attempt identifier derived
    from the canonical attempt fields. Used as the primary
    key for both the attempt and the correlation token.

    Note: the correlation token is intentionally NOT a
    security boundary by itself. The token is what the
    executor writes into the request/response/runtime and
    the verifier independently checks that the executor
    actually observed the token. The token's secrecy is
    not relied upon.
    """

    return "va-" + _sha256_hex(_canonical_json(canonical))


def logical_pair_id_from_canonical(canonical: dict) -> str:
    """
    Deterministic SHA-256-based logical-pair identifier
    shared by every attempt that targets the same payload,
    case, endpoint, parameter, and attribution.

    The canonical excludes ``mode`` and ``phase`` so an
    HTTP attempt and a browser attempt issued for the same
    payload share the same ``logical_pair_id``. It also
    excludes any free-form LLM fields; the inputs are
    the case- and payload-side identifiers only.

    The verifier uses this id to pair HTTP and browser
    attempts for reflected/mutation CONFIRMED. DOM XSS
    pairs do not apply (browser-only).
    """

    return "lp-" + _sha256_hex(_canonical_json(canonical))


def correlation_token_from_attempt(
    attempt_id: str,
    *,
    phase: str = "primary",
) -> str:
    """
    Deterministic correlation token derived from
    ``attempt_id`` and a phase label.

    The phase label exists so the executor can distinguish
    multiple correlation channels (e.g. submit/read for
    stored XSS) but the verifier does not treat the phase
    itself as a security boundary. The verifier correlates
    evidence to attempts by ``attempt_id`` first, then by
    token value. The phase label is metadata only.
    """

    return "ct-" + _sha256_hex(
        f"{attempt_id}|{phase}", length=32
    )


class ReflectionObservation(BaseModel):
    """
    HTTP-side observation.

    ``reflected`` indicates the payload (or its
    correlation token) was found in the response body.
    ``matched_correlation_token`` is the executor's
    advisory flag; the verifier does NOT trust it on its
    own. The verifier independently compares
    ``observed_correlation_token`` against the
    ``attempt.correlation_token``. The boolean remains
    for executor reporting.
    """

    reflected: bool
    location: ReflectionLocation
    context_before: str | None = None
    context_after: str | None = None
    matched_correlation_token: bool = False
    # Structured value the executor claims to have seen
    # in the response body. The verifier compares this to
    # the attempt's correlation token and does NOT trust
    # the boolean alone. None means the executor did not
    # record a specific token value.
    observed_correlation_token: str | None = None
    truncated: bool = False


class SourceToSinkStep(BaseModel):
    """
    One typed step in a DOM-XSS source-to-sink chain.

    ``kind`` is constrained so the verifier can mechanically
    walk the chain from parameter to observable. A free-form
    string is not accepted: if an executor cannot characterize
    a step with one of these labels, the chain is incomplete
    and the finding is INCONCLUSIVE.

    For a step of ``kind == "parameter"``, the executor must
    additionally supply:

    - ``parameter_name`` matching ``attempt.parameter``,
    - ``parameter_location`` matching ``attempt.parameter_location``,
    - ``endpoint`` matching ``attempt.endpoint``.

    The verifier enforces these three identifier bindings
    mechanically. A chain whose parameter step does not name
    the exact parameter, location, and endpoint of the
    attempt under verification cannot yield CONFIRMED.

    The static helper :meth:`is_well_formed_chain` is the
    single source of truth for the chain's structural
    rule. The Pydantic model validator on
    :class:`BrowserExecutionObservation` and the verifier's
    :meth:`XSSVerifier._chain_attempt_bound` both delegate
    to it, so the rule cannot drift between construction
    and classification.
    """

    kind: Literal[
        "parameter",
        "attacker_value",
        "intermediate",
        "sink",
        "observable",
    ]
    description: str
    location: str | None = None
    parameter_name: str | None = None
    parameter_location: str | None = None
    endpoint: str | None = None

    @model_validator(mode="after")
    def _parameter_step_has_binding(self) -> "SourceToSinkStep":
        if self.kind != "parameter":
            return self
        missing = [
            name
            for name, value in (
                ("parameter_name", self.parameter_name),
                (
                    "parameter_location",
                    self.parameter_location,
                ),
                ("endpoint", self.endpoint),
            )
            if value is None or value == ""
        ]
        if missing:
            raise ValueError(
                "parameter step requires non-empty "
                f"{', '.join(missing)}"
            )
        return self

    @staticmethod
    def is_well_formed_chain(
        chain: list["SourceToSinkStep"],
    ) -> bool:
        """
        The single source of truth for source-to-sink
        chain structural validity. A chain is well-formed
        when:

        - it is non-empty,
        - the first step has ``kind == "parameter"``,
        - the last step has ``kind == "observable"``,
        - at least one step has ``kind == "sink"``.

        This is the same rule the Pydantic model
        validator on :class:`BrowserExecutionObservation`
        enforces. The verifier calls it as a
        defence-in-depth re-check during classification.
        """

        if not chain:
            return False
        kinds = [step.kind for step in chain]
        if "parameter" not in kinds:
            return False
        if "sink" not in kinds:
            return False
        if "observable" not in kinds:
            return False
        if kinds[0] != "parameter":
            return False
        if kinds[-1] != "observable":
            return False
        return True


class BrowserExecutionObservation(BaseModel):
    """
    Browser-side observation.

    The booleans ``executed_script`` and
    ``correlation_token_in_runtime`` are executor-advisory
    metadata. The verifier does NOT trust them on their
    own. CONFIRMED requires that at least one structured
    runtime channel (``dom_changes``, ``console_messages``,
    ``network_requests``, ``storage_writes``) actually
    contains the attempt's correlation token string.

    For DOM XSS, ``source_to_sink`` must be a non-empty
    chain of typed steps that starts with ``parameter``,
    includes ``sink``, and ends with ``observable``.
    The parameter step must bind to the attempt's
    parameter, location, and endpoint.
    """

    executed_script: bool = False
    dom_changes: list[str] = Field(default_factory=list)
    console_messages: list[str] = Field(default_factory=list)
    network_requests: list[str] = Field(default_factory=list)
    storage_writes: list[str] = Field(default_factory=list)
    # Advisory booleans. Not authoritative.
    correlation_token_in_runtime: bool = False
    # Structured value the executor claims to have seen in
    # a runtime channel. The verifier independently
    # confirms the token string is present in at least one
    # of the structured channels above.
    observed_correlation_token: str | None = None
    source_to_sink: list[SourceToSinkStep] = Field(
        default_factory=list
    )

    @model_validator(mode="after")
    def _chain_well_formed(self) -> "BrowserExecutionObservation":
        if not self.source_to_sink:
            return self
        kinds = [step.kind for step in self.source_to_sink]
        if not SourceToSinkStep.is_well_formed_chain(
            self.source_to_sink
        ):
            if "parameter" not in kinds:
                raise ValueError(
                    "source_to_sink must start with a 'parameter' step"
                )
            if "sink" not in kinds:
                raise ValueError(
                    "source_to_sink must include a 'sink' step"
                )
            if "observable" not in kinds:
                raise ValueError(
                    "source_to_sink must end with an 'observable' step"
                )
            if kinds[0] != "parameter":
                raise ValueError(
                    "source_to_sink must start with a 'parameter' step"
                )
            raise ValueError(
                "source_to_sink must end with an 'observable' step"
            )
        return self


class VerificationAttempt(BaseModel):
    """
    One planned test. The verifier builds attempts from the
    orchestrator's LLM output. Each attempt carries the
    attribution fields the verifier must preserve, plus a
    deterministic ``attempt_id`` and ``correlation_token``.

    ``logical_pair_id`` is a deterministic identifier
    shared by every attempt that targets the same
    payload/case/endpoint/parameter/attribution tuple.
    HTTP and browser attempts for the same logical pair
    share this id; their ``attempt_id`` and
    ``correlation_token`` values remain distinct (they
    are derived from the same canonical plus ``mode`` and
    ``phase``). The verifier uses ``logical_pair_id`` to
    pair HTTP and browser evidence for reflected/mutation
    CONFIRMED. DOM XSS pairs do not apply.
    """

    attempt_id: str
    logical_pair_id: str
    case_id: str
    endpoint: str
    method: str
    parameter: str | None
    parameter_location: str
    payload: str
    payload_origin: Literal["knowledge", "model_generated"]
    knowledge_ids: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    based_on_pattern: str | None = None
    mode: VerificationMode
    correlation_token: str
    # Phase is metadata only. The verifier correlates
    # evidence to attempts via attempt_id and the
    # observed correlation token, NOT via phase.
    phase: str = "primary"

    # Deterministic pre-oracle candidate identity the oracle seed was
    # minted against (the paired plain-browser attempt's ``attempt_id``).
    # Required because the oracle attempt's own ``attempt_id`` includes
    # the seed-bearing payload, which would make seed derivation
    # circular. The verifier re-derives run freshness from
    # ``oracle_seed(run_salt, oracle_identity, phase)`` and rejects any
    # attempt whose ``oracle_identity`` does not map to the same
    # ``logical_pair_id`` candidate. Only oracle attempts carry it;
    # ``None`` keeps every existing attempt unchanged.
    oracle_identity: str | None = None

    @field_validator(
        "attempt_id", "logical_pair_id", "correlation_token"
    )
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError(
                "must be a non-empty string"
            )
        return value

    @field_validator("endpoint", "payload")
    @classmethod
    def _endpoint_or_payload_non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError(
                "must be a non-empty string"
            )
        return value


def _build_attempt_id(
    *,
    case_id: str,
    endpoint: str,
    method: str,
    parameter: str | None,
    parameter_location: str,
    payload: str,
    payload_origin: str,
    knowledge_ids: list[str],
    source_ids: list[str],
    based_on_pattern: str | None,
    mode: VerificationMode,
    phase: str,
) -> str:
    canonical = {
        "based_on_pattern": based_on_pattern,
        "case_id": case_id,
        "endpoint": endpoint,
        "knowledge_ids": sorted(knowledge_ids),
        "method": method,
        "mode": mode.value,
        "parameter": parameter,
        "parameter_location": parameter_location,
        "payload": payload,
        "payload_origin": payload_origin,
        "phase": phase,
        "source_ids": sorted(source_ids),
    }
    return attempt_id_from_canonical(canonical)


def _build_logical_pair_id(
    *,
    case_id: str,
    endpoint: str,
    method: str,
    parameter: str | None,
    parameter_location: str,
    payload: str,
    payload_origin: str,
    knowledge_ids: list[str],
    source_ids: list[str],
    based_on_pattern: str | None,
) -> str:
    # The logical-pair canonical deliberately excludes
    # ``mode`` and ``phase``. HTTP and browser attempts
    # for the same logical verification share this id.
    # ``method`` IS included: a GET attempt and a POST
    # attempt against the same endpoint+parameter+payload
    # are not the same logical verification (different
    # request shape, different reflection surface,
    # different runtime path) and must not be paired.
    canonical = {
        "based_on_pattern": based_on_pattern,
        "case_id": case_id,
        "endpoint": endpoint,
        "knowledge_ids": sorted(knowledge_ids),
        "method": method,
        "parameter": parameter,
        "parameter_location": parameter_location,
        "payload": payload,
        "payload_origin": payload_origin,
        "source_ids": sorted(source_ids),
    }
    return logical_pair_id_from_canonical(canonical)


def build_verification_attempt(
    *,
    case_id: str,
    endpoint: str,
    method: str,
    parameter: str | None,
    parameter_location: str,
    payload: str,
    payload_origin: Literal["knowledge", "model_generated"],
    knowledge_ids: list[str],
    source_ids: list[str],
    based_on_pattern: str | None,
    mode: VerificationMode,
    phase: str = "primary",
) -> "VerificationAttempt":
    """
    Factory that computes ``attempt_id``,
    ``logical_pair_id``, and ``correlation_token``
    deterministically from the canonical attempt fields.

    ``logical_pair_id`` is independent of ``mode`` and
    ``phase`` so HTTP and browser attempts for the same
    payload share it. ``logical_pair_id`` does include
    ``method`` because the same payload over different
    HTTP methods is not the same logical verification.
    ``attempt_id`` includes ``mode`` and ``phase`` so
    the two attempts remain distinct.
    """

    attempt_id = _build_attempt_id(
        case_id=case_id,
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        parameter_location=parameter_location,
        payload=payload,
        payload_origin=payload_origin,
        knowledge_ids=list(knowledge_ids),
        source_ids=list(source_ids),
        based_on_pattern=based_on_pattern,
        mode=mode,
        phase=phase,
    )
    logical_pair_id = _build_logical_pair_id(
        case_id=case_id,
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        parameter_location=parameter_location,
        payload=payload,
        payload_origin=payload_origin,
        knowledge_ids=list(knowledge_ids),
        source_ids=list(source_ids),
        based_on_pattern=based_on_pattern,
    )
    correlation_token = correlation_token_from_attempt(
        attempt_id, phase=phase
    )
    return VerificationAttempt(
        attempt_id=attempt_id,
        logical_pair_id=logical_pair_id,
        case_id=case_id,
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        parameter_location=parameter_location,
        payload=payload,
        payload_origin=payload_origin,
        knowledge_ids=list(knowledge_ids),
        source_ids=list(source_ids),
        based_on_pattern=based_on_pattern,
        mode=mode,
        correlation_token=correlation_token,
        phase=phase,
    )


class VerificationEvidence(BaseModel):
    """
    What the executor actually observed. ``attempt_id``
    links the evidence to the attempt that produced it.
    Headers are stored redacted: ``Cookie`` and
    ``Authorization`` must be redacted by the executor
    before this schema is constructed.

    The verifier treats this schema as untrusted input and
    performs independent binding checks. The booleans
    ``matched_correlation_token`` (HTTP) and
    ``correlation_token_in_runtime`` (browser) are
    advisory; the verifier independently matches
    ``observed_correlation_token`` against the attempt's
    correlation token.

    Stored XSS verification additionally requires
    ``stored_phases`` to contain a complete SUBMIT/READ
    pair with matching observed correlation tokens.
    """

    attempt_id: str
    attempt_status: AttemptStatus
    request_url: str
    request_method: str
    request_headers_redacted: dict[str, str] = Field(
        default_factory=dict
    )
    response_status: int | None = None
    response_headers_redacted: dict[str, str] = Field(
        default_factory=dict
    )
    response_body_truncated: str | None = None
    reflection: ReflectionObservation = Field(
        default_factory=lambda: ReflectionObservation(
            reflected=False, location=ReflectionLocation.NONE
        )
    )
    browser: BrowserExecutionObservation | None = None
    waf_observations: list[WAFObservation] = Field(
        default_factory=list
    )
    # Per-phase observations for stored XSS. For
    # non-stored XSS, this stays empty. A complete
    # stored-XSS confirmation requires both SUBMIT and
    # READ entries referring to the same attempt_id and
    # sharing an observed correlation token that matches
    # the verification attempt's correlation_token.
    stored_phases: list[StoredXSSPhaseObservation] = Field(
        default_factory=list
    )
    started_at: str = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )
    finished_at: str = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )
    error_reason: str | None = None
    # The LLM's own hint for the executor. The verifier
    # MUST NOT use this for verdict decisions.
    expected_behavior: str | None = None
    # Negative-control evidence. The current schema is
    # intentionally minimal. The verifier does NOT issue
    # NOT_VULNERABLE on the strength of this field.
    # NOT_VULNERABLE is not produced by the current
    # verifier; it would require a structured
    # two-control evidence extension that the current
    # code does not implement. Today this is metadata
    # only.
    control_request_unchanged: bool | None = None
    control_response_status: int | None = None


class VerificationPlan(BaseModel):
    attempts: list[VerificationAttempt] = Field(
        default_factory=list
    )


class XSSVerificationAudit(BaseModel):
    attempt_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    timeout_count: int = 0
    waf_blocked_count: int = 0
    waf_transformed_count: int = 0
    error_count: int = 0
    has_browser_execution_evidence: bool = False
    has_reflection_evidence: bool = False
    notes: list[str] = Field(default_factory=list)


class XSSVerificationResult(BaseModel):
    case_id: str
    attempts: list[VerificationAttempt]
    evidence: list[VerificationEvidence]
    findings: list[XSSFinding]
    audit: XSSVerificationAudit


__all__ = [
    "AttemptStatus",
    "BrowserExecutionObservation",
    "ReflectionLocation",
    "ReflectionObservation",
    "SourceToSinkStep",
    "StoredXSSPhase",
    "StoredXSSPhaseObservation",
    "VerificationAttempt",
    "VerificationEvidence",
    "VerificationMode",
    "VerificationPlan",
    "WAFObservation",
    "WAFObservationKind",
    "XSSVerificationAudit",
    "XSSVerificationResult",
    "attempt_id_from_canonical",
    "build_verification_attempt",
    "correlation_token_from_attempt",
    "logical_pair_id_from_canonical",
]
