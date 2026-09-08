"""5I classification state machine (Phase 5I).

Minimum outcomes (architecture §5): CONFIRMED*, POTENTIAL,
UNKNOWN/INCONCLUSIVE*, NOT_VULNERABLE*. In THIS build:

- ``CONFIRMED`` requires the complete ordered gate list of an
  execution-proof path (sealed oracle E1/E2/E3, or the full stored
  round) with zero skips.
- ``POTENTIAL`` is the ceiling for reflection-only / advisory-only /
  storage-attributed evidence and never self-promotes.
- ``UNKNOWN`` is the safe default: every single predicate failure,
  gate rejection, unsupported schema, or ambiguous observation maps
  here. Gate failures never enter classification at all.
- ``NOT_VULNERABLE`` is UNREACHABLE: no two-control negative-evidence
  schema exists, none is invented here, and any transition attempt
  raises ``VerifierInvariantError`` (implementation invariant).

LLM independence: no LLM-derived field exists on any input type; the
classifier cannot read LLM text even if upstream stages carry it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.schemas import evidence as ev
from ai.schemas.execution_authorization import IssuedExecutionAuthorization

from ai.verification.deterministic import http as http_rule
from ai.verification.deterministic import nuclei as nuclei_rule
from ai.verification.deterministic import xss_oracle, xss_stored
from ai.verification.deterministic.models import (
    OUTCOME_CONFIRMED,
    OUTCOME_NOT_VULNERABLE,
    OUTCOME_POTENTIAL,
    OUTCOME_UNKNOWN,
    POLICY_VERSION,
    VerifierInvariantError,
)
from ai.verification.deterministic.registry import (
    ARTIFACT_SCHEMA_VERSION,
    OBSERVATION_SCHEMA_VERSION,
    RuleSpec,
    resolve_rule,
    rule_display_id,
)
from ai.verification.deterministic.result import (
    ClassificationResult,
    compute_result_hash,
)
from ai.verification.deterministic.severity import resolve_severity

__all__ = [
    "ClassificationResult",
    "classify_evidence",
    "not_vulnerable_transition",
    "route_rule_id",
]


def not_vulnerable_transition(*_args: object) -> ClassificationResult:
    """The NOT_VULNERABLE transition — UNREACHABLE by construction.

    There is no valid two-control negative-evidence schema in this
    build and none may be invented. Reaching this function is an
    implementation invariant violation, never a security result.
    """
    raise VerifierInvariantError(
        "NOT_VULNERABLE transition targeted without the future "
        "two-control negative-evidence schema (implementation invariant)"
    )


def route_rule_id(record: ev.EvidenceRecord) -> str:
    """Deterministic rule routing over sealed class/stage/derivation."""
    cls = record.execution_class
    if cls in ("http_probe", "http_verification"):
        return "http-meaningful-reflection"
    if cls == "nuclei_scan":
        return "nuclei-advisory"
    # browser_verification:
    stage = record.execution_stage
    phase = (
        record.derivation_binding.execution_phase
        if record.derivation_binding is not None
        else None
    )
    if stage == "read" or phase == "stored_read":
        return "xss-stored-round"
    if stage == "oracle" or phase == "oracle":
        return "xss-reflected-oracle"
    if phase in ("stored_submit", "stored_read"):
        return "xss-stored-round"
    return "xss-stored-legacy"


def _vulnerability_class(record: ev.EvidenceRecord) -> str:
    """Sealed-bound class derivation (never a caller claim)."""
    cls = record.execution_class
    if cls in ("http_probe", "http_verification"):
        return "reflected_xss"
    if cls == "nuclei_scan":
        return "nuclei_advisory"
    phase = (
        record.derivation_binding.execution_phase
        if record.derivation_binding is not None
        else None
    )
    if phase == "stored_read" or record.execution_stage == "read":
        return "stored_xss"
    return "reflected_xss"


@dataclass(frozen=True)
class _Decision:
    """Internal deterministic decision (never a public authority type)."""

    outcome: str
    detail: str
    state: str | None
    channels: tuple[str, ...]
    reason: str


def _unknown(reason: str) -> _Decision:
    return _Decision(OUTCOME_UNKNOWN, "insufficient_evidence", None, (), reason)


def _decide_reflected_oracle(
    record: ev.EvidenceRecord, authorization: object | None
) -> _Decision:
    """Reflected XSS: the ONLY route to CONFIRMED is sealed E1/E2/E3."""
    try:
        identity = xss_oracle.derive_oracle_identity(record)
    except ValueError:
        return _unknown("oracle_identity_invalid")
    if not xss_oracle.contract_hash_matches(record, authorization):
        return _unknown("derivation_contract_mismatch")
    target = record.target
    endpoint_origin = (target.scheme, target.host, str(target.effective_port))
    browser = record.browser
    if browser is None:
        return _unknown("browser_observation_missing")
    if xss_oracle.sealed_anti_harvest_violations(identity, record):
        return _unknown("anti_harvest_violation")
    channels: list[str] = []
    if xss_oracle.evaluate_sealed_e1(browser, identity.value):
        channels.append("E1")
    if xss_oracle.evaluate_sealed_e2(
        browser, identity.value, endpoint_origin=endpoint_origin
    ):
        channels.append("E2")
    if xss_oracle.evaluate_sealed_e3(
        browser, identity, authorization, execution_id=record.execution_id
    ):
        channels.append("E3")
    if not channels:
        # Advisory booleans may say "observed" while exact proof fails;
        # that is inconclusive, never a downgrade-as-proof.
        return _unknown("oracle_execution_proof_absent")
    state = (
        "OBSERVABLE_EFFECT" if "E2" in channels else "JAVASCRIPT_EXECUTION"
    )
    return _Decision(
        OUTCOME_CONFIRMED,
        "oracle_execution_proof",
        state,
        tuple(sorted(channels)),
        "sealed_oracle_execution_proof",
    )


def _decide_stored(
    record: ev.EvidenceRecord,
    authorization: object | None,
    seam: object,
) -> _Decision:
    """Stored XSS: SUBMIT -> READ -> EXECUTION with no shortcut."""
    stage = record.execution_stage
    if stage != "read":
        # Legacy single-pass stored shape: POTENTIAL ceiling only.
        browser = record.browser
        if browser is not None and (
            browser.e1_observed or browser.e2_observed or browser.e3_observed
        ):
            return _Decision(
                OUTCOME_POTENTIAL,
                "storage_attributed",
                "STORAGE_ATTRIBUTED",
                (),
                "legacy_single_pass_stored_ceiling",
            )
        return _unknown("legacy_single_pass_stored_unattributed")
    try:
        round_outcome = xss_stored.verify_stored_round(
            record, seam=seam, read_authorization=authorization
        )
    except xss_stored.IncompleteEvidence:
        return _unknown("submit_leg_unreadable")
    if round_outcome.confirmed:
        return _Decision(
            OUTCOME_CONFIRMED,
            "stored_round_execution_proof",
            round_outcome.state,
            round_outcome.channels,
            round_outcome.reason,
        )
    if round_outcome.storage_attributed:
        return _Decision(
            OUTCOME_POTENTIAL,
            "storage_attributed",
            "STORAGE_ATTRIBUTED",
            (),
            round_outcome.reason,
        )
    return _unknown(round_outcome.reason)


def _decide_http(
    record: ev.EvidenceRecord, authorization: object | None
) -> _Decision:
    """HTTP: meaningful reflection + exact marker => POTENTIAL ceiling."""
    identity: xss_oracle.OracleIdentity | None
    try:
        identity = xss_oracle.derive_oracle_identity(record)
    except ValueError:
        identity = None
    proof = http_rule.verify_http_observation(
        record, authorization=authorization, identity=identity
    )
    if proof.positive:
        return _Decision(
            OUTCOME_POTENTIAL,
            "meaningful_http_reflection",
            "REFLECTION",
            (),
            proof.reason,
        )
    return _unknown(proof.reason)


def _decide_nuclei(record: ev.EvidenceRecord) -> _Decision:
    """Nuclei: advisory gating only; CONFIRMED is unreachable here."""
    advisory = nuclei_rule.verify_nuclei_observation(record)
    if advisory.advisory_match:
        return _Decision(
            OUTCOME_POTENTIAL,
            "nuclei_advisory_weak",
            None,
            (),
            advisory.reason,
        )
    return _unknown(advisory.reason)


def classify_evidence(
    record: ev.EvidenceRecord,
    *,
    authorization: IssuedExecutionAuthorization | None,
    seam: object,
    policy_version: str = POLICY_VERSION,
) -> ClassificationResult:
    """Classify one gate-verified sealed record (pure, deterministic).

    The caller MUST have passed the integrity/provenance gate first;
    this function never re-opens it and never executes anything.
    """
    rule_id = route_rule_id(record)
    spec = resolve_rule(
        rule_id,
        execution_class=record.execution_class,
        observation_schema_version=record.evidence_schema_version,
        artifact_schema_version=ARTIFACT_SCHEMA_VERSION,
        policy_version=policy_version,
    )
    if spec is None:
        decision = _unknown("rule_or_schema_unresolved")
        display_rule = rule_id
    else:
        display_rule = rule_display_id(spec)
        if rule_id == "xss-reflected-oracle":
            decision = _decide_reflected_oracle(record, authorization)
        elif rule_id == "xss-stored-round":
            decision = _decide_stored(record, authorization, seam)
        elif rule_id == "xss-stored-legacy":
            decision = _decide_stored(record, authorization, seam)
        elif rule_id == "http-meaningful-reflection":
            decision = _decide_http(record, authorization)
        elif rule_id == "nuclei-advisory":
            decision = _decide_nuclei(record)
        else:  # pragma: no cover - registry is closed
            decision = _unknown("rule_unmapped")

    if decision.outcome == OUTCOME_NOT_VULNERABLE:  # pragma: no cover
        # Defensive: no rule may produce it; targeting it is a bug.
        not_vulnerable_transition()

    severity = resolve_severity(
        vulnerability_class=_vulnerability_class(record),
        rule_id=rule_id,
        outcome=decision.outcome,
        policy_version=policy_version,
    )
    finding_eligible = bool(
        spec is not None
        and decision.outcome == OUTCOME_CONFIRMED
        and spec.finding_eligible_on_confirmed
    )
    result = ClassificationResult(
        evidence_id=record.evidence_id,
        execution_id=record.execution_id,
        authorization_id=record.authorization_id,
        program_name=record.program_name,
        target_host=record.target.host,
        target_scheme=record.target.scheme,
        target_effective_port=record.target.effective_port,
        target_path_scope=record.target.path_scope,
        artifact_id=record.artifact_id,
        artifact_content_hash=record.artifact_content_hash,
        test_plan_id=record.test_plan_id,
        hypothesis_id=record.hypothesis_id,
        match_id=record.match_id,
        evidence_bindings_hash=record.bindings_hash or "",
        evidence_observations_hash=record.observations_hash or "",
        evidence_content_hash=record.content_hash or "",
        verifier_version=spec.verifier_version if spec is not None else "",
        rule_id=display_rule,
        observation_schema_version=(
            spec.observation_schema_version
            if spec is not None
            else OBSERVATION_SCHEMA_VERSION
        ),
        artifact_schema_version=(
            spec.artifact_schema_version
            if spec is not None
            else ARTIFACT_SCHEMA_VERSION
        ),
        policy_version=policy_version,
        outcome=decision.outcome,
        outcome_detail=decision.detail,
        severity=severity.severity,
        severity_unset_reason=severity.unset_reason,
        finding_eligible=finding_eligible,
        confirmation_state=decision.state,
        oracle_channels=decision.channels,
        reason_code=decision.reason,
    )
    return result


__all__ += ["compute_result_hash"]
