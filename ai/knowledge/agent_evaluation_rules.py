"""Stage R42.2 deterministic agent evaluation rule engine (pure engine).

Evaluates a bounded evaluation input against closed deterministic rules:

    "How good is this structured research result?"

Hard boundaries encoded here:

- Evaluation only: rules operate exclusively on structured data. No
  execution, no network, no SQL, no database, no browser, no LLM judgment,
  no payloads, no exploit verification. R42 never confirms a vulnerability.
- Generic: the same rules apply to every specialist category; no
  ``if category == XSS`` style logic exists.
- Deterministic: dimension scores, reasons and diagnostics are pure
  functions of the bounded input.
- Pure and offline: no I/O, no network, no LLM, no Mongo, no wall-clock
  time, no randomness.
- Read-only: inputs are never mutated.
"""

from __future__ import annotations

from ai.knowledge.agent_evaluation_input import (
    evaluation_context_fact_count,
)
from ai.schemas.agent_evaluation_diagnostic import (
    CONFIDENCE_OVERSTATED,
    CONFIDENCE_UNDERSPECIFIED,
    CONTEXT_TOO_SPARSE,
    EVIDENCE_INCONSISTENT,
    EVIDENCE_REQUIRED_LIMITATION_MISSING,
    EXECUTION_CLAIM_DETECTED,
    GOVERNANCE_INCONSISTENT,
    GOVERNANCE_UNKNOWN,
    HYPOTHESIS_SAFETY_FLAGS_MISSING,
    INVALID_ENUM_VALUE,
    INVALID_RULE_VERSION,
    LIMITATION_DISCLOSURE_INCOMPLETE,
    MALFORMED_EVIDENCE_PLAN,
    MALFORMED_GOVERNANCE,
    MALFORMED_HYPOTHESIS,
    MALFORMED_LIMITATIONS,
    MALFORMED_PROVENANCE,
    MISSING_EVIDENCE_REQUIREMENT,
    MISSING_REQUIRED_FIELD,
    NON_DETERMINISTIC_OUTPUT,
    NO_HYPOTHESES_REPORTED,
    PROVENANCE_INCOMPLETE,
    PROVENANCE_INVENTED_LAYER,
    RESEARCH_ONLY_FALSE,
    SAFETY_LIMITATION_MISSING,
    UNKNOWN_AGENT_CATEGORY,
    UNSUPPORTED_HYPOTHESIS,
    VULNERABILITY_CONFIRMATION_CLAIM,
)
from ai.schemas.agent_evaluation_input import (
    FLAG_INVALID_ENUM_VALUE,
    FLAG_INVALID_RULE_VERSION,
    FLAG_MALFORMED_EVIDENCE_PLAN,
    FLAG_MALFORMED_GOVERNANCE,
    FLAG_MALFORMED_HYPOTHESIS,
    FLAG_MALFORMED_LIMITATIONS,
    FLAG_MALFORMED_PROVENANCE,
    FLAG_MISSING_REQUIRED_FIELD,
    FLAG_NON_DETERMINISTIC_OUTPUT,
    FLAG_PROVENANCE_INVENTED_LAYER,
    FLAG_UNKNOWN_AGENT_CATEGORY,
    HYPOTHESIS_SAFETY_LIMITATIONS,
    SAFETY_REQUIRED_LIMITATIONS,
    sanitize_agent_evaluation_input,
)
from ai.schemas.agent_evaluation_rule import (
    AGENT_EVALUATION_RULE_RULE_VERSION,
    DIMENSION_CONFIDENCE_CALIBRATION,
    DIMENSION_CONTEXT_COMPLETENESS,
    DIMENSION_DETERMINISM,
    DIMENSION_EVIDENCE_COMPLETENESS,
    DIMENSION_GOVERNANCE_COMPLETENESS,
    DIMENSION_HYPOTHESIS_SUPPORT,
    DIMENSION_LIMITATION_DISCLOSURE,
    DIMENSION_PROVENANCE_COMPLETENESS,
    DIMENSION_SAFETY_COMPLIANCE,
    DIMENSION_STRUCTURAL_VALIDITY,
    EVALUATION_DIMENSIONS,
    RULE_AGENT_CATEGORY_KNOWN,
    RULE_CONFIDENCE_MATCHES_CONTEXT,
    RULE_CONTEXT_FACTS_SUFFICIENT,
    RULE_CONTEXT_PRESENT,
    RULE_ENUM_VALUES_VALID,
    RULE_EVIDENCE_ITEMS_PRESENT,
    RULE_EVIDENCE_PLAN_STRUCTURALLY_VALID,
    RULE_EVIDENCE_REQUIRED_PRESERVED,
    RULE_EVIDENCE_STATE_CONSISTENT,
    RULE_GOVERNANCE_CONSISTENT,
    RULE_GOVERNANCE_PRESENT,
    RULE_GOVERNANCE_STATE_VISIBLE,
    RULE_GOVERNANCE_STRUCTURALLY_VALID,
    RULE_HYPOTHESES_PRESENT,
    RULE_HYPOTHESES_STRUCTURALLY_VALID,
    RULE_HYPOTHESIS_SAFETY_FLAGS,
    RULE_LIMITATIONS_PRESENT,
    RULE_LIMITATIONS_STRUCTURALLY_VALID,
    RULE_NON_EXECUTION_DISCLOSED,
    RULE_NO_EXECUTION_CLAIMS,
    RULE_NO_VULNERABILITY_CONFIRMATION,
    RULE_OUTPUT_DETERMINISTIC,
    RULE_PROVENANCE_LAYERS_VALID,
    RULE_PROVENANCE_PRESENT,
    RULE_PROVENANCE_STATE_CONSISTENT,
    RULE_PROVENANCE_STRUCTURALLY_VALID,
    RULE_REQUIRED_FIELDS_PRESENT,
    RULE_RESEARCH_ONLY,
    RULE_RULE_VERSIONS_VALID,
    RULE_SAFETY_LIMITATIONS_PRESENT,
    RULE_SIGNALS_PRESENT,
    RULE_TYPE_CONFIDENCE_CONSISTENT,
    AgentEvaluationDimensionOutcome,
    agent_evaluation_dimension_outcome_projection,
)
from ai.schemas.research_governance_export import (
    RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION,
)

AGENT_EVALUATION_RULE_ENGINE_RULE_VERSION = "r42-2"
RULE_VERSION = AGENT_EVALUATION_RULE_ENGINE_RULE_VERSION

EXECUTION_CLAIM_TOKENS: tuple[str, ...] = (
    "PAYLOAD_SENT",
    "PAYLOAD_EXECUTED",
    "COMMAND_EXECUTED",
    "ATTACK_PERFORMED",
    "SCAN_PERFORMED",
    "EXPLOITED",
    "EXECUTED",
)

CONFIRMATION_CLAIM_TOKENS: tuple[str, ...] = (
    "VULNERABILITY_CONFIRMED",
    "CONFIRMED_VULNERABILITY",
    "CONFIRMED_EXPLOIT",
    "EXPLOIT_CONFIRMED",
    "IS_VULNERABLE",
    "VULNERABILITY_FOUND",
)

# flag -> (rule, penalty, diagnostic code)
_STRUCTURAL_FLAG_MAP: dict[str, tuple] = {
    FLAG_MISSING_REQUIRED_FIELD: (
        RULE_REQUIRED_FIELDS_PRESENT, 25, MISSING_REQUIRED_FIELD,
    ),
    FLAG_INVALID_RULE_VERSION: (
        RULE_RULE_VERSIONS_VALID, 20, INVALID_RULE_VERSION,
    ),
    FLAG_INVALID_ENUM_VALUE: (
        RULE_ENUM_VALUES_VALID, 20, INVALID_ENUM_VALUE,
    ),
    FLAG_UNKNOWN_AGENT_CATEGORY: (
        RULE_AGENT_CATEGORY_KNOWN, 25, UNKNOWN_AGENT_CATEGORY,
    ),
    FLAG_MALFORMED_HYPOTHESIS: (
        RULE_HYPOTHESES_STRUCTURALLY_VALID, 15, MALFORMED_HYPOTHESIS,
    ),
    FLAG_MALFORMED_EVIDENCE_PLAN: (
        RULE_EVIDENCE_PLAN_STRUCTURALLY_VALID, 20,
        MALFORMED_EVIDENCE_PLAN,
    ),
    FLAG_MALFORMED_PROVENANCE: (
        RULE_PROVENANCE_STRUCTURALLY_VALID, 15, MALFORMED_PROVENANCE,
    ),
    FLAG_MALFORMED_GOVERNANCE: (
        RULE_GOVERNANCE_STRUCTURALLY_VALID, 15, MALFORMED_GOVERNANCE,
    ),
    FLAG_MALFORMED_LIMITATIONS: (
        RULE_LIMITATIONS_STRUCTURALLY_VALID, 10, MALFORMED_LIMITATIONS,
    ),
}

_REASONS: dict[str, str] = {
    RULE_REQUIRED_FIELDS_PRESENT: "required result fields are missing",
    RULE_RULE_VERSIONS_VALID: "a rule version is missing or malformed",
    RULE_ENUM_VALUES_VALID: "a closed-vocabulary value is invalid",
    RULE_AGENT_CATEGORY_KNOWN: "the agent category is UNKNOWN",
    RULE_HYPOTHESES_STRUCTURALLY_VALID: "hypotheses are malformed",
    RULE_EVIDENCE_PLAN_STRUCTURALLY_VALID: "the evidence plan is malformed",
    RULE_PROVENANCE_STRUCTURALLY_VALID: "the provenance record is malformed",
    RULE_GOVERNANCE_STRUCTURALLY_VALID: "the governance reference is "
                                        "malformed",
    RULE_LIMITATIONS_STRUCTURALLY_VALID: "the limitations list is malformed",
    RULE_CONTEXT_PRESENT: "no context analysis was supplied",
    RULE_CONTEXT_FACTS_SUFFICIENT: "too few known context facts",
    RULE_HYPOTHESES_PRESENT: "no hypotheses were reported",
    RULE_SIGNALS_PRESENT: "a hypothesis has no supporting signals",
    RULE_TYPE_CONFIDENCE_CONSISTENT: "hypothesis type and confidence are "
                                     "inconsistent",
    RULE_HYPOTHESIS_SAFETY_FLAGS: "hypothesis safety limitations are missing",
    RULE_EVIDENCE_ITEMS_PRESENT: "no evidence requirements were planned",
    RULE_EVIDENCE_REQUIRED_PRESERVED: "EVIDENCE_REQUIRED is not preserved",
    RULE_EVIDENCE_STATE_CONSISTENT: "evidence state and confidence are "
                                    "inconsistent",
    RULE_CONFIDENCE_MATCHES_CONTEXT: "confidence does not match the supplied "
                                     "context",
    RULE_RESEARCH_ONLY: "the result is not research-only",
    RULE_SAFETY_LIMITATIONS_PRESENT: "safety limitations are missing",
    RULE_NO_EXECUTION_CLAIMS: "an execution claim is present",
    RULE_NO_VULNERABILITY_CONFIRMATION: "a vulnerability confirmation claim "
                                        "is present",
    RULE_PROVENANCE_PRESENT: "provenance is absent",
    RULE_PROVENANCE_STATE_CONSISTENT: "provenance state and layers are "
                                      "inconsistent",
    RULE_PROVENANCE_LAYERS_VALID: "provenance contains a non-declared layer",
    RULE_GOVERNANCE_PRESENT: "the governance reference is absent",
    RULE_GOVERNANCE_STATE_VISIBLE: "the governance state is not referenced",
    RULE_GOVERNANCE_CONSISTENT: "the governance reference is inconsistent",
    RULE_OUTPUT_DETERMINISTIC: "the result carries non-deterministic markers",
    RULE_LIMITATIONS_PRESENT: "no limitations were disclosed",
    RULE_NON_EXECUTION_DISCLOSED: "the non-execution boundary is not "
                                  "disclosed",
}

_UNKNOWN = "UNKNOWN"
_COMPLETE = "COMPLETE"
_PARTIAL = "PARTIAL"


def _clamp(score: int) -> int:
    return max(0, min(100, score))


def _outcome(
    dimension: str,
    score: int,
    passed: object,
    failed: object,
    diagnostics: object,
) -> dict:
    passed_rules: list[str] = []
    failed_rules: list[str] = []
    for rule in passed or ():
        if rule not in passed_rules:
            passed_rules.append(rule)
    for rule in failed or ():
        if rule not in failed_rules:
            failed_rules.append(rule)
    reasons = [_REASONS[rule] for rule in failed_rules if rule in _REASONS]
    plan = AgentEvaluationDimensionOutcome(
        rule_version=AGENT_EVALUATION_RULE_RULE_VERSION,
        dimension=dimension,
        score=_clamp(score),
        passed_rules=passed_rules,
        failed_rules=failed_rules,
        reasons=reasons,
        diagnostics=[
            item for item in diagnostics or () if isinstance(item, dict)
        ],
    )
    return agent_evaluation_dimension_outcome_projection(plan)


def _diag(code: str, reference: str = "") -> dict:
    return {"diagnostic_code": code, "evidence_reference": reference}


def _claim_text(evaluation_input: dict) -> str:
    parts: list[str] = []
    for hypothesis in evaluation_input.get("hypotheses") or ():
        parts.append(str(hypothesis.get("hypothesis_type") or ""))
        parts.append(" ".join(hypothesis.get("supporting_signals") or ()))
        parts.append(" ".join(hypothesis.get("limitations") or ()))
    parts.append(" ".join(evaluation_input.get("limitations") or ()))
    evidence = evaluation_input.get("evidence_plan") or {}
    parts.append(" ".join(evidence.get("evidence_items") or ()))
    parts.append(" ".join(evidence.get("limitations") or ()))
    parts.append(str(evidence.get("evidence_state") or ""))
    provenance = evaluation_input.get("provenance") or {}
    parts.append(" ".join(provenance.get("source_layers") or ()))
    parts.append(str(provenance.get("provenance_state") or ""))
    governance = evaluation_input.get("governance_reference") or {}
    parts.append(str(governance.get("reference_state") or ""))
    for key in (
        "provenance_state", "trace_state", "audit_state",
        "explanation_state",
    ):
        parts.append(str(governance.get(key) or ""))
    return " ".join(parts).upper()


def _execution_claim_present(evaluation_input: dict) -> bool:
    text = _claim_text(evaluation_input)
    return any(token in text for token in EXECUTION_CLAIM_TOKENS)


def _confirmation_claim_present(evaluation_input: dict) -> bool:
    text = _claim_text(evaluation_input)
    return any(token in text for token in CONFIRMATION_CLAIM_TOKENS)


# ---------------------------------------------------------------------------
# Dimension evaluators
# ---------------------------------------------------------------------------


def _evaluate_structural(evaluation_input: dict) -> dict:
    flags = set(evaluation_input.get("structural_flags") or ())
    score = 100
    failed: list[str] = []
    diagnostics: list[dict] = []
    for flag in sorted(flags):
        mapping = _STRUCTURAL_FLAG_MAP.get(flag)
        if not mapping:
            continue
        rule, penalty, code = mapping
        score -= penalty
        if rule not in failed:
            failed.append(rule)
        diagnostics.append(_diag(code, flag))
    passed = [
        rule
        for rule in (
            RULE_REQUIRED_FIELDS_PRESENT,
            RULE_RULE_VERSIONS_VALID,
            RULE_ENUM_VALUES_VALID,
            RULE_AGENT_CATEGORY_KNOWN,
            RULE_HYPOTHESES_STRUCTURALLY_VALID,
            RULE_EVIDENCE_PLAN_STRUCTURALLY_VALID,
            RULE_PROVENANCE_STRUCTURALLY_VALID,
            RULE_GOVERNANCE_STRUCTURALLY_VALID,
            RULE_LIMITATIONS_STRUCTURALLY_VALID,
        )
        if rule not in failed
    ]
    return _outcome(
        DIMENSION_STRUCTURAL_VALIDITY, score, passed, failed, diagnostics
    )


def _evaluate_context(evaluation_input: dict) -> dict:
    context = evaluation_input.get("context_analysis") or {}
    facts = evaluation_context_fact_count(context)
    if facts >= 7:
        score = 100
    elif facts >= 5:
        score = 85
    elif facts >= 3:
        score = 65
    elif facts >= 1:
        score = 45
    else:
        score = 20
    failed: list[str] = []
    diagnostics: list[dict] = []
    if not context:
        failed.append(RULE_CONTEXT_PRESENT)
    if facts < 3:
        failed.append(RULE_CONTEXT_FACTS_SUFFICIENT)
    if facts < 2:
        diagnostics.append(_diag(CONTEXT_TOO_SPARSE, "context_analysis"))
    passed = [
        rule
        for rule in (RULE_CONTEXT_PRESENT, RULE_CONTEXT_FACTS_SUFFICIENT)
        if rule not in failed
    ]
    return _outcome(
        DIMENSION_CONTEXT_COMPLETENESS, score, passed, failed, diagnostics
    )


def _evaluate_hypotheses(evaluation_input: dict) -> dict:
    hypotheses = evaluation_input.get("hypotheses") or []
    diagnostics: list[dict] = []
    failed: list[str] = []
    if not hypotheses:
        return _outcome(
            DIMENSION_HYPOTHESIS_SUPPORT,
            40,
            [],
            [RULE_HYPOTHESES_PRESENT],
            [_diag(NO_HYPOTHESES_REPORTED, "hypotheses")],
        )
    score = 100
    for index, hypothesis in enumerate(hypotheses):
        reference = f"hypotheses[{index}]"
        signals = hypothesis.get("supporting_signals") or []
        confidence = hypothesis.get("confidence") or _UNKNOWN
        priority = hypothesis.get("priority") or _UNKNOWN
        hypothesis_type = hypothesis.get("hypothesis_type") or _UNKNOWN
        limitations = hypothesis.get("limitations") or []

        if not signals:
            score -= 30
            if RULE_SIGNALS_PRESENT not in failed:
                failed.append(RULE_SIGNALS_PRESENT)
            diagnostics.append(
                _diag(UNSUPPORTED_HYPOTHESIS, reference)
            )
        if (hypothesis_type == _UNKNOWN) != (confidence == _UNKNOWN):
            score -= 15
            if RULE_TYPE_CONFIDENCE_CONSISTENT not in failed:
                failed.append(RULE_TYPE_CONFIDENCE_CONSISTENT)
            diagnostics.append(
                _diag(UNSUPPORTED_HYPOTHESIS, reference)
            )
        missing = [
            code
            for code in HYPOTHESIS_SAFETY_LIMITATIONS
            if code not in limitations
        ]
        if missing:
            score -= 25
            if RULE_HYPOTHESIS_SAFETY_FLAGS not in failed:
                failed.append(RULE_HYPOTHESIS_SAFETY_FLAGS)
            diagnostics.append(
                _diag(HYPOTHESIS_SAFETY_FLAGS_MISSING, reference)
            )
        if priority not in (_UNKNOWN, confidence):
            score -= 5
            if RULE_TYPE_CONFIDENCE_CONSISTENT not in failed:
                failed.append(RULE_TYPE_CONFIDENCE_CONSISTENT)
    passed = [
        rule
        for rule in (
            RULE_HYPOTHESES_PRESENT,
            RULE_SIGNALS_PRESENT,
            RULE_TYPE_CONFIDENCE_CONSISTENT,
            RULE_HYPOTHESIS_SAFETY_FLAGS,
        )
        if rule not in failed
    ]
    return _outcome(
        DIMENSION_HYPOTHESIS_SUPPORT, score, passed, failed, diagnostics
    )


def _evaluate_evidence(evaluation_input: dict) -> dict:
    evidence = evaluation_input.get("evidence_plan") or {}
    items = evidence.get("evidence_items") or []
    state = evidence.get("evidence_state") or _UNKNOWN
    limitations = evidence.get("limitations") or []
    confidence = evaluation_input.get("result_confidence") or _UNKNOWN

    score = 100
    failed: list[str] = []
    diagnostics: list[dict] = []

    if not items or items == [_UNKNOWN]:
        score = 30
        failed.append(RULE_EVIDENCE_ITEMS_PRESENT)
        diagnostics.append(
            _diag(MISSING_EVIDENCE_REQUIREMENT, "evidence_plan")
        )
    if "EVIDENCE_REQUIRED" not in limitations:
        score -= 15
        failed.append(RULE_EVIDENCE_REQUIRED_PRESERVED)
        diagnostics.append(
            _diag(EVIDENCE_REQUIRED_LIMITATION_MISSING, "evidence_plan")
        )
    if state == _COMPLETE and confidence in (_UNKNOWN, "LOW"):
        score -= 25
        failed.append(RULE_EVIDENCE_STATE_CONSISTENT)
        diagnostics.append(
            _diag(EVIDENCE_INCONSISTENT, "evidence_plan")
        )
    passed = [
        rule
        for rule in (
            RULE_EVIDENCE_ITEMS_PRESENT,
            RULE_EVIDENCE_REQUIRED_PRESERVED,
            RULE_EVIDENCE_STATE_CONSISTENT,
        )
        if rule not in failed
    ]
    return _outcome(
        DIMENSION_EVIDENCE_COMPLETENESS, score, passed, failed, diagnostics
    )


def _evaluate_confidence(evaluation_input: dict) -> dict:
    confidence = evaluation_input.get("result_confidence") or _UNKNOWN
    facts = evaluation_context_fact_count(
        evaluation_input.get("context_analysis") or {}
    )
    evidence_state = (
        evaluation_input.get("evidence_plan") or {}
    ).get("evidence_state") or _UNKNOWN

    score = 100
    failed: list[str] = []
    diagnostics: list[dict] = []

    if confidence == "HIGH":
        if facts < 5:
            score -= 40
            failed.append(RULE_CONFIDENCE_MATCHES_CONTEXT)
            diagnostics.append(
                _diag(CONFIDENCE_OVERSTATED, "result_confidence")
            )
        if not (evaluation_input.get("hypotheses") or []):
            score -= 20
            if RULE_CONFIDENCE_MATCHES_CONTEXT not in failed:
                failed.append(RULE_CONFIDENCE_MATCHES_CONTEXT)
            diagnostics.append(
                _diag(CONFIDENCE_OVERSTATED, "hypotheses")
            )
    elif confidence == "MEDIUM":
        if facts < 2:
            score -= 25
            failed.append(RULE_CONFIDENCE_MATCHES_CONTEXT)
            diagnostics.append(
                _diag(CONFIDENCE_OVERSTATED, "result_confidence")
            )
    elif confidence == _UNKNOWN:
        if facts >= 7:
            score -= 25
            failed.append(RULE_CONFIDENCE_MATCHES_CONTEXT)
            diagnostics.append(
                _diag(CONFIDENCE_UNDERSPECIFIED, "result_confidence")
            )
    elif confidence == "LOW":
        if facts >= 8:
            score -= 10
            failed.append(RULE_CONFIDENCE_MATCHES_CONTEXT)
            diagnostics.append(
                _diag(CONFIDENCE_UNDERSPECIFIED, "result_confidence")
            )
    if evidence_state == _COMPLETE and confidence == _UNKNOWN:
        score -= 15
        if RULE_CONFIDENCE_MATCHES_CONTEXT not in failed:
            failed.append(RULE_CONFIDENCE_MATCHES_CONTEXT)
        diagnostics.append(
            _diag(CONFIDENCE_UNDERSPECIFIED, "evidence_plan")
        )
    passed: list[str] = []
    if RULE_CONFIDENCE_MATCHES_CONTEXT not in failed:
        passed.append(RULE_CONFIDENCE_MATCHES_CONTEXT)
    return _outcome(
        DIMENSION_CONFIDENCE_CALIBRATION,
        score,
        passed,
        failed,
        diagnostics,
    )


def _disclosed_limitations(evaluation_input: dict) -> list[str]:
    """Union of disclosed limitations across bounded limitation channels.

    Specialists may disclose safety limitations on the aggregate result,
    on the evidence plan or on individual hypotheses; all are legitimate
    disclosure channels, so the safety dimension checks the union.
    """

    codes: list[str] = []
    for code in evaluation_input.get("limitations") or ():
        if code not in codes:
            codes.append(code)
    evidence = evaluation_input.get("evidence_plan") or {}
    for code in evidence.get("limitations") or ():
        if code not in codes:
            codes.append(code)
    for hypothesis in evaluation_input.get("hypotheses") or ():
        for code in hypothesis.get("limitations") or ():
            if code not in codes:
                codes.append(code)
    return codes


def _evaluate_safety(evaluation_input: dict) -> dict:
    score = 100
    failed: list[str] = []
    diagnostics: list[dict] = []

    if not evaluation_input.get("research_only", True):
        score = 0
        failed.append(RULE_RESEARCH_ONLY)
        diagnostics.append(_diag(RESEARCH_ONLY_FALSE, "research_only"))

    required = list(SAFETY_REQUIRED_LIMITATIONS)
    if evaluation_input.get("hypotheses"):
        for code in ("HYPOTHESIS_ONLY", "EVIDENCE_REQUIRED"):
            if code not in required:
                required.append(code)
    limitations = _disclosed_limitations(evaluation_input)
    missing = [code for code in required if code not in limitations]
    if missing:
        score -= min(60, 20 * len(missing))
        failed.append(RULE_SAFETY_LIMITATIONS_PRESENT)
        diagnostics.append(
            _diag(SAFETY_LIMITATION_MISSING, "limitations")
        )
    if _execution_claim_present(evaluation_input):
        score -= 60
        failed.append(RULE_NO_EXECUTION_CLAIMS)
        diagnostics.append(
            _diag(EXECUTION_CLAIM_DETECTED, "result")
        )
    if _confirmation_claim_present(evaluation_input):
        score -= 60
        failed.append(RULE_NO_VULNERABILITY_CONFIRMATION)
        diagnostics.append(
            _diag(VULNERABILITY_CONFIRMATION_CLAIM, "result")
        )
    passed = [
        rule
        for rule in (
            RULE_RESEARCH_ONLY,
            RULE_SAFETY_LIMITATIONS_PRESENT,
            RULE_NO_EXECUTION_CLAIMS,
            RULE_NO_VULNERABILITY_CONFIRMATION,
        )
        if rule not in failed
    ]
    return _outcome(
        DIMENSION_SAFETY_COMPLIANCE, score, passed, failed, diagnostics
    )


def _evaluate_provenance(evaluation_input: dict) -> dict:
    provenance = evaluation_input.get("provenance") or {}
    layers = provenance.get("source_layers") or []
    state = provenance.get("provenance_state") or _UNKNOWN
    flags = set(evaluation_input.get("structural_flags") or ())

    score = 100
    failed: list[str] = []
    diagnostics: list[dict] = []

    if not provenance or (not layers and state == _UNKNOWN):
        score = 30
        failed.append(RULE_PROVENANCE_PRESENT)
        diagnostics.append(_diag(PROVENANCE_INCOMPLETE, "provenance"))
    else:
        if state == _UNKNOWN:
            score -= 50
            failed.append(RULE_PROVENANCE_STATE_CONSISTENT)
            diagnostics.append(_diag(PROVENANCE_INCOMPLETE, "provenance"))
        elif state == _PARTIAL:
            score -= 20
        if state == _COMPLETE and len(layers) < 5:
            score -= 30
            failed.append(RULE_PROVENANCE_STATE_CONSISTENT)
            diagnostics.append(_diag(PROVENANCE_INCOMPLETE, "provenance"))
        if state == _PARTIAL and not layers:
            score -= 20
            if RULE_PROVENANCE_STATE_CONSISTENT not in failed:
                failed.append(RULE_PROVENANCE_STATE_CONSISTENT)
            diagnostics.append(_diag(PROVENANCE_INCOMPLETE, "provenance"))
        if provenance.get("research_only") is not True:
            score -= 20
            failed.append(RULE_PROVENANCE_LAYERS_VALID)
            diagnostics.append(_diag(PROVENANCE_INCOMPLETE, "provenance"))
    if FLAG_PROVENANCE_INVENTED_LAYER in flags:
        score -= 20
        failed.append(RULE_PROVENANCE_LAYERS_VALID)
        diagnostics.append(
            _diag(PROVENANCE_INVENTED_LAYER, "provenance")
        )
    passed = [
        rule
        for rule in (
            RULE_PROVENANCE_PRESENT,
            RULE_PROVENANCE_STATE_CONSISTENT,
            RULE_PROVENANCE_LAYERS_VALID,
        )
        if rule not in failed
    ]
    return _outcome(
        DIMENSION_PROVENANCE_COMPLETENESS, score, passed, failed,
        diagnostics,
    )


def _evaluate_governance(evaluation_input: dict) -> dict:
    governance = evaluation_input.get("governance_reference") or {}
    state = governance.get("reference_state") or _UNKNOWN

    score = 100
    failed: list[str] = []
    diagnostics: list[dict] = []

    if not governance:
        score = 30
        failed.append(RULE_GOVERNANCE_PRESENT)
        diagnostics.append(_diag(GOVERNANCE_UNKNOWN, "governance_reference"))
    elif state == _UNKNOWN:
        score = 60
        failed.append(RULE_GOVERNANCE_STATE_VISIBLE)
        diagnostics.append(_diag(GOVERNANCE_UNKNOWN, "governance_reference"))
    else:
        if governance.get("rule_version") != (
            RESEARCH_GOVERNANCE_EXPORT_RULE_VERSION
        ):
            score -= 30
            failed.append(RULE_GOVERNANCE_CONSISTENT)
            diagnostics.append(
                _diag(GOVERNANCE_INCONSISTENT, "governance_reference")
            )
        components = (
            governance.get("provenance_state"),
            governance.get("trace_state"),
            governance.get("audit_state"),
            governance.get("explanation_state"),
        )
        if governance.get("ready") is True and any(
            component == _UNKNOWN for component in components
        ):
            score -= 30
            if RULE_GOVERNANCE_CONSISTENT not in failed:
                failed.append(RULE_GOVERNANCE_CONSISTENT)
            diagnostics.append(
                _diag(GOVERNANCE_INCONSISTENT, "governance_reference")
            )
    if governance.get("ready") is True and state != "REFERENCED":
        score -= 30
        if RULE_GOVERNANCE_CONSISTENT not in failed:
            failed.append(RULE_GOVERNANCE_CONSISTENT)
        diagnostics.append(
            _diag(GOVERNANCE_INCONSISTENT, "governance_reference")
        )
    passed = [
        rule
        for rule in (
            RULE_GOVERNANCE_PRESENT,
            RULE_GOVERNANCE_STATE_VISIBLE,
            RULE_GOVERNANCE_CONSISTENT,
        )
        if rule not in failed
    ]
    return _outcome(
        DIMENSION_GOVERNANCE_COMPLETENESS, score, passed, failed,
        diagnostics,
    )


def _evaluate_determinism(evaluation_input: dict) -> dict:
    flags = set(evaluation_input.get("structural_flags") or ())
    score = 100
    failed: list[str] = []
    diagnostics: list[dict] = []
    if FLAG_NON_DETERMINISTIC_OUTPUT in flags:
        score = 0
        failed.append(RULE_OUTPUT_DETERMINISTIC)
        diagnostics.append(
            _diag(NON_DETERMINISTIC_OUTPUT, "result")
        )
    if not evaluation_input.get("result_rule_version") or not (
        evaluation_input.get("agent_rule_version")
    ):
        score -= 40
        if RULE_OUTPUT_DETERMINISTIC not in failed:
            failed.append(RULE_OUTPUT_DETERMINISTIC)
        diagnostics.append(_diag(INVALID_RULE_VERSION, "rule_version"))
    passed = (
        [RULE_OUTPUT_DETERMINISTIC]
        if RULE_OUTPUT_DETERMINISTIC not in failed
        else []
    )
    return _outcome(
        DIMENSION_DETERMINISM, score, passed, failed, diagnostics
    )


def _evaluate_limitations(evaluation_input: dict) -> dict:
    limitations = evaluation_input.get("limitations") or []
    score = 100
    failed: list[str] = []
    diagnostics: list[dict] = []
    if not limitations:
        score = 20
        failed.append(RULE_LIMITATIONS_PRESENT)
        diagnostics.append(
            _diag(LIMITATION_DISCLOSURE_INCOMPLETE, "limitations")
        )
    else:
        if "NO_EXECUTION_PERFORMED" not in limitations:
            score -= 40
            failed.append(RULE_NON_EXECUTION_DISCLOSED)
            diagnostics.append(
                _diag(LIMITATION_DISCLOSURE_INCOMPLETE, "limitations")
            )
        if len(limitations) < 2:
            score -= 25
            if RULE_LIMITATIONS_PRESENT not in failed:
                failed.append(RULE_LIMITATIONS_PRESENT)
            diagnostics.append(
                _diag(LIMITATION_DISCLOSURE_INCOMPLETE, "limitations")
            )
    passed = [
        rule
        for rule in (RULE_LIMITATIONS_PRESENT, RULE_NON_EXECUTION_DISCLOSED)
        if rule not in failed
    ]
    return _outcome(
        DIMENSION_LIMITATION_DISCLOSURE, score, passed, failed, diagnostics
    )


_EVALUATORS = {
    DIMENSION_STRUCTURAL_VALIDITY: _evaluate_structural,
    DIMENSION_CONTEXT_COMPLETENESS: _evaluate_context,
    DIMENSION_HYPOTHESIS_SUPPORT: _evaluate_hypotheses,
    DIMENSION_EVIDENCE_COMPLETENESS: _evaluate_evidence,
    DIMENSION_CONFIDENCE_CALIBRATION: _evaluate_confidence,
    DIMENSION_SAFETY_COMPLIANCE: _evaluate_safety,
    DIMENSION_PROVENANCE_COMPLETENESS: _evaluate_provenance,
    DIMENSION_GOVERNANCE_COMPLETENESS: _evaluate_governance,
    DIMENSION_DETERMINISM: _evaluate_determinism,
    DIMENSION_LIMITATION_DISCLOSURE: _evaluate_limitations,
}


def evaluate_evaluation_dimensions(evaluation_input: object) -> list[dict]:
    """Evaluate every dimension in canonical order (read-only).

    Returns one bounded outcome per evaluation dimension. The same input
    always produces byte-identical outcomes.
    """

    bounded = sanitize_agent_evaluation_input(evaluation_input)
    return [
        _EVALUATORS[dimension](bounded)
        for dimension in EVALUATION_DIMENSIONS
    ]


__all__ = [
    "AGENT_EVALUATION_RULE_ENGINE_RULE_VERSION",
    "RULE_VERSION",
    "EXECUTION_CLAIM_TOKENS",
    "CONFIRMATION_CLAIM_TOKENS",
    "evaluate_evaluation_dimensions",
]
