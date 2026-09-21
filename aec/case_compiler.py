"""Authorization request compiler (AEC-1 T4, offline preparation half).

Converts a selected T1 pilot case (:class:`CaseRef`, or a selected
:class:`SelectionDecision`) into a deterministic ``AuthorizationRequest``
*draft* plus a human approval sheet.

A draft is intent paperwork, never authority: it cannot be consumed,
executed, or treated as permission. Only the issuance service can mint an
authorization, and this module never contacts it, any target, or anything
else. No sockets. No HTTP. No DNS. No subprocess. No filesystem writes.

DRAFT ONLY — NOT AN AUTHORIZATION. NO CONTACT HAS OCCURRED.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from aec.models import CaseRef, EvidenceGap, SelectionDecision

COMPILER_VERSION = "aec-compiler/v1"

#: Observation methods the offline half may ever describe. Strict subset of
#: the frozen schema's allowed methods; GET/HEAD carry no body.
ALLOWED_METHODS = ("GET", "HEAD")

#: Cost attributed to one compiled draft in the budget reference.
REQUESTED_COST = 1

#: Budget policy this draft's reference points at (a name, not a lookup).
BUDGET_POLICY_REF = "pilot-budget/v1"

#: Requested-observation purpose per normalised case category. Closed
#: vocabulary: unknown categories fall back to the generic purpose.
PURPOSE_FOR_CATEGORY = {
    "idor": "OBJECT_REFERENCE_OBSERVATION",
    "ssrf": "SERVER_REQUEST_OBSERVATION",
    "xss": "REFLECTION_OBSERVATION",
}
GENERIC_PURPOSE = "GENERIC_EVIDENCE_OBSERVATION"

#: Closed refusal vocabulary. No free-form refusal reasons.
REFUSAL_CODES = frozenset({
    "INVALID_INPUT",
    "NOT_SELECTED",
    "INVALID_CASE_ID",
    "MISSING_HOST",
    "MISSING_ENDPOINT",
    "MISSING_EVIDENCE_GAP",
    "GAP_COMPLETE",
    "UNSUPPORTED_METHOD",
})

_APPROVAL_DISCLAIMER = "DRAFT ONLY — NOT AN AUTHORIZATION. NO CONTACT HAS OCCURRED."


def purpose_for(category: object) -> str:
    """Closed-vocabulary observation purpose for a normalised category."""
    return PURPOSE_FOR_CATEGORY.get(str(category or "").strip().lower(), GENERIC_PURPOSE)


@dataclass(frozen=True)
class BudgetReference:
    """Which budget a draft would draw from, and at what cost."""

    policy: str
    requested_cost: int
    case_id: str
    host: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "requested_cost": self.requested_cost,
            "case_id": self.case_id,
            "host": self.host,
        }


@dataclass(frozen=True)
class AuthorizationRequestDraft:
    """Deterministic draft of an authorization request. Not authority."""

    case_id: str
    host: str
    endpoint: str
    parameter: str
    method: str
    category: str
    purpose_code: str
    purpose_detail: tuple[str, ...]
    evidence_gap: dict[str, Any]
    budget_ref: BudgetReference
    compiler_version: str = COMPILER_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "host": self.host,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "category": self.category,
            "purpose_code": self.purpose_code,
            "purpose_detail": list(self.purpose_detail),
            "evidence_gap": dict(self.evidence_gap),
            "budget_ref": self.budget_ref.to_dict(),
            "compiler_version": self.compiler_version,
        }


@dataclass(frozen=True)
class CompileOutcome:
    """Result of compiling: either a draft or a closed-vocabulary refusal."""

    ok: bool
    request: AuthorizationRequestDraft | None
    refusal_code: str | None
    refusal_detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "request": self.request.to_dict() if self.request is not None else None,
            "refusal_code": self.refusal_code,
            "refusal_detail": self.refusal_detail,
        }


def _refuse(code: str, detail: str) -> CompileOutcome:
    assert code in REFUSAL_CODES, f"refusal code outside closed vocabulary: {code!r}"
    return CompileOutcome(ok=False, request=None, refusal_code=code, refusal_detail=detail)


def compile_authorization_request(source: object) -> CompileOutcome:
    """Compile a selected pilot case into an authorization request draft.

    Accepts a :class:`CaseRef` or a selected :class:`SelectionDecision`.
    Pure and deterministic: same input always yields an equal outcome, and
    the input objects are never mutated.
    """
    case: Any = source
    if isinstance(source, SelectionDecision):
        if not source.selected:
            return _refuse(
                "NOT_SELECTED",
                f"case {source.case_id!r} was not selected ({source.decision})",
            )
        case = source.case
    if not isinstance(case, CaseRef):
        return _refuse(
            "INVALID_INPUT",
            f"expected CaseRef or selected SelectionDecision, got {type(source).__name__}",
        )
    if not case.case_id.strip():
        return _refuse("INVALID_CASE_ID", "case carries no case_id")
    if not case.host.strip():
        return _refuse("MISSING_HOST", f"case {case.case_id!r} names no target host")
    if not case.endpoint.strip():
        return _refuse("MISSING_ENDPOINT", f"case {case.case_id!r} names no endpoint")
    gap = case.evidence_gap
    if not isinstance(gap, EvidenceGap):
        return _refuse(
            "MISSING_EVIDENCE_GAP", f"case {case.case_id!r} carries no evidence gap"
        )
    if gap.is_complete:
        return _refuse(
            "GAP_COMPLETE",
            f"case {case.case_id!r} states no missing evidence; nothing to request",
        )
    method = case.method.strip().upper()
    if method not in ALLOWED_METHODS:
        return _refuse(
            "UNSUPPORTED_METHOD",
            f"case {case.case_id!r} uses method {case.method!r}; "
            f"drafts describe {', '.join(ALLOWED_METHODS)} only",
        )
    outstanding = tuple(sorted(set(gap.missing) | set(gap.artifacts_missing)))
    draft = AuthorizationRequestDraft(
        case_id=case.case_id,
        host=case.host,
        endpoint=case.endpoint,
        parameter=case.parameter,
        method=method,
        category=case.category,
        purpose_code=purpose_for(case.category),
        purpose_detail=outstanding,
        evidence_gap=gap.to_dict(),
        budget_ref=BudgetReference(
            policy=BUDGET_POLICY_REF,
            requested_cost=REQUESTED_COST,
            case_id=case.case_id,
            host=case.host,
        ),
    )
    return CompileOutcome(ok=True, request=draft, refusal_code=None)


def serialize_request(draft: AuthorizationRequestDraft) -> str:
    """Stable serialization: identical drafts always produce identical bytes."""
    return json.dumps(draft.to_dict(), sort_keys=True)


def render_approval_sheet(outcome: CompileOutcome) -> str:
    """Human-readable approval sheet for one compile outcome.

    Pure string building. A refused outcome renders the refusal, never a
    draft; a draft renders as paperwork awaiting a human decision.
    """
    lines = ["Authorization request — human approval sheet"]
    if not outcome.ok or outcome.request is None:
        lines.append("STATUS: REFUSED")
        lines.append(f"refusal_code: {outcome.refusal_code}")
        if outcome.refusal_detail:
            lines.append(f"refusal_detail: {outcome.refusal_detail}")
        lines.append(_APPROVAL_DISCLAIMER)
        return "\n".join(lines) + "\n"
    request = outcome.request
    lines.append("STATUS: DRAFT")
    lines.append(f"case_id: {request.case_id}")
    lines.append(f"host: {request.host}")
    lines.append(f"endpoint: {request.endpoint}")
    lines.append(f"parameter: {request.parameter}")
    lines.append(f"method: {request.method}")
    lines.append(f"category: {request.category}")
    lines.append(f"purpose: {request.purpose_code}")
    for item in request.purpose_detail:
        lines.append(f"  outstanding: {item}")
    lines.append(
        f"budget: {request.budget_ref.policy} "
        f"requested_cost={request.budget_ref.requested_cost}"
    )
    lines.append(f"compiler: {request.compiler_version}")
    lines.append(_APPROVAL_DISCLAIMER)
    return "\n".join(lines) + "\n"


__all__ = [
    "ALLOWED_METHODS",
    "BUDGET_POLICY_REF",
    "GENERIC_PURPOSE",
    "COMPILER_VERSION",
    "PURPOSE_FOR_CATEGORY",
    "REFUSAL_CODES",
    "REQUESTED_COST",
    "AuthorizationRequestDraft",
    "BudgetReference",
    "CompileOutcome",
    "compile_authorization_request",
    "purpose_for",
    "render_approval_sheet",
    "serialize_request",
]
