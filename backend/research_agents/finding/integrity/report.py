"""Evidence-first report contract + the report validation gate
(EPIC11 §9–§15, §18).

The report is assembled from persisted state only.  Every substantive
statement it makes is either (a) a claim whose evaluation is attached, or
(b) an explicit limitation / negative fact.  ``validate_report`` is the
deterministic gate that must pass before a case may reach
``READY_FOR_REVIEW`` — a report with an unsupported confirmed claim, a
dangling evidence reference, an out-of-scope reference, an unsupported
impact/severity, or an unresolved contradiction is BLOCKED with explicit
reasons and never becomes an analyst deliverable.

No subjective scoring exists here: every check is a deterministic
pass/fail over persisted state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.research_agents.finding.integrity import claims as cl
from backend.research_agents.finding.integrity import contracts as ct
from backend.research_agents.finding.integrity import gate as ig
from backend.research_agents.finding.integrity import taxonomy as tx

REPORT_RULE_VERSION = "epic11-report-contract-1"

REPORT_READY = "READY_FOR_REVIEW"
REPORT_BLOCKED = "BLOCKED"

# claim that must be SUPPORTED before a phrase may appear in a report
FORBIDDEN_CLAIM_PHRASES: dict[str, str] = {
    "payload executed": "payload_execution",
    "payload execution confirmed": "payload_execution",
    "execution confirmed": "payload_execution",
    "reflected xss confirmed": "vulnerability_confirmed",
    "xss confirmed": "vulnerability_confirmed",
    "confirmed vulnerability": "vulnerability_confirmed",
    "vulnerable to xss": "vulnerability_confirmed",
    "exploitable": "payload_execution",
    "exploit proven": "payload_execution",
    "reflection confirmed": "reflection_observed",
    "unsafe output context confirmed": "output_context_unsafe",
    "arbitrary javascript execution": "impact_established",
    "account takeover": "impact_established",
    "credential theft": "impact_established",
    "session compromise": "impact_established",
    "data exfiltration": "impact_established",
    "full account access": "impact_established",
    "impact confirmed": "impact_established",
}

SEVERITY_UNASSESSED = "UNASSESSED"
SEVERITY_PROVENANCE_UNASSESSED = "unassessed_no_authoritative_rule"

CHECK_CLAIM_SUPPORT = "claim_support"
CHECK_CONFIRMATION = "confirmation_claim_supported"
CHECK_EVIDENCE_EXISTS = "evidence_references_exist"
CHECK_EVIDENCE_SCOPE = "evidence_within_scope"
CHECK_NO_UNSUPPORTED_CONFIRMED = "no_unsupported_claim_confirmed"
CHECK_STATE_MATCHES_GATE = "state_matches_evidence_gate"
CHECK_SEVERITY = "severity_matches_authoritative_rule"
CHECK_IMPACT = "impact_claims_supported"
CHECK_AUTHORIZATION = "authorization_lineage_present"
CHECK_ADVISORY = "historical_advisory_not_authoritative"
CHECK_LIMITATIONS = "limitations_preserved"
CHECK_CONTRADICTIONS = "no_unresolved_contradictions"
CHECK_CLAIMS_WELLFORMED = "claims_well_formed"
CHECKS: tuple[str, ...] = (
    CHECK_CLAIM_SUPPORT, CHECK_CONFIRMATION, CHECK_EVIDENCE_EXISTS,
    CHECK_EVIDENCE_SCOPE,
    CHECK_NO_UNSUPPORTED_CONFIRMED, CHECK_STATE_MATCHES_GATE,
    CHECK_SEVERITY, CHECK_IMPACT, CHECK_AUTHORIZATION, CHECK_ADVISORY,
    CHECK_LIMITATIONS, CHECK_CONTRADICTIONS, CHECK_CLAIMS_WELLFORMED,
)

_WS = re.compile(r"\s+")


def _norm(text: Any) -> str:
    return _WS.sub(" ", str(text or "").lower()).strip()


def _bounded(value: Any, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


# --------------------------------------------------------------- builder

def build_report(
    *,
    candidate: Any,
    verification: Any,
    decision: ig.IntegrityDecision,
    evaluation: cl.ClaimEvaluation,
    severity: str = SEVERITY_UNASSESSED,
    severity_provenance: str = SEVERITY_PROVENANCE_UNASSESSED,
    severity_authoritative: bool = False,
    endpoint_context: Any = "",
    timeline: Iterable[dict[str, Any]] = (),
    historical_advisory: dict[str, Any] | None = None,
    evidence_jobs: Iterable[str] = (),
    reproduction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the evidence-backed report contract (§9/§10/§11)."""
    state = decision.authoritative_state
    claims = [c.to_dict() for c in evaluation.claims]
    matrix = evaluation.claim_matrix()
    evidence_ids = sorted({str(i.get("evidence_id") or "")
                           for i in evaluation.evidence_items
                           if i.get("evidence_id")})
    by_type: dict[str, int] = {}
    for item in evaluation.evidence_items:
        key = str(item.get("evidence_type") or "")
        by_type[key] = by_type.get(key, 0) + 1

    conclusion = {
        ig.VERIFIED: "Verified by authorized exploitability evidence.",
        ig.VERIFICATION_PENDING:
            "Not verified: required verification evidence is missing "
            f"({decision.gate_reason}).",
        ig.BLOCKED:
            "Blocked: verification could not be authorized/proceeded "
            f"({decision.gate_reason}).",
        ig.REJECTED:
            "Rejected: persisted evidence contradicts the claim "
            f"({decision.gate_reason}).",
    }.get(state, "Not verified.")

    report = {
        "report_id": f"report-{_bounded(getattr(candidate, 'candidate_id',
                                                ''), 40)}",
        "rule_version": REPORT_RULE_VERSION,
        "generated_from": "persisted_evidence_and_gate_records",
        "executive_conclusion": {
            "state": state,
            "statement": conclusion,
            "stage_reached": evaluation.stage_reached,
            "stage_label": tx.STAGE_LABELS.get(evaluation.stage_reached,
                                               "no evidence"),
            "confirmed": state == ig.VERIFIED,
            "advisory_influence": "none",
        },
        "evidence_summary": {
            "unique_observations": evaluation.unique_observations,
            "duplicate_evidence_events": evaluation.duplicate_events,
            "evidence_by_type": dict(sorted(by_type.items())),
            "evidence_ids": evidence_ids[:60],
            "evidence_jobs": [str(j) for j in evidence_jobs][:10],
            "authoritative_gate_reason": decision.gate_reason,
            "runtime_gate_reason": str(
                getattr(decision, "runtime_gate_reason", "") or ""),
            "runtime_gate_claimed_case": bool(
                getattr(decision, "runtime_gate_claimed_case", False)),
        },
        "claim_evidence_matrix": matrix,
        "claims": claims,
        "reproduction_verification_details": dict(
            reproduction or {
                "verification_id": str(getattr(verification,
                                               "verification_id", "")),
                "verification_state": str(getattr(verification, "state", "")),
                "verification_job": str(getattr(verification, "job_id", "")),
                "plan_ids": list(getattr(verification, "plan_ids", ()) or []),
                "authorization_ids": list(
                    getattr(verification, "authorization_ids", ()) or []),
                "observation_ids": list(
                    getattr(verification, "observation_ids", ()) or []),
                "payload_execution_performed": any(
                    i.get("evidence_type") == tx.PAYLOAD_EXECUTION
                    for i in evaluation.evidence_items),
                "note": ("read-only authorized observation; no exploit was "
                         "executed unless a payload-execution evidence row "
                         "is listed above"),
            }),
        "negative_evidence": list(evaluation.negative_evidence),
        "missing_evidence": list(evaluation.missing_evidence),
        # §10/§11/§18: the exact missing evidence TYPES and the malformed
        # input rows (which can never support anything) are first-class
        "missing_evidence_types": list(evaluation.missing_evidence_types),
        "malformed_evidence": list(evaluation.malformed_evidence),
        "authorization_context": dict(evaluation.authorization or {}),
        "limitations": _limitations_of(decision),
        "severity_status": {
            "severity": str(severity or SEVERITY_UNASSESSED),
            "provenance": str(severity_provenance
                              or SEVERITY_PROVENANCE_UNASSESSED),
            "authoritative": bool(severity_authoritative),
            "statement": ("UNASSESSED — no authoritative severity rule "
                          "applies to this claim"
                          if str(severity or SEVERITY_UNASSESSED)
                          == SEVERITY_UNASSESSED else _bounded(severity, 40)),
        },
        "final_disposition": {
            "state": state,
            "gate_reason": decision.gate_reason,
            "blockers": list(getattr(decision, "blockers", ()) or ()),
            "evidence_required_but_missing": list(
                getattr(decision, "missing_evidence_types", None)
                or getattr(decision, "missing_evidence", ()) or ()),
            "missing_evidence_reasons": list(
                getattr(decision, "missing_reasons", ()) or ()),
            "report_status": "",         # filled by validate_report
        },
        "evidence_lineage": {
            "candidate_id": str(getattr(candidate, "candidate_id", "")),
            "scope_ref": str(getattr(candidate, "scope_ref", "")),
            "vulnerability_class": str(getattr(candidate,
                                               "vulnerability_class", "")),
            "contract_id": evaluation.contract_id,
            "claim_rule_version": evaluation.rule_version,
            "gate_rule_version": decision.rule_version,
            "taxonomy_rule_version": tx.TAXONOMY_RULE_VERSION,
            "source_job": str(getattr(candidate, "source_job", "")),
            "verification_job": str(getattr(verification, "job_id", "")),
            "endpoint_context": endpoint_context
            or str(getattr(candidate, "endpoint", "")),
            "timeline": [dict(t) for t in list(timeline)[:40]],
            "evidence_ids": evidence_ids[:60],
        },
        "assertions": [
            {"claim_type": c["claim_type"],
             "asserted_status": c["status"],
             "source": "claim_evaluation"}
            for c in claims
        ],
        "historical_advisory": _advisory_block(historical_advisory),
    }
    return report


def _limitations_of(decision: Any) -> list[str]:
    """Accept both a list of limitations and a single bounded string."""
    raw = getattr(decision, "limitations", None)
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw]
    return [str(raw)]


def _advisory_block(advisory: dict[str, Any] | None) -> dict[str, Any]:
    """Historical LLM advisory: preserved verbatim, never authoritative."""
    if not advisory:
        return {"present": False, "authoritative": False}
    record = dict(advisory)
    return {
        "present": True,
        "authoritative": False,
        "label": "Historical / Advisory Only",
        "disclaimer": ("model output recorded at the time of the run; it is "
                       "not an authoritative security state and must never "
                       "be read as verification"),
        # §22: the recorded advisory state/source/timestamp stay visible
        # verbatim so a historical conflict can be shown, never resolved
        # in favour of the advisory.
        "advisory_state": str(record.get("advisory_state") or ""),
        "source": str(record.get("source") or ""),
        "recorded_at": str(record.get("recorded_at") or ""),
        "text": str(record.get("text") or ""),
        "record": record,
    }


# ------------------------------------------------------------- validation

@dataclass
class ReportValidation:
    status: str = REPORT_BLOCKED
    checks: dict[str, bool] = field(default_factory=dict)
    blockers: list[dict[str, str]] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    unsupported_claims: list[str] = field(default_factory=list)
    unsupported_claim_ids: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    rule_version: str = REPORT_RULE_VERSION

    @property
    def ready(self) -> bool:
        return self.status == REPORT_READY and not self.blockers

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "ready": self.ready,
            "checks": dict(sorted(self.checks.items())),
            "blockers": list(self.blockers),
            "contradictions": list(self.contradictions),
            "unsupported_claims": list(self.unsupported_claims),
            "unsupported_claim_ids": list(self.unsupported_claim_ids),
            "missing_evidence": list(self.missing_evidence),
            "rule_version": self.rule_version,
        }


def _assertion_claims(report: dict[str, Any]) -> list[dict[str, Any]]:
    out = list(report.get("assertions") or [])
    for row in report.get("claims") or []:
        if isinstance(row, dict):
            out.append({"claim_type": row.get("claim_type"),
                        "asserted_status": row.get("status"),
                        "source": "claims"})
    return out


def detect_contradictions(
    report: dict[str, Any],
    *,
    evaluation: cl.ClaimEvaluation,
    authoritative_state: str,
    severity: str = SEVERITY_UNASSESSED,
    severity_authoritative: bool = False,
    historical_advisory: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Deterministic contradictions (§15).  Never picks the louder side."""
    found: list[dict[str, Any]] = []
    supported = {c.claim_type for c in evaluation.claims
                 if c.status == cl.CLAIM_SUPPORTED}
    matrix = report.get("claim_evidence_matrix") or []
    for row in matrix:
        if not isinstance(row, dict):
            continue
        if str(row.get("status")) == cl.CLAIM_SUPPORTED and \
                str(row.get("claim_type")) not in supported:
            found.append({
                "kind": "claim_marked_supported_without_evidence",
                "claim_type": str(row.get("claim_type")),
                "detail": "matrix marks the claim SUPPORTED but the "
                          "evidence evaluation does not support it",
            })

    disposition = str((report.get("final_disposition") or {}).get("state")
                      or "")
    if disposition and disposition != authoritative_state:
        found.append({
            "kind": "report_state_conflicts_with_authoritative_state",
            "detail": f"report says {disposition}, authoritative state is "
                      f"{authoritative_state}",
        })

    body = _norm(" ".join([
        str((report.get("executive_conclusion") or {}).get("statement")),
        str(disposition),
        str((report.get("severity_status") or {}).get("statement")),
        str((report.get("reproduction_verification_details") or {}).get("note")),
    ]))
    for phrase, claim_type in FORBIDDEN_CLAIM_PHRASES.items():
        if phrase in body and claim_type not in supported:
            found.append({
                "kind": "report_asserts_unsupported_claim",
                "claim_type": claim_type,
                "detail": f"report text asserts '{phrase}' while claim "
                          f"{claim_type} is not supported by evidence",
            })

    if str(severity or SEVERITY_UNASSESSED) != SEVERITY_UNASSESSED and \
            not severity_authoritative:
        found.append({
            "kind": "severity_claimed_without_authoritative_rule",
            "detail": f"severity {severity} has no authoritative rule",
        })

    execution_evidence = any(
        i.get("evidence_type") in tx.CONFIRMATION_EVIDENCE
        for i in evaluation.evidence_items)
    if "payload executed" in body and not execution_evidence:
        found.append({
            "kind": "claimed_execution_without_execution_evidence",
            "detail": "report asserts payload execution and the evidence "
                      "set contains no execution event",
        })
    if evaluation.stage_reached < tx.STAGE_REFLECTION and \
            "reflection confirmed" in body:
        found.append({
            "kind": "claimed_reflection_without_reflection_evidence",
            "detail": "report asserts confirmed reflection but only "
                      "parameter-inventory evidence exists",
        })

    if historical_advisory:
        advisory_state = _norm(
            historical_advisory.get("advisory_state")
            or historical_advisory.get("state")
            or historical_advisory.get("verdict") or "")
        if advisory_state and authoritative_state and advisory_state not in (
                _norm(authoritative_state),):
            found.append({
                "kind": "historical_advisory_conflicts_with_current_state",
                "detail": f"historical advisory recorded "
                          f"'{_bounded(advisory_state, 60)}' while the "
                          f"current authoritative state is "
                          f"{authoritative_state}",
                "resolution": "historical advisory is ADVISORY ONLY; the "
                              "authoritative state wins",
            })
    return found


def validate_report(
    report: dict[str, Any],
    *,
    evaluation: cl.ClaimEvaluation,
    authoritative_state: str,
    severity: str = SEVERITY_UNASSESSED,
    severity_provenance: str = SEVERITY_PROVENANCE_UNASSESSED,
    severity_authoritative: bool = False,
    authorization_required: bool = True,
    historical_advisory: dict[str, Any] | None = None,
) -> ReportValidation:
    """The deterministic report validation gate (§14/§15/§18)."""
    checks: dict[str, bool] = {name: True for name in CHECKS}
    blockers: list[dict[str, str]] = []

    def fail(code: str, detail: str, check: str = CHECK_CLAIM_SUPPORT) -> None:
        checks[check] = False
        blockers.append({"code": code, "detail": _bounded(detail, 220)})

    unsupported = [c.claim_id for c in evaluation.claims
                   if c.status != cl.CLAIM_SUPPORTED]
    presented_unsupported = [
        str(row.get("claim_type")) for row in
        (report.get("claim_evidence_matrix") or [])
        if isinstance(row, dict)
        and str(row.get("status")) == cl.CLAIM_SUPPORTED
        and str(row.get("claim_type")) not in {
            c.claim_type for c in evaluation.claims
            if c.status == cl.CLAIM_SUPPORTED}]
    if presented_unsupported:
        fail("unsupported_claims",
             "claims presented as confirmed without evidence: "
             + ",".join(presented_unsupported[:8]))

    # §14/§17.N: a claim the report carries must be well formed and must
    # exist in the authoritative claim set — a missing claim_type, a
    # non-mapping entry or an invented claim is a hard blocker.
    known_types = {c.claim_type for c in evaluation.claims}
    for entry in report.get("claims") or []:
        if not isinstance(entry, dict) or not str(
                entry.get("claim_type") or ""):
            fail("malformed_claim",
                 "report carries a claim without a claim_type",
                 CHECK_CLAIMS_WELLFORMED)
            break
        if str(entry.get("claim_type")) not in known_types and str(
                entry.get("status") or "") == cl.CLAIM_SUPPORTED:
            fail("malformed_claim",
                 f"claim {entry.get('claim_type')} is not part of the "
                 f"authoritative claim set but is marked SUPPORTED",
                 CHECK_CLAIMS_WELLFORMED)
            break

    # the confirmation claim itself must be supported by the evidence
    # evaluation whenever the authoritative state claims VERIFIED
    confirmation = evaluation.confirmation_claim
    if str(authoritative_state) == ig.VERIFIED and (
            confirmation is None
            or confirmation.status != cl.CLAIM_SUPPORTED):
        fail("confirmation_claim_unsupported",
             "authoritative state is VERIFIED but the confirmation claim "
             "is "
             + (confirmation.status if confirmation else "absent"),
             CHECK_CONFIRMATION)

    known_ids = {str(i.get("evidence_id") or "")
                 for i in evaluation.evidence_items}
    referenced: set[str] = set()
    matrix = report.get("claim_evidence_matrix") or []
    for row in matrix:
        if isinstance(row, dict):
            referenced.update(str(e) for e in (row.get("evidence_ids") or []))
    for row in report.get("claims") or []:
        if isinstance(row, dict):
            referenced.update(
                str(e) for e in (row.get("supporting_evidence_ids") or []))
    referenced.update(str(e) for e in
                      ((report.get("evidence_summary") or {})
                       .get("evidence_ids") or []))
    dangling = sorted(e for e in referenced if e and e not in known_ids)
    if dangling:
        fail("missing_evidence_reference",
             "evidence ids referenced but absent from the evidence set: "
             + ",".join(dangling[:8]), CHECK_EVIDENCE_EXISTS)

    allowed_jobs = {str(j) for j in
                    ((report.get("evidence_summary") or {})
                     .get("evidence_jobs") or [])}
    scope_ref = str((report.get("evidence_lineage") or {}).get("scope_ref")
                    or "")
    outside = [i.get("evidence_id") for i in evaluation.evidence_items
               if allowed_jobs and i.get("job_id")
               and str(i.get("job_id")) not in allowed_jobs]
    if outside:
        fail("evidence_outside_authorized_jobs",
             "evidence referenced from jobs outside the candidate's "
             "research/verification jobs: "
             + ",".join(str(x) for x in outside[:6]), CHECK_EVIDENCE_SCOPE)
    if not scope_ref:
        fail("authorization_lineage_missing",
             "no scope reference recorded for this report",
             CHECK_EVIDENCE_SCOPE)

    for row in matrix:
        if isinstance(row, dict) and \
                str(row.get("status")) == cl.CLAIM_SUPPORTED:
            claim_type = str(row.get("claim_type"))
            matching = next((c for c in evaluation.claims
                             if c.claim_type == claim_type), None)
            if matching is None or matching.status != cl.CLAIM_SUPPORTED:
                fail("unsupported_claim_marked_confirmed",
                     f"matrix marks {claim_type} SUPPORTED without "
                     f"evidence",
                     CHECK_NO_UNSUPPORTED_CONFIRMED)
                break

    disposition = str((report.get("final_disposition") or {}).get("state")
                      or "")
    if disposition != authoritative_state:
        fail("state_mismatch",
             f"report disposition {disposition or 'unset'} != authoritative "
             f"{authoritative_state}", CHECK_STATE_MATCHES_GATE)
    conclusion_state = str(
        (report.get("executive_conclusion") or {}).get("state") or "")
    if conclusion_state and conclusion_state != authoritative_state:
        fail("executive_conclusion_mismatch",
             f"executive conclusion says {conclusion_state} while the "
             f"authoritative state is {authoritative_state}",
             CHECK_STATE_MATCHES_GATE)
    if str(authoritative_state) != ig.VERIFIED and bool(
            (report.get("executive_conclusion") or {}).get("confirmed")):
        fail("unsupported_confirmation_in_conclusion",
             "executive conclusion claims a confirmed vulnerability while "
             "the authoritative state is not VERIFIED",
             CHECK_NO_UNSUPPORTED_CONFIRMED)

    if str(severity or SEVERITY_UNASSESSED) != SEVERITY_UNASSESSED and \
            not severity_authoritative:
        fail("severity_not_authoritative",
             f"severity {severity} presented without an authoritative "
             f"rule", CHECK_SEVERITY)
    if str(severity or SEVERITY_UNASSESSED) == SEVERITY_UNASSESSED and \
            str(severity_provenance or SEVERITY_PROVENANCE_UNASSESSED) != \
            SEVERITY_PROVENANCE_UNASSESSED:
        checks[CHECK_SEVERITY] = False
        blockers.append({
            "code": "severity_provenance_without_severity",
            "detail": "severity provenance present while severity is "
                      "UNASSESSED"})

    impact = next((c for c in evaluation.claims
                   if c.claim_type == "impact_established"), None)
    if impact is not None and impact.status == cl.CLAIM_SUPPORTED and \
            not impact.supporting_evidence_ids:
        fail("impact_without_evidence",
             "impact claim supported without evidence ids",
             CHECK_IMPACT)
    # §13: an impact claim ASSERTED BY THE REPORT (model text, hand edit,
    # any source) without evidence is a hard blocker even when the
    # authoritative claim set says otherwise.
    authoritative_impact = (impact.status if impact is not None else
                            cl.CLAIM_UNSUPPORTED)
    for entry in report.get("claims") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("claim_type")) != "impact_established":
            continue
        if str(entry.get("status") or "") == cl.CLAIM_SUPPORTED and (
                not entry.get("supporting_evidence_ids")
                or authoritative_impact != cl.CLAIM_SUPPORTED):
            fail("impact_without_evidence",
                 "report asserts an established impact without supporting "
                 "impact evidence", CHECK_IMPACT)
            break

    authorization = report.get("authorization_context") or {}
    if authorization_required and not authorization.get("present"):
        fail("authorization_context_absent",
             "no authorization context recorded", CHECK_AUTHORIZATION)

    advisory = report.get("historical_advisory") or {}
    if advisory.get("present") and advisory.get("authoritative") is not False:
        fail("historical_advisory_marked_authoritative",
             "historical advisory must never be authoritative",
             CHECK_ADVISORY)

    if not (report.get("limitations") or []):
        fail("limitations_absent", "report carries no limitations",
             CHECK_LIMITATIONS)

    contradictions = detect_contradictions(
        report, evaluation=evaluation, authoritative_state=authoritative_state,
        severity=severity, severity_authoritative=severity_authoritative,
        historical_advisory=historical_advisory)
    # §15: contradictions already established by the claim evaluation
    # (persisted negative evidence refuting a claim) are authoritative and
    # must block — they are never softened into a warning.
    for item in (getattr(evaluation, "contradictions", None) or []):
        if isinstance(item, dict) and item not in contradictions:
            contradictions.append(dict(item))
    blocking = [c for c in contradictions if c.get("kind") !=
                "historical_advisory_conflicts_with_current_state"]
    if blocking:
        checks[CHECK_CONTRADICTIONS] = False
        for item in blocking:
            blockers.append({
                "code": f"contradiction:{item.get('kind')}",
                "detail": _bounded(item.get("detail"), 220)})

    # §14/§18: only a gate-VERIFIED finding can produce a ready-for-review
    # package.  A pending/blocked/rejected report is never "ready", no
    # matter how clean its text is.
    if str(authoritative_state) != ig.VERIFIED:
        fail("report_ready_without_verified_state",
             "report cannot be READY_FOR_REVIEW while the authoritative "
             f"evidence gate state is {authoritative_state} "
             f"({_bounded(getattr(evaluation, 'gate_reason', ''), 80)})",
             CHECK_CONFIRMATION)

    status = REPORT_READY if not blockers else REPORT_BLOCKED
    return ReportValidation(
        status=status,
        checks=checks,
        blockers=blockers,
        contradictions=contradictions,
        unsupported_claims=presented_unsupported,
        unsupported_claim_ids=unsupported,
        missing_evidence=list(evaluation.missing_evidence),
    )


def attach_validation(report: dict[str, Any],
                      validation: ReportValidation) -> dict[str, Any]:
    """Return the report with the validation outcome recorded in place."""
    report = dict(report)
    disposition = dict(report.get("final_disposition") or {})
    disposition["report_status"] = validation.status
    disposition["validation_blockers"] = [b["code"]
                                          for b in validation.blockers]
    report["final_disposition"] = disposition
    report["report_validation"] = validation.to_dict()
    return report


__all__ = [
    "CHECKS", "CHECK_CLAIM_SUPPORT", "CHECK_CONFIRMATION",
    "CHECK_EVIDENCE_EXISTS",
    "CHECK_EVIDENCE_SCOPE", "FORBIDDEN_CLAIM_PHRASES", "REPORT_BLOCKED",
    "REPORT_READY", "REPORT_RULE_VERSION", "ReportValidation",
    "SEVERITY_PROVENANCE_UNASSESSED", "SEVERITY_UNASSESSED",
    "attach_validation", "build_report", "detect_contradictions",
    "validate_report",
]
