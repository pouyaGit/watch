"""Candidate Finding / Verification Objective / Case package models.

A candidate finding is a *research-derived security signal awaiting
verification* — never a verified vulnerability.  ``VERIFIED`` is reachable
only through the authoritative verification gate (finding.gate), which is
built on the existing Evidence Gate primitives.

Scope is mandatory everywhere (rule 15): every model validates a
``watch:scope:``/``fixture:`` prefixed scope_ref at construction.
Severity defaults to ``UNASSESSED`` with explicit provenance — nothing
here may invent severity, exploitability, or CVE applicability (rule 21-23).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

SEVERITY_UNASSESSED = "UNASSESSED"
SEVERITY_PROVENANCE_UNASSESSED = "unassessed_no_authoritative_rule"


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_scope_ref(scope_ref: str) -> str:
    """Explicit authorized scope is mandatory (rule 15/16)."""

    text = str(scope_ref or "").strip()
    if not text:
        raise FindingScopeError("scope_ref is required")
    if not (text.startswith("watch:scope:") or text.startswith("fixture:")):
        raise FindingScopeError(
            f"scope_ref must be watch:scope: or fixture: prefixed: {text[:40]}")
    return text


class FindingScopeError(ValueError):
    pass


class FindingStateError(ValueError):
    pass


class FindingStoreError(ValueError):
    pass


# ---------------------------------------------------------------- candidate

CANDIDATE_STATES: tuple[str, ...] = (
    "DETECTED", "TRIAGED", "NEEDS_EVIDENCE", "VERIFICATION_PLANNED",
    "VERIFICATION_PENDING", "VERIFYING", "VERIFIED", "REJECTED",
    "INCONCLUSIVE", "DUPLICATE", "BLOCKED", "EXPIRED",
)

CANDIDATE_TERMINAL: frozenset[str] = frozenset(
    {"VERIFIED", "REJECTED", "INCONCLUSIVE", "DUPLICATE", "EXPIRED"})

# The gate is the ONLY writer of VERIFIED (validated again in the store).
CANDIDATE_TRANSITIONS: dict[str, frozenset[str]] = {
    "DETECTED": frozenset({"TRIAGED", "DUPLICATE", "BLOCKED", "EXPIRED",
                           "REJECTED"}),
    "TRIAGED": frozenset({"NEEDS_EVIDENCE", "VERIFICATION_PLANNED",
                          "REJECTED", "DUPLICATE", "BLOCKED", "EXPIRED",
                          "INCONCLUSIVE"}),
    "NEEDS_EVIDENCE": frozenset({"VERIFICATION_PLANNED", "DUPLICATE",
                                 "REJECTED", "BLOCKED", "EXPIRED",
                                 "INCONCLUSIVE"}),
    "VERIFICATION_PLANNED": frozenset({"VERIFICATION_PENDING", "DUPLICATE",
                                       "BLOCKED", "EXPIRED", "REJECTED"}),
    "VERIFICATION_PENDING": frozenset({"VERIFYING", "BLOCKED", "EXPIRED",
                                       "REJECTED"}),
    "VERIFYING": frozenset({"VERIFIED", "REJECTED", "INCONCLUSIVE",
                            "BLOCKED", "EXPIRED",
                            "VERIFICATION_PENDING"}),
    "BLOCKED": frozenset({"VERIFICATION_PLANNED", "NEEDS_EVIDENCE",
                          "EXPIRED", "REJECTED"}),
    "VERIFIED": frozenset(),
    "REJECTED": frozenset(),
    "INCONCLUSIVE": frozenset(),
    "DUPLICATE": frozenset(),
    "EXPIRED": frozenset(),
}


@dataclass
class CandidateFinding:
    """One research-derived candidate security signal (Phase 1)."""

    candidate_id: str
    source_job: str
    scope_ref: str                      # mandatory, == verification scope
    vulnerability_class: str            # canonical specialist category
    hypothesis: str
    specialist: str = ""
    source_campaign: str = ""
    source_objective: str = ""
    target: str = ""                    # program/subdomain label, no scheme
    endpoint: str = ""                  # path/endpoint context (no host fetch)
    parameter: str = ""
    lifecycle_state: str = "DETECTED"
    confidence: str = "insufficient"    # provenance: research result only
    confidence_provenance: str = "research_result"
    severity: str = SEVERITY_UNASSESSED
    severity_provenance: str = SEVERITY_PROVENANCE_UNASSESSED
    supporting_signals: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    canonical_id: str = ""              # set when this is a DUPLICATE
    duplicate_of: str = ""              # canonical candidate id
    correlation: dict[str, Any] = field(default_factory=dict)
    verification_ids: list[str] = field(default_factory=list)
    case_id: str = ""                   # case package id ("" = no case)
    provenance: dict[str, Any] = field(default_factory=dict)
    revision: int = 1
    attempts: int = 0
    termination_reason: str = ""
    termination_detail: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        self.scope_ref = validate_scope_ref(self.scope_ref)
        for key in ("candidate_id", "source_job", "vulnerability_class",
                    "hypothesis"):
            if not str(getattr(self, key) or "").strip():
                raise ValueError(f"{key} is required")
        if self.lifecycle_state not in CANDIDATE_STATES:
            raise ValueError(f"unknown candidate state: {self.lifecycle_state!r}")
        # no invented severity: whitelist + provenance required together
        if self.severity != SEVERITY_UNASSESSED and \
                self.severity_provenance == SEVERITY_PROVENANCE_UNASSESSED:
            raise ValueError(
                "severity outside UNASSESSED requires explicit provenance")
        if self.created_at == "":
            self.created_at = utcnow()
        if self.updated_at == "":
            self.updated_at = self.created_at

    @property
    def is_terminal(self) -> bool:
        return self.lifecycle_state in CANDIDATE_TERMINAL

    def transition(self, new_state: str, *, reason: str = "",
                   detail: str = "", now: str | None = None) -> None:
        if self.lifecycle_state in CANDIDATE_TERMINAL:
            raise FindingStateError(
                f"candidate {self.candidate_id} is terminal "
                f"({self.lifecycle_state}); cannot transition to {new_state}")
        allowed = CANDIDATE_TRANSITIONS.get(self.lifecycle_state, frozenset())
        if new_state not in allowed:
            raise FindingStateError(
                f"invalid candidate transition "
                f"{self.lifecycle_state}->{new_state}")
        # VERIFIED is gate-only: reachable from VERIFYING (the post-verification
        # state) — the store re-checks the gate decision before persisting.
        self.lifecycle_state = new_state
        self.revision += 1
        self.updated_at = now or utcnow()
        if new_state in CANDIDATE_TERMINAL:
            self.termination_reason = str(reason)[:400] or new_state.lower()
            self.termination_detail = str(detail)[:400]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source_job": self.source_job,
            "source_campaign": self.source_campaign,
            "source_objective": self.source_objective,
            "specialist": self.specialist,
            "scope_ref": self.scope_ref,
            "target": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "vulnerability_class": self.vulnerability_class,
            "hypothesis": self.hypothesis,
            "lifecycle_state": self.lifecycle_state,
            "confidence": self.confidence,
            "confidence_provenance": self.confidence_provenance,
            "severity": self.severity,
            "severity_provenance": self.severity_provenance,
            "supporting_signals": list(self.supporting_signals),
            "evidence_refs": list(self.evidence_refs),
            "missing_evidence": list(self.missing_evidence),
            "canonical_id": self.canonical_id,
            "duplicate_of": self.duplicate_of,
            "correlation": dict(self.correlation),
            "verification_ids": list(self.verification_ids),
            "case_id": self.case_id,
            "provenance": dict(self.provenance),
            "revision": self.revision,
            "attempts": self.attempts,
            "termination_reason": self.termination_reason,
            "termination_detail": self.termination_detail,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> CandidateFinding:
        # Round-2 production fix: endpoint may be the spec'd dict
        # {url, method, parameter} OR a raw URL string (production rows).
        # str()-ing a dict mangled the round trip and silently broke the
        # correlation shape/parameter signals against loaded rows.
        endpoint_raw = row.get("endpoint")
        endpoint = (dict(endpoint_raw) if isinstance(endpoint_raw, dict)
                    else str(endpoint_raw or ""))
        return cls(
            candidate_id=str(row.get("candidate_id") or ""),
            source_job=str(row.get("source_job") or ""),
            source_campaign=str(row.get("source_campaign") or ""),
            source_objective=str(row.get("source_objective") or ""),
            specialist=str(row.get("specialist") or ""),
            scope_ref=str(row.get("scope_ref") or ""),
            target=str(row.get("target") or ""),
            endpoint=endpoint,
            parameter=str(row.get("parameter") or ""),
            vulnerability_class=str(row.get("vulnerability_class") or ""),
            hypothesis=str(row.get("hypothesis") or ""),
            lifecycle_state=str(row.get("lifecycle_state") or "DETECTED"),
            confidence=str(row.get("confidence") or "insufficient"),
            confidence_provenance=str(
                row.get("confidence_provenance") or "research_result"),
            severity=str(row.get("severity") or SEVERITY_UNASSESSED),
            severity_provenance=str(
                row.get("severity_provenance") or SEVERITY_PROVENANCE_UNASSESSED),
            supporting_signals=list(row.get("supporting_signals") or []),
            evidence_refs=list(row.get("evidence_refs") or []),
            missing_evidence=list(row.get("missing_evidence") or []),
            canonical_id=str(row.get("canonical_id") or ""),
            duplicate_of=str(row.get("duplicate_of") or ""),
            correlation=dict(row.get("correlation") or {}),
            verification_ids=list(row.get("verification_ids") or []),
            case_id=str(row.get("case_id") or ""),
            provenance=dict(row.get("provenance") or {}),
            revision=int(row.get("revision") or 1),
            attempts=int(row.get("attempts") or 0),
            termination_reason=str(row.get("termination_reason") or ""),
            termination_detail=str(row.get("termination_detail") or ""),
            created_at=str(row.get("created_at") or ""),
            updated_at=str(row.get("updated_at") or ""),
        )


# --------------------------------------------------- verification objective

# Candidates in these states may still be folded into a canonical twin.
# Anything else (verification-bound or terminal) is preserved as history.
DEDUPE_STATES: frozenset[str] = frozenset(
    {"DETECTED", "TRIAGED", "NEEDS_EVIDENCE"})


VERIFICATION_STATES: tuple[str, ...] = (
    "CREATED", "READY", "AUTHORIZATION_REQUIRED", "AUTHORIZED", "EXECUTING",
    "WAITING", "VERIFIED", "REJECTED", "INCONCLUSIVE", "BLOCKED", "FAILED",
    "EXPIRED",
)

VERIFICATION_TERMINAL: frozenset[str] = frozenset(
    {"VERIFIED", "REJECTED", "INCONCLUSIVE", "FAILED", "EXPIRED"})

VERIFICATION_TRANSITIONS: dict[str, frozenset[str]] = {
    "CREATED": frozenset({"READY", "EXPIRED", "FAILED", "BLOCKED"}),
    "READY": frozenset({"AUTHORIZATION_REQUIRED", "EXPIRED", "FAILED",
                        "BLOCKED", "REJECTED"}),
    "AUTHORIZATION_REQUIRED": frozenset({"AUTHORIZED", "BLOCKED", "EXPIRED",
                                         "FAILED", "REJECTED"}),
    "AUTHORIZED": frozenset({"EXECUTING", "BLOCKED", "EXPIRED", "FAILED"}),
    "EXECUTING": frozenset({"WAITING", "VERIFIED", "REJECTED",
                            "INCONCLUSIVE", "BLOCKED", "FAILED", "EXPIRED"}),
    "WAITING": frozenset({"EXECUTING", "VERIFIED", "REJECTED",
                          "INCONCLUSIVE", "BLOCKED", "FAILED", "EXPIRED"}),
    "BLOCKED": frozenset({"READY", "AUTHORIZATION_REQUIRED", "EXPIRED",
                          "FAILED"}),
    "VERIFIED": frozenset(),
    "REJECTED": frozenset(),
    "INCONCLUSIVE": frozenset(),
    "FAILED": frozenset(),
    "EXPIRED": frozenset(),
}


@dataclass
class VerificationObjective:
    """Bounded verification run for one candidate (Phase 6)."""

    verification_id: str
    candidate_id: str
    scope_ref: str                       # must equal candidate scope
    vulnerability_class: str
    hypothesis: str
    required_evidence: list[str] = field(default_factory=list)
    current_evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    allowed_observation_types: list[str] = field(default_factory=list)
    state: str = "CREATED"
    budget: dict[str, int] = field(default_factory=dict)
    job_id: str = ""
    plan_ids: list[str] = field(default_factory=list)
    authorization_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    gate_reason: str = ""
    decision: str = ""                   # VERIFIED|REJECTED|INCONCLUSIVE|BLOCKED
    # EPIC11: the authoritative claim-contract outcome for this objective
    # (status/gate_reason/stage/missing evidence/matrix).  Required by the
    # store before ANY VERIFIED transition can be persisted.
    claim_integrity: dict[str, Any] = field(default_factory=dict)
    authoritative_state: str = ""
    missing_evidence_contract: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    revision: int = 1
    attempts: int = 0
    termination_reason: str = ""
    termination_detail: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        self.scope_ref = validate_scope_ref(self.scope_ref)
        for key in ("verification_id", "candidate_id", "hypothesis"):
            if not str(getattr(self, key) or "").strip():
                raise ValueError(f"{key} is required")
        if self.state not in VERIFICATION_STATES:
            raise ValueError(f"unknown verification state: {self.state!r}")
        if self.created_at == "":
            self.created_at = utcnow()
        if self.updated_at == "":
            self.updated_at = self.created_at

    @property
    def is_terminal(self) -> bool:
        return self.state in VERIFICATION_TERMINAL

    def transition(self, new_state: str, *, reason: str = "",
                   detail: str = "", now: str | None = None) -> None:
        if self.state in VERIFICATION_TERMINAL:
            raise FindingStateError(
                f"verification {self.verification_id} is terminal "
                f"({self.state}); cannot transition to {new_state}")
        allowed = VERIFICATION_TRANSITIONS.get(self.state, frozenset())
        if new_state not in allowed:
            raise FindingStateError(
                f"invalid verification transition {self.state}->{new_state}")
        self.state = new_state
        self.revision += 1
        self.updated_at = now or utcnow()
        if new_state in VERIFICATION_TERMINAL:
            self.termination_reason = str(reason)[:400] or new_state.lower()
            self.termination_detail = str(detail)[:400]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "candidate_id": self.candidate_id,
            "scope_ref": self.scope_ref,
            "vulnerability_class": self.vulnerability_class,
            "hypothesis": self.hypothesis,
            "required_evidence": list(self.required_evidence),
            "current_evidence": list(self.current_evidence),
            "missing_evidence": list(self.missing_evidence),
            "allowed_observation_types": list(self.allowed_observation_types),
            "state": self.state,
            "budget": dict(self.budget),
            "job_id": self.job_id,
            "plan_ids": list(self.plan_ids),
            "authorization_ids": list(self.authorization_ids),
            "observation_ids": list(self.observation_ids),
            "gate_reason": self.gate_reason,
            "decision": self.decision,
            "claim_integrity": dict(self.claim_integrity),
            "authoritative_state": self.authoritative_state,
            "missing_evidence_contract": list(self.missing_evidence_contract),
            "provenance": dict(self.provenance),
            "revision": self.revision,
            "attempts": self.attempts,
            "termination_reason": self.termination_reason,
            "termination_detail": self.termination_detail,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> VerificationObjective:
        return cls(
            verification_id=str(row.get("verification_id") or ""),
            candidate_id=str(row.get("candidate_id") or ""),
            scope_ref=str(row.get("scope_ref") or ""),
            vulnerability_class=str(row.get("vulnerability_class") or ""),
            hypothesis=str(row.get("hypothesis") or ""),
            required_evidence=list(row.get("required_evidence") or []),
            current_evidence=list(row.get("current_evidence") or []),
            missing_evidence=list(row.get("missing_evidence") or []),
            allowed_observation_types=list(
                row.get("allowed_observation_types") or []),
            state=str(row.get("state") or "CREATED"),
            budget=dict(row.get("budget") or {}),
            job_id=str(row.get("job_id") or ""),
            plan_ids=list(row.get("plan_ids") or []),
            authorization_ids=list(row.get("authorization_ids") or []),
            observation_ids=list(row.get("observation_ids") or []),
            gate_reason=str(row.get("gate_reason") or ""),
            decision=str(row.get("decision") or ""),
            claim_integrity=dict(row.get("claim_integrity") or {}),
            authoritative_state=str(row.get("authoritative_state") or ""),
            missing_evidence_contract=list(
                row.get("missing_evidence_contract") or []),
            provenance=dict(row.get("provenance") or {}),
            revision=int(row.get("revision") or 1),
            attempts=int(row.get("attempts") or 0),
            termination_reason=str(row.get("termination_reason") or ""),
            termination_detail=str(row.get("termination_detail") or ""),
            created_at=str(row.get("created_at") or ""),
            updated_at=str(row.get("updated_at") or ""),
        )


# ---------------------------------------------------------------- case pkg

CASE_STATES: tuple[str, ...] = (
    "CANDIDATE", "TRIAGED", "VERIFYING", "VERIFICATION_PENDING", "VERIFIED",
    "READY_FOR_REVIEW", "HANDED_OFF", "CLOSED", "REJECTED", "INCONCLUSIVE",
    "DUPLICATE", "BLOCKED",
)

CASE_TERMINAL: frozenset[str] = frozenset(
    {"CLOSED", "REJECTED", "INCONCLUSIVE", "DUPLICATE"})

CASE_TRANSITIONS: dict[str, frozenset[str]] = {
    "CANDIDATE": frozenset({"TRIAGED", "DUPLICATE", "BLOCKED", "CLOSED"}),
    "TRIAGED": frozenset({"VERIFYING", "REJECTED", "DUPLICATE", "BLOCKED",
                          "CLOSED"}),
    "VERIFYING": frozenset({"VERIFIED", "REJECTED", "INCONCLUSIVE",
                            "VERIFICATION_PENDING", "BLOCKED"}),
    # EPIC11: verification ran but the claim contract is not satisfied —
    # the case is parked with the exact missing evidence, NOT closed as a
    # finding.  Re-planning is allowed; nothing here is a "verified" state.
    "VERIFICATION_PENDING": frozenset({"VERIFYING", "BLOCKED", "INCONCLUSIVE",
                                       "REJECTED", "CLOSED"}),
    "VERIFIED": frozenset({"READY_FOR_REVIEW", "BLOCKED", "CLOSED"}),
    "READY_FOR_REVIEW": frozenset({"HANDED_OFF", "BLOCKED", "CLOSED"}),
    "HANDED_OFF": frozenset({"CLOSED"}),
    "BLOCKED": frozenset({"VERIFYING", "TRIAGED", "CLOSED"}),
    "CLOSED": frozenset(),
    "REJECTED": frozenset(),
    "INCONCLUSIVE": frozenset(),
    "DUPLICATE": frozenset(),
}


@dataclass
class CasePackage:
    """Analyst-ready case record (Phase 12/13).

    Cases are NOT forced on every candidate: one is created only when a
    candidate enters verification (store enforces creation state).  Only a
    gate-VERIFIED candidate may move the case to VERIFIED (store re-checks).
    """

    case_id: str
    candidate_id: str
    scope_ref: str
    title: str
    vulnerability_class: str
    target: str = ""
    endpoint: str = ""
    state: str = "TRIAGED"
    severity: str = SEVERITY_UNASSESSED
    severity_provenance: str = SEVERITY_PROVENANCE_UNASSESSED
    verification_id: str = ""
    gate_result: str = ""
    package: dict[str, Any] = field(default_factory=dict)
    # EPIC11: authoritative claim-integrity outcome + the report
    # validation gate result.  A case that cannot pass report validation
    # never reaches READY_FOR_REVIEW.
    claim_integrity: dict[str, Any] = field(default_factory=dict)
    report_validation: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    recommended_next_step: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    revision: int = 1
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        self.scope_ref = validate_scope_ref(self.scope_ref)
        for key in ("case_id", "candidate_id", "title"):
            if not str(getattr(self, key) or "").strip():
                raise ValueError(f"{key} is required")
        if self.state not in CASE_STATES:
            raise ValueError(f"unknown case state: {self.state!r}")
        if self.created_at == "":
            self.created_at = utcnow()
        if self.updated_at == "":
            self.updated_at = self.created_at

    @property
    def is_terminal(self) -> bool:
        return self.state in CASE_TERMINAL

    def transition(self, new_state: str, *, reason: str = "",
                   now: str | None = None) -> None:
        if self.state in CASE_TERMINAL:
            raise FindingStateError(
                f"case {self.case_id} is terminal ({self.state})")
        allowed = CASE_TRANSITIONS.get(self.state, frozenset())
        if new_state not in allowed:
            raise FindingStateError(
                f"invalid case transition {self.state}->{new_state}")
        self.state = new_state
        self.revision += 1
        self.updated_at = now or utcnow()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "candidate_id": self.candidate_id,
            "scope_ref": self.scope_ref,
            "title": self.title,
            "vulnerability_class": self.vulnerability_class,
            "target": self.target,
            "endpoint": self.endpoint,
            "state": self.state,
            "severity": self.severity,
            "severity_provenance": self.severity_provenance,
            "verification_id": self.verification_id,
            "gate_result": self.gate_result,
            "package": dict(self.package),
            "claim_integrity": dict(self.claim_integrity),
            "report_validation": dict(self.report_validation),
            "limitations": list(self.limitations),
            "recommended_next_step": self.recommended_next_step,
            "provenance": dict(self.provenance),
            "revision": self.revision,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> CasePackage:
        # Round-2 production fix (same as CandidateFinding): never str()
        # a dict endpoint — keep the spec'd {url, method, parameter} shape.
        endpoint_raw = row.get("endpoint")
        endpoint = (dict(endpoint_raw) if isinstance(endpoint_raw, dict)
                    else str(endpoint_raw or ""))
        return cls(
            case_id=str(row.get("case_id") or ""),
            candidate_id=str(row.get("candidate_id") or ""),
            scope_ref=str(row.get("scope_ref") or ""),
            title=str(row.get("title") or ""),
            vulnerability_class=str(row.get("vulnerability_class") or ""),
            target=str(row.get("target") or ""),
            endpoint=endpoint,
            state=str(row.get("state") or "TRIAGED"),
            severity=str(row.get("severity") or SEVERITY_UNASSESSED),
            severity_provenance=str(
                row.get("severity_provenance")
                or SEVERITY_PROVENANCE_UNASSESSED),
            verification_id=str(row.get("verification_id") or ""),
            gate_result=str(row.get("gate_result") or ""),
            package=dict(row.get("package") or {}),
            claim_integrity=dict(row.get("claim_integrity") or {}),
            report_validation=dict(row.get("report_validation") or {}),
            limitations=list(row.get("limitations") or []),
            recommended_next_step=str(
                row.get("recommended_next_step") or ""),
            provenance=dict(row.get("provenance") or {}),
            revision=int(row.get("revision") or 1),
            created_at=str(row.get("created_at") or ""),
            updated_at=str(row.get("updated_at") or ""),
        )


def validate_candidate_transition(old: str, new: str) -> None:
    if old in CANDIDATE_TERMINAL:
        raise FindingStateError(f"candidate {old} is terminal")
    if new not in CANDIDATE_TRANSITIONS.get(old, frozenset()):
        raise FindingStateError(f"invalid candidate transition {old}->{new}")


def validate_verification_transition(old: str, new: str) -> None:
    if old in VERIFICATION_TERMINAL:
        raise FindingStateError(f"verification {old} is terminal")
    if new not in VERIFICATION_TRANSITIONS.get(old, frozenset()):
        raise FindingStateError(f"invalid verification transition {old}->{new}")


def validate_case_transition(old: str, new: str) -> None:
    if old in CASE_TERMINAL:
        raise FindingStateError(f"case {old} is terminal")
    if new not in CASE_TRANSITIONS.get(old, frozenset()):
        raise FindingStateError(f"invalid case transition {old}->{new}")
