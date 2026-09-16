"""Stage R80 deterministic research evidence submission boundary (adapter).

R79 established that the real Indeed case has no genuine stored
METHOD_AUTH / RESPONSE_BEHAVIOR evidence, so the next problem is the
submission boundary: how does an authorized researcher safely hand
externally acquired evidence to Watch?

R80 is a **small submission-boundary adapter around the existing R74
contract**. It is not a planner, ranking engine, intelligence layer, readiness
algorithm or state machine, and it does not acquire evidence. The researcher
performs authorized research outside Watch; Watch only receives and processes
the bounded package:

    bounded submission envelope -> case binding -> requirement binding
      -> boundary safety pre-scan -> R74 intake (authoritative)
      -> R75 -> R72 -> R73 -> R76 -> R77 (unchanged authorities)

Authority boundaries:

- R74 remains the authoritative evidence intake: R80 validates only the
  submission envelope (version, case binding, requirement binding, submitter
  label, size and the boundary safety pre-scan) and then delegates the items
  to ``ai.knowledge.research_evidence_intake``. The R74 result is returned
  as-is; R80 never re-implements or relaxes R74 rules.
- R75/R72/R73/R76/R77 remain untouched authorities; R80 duplicates none of
  their logic and produces no readiness, provenance, case-state or workbench
  output of its own.
- No new source taxonomy: item sources use the existing R74 vocabulary and
  are validated by R74.
- No persistence, no UI, no target interaction, no Mongo access, no HTTP,
  socket, subprocess, shell or scanner use.

Hard boundaries encoded here:

- Explicit case binding: ``case_ref`` must equal the target case's
  ``case_id``; evidence is never silently redirected to another case.
- Explicit requirement binding: every item's ``requirement_kind`` must be one
  of the target case's current required-evidence kinds (from its R71 plan /
  R72 record), and every ``hypothesis_ref`` must belong to the case.
- Sensitive/execution pre-scan: raw URLs, IPs, Mongo ids, credentials,
  tokens, bearer values, shell/scanner/exploit commands and execution
  instructions are rejected at the boundary before R74 is invoked.
- Non-personal submitter: ``submitted_by`` is an optional bounded label; it
  must not contain email/phone/credential-like content and is never an
  identity store.
- Bounded size: R74's own item bound is reused (never larger).
- Additive and deterministic: inputs are never mutated; the result carries
  ``rule_version = "r80-1"`` and the unchanged safety block.
"""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from ai.knowledge.research_evidence_intake import (
    MAX_PACKAGE_ITEMS,
    intake_and_reevaluate,
)
from ai.knowledge.research_outcome_planner import SAFETY_BLOCK

RULE_VERSION = "r80-1"
SUBMISSION_VERSION = "r80-1"

MAX_SUBMITTER_CHARS = 64
MAX_REF_CHARS = 512
MAX_TEXT_CHARS = 320

# ---------------------------------------------------------------------------
# Closed boundary rejection codes
# ---------------------------------------------------------------------------

ERROR_MALFORMED_ENVELOPE = "MALFORMED_ENVELOPE"
ERROR_UNSUPPORTED_SUBMISSION_VERSION = "UNSUPPORTED_SUBMISSION_VERSION"
ERROR_CASE_REF_REQUIRED = "CASE_REF_REQUIRED"
ERROR_UNKNOWN_CASE = "UNKNOWN_CASE"
ERROR_CASE_MISMATCH = "CASE_MISMATCH"
ERROR_CASE_STATE_UNAVAILABLE = "CASE_STATE_UNAVAILABLE"
ERROR_UNKNOWN_REQUIREMENT_FOR_CASE = "UNKNOWN_REQUIREMENT_FOR_CASE"
ERROR_HYPOTHESIS_NOT_IN_CASE = "HYPOTHESIS_NOT_IN_CASE"
ERROR_SUBMITTER_NOT_ALLOWED = "SUBMITTER_NOT_ALLOWED"
ERROR_SENSITIVE_SUBMISSION = "SENSITIVE_SUBMISSION_REJECTED"
ERROR_EXECUTION_CONTENT = "EXECUTION_CONTENT_REJECTED"
ERROR_SUBMISSION_TOO_LARGE = "SUBMISSION_TOO_LARGE"

REJECTION_CODES: tuple[str, ...] = (
    ERROR_MALFORMED_ENVELOPE,
    ERROR_UNSUPPORTED_SUBMISSION_VERSION,
    ERROR_CASE_REF_REQUIRED,
    ERROR_UNKNOWN_CASE,
    ERROR_CASE_MISMATCH,
    ERROR_CASE_STATE_UNAVAILABLE,
    ERROR_UNKNOWN_REQUIREMENT_FOR_CASE,
    ERROR_HYPOTHESIS_NOT_IN_CASE,
    ERROR_SUBMITTER_NOT_ALLOWED,
    ERROR_SENSITIVE_SUBMISSION,
    ERROR_EXECUTION_CONTENT,
    ERROR_SUBMISSION_TOO_LARGE,
)

STATUS_SUBMISSION_REJECTED = "SUBMISSION_REJECTED"
STATUS_NO_PACKAGE = "NO_PACKAGE"

_URL_RE = re.compile(r"://")
_MONGO_ID_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{24}(?![0-9a-fA-F])")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|session|sessionid|cookie|authorization|bearer)"
    r"\s*[:=]\s*\S+"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]+")
_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_PHONE_RE = re.compile(r"\+?\d[\d\s\-().]{6,}\d")
_EXECUTION_RE = re.compile(
    r"(?i)("
    r"\bcurl\b|\bwget\b|\bnmap\b|\bmasscan\b|\bsqlmap\b|\bnuclei\b|"
    r"\bffuf\b|\bgobuster\b|\bnikto\b|\bmetasploit\b|\bmsfconsole\b|"
    r"\bhydra\b|\bhashcat\b|\bburp\b|\bshell\b|\bcmd\.exe\b|"
    r"\bbash\s+-c\b|\bsh\s+-c\b|\bpowershell\b|\bpython\s+-c\b|"
    r";\s*rm\s|\|\s*sh\b|`[^`]+`|\$\([^)]*\)"
    r")"
)


class EvidenceSubmissionError(ValueError):
    """Deterministic, secret-free R80 submission failure."""

    def __init__(self, code: str, safe_message: str = "") -> None:
        self.code = str(code)
        self.safe_message = " ".join(str(safe_message).split())[:160]
        super().__init__(f"{self.code}: {self.safe_message}")


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _text(value: object) -> str:
    return str(value if value is not None else "").strip()


def _upper(value: object) -> str:
    return _text(value).upper()


def _block(value: object) -> dict:
    return value if isinstance(value, Mapping) else {}


def _mapping_items(value: object) -> list[Mapping]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _is_sensitive(text: str) -> bool:
    return bool(
        _URL_RE.search(text)
        or _MONGO_ID_RE.search(text)
        or _IPV4_RE.search(text)
        or _SECRET_RE.search(text)
        or _BEARER_RE.search(text)
        or _USERINFO_RE.search(text)
    )


def _ref_is_sensitive(ref: str) -> bool:
    _, _, value = _text(ref).partition(":")
    return _is_sensitive(value)


def _is_execution_instruction(text: str) -> bool:
    return bool(_EXECUTION_RE.search(text))


# ---------------------------------------------------------------------------
# Case and requirement binding (read-only over existing stage outputs)
# ---------------------------------------------------------------------------


def _case_requirement_kinds(
    case: Mapping, acquisition_plan: object, readiness_plan: object
) -> set[str] | None:
    """Required-evidence kinds of the case's current R71/R72 state."""

    plan_ref = _text(_block(case.get("acquisition")).get("plan_ref"))
    kinds: set[str] = set()
    for plan in _mapping_items(_block(acquisition_plan).get("plans")):
        if plan_ref and _text(plan.get("plan_id")) != plan_ref:
            continue
        for entry in _mapping_items(plan.get("required_evidence")):
            kind = _upper(entry.get("requirement_kind"))
            if kind:
                kinds.add(kind)
    for record in _mapping_items(_block(readiness_plan).get("records")):
        if plan_ref and _text(record.get("plan_ref")) != plan_ref:
            continue
        for entry in _mapping_items(record.get("required_evidence")):
            kind = _upper(entry.get("requirement_kind"))
            if kind:
                kinds.add(kind)
    return kinds or None


# ---------------------------------------------------------------------------
# Boundary safety pre-scan (early gate; R74 remains authoritative)
# ---------------------------------------------------------------------------


def _scan_boundary_safety(items: Sequence[Mapping]) -> str | None:
    """Return a boundary rejection code for sensitive/execution content."""

    def scan_ref(ref: object) -> bool:
        text = _text(ref)
        return bool(text) and _ref_is_sensitive(text)

    def scan_text(value: object) -> bool:
        text = _text(value)
        if not text:
            return False
        return _is_sensitive(text) or _is_execution_instruction(text)

    execution_hit = False
    for item in items:
        if scan_ref(item.get("evidence_ref")):
            return ERROR_SENSITIVE_SUBMISSION
        for entry in _mapping_items(item.get("observations")):
            if scan_ref(entry.get("ref")):
                return ERROR_SENSITIVE_SUBMISSION
            fact = _text(entry.get("fact"))
            if _is_sensitive(fact):
                return ERROR_SENSITIVE_SUBMISSION
            if _is_execution_instruction(fact):
                execution_hit = True
        for entry in _mapping_items(item.get("derived_signals")):
            name = _text(entry.get("signal"))
            detail = _text(entry.get("detail"))
            if _is_sensitive(name) or _is_sensitive(detail):
                return ERROR_SENSITIVE_SUBMISSION
            if _is_execution_instruction(name) or _is_execution_instruction(
                detail
            ):
                execution_hit = True
        for ref in item.get("invalidates_refs") or ():
            if scan_ref(ref):
                return ERROR_SENSITIVE_SUBMISSION
    return ERROR_EXECUTION_CONTENT if execution_hit else None


# ---------------------------------------------------------------------------
# Submission boundary
# ---------------------------------------------------------------------------


def _rejected(
    code: str,
    *,
    case_ref: str = "",
    submitted_by: str = "",
    item_count: int = 0,
) -> dict:
    return {
        "rule_version": RULE_VERSION,
        "submission_version": SUBMISSION_VERSION,
        "status": STATUS_SUBMISSION_REJECTED,
        "case_ref": case_ref,
        "submitted_by": submitted_by,
        "item_count": item_count,
        "rejections": [{"code": code}],
        "intake": None,
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


def _normalize_submitter(value: object) -> tuple[str, str | None]:
    label = _CONTROL_RE.sub(" ", _text(value))
    label = " ".join(label.split())
    if not label:
        return "", None
    if len(label) > MAX_SUBMITTER_CHARS:
        return "", ERROR_SUBMITTER_NOT_ALLOWED
    if (
        _EMAIL_RE.search(label)
        or _PHONE_RE.search(label)
        or _is_sensitive(label)
    ):
        return "", ERROR_SUBMITTER_NOT_ALLOWED
    return label, None


def submit_research_evidence(
    submission: object = None,
    *,
    case: object = None,
    hypotheses: object = None,
    action_plan: object = None,
    acquisition_plan: object = None,
    readiness_plan: object = None,
) -> dict:
    """Validate one case-bound submission envelope and delegate to R74.

    Returns a bounded submission result with ``status`` (R74 package status or
    ``SUBMISSION_REJECTED``) and the full R74 result under ``intake`` for
    accepted/partial submissions. R74 remains authoritative for evidence
    validation, acceptance and rejection.
    """

    envelope = _block(submission)
    if not isinstance(submission, Mapping):
        return _rejected(ERROR_MALFORMED_ENVELOPE)

    version = _text(envelope.get("submission_version"))
    if version != SUBMISSION_VERSION:
        return _rejected(ERROR_UNSUPPORTED_SUBMISSION_VERSION)

    case_block = _block(case)
    case_id = _text(case_block.get("case_id"))
    if not case_id:
        return _rejected(ERROR_UNKNOWN_CASE)

    case_ref = _text(envelope.get("case_ref"))
    if not case_ref:
        return _rejected(ERROR_CASE_REF_REQUIRED, submitted_by="")
    if case_ref != case_id:
        return _rejected(ERROR_CASE_MISMATCH, case_ref=case_ref)

    submitter, submitter_error = _normalize_submitter(
        envelope.get("submitted_by")
    )
    if submitter_error:
        return _rejected(
            submitter_error, case_ref=case_ref, item_count=0
        )

    items = envelope.get("items")
    if not isinstance(items, (list, tuple)):
        return _rejected(
            ERROR_MALFORMED_ENVELOPE, case_ref=case_ref, submitted_by=submitter
        )
    if not items:
        return _rejected(
            ERROR_MALFORMED_ENVELOPE,
            case_ref=case_ref,
            submitted_by=submitter,
            item_count=0,
        )
    if len(items) > MAX_PACKAGE_ITEMS:
        return _rejected(
            ERROR_SUBMISSION_TOO_LARGE,
            case_ref=case_ref,
            submitted_by=submitter,
            item_count=len(items),
        )
    item_blocks = _mapping_items(items)
    if len(item_blocks) != len(items):
        return _rejected(
            ERROR_MALFORMED_ENVELOPE,
            case_ref=case_ref,
            submitted_by=submitter,
            item_count=len(items),
        )

    allowed_hypotheses = set(
        _text(ref) for ref in case_block.get("hypothesis_refs") or ()
    )
    if not allowed_hypotheses:
        return _rejected(
            ERROR_HYPOTHESIS_NOT_IN_CASE,
            case_ref=case_ref,
            submitted_by=submitter,
            item_count=len(items),
        )
    for item in item_blocks:
        if _text(item.get("hypothesis_ref")) not in allowed_hypotheses:
            return _rejected(
                ERROR_HYPOTHESIS_NOT_IN_CASE,
                case_ref=case_ref,
                submitted_by=submitter,
                item_count=len(items),
            )

    allowed_kinds = _case_requirement_kinds(
        case_block, acquisition_plan, readiness_plan
    )
    if allowed_kinds is None:
        return _rejected(
            ERROR_CASE_STATE_UNAVAILABLE,
            case_ref=case_ref,
            submitted_by=submitter,
            item_count=len(items),
        )
    for item in item_blocks:
        if _upper(item.get("requirement_kind")) not in allowed_kinds:
            return _rejected(
                ERROR_UNKNOWN_REQUIREMENT_FOR_CASE,
                case_ref=case_ref,
                submitted_by=submitter,
                item_count=len(items),
            )

    boundary_code = _scan_boundary_safety(item_blocks)
    if boundary_code:
        return _rejected(
            boundary_code,
            case_ref=case_ref,
            submitted_by=submitter,
            item_count=len(items),
        )

    package = {
        "package_version": "r74-1",
        "items": [dict(item) for item in item_blocks],
    }
    intake = intake_and_reevaluate(
        package,
        hypotheses=hypotheses,
        action_plan=action_plan or None,
        acquisition_plan=acquisition_plan or None,
        readiness_plan=readiness_plan or None,
    )
    return {
        "rule_version": RULE_VERSION,
        "submission_version": SUBMISSION_VERSION,
        "status": _upper(intake.get("package_status")) or "REJECTED",
        "case_ref": case_ref,
        "submitted_by": submitter,
        "item_count": len(item_blocks),
        "rejections": [],
        "intake": intake,
        "safety": dict(SAFETY_BLOCK),
        "advisory": True,
        "research_only": True,
        "confirmation_state": "NOT_CONFIRMED",
    }


__all__ = [
    "RULE_VERSION",
    "SUBMISSION_VERSION",
    "MAX_SUBMITTER_CHARS",
    "MAX_REF_CHARS",
    "MAX_TEXT_CHARS",
    "REJECTION_CODES",
    "STATUS_SUBMISSION_REJECTED",
    "STATUS_NO_PACKAGE",
    "ERROR_MALFORMED_ENVELOPE",
    "ERROR_UNSUPPORTED_SUBMISSION_VERSION",
    "ERROR_CASE_REF_REQUIRED",
    "ERROR_UNKNOWN_CASE",
    "ERROR_CASE_MISMATCH",
    "ERROR_CASE_STATE_UNAVAILABLE",
    "ERROR_UNKNOWN_REQUIREMENT_FOR_CASE",
    "ERROR_HYPOTHESIS_NOT_IN_CASE",
    "ERROR_SUBMITTER_NOT_ALLOWED",
    "ERROR_SENSITIVE_SUBMISSION",
    "ERROR_EXECUTION_CONTENT",
    "ERROR_SUBMISSION_TOO_LARGE",
    "EvidenceSubmissionError",
    "submit_research_evidence",
]
