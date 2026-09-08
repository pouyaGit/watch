"""Sealed stored-XSS round proof (Phase 5I): SUBMIT -> READ -> EXECUTION.

No shortcut. The READ leg is the verified handoff record; its SUBMIT
leg is resolved through the injected verified-read seam by the sealed
``submit_evidence_ref`` (a content hash, never a mutable pointer) and
re-verified from scratch. Ordered gates (ported from the frozen World
A ``_stored_oracle_proof`` semantics, adapted to sealed bytes):

 1. both-legs identity + integrity (SUBMIT re-verified SEALED/complete)
 2. round binding (shared ``sr-`` round_id, sealed submit ref, shared
    derivation identity, provenance lease round equality)
 3. oracle pair validity + executed-identity binding (S/D recomputed
    from the READ execution binding; never trusted from claims)
 4. freshness (seed re-derivation under the sealed execution binding)
 5. same-origin READ (sealed page origin == sealed target origin)
 6. strict temporal ordering (READ started after SUBMIT finished,
    bounded round window; unparseable/reversed/over-window fails closed)
 7. clean READ (no S/D/round-id/payload material in the sealed page URL)
 8. anti-harvest over BOTH legs' sealed pre-execution material
 9. exact E1/E2/E3 over the READ channels (E2 origin = READ origin)

Deterministic outcomes: correct round + complete execution proof =>
CONFIRMED. Wrong round / stale READ / mismatched READ / reflected-only
READ / missing execution / ambiguous pairing => never CONFIRMED: at
most POTENTIAL (STORAGE_ATTRIBUTED) when a genuine acceptance+binding
signal exists, else UNKNOWN. The legacy single-pass ``stored`` shape
caps at POTENTIAL and MUST NEVER confirm.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ai.evidence.builder import verify_record
from ai.evidence.hashing import sha256_hex
from ai.schemas import evidence as ev

from ai.verification.deterministic import xss_oracle
from ai.verification.deterministic.models import IncompleteEvidence
from ai.verification.deterministic.xss_oracle import (
    OracleIdentity,
    derive_oracle_identity,
)

__all__ = [
    "STORED_ROUND_MAX_WINDOW_SECONDS",
    "StoredRoundOutcome",
    "verify_stored_round",
    "submit_accepted",
    "clean_read_ok",
    "round_ordered",
]

#: Deterministic round freshness window (READ started at most this
#: many seconds after SUBMIT finished). No wall clock participates.
STORED_ROUND_MAX_WINDOW_SECONDS = 3600

_SUBMIT_REJECT_BODY_MARKERS = (
    "captcha",
    "invalid csrf",
    "csrf validation failed",
    "csrf token invalid",
    "csrf token mismatch",
    "csrf token expired",
    "missing csrf token",
    "csrf_required",
    "invalid token",
    "token mismatch",
    "token expired",
    "mfa",
    "multi-factor",
)


@dataclass(frozen=True)
class StoredRoundOutcome:
    """Deterministic stored-round classification outcome."""

    confirmed: bool
    storage_attributed: bool
    channels: tuple[str, ...]
    state: str | None
    reason: str


def _parse_instant(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def round_ordered(submit: ev.EvidenceRecord, read: ev.EvidenceRecord) -> bool:
    """Strict temporal ordering over sealed timestamps (no heuristics).

    Unparseable, reversed/equal, or over-window ordering fails closed.
    """
    submit_finished = _parse_instant(submit.finished_at)
    read_started = _parse_instant(read.started_at)
    if submit_finished is None or read_started is None:
        return False
    delta = (read_started - submit_finished).total_seconds()
    if delta <= 0:
        return False
    return delta <= STORED_ROUND_MAX_WINDOW_SECONDS


def submit_accepted(submit: ev.EvidenceRecord) -> tuple[bool, str]:
    """Ported SUBMIT-acceptance gate over sealed HTTP facts.

    Acceptance is a precondition only — never storage proof, never
    confirmation.
    """
    http = submit.http
    if http is None:
        return False, "submit_transport_missing"
    if http.transport_outcome != "responded":
        return False, "submit_transport"
    status = http.response_status
    if status is None:
        return False, "submit_status_missing"
    if status in (401, 403, 407):
        return False, "submit_auth_required"
    if status in (402, 405, 406, 409, 410, 423, 451):
        return False, f"submit_status_{status}"
    if not 200 <= status < 400:
        return False, f"submit_status_{status}"
    body = (http.response_body_sample or "").casefold()
    for marker in _SUBMIT_REJECT_BODY_MARKERS:
        if marker in body:
            if "csrf" in marker or "token" in marker:
                return False, "submit_csrf_required"
            return False, f"submit_rejected_{marker.replace(' ', '_')}"
    return True, "accepted"


def clean_read_ok(
    read: ev.EvidenceRecord, identity: OracleIdentity
) -> bool:
    """Clean-READ invariant over the sealed page URL (re-checked).

    The READ navigation URL must contain none of S, D, or the
    round_id. The executor guarantees clean navigation; this fails
    closed on any violation (defense in depth).
    """
    browser = read.browser
    if browser is None or browser.page_url is None:
        return False
    url = browser.page_url.redacted_url
    needles = (identity.seed, identity.value, browser.round_id or "")
    return not any(needle and needle in url for needle in needles)


def _target_tuple(record: ev.EvidenceRecord) -> tuple:
    target = record.target
    return (
        record.program_name,
        target.program_name,
        target.host,
        target.scheme,
        target.effective_port,
        target.path_scope,
    )


def verify_stored_round(
    read_record: ev.EvidenceRecord,
    *,
    seam: object,
    read_authorization: object | None,
) -> StoredRoundOutcome:
    """Run the ordered stored-round gates over sealed evidence.

    ``seam`` must provide ``read_by_content_hash`` (returns a tuple of
    verified records; anything other than exactly one is ambiguous
    pairing and never guessed).
    """
    browser = read_record.browser
    if browser is None:
        return StoredRoundOutcome(False, False, (), None, "read_browser_missing")

    # -- Gate 2 (first half): round identity on the READ leg. ----------
    round_id = browser.round_id
    if not round_id:
        return StoredRoundOutcome(False, False, (), None, "round_id_missing")
    submit_ref = browser.submit_evidence_ref
    if not submit_ref:
        return StoredRoundOutcome(
            False, False, (), None, "submit_evidence_ref_missing"
        )

    # Provenance lease round equality (when the issuance carries one).
    leases = getattr(read_authorization, "stored_leases", None)
    if leases is not None and leases.round_id != round_id:
        return StoredRoundOutcome(False, False, (), None, "round_lease_mismatch")

    # -- Gate 1: resolve + re-verify the SUBMIT leg. -------------------
    reader = getattr(seam, "read_by_content_hash", None)
    if not callable(reader):
        raise IncompleteEvidence("submit leg seam lacks read_by_content_hash")
    try:
        legs = reader(submit_ref)
    except Exception as exc:
        raise IncompleteEvidence("submit leg unreadable") from exc
    if not isinstance(legs, tuple) or len(legs) != 1:
        return StoredRoundOutcome(
            False, False, (), None, "submit_leg_ambiguous"
        )
    submit = legs[0]
    if not isinstance(submit, ev.EvidenceRecord):
        return StoredRoundOutcome(False, False, (), None, "submit_leg_malformed")
    try:
        verify_record(submit)
    except ev.EvidenceError:
        return StoredRoundOutcome(False, False, (), None, "submit_leg_integrity")
    if submit.lifecycle != "SEALED" or not submit.complete:
        return StoredRoundOutcome(False, False, (), None, "submit_leg_not_sealed")
    if submit.execution_stage != "submit":
        return StoredRoundOutcome(False, False, (), None, "submit_leg_stage")
    if submit.execution_class not in ("http_verification", "browser_verification"):
        return StoredRoundOutcome(False, False, (), None, "submit_leg_class")

    # -- Gate 2 (second half): cross-leg bindings + shared round. -------
    if _target_tuple(submit) != _target_tuple(read_record):
        return StoredRoundOutcome(False, False, (), None, "cross_leg_binding_mismatch")
    if submit.artifact_id != read_record.artifact_id:
        return StoredRoundOutcome(False, False, (), None, "cross_leg_artifact_mismatch")
    if submit.test_plan_id != read_record.test_plan_id:
        return StoredRoundOutcome(False, False, (), None, "cross_leg_plan_mismatch")
    submit_derivation = submit.derivation_binding
    read_derivation = read_record.derivation_binding
    if (
        submit_derivation is None
        or read_derivation is None
        or not submit_derivation.contract_hash
        or not read_derivation.contract_hash
    ):
        return StoredRoundOutcome(
            False, False, (), None, "derivation_identity_mismatch"
        )
    if submit_derivation.execution_phase != "stored_submit":
        return StoredRoundOutcome(False, False, (), None, "submit_phase_mismatch")
    if read_derivation.execution_phase != "stored_read":
        return StoredRoundOutcome(False, False, (), None, "read_phase_mismatch")

    # Shared derivation identity: both legs must be authorized for the
    # SAME source payload artifact and the SAME round. Derivation
    # contract hashes may differ per leg only by phase; each leg's
    # contract hash is integrity-checked against its own issuance.
    reader_authz = getattr(seam, "read_authorization", None)
    if not callable(reader_authz):
        raise IncompleteEvidence("submit leg seam lacks read_authorization")
    try:
        submit_authorization = reader_authz(submit.authorization_id)
    except Exception as exc:
        raise IncompleteEvidence("submit authorization unreadable") from exc
    if submit_authorization is None:
        return StoredRoundOutcome(False, False, (), None, "submit_provenance_missing")
    submit_leases = getattr(submit_authorization, "stored_leases", None)
    if submit_leases is None or submit_leases.round_id != round_id:
        return StoredRoundOutcome(False, False, (), None, "submit_round_lease_mismatch")
    submit_contract = getattr(submit_authorization, "xss_derivation", None)
    if submit_contract is None:
        return StoredRoundOutcome(False, False, (), None, "submit_contract_missing")
    from ai.evidence.hashing import hash_payload

    if hash_payload(submit_contract.model_dump(mode="json")) != (
        submit_derivation.contract_hash
    ):
        return StoredRoundOutcome(False, False, (), None, "submit_contract_mismatch")
    if read_authorization is not None:
        read_contract = getattr(read_authorization, "xss_derivation", None)
        if read_contract is None:
            return StoredRoundOutcome(False, False, (), None, "read_contract_missing")
        if hash_payload(read_contract.model_dump(mode="json")) != (
            read_derivation.contract_hash
        ):
            return StoredRoundOutcome(False, False, (), None, "read_contract_mismatch")
        if (
            submit_contract.source_content_hash
            != read_contract.source_content_hash
            or submit_contract.oracle_version != read_contract.oracle_version
        ):
            return StoredRoundOutcome(
                False, False, (), None, "derivation_identity_mismatch"
            )

    # -- Gates 3/4: oracle identity recomputation (READ-leg owned). ----
    try:
        identity = derive_oracle_identity(read_record)
    except ValueError:
        return StoredRoundOutcome(False, False, (), None, "oracle_identity_invalid")
    executed = read_derivation.executed_payload_hash
    if executed is None or executed != sha256_hex(
        identity.value.encode("utf-8")
    ):
        return StoredRoundOutcome(False, False, (), None, "executed_identity_mismatch")

    # -- Gate 5: same-origin READ (sealed page vs sealed target). ------
    target = read_record.target
    endpoint_origin = (target.scheme, target.host, str(target.effective_port))
    page = browser.page_url
    if page is None:
        return StoredRoundOutcome(False, False, (), None, "read_page_missing")
    if xss_oracle.page_origin(page.redacted_url) != endpoint_origin:
        return StoredRoundOutcome(False, False, (), None, "read_origin_mismatch")

    # -- Gate 6: strict temporal ordering. ------------------------------
    if not round_ordered(submit, read_record):
        return StoredRoundOutcome(False, False, (), None, "read_stale_or_unordered")

    # -- Gate 7: clean READ. --------------------------------------------
    if not clean_read_ok(read_record, identity):
        return StoredRoundOutcome(False, False, (), None, "read_not_clean")

    # -- Gate 8: anti-harvest across BOTH legs. -------------------------
    violations = xss_oracle.sealed_anti_harvest_violations(identity, read_record)
    violations += xss_oracle.sealed_anti_harvest_violations(identity, submit)
    if violations:
        return StoredRoundOutcome(False, False, (), None, "anti_harvest_violation")

    # -- Gate 9: exact E1/E2/E3 over READ channels. ---------------------
    channels: list[str] = []
    if xss_oracle.evaluate_sealed_e1(browser, identity.value):
        channels.append("E1")
    if xss_oracle.evaluate_sealed_e2(
        browser, identity.value, endpoint_origin=endpoint_origin
    ):
        channels.append("E2")
    if xss_oracle.evaluate_sealed_e3(
        browser,
        identity,
        read_authorization,
        execution_id=read_record.execution_id,
    ):
        channels.append("E3")
    if not channels:
        # Accepted + bound + clean + ordered but NO execution proof:
        # storage-attributed POTENTIAL ceiling, never CONFIRMED.
        accepted, _signal = submit_accepted(submit)
        if accepted:
            return StoredRoundOutcome(
                False, True, (), "STORAGE_ATTRIBUTED", "read_execution_missing"
            )
        return StoredRoundOutcome(
            False, False, (), None, "read_execution_missing"
        )
    accepted, _signal = submit_accepted(submit)
    if not accepted:
        return StoredRoundOutcome(
            False, False, (), None, "submit_not_accepted"
        )
    channels = sorted(channels)
    state = (
        "OBSERVABLE_EFFECT" if "E2" in channels else "JAVASCRIPT_EXECUTION"
    )
    return StoredRoundOutcome(
        True, False, tuple(channels), state, "stored_round_execution_proof"
    )
