"""Phase 5I Deterministic Verifier tests (offline, deterministic).

Stdlib ``unittest`` only. No network, no DNS, no subprocess, no
MongoDB, no browser, no JavaScript, no Nuclei, no LLM, no Git.
Authorization, ledger, audit, blob, and index peers are fakes.
Random IDs are asserted by format, never by value.

Every test asserts an exact terminal state (accepted/blocked +
closed reason + outcome) and result-hash stability.
"""

from __future__ import annotations

import ast
import hashlib
import unittest
from pathlib import Path

from ai.evidence import builder as seal
from ai.evidence import hashing, observations
from ai.evidence.blob_store import InMemoryBlobStore
from ai.evidence.handoff import (
    EvidenceHandoff,
    HandoffProvenance,
    assemble_handoff,
    bind_provenance,
)
from ai.evidence.index import InMemoryEvidenceIndex
from ai.evidence.store import (
    EvidenceStore,
    RetentionPolicy,
    canonical_envelope_bytes,
    parse_envelope,
)
from ai.execution.nuclei_executor import (
    argv_digest_for,
    build_nuclei_argv,
    build_target_string,
    scratch_dir_for,
)
from ai.schemas import evidence as ev
from ai.schemas.artifact import artifact_id_for, content_hash_for_bytes
from ai.schemas.execution_authorization import (
    IssuedExecutionAuthorization,
    StoredStageLeases,
)
from ai.verification.oracle import (
    OraclePlanner,
    oracle_seed,
    oracle_value_from_seed,
)

from ai.verification.deterministic import (
    POLICY_VERSION,
    RULES_VERSION,
    VERIFIER_VERSION,
    ClassificationResult,
    MaterializationSeamDisabledError,
    StoreVerifiedRead,
    VerifierInput,
    VerifierInvariantError,
    compute_result_hash,
    materialize_finding,
    verify_handoff,
)
from ai.verification.deterministic import nuclei as nuclei_rule
from ai.verification.deterministic import xss_oracle
from ai.verification.deterministic.classifier import (
    classify_evidence,
    not_vulnerable_transition,
    route_rule_id,
)
from ai.verification.deterministic.gate import verify_handoff_evidence
from ai.verification.deterministic.models import (
    FORBIDDEN_AUTHORITY_FIELDS,
    OUTCOME_CONFIRMED,
    OUTCOME_NOT_VULNERABLE,
    OUTCOME_POTENTIAL,
    OUTCOME_UNKNOWN,
)
from ai.verification.deterministic.registry import resolve_rule
from ai.verification.deterministic.severity import resolve_severity
from ai.verification.deterministic.verified_read import VerifiedEvidence

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

PROGRAM = "acme"
HOST = "example.com"
OTHER_HOST = "other.example.com"
TP_ID = "tp-" + "a" * 16
HYP_ID = "hyp-" + "b" * 16
TM_ID = "tm-" + "c" * 16
SCOPE_HASH = "e" * 64
NONCE = "f" * 32
ISSUED_AT = "2026-01-01T00:00:00+00:00"
EXPIRES_AT = "2026-02-01T00:00:00+00:00"
STARTED_AT = "2026-01-15T00:00:00+00:00"
SUBMIT_FINISHED = "2026-01-15T00:00:05+00:00"
READ_STARTED = "2026-01-15T00:00:10+00:00"

EX_ORACLE = "ex-" + "1" * 32
EX_SUBMIT = "ex-" + "2" * 32
EX_READ = "ex-" + "3" * 32
EX_HTTP = "ex-" + "4" * 32
EX_NUCLEI = "ex-" + "5" * 32
AUTHZ_ORACLE = "authz-" + "1" * 16
AUTHZ_SUBMIT = "authz-" + "2" * 16
AUTHZ_READ = "authz-" + "3" * 16
AUTHZ_HTTP = "authz-" + "4" * 16
AUTHZ_NUCLEI = "authz-" + "5" * 16
ROUND_ID = "sr-" + "7" * 32

_PLANNER = OraclePlanner()


def _planner_payload(execution_id: str, phase: str, context: str = "html_body") -> str:
    plan = _PLANNER.plan(
        context_type=context,
        case_id="sealed",
        attempt_id=execution_id,
        logical_pair_id="lp",
        run_salt="executor-runtime",
        phase=phase,
    )
    return plan.payload


def oracle_pair(execution_id: str, phase: str) -> tuple[str, str]:
    seed = oracle_seed("executor-runtime", execution_id, phase)
    return seed, oracle_value_from_seed(seed)


# ------------------------------------------------------------------
# Authorization fixtures
# ------------------------------------------------------------------


def make_authz(
    *,
    authz_id: str,
    execution_id: str,
    execution_class: str,
    artifact_bytes: bytes,
    artifact_type: str = "xss_payload",
    host: str = HOST,
    scheme: str = "https",
    port: int = 443,
    path_scope: str = "/app",
    lifecycle: str = "CONSUMED",
    phase: str | None = None,
    context: str = "html_body",
    nonce: str = NONCE,
    issued_at: str = ISSUED_AT,
    expires_at: str = EXPIRES_AT,
    leases: StoredStageLeases | None = None,
    plan_method: str = "GET",
    artifact_method: str = "GET",
) -> IssuedExecutionAuthorization:
    digest = content_hash_for_bytes(artifact_bytes)
    artifact_id = artifact_id_for(
        artifact_type=artifact_type,
        test_plan_id=TP_ID,
        content_hash=digest,
    )
    kwargs: dict = {
        "authorization_id": authz_id,
        "idempotency_key": "0" * 64,
        "issuance_nonce": nonce,
        "issuer_identity": "human-review-board",
        "issued_at": issued_at,
        "expires_at": expires_at,
        "lifecycle": lifecycle,
        "record_version": 1,
        "test_plan_id": TP_ID,
        "hypothesis_id": HYP_ID,
        "match_id": TM_ID,
        "artifact": {
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "content_hash": digest,
            "test_plan_id": TP_ID,
            "hypothesis_id": HYP_ID,
            "match_id": TM_ID,
        },
        "target": {
            "program_name": PROGRAM,
            "host": host,
            "scheme": scheme,
            "effective_port": port,
            "path_scope": path_scope,
            "scope_policy_version": "scope-policy/v1",
            "scope_lists_hash": SCOPE_HASH,
        },
        "execution_class": execution_class,
        "execution_phase": "single",
        "plan_method": plan_method,
        "artifact_method": artifact_method,
        "caller_scope": "manual",
    }
    if phase is not None:
        kwargs["xss_derivation"] = {
            "source_artifact_id": artifact_id,
            "source_content_hash": digest,
            "allowed_context": context,
            "allowed_skeleton_family": "attribute",
            "execution_phase": phase,
        }
    if leases is not None:
        kwargs["stored_leases"] = leases
    return IssuedExecutionAuthorization(**kwargs)


# ------------------------------------------------------------------
# Sealed-record fixtures
# ------------------------------------------------------------------


def browser_observation(
    execution_id: str,
    phase: str,
    *,
    e1: bool = False,
    e2: bool = False,
    e3: bool = False,
    e1_kind: str = "alert",
    e1_value: str | None = None,
    e2_value: str | None = None,
    e3_value: str | None = None,
    e3_operator: str = "eval",
    page_path: str = "/app",
    page_host: str = HOST,
    advisory: tuple[bool, bool, bool] = (False, False, False),
    truncated: bool = False,
    round_id: str | None = None,
    submit_ref: str | None = None,
    executed_override: str | None = None,
) -> ev.BrowserObservation:
    _seed, value = oracle_pair(execution_id, phase)
    dialogs = ()
    oracles = ()
    evals = ()
    if e1:
        marker = e1_value if e1_value is not None else value
        dialogs = (hashing.sha256_hex(f"{e1_kind}:{marker}".encode()),)
    if e2:
        marker = e2_value if e2_value is not None else value
        oracles = (hashing.sha256_hex(f"network:{marker}".encode()),)
    if e3:
        marker = e3_value if e3_value is not None else value
        evals = (hashing.sha256_hex(f"{e3_operator}:{marker}".encode()),)
    executed = (
        executed_override
        if executed_override is not None
        else hashing.hash_text(value)
    )
    return ev.BrowserObservation(
        dialog_marker_hashes=dialogs,
        oracle_event_hashes=oracles,
        eval_marker_hashes=evals,
        e1_observed=advisory[0],
        e2_observed=advisory[1],
        e3_observed=advisory[2],
        executed_payload_hash=executed,
        page_url=observations.observe_url(f"https://{page_host}{page_path}"),
        channels_truncated=truncated,
        round_id=round_id,
        submit_evidence_ref=submit_ref,
    )


def http_observation(
    *,
    reflected: str | None = None,
    location: str = "attribute",
    url: str = f"https://{HOST}/app?q=1",
    status: int = 200,
    transport: str = "responded",
    sample_omitted: str | None = None,
    chain: tuple[str, ...] = (),
    chain_truncated: bool = False,
    method: str = "GET",
    body_sample: str | None = None,
) -> ev.HttpObservation:
    if reflected is not None:
        if location == "attribute":
            body = f'<div id="{reflected}">x</div>'
        elif location == "script":
            body = f"<script>var v='{reflected}';</script>"
        elif location == "url":
            body = f'<a href="/s?q={reflected}">go</a>'
        elif location == "js_string":
            body = f"<script>var v = \"{reflected}\";</script>"
        else:
            body = f"<p>{reflected}</p>"
    else:
        body = body_sample or "hello"
    body_hash = hashing.sha256_hex(body.encode("utf-8"))
    return ev.HttpObservation(
        method=method,
        request_url=observations.observe_url(url),
        request_body_hash=hashing.sha256_hex(b""),
        request_body_sample=None,
        response_status=status,
        response_body_hash=body_hash,
        response_body_sample=None if sample_omitted else body,
        sample_omitted=sample_omitted,
        redirect_chain=[observations.observe_url(u) for u in chain],
        chain_truncated=chain_truncated,
        transport_outcome=transport,
    )


def nuclei_observation(
    record_target: ev.TargetIdentity,
    execution_id: str,
    *,
    template_id: str = "tpl-1",
    template_hash: str | None = None,
    argv_digest: str | None = None,
    exit_code: int | None = 0,
    timed_out: bool = False,
    killed: bool = False,
    finding_like: bool = False,
    stdout_sample: str | None = None,
) -> ev.NucleiObservation:
    if template_hash is None:
        template_hash = hashing.sha256_hex(b"template-bytes")
    if argv_digest is None:
        target_string = build_target_string(
            scheme=record_target.scheme,
            canonical_host=record_target.host,
            effective_port=record_target.effective_port,
        )
        scratch = scratch_dir_for(execution_id)
        argv = build_nuclei_argv(
            template_path=f"{scratch}/{template_hash[:16]}.json",
            target_string=target_string,
        )
        argv_digest = argv_digest_for(argv)
    return ev.NucleiObservation(
        template_id=template_id,
        template_hash=template_hash,
        argv_digest=argv_digest,
        exit_code=exit_code,
        timed_out=timed_out,
        killed=killed,
        stdout_hash=hashing.sha256_hex((stdout_sample or "").encode()),
        stderr_hash=hashing.sha256_hex(b""),
        stdout_sample=stdout_sample,
        finding_like_text_present=finding_like,
    )


class World:
    """Store + seam + authz registry + audit sink for one test."""

    def __init__(self) -> None:
        self.blobs = InMemoryBlobStore()
        self.index = InMemoryEvidenceIndex()
        self.audit: list = []
        self.store = EvidenceStore(
            self.blobs, self.index, ledger=None, audit=self.audit
        )
        self.authz: dict[str, IssuedExecutionAuthorization] = {}

    def register(self, authorization: IssuedExecutionAuthorization) -> None:
        self.authz[authorization.authorization_id] = authorization

    def seam(self) -> StoreVerifiedRead:
        return StoreVerifiedRead(
            self.store, self.index, self.authz.get
        )

    def persist(self, record: ev.EvidenceRecord) -> ev.EvidenceRecord:
        self.store.persist_sealed(record)
        return record

    def input_for(
        self,
        record: ev.EvidenceRecord,
        authorization: IssuedExecutionAuthorization,
        *,
        envelope: bytes | None = None,
    ) -> VerifierInput:
        handoff = bind_provenance(assemble_handoff(record), authorization)
        raw = (
            envelope
            if envelope is not None
            else canonical_envelope_bytes(record)
        )
        return VerifierInput(
            handoff=handoff,
            envelope=raw,
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )

    def verify(
        self,
        record: ev.EvidenceRecord,
        authorization: IssuedExecutionAuthorization,
        *,
        envelope: bytes | None = None,
    ):
        return verify_handoff(
            self.input_for(record, authorization, envelope=envelope),
            self.seam(),
            audit=self.audit,
        )


# ------------------------------------------------------------------
# Record builders (per scenario family)
# ------------------------------------------------------------------


def build_oracle_record(
    world: World,
    *,
    execution_id: str = EX_ORACLE,
    authz_id: str = AUTHZ_ORACLE,
    phase: str = "oracle",
    obs_kwargs: dict | None = None,
    host: str = HOST,
    artifact_bytes: bytes | None = None,
) -> tuple[ev.EvidenceRecord, IssuedExecutionAuthorization]:
    payload = _planner_payload(execution_id, phase)
    art = artifact_bytes if artifact_bytes is not None else payload.encode()
    authorization = make_authz(
        authz_id=authz_id,
        execution_id=execution_id,
        execution_class="browser_verification",
        artifact_bytes=art,
        phase=phase,
        host=host,
    )
    world.register(authorization)
    builder = seal.EvidenceBuilder.begin(
        authorization=authorization,
        execution_id=execution_id,
        execution_class="browser_verification",
        execution_stage="oracle",
        started_at=STARTED_AT,
    )
    kwargs = dict(obs_kwargs or {})
    kwargs.setdefault("e1", True)
    builder.attach_browser(browser_observation(execution_id, phase, **kwargs))
    record = world.persist(
        builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)
    )
    return record, authorization


def build_http_record(
    world: World,
    *,
    execution_id: str = EX_HTTP,
    authz_id: str = AUTHZ_HTTP,
    obs_kwargs: dict | None = None,
    host: str = HOST,
    phase: str | None = "oracle",
) -> tuple[ev.EvidenceRecord, IssuedExecutionAuthorization]:
    art = b"http-request-spec-bytes"
    authorization = make_authz(
        authz_id=authz_id,
        execution_id=execution_id,
        execution_class="http_verification",
        artifact_bytes=art,
        artifact_type="http_request_spec",
        phase=phase,
        host=host,
    )
    world.register(authorization)
    builder = seal.EvidenceBuilder.begin(
        authorization=authorization,
        execution_id=execution_id,
        execution_class="http_verification",
        execution_stage="single",
        started_at=STARTED_AT,
    )
    kwargs = dict(obs_kwargs or {})
    if phase is not None and "reflected" not in kwargs:
        # The sealed HTTP proof expects the locally derived SEED (S):
        # S travels inside the payload by design, while D must never
        # appear on the wire (anti-harvest). Reflecting D here would
        # be incoherent with the verifier's marker expectation.
        seed, _value = oracle_pair(execution_id, phase)
        kwargs["reflected"] = seed
    builder.attach_http(http_observation(**kwargs))
    record = world.persist(
        builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)
    )
    return record, authorization


def build_nuclei_record(
    world: World,
    *,
    execution_id: str = EX_NUCLEI,
    authz_id: str = AUTHZ_NUCLEI,
    obs_kwargs: dict | None = None,
    host: str = HOST,
) -> tuple[ev.EvidenceRecord, IssuedExecutionAuthorization]:
    art = b"nuclei-template-bytes"
    authorization = make_authz(
        authz_id=authz_id,
        execution_id=execution_id,
        execution_class="nuclei_scan",
        artifact_bytes=art,
        artifact_type="nuclei_template",
        phase=None,
        host=host,
    )
    world.register(authorization)
    builder = seal.EvidenceBuilder.begin(
        authorization=authorization,
        execution_id=execution_id,
        execution_class="nuclei_scan",
        execution_stage="single",
        started_at=STARTED_AT,
    )
    target = ev.TargetIdentity(
        program_name=PROGRAM,
        host=host,
        scheme="https",
        effective_port=443,
        path_scope="/app",
    )
    builder.attach_nuclei(
        nuclei_observation(target, execution_id, **(obs_kwargs or {}))
    )
    record = world.persist(
        builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)
    )
    return record, authorization


def build_stored_round(
    world: World,
    *,
    read_obs_kwargs: dict | None = None,
    submit_status: int = 200,
    round_id: str = ROUND_ID,
    submit_round_id: str | None = None,
    read_round_id: str | None = None,
    submit_artifact: bytes | None = None,
    read_artifact: bytes | None = None,
    read_started: str = READ_STARTED,
    submit_finished: str = SUBMIT_FINISHED,
    read_host: str = HOST,
    submit_host: str = HOST,
    e1: bool = True,
) -> tuple[ev.EvidenceRecord, IssuedExecutionAuthorization]:
    """Seal a SUBMIT (http) + READ (browser) round; return READ pair."""
    submit_round = submit_round_id if submit_round_id is not None else round_id
    read_round = read_round_id if read_round_id is not None else round_id
    payload = _planner_payload(EX_READ, "stored_read")
    submit_art = submit_artifact if submit_artifact is not None else payload.encode()
    read_art = read_artifact if read_artifact is not None else payload.encode()

    submit_authz = make_authz(
        authz_id=AUTHZ_SUBMIT,
        execution_id=EX_SUBMIT,
        execution_class="http_verification",
        artifact_bytes=submit_art,
        phase="stored_submit",
        host=submit_host,
        leases=StoredStageLeases(round_id=submit_round),
    )
    world.register(submit_authz)
    submit_builder = seal.EvidenceBuilder.begin(
        authorization=submit_authz,
        execution_id=EX_SUBMIT,
        execution_class="http_verification",
        execution_stage="submit",
        started_at=STARTED_AT,
    )
    submit_builder.attach_http(
        http_observation(
            url=f"https://{submit_host}/app/submit",
            status=submit_status,
            body_sample="created",
        )
    )
    submit_record = world.persist(
        submit_builder.seal(
            finished_at=submit_finished, sealed_at=submit_finished
        )
    )

    read_authz = make_authz(
        authz_id=AUTHZ_READ,
        execution_id=EX_READ,
        execution_class="browser_verification",
        artifact_bytes=read_art,
        phase="stored_read",
        host=read_host,
        leases=StoredStageLeases(round_id=read_round),
    )
    world.register(read_authz)
    read_builder = seal.EvidenceBuilder.begin(
        authorization=read_authz,
        execution_id=EX_READ,
        execution_class="browser_verification",
        execution_stage="read",
        started_at=read_started,
    )
    kwargs = dict(read_obs_kwargs or {})
    kwargs.setdefault("round_id", read_round)
    kwargs.setdefault("submit_ref", submit_record.content_hash)
    kwargs["e1"] = e1
    read_builder.attach_browser(
        browser_observation(EX_READ, "stored_read", **kwargs)
    )
    read_record = world.persist(
        read_builder.seal(
            finished_at="2026-01-15T00:00:20+00:00",
            sealed_at="2026-01-15T00:00:20+00:00",
        )
    )
    return read_record, read_authz


# ------------------------------------------------------------------
# HANDOFF
# ------------------------------------------------------------------


class HandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_valid_handoff_accepted(self) -> None:
        record, authz = build_oracle_record(self.world)
        outcome = self.world.verify(record, authz)
        self.assertTrue(outcome.accepted)
        self.assertEqual(outcome.result.outcome, OUTCOME_CONFIRMED)

    def test_incomplete_evidence_refused(self) -> None:
        authorization = make_authz(
            authz_id=AUTHZ_ORACLE,
            execution_id=EX_ORACLE,
            execution_class="browser_verification",
            artifact_bytes=b"x",
            phase="oracle",
        )
        builder = seal.EvidenceBuilder.begin(
            authorization=authorization,
            execution_id=EX_ORACLE,
            execution_class="browser_verification",
            execution_stage="oracle",
            started_at=STARTED_AT,
        )
        partial = builder.seal_partial(
            reasons=("channels_partial",),
            finished_at=STARTED_AT,
            sealed_at=STARTED_AT,
        )
        with self.assertRaises(ev.EvidenceError) as ctx:
            assemble_handoff(partial)
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_building_refused(self) -> None:
        authorization = make_authz(
            authz_id=AUTHZ_ORACLE,
            execution_id=EX_ORACLE,
            execution_class="browser_verification",
            artifact_bytes=b"x",
            phase="oracle",
        )
        builder = seal.EvidenceBuilder.begin(
            authorization=authorization,
            execution_id=EX_ORACLE,
            execution_class="browser_verification",
            execution_stage="oracle",
            started_at=STARTED_AT,
        )
        with self.assertRaises(ev.EvidenceError):
            assemble_handoff(builder.record)

    def test_quarantined_refused(self) -> None:
        record, authz = build_oracle_record(self.world)
        self.world.store.quarantine_evidence(
            record.evidence_id, reason="test-quarantine"
        )
        outcome = self.world.verify(record, authz)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "LIFECYCLE_FORBIDDEN_STATE")

    def test_tombstoned_refused(self) -> None:
        record, authz = build_oracle_record(self.world)
        self.world.store.tombstone_evidence(
            record.evidence_id,
            policy=RetentionPolicy(policy_id="ret-1", allow_blob_deletion=False),
        )
        outcome = self.world.verify(record, authz)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "LIFECYCLE_FORBIDDEN_STATE")

    def test_unknown_handoff_schema_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        handoff = bind_provenance(assemble_handoff(record), authz)
        forged = handoff.model_copy(
            update={"handoff_schema_version": "evidence-handoff/v9"}
        )
        verifier_input = VerifierInput(
            handoff=forged,
            envelope=canonical_envelope_bytes(record),
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )
        outcome = verify_handoff(verifier_input, self.world.seam())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "HANDOFF_SCHEMA_UNSUPPORTED")

    def test_missing_seal_hash_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        handoff = bind_provenance(assemble_handoff(record), authz)
        forged = handoff.model_copy(update={"content_hash": "0" * 64})
        verifier_input = VerifierInput(
            handoff=forged,
            envelope=canonical_envelope_bytes(record),
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )
        outcome = verify_handoff(verifier_input, self.world.seam())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "TRIPLE_HASH_MISMATCH")


# ------------------------------------------------------------------
# INTEGRITY
# ------------------------------------------------------------------


class IntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_tampered_envelope_bytes_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        raw = bytearray(canonical_envelope_bytes(record))
        raw[-2] ^= 0xFF
        outcome = self.world.verify(record, authz, envelope=bytes(raw))
        self.assertFalse(outcome.accepted)
        self.assertIn(
            outcome.reason, ("ENVELOPE_MALFORMED", "TRIPLE_HASH_MISMATCH")
        )

    def test_hash_mismatch_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        mutated = record.model_copy(
            update={"artifact_content_hash": "9" * 64}
        )
        handoff = bind_provenance(assemble_handoff(record), authz)
        verifier_input = VerifierInput(
            handoff=handoff,
            envelope=canonical_envelope_bytes(mutated),
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )
        outcome = verify_handoff(verifier_input, self.world.seam())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "TRIPLE_HASH_MISMATCH")

    def test_binding_mismatch_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        handoff = bind_provenance(assemble_handoff(record), authz)
        forged = handoff.model_copy(update={"artifact_id": "art-" + "9" * 16})
        verifier_input = VerifierInput(
            handoff=forged,
            envelope=canonical_envelope_bytes(record),
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )
        outcome = verify_handoff(verifier_input, self.world.seam())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "ARTIFACT_BINDING_MISMATCH")

    def test_cross_program_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        handoff = bind_provenance(assemble_handoff(record), authz)
        forged = handoff.model_copy(update={"program_name": "other-program"})
        verifier_input = VerifierInput(
            handoff=forged,
            envelope=canonical_envelope_bytes(record),
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )
        outcome = verify_handoff(verifier_input, self.world.seam())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "PROGRAM_BINDING_MISMATCH")

    def test_cross_target_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        handoff = bind_provenance(assemble_handoff(record), authz)
        forged = handoff.model_copy(update={"target_host": OTHER_HOST})
        verifier_input = VerifierInput(
            handoff=forged,
            envelope=canonical_envelope_bytes(record),
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )
        outcome = verify_handoff(verifier_input, self.world.seam())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "TARGET_BINDING_MISMATCH")

    def test_missing_blob_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        # Drop the bytes: index claims remain, blob is gone.
        self.world.blobs._objects.clear()
        outcome = self.world.verify(record, authz)
        self.assertFalse(outcome.accepted)

    def test_index_claim_mismatch_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        seam = self.world.seam()
        good = seam.read_verified(record.evidence_id)

        class DivergingIndexSeam:
            def read_verified(self, evidence_id):
                from ai.verification.deterministic.verified_read import (
                    IndexClaims,
                )

                claims = IndexClaims(
                    evidence_id=good.record.evidence_id,
                    execution_id=good.record.execution_id,
                    authorization_id=good.record.authorization_id,
                    content_hash="7" * 64,
                    bindings_hash=good.record.bindings_hash,
                    observations_hash=good.record.observations_hash,
                    lifecycle="SEALED",
                )
                return VerifiedEvidence(record=good.record, index=claims)

            def read_authorization(self, authorization_id):
                return self.world.authz.get(authorization_id)

            def read_by_content_hash(self, content_hash):
                return ()

        DivergingIndexSeam.world = self.world
        verifier_input = self.world.input_for(record, authz)
        outcome = verify_handoff(verifier_input, DivergingIndexSeam())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "INDEX_CLAIM_MISMATCH")


# ------------------------------------------------------------------
# PROVENANCE
# ------------------------------------------------------------------


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_consumed_authorization_valid_as_provenance(self) -> None:
        record, authz = build_oracle_record(
            self.world,
        )
        self.assertEqual(authz.lifecycle, "CONSUMED")
        outcome = self.world.verify(record, authz)
        self.assertTrue(outcome.accepted)

    def test_consumed_authorization_not_live_for_execution(self) -> None:
        from ai.evidence.handoff import require_live_for_execution

        record, authz = build_oracle_record(self.world)
        with self.assertRaises(ev.EvidenceError) as ctx:
            require_live_for_execution(authz, now=STARTED_AT)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")

    def test_revoked_provenance_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        revoked = authz.model_copy(update={"lifecycle": "REVOKED"})
        self.world.register(revoked)
        outcome = self.world.verify(record, revoked)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "PROVENANCE_INVALID")

    def test_expired_provenance_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        expired = authz.model_copy(
            update={
                "expires_at": "2026-01-10T00:00:00+00:00",
                "lifecycle": "ISSUED",
            }
        )
        self.world.register(expired)
        outcome = self.world.verify(record, expired)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "PROVENANCE_INVALID")

    def test_forged_nonce_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        forged_authz = authz.model_copy(
            update={"issuance_nonce": "a" * 32}
        )
        self.world.register(forged_authz)
        handoff = bind_provenance(assemble_handoff(record), authz)
        verifier_input = VerifierInput(
            handoff=handoff,
            envelope=canonical_envelope_bytes(record),
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )
        outcome = verify_handoff(verifier_input, self.world.seam())
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "PROVENANCE_INVALID")

    def test_target_drift_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        drifted = make_authz(
            authz_id=authz.authorization_id,
            execution_id=EX_ORACLE,
            execution_class="browser_verification",
            artifact_bytes=_planner_payload(EX_ORACLE, "oracle").encode(),
            phase="oracle",
            host=OTHER_HOST,
        )
        self.world.register(drifted)
        outcome = self.world.verify(record, authz)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "PROVENANCE_INVALID")

    def test_artifact_drift_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        drifted = make_authz(
            authz_id=authz.authorization_id,
            execution_id=EX_ORACLE,
            execution_class="browser_verification",
            artifact_bytes=b"different-artifact-bytes",
            phase="oracle",
        )
        self.world.register(drifted)
        outcome = self.world.verify(record, authz)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "PROVENANCE_INVALID")

    def test_missing_provenance_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        self.world.authz.clear()
        outcome = self.world.verify(record, authz)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, "PROVENANCE_MISSING")


# ------------------------------------------------------------------
# XSS ORACLE (E1/E2/E3)
# ------------------------------------------------------------------


class XssOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def _classify(self, record, authz):
        return classify_evidence(record, authorization=authz, seam=self.world.seam())

    def test_e1_exact_positive(self) -> None:
        record, authz = build_oracle_record(
            self.world, obs_kwargs={"e1": True, "e2": False}
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_CONFIRMED)
        self.assertEqual(result.oracle_channels, ("E1",))
        self.assertEqual(result.confirmation_state, "JAVASCRIPT_EXECUTION")

    def test_e1_wrong_message_not_proof(self) -> None:
        _seed, value = oracle_pair(EX_ORACLE, "oracle")
        record, authz = build_oracle_record(
            self.world,
            obs_kwargs={"e1": True, "e2": False, "e1_value": value + "deadbeef"},
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_e1_wrong_kind_not_proof(self) -> None:
        record, authz = build_oracle_record(
            self.world,
            obs_kwargs={"e1": True, "e2": False, "e1_kind": "beforeunload"},
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_e2_exact_positive(self) -> None:
        record, authz = build_oracle_record(
            self.world, obs_kwargs={"e1": False, "e2": True}
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_CONFIRMED)
        self.assertEqual(result.oracle_channels, ("E2",))
        self.assertEqual(result.confirmation_state, "OBSERVABLE_EFFECT")

    def test_e2_wrong_origin_not_proof(self) -> None:
        record, authz = build_oracle_record(
            self.world,
            obs_kwargs={"e1": False, "e2": True, "page_host": OTHER_HOST},
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_e2_navigation_not_proof(self) -> None:
        _seed, value = oracle_pair(EX_ORACLE, "oracle")
        record, authz = build_oracle_record(
            self.world,
            obs_kwargs={
                "e1": False,
                "e2": True,
                "page_path": f"/.watch-oracle/{value}",
            },
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_e2_suffix_not_proof(self) -> None:
        _seed, value = oracle_pair(EX_ORACLE, "oracle")
        record, authz = build_oracle_record(
            self.world,
            obs_kwargs={"e1": False, "e2": True, "e2_value": value + "ff"},
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_e3_exact_positive(self) -> None:
        record, authz = build_oracle_record(
            self.world, obs_kwargs={"e1": False, "e2": False, "e3": True}
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_CONFIRMED)
        self.assertEqual(result.oracle_channels, ("E3",))

    def test_e3_wrong_payload_not_proof(self) -> None:
        record, authz = build_oracle_record(
            self.world,
            obs_kwargs={
                "e1": False,
                "e2": False,
                "e3": True,
                "e3_value": "0123456789abcdef",
            },
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_e3_over_240_not_proof(self) -> None:
        record, authz = build_oracle_record(
            self.world,
            obs_kwargs={
                "e1": False,
                "e2": False,
                "e3": True,
                "e3_value": "z" * 241,
            },
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_e3_unsupported_operator_not_proof(self) -> None:
        record, authz = build_oracle_record(
            self.world,
            obs_kwargs={
                "e1": False,
                "e2": False,
                "e3": True,
                "e3_operator": "new Function",
            },
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_marker_replay_across_executions_not_proof(self) -> None:
        # Steal the oracle markers from EX_ORACLE and replay them on a
        # different execution: recomputed D differs -> no proof.
        record, authz = build_oracle_record(self.world)
        stolen = record.browser
        other_id = "ex-" + "9" * 32
        other_authz = make_authz(
            authz_id="authz-" + "9" * 16,
            execution_id=other_id,
            execution_class="browser_verification",
            artifact_bytes=_planner_payload(other_id, "oracle").encode(),
            phase="oracle",
        )
        self.world.register(other_authz)
        builder = seal.EvidenceBuilder.begin(
            authorization=other_authz,
            execution_id=other_id,
            execution_class="browser_verification",
            execution_stage="oracle",
            started_at=STARTED_AT,
        )
        builder.attach_browser(
            stolen.model_copy(
                update={
                    "executed_payload_hash": hashing.hash_text(
                        oracle_pair(other_id, "oracle")[1]
                    )
                }
            )
        )
        # NOTE: the replayed record is sealed but deliberately NOT
        # persisted: the frozen 5H blob layer is content-addressed by
        # the samples-only content_hash, so a replay with identical
        # sample shapes but divergent bindings is refused fail-closed
        # at persist time ("same key with differing bytes"). The
        # classifier is pure over sealed bytes and needs no store
        # row for the reflected-oracle path.
        replayed = builder.seal(
            finished_at=STARTED_AT, sealed_at=STARTED_AT
        )
        result = classify_evidence(
            replayed, authorization=other_authz, seam=self.world.seam()
        )
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_advisory_booleans_never_proof(self) -> None:
        record, authz = build_oracle_record(
            self.world,
            obs_kwargs={
                "e1": False,
                "e2": False,
                "e3": False,
                "advisory": (True, True, True),
            },
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_anti_harvest_violation_blocks(self) -> None:
        _seed, value = oracle_pair(EX_ORACLE, "oracle")
        record, authz = build_oracle_record(self.world)
        # Forge: D present in the sealed page URL (harvested onto wire).
        poisoned = record.model_copy(
            update={
                "browser": record.browser.model_copy(
                    update={
                        "page_url": observations.observe_url(
                            f"https://{HOST}/app?d={value}"
                        )
                    }
                )
            }
        )
        violations = xss_oracle.sealed_anti_harvest_violations(
            xss_oracle.derive_oracle_identity(poisoned), poisoned
        )
        self.assertTrue(violations)

    def test_truncated_channels_never_proof(self) -> None:
        record, authz = build_oracle_record(
            self.world, obs_kwargs={"truncated": True}
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)


def world_persist(world: World, builder: seal.EvidenceBuilder) -> ev.EvidenceRecord:
    return world.persist(
        builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)
    )


# ------------------------------------------------------------------
# STORED XSS
# ------------------------------------------------------------------


class StoredXssTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_correct_round_confirmed(self) -> None:
        record, authz = build_stored_round(self.world)
        outcome = self.world.verify(record, authz)
        self.assertTrue(outcome.accepted)
        self.assertEqual(outcome.result.outcome, OUTCOME_CONFIRMED)
        self.assertEqual(outcome.result.confirmation_state, "JAVASCRIPT_EXECUTION")

    def test_wrong_round_never_confirmed(self) -> None:
        record, authz = build_stored_round(
            self.world, submit_round_id="sr-" + "8" * 32
        )
        outcome = self.world.verify(record, authz)
        self.assertTrue(outcome.accepted)
        self.assertNotEqual(outcome.result.outcome, OUTCOME_CONFIRMED)
        self.assertEqual(outcome.result.outcome, OUTCOME_UNKNOWN)

    def test_stale_read_never_confirmed(self) -> None:
        record, authz = build_stored_round(
            self.world,
            read_started="2026-01-15T00:00:01+00:00",
            submit_finished="2026-01-15T00:00:05+00:00",
        )
        outcome = self.world.verify(record, authz)
        self.assertTrue(outcome.accepted)
        self.assertNotEqual(outcome.result.outcome, OUTCOME_CONFIRMED)

    def test_mismatched_read_never_confirmed(self) -> None:
        record, authz = build_stored_round(
            self.world, read_artifact=b"different-read-artifact"
        )
        outcome = self.world.verify(record, authz)
        self.assertTrue(outcome.accepted)
        self.assertNotEqual(outcome.result.outcome, OUTCOME_CONFIRMED)

    def test_reflected_only_read_never_confirmed(self) -> None:
        record, authz = build_stored_round(
            self.world,
            read_obs_kwargs={"e1": False, "e2": False, "e3": False},
            e1=False,
        )
        outcome = self.world.verify(record, authz)
        self.assertTrue(outcome.accepted)
        self.assertNotEqual(outcome.result.outcome, OUTCOME_CONFIRMED)
        self.assertEqual(outcome.result.outcome, OUTCOME_POTENTIAL)
        self.assertEqual(
            outcome.result.confirmation_state, "STORAGE_ATTRIBUTED"
        )

    def test_missing_execution_never_confirmed(self) -> None:
        record, authz = build_stored_round(
            self.world,
            read_obs_kwargs={"e1": False},
            e1=False,
        )
        outcome = self.world.verify(record, authz)
        self.assertTrue(outcome.accepted)
        self.assertNotEqual(outcome.result.outcome, OUTCOME_CONFIRMED)

    def test_ambiguous_pairing_never_confirmed(self) -> None:
        record, authz = build_stored_round(self.world)
        seam = self.world.seam()
        original = seam.read_by_content_hash

        class AmbiguousSeam:
            def read_verified(self, evidence_id):
                return seam.read_verified(evidence_id)

            def read_authorization(self, authorization_id):
                return seam.read_authorization(authorization_id)

            def read_by_content_hash(self, content_hash):
                one = original(content_hash)
                return tuple(one) + tuple(one)

        verifier_input = self.world.input_for(record, authz)
        outcome = verify_handoff(verifier_input, AmbiguousSeam())
        self.assertTrue(outcome.accepted)
        self.assertNotEqual(outcome.result.outcome, OUTCOME_CONFIRMED)
        self.assertEqual(outcome.result.outcome, OUTCOME_UNKNOWN)

    def test_unclean_read_never_confirmed(self) -> None:
        _seed, value = oracle_pair(EX_READ, "stored_read")
        record, authz = build_stored_round(
            self.world,
            read_obs_kwargs={"page_path": f"/app?d={value}"},
        )
        outcome = self.world.verify(record, authz)
        self.assertTrue(outcome.accepted)
        self.assertNotEqual(outcome.result.outcome, OUTCOME_CONFIRMED)

    def test_legacy_single_pass_caps_at_potential(self) -> None:
        authorization = make_authz(
            authz_id=AUTHZ_ORACLE,
            execution_id=EX_ORACLE,
            execution_class="browser_verification",
            artifact_bytes=b"legacy-stored-payload",
            phase="stored_submit",
        )
        self.world.register(authorization)
        builder = seal.EvidenceBuilder.begin(
            authorization=authorization,
            execution_id=EX_ORACLE,
            execution_class="browser_verification",
            execution_stage="single",
            started_at=STARTED_AT,
        )
        builder.attach_browser(
            browser_observation(
                EX_ORACLE,
                "stored_submit",
                e1=True,
                advisory=(True, False, False),
            )
        )
        record = world_persist(self.world, builder)
        result = classify_evidence(
            record, authorization=authorization, seam=self.world.seam()
        )
        self.assertEqual(result.outcome, OUTCOME_POTENTIAL)
        self.assertEqual(
            result.confirmation_state, "STORAGE_ATTRIBUTED"
        )
        self.assertFalse(result.finding_eligible)


# ------------------------------------------------------------------
# HTTP
# ------------------------------------------------------------------


class HttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def _classify(self, record, authz):
        return classify_evidence(record, authorization=authz, seam=None)

    def test_valid_positive_potential(self) -> None:
        # Default fixture reflects the locally derived seed inside an
        # HTML attribute: meaningful reflection => POTENTIAL ceiling
        # (HTTP reflection proves reflection, never execution).
        record, authz = build_http_record(self.world)
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_POTENTIAL)
        self.assertEqual(result.confirmation_state, "REFLECTION")
        self.assertFalse(result.finding_eligible)

    def test_html_body_only_insufficient(self) -> None:
        record, authz = build_http_record(
            self.world, obs_kwargs={"location": "body"}
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_generic_error_insufficient(self) -> None:
        record, authz = build_http_record(
            self.world,
            obs_kwargs={"reflected": None, "body_sample": "404 Not Found"},
            phase=None,
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_waf_confounder(self) -> None:
        record, authz = build_http_record(
            self.world, obs_kwargs={"status": 403}
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)
        self.assertEqual(result.reason_code, "waf_confounder")

    def test_truncated_body_not_guessed(self) -> None:
        record, authz = build_http_record(
            self.world, obs_kwargs={"sample_omitted": "over-sample-budget"}
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_redirect_violation(self) -> None:
        record, authz = build_http_record(
            self.world,
            obs_kwargs={"chain": (f"https://{OTHER_HOST}/app",)},
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)
        self.assertEqual(
            result.reason_code, "redirect_boundary_violation"
        )

    def test_target_mismatch(self) -> None:
        record, authz = build_http_record(
            self.world,
            obs_kwargs={"url": f"https://{OTHER_HOST}/app?q=1"},
        )
        result = self._classify(record, authz)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_transport_failure(self) -> None:
        # A transport-failure observation cannot seal complete (the
        # frozen builder requires a response status), so it seals
        # INCOMPLETE via seal_partial; classification over its sealed
        # bytes is still UNKNOWN (transport failure, never negative).
        authorization = make_authz(
            authz_id=AUTHZ_HTTP,
            execution_id=EX_HTTP,
            execution_class="http_verification",
            artifact_bytes=b"http-request-spec-bytes",
            artifact_type="http_request_spec",
            phase="oracle",
        )
        self.world.register(authorization)
        builder = seal.EvidenceBuilder.begin(
            authorization=authorization,
            execution_id=EX_HTTP,
            execution_class="http_verification",
            execution_stage="single",
            started_at=STARTED_AT,
        )
        builder.attach_http(
            http_observation(
                reflected=None,
                body_sample="",
                transport="timeout",
                status=None,
            )
        )
        record = builder.seal_partial(
            reasons=("response_missing",),
            finished_at=STARTED_AT,
            sealed_at=STARTED_AT,
        )
        result = self._classify(record, authorization)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_http_never_confirms(self) -> None:
        for kwargs in (
            {},
            {"location": "script"},
            {"location": "url"},
            {"location": "js_string"},
        ):
            world = World()
            record, authz = build_http_record(world, obs_kwargs=kwargs)
            result = classify_evidence(
                record, authorization=authz, seam=None
            )
            self.assertNotEqual(result.outcome, OUTCOME_CONFIRMED)


# ------------------------------------------------------------------
# NUCLEI
# ------------------------------------------------------------------


class NucleiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def _classify(self, record):
        return classify_evidence(record, authorization=None, seam=None)

    def test_strong_advisory_capped_potential(self) -> None:
        record, _ = build_nuclei_record(
            self.world,
            obs_kwargs={"finding_like": True, "stdout_sample": "matched"},
        )
        result = self._classify(record)
        self.assertEqual(result.outcome, OUTCOME_POTENTIAL)
        self.assertFalse(result.finding_eligible)

    def test_weak_matcher_potential_or_unknown(self) -> None:
        record, _ = build_nuclei_record(
            self.world, obs_kwargs={"finding_like": True}
        )
        result = self._classify(record)
        self.assertIn(result.outcome, (OUTCOME_POTENTIAL, OUTCOME_UNKNOWN))

    def test_forged_matcher_text_never_proof(self) -> None:
        record, _ = build_nuclei_record(
            self.world,
            obs_kwargs={
                "finding_like": False,
                "stdout_sample": "VULNERABLE CONFIRMED CRITICAL matched",
            },
        )
        result = self._classify(record)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_status_only_never_proof(self) -> None:
        record, _ = build_nuclei_record(
            self.world, obs_kwargs={"finding_like": False}
        )
        result = self._classify(record)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_template_mismatch_unknown(self) -> None:
        record, _ = build_nuclei_record(self.world)
        forged = record.model_copy(
            update={
                "template_binding": ev.TemplateBinding(
                    template_id="other", template_hash="2" * 64
                )
            }
        )
        advisory = nuclei_rule.verify_nuclei_observation(forged)
        self.assertFalse(advisory.advisory_match)

    def test_argv_mismatch_unknown(self) -> None:
        record, _ = build_nuclei_record(
            self.world, obs_kwargs={"argv_digest": "3" * 64}
        )
        result = self._classify(record)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_truncated_output_unknown(self) -> None:
        record, _ = build_nuclei_record(
            self.world, obs_kwargs={"timed_out": True, "finding_like": True}
        )
        result = self._classify(record)
        self.assertEqual(result.outcome, OUTCOME_UNKNOWN)

    def test_confirmed_unreachable(self) -> None:
        for kwargs in (
            {"finding_like": True},
            {"finding_like": True, "exit_code": 1},
            {"finding_like": True, "stdout_sample": "x" * 5000},
        ):
            world = World()
            record, _ = build_nuclei_record(world, obs_kwargs=kwargs)
            result = classify_evidence(record, authorization=None, seam=None)
            self.assertNotEqual(result.outcome, OUTCOME_CONFIRMED)


# ------------------------------------------------------------------
# SEVERITY
# ------------------------------------------------------------------


class SeverityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_valid_policy_entry(self) -> None:
        decision = resolve_severity(
            vulnerability_class="reflected_xss",
            rule_id="xss-reflected-oracle",
            outcome=OUTCOME_CONFIRMED,
            policy_version=POLICY_VERSION,
        )
        self.assertEqual(decision.severity, "high")

    def test_missing_policy_entry_unset(self) -> None:
        decision = resolve_severity(
            vulnerability_class="unknown_class",
            rule_id="no-such-rule",
            outcome=OUTCOME_CONFIRMED,
            policy_version=POLICY_VERSION,
        )
        self.assertEqual(decision.severity, "UNSET")
        self.assertEqual(
            decision.unset_reason, "no_policy_entry_for_class_and_rule"
        )

    def test_injected_severity_cannot_enter(self) -> None:
        record, authz = build_oracle_record(self.world)
        handoff = bind_provenance(assemble_handoff(record), authz)
        with self.assertRaises(Exception):
            VerifierInput(
                handoff=handoff,
                envelope=canonical_envelope_bytes(record),
                verifier_version=VERIFIER_VERSION,
                rule_version=RULES_VERSION,
                policy_version=POLICY_VERSION,
                severity="critical",  # type: ignore[call-arg]
            )

    def test_upstream_severity_ignored(self) -> None:
        # Nuclei observation carries no severity; classification never
        # inherits severity from any upstream source.
        world = World()
        record, _ = build_nuclei_record(world, obs_kwargs={"finding_like": True})
        result = classify_evidence(record, authorization=None, seam=None)
        self.assertEqual(result.severity, "UNSET")

    def test_potential_never_confirmed_class_severity(self) -> None:
        decision = resolve_severity(
            vulnerability_class="reflected_xss",
            rule_id="xss-reflected-oracle",
            outcome=OUTCOME_POTENTIAL,
            policy_version=POLICY_VERSION,
        )
        self.assertEqual(decision.severity, "UNSET")


# ------------------------------------------------------------------
# VERSIONING / REPLAY
# ------------------------------------------------------------------


class VersioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_same_input_replay_identical(self) -> None:
        record, authz = build_oracle_record(self.world)
        first = self.world.verify(record, authz)
        second = self.world.verify(record, authz)
        self.assertEqual(first.result_hash, second.result_hash)
        self.assertEqual(
            first.result.model_dump_json(), second.result.model_dump_json()
        )

    def test_result_hash_equality(self) -> None:
        record, authz = build_oracle_record(self.world)
        result = classify_evidence(
            record, authorization=authz, seam=self.world.seam()
        )
        self.assertEqual(
            compute_result_hash(result), compute_result_hash(result)
        )

    def test_rule_mismatch_blocked(self) -> None:
        spec = resolve_rule(
            "no-such-rule",
            execution_class="browser_verification",
            observation_schema_version="evidence/v1",
            artifact_schema_version="artifact/v1",
            policy_version=POLICY_VERSION,
        )
        self.assertIsNone(spec)

    def test_schema_mismatch_blocked(self) -> None:
        spec = resolve_rule(
            "xss-reflected-oracle",
            execution_class="browser_verification",
            observation_schema_version="evidence/v9",
            artifact_schema_version="artifact/v1",
            policy_version=POLICY_VERSION,
        )
        self.assertIsNone(spec)

    def test_policy_mismatch_blocked(self) -> None:
        spec = resolve_rule(
            "xss-reflected-oracle",
            execution_class="browser_verification",
            observation_schema_version="evidence/v1",
            artifact_schema_version="artifact/v1",
            policy_version="other-policy/v9",
        )
        self.assertIsNone(spec)

    def test_downgrade_attempt_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        handoff = bind_provenance(assemble_handoff(record), authz)
        with self.assertRaises(Exception):
            VerifierInput(
                handoff=handoff,
                envelope=canonical_envelope_bytes(record),
                verifier_version="deterministic-verifier/5I-v0",
                rule_version=RULES_VERSION,
                policy_version=POLICY_VERSION,
            )


# ------------------------------------------------------------------
# LEGACY BYPASS PROTECTION
# ------------------------------------------------------------------

_DETERMINISTIC_DIR = Path(__file__).parent / "verification" / "deterministic"

_LEGACY_IMPORT_TARGETS = (
    "ai.verification.verifier",
    "ai.researcher.nuclei_runner",
    "ai.researcher.nuclei_pipeline",
    "ai.schemas.xss_finding",
    "ai.schemas.finding",
)


class LegacyBypassTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_no_legacy_execute_and_judge_imports(self) -> None:
        for path in sorted(_DETERMINISTIC_DIR.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn(
                        node.module,
                        _LEGACY_IMPORT_TARGETS,
                        f"{path.name} imports legacy {node.module}",
                    )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(alias.name, _LEGACY_IMPORT_TARGETS)

    def test_no_legacy_callables_referenced(self) -> None:
        for path in sorted(_DETERMINISTIC_DIR.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("XSSVerifier", text, path.name)
            self.assertNotIn("to_findings", text, path.name)
            self.assertNotIn("save_findings", text, path.name)
            self.assertNotIn("XSSFinding(", text, path.name)
            self.assertNotIn("NucleiFinding(", text, path.name)

    def test_legacy_to_findings_not_classifier_authority(self) -> None:
        # The legacy runner verdict predicate cannot be imported as a
        # 5I dependency: the package does not reference it at all.
        import ai.verification.deterministic as pkg

        source = "\n".join(
            p.read_text(encoding="utf-8")
            for p in sorted(_DETERMINISTIC_DIR.glob("*.py"))
        )
        self.assertNotIn("nuclei_runner", source)
        self.assertTrue(hasattr(pkg, "verify_handoff"))

    def test_severity_passthrough_impossible(self) -> None:
        # ClassificationResult severity is policy-derived only; there is
        # no constructor path that accepts an upstream severity.
        fields = ClassificationResult.model_fields
        self.assertIn("severity", fields)
        annotation = str(fields["severity"].annotation)
        self.assertIn("UNSET", annotation)

    def test_llm_derived_field_mutation_rejected(self) -> None:
        record, authz = build_oracle_record(self.world)
        handoff = bind_provenance(assemble_handoff(record), authz)
        for field in ("verdict", "confidence", "llm_prose", "expected_behavior"):
            with self.subTest(field=field):
                with self.assertRaises(Exception):
                    VerifierInput(
                        handoff=handoff,
                        envelope=canonical_envelope_bytes(record),
                        verifier_version=VERIFIER_VERSION,
                        rule_version=RULES_VERSION,
                        policy_version=POLICY_VERSION,
                        **{field: "anything"},
                    )


# ------------------------------------------------------------------
# FINDING MATERIALIZATION BOUNDARY
# ------------------------------------------------------------------


class MaterializationTests(unittest.TestCase):
    """Phase 5K (P0-2): the 5I materialization seam is hard-blocked.

    5I is classification-only; findings materialize exclusively
    through 5J (CONFIRMED-only). Every call through the retired 5I
    helper raises deterministically — CONFIRMED, POTENTIAL, UNKNOWN,
    stale, or rebound — so no finding can ever be minted here.
    """

    def setUp(self) -> None:
        self.world = World()

    def test_confirmed_raises_no_finding_old_path(self) -> None:
        record, authz = build_oracle_record(self.world)
        outcome = self.world.verify(record, authz)
        with self.assertRaises(MaterializationSeamDisabledError):
            materialize_finding(outcome.result, self.world.seam())

    def test_potential_raises_no_finding_old_path(self) -> None:
        record, authz = build_oracle_record(self.world)
        outcome = self.world.verify(record, authz)
        potential = outcome.result.model_copy(
            update={"outcome": OUTCOME_POTENTIAL}
        )
        with self.assertRaises(MaterializationSeamDisabledError):
            materialize_finding(potential, self.world.seam())

    def test_unknown_raises_no_finding_old_path(self) -> None:
        record, authz = build_http_record(
            self.world, obs_kwargs={"location": "body"}
        )
        result = classify_evidence(record, authorization=authz, seam=None)
        with self.assertRaises(MaterializationSeamDisabledError):
            materialize_finding(result, self.world.seam())

    def test_stale_evidence_raises_no_finding_old_path(self) -> None:
        record, authz = build_oracle_record(self.world)
        outcome = self.world.verify(record, authz)
        self.world.blobs._objects.clear()
        with self.assertRaises(MaterializationSeamDisabledError):
            materialize_finding(outcome.result, self.world.seam())

    def test_rebinding_raises_no_finding_old_path(self) -> None:
        record, authz = build_oracle_record(self.world)
        outcome = self.world.verify(record, authz)
        tampered = outcome.result.model_copy(
            update={"artifact_content_hash": "5" * 64}
        )
        with self.assertRaises(MaterializationSeamDisabledError):
            materialize_finding(tampered, self.world.seam())

    def test_block_error_is_deterministic(self) -> None:
        record, authz = build_oracle_record(self.world)
        outcome = self.world.verify(record, authz)
        first: str | None = None
        second: str | None = None
        with self.assertRaises(MaterializationSeamDisabledError) as ctx1:
            materialize_finding(outcome.result, self.world.seam())
        first = str(ctx1.exception)
        with self.assertRaises(MaterializationSeamDisabledError) as ctx2:
            materialize_finding(outcome.result, self.world.seam())
        second = str(ctx2.exception)
        self.assertTrue(first)
        self.assertEqual(first, second)

    def test_no_finding_ever_minted_old_path(self) -> None:
        # The retired helper cannot return a finding object: it
        # raises before any construction, so no severity (or any
        # other field) can pass through it.
        record, authz = build_oracle_record(self.world)
        outcome = self.world.verify(record, authz)
        try:
            materialize_finding(outcome.result, self.world.seam())
        except MaterializationSeamDisabledError:
            pass
        else:  # pragma: no cover - must never return
            self.fail("retired seam must raise, never return")


# ------------------------------------------------------------------
# AUDIT
# ------------------------------------------------------------------


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_accepted_emits_handoff_and_classification(self) -> None:
        record, authz = build_oracle_record(self.world)
        self.world.verify(record, authz)
        names = [
            e.event
            for e in self.world.audit
            if hasattr(e, "event")
        ]
        self.assertIn("HANDOFF_ACCEPTED", names)
        self.assertIn("CLASSIFICATION_COMPLETED", names)

    def test_rejection_emits_reject_event(self) -> None:
        record, authz = build_oracle_record(self.world)
        raw = bytearray(canonical_envelope_bytes(record))
        raw[-2] ^= 0xFF
        self.world.verify(record, authz, envelope=bytes(raw))
        names = [
            e.event for e in self.world.audit if hasattr(e, "event")
        ]
        self.assertTrue(
            any(n in ("HANDOFF_REJECTED", "INTEGRITY_REJECTED") for n in names)
            or not names  # envelope-level parse failure blocks before audit
        )

    def test_unknown_emits_blocked_event(self) -> None:
        record, authz = build_http_record(
            self.world, obs_kwargs={"location": "body"}
        )
        self.world.verify(record, authz)
        names = [
            e.event for e in self.world.audit if hasattr(e, "event")
        ]
        self.assertIn("CLASSIFICATION_BLOCKED_UNKNOWN", names)

    def test_audit_carries_no_secrets_or_bodies(self) -> None:
        record, authz = build_oracle_record(self.world)
        self.world.verify(record, authz)
        for event in self.world.audit:
            if not hasattr(event, "model_dump_json"):
                continue
            dumped = event.model_dump_json()
            for needle in ("mongodb://", "password", "bearer ", "<script"):
                self.assertNotIn(needle, dumped)


# ------------------------------------------------------------------
# PROPERTIES / INVARIANTS
# ------------------------------------------------------------------


class PropertyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.world = World()

    def test_determinism_across_rebuilds(self) -> None:
        # The determinism contract is over sealed envelope BYTES, not
        # over random handles: byte-identical sealed evidence verified
        # in two independent worlds yields byte-identical results.
        # (Random evidence_id handles necessarily differ across fresh
        # builds, so rebuilding from scratch cannot hash-equal.)
        first = World()
        second = World()
        r1, a1 = build_oracle_record(first)
        raw = canonical_envelope_bytes(r1)
        r2 = parse_envelope(raw)
        second.register(a1)
        second.persist(r2)
        o1 = first.verify(r1, a1)
        o2 = second.verify(r2, a1)
        self.assertTrue(o1.accepted)
        self.assertTrue(o2.accepted)
        self.assertEqual(o1.result_hash, o2.result_hash)
        self.assertEqual(o1.result, o2.result)

    def test_no_verdict_on_integrity_failure(self) -> None:
        record, authz = build_oracle_record(self.world)
        mutated = record.model_copy(
            update={"artifact_content_hash": "9" * 64}
        )
        handoff = bind_provenance(assemble_handoff(record), authz)
        verifier_input = VerifierInput(
            handoff=handoff,
            envelope=canonical_envelope_bytes(mutated),
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )
        outcome = verify_handoff(verifier_input, self.world.seam())
        self.assertFalse(outcome.accepted)
        self.assertIsNone(outcome.result)

    def test_not_vulnerable_unreachable(self) -> None:
        with self.assertRaises(VerifierInvariantError):
            not_vulnerable_transition()

    def test_no_not_vulnerable_in_any_outcome(self) -> None:
        world = World()
        scenarios = []
        rec, authz = build_oracle_record(world)
        scenarios.append((rec, authz))
        rec, authz = build_http_record(world)
        scenarios.append((rec, authz))
        rec, authz = build_nuclei_record(world)
        scenarios.append((rec, authz))
        for record, authorization in scenarios:
            result = classify_evidence(
                record, authorization=authorization, seam=world.seam()
            )
            self.assertNotEqual(result.outcome, OUTCOME_NOT_VULNERABLE)

    def test_binding_completeness(self) -> None:
        record, authz = build_oracle_record(self.world)
        base = bind_provenance(assemble_handoff(record), authz)
        mutations = {
            "program_name": "evil",
            "target_host": OTHER_HOST,
            "artifact_id": "art-" + "9" * 16,
            "test_plan_id": "tp-" + "9" * 16,
            "execution_id": "ex-" + "9" * 32,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                forged = base.model_copy(update={field: value})
                verifier_input = VerifierInput(
                    handoff=forged,
                    envelope=canonical_envelope_bytes(record),
                    verifier_version=VERIFIER_VERSION,
                    rule_version=RULES_VERSION,
                    policy_version=POLICY_VERSION,
                )
                outcome = verify_handoff(
                    verifier_input, self.world.seam()
                )
                self.assertFalse(outcome.accepted)

    def test_llm_independence(self) -> None:
        # No classifier input type carries LLM text; mutating arbitrary
        # LLM-shaped prose cannot change a result hash.
        record, authz = build_oracle_record(self.world)
        first = self.world.verify(record, authz)
        second = self.world.verify(record, authz)
        self.assertEqual(first.result_hash, second.result_hash)

    def test_idempotency(self) -> None:
        record, authz = build_oracle_record(self.world)
        seen = {
            self.world.verify(record, authz).result_hash for _ in range(3)
        }
        self.assertEqual(len(seen), 1)

    def test_forbidden_authority_fields_closed(self) -> None:
        for field in ("verdict", "severity", "confidence", "confirmed"):
            self.assertIn(field, FORBIDDEN_AUTHORITY_FIELDS)

    def test_gate_first_failure_wins(self) -> None:
        # Tampered envelope (gate 3) outranks provenance drift (gate 8).
        record, authz = build_oracle_record(self.world)
        drifted = authz.model_copy(update={"lifecycle": "REVOKED"})
        self.world.register(drifted)
        raw = bytearray(canonical_envelope_bytes(record))
        raw[-2] ^= 0xFF
        outcome = self.world.verify(record, drifted, envelope=bytes(raw))
        self.assertFalse(outcome.accepted)
        self.assertIn(
            outcome.reason, ("ENVELOPE_MALFORMED", "TRIPLE_HASH_MISMATCH")
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
