"""Stage 2 persistence-backed dry-run (B1 + B2 read/persist, no live I/O).

Same authorized chain as Stage 1, but every in-memory-only seam that
has a production counterpart now runs through it:

- 5B issuance/CAS/consume → ``MongoAuthorizationStore`` (B2) over an
  injected driver (``FakeMongoCollection`` in tests; a real
  collection object may be injected by production wiring — the driver
  subset matches that surface exactly).
- Scope policy → ``DictProgramReader``/``MongoProgramReader`` Watch
  rows compiled by the EXISTING ``compile_policy`` (B2 read path);
  5D evaluation itself is unchanged.
- 5C addresses → ``InventoryAddressSource`` over explicit
  ``AddressReview`` facts built from Watch asset rows (B1); the
  existing ``TargetResolver`` + frozen ``validate_answers`` gate are
  unchanged, and no DNS/socket I/O exists anywhere on this path.
- Ledger → ``MongoExecutionLedger`` (B2): claim → consume → start →
  seal transitions with identical at-most-once semantics.
- Audit → ``MongoAuditSink`` (B2): append-only ``AuditRecord`` rows.
- Evidence → ``EvidenceStore`` over ``MongoBlobStore`` +
  ``MongoEvidenceIndex`` (B2): envelopes/hashes/sealing unchanged,
  blob/index separation preserved.
- Orphan sweep → existing ``run_sweep`` over the same mongo-backed
  seams (report mode; no deletion exists anywhere in Stage 2).
- 5I ``verify_handoff`` + 5J ``materialize`` dry-run (in-memory
  finding infra; the finding Mongo adapter stays B2-blocked by
  design — findings are never persisted in Stage 2).

Still fully dry-run: NO live HTTP, NO DNS, NO sockets, NO browser,
NO Nuclei, NO subprocess. ``LIVE_TRAFFIC_ENABLED`` / ``LIVE_NUCLEI``
are asserted ``False``. ``database.db`` is never imported (Watch
rows enter as plain dicts through the duck-typed readers).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ai.authorizer.service import consume_authorization, issue_authorization
from ai.evidence import hashing as hash_mod
from ai.evidence import observations as obs
from ai.evidence.builder import EvidenceBuilder
from ai.evidence.handoff import assemble_handoff, bind_provenance
from ai.evidence.store import EvidenceStore, canonical_envelope_bytes
from ai.evidence.sweep import SweepReport, run_sweep
from ai.audit.trail import AuditRecord
from ai.execution import http_executor as hx
from ai.execution import nuclei_executor as nx
from ai.execution.ledger import ExecutionRecord
from ai.finding.materializer import (
    FindingInfrastructure,
    MaterializationOutcome,
    materialize,
)
from ai.finding.notify import AlertLedgerMemory, RecordingNotificationSink
from ai.finding.store_memory import FindingStoreMemory, WorkflowStoreMemory
from ai.persistence.driver import FakeMongoCollection
from ai.persistence.mongo_audit import MongoAuditSink
from ai.persistence.mongo_authz import MongoAuthorizationStore
from ai.persistence.mongo_evidence import MongoBlobStore, MongoEvidenceIndex
from ai.persistence.mongo_ledger import MongoExecutionLedger
from ai.persistence.watch_reads import (
    DictAssetReader,
    DictProgramReader,
    address_facts_for,
    inventory_records_for,
    policy_for_program,
)
from ai.researcher.artifact_validator import build_validated_reference
from ai.resolver.canonicalization import canonicalize_host
from ai.resolver.inventory import InMemoryInventoryRepository, scope_lists_hash_for
from ai.resolver.inventory_addresses import AddressReview, InventoryAddressSource
from ai.resolver.resolver import TargetResolver
from ai.schemas import evidence as ev
from ai.schemas.artifact import (
    ArtifactReference,
    artifact_id_for,
    content_hash_for_bytes,
)
from ai.schemas.execution_authorization import (
    ArtifactBinding,
    AuthorizationRequest,
    IssuedExecutionAuthorization,
    TargetBinding,
)
from ai.schemas.hypothesis import ResearchProvenance, TargetRef
from ai.schemas.target_resolution import ResolutionRequest
from ai.schemas.test_plan import TestPlan, build_test_plan
from ai.scope.evaluator import ScopeEvaluator
from ai.scope.policy import InMemoryPolicyStore
from ai.scope.policy import InMemoryPolicyStore
from ai.stage1_offline_pipeline import EndpointView
from ai.verification.deterministic.models import (
    POLICY_VERSION,
    RULES_VERSION,
    VERIFIER_VERSION,
    VerifierInput,
)
from ai.verification.deterministic.pipeline import (
    VerificationOutcome,
    verify_handoff,
)
from ai.verification.deterministic.verified_read import StoreVerifiedRead

__all__ = [
    "Stage2Config",
    "Stage2Error",
    "Stage2Result",
    "Stage2Stores",
    "run_stage2_dryrun",
]

STAGE2_ISSUED_AT = "2026-01-01T00:00:00+00:00"
STAGE2_NOW = "2026-01-15T00:00:00+00:00"
STAGE2_EXPIRES_AT = "2026-02-01T00:00:00+00:00"


class Stage2Error(ValueError):
    """Closed Stage 2 orchestration failure (wiring only, never a verdict)."""

    CODES = frozenset(
        {
            "ARTIFACT_NOT_READY",
            "AUTHZ_FAILED",
            "PROGRAM_UNKNOWN",
            "RESOLUTION_FAILED",
            "SCOPE_DENIED",
            "SCOPE_INCONCLUSIVE",
            "SPEC_FAILED",
            "EVIDENCE_FAILED",
            "VERIFY_BLOCKED",
            "LEDGER_FAILED",
            "AUDIT_FAILED",
            "SWEEP_FAILED",
            "LIVE_GATE_VIOLATION",
        }
    )

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in self.CODES:
            raise ValueError(f"unknown stage2 error code: {code!r}")
        safe = (detail or "")[:200]
        if "\n" in safe or "\r" in safe:
            raise ValueError("stage2 error detail must be single-line")
        super().__init__(f"{code}: {safe}" if safe else code)
        self.code = code
        self.detail = safe


@dataclass(frozen=True)
class Stage2Config:
    """Stage 2 wiring (Watch-shaped rows + clocks + drift hook).

    ``program_rows`` mirrors ``Programs`` documents:
    ``{program_name: {"program_name", "scopes", "ooscopes"}}``.
    ``asset_rows`` mirrors ``Http``/``LiveSubdomains`` observations:
    ``{(program_name, subdomain): [{"ips", "url"}]}``.
    ``post_issuance_scopes`` optionally replaces the scope lists for
    every read AFTER issuance to prove drift fail-closed behavior.
    """

    program_rows: dict[str, dict] | None = None
    asset_rows: dict[tuple[str, str], list[dict]] | None = None
    post_issuance_scopes: tuple[list[str], list[str]] | None = None
    issued_at: str = STAGE2_ISSUED_AT
    now: str = STAGE2_NOW
    expires_at: str = STAGE2_EXPIRES_AT
    reviewed_at: str = STAGE2_NOW


@dataclass
class Stage2Stores:
    """Injected persistence backends (fakes in tests, real wiring later)."""

    authz: MongoAuthorizationStore
    ledger: MongoExecutionLedger
    audit: MongoAuditSink
    blobs: MongoBlobStore
    index: MongoEvidenceIndex
    authz_collection: Any = None
    ledger_collection: Any = None
    audit_collection: Any = None
    blob_collection: Any = None
    index_collection: Any = None


@dataclass(frozen=True)
class Stage2Result:
    """Persistence-backed dry-run outcome (evidence + verify, no live I/O)."""

    test_plan: TestPlan
    artifact_reference: ArtifactReference
    artifact_bytes: bytes
    authorization: IssuedExecutionAuthorization
    resolution: Any
    scope_evaluation: Any
    exec_spec: Any
    evidence_record: Any
    verification_outcome: VerificationOutcome
    materialization_outcome: MaterializationOutcome | None
    sweep_report: SweepReport | None
    notes: tuple[str, ...] = field(default_factory=tuple)


def default_stage2_stores() -> Stage2Stores:
    """Build the standard fake-backed store bundle (tests/fixture path)."""
    from ai.persistence.mongo_authz import AUTHZ_UNIQUE_INDEXES
    from ai.persistence.mongo_ledger import LEDGER_UNIQUE_INDEXES
    from ai.persistence.mongo_audit import AUDIT_UNIQUE_INDEXES
    from ai.persistence.mongo_evidence import (
        BLOB_UNIQUE_INDEXES,
        INDEX_UNIQUE_INDEXES,
    )

    authz_collection = FakeMongoCollection(list(AUTHZ_UNIQUE_INDEXES))
    ledger_collection = FakeMongoCollection(list(LEDGER_UNIQUE_INDEXES))
    audit_collection = FakeMongoCollection(list(AUDIT_UNIQUE_INDEXES))
    blob_collection = FakeMongoCollection(list(BLOB_UNIQUE_INDEXES))
    index_collection = FakeMongoCollection(list(INDEX_UNIQUE_INDEXES))
    return Stage2Stores(
        authz=MongoAuthorizationStore(authz_collection),
        ledger=MongoExecutionLedger(ledger_collection),
        audit=MongoAuditSink(audit_collection),
        blobs=MongoBlobStore(blob_collection),
        index=MongoEvidenceIndex(index_collection),
        authz_collection=authz_collection,
        ledger_collection=ledger_collection,
        audit_collection=audit_collection,
        blob_collection=blob_collection,
        index_collection=index_collection,
    )


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _assert_live_gates_closed() -> None:
    if hx.LIVE_TRAFFIC_ENABLED is not False:
        raise Stage2Error("LIVE_GATE_VIOLATION", "LIVE_TRAFFIC_ENABLED is not False")
    if nx.LIVE_NUCLEI is not False:
        raise Stage2Error("LIVE_GATE_VIOLATION", "LIVE_NUCLEI is not False")


def run_stage2_dryrun(
    endpoint: EndpointView,
    config: Stage2Config | None = None,
    *,
    stores: Stage2Stores | None = None,
) -> Stage2Result:
    """Run the persistence-backed Stage 2 dry-run (no live I/O)."""
    _assert_live_gates_closed()
    cfg = config or Stage2Config()
    backend = stores or default_stage2_stores()
    notes: list[str] = []

    if not isinstance(endpoint, EndpointView):
        raise TypeError(
            "run_stage2_dryrun accepts only EndpointView, "
            f"not {type(endpoint).__name__}"
        )

    parts = urlsplit(endpoint.example_url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise Stage2Error("AUTHZ_FAILED", "endpoint scheme is not http(s)")
    host = (parts.hostname or "").lower()
    if not host:
        raise Stage2Error("AUTHZ_FAILED", "endpoint has no host")
    try:
        canonical_host, _kind = canonicalize_host(host)
    except Exception as exc:
        raise Stage2Error("AUTHZ_FAILED", "endpoint host not canonical") from exc
    port = parts.port or (443 if scheme == "https" else 80)

    program_reader = DictProgramReader(cfg.program_rows)
    asset_reader = DictAssetReader(cfg.asset_rows)

    # 1. TestPlan + validated artifact (frozen factories, stage-2 tag).
    hypothesis_id = "hyp-" + _sha256_hex(
        "|".join(
            ["stage2-hyp", endpoint.program_name, endpoint.subdomain,
             endpoint.example_url]
        )
    )[:16]
    provenance = ResearchProvenance(
        research_hashes=[_sha256_hex(f"stage2-provenance|{endpoint.example_url}")]
    )
    test_plan = build_test_plan(
        hypothesis_id=hypothesis_id,
        target=TargetRef(
            program_name=endpoint.program_name,
            subdomain=endpoint.subdomain,
            endpoint=endpoint.path or "/",
        ),
        test_category="http_probe",
        objective=(
            "Stage 2 persistence-backed probe intent for "
            f"{endpoint.program_name}/{endpoint.subdomain} "
            f"hypothesis {hypothesis_id}; intent only, never authorization."
        ),
        execution_type="http_probe",
        verifier_type="http_matcher",
        provenance=provenance,
    )
    first_param = next(
        (name for name in endpoint.params if isinstance(name, str) and name),
        None,
    )
    artifact_bytes = json.dumps(
        {
            "method": (endpoint.method or "GET").upper(),
            "path": endpoint.path or "/",
            "query_params": {first_param: ""} if first_param else {},
            "headers": {},
            "body": None,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    validation = build_validated_reference(test_plan, artifact_bytes, "http_request_spec")
    if validation.state != "VALID":
        raise Stage2Error(
            "ARTIFACT_NOT_READY", "; ".join(validation.reasons)[:180]
        )
    digest = content_hash_for_bytes(artifact_bytes)
    artifact_id = artifact_id_for(
        artifact_type="http_request_spec",
        test_plan_id=test_plan.test_plan_id,
        content_hash=digest,
    )
    artifact_reference = ArtifactReference(
        artifact_id=artifact_id,
        artifact_type="http_request_spec",
        content_hash=digest,
        test_plan_id=test_plan.test_plan_id,
        hypothesis_id=test_plan.hypothesis_id,
        validation_state="VALID",
    )

    # 2. Scope hash from the LIVE program row; issuance binds it.
    policy = policy_for_program(program_reader, endpoint.program_name)
    if policy is None:
        raise Stage2Error("PROGRAM_UNKNOWN", "watch program row is absent")
    scope_hash = policy.scope_lists_hash
    try:
        authorization = issue_authorization(
            backend.authz,
            AuthorizationRequest(
                test_plan_id=test_plan.test_plan_id,
                hypothesis_id=test_plan.hypothesis_id,
                artifact=ArtifactBinding(
                    artifact_id=artifact_id,
                    artifact_type="http_request_spec",
                    content_hash=digest,
                    test_plan_id=test_plan.test_plan_id,
                    hypothesis_id=test_plan.hypothesis_id,
                ),
                target=TargetBinding(
                    program_name=endpoint.program_name,
                    host=canonical_host,
                    scheme=scheme,  # type: ignore[arg-type]
                    effective_port=port,
                    scope_lists_hash=scope_hash,
                ),
                execution_class="http_probe",
                execution_phase="single",
                plan_method="GET",
                artifact_method="GET",
                expires_at=cfg.expires_at,
                caller_scope="manual",
                issuer_identity="human-review-board",
            ),
            now=cfg.issued_at,
        )
    except Stage2Error:
        raise
    except Exception as exc:
        raise Stage2Error("AUTHZ_FAILED", type(exc).__name__) from exc
    notes.append(f"authz:{authorization.authorization_id}")

    # Post-issuance read surface (drift hook: replace scope lists for
    # every subsequent read to prove fail-closed drift behavior).
    if cfg.post_issuance_scopes is not None:
        drift_scopes, drift_ooscopes = cfg.post_issuance_scopes
        program_reader = DictProgramReader(
            {endpoint.program_name: {
                "program_name": endpoint.program_name,
                "scopes": list(drift_scopes),
                "ooscopes": list(drift_ooscopes),
            }}
        )

    execution_id = "ex-" + _sha256_hex(
        "|".join(
            ["stage2-ex", test_plan.test_plan_id, artifact_id,
             endpoint.program_name, canonical_host]
        )
    )[:32]

    # 3. B1 reviewed facts -> 5C resolution (no DNS, no sockets).
    #    Resolution runs while the authorization is still LIVE
    #    (ISSUED): the frozen 5C liveness gate requires permission,
    #    while provenance (handoff/verify below) accepts CONSUMED.
    facts = address_facts_for(asset_reader, endpoint.program_name, endpoint.subdomain)
    if not facts:
        raise Stage2Error("RESOLUTION_FAILED", "no reviewed address facts")
    source = InventoryAddressSource(
        program_name=endpoint.program_name,
        reviews=[
            AddressReview(
                program_name=endpoint.program_name,
                canonical_host=canonical_host,
                addresses=facts,
                source="watch-inventory:Http+LiveSubdomains",
                reviewer="stage2-dryrun",
                reviewed_at=cfg.reviewed_at,
            )
        ],
    )
    program_row = program_reader.get_program_row(endpoint.program_name)
    if program_row is None:
        raise Stage2Error("PROGRAM_UNKNOWN", "watch program row went absent")
    program_record, asset_record = inventory_records_for(
        program_row,
        canonical_host,
        scheme,
        port,
        asset_reader.get_asset_rows(endpoint.program_name, endpoint.subdomain),
    )
    from ai.resolver.inventory import InMemoryInventoryRepository

    inventory = InMemoryInventoryRepository(
        programs=[program_record], assets=[asset_record]
    )
    try:
        resolution = TargetResolver(inventory=inventory, dns=source).resolve(
            ResolutionRequest(
                authorization=authorization,
                execution_id=execution_id,
                now=cfg.now,
            )
        )
    except Exception as exc:
        raise Stage2Error("RESOLUTION_FAILED", type(exc).__name__) from exc
    if resolution.status != "RESOLVED":
        raise Stage2Error(
            "RESOLUTION_FAILED",
            f"{resolution.status}:{resolution.failure_code or ''}",
        )
    notes.append(f"resolution:{resolution.resolution_id}")

    # 4. 5D scope over the (possibly drifted) live policy. The read
    #    path compiles the live row through the EXISTING
    #    compile_policy; the evaluator keeps its frozen semantics, so
    #    drift fails closed here (or already at resolution above).
    live_row = program_reader.get_program_row(endpoint.program_name)
    if live_row is None:
        raise Stage2Error("PROGRAM_UNKNOWN", "watch program row went absent")
    live_policy = policy_for_program(program_reader, endpoint.program_name)
    assert live_policy is not None
    assert live_policy.scope_lists_hash == scope_lists_hash_for(
        list(live_row["scopes"]), list(live_row["ooscopes"])
    )
    evaluation = ScopeEvaluator(
        policy_store=InMemoryPolicyStore(
            {endpoint.program_name: (
                list(live_row["scopes"]), list(live_row["ooscopes"])
            )}
        )
    ).evaluate(authorization, resolution, execution_id=execution_id, now=cfg.now)
    if evaluation.decision == "DENIED":
        raise Stage2Error("SCOPE_DENIED", evaluation.failure_code or "denied")
    if evaluation.decision != "ALLOWED":
        raise Stage2Error("SCOPE_INCONCLUSIVE", evaluation.decision or "denied")
    notes.append(f"scope:{evaluation.evaluation_id}")

    # 5. Ledger claim + consume + start (executor ordering, no transport).
    try:
        backend.ledger.put_new(
            ExecutionRecord(
                execution_id=execution_id,
                authorization_id=authorization.authorization_id,
                execution_stage="single",
                idempotency_key=authorization.idempotency_key,
            )
        )
        authorization = consume_authorization(
            backend.authz, authorization.authorization_id, now=cfg.now
        )
        backend.ledger.mark_started(execution_id, started_at=cfg.now)
    except Stage2Error:
        raise
    except Exception as exc:
        raise Stage2Error("LEDGER_FAILED", type(exc).__name__) from exc
    try:
        backend.audit.append(
            AuditRecord(
                seq=0,
                execution_id=execution_id,
                authorization_id=authorization.authorization_id,
                transition="AUTHORIZATION",
                at=cfg.now,
                actor="stage2-dryrun",
                program_name=endpoint.program_name,
                host=canonical_host,
                artifact_id=artifact_id,
                artifact_content_hash=digest,
            )
        )
        backend.audit.append(
            AuditRecord(
                seq=1,
                execution_id=execution_id,
                authorization_id=authorization.authorization_id,
                transition="EXECUTION_STARTED",
                at=cfg.now,
                actor="stage2-dryrun",
                program_name=endpoint.program_name,
                host=canonical_host,
            )
        )
    except Exception as exc:
        raise Stage2Error("AUDIT_FAILED", type(exc).__name__) from exc

    # 6. SPEC only.
    _assert_live_gates_closed()
    from ai.execution import http_executor as hx

    try:
        exec_spec = hx.translate_bounded_request(
            authorization=authorization,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference,
            artifact_bytes=artifact_bytes,
            execution_id=execution_id,
        )
    except Exception as exc:
        raise Stage2Error("SPEC_FAILED", type(exc).__name__) from exc

    # 7. Synthetic evidence -> mongo-backed seal + ledger/audit close.
    try:
        body_hash, body_sample, omitted = obs.observe_body(
            b"stage2 persistence-backed synthetic response body",
            content_type="text/html",
        )
        builder = EvidenceBuilder.begin(
            authorization=authorization,
            execution_id=execution_id,
            execution_class="http_probe",
            execution_stage="single",
            started_at=cfg.now,
        )
        builder.attach_http(
            ev.HttpObservation(
                method="GET",
                request_url=obs.observe_url(exec_spec.canonical_url),
                request_body_hash=hash_mod.sha256_hex(b""),
                response_status=200,
                response_body_hash=body_hash,
                response_body_sample=body_sample,
                sample_omitted=omitted,
                transport_outcome="responded",
            )
        )
        record = builder.seal(finished_at=cfg.now, sealed_at=cfg.now)
    except Exception as exc:
        raise Stage2Error("EVIDENCE_FAILED", type(exc).__name__) from exc
    evidence_store = EvidenceStore(
        backend.blobs, backend.index, ledger=None, audit=[]
    )
    evidence_store.persist_sealed(record)
    backend.ledger.mark_sealed(record.execution_id, record.evidence_id,
                               terminal_at=cfg.now)
    backend.audit.append(
        AuditRecord(
            seq=2,
            execution_id=execution_id,
            authorization_id=authorization.authorization_id,
            evidence_id=record.evidence_id,
            transition="EVIDENCE_SEALED",
            at=cfg.now,
            actor="stage2-dryrun",
            program_name=endpoint.program_name,
            host=canonical_host,
            evidence_hashes={
                "bindings_hash": record.bindings_hash or "",
                "observations_hash": record.observations_hash or "",
                "content_hash": record.content_hash or "",
            },
        )
    )
    notes.append(f"evidence:{record.content_hash}")

    # 8. 5I verify + 5J dry-run (finding infra stays in-memory by design).
    by_id = {authorization.authorization_id: authorization}
    seam = StoreVerifiedRead(evidence_store, backend.index, by_id.get)
    outcome = verify_handoff(
        VerifierInput(
            handoff=bind_provenance(assemble_handoff(record), authorization),
            envelope=canonical_envelope_bytes(record),
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        ),
        seam,
        audit=[],
    )
    if not outcome.accepted or outcome.result is None:
        raise Stage2Error("VERIFY_BLOCKED", outcome.reason)
    notes.append(f"verify:{outcome.result.outcome}:{outcome.result_hash}")
    infra = FindingInfrastructure(
        evidence_reader=seam,
        finding_store=FindingStoreMemory(),
        workflow_store=WorkflowStoreMemory(),
        audit_sink=[],
        notification_sink=RecordingNotificationSink(),
        alert_ledger=AlertLedgerMemory(),
    )
    materialization = materialize(outcome.result, infra)
    notes.append(
        f"finding:{'accepted' if materialization.accepted else 'refused'}"
        f":{materialization.reason}"
    )

    # 9. Orphan sweep over the same mongo-backed seams (report mode).
    try:
        sweep_report = run_sweep(
            store=evidence_store,
            blobs=backend.blobs,
            index=backend.index,
            now_epoch=cfg.now,
        )
    except Exception as exc:
        raise Stage2Error("SWEEP_FAILED", type(exc).__name__) from exc
    notes.append(f"sweep:candidates={len(sweep_report.candidates)}")

    return Stage2Result(
        test_plan=test_plan,
        artifact_reference=artifact_reference,
        artifact_bytes=artifact_bytes,
        authorization=authorization,
        resolution=resolution,
        scope_evaluation=evaluation,
        exec_spec=exec_spec,
        evidence_record=record,
        verification_outcome=outcome,
        materialization_outcome=materialization,
        sweep_report=sweep_report,
        notes=tuple(notes),
    )
