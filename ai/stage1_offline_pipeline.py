"""Stage 1 offline authorized pipeline (fully dry-run, no live execution).

Connects the existing deterministic 5B-5J contracts for one Watch
endpoint without performing any network, DNS, subprocess, browser, or
Nuclei activity::

    EndpointView
      -> TestPlan (ai.schemas.test_plan.build_test_plan)
      -> ArtifactReference (ai.researcher.artifact_validator)
      -> AuthorizationRequest -> issue_authorization (InMemory store)
      -> TargetResolver + InMemoryInventory + FakeDnsResolver (no DNS)
      -> ScopeEvaluator (InMemoryPolicyStore, verdicts unchanged)
      -> translate_bounded_request (execution SPEC only, 5E pure)
      -> EvidenceBuilder synthetic HttpObservation -> seal (5H)
      -> persist (in-memory EvidenceStore) -> verify_handoff (5I)
      -> materialize (5J dry-run, in-memory stores only)

Safety properties (enforced in code, asserted by tests):

- ``LIVE_TRAFFIC_ENABLED`` and ``LIVE_NUCLEI`` are read and asserted
  ``False`` on every run; live runners/sockets are never constructed
  for execution (a live-runner block is probed, never launched).
- The legacy World A pipeline (``ai.verification.verifier``,
  ``http_executor``, ``browser_executor``, ``composite_executor``,
  ``xss_pipeline``) is never imported here.
- ``database.db`` (and its legacy ``XssFindings`` collection) is never
  imported here; no Mongo persistence exists in this stage.
- The retired 5I materialization seam is never imported; findings flow
  only through the authoritative 5J ``materialize`` dry-run.
- No ``NOT_VULNERABLE`` is representable: the pipeline never invents
  it and the 5I classifier cannot produce it.
- Determinism: every derived identity (hypothesis/test-plan/artifact/
  execution) is a deterministic hash of the input. ``evidence_id``
  and the 5B issuance nonce remain random handles by architecture
  design (handles, not content identity); repeatability is therefore
  asserted on content hashes and the classification result hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ai.authorizer.service import issue_authorization
from ai.authorizer.store import InMemoryAuthorizationStore
from ai.evidence import hashing as hash_mod
from ai.evidence import observations as obs
from ai.evidence.builder import EvidenceBuilder
from ai.evidence.blob_store import InMemoryBlobStore
from ai.evidence.handoff import assemble_handoff, bind_provenance
from ai.evidence.index import InMemoryEvidenceIndex
from ai.evidence.store import EvidenceStore, canonical_envelope_bytes
from ai.execution import http_executor as hx
from ai.execution import nuclei_executor as nx
from ai.finding.materializer import (
    FindingInfrastructure,
    MaterializationOutcome,
    materialize,
)
from ai.finding.notify import AlertLedgerMemory, RecordingNotificationSink
from ai.finding.store_memory import FindingStoreMemory, WorkflowStoreMemory
from ai.researcher.artifact_validator import build_validated_reference
from ai.resolver.canonicalization import canonicalize_host
from ai.resolver.dns import FakeDnsResolver
from ai.resolver.inventory import (
    AssetRecord,
    InMemoryInventoryRepository,
    ProgramRecord,
    scope_lists_hash_for,
)
from ai.resolver.resolver import TargetResolver
from ai.schemas import evidence as ev
from ai.schemas.artifact import artifact_id_for, content_hash_for_bytes
from ai.schemas.execution_authorization import (
    ArtifactBinding,
    AuthorizationRequest,
    IssuedExecutionAuthorization,
    TargetBinding,
)
from ai.schemas.hypothesis import ResearchProvenance, TargetRef
from ai.schemas.target_resolution import ResolutionRequest
from ai.schemas.test_plan import TestPlan, build_test_plan
from ai.scope.evaluator import HopObservation, ScopeEvaluator
from ai.scope.policy import InMemoryPolicyStore
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
    "EndpointView",
    "Stage1Config",
    "Stage1Error",
    "Stage1Result",
    "run_stage1",
]

# Fixed offline fixtures (documentation addresses are avoided: the fake
# DNS mapping below uses globally-routable TEST IPs only at resolution
# time; no packet ever leaves the process).
FAKE_DNS_ADDRESS = "8.8.8.8"
STAGE1_ISSUED_AT = "2026-01-01T00:00:00+00:00"
STAGE1_NOW = "2026-01-15T00:00:00+00:00"
STAGE1_EXPIRES_AT = "2026-02-01T00:00:00+00:00"


class Stage1Error(ValueError):
    """Closed Stage 1 orchestration failure (wiring only, never a verdict)."""

    CODES = frozenset(
        {
            "ARTIFACT_NOT_READY",
            "AUTHZ_FAILED",
            "RESOLUTION_FAILED",
            "SCOPE_DENIED",
            "SCOPE_INCONCLUSIVE",
            "SPEC_FAILED",
            "EVIDENCE_FAILED",
            "VERIFY_BLOCKED",
            "LIVE_GATE_VIOLATION",
        }
    )

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in self.CODES:
            raise ValueError(f"unknown stage1 error code: {code!r}")
        safe = (detail or "")[:200]
        if "\n" in safe or "\r" in safe:
            raise ValueError("stage1 error detail must be single-line")
        super().__init__(f"{code}: {safe}" if safe else code)
        self.code = code
        self.detail = safe


@dataclass(frozen=True)
class EndpointView:
    """Minimal Watch-endpoint projection (duck-typed, no Mongo import).

    Mirrors the fields Stage 1 reads from a ``database.db.Endpoints``
    row (``program_name``, ``subdomain``, ``path``, ``example_url``,
    ``params``) without importing ``database.db`` (which opens a Mongo
    connection at import time).
    """

    program_name: str
    subdomain: str
    path: str
    example_url: str
    params: tuple[str, ...] = ()
    method: str = "GET"


@dataclass(frozen=True)
class Stage1Config:
    """Offline wiring configuration (all fakes, all deterministic)."""

    scopes: tuple[str, ...] = ("example.com",)
    ooscopes: tuple[str, ...] = ()
    dns_answers: tuple[str, ...] = (FAKE_DNS_ADDRESS,)
    issued_at: str = STAGE1_ISSUED_AT
    now: str = STAGE1_NOW
    expires_at: str = STAGE1_EXPIRES_AT
    # Optional redirect observations for evaluate_chain. ``None`` means
    # initial evaluation only; an empty tuple is treated the same.
    # A hop with empty addresses yields an INCONCLUSIVE stop.
    redirect_hops: tuple[HopObservation, ...] | None = None


@dataclass(frozen=True)
class Stage1Result:
    """Deterministic Stage 1 outcome (evidence + verification, no live I/O)."""

    test_plan: TestPlan
    artifact_reference: Any
    artifact_bytes: bytes
    authorization: IssuedExecutionAuthorization
    resolution: Any
    scope_evaluation: Any
    exec_spec: Any
    evidence_record: Any
    verification_outcome: VerificationOutcome
    materialization_outcome: MaterializationOutcome | None
    notes: tuple[str, ...] = field(default_factory=tuple)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _assert_live_gates_closed() -> None:
    if hx.LIVE_TRAFFIC_ENABLED is not False:
        raise Stage1Error("LIVE_GATE_VIOLATION", "LIVE_TRAFFIC_ENABLED is not False")
    if nx.LIVE_NUCLEI is not False:
        raise Stage1Error("LIVE_GATE_VIOLATION", "LIVE_NUCLEI is not False")


def _split_target(example_url: str) -> tuple[str, str, int]:
    parts = urlsplit(example_url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise Stage1Error("AUTHZ_FAILED", "endpoint scheme is not http(s)")
    host = (parts.hostname or "").lower()
    if not host:
        raise Stage1Error("AUTHZ_FAILED", "endpoint has no host")
    try:
        canonical, _kind = canonicalize_host(host)
    except Exception as exc:
        raise Stage1Error("AUTHZ_FAILED", "endpoint host not canonical") from exc
    port = parts.port
    if port is None:
        port = 443 if scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise Stage1Error("AUTHZ_FAILED", "endpoint port out of range")
    return scheme, canonical, port


def _build_test_plan(endpoint: EndpointView) -> TestPlan:
    hypothesis_id = "hyp-" + _sha256_hex(
        "|".join(
            ["stage1-hyp", endpoint.program_name, endpoint.subdomain, endpoint.example_url]
        )
    )[:16]
    provenance = ResearchProvenance(
        research_hashes=[
            _sha256_hex(f"stage1-provenance|{endpoint.example_url}")
        ]
    )
    target = TargetRef(
        program_name=endpoint.program_name,
        subdomain=endpoint.subdomain,
        endpoint=endpoint.path or "/",
    )
    return build_test_plan(
        hypothesis_id=hypothesis_id,
        target=target,
        test_category="http_probe",
        objective=(
            "Stage 1 offline probe intent for "
            f"{endpoint.program_name}/{endpoint.subdomain} "
            f"hypothesis {hypothesis_id}; intent only, never authorization."
        ),
        execution_type="http_probe",
        verifier_type="http_matcher",
        provenance=provenance,
    )


def _build_artifact_bytes(test_plan: TestPlan, endpoint: EndpointView) -> bytes:
    first_param = next(
        (name for name in endpoint.params if isinstance(name, str) and name), None
    )
    payload = {
        "method": (endpoint.method or "GET").upper(),
        "path": endpoint.path or "/",
        "query_params": {first_param: ""} if first_param else {},
        "headers": {},
        "body": None,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    validation = build_validated_reference(test_plan, raw, "http_request_spec")
    if validation.state != "VALID":
        raise Stage1Error(
            "ARTIFACT_NOT_READY", "; ".join(validation.reasons)[:180]
        )
    return raw


def run_stage1(
    endpoint: EndpointView,
    config: Stage1Config | None = None,
    *,
    authz_store: InMemoryAuthorizationStore | None = None,
) -> Stage1Result:
    """Run the full offline Stage 1 chain for one endpoint (no live I/O)."""
    _assert_live_gates_closed()
    cfg = config or Stage1Config()
    notes: list[str] = []

    if not isinstance(endpoint, EndpointView):
        raise TypeError(
            "run_stage1 accepts only EndpointView, "
            f"not {type(endpoint).__name__}"
        )

    scheme, canonical_host, port = _split_target(endpoint.example_url)

    # 1-2. TestPlan + validated artifact (pure, deterministic).
    test_plan = _build_test_plan(endpoint)
    artifact_bytes = _build_artifact_bytes(test_plan, endpoint)
    digest = content_hash_for_bytes(artifact_bytes)
    artifact_id = artifact_id_for(
        artifact_type="http_request_spec",
        test_plan_id=test_plan.test_plan_id,
        content_hash=digest,
    )
    from ai.schemas.artifact import ArtifactReference as _ArtifactReference

    artifact_reference = _ArtifactReference(
        artifact_id=artifact_id,
        artifact_type="http_request_spec",
        content_hash=digest,
        test_plan_id=test_plan.test_plan_id,
        hypothesis_id=test_plan.hypothesis_id,
        validation_state="VALID",
    )
    notes.append(f"artifact:{artifact_id}")

    # 3. Authorization issuance (in-memory store only, existing service).
    scope_hash = scope_lists_hash_for(list(cfg.scopes), list(cfg.ooscopes))
    store = authz_store or InMemoryAuthorizationStore()
    request = AuthorizationRequest(
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
    )
    try:
        authorization = issue_authorization(store, request, now=cfg.issued_at)
    except Exception as exc:
        raise Stage1Error("AUTHZ_FAILED", type(exc).__name__) from exc
    notes.append(f"authz:{authorization.authorization_id}")

    # 4. Deterministic resolution (fake inventory + fake DNS, no network).
    inventory = InMemoryInventoryRepository(
        programs=[
            ProgramRecord(
                program_name=endpoint.program_name,
                scopes=tuple(cfg.scopes),
                ooscopes=tuple(cfg.ooscopes),
            )
        ],
        assets=[
            AssetRecord(
                program_name=endpoint.program_name,
                canonical_host=canonical_host,
                scheme=scheme,
                effective_port=port,
            )
        ],
    )
    dns = FakeDnsResolver(mapping={canonical_host: list(cfg.dns_answers)})
    execution_id = "ex-" + _sha256_hex(
        "|".join(
            [
                "stage1-ex",
                test_plan.test_plan_id,
                artifact_id,
                endpoint.program_name,
                canonical_host,
            ]
        )
    )[:32]
    resolver = TargetResolver(inventory=inventory, dns=dns)
    try:
        resolution = resolver.resolve(
            ResolutionRequest(
                authorization=authorization,
                execution_id=execution_id,
                now=cfg.now,
            )
        )
    except Exception as exc:
        raise Stage1Error("RESOLUTION_FAILED", type(exc).__name__) from exc
    if resolution.status != "RESOLVED":
        raise Stage1Error(
            "RESOLUTION_FAILED",
            f"{resolution.status}:{resolution.failure_code or ''}",
        )
    notes.append(f"resolution:{resolution.resolution_id}")

    # 5. Scope evaluation (existing evaluator, semantics unchanged).
    policy_store = InMemoryPolicyStore(
        {endpoint.program_name: (tuple(cfg.scopes), tuple(cfg.ooscopes))}
    )
    evaluator = ScopeEvaluator(policy_store=policy_store)
    if cfg.redirect_hops:
        evaluation = evaluator.evaluate_chain(
            authorization,
            resolution,
            execution_id=execution_id,
            now=cfg.now,
            hops=tuple(cfg.redirect_hops),
        )
    else:
        evaluation = evaluator.evaluate(
            authorization,
            resolution,
            execution_id=execution_id,
            now=cfg.now,
        )
    if evaluation.decision == "DENIED":
        raise Stage1Error(
            "SCOPE_DENIED", evaluation.failure_code or "scope denied"
        )
    if evaluation.decision != "ALLOWED":
        raise Stage1Error(
            "SCOPE_INCONCLUSIVE", evaluation.decision or "not allowed"
        )
    notes.append(f"scope:{evaluation.evaluation_id}")

    # 6. Execution SPEC only (pure translator; nothing is launched).
    _assert_live_gates_closed()
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
        raise Stage1Error("SPEC_FAILED", type(exc).__name__) from exc
    notes.append(f"spec:{exec_spec.canonical_url}")

    # 7. Deterministic synthetic evidence (offline HttpObservation).
    try:
        body_text = "stage1 offline synthetic response body"
        body_hash, body_sample, omitted = obs.observe_body(
            body_text.encode("utf-8"), content_type="text/html"
        )
        request_url = obs.observe_url(exec_spec.canonical_url)
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
                request_url=request_url,
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
        raise Stage1Error("EVIDENCE_FAILED", type(exc).__name__) from exc
    notes.append(f"evidence:{record.content_hash}")

    # 8. Persist (in-memory) + 5I verify_handoff (existing pipeline).
    blobs = InMemoryBlobStore()
    index = InMemoryEvidenceIndex()
    evidence_audit: list = []
    evidence_store = EvidenceStore(blobs, index, ledger=None, audit=evidence_audit)
    evidence_store.persist_sealed(record)
    by_id = {authorization.authorization_id: authorization}
    seam = StoreVerifiedRead(evidence_store, index, by_id.get)
    verifier_input = VerifierInput(
        handoff=bind_provenance(assemble_handoff(record), authorization),
        envelope=canonical_envelope_bytes(record),
        verifier_version=VERIFIER_VERSION,
        rule_version=RULES_VERSION,
        policy_version=POLICY_VERSION,
    )
    outcome = verify_handoff(verifier_input, seam, audit=[])
    if not outcome.accepted or outcome.result is None:
        raise Stage1Error("VERIFY_BLOCKED", outcome.reason)
    notes.append(f"verify:{outcome.result.outcome}:{outcome.result_hash}")

    # 9. 5J dry-run (in-memory stores only; UNKNOWN/POTENTIAL refuse).
    finding_audit: list = []
    infra = FindingInfrastructure(
        evidence_reader=seam,
        finding_store=FindingStoreMemory(),
        workflow_store=WorkflowStoreMemory(),
        audit_sink=finding_audit,
        notification_sink=RecordingNotificationSink(),
        alert_ledger=AlertLedgerMemory(),
    )
    materialization = materialize(outcome.result, infra)
    notes.append(
        f"finding:{'accepted' if materialization.accepted else 'refused'}"
        f":{materialization.reason}"
    )

    return Stage1Result(
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
        notes=tuple(notes),
    )
