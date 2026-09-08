"""Controlled live validation lane (Phase 5K-live).

Orchestrates the full gate chain for a single CVE-2026-1557 validation
run against an explicit caller-supplied target. Reuses existing 5B-5F
components through injected deps; offline tests use FakeNucleiRunner +
deterministic fakes only.

Gate order (first failure blocks, each gate recorded):

  1. config: WATCH_AI_LIVE_VALIDATION env gate
  2. target: explicit non-empty target required
  3. candidate: CVE identity == CVE-2026-1557
  4. template: pinned template safety + specificity
  5. authorization: issue_authorization + get_issued_authorization
  6. scope: ScopeEvaluator + policy (allow explicit target only)
  7. execution: execute_nuclei via deps + runner
  8. verification: 5I verify_handoff via injected seam
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any, Callable

from ai.authorizer.service import get_issued_authorization, issue_authorization
from ai.authorizer.store import AuthorizationStore, InMemoryAuthorizationStore
from ai.evidence.handoff import assemble_handoff, bind_provenance
from ai.evidence.store import canonical_envelope_bytes
from ai.execution.b3_boundary import (
    check_destination_allowed,
    is_forbidden_destination,
)
from ai.execution.http_executor import InMemoryAuditSink
from ai.execution.ledger import InMemoryExecutionLedger
from ai.execution.nuclei_executor import (
    FakeNucleiRunner,
    NucleiExecutorDeps,
    NucleiExecutionResult,
    execute_nuclei,
)
from ai.live_validation.config import (
    LiveValidationDisabled,
    require_live_validation_enabled,
)
from ai.live_validation.gates import (
    HARD_SCOPE_CVE_ID,
    PinnedCveCandidate,
    resolve_pinned_candidate,
    validate_template_safety,
)
from ai.live_validation.schemas import (
    GateResult,
    LiveValidationEvidence,
    LiveValidationMode,
    LiveValidationResult,
    LiveValidationStatus,
    VerificationFacts,
)
from ai.resolver.canonicalization import CanonicalizationError, canonicalize_target
from ai.resolver.dns import DnsError, validate_answers
from ai.resolver.inventory import scope_lists_hash_for
from ai.resolver.resolver import canonical_target_hash_for, resolution_id_for
from ai.schemas.artifact import artifact_id_for, build_artifact_reference
from ai.schemas.execution_authorization import (
    ArtifactBinding,
    AuthorizationRequest,
    IssuedExecutionAuthorization,
    TargetBinding,
    effective_port_for,
)
from ai.schemas.scope_evaluation import ScopeEvaluation
from ai.schemas.target_resolution import (
    DialBinding,
    TargetResolution,
)
from ai.scope.evaluator import ScopeEvaluator
from ai.scope.policy import InMemoryPolicyStore
from ai.verification.deterministic.models import (
    POLICY_VERSION,
    RULES_VERSION,
    VERIFIER_VERSION,
    VerifierInput,
)
from ai.verification.deterministic.pipeline import verify_handoff

# ------------------------------------------------------------------
# Frozen clock / expiry constants (deterministic lane time)
# ------------------------------------------------------------------

NOW_ISO = "2026-09-07T12:00:00+00:00"
EXPIRES_FAR_FUTURE = "2030-12-31T23:59:59+00:00"

#: Default pinned address for the offline v1 lane. Globally routable
#: unicast so the 5D address gate passes; NEVER dialed (FakeNucleiRunner
#: performs no transport).
_DEFAULT_PINNED_ADDRESS = ("8.8.8.8",)


# ------------------------------------------------------------------
# Pure helpers (deterministic)
# ------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_raw_target(target: str) -> tuple[str, str, int]:
    """Parse a raw CLI target string to (scheme, host, port).

    Uses the shared canonicalize_target for scheme allowlist,
    hostname canonicalization, and port handling. Raises
    ValueError on any invalid input.
    """
    if "://" not in target:
        scheme = "https"
        rest = target
    else:
        parts = target.split("://", 1)
        scheme = parts[0]
        rest = parts[1]
    # Strip path/query/fragment; extract host and optional port.
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in authority:
        raise ValueError("userinfo not allowed in target")
    if ":" in authority and not authority.startswith("["):
        host_part, _, port_part = authority.rpartition(":")
        if port_part.isdigit():
            port = int(port_part)
        else:
            host_part = authority
            port = None
    elif authority.startswith("["):
        # IPv6 bracket notation
        close = authority.find("]")
        if close < 0:
            raise ValueError("malformed IPv6 bracket notation")
        host_part = authority[1:close]
        rest_after = authority[close + 1 :]
        if rest_after.startswith(":") and rest_after[1:].isdigit():
            port = int(rest_after[1:])
        else:
            port = None
    else:
        host_part = authority
        port = None
    canonical = canonicalize_target(host_part, scheme, port)
    return canonical.scheme, canonical.canonical_host, canonical.effective_port


def _program_name_for(canonical_host: str) -> str:
    """Deterministic program label for an explicit target."""
    return f"explicit:{canonical_host}"


def _explicit_policy_store(canonical_host: str) -> InMemoryPolicyStore:
    """Offline policy allowing only the explicit target host.

    Deterministic and narrow: the program is ``explicit:<host>`` and its
    single inclusion is exactly that host. No other scope exists.
    """
    return InMemoryPolicyStore({f"explicit:{canonical_host}": ([canonical_host], [])})


def _scope_hash_for_host(host: str) -> str:
    """Canonical scope-list hash for the single-host policy."""
    return scope_lists_hash_for((host,), ())


def _deterministic_tp_id(cve_id: str, target: str) -> str:
    """Deterministic test-plan id (``tp-`` + 16 hex)."""
    basis = f"testplan:v1:{cve_id}:{target}"
    return "tp-" + _sha256_hex(basis.encode("utf-8"))[:16]


def _deterministic_ex_id(cve_id: str, target: str, nonce: str) -> str:
    """Deterministic execution id (``ex-`` + 32 hex)."""
    basis = f"live-validation:v1:{cve_id}:{target}:{nonce}"
    return "ex-" + _sha256_hex(basis.encode("utf-8"))[:32]


# ------------------------------------------------------------------
# Lane
# ------------------------------------------------------------------


class ControlledLiveValidationLane:
    """Orchestrator for CVE-2026-1557 live validation.

    Dependencies are injected for offline testability:
    - ``runner_factory``: returns the 5F runner (FakeNucleiRunner offline)
    - ``resolver``: a reviewed ``DnsResolver``-shaped source
      (``FakeDnsResolver`` offline; ``ProductionAddressSource`` for
      the reviewed activation path). The ONLY authoritative address
      source: exactly one ``resolve()`` per execution, answers gated
      by ``validate_answers``. REQUIRED in live mode.
    - ``dns_mapping``: host → list of IP literals (offline/test-only
      fallback for dry-run; never authoritative for live execution)
    - ``policy_store``: InMemoryPolicyStore (default: narrow explicit-host
      policy derived from the CLI target; a supplied store is used as-is)
    - ``authz_store``: AuthorizationStore (default
      InMemoryAuthorizationStore; production wiring injects the
      5H-core MongoAuthorizationStore — same protocol, same gates)
    - ``now`` / ``monotonic``: time injection
    """

    def __init__(
        self,
        *,
        runner_factory: Callable[[], Any] | None = None,
        resolver: Any | None = None,
        dns_mapping: dict[str, list[str]] | None = None,
        policy_store: InMemoryPolicyStore | None = None,
        authz_store: AuthorizationStore | None = None,
        now: Callable[[], str] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self._runner_factory = runner_factory or FakeNucleiRunner
        self._resolver = resolver
        self._dns_mapping = dict(dns_mapping or {})
        self._policy_store = policy_store
        self._authz_store = authz_store or InMemoryAuthorizationStore()
        self._now = now or (lambda: NOW_ISO)
        self._monotonic = monotonic or (lambda: 1000.0)
        self._gates: list[GateResult] = []
        self._last_cve_id: str = ""
        self._last_target: str | None = None
        self._last_mode: LiveValidationMode = "dry_run"
        self._last_execution: LiveValidationEvidence | None = None

    # -- public ------------------------------------------------------

    def run(
        self,
        cve_id: str,
        target: str | None,
        *,
        mode: LiveValidationMode = "dry_run",
    ) -> LiveValidationResult:
        """Run the full live-validation gate chain for one CVE+target.

        Returns a LiveValidationResult with status BLOCKED on any
        gate failure, or NO_MATCH / MATCH_UNVERIFIED / VERIFIED after
        execution + verification. In ``dry_run`` mode execution and
        verification are recorded as NOT_PERFORMED (zero network).
        """
        self._gates = []

        def block(gate: str, reason: str) -> LiveValidationResult:
            self._gates.append(
                GateResult(gate=gate, decision="BLOCK", reason=reason)
            )
            return LiveValidationResult(
                cve_id=cve_id,
                target=target if isinstance(target, str) else None,
                mode=mode,
                status="BLOCKED",
                gates=tuple(self._gates),
                blocked_reason=reason,
                research_only=(mode == "dry_run"),
            )

        # -- Gate 1: config (WATCH_AI_LIVE_VALIDATION) --
        if mode == "live":
            try:
                require_live_validation_enabled()
            except LiveValidationDisabled:
                return block("config", "LIVE_VALIDATION_DISABLED")
            self._gates.append(
                GateResult(gate="config", decision="PASS", reason="live enabled")
            )
        else:
            self._gates.append(
                GateResult(gate="config", decision="PASS", reason="dry_run mode")
            )

        # -- Gate 2: target (shared canonicalization) --
        if not target or not isinstance(target, str) or not target.strip():
            return block("target", "TARGET_REQUIRED")
        target = target.strip()
        try:
            scheme, host, port = _parse_raw_target(target)
        except (ValueError, CanonicalizationError) as exc:
            return block("target", f"TARGET_INVALID: {exc}")
        self._gates.append(
            GateResult(gate="target", decision="PASS", reason="explicit target provided")
        )

        # -- Gate 3: candidate --
        if cve_id != HARD_SCOPE_CVE_ID:
            return block(
                "candidate", f"CVE_MISMATCH: {cve_id!r} != {HARD_SCOPE_CVE_ID!r}"
            )
        candidate = resolve_pinned_candidate(cve_id)
        self._gates.append(
            GateResult(gate="candidate", decision="PASS", reason="CVE identity pinned")
        )

        # -- Gate 4: template --
        passed, reasons = validate_template_safety(candidate)
        if not passed:
            return block("template", f"TEMPLATE_UNSAFE: {'; '.join(reasons)}")
        self._gates.append(
            GateResult(
                gate="template",
                decision="PASS",
                reason="safety+specificity validated",
            )
        )

        # -- Gate 5: authorization --
        authz, authz_err = self._issue_and_verify_authz(
            cve_id, target, candidate
        )
        if authz_err:
            return block("authorization", authz_err)
        self._gates.append(
            GateResult(gate="authorization", decision="PASS", reason="authz issued")
        )

        # -- Gate 6: scope --
        ex_id = _deterministic_ex_id(cve_id, target, secrets.token_hex(16))
        policy_store = self._policy_store or _explicit_policy_store(host)
        if mode == "live" and self._resolver is None:
            # B6-C: the injected mapping is a test-only fallback and
            # can never authorize live execution. Live mode resolves
            # exactly once through the injected reviewed resolver.
            return block("resolution", "LIVE_RESOLVER_REQUIRED")
        resolution, evaluation, scope_err = self._evaluate_scope(
            target, authz, ex_id, port, policy_store
        )
        if scope_err:
            return block("scope", scope_err)
        self._gates.append(
            GateResult(gate="scope", decision="PASS", reason="scope allowed")
        )

        # -- Gate 6b: B3 egress boundary guard --
        # Fail-closed: every resolved address must pass the B3
        # destination check. This proves the target is globally
        # routable before any execution can proceed.
        if resolution is None or not resolution.resolved_addresses:
            return block("egress", "EGRESS_NO_ADDRESSES")
        for addr in resolution.resolved_addresses:
            if is_forbidden_destination(addr):
                return block("egress", f"EGRESS_FORBIDDEN: {addr}")
            try:
                check_destination_allowed(addr)
            except Exception as exc:
                code = getattr(exc, "code", "EGRESS_DENIED")
                return block("egress", f"EGRESS_DENIED: {code}")
        self._gates.append(
            GateResult(
                gate="egress", decision="PASS", reason="addresses permitted"
            )
        )

        # -- Dry-run path: zero execution --
        if mode == "dry_run":
            self._gates.append(
                GateResult(
                    gate="execution", decision="NOT_PERFORMED", reason="dry_run"
                )
            )
            self._gates.append(
                GateResult(
                    gate="verification", decision="NOT_PERFORMED", reason="dry_run"
                )
            )
            return LiveValidationResult(
                cve_id=cve_id,
                target=target,
                mode="dry_run",
                status="BLOCKED",
                gates=tuple(self._gates),
                blocked_reason="DRY_RUN_NOT_PERFORMED",
                research_only=True,
            )

        # -- Gate 7: execution --
        self._last_cve_id = cve_id
        self._last_target = target
        self._last_mode = mode
        runner = self._runner_factory()
        deps = NucleiExecutorDeps(
            authz_store=self._authz_store,
            ledger=InMemoryExecutionLedger(),
            audit=InMemoryAuditSink(),
            now_iso=self._now,
            monotonic=self._monotonic,
        )
        tp_id = _deterministic_tp_id(cve_id, target)
        try:
            exec_result = execute_nuclei(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=build_artifact_reference(
                    artifact_type="nuclei_template",
                    content=candidate.canonical_bytes,
                    test_plan_id=tp_id,
                    validation_state="VALID",
                ),
                artifact_bytes=candidate.canonical_bytes,
                execution_id=ex_id,
                deps=deps,
                runner=runner,
                fixtures=tuple(candidate.fixtures),
            )
        except Exception as exc:
            code = getattr(exc, "code", "EXECUTION_FAILED")
            detail = getattr(exc, "detail", str(exc))
            return block("execution", f"{code}: {detail}")
        assert exec_result.outcome == "sealed"
        self._last_execution = _evidence_from_result(exec_result)
        self._gates.append(
            GateResult(
                gate="execution", decision="PASS", reason=exec_result.outcome
            )
        )

        if exec_result.evidence is None:
            return self._unverified("NO_EVIDENCE_SEALED")

        # -- Gate 8: verification --
        evidence = exec_result.evidence
        envelope = canonical_envelope_bytes(evidence)
        handoff = assemble_handoff(evidence)
        handoff_bound = bind_provenance(handoff, authz)
        verifier_input = VerifierInput(
            handoff=handoff_bound,
            envelope=envelope,
            verifier_version=VERIFIER_VERSION,
            rule_version=RULES_VERSION,
            policy_version=POLICY_VERSION,
        )
        seam = self._build_seam(evidence, envelope)
        try:
            outcome = verify_handoff(verifier_input, seam)
        except Exception as exc:
            return self._unverified(f"VERIFIER_ERROR: {exc}")

        if not outcome.accepted:
            return self._unverified(f"VERIFIER_REJECTED: {outcome.reason}")

        self._gates.append(
            GateResult(
                gate="verification",
                decision="PASS",
                reason=outcome.reason or "accepted",
            )
        )

        final_status, blocked_reason = self._resolve_final_status(outcome)
        return LiveValidationResult(
            cve_id=cve_id,
            target=target,
            mode="live",
            status=final_status,
            gates=tuple(self._gates),
            blocked_reason=blocked_reason,
            research_only=False,
            execution=_evidence_from_result(exec_result),
            verification=_verification_from_outcome(outcome),
            result_hash=outcome.result_hash or "",
        )

    def _unverified(self, reason: str) -> LiveValidationResult:
        """Post-execution inconclusive state (evidence exists, no verdict)."""
        self._gates.append(
            GateResult(gate="verification", decision="BLOCK", reason=reason)
        )
        return LiveValidationResult(
            cve_id=self._last_cve_id or "",
            target=self._last_target,
            mode=self._last_mode,
            status="MATCH_UNVERIFIED",
            gates=tuple(self._gates),
            blocked_reason=reason,
            research_only=False,
            execution=self._last_execution,
        )

    # -- internals ---------------------------------------------------

    def _build_seam(self, evidence, envelope):
        """Offline verified-read seam for the 5I verifier."""
        from ai.live_validation.seam import OfflineVerifiedSeam

        return OfflineVerifiedSeam(
            sealed_record=evidence,
            envelope=envelope,
            authz_store=self._authz_store,
        )

    def _issue_and_verify_authz(
        self, cve_id: str, target: str, candidate: PinnedCveCandidate
    ) -> tuple[IssuedExecutionAuthorization | None, str | None]:
        """Issue an authorization record and verify it's live."""
        tp_id = _deterministic_tp_id(cve_id, target)
        scheme, host, port = _parse_raw_target(target)
        program_name = _program_name_for(host)
        scope_hash = _scope_hash_for_host(host)

        try:
            request = AuthorizationRequest(
                test_plan_id=tp_id,
                artifact=ArtifactBinding(
                    artifact_id=artifact_id_for(
                        artifact_type="nuclei_template",
                        test_plan_id=tp_id,
                        content_hash=candidate.digest,
                    ),
                    artifact_type="nuclei_template",
                    content_hash=candidate.digest,
                    test_plan_id=tp_id,
                ),
                target=TargetBinding(
                    program_name=program_name,
                    host=host,
                    scheme=scheme,
                    effective_port=port,
                    scope_lists_hash=scope_hash,
                ),
                execution_class="nuclei_scan",
                plan_method="GET",
                artifact_method="GET",
                expires_at=EXPIRES_FAR_FUTURE,
                caller_scope="manual",
                issuer_identity="human-review-board",
            )
            issued = issue_authorization(
                self._authz_store, request, now=self._now()
            )
        except Exception as exc:
            return None, f"ISSUANCE_FAILED: {exc}"

        live = get_issued_authorization(
            self._authz_store, issued.authorization_id
        )
        if live is None:
            return None, "AUTHZ_NOT_FOUND"
        if live.lifecycle != "ISSUED":
            return None, f"AUTHZ_NOT_LIVE: {live.lifecycle}"
        return live, None

    def _evaluate_scope(
        self,
        target: str,
        authz: IssuedExecutionAuthorization,
        ex_id: str,
        port: int,
        policy_store: InMemoryPolicyStore,
    ) -> tuple[TargetResolution | None, ScopeEvaluation | None, str | None]:
        """Evaluate scope for the explicit target; return (res, eval, err)."""
        scheme, host, _ = _parse_raw_target(target)
        program_name = authz.target.program_name
        scope_hash = authz.target.scope_lists_hash
        try:
            resolution = self._build_resolution(
                authz=authz,
                ex_id=ex_id,
                program_name=program_name,
                host=host,
                scheme=scheme,
                port=port,
                scope_hash=scope_hash,
            )
        except Exception as exc:
            code = getattr(exc, "code", "SCOPE_ERROR")
            return None, None, f"SCOPE_DENIED: {code}"
        evaluator = ScopeEvaluator(policy_store=policy_store)
        try:
            evaluation = evaluator.evaluate(
                authz, resolution, execution_id=ex_id, now=self._now()
            )
            if evaluation.decision != "ALLOWED":
                return None, None, f"SCOPE_DENIED: {evaluation.decision}"
            return resolution, evaluation, None
        except Exception as exc:
            return None, None, f"SCOPE_ERROR: {exc}"

    def _resolve_addresses(self, host: str) -> tuple[tuple[str, ...], str]:
        """Resolve once; return ``(ordered_addresses, dns_source)``.

        B6-C resolution boundary:

        - With an injected reviewed resolver (required live): exactly
          one ``resolve()`` call for the canonical host; the raw
          answers pass through the frozen ``validate_answers`` gate
          (``dns_answers`` ceiling, whole-set failure on any
          unsafe/malformed entry, deterministic numeric order — never
          truncated, never "first clean wins"). Provenance is the
          resolver's own identity (``resolver.name`` must be a
          non-empty string; anything else fails closed).
        - Without a resolver (dry-run/test-only): the injected mapping
          (or the default pinned address) passes through the SAME
          ``validate_answers`` gate. ``DnsError`` from either path
          propagates to ``_evaluate_scope`` as ``SCOPE_DENIED``.
        """

        if self._resolver is not None:
            resolve = getattr(self._resolver, "resolve", None)
            if not callable(resolve):
                raise DnsError(
                    "DNS_RESOLUTION_FAILED", "resolver without resolve"
                )
            try:
                raw = resolve(host)
            except DnsError:
                raise
            except Exception as exc:
                raise DnsError(
                    "DNS_RESOLUTION_FAILED", "resolver exchange failed"
                ) from exc
            if not isinstance(raw, (list, tuple)):
                raise DnsError(
                    "DNS_MALFORMED_ANSWER", "resolver answer untyped"
                )
            addresses = validate_answers(list(raw))
            name = getattr(self._resolver, "name", "")
            if not isinstance(name, str) or not name:
                raise DnsError(
                    "DNS_RESOLUTION_FAILED", "resolver identity absent"
                )
            return addresses, name
        raw_mapping = tuple(
            self._dns_mapping.get(host, list(_DEFAULT_PINNED_ADDRESS))
        )
        return validate_answers(list(raw_mapping)), "live-validation-address/v1"

    def _build_resolution(
        self,
        *,
        authz: IssuedExecutionAuthorization,
        ex_id: str,
        program_name: str,
        host: str,
        scheme: str,
        port: int,
        scope_hash: str,
    ) -> TargetResolution:
        """Build a genuine TargetResolution from deterministic inputs.

        B6-C fix: addresses come from ``_resolve_addresses`` (one
        reviewed resolution gated by ``validate_answers`` with honest
        provenance). Unsafe/mixed/over-ceiling/empty answer sets are
        rejected fail-closed before the scope evaluator runs.
        """
        addresses, dns_source = self._resolve_addresses(host)
        authority = canonicalize_target(host, scheme, port)
        canonical_host, host_kind = authority.canonical_host, authority.host_kind
        cth = canonical_target_hash_for(
            program_name=program_name,
            canonical_host=canonical_host,
            scheme=scheme,
            effective_port=port,
        )
        rid = resolution_id_for(
            authorization_id=authz.authorization_id,
            execution_id=ex_id,
            canonical_target_hash=cth,
            resolved_addresses=addresses,
            scope_lists_hash_current=scope_hash,
            snapshot_current=None,
        )
        default = {"http": 80, "https": 443}[scheme]
        return TargetResolution(
            resolution_id=rid,
            authorization_id=authz.authorization_id,
            execution_id=ex_id,
            program_name=program_name,
            host_as_authorized=canonical_host,
            canonical_host=canonical_host,
            host_kind=host_kind,
            scheme=scheme,
            effective_port=port,
            base_authority=(
                f"{scheme}://{canonical_host}"
                if port == default
                else f"{scheme}://{canonical_host}:{port}"
            ),
            resolved_addresses=addresses,
            dns_answer_count=len(addresses),
            dns_source=dns_source,
            dial=DialBinding(
                addresses=addresses,
                effective_port=port,
                sni_host=canonical_host,
            ),
            scope_lists_hash_authorized=authz.target.scope_lists_hash,
            scope_lists_hash_current=scope_hash,
            scope_drift=False,
            status="RESOLVED",
            canonical_target_hash=cth,
            resolved_at=NOW_ISO,
        )

    @staticmethod
    def _resolve_final_status(
        outcome: object,
    ) -> tuple[LiveValidationStatus, str | None]:
        """Map a verification outcome to the verdict-free lane status.

        - nuclei_advisory_weak => VERIFIED (advisory POTENTIAL ceiling)
        - nuclei_no_advisory_signal => NO_MATCH
        - anything else => MATCH_UNVERIFIED
        """
        result = getattr(outcome, "result", None)
        if result is None:
            return "MATCH_UNVERIFIED", "classification_unresolved"
        if result.outcome_detail == "nuclei_advisory_weak":
            return "VERIFIED", None
        if result.reason_code == "nuclei_no_advisory_signal":
            return "NO_MATCH", None
        return "MATCH_UNVERIFIED", result.reason_code


# ------------------------------------------------------------------
# Evidence / verification mappers (verdict-free)
# ------------------------------------------------------------------


def _evidence_from_result(result: NucleiExecutionResult) -> LiveValidationEvidence:
    """Map NucleiExecutionResult to LiveValidationEvidence."""
    evidence = result.evidence
    spec = result.spec
    return LiveValidationEvidence(
        execution_id=result.execution_id,
        evidence_id=evidence.evidence_id if evidence is not None else "",
        authorization_id=result.authorization_id,
        outcome=result.outcome,
        error_code=result.error_code,
        error_detail=result.error_detail,
        template_id=spec.template_id if spec is not None else "",
        template_hash=spec.template_hash if spec is not None else "",
        argv_digest=spec.argv_digest if spec is not None else "",
        exit_code=None,
        finding_like_text_present=(
            bool(evidence.nuclei.finding_like_text_present)
            if evidence is not None and evidence.nuclei is not None
            else False
        ),
        evidence_bindings_hash=(
            evidence.bindings_hash if evidence is not None else None
        ),
        evidence_observations_hash=(
            evidence.observations_hash if evidence is not None else None
        ),
        evidence_content_hash=(
            evidence.content_hash if evidence is not None else None
        ),
    )


def _verification_from_outcome(outcome: object) -> VerificationFacts:
    """Map VerificationOutcome to VerificationFacts."""
    result = getattr(outcome, "result", None)
    if result is None:
        return VerificationFacts(
            verifier_version="",
            rule_id="",
            outcome="",
            reason_code=getattr(outcome, "reason", ""),
        )
    return VerificationFacts(
        verifier_version=result.verifier_version,
        rule_id=result.rule_id,
        outcome=result.outcome,
        outcome_detail=result.outcome_detail,
        result_hash=getattr(outcome, "result_hash", None),
        reason_code=result.reason_code,
        finding_eligible=result.finding_eligible,
    )