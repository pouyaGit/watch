"""Adversarial offline tests for Phase 5F v1 (closed-spec Nuclei executor).

Deterministic stdlib ``unittest``. No live execution, no Nuclei
binary, no process creation, no transport, no DNS, no browser, no
LLM, no MongoDB. Authorization, ledger, audit, policy, and runner
peers are fakes. Random IDs are asserted by format, never by value.
"""

from __future__ import annotations

import ast
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock

from ai.audit.trail import check_ordering
from ai.authorizer.service import consume_authorization
from ai.authorizer.store import InMemoryAuthorizationStore
from ai.evidence import hashing as hash_mod
from ai.evidence.builder import verify_record
from ai.evidence.scrubber import REDACTED
from ai.execution import nuclei_executor as nx
from ai.execution.ledger import InMemoryExecutionLedger
from ai.execution.http_executor import InMemoryAuditSink
from ai.execution.nuclei_executor import (
    B3NetnsNucleiRunner,
    ExecutorError,
    FakeNucleiRunner,
    LiveNucleiRunner,
    NucleiExecutionSpec,
    NucleiExecutorDeps,
    argv_digest_for,
    build_nuclei_argv,
    build_nuclei_environment,
    build_target_string,
    default_resource_limits,
    execute_nuclei,
    scratch_dir_for,
    validate_nuclei_safety_template,
)
from ai.limits.ceilings import CEILINGS
from ai.resolver.inventory import scope_lists_hash_for
from ai.schemas import evidence as ev
from ai.schemas.artifact import (
    ArtifactReference,
    artifact_id_for,
    content_hash_for_bytes,
)
from ai.schemas.execution_authorization import IssuedExecutionAuthorization
from ai.schemas.scope_evaluation import ScopeEvaluation
from ai.schemas.target_resolution import (
    DialBinding,
    TargetResolution,
    canonical_target_hash_for,
    resolution_id_for,
)
from ai.scope.evaluator import ScopeEvaluator
from ai.scope.policy import InMemoryPolicyStore

PROGRAM = "acme"
HOST = "authorized.example.com"
SIBLING = "evil.example.com"
OOS_HOST = "other.example.net"
EXCLUDED = "excluded.example.com"

IP_A = "8.8.8.8"
IP_B = "8.8.4.4"

SCOPES = [HOST, "www.example.com"]
OOSCOPES = [EXCLUDED]
SCOPE_HASH = scope_lists_hash_for(SCOPES, OOSCOPES)

TP_ID = "tp-" + "a" * 16
AUTHZ_ID = "authz-" + "b" * 16
EX_ID = "ex-" + "c" * 32
ISSUED_AT = "2026-01-01T00:00:00+00:00"
NOW = "2026-01-15T00:00:00+00:00"
EXPIRES_AT = "2026-02-01T00:00:00+00:00"
PAST = "2025-01-01T00:00:00+00:00"

MARKER = "specific-marker-xyz-123"


# ------------------------------------------------------------------
# Template / artifact helpers
# ------------------------------------------------------------------

def template_content(**overrides) -> bytes:
    payload = {
        "template_id": "acme-cve-probe",
        "method": "GET",
        "path": "/search",
        "headers": {"accept": "text/html"},
        "query_params": {"q": "hello"},
        "body": None,
        "matchers": [
            {"matcher_type": "word", "values": [MARKER], "part": "body"}
        ],
    }
    payload.update(overrides)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


GOOD_TEMPLATE = template_content()


def artifact_reference_for(
    content: bytes, tp_id: str = TP_ID
) -> ArtifactReference:
    digest = content_hash_for_bytes(content)
    return ArtifactReference(
        artifact_id=artifact_id_for(
            artifact_type="nuclei_template",
            test_plan_id=tp_id,
            content_hash=digest,
        ),
        artifact_type="nuclei_template",
        content_hash=digest,
        test_plan_id=tp_id,
        validation_state="VALID",
    )


BENIGN_FIXTURE_BODY = "benign welcome content with nothing unusual"
VULN_FIXTURE_BODY = f"response carrying {MARKER} for positive proof"


def nuclei_fixtures():
    from ai.researcher.nuclei_artifact_validator import NucleiFixture

    return [
        NucleiFixture(
            fixture_kind="benign", status=200, body=BENIGN_FIXTURE_BODY
        ),
        NucleiFixture(
            fixture_kind="vulnerable", status=200, body=VULN_FIXTURE_BODY
        ),
    ]


# ------------------------------------------------------------------
# Authorization / resolution / evaluation fixtures (genuine types)
# ------------------------------------------------------------------

def make_authz(
    content: bytes = GOOD_TEMPLATE,
    *,
    authz_id: str = AUTHZ_ID,
    host: str = HOST,
    scheme: str = "https",
    port: int = 443,
    plan_method: str = "GET",
    artifact_method: str = "GET",
    execution_class: str = "nuclei_scan",
    lifecycle: str = "ISSUED",
    expires_at: str = EXPIRES_AT,
    scope_hash: str = SCOPE_HASH,
) -> IssuedExecutionAuthorization:
    digest = content_hash_for_bytes(content)
    return IssuedExecutionAuthorization(
        authorization_id=authz_id,
        idempotency_key="d" * 64,
        issuance_nonce="e" * 32,
        issuer_identity="human-review-board",
        issued_at=ISSUED_AT,
        expires_at=expires_at,
        lifecycle=lifecycle,  # type: ignore[arg-type]
        record_version=1,
        test_plan_id=TP_ID,
        artifact={
            "artifact_id": artifact_id_for(
                artifact_type="nuclei_template",
                test_plan_id=TP_ID,
                content_hash=digest,
            ),
            "artifact_type": "nuclei_template",
            "content_hash": digest,
            "test_plan_id": TP_ID,
        },
        target={
            "program_name": PROGRAM,
            "host": host,
            "scheme": scheme,
            "effective_port": port,
            "scope_lists_hash": scope_hash,
        },
        execution_class=execution_class,  # type: ignore[arg-type]
        plan_method=plan_method,  # type: ignore[arg-type]
        artifact_method=artifact_method,  # type: ignore[arg-type]
    )


def make_resolution(
    authz: IssuedExecutionAuthorization,
    ex_id: str,
    addresses: tuple[str, ...] = (IP_A,),
    *,
    scope_hash_current: str | None = None,
    status: str = "RESOLVED",
    host: str | None = None,
    scheme: str | None = None,
    port: int | None = None,
) -> TargetResolution:
    host = host if host is not None else authz.target.host
    scheme = scheme if scheme is not None else authz.target.scheme
    port = port if port is not None else authz.target.effective_port
    cth = canonical_target_hash_for(
        program_name=PROGRAM,
        canonical_host=host,
        scheme=scheme,
        effective_port=port,
    )
    current = scope_hash_current if scope_hash_current is not None else SCOPE_HASH
    rid = resolution_id_for(
        authorization_id=authz.authorization_id,
        execution_id=ex_id,
        canonical_target_hash=cth,
        resolved_addresses=tuple(addresses),
        scope_lists_hash_current=current,
        snapshot_current=None,
    )
    default = {"http": 80, "https": 443}[scheme]
    return TargetResolution(
        resolution_id=rid,
        authorization_id=authz.authorization_id,
        execution_id=ex_id,
        program_name=PROGRAM,
        host_as_authorized=host,
        canonical_host=host,
        host_kind="dns",
        scheme=scheme,  # type: ignore[arg-type]
        effective_port=port,
        base_authority=f"{scheme}://{host}"
        if port == default
        else f"{scheme}://{host}:{port}",
        resolved_addresses=tuple(addresses),
        dns_answer_count=len(addresses),
        dns_source="fake-dns/v1",
        dial=DialBinding(
            addresses=tuple(addresses),
            effective_port=port,
            sni_host=host,
        ),
        scope_lists_hash_authorized=authz.target.scope_lists_hash,
        scope_lists_hash_current=current,
        scope_drift=(current != authz.target.scope_lists_hash),
        status=status,  # type: ignore[arg-type]
        canonical_target_hash=cth,
        resolved_at=NOW,
    )


def make_policy_store(extra: dict | None = None) -> InMemoryPolicyStore:
    programs: dict[str, tuple] = {PROGRAM: (list(SCOPES), list(OOSCOPES))}
    if extra:
        programs.update(extra)
    return InMemoryPolicyStore(programs)


def make_evaluation(
    authz: IssuedExecutionAuthorization,
    resolution: TargetResolution,
    ex_id: str,
    policies: InMemoryPolicyStore | None = None,
    expect: str | None = "ALLOWED",
) -> ScopeEvaluation:
    evaluator = ScopeEvaluator(
        policy_store=policies or make_policy_store()
    )
    evaluation = evaluator.evaluate(
        authz, resolution, execution_id=ex_id, now=NOW
    )
    if expect is not None:
        assert evaluation.decision == expect, evaluation
    return evaluation


def make_world(
    content: bytes = GOOD_TEMPLATE,
    *,
    runner: FakeNucleiRunner | None = None,
    ex_id: str = EX_ID,
    authz_kwargs: dict | None = None,
    host: str | None = None,
    evaluation_policies: InMemoryPolicyStore | None = None,
):
    authz = make_authz(content, **(authz_kwargs or {}))
    store = InMemoryAuthorizationStore()
    store.put_new(authz)
    resolution = make_resolution(
        authz, ex_id, host=host or authz.target.host
    )
    evaluation = make_evaluation(
        authz, resolution, ex_id, policies=evaluation_policies
    )
    ledger = InMemoryExecutionLedger()
    audit = InMemoryAuditSink()
    deps = NucleiExecutorDeps(
        authz_store=store,
        ledger=ledger,
        audit=audit,
        now_iso=lambda: NOW,
        monotonic=lambda: 1000.0,
    )
    return {
        "authz": authz,
        "store": store,
        "resolution": resolution,
        "evaluation": evaluation,
        "ledger": ledger,
        "audit": audit,
        "deps": deps,
        "runner": runner or FakeNucleiRunner(),
        "reference": artifact_reference_for(content),
        "content": content,
    }


def run_ok(world: dict, **overrides):
    params = {
        "authorization": world["authz"],
        "resolution": world["resolution"],
        "evaluation": world["evaluation"],
        "artifact_reference": world["reference"],
        "artifact_bytes": world["content"],
        "execution_id": EX_ID,
        "deps": world["deps"],
        "runner": world["runner"],
    }
    params.update(overrides)
    return execute_nuclei(**params)


# ------------------------------------------------------------------
# AUTHORIZATION
# ------------------------------------------------------------------

class AuthorizationTests(unittest.TestCase):
    def test_expired_authorization_refused(self):
        # The scope evaluator also enforces liveness, so the expired
        # record is planted in the store after fixtures are built.
        world = make_world()
        expired = make_authz(expires_at=PAST)
        expired_store = InMemoryAuthorizationStore()
        expired_store.put_new(expired)
        world["deps"].authz_store = expired_store
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(world["runner"].invocations, [])

    def test_consumed_authorization_refused(self):
        world = make_world()
        consume_authorization(world["store"], AUTHZ_ID, now=NOW)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(world["runner"].invocations, [])

    def test_revoked_authorization_refused(self):
        from ai.authorizer.service import revoke_authorization

        world = make_world()
        revoke_authorization(world["store"], AUTHZ_ID)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(world["runner"].invocations, [])

    def test_forged_authorization_refused(self):
        world = make_world()
        forged = make_authz(authz_id="authz-" + "f" * 16)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, authorization=forged)
        self.assertIn(
            ctx.exception.code, ("AUTHZ_NOT_FOUND", "AUTHZ_NOT_LIVE")
        )
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_execution_id_refused(self):
        world = make_world()
        other_ex = "ex-" + "d" * 32
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, execution_id=other_ex)
        self.assertIn(
            ctx.exception.code,
            ("AUTHZ_BINDING_MISMATCH", "RESOLUTION_BINDING_MISMATCH"),
        )
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_target_refused(self):
        world = make_world()
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, host=SIBLING
        )
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID, expect=None
        )
        with self.assertRaises(ExecutorError):
            run_ok(world)
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_program_refused(self):
        world = make_world()
        other = make_authz(
            authz_id="authz-" + "e" * 16,
        )
        other = IssuedExecutionAuthorization.model_validate(
            {**other.model_dump(mode="json"),
             "target": {**other.target.model_dump(mode="json"),
                        "program_name": "other-program"}}
        )
        store = InMemoryAuthorizationStore()
        store.put_new(other)
        world["deps"].authz_store = store
        with self.assertRaises(ExecutorError):
            run_ok(world, authorization=other)
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_artifact_refused(self):
        world = make_world()
        other_content = template_content(path="/other")
        other_ref = artifact_reference_for(other_content)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, artifact_reference=other_ref,
                   artifact_bytes=other_content)
        self.assertEqual(
            ctx.exception.code, "ARTIFACT_REVALIDATION_FAILED"
        )
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_execution_class_refused(self):
        world = make_world(
            authz_kwargs={"execution_class": "http_probe"},
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUTHZ_BINDING_MISMATCH")
        self.assertEqual(world["runner"].invocations, [])

    def test_replay_after_consume_refused(self):
        world = make_world()
        first = run_ok(world)
        self.assertEqual(first.outcome, "sealed")
        # Step 2 (liveness re-read) precedes step 9 (ledger claim),
        # so a consumed authorization refuses as not-live before any
        # launch. Fail-closed either way.
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(len(world["runner"].invocations), 1)


# ------------------------------------------------------------------
# ARTIFACT (template safety matrix)
# ------------------------------------------------------------------

class ArtifactSafetyTests(unittest.TestCase):
    def _deny(self, content: bytes, feature: str):
        report = validate_nuclei_safety_template(content)
        self.assertEqual(report.decision, "DENY", report.reasons)
        self.assertIn(feature, report.denied_features)

    def test_good_template_allows(self):
        report = validate_nuclei_safety_template(
            GOOD_TEMPLATE, fixtures=nuclei_fixtures()
        )
        self.assertEqual(report.decision, "ALLOW")
        self.assertEqual(report.denied_features, ())

    def test_wrong_hash_refused_at_execution(self):
        world = make_world()
        ref = world["reference"].model_copy(
            update={"content_hash": "0" * 64}
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, artifact_reference=ref)
        self.assertEqual(
            ctx.exception.code, "ARTIFACT_REVALIDATION_FAILED"
        )

    def test_modified_bytes_refused_at_execution(self):
        world = make_world()
        tampered = template_content(path="/tampered")
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, artifact_bytes=tampered)
        self.assertEqual(
            ctx.exception.code, "ARTIFACT_REVALIDATION_FAILED"
        )

    def test_unsafe_template_refused_at_execution(self):
        bad = template_content(method="DELETE")
        world = make_world(content=bad)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        # Destructive methods fail at artifact revalidation (H2
        # re-run) before the executor-time gate: either refusal is
        # fail-closed and launches nothing.
        self.assertIn(
            ctx.exception.code,
            ("TEMPLATE_REJECTED", "ARTIFACT_REVALIDATION_FAILED"),
        )
        self.assertEqual(world["runner"].invocations, [])

    def test_specificity_failure_denied(self):
        from ai.researcher.nuclei_artifact_validator import NucleiFixture

        report = validate_nuclei_safety_template(
            GOOD_TEMPLATE,
            fixtures=[
                NucleiFixture(
                    fixture_kind="benign", status=200,
                    body=f"benign carrying {MARKER}",
                ),
                NucleiFixture(
                    fixture_kind="vulnerable", status=200,
                    body=VULN_FIXTURE_BODY,
                ),
            ],
        )
        self.assertEqual(report.decision, "DENY")
        self.assertIn("specificity", report.denied_features)

    def test_forbidden_protocol_blocks(self):
        for key in ("dns", "network", "file", "code", "headless",
                    "javascript", "browser", "workflow", "workflows"):
            raw = dict(json.loads(GOOD_TEMPLATE))
            raw[key] = {"anything": "x"}
            content = json.dumps(raw, sort_keys=True).encode()
            with self.subTest(block=key):
                self._deny(content, key)

    def test_oob_markers_denied(self):
        for marker in ("interactsh", "oast"):
            bad = template_content(
                path=f"/x?cb={marker}-example.com")
            with self.subTest(marker=marker):
                self._deny(bad, "oob-callback")

    def test_extractors_denied(self):
        raw = dict(json.loads(GOOD_TEMPLATE))
        raw["extractors"] = [{"type": "regex"}]
        content = json.dumps(raw, sort_keys=True).encode()
        self._deny(content, "extractors")

    def test_fuzzing_attack_clustering_denied(self):
        for key in ("fuzzing", "attack", "clustering", "payloads"):
            raw = dict(json.loads(GOOD_TEMPLATE))
            raw[key] = {"mode": "clusterbomb"}
            content = json.dumps(raw, sort_keys=True).encode()
            with self.subTest(block=key):
                report = validate_nuclei_safety_template(content)
                self.assertEqual(report.decision, "DENY", key)

    def test_unknown_block_denied(self):
        raw = dict(json.loads(GOOD_TEMPLATE))
        raw["mystery Novelty"] = {"x": "y"}
        content = json.dumps(raw, sort_keys=True).encode()
        self._deny(content, "unknown-block")

    def test_variables_denied_in_v1(self):
        # 5F v1 stays within the frozen typed shape
        # (NucleiTemplateContent has no variables field): any
        # variables block denies fail-closed with an explicit name.
        for variables in (
            {"ok_name": "literal-value"},
            {"Bad-Name!": "v"},
            {"ok_name": "{{cmd}}"},
            {"ok_name": "x" * 2000},
        ):
            raw = dict(json.loads(GOOD_TEMPLATE))
            raw["variables"] = variables
            content = json.dumps(raw, sort_keys=True).encode()
            with self.subTest(variables=variables):
                self._deny(content, "variables")

    def test_status_only_matcher_denied(self):
        bad = template_content(matchers=[
            {"matcher_type": "status", "values": ["200"],
             "part": "body"}
        ])
        self._deny(bad, "status-only-matcher")

    def test_generic_matcher_denied(self):
        bad = template_content(matchers=[
            {"matcher_type": "word", "values": ["error"],
             "part": "body"}
        ])
        self._deny(bad, "generic-matcher")
        bad = template_content(matchers=[
            {"matcher_type": "word", "values": ["abc"],
             "part": "body"}
        ])
        self._deny(bad, "generic-matcher")

    def test_matcher_size_bounds(self):
        bad = template_content(matchers=[
            {"matcher_type": "word", "values": ["z" * 1025],
             "part": "body"}
        ])
        report = validate_nuclei_safety_template(bad)
        self.assertEqual(report.decision, "DENY")
        many = [
            {"matcher_type": "word", "values": [f"token-{i}-abcd"],
             "part": "body"}
            for i in range(17)
        ]
        bad = template_content(matchers=many)
        report = validate_nuclei_safety_template(bad)
        self.assertEqual(report.decision, "DENY")

    def test_destructive_method_denied(self):
        bad = template_content(method="DELETE")
        self._deny(bad, "destructive-method")

    def test_template_size_bound(self):
        big = template_content(body="z" * (32 * 1024 + 8))
        report = validate_nuclei_safety_template(big)
        self.assertEqual(report.decision, "DENY")
        self.assertIn("template-size", report.denied_features)

    def test_malformed_content_denied(self):
        for raw in (b"\xff\xfe", b"not json", b"[1,2]", b'"str"'):
            with self.subTest(raw=raw[:8]):
                report = validate_nuclei_safety_template(raw)
                self.assertEqual(report.decision, "DENY")

    def test_typed_input_enforced(self):
        with self.assertRaises(TypeError):
            validate_nuclei_safety_template({"not": "bytes"})  # type: ignore[arg-type]


# ------------------------------------------------------------------
# AUTHORITY (template must never override target authority)
# ------------------------------------------------------------------

class AuthorityTests(unittest.TestCase):
    def _deny(self, content: bytes, feature: str):
        report = validate_nuclei_safety_template(content)
        self.assertEqual(report.decision, "DENY", report.reasons)
        self.assertIn(feature, report.denied_features)

    def test_host_header_denied(self):
        bad = template_content(
            headers={"Host": HOST, "accept": "text/html"})
        self._deny(bad, "authority-override")

    def test_authorization_header_denied(self):
        bad = template_content(
            headers={"Authorization": "Bearer abc"})
        report = validate_nuclei_safety_template(bad)
        self.assertEqual(report.decision, "DENY")

    def test_cookie_header_denied(self):
        bad = template_content(headers={"Cookie": "s=1"})
        report = validate_nuclei_safety_template(bad)
        self.assertEqual(report.decision, "DENY")

    def test_proxy_header_denied(self):
        bad = template_content(
            headers={"Proxy-Authorization": "x"})
        self._deny(bad, "authority-override")

    def test_benign_custom_header_allowed(self):
        good = template_content(headers={"X-Custom": "v"})
        report = validate_nuclei_safety_template(good)
        self.assertEqual(report.decision, "ALLOW")

    def test_absolute_url_in_path_denied(self):
        bad = template_content(path="https://attacker.example/x")
        self._deny(bad, "absolute-url")

    def test_absolute_url_in_query_denied(self):
        bad = template_content(
            query_params={"next": "https://attacker.example/"})
        self._deny(bad, "absolute-url")

    def test_absolute_url_in_body_denied(self):
        bad = template_content(
            method="POST",
            headers={"accept": "text/html",
                     "content-type": "application/x-www-form-urlencoded"},
            body="next=https://attacker.example/",
        )
        report = validate_nuclei_safety_template(bad)
        self.assertEqual(report.decision, "DENY")

    def test_absolute_url_in_header_denied(self):
        bad = template_content(
            headers={"referer": "https://attacker.example/"})
        self._deny(bad, "absolute-url")

    def test_authority_form_path_denied(self):
        bad = template_content(path="//attacker.example/x")
        self._deny(bad, "authority-override")

    def test_userinfo_marker_in_path_denied(self):
        bad = template_content(path="/x@attacker.example")
        self._deny(bad, "authority-override")

    def test_host_line_in_body_denied(self):
        bad = template_content(
            method="POST",
            headers={"accept": "text/html",
                     "content-type": "application/x-www-form-urlencoded"},
            body="a=1\nHost: attacker.example",
        )
        report = validate_nuclei_safety_template(bad)
        self.assertEqual(report.decision, "DENY")

    def test_authority_template_never_executes(self):
        bad = template_content(headers={"Host": "attacker.example"})
        world = make_world(content=bad)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "TEMPLATE_REJECTED")
        self.assertEqual(world["runner"].invocations, [])


# ------------------------------------------------------------------
# TARGET binding
# ------------------------------------------------------------------

class TargetBindingTests(unittest.TestCase):
    def test_canonical_target_string(self):
        self.assertEqual(
            build_target_string(
                scheme="https", canonical_host=HOST, effective_port=443
            ),
            f"https://{HOST}",
        )
        self.assertEqual(
            build_target_string(
                scheme="https", canonical_host=HOST,
                effective_port=8443,
            ),
            f"https://{HOST}:8443",
        )

    def test_exact_host_executes(self):
        world = make_world()
        result = run_ok(world)
        self.assertEqual(result.outcome, "sealed")
        self.assertIsNotNone(result.evidence)
        assert result.spec is not None
        self.assertEqual(
            result.spec.target_string, f"https://{HOST}"
        )
        self.assertEqual(result.spec.canonical_host, HOST)

    def test_sibling_host_refused(self):
        world = make_world()
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, host=SIBLING
        )
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID, expect=None
        )
        with self.assertRaises(ExecutorError):
            run_ok(world)
        self.assertEqual(world["runner"].invocations, [])

    def test_excluded_host_refused(self):
        # Authorization genuinely targets the excluded host, so the
        # refusal comes from scope (not from target binding).
        world = make_world()
        world["authz"] = make_authz(host=EXCLUDED)
        world["store"] = InMemoryAuthorizationStore()
        world["store"].put_new(world["authz"])
        world["deps"].authz_store = world["store"]
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, host=EXCLUDED
        )
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID, expect="DENIED"
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertIn(
            ctx.exception.code,
            ("TARGET_NOT_IN_SCOPE", "TARGET_EXCLUDED"),
        )
        self.assertEqual(world["runner"].invocations, [])

    def test_out_of_scope_refused(self):
        world = make_world()
        world["authz"] = make_authz(host=OOS_HOST)
        world["store"] = InMemoryAuthorizationStore()
        world["store"].put_new(world["authz"])
        world["deps"].authz_store = world["store"]
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, host=OOS_HOST
        )
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID, expect="DENIED"
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(
            ctx.exception.code, "TARGET_NOT_IN_SCOPE"
        )
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_program_refused(self):
        world = make_world()
        res = world["resolution"]
        tampered = TargetResolution.model_validate(
            {**res.model_dump(mode="json"), "program_name": "other"}
        )
        with self.assertRaises(ExecutorError):
            run_ok(world, resolution=tampered)

    def test_wrong_resolution_id_refused(self):
        world = make_world()
        res = world["resolution"]
        other = make_resolution(world["authz"], "ex-" + "e" * 32)
        with self.assertRaises(ExecutorError):
            run_ok(world, resolution=other)
        _ = res

    def test_wrong_evaluation_refused(self):
        world = make_world()
        other_ex = "ex-" + "e" * 32
        other_res = make_resolution(world["authz"], other_ex)
        other_eval = make_evaluation(
            world["authz"], other_res, other_ex
        )
        with self.assertRaises(ExecutorError):
            run_ok(world, evaluation=other_eval)
        self.assertEqual(world["runner"].invocations, [])

    def test_denied_evaluation_refused(self):
        world = make_world()
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, host=OOS_HOST
        )
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID, expect="DENIED"
        )
        with self.assertRaises(ExecutorError):
            run_ok(world)
        self.assertEqual(world["runner"].invocations, [])

    def test_scope_drift_refused(self):
        other_hash = scope_lists_hash_for(["elsewhere.example"], [])
        world = make_world()
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, scope_hash_current=other_hash
        )
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "SCOPE_DRIFT")

    def test_unresolved_status_refused(self):
        world = make_world()
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, status="RESOLUTION_FAILED"
        )
        with self.assertRaises(ExecutorError):
            run_ok(world)


# ------------------------------------------------------------------
# ARGV
# ------------------------------------------------------------------

class ArgvTests(unittest.TestCase):
    def test_exact_argv_shape(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        tpl = f"/srv/watch/scratch/nuclei/{EX_ID}/" \
            f"{result.spec.template_hash[:16]}.json"
        self.assertEqual(
            list(result.spec.argv),
            [
                "/usr/bin/nuclei",
                "-t", tpl,
                "-u", f"https://{HOST}",
                "-disable-update-check",
                "-disable-redirects",
                "-no-interactsh",
                "-silent",
                "-no-color",
                "-stats-interval", "0",
                "-jsonl",
                "-bulk-size", "1",
                "-concurrency", "1",
                "-timeout", "5",
                "-retries", "0",
                "-restrict-local-network-access",
                "-nc",
            ],
        )

    def test_server_controlled_binary(self):
        argv = build_nuclei_argv(
            template_path=f"/srv/watch/scratch/nuclei/{EX_ID}/t.json",
            target_string=f"https://{HOST}",
        )
        self.assertEqual(argv[0], "/usr/bin/nuclei")
        self.assertEqual(argv[0], nx.SERVER_CONTROLLED_NUCLEI_BINARY)

    def test_template_path_scratch_only(self):
        with self.assertRaises(ExecutorError):
            build_nuclei_argv(
                template_path="/tmp/evil.json",
                target_string=f"https://{HOST}",
            )
        with self.assertRaises(ExecutorError):
            build_nuclei_argv(
                template_path="/srv/watch/scratch/nuclei-evil/t.json",
                target_string=f"https://{HOST}",
            )

    def test_target_derived_from_binding(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        invoked = world["runner"].invocations[0]
        self.assertEqual(invoked.argv[4], f"https://{HOST}")
        self.assertNotIn("attacker", invoked.argv[4])

    def test_no_shell_no_string_command(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        self.assertIsInstance(result.spec.argv, tuple)
        for part in result.spec.argv:
            self.assertIsInstance(part, str)
            self.assertNotIn(";", part)
            self.assertNotIn("|", part)

    def test_argv_digest_deterministic(self):
        world = make_world()
        first = run_ok(world)
        assert first.spec is not None
        expected = hashlib.sha256(
            json.dumps(
                list(first.spec.argv), ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(first.spec.argv_digest, expected)
        self.assertEqual(
            argv_digest_for(first.spec.argv), expected
        )
        assert first.evidence is not None and first.evidence.nuclei is not None
        self.assertEqual(
            first.evidence.nuclei.argv_digest, first.spec.argv_digest
        )


# ------------------------------------------------------------------
# ENV
# ------------------------------------------------------------------

class EnvironmentTests(unittest.TestCase):
    def test_exact_allowlist(self):
        cwd = scratch_dir_for(EX_ID)
        env = build_nuclei_environment(scratch_dir=cwd)
        self.assertEqual(
            dict(env),
            {
                "PATH": "/usr/bin:/bin",
                "HOME": cwd,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TMPDIR": cwd,
            },
        )

    def test_no_inherited_env(self):
        import os as _os

        _os.environ["NUCLEI_EVIL_INHERIT"] = "1"
        try:
            env = build_nuclei_environment(
                scratch_dir=scratch_dir_for(EX_ID)
            )
            self.assertNotIn("NUCLEI_EVIL_INHERIT", dict(env))
        finally:
            del _os.environ["NUCLEI_EVIL_INHERIT"]

    def test_no_proxy_or_secrets(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        names = {name for name, _ in result.spec.environment}
        for banned in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                       "NO_PROXY", "AWS_SECRET_ACCESS_KEY", "API_KEY",
                       "TOKEN"):
            self.assertNotIn(banned, names)
        self.assertEqual(
            names, {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}
        )

    def test_spec_environment_immutable(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        with self.assertRaises(Exception):
            result.spec.environment += (("EVIL", "1"),)  # type: ignore[misc]
        try:
            result.spec.environment[0] = ("EVIL", "1")  # type: ignore[index]
            self.fail("environment must be immutable")
        except TypeError:
            pass

    def test_scratch_dir_bound_to_execution(self):
        cwd = scratch_dir_for(EX_ID)
        self.assertTrue(cwd.startswith("/srv/watch/scratch/nuclei/"))
        self.assertIn(EX_ID, cwd)
        with self.assertRaises(ExecutorError):
            scratch_dir_for("not-an-execution-id")


# ------------------------------------------------------------------
# PROCESS (live gate)
# ------------------------------------------------------------------

class ProcessGateTests(unittest.TestCase):
    def test_live_runner_always_blocked(self):
        world = make_world()
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, runner=LiveNucleiRunner())
        self.assertEqual(
            ctx.exception.code, "NUCLEI_EXECUTION_BLOCKED"
        )

    def test_b3_placeholder_blocked(self):
        world = make_world()
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, runner=B3NetnsNucleiRunner())
        self.assertEqual(
            ctx.exception.code, "NUCLEI_EXECUTION_BLOCKED"
        )

    def test_live_runner_direct_launch_blocked(self):
        spec = NucleiExecutionSpec(
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            program_name=PROGRAM,
            canonical_host=HOST,
            scheme="https",
            effective_port=443,
            target_string=f"https://{HOST}",
            artifact_id="art-" + "a" * 16,
            template_id="t",
            template_hash="0" * 64,
            argv=(),
            argv_digest="0" * 64,
            cwd=scratch_dir_for(EX_ID),
            environment=(),
            stdin_policy="closed",
            stdout_cap_bytes=1024,
            stderr_cap_bytes=1024,
            limits=default_resource_limits(),
        )
        for runner in (LiveNucleiRunner(), B3NetnsNucleiRunner()):
            with self.assertRaises(ExecutorError) as ctx:
                runner.launch(spec)
            self.assertEqual(
                ctx.exception.code, "NUCLEI_EXECUTION_BLOCKED"
            )

    def test_live_gate_literal_false(self):
        self.assertIs(nx.LIVE_NUCLEI, False)

    def test_fake_runner_records_invocation(self):
        runner = FakeNucleiRunner(stdout="ok")
        world = make_world(runner=runner)
        run_ok(world)
        self.assertEqual(len(runner.invocations), 1)
        self.assertIsInstance(runner.invocations[0], NucleiExecutionSpec)

    def test_fake_runner_rejects_untyped_spec(self):
        runner = FakeNucleiRunner()
        with self.assertRaises(TypeError):
            runner.launch({"not": "a-spec"})  # type: ignore[arg-type]

    def test_executor_rejects_untyped_runner(self):
        world = make_world()
        with self.assertRaises(TypeError):
            run_ok(world, runner=object())  # type: ignore[arg-type]


# ------------------------------------------------------------------
# RESOURCE
# ------------------------------------------------------------------

class ResourceTests(unittest.TestCase):
    def test_limits_reuse_ceilings(self):
        limits = default_resource_limits()
        self.assertEqual(
            limits.wall_seconds, CEILINGS["nuclei_wall_seconds"]
        )
        self.assertEqual(
            limits.cpu_seconds, CEILINGS["subprocess_cpu_seconds"]
        )
        self.assertEqual(
            limits.memory_bytes, CEILINGS["subprocess_memory_bytes"]
        )
        self.assertEqual(
            limits.stdout_cap_bytes, CEILINGS["nuclei_output_bytes"]
        )
        self.assertEqual(
            limits.stderr_cap_bytes, CEILINGS["nuclei_output_bytes"]
        )
        self.assertEqual(
            limits.file_size_bytes, CEILINGS["temp_storage_bytes"]
        )
        self.assertEqual(
            limits.scratch_bytes, CEILINGS["temp_storage_bytes"]
        )

    def test_output_cap_enforced(self):
        big = "A" * (CEILINGS["nuclei_output_bytes"] + 16)
        world = make_world(runner=FakeNucleiRunner(stdout=big))
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(
            ctx.exception.code, "SUBPROCESS_OUTPUT_LIMIT"
        )

    def test_stderr_cap_enforced(self):
        big = "B" * (CEILINGS["nuclei_output_bytes"] + 16)
        world = make_world(runner=FakeNucleiRunner(stderr=big))
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(
            ctx.exception.code, "SUBPROCESS_OUTPUT_LIMIT"
        )

    def test_timeout_spec_in_argv(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        argv = list(result.spec.argv)
        idx = argv.index("-timeout")
        self.assertEqual(argv[idx + 1], "5")
        self.assertEqual(
            result.spec.limits.wall_seconds,
            CEILINGS["nuclei_wall_seconds"],
        )

    def test_spec_immutable(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        with self.assertRaises(Exception):
            result.spec.target_string = "https://evil.example"  # type: ignore[misc]

    def test_request_count_single(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        targets = [p for p in result.spec.argv if p == "-u"]
        self.assertEqual(len(targets), 1)
        templates = [p for p in result.spec.argv if p == "-t"]
        self.assertEqual(len(templates), 1)


# ------------------------------------------------------------------
# EVIDENCE
# ------------------------------------------------------------------

class EvidenceTests(unittest.TestCase):
    def test_observation_only_no_verdict_fields(self):
        world = make_world(
            runner=FakeNucleiRunner(
                stdout='{"matched":true,"severity":"critical"}'
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        record = result.evidence
        self.assertEqual(record.execution_class, "nuclei_scan")
        self.assertIsNone(record.http)
        self.assertIsNotNone(record.nuclei)
        dumped = record.model_dump(mode="json")
        for banned in ("verdict", "finding", "severity", "confirmed",
                       "vulnerable", "not_vulnerable", "exploited",
                       "matched"):
            self.assertNotIn(banned, dumped)
        verify_record(record)

    def test_finding_like_text_is_observation(self):
        world = make_world(
            runner=FakeNucleiRunner(stdout="[vulnerability] CRITICAL found")
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.nuclei is not None
        self.assertTrue(
            result.evidence.nuclei.finding_like_text_present
        )
        dumped = result.evidence.model_dump(mode="json")
        self.assertNotIn("verdict", dumped)

    def test_benign_text_no_finding_like(self):
        world = make_world(runner=FakeNucleiRunner(stdout="no match"))
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.nuclei is not None
        self.assertFalse(
            result.evidence.nuclei.finding_like_text_present
        )

    def test_scrubbed_stdout_and_hashes(self):
        secret_stdout = "result ok mongodb://user:pass@host/db done"
        world = make_world(
            runner=FakeNucleiRunner(stdout=secret_stdout)
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.nuclei is not None
        obs = result.evidence.nuclei
        assert obs.stdout_sample is not None
        self.assertNotIn("mongodb://", obs.stdout_sample)
        self.assertIn(REDACTED, obs.stdout_sample)
        self.assertEqual(
            obs.stdout_hash,
            hash_mod.sha256_hex(obs.stdout_sample.encode("utf-8")),
        )
        verify_record(result.evidence)

    def test_scrubbed_stderr_and_hashes(self):
        world = make_world(
            runner=FakeNucleiRunner(stderr="bearer abcdef123456")
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.nuclei is not None
        obs = result.evidence.nuclei
        assert obs.stderr_sample is not None
        self.assertEqual(
            obs.stderr_hash,
            hash_mod.sha256_hex(obs.stderr_sample.encode("utf-8")),
        )

    def test_newline_normalization(self):
        world = make_world(
            runner=FakeNucleiRunner(stdout="a\r\nb\rc")
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.nuclei is not None
        self.assertEqual(
            result.evidence.nuclei.stdout_sample, "a\nb\nc"
        )

    def test_artifact_target_execution_binding(self):
        world = make_world()
        result = run_ok(world)
        assert result.evidence is not None
        record = result.evidence
        self.assertEqual(record.execution_id, EX_ID)
        self.assertEqual(record.authorization_id, AUTHZ_ID)
        self.assertEqual(
            record.artifact_id, world["reference"].artifact_id
        )
        self.assertEqual(
            record.artifact_content_hash,
            world["reference"].content_hash,
        )
        self.assertEqual(record.program_name, PROGRAM)
        self.assertEqual(record.target.host, HOST)
        assert record.template_binding is not None
        assert record.nuclei is not None
        self.assertEqual(
            record.template_binding.template_hash,
            record.nuclei.template_hash,
        )

    def test_exit_code_recorded(self):
        world = make_world(
            runner=FakeNucleiRunner(exit_code=3, stdout="x")
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.nuclei is not None
        self.assertEqual(result.evidence.nuclei.exit_code, 3)


# ------------------------------------------------------------------
# CRASH / lifecycle
# ------------------------------------------------------------------

class CrashTests(unittest.TestCase):
    def test_consume_ambiguity_no_retry(self):
        # Pre-consumed authorization refuses at liveness re-read.
        world = make_world()
        consume_authorization(world["store"], AUTHZ_ID, now=NOW)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(world["runner"].invocations, [])

    def test_consume_race_maps_to_consumed(self):
        # A CAS loss between liveness re-read and consume (lost race)
        # maps deterministically to EXECUTION_ALREADY_CONSUMED.
        from ai.authorizer.store import VersionConflictError

        class RacingStore(InMemoryAuthorizationStore):
            def compare_and_swap(
                self, authorization_id, expected_version, new_record
            ):
                raise VersionConflictError("simulated race lost")

        world = make_world()
        racing = RacingStore()
        racing.put_new(world["authz"])
        world["deps"].authz_store = racing
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(
            ctx.exception.code, "EXECUTION_ALREADY_CONSUMED"
        )
        self.assertEqual(world["runner"].invocations, [])

    def test_start_ambiguity_unknown(self):
        from ai.execution.ledger import ExecutionRecord

        class FailingStartLedger(InMemoryExecutionLedger):
            def mark_started(self, execution_id, *, started_at=""):
                from ai.execution.ledger import LedgerError

                raise LedgerError("simulated start ambiguity")

        # A colliding ledger slot refuses as replay...
        world = make_world()
        world["ledger"].put_new(
            ExecutionRecord(
                execution_id="ex-" + "9" * 32,
                authorization_id=AUTHZ_ID,
                execution_stage="single",
                idempotency_key="k" * 64,
            )
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "EXECUTION_REPLAY")
        # ...while consume-succeeded-but-start-ambiguous is UNKNOWN.
        world2 = make_world()
        world2["deps"].ledger = FailingStartLedger()
        with self.assertRaises(ExecutorError) as ctx2:
            run_ok(world2)
        self.assertEqual(ctx2.exception.code, "OUTCOME_UNKNOWN")
        self.assertEqual(world2["runner"].invocations, [])

    def test_runner_timeout_unknown(self):
        world = make_world(
            runner=FakeNucleiRunner(timed_out=True, exit_code=None)
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "SUBPROCESS_TIMEOUT")
        row = world["ledger"].get(EX_ID)
        assert row is not None
        self.assertEqual(row.lifecycle, "UNKNOWN")

    def test_runner_killed_unknown(self):
        world = make_world(
            runner=FakeNucleiRunner(killed=True, exit_code=None)
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "SUBPROCESS_KILLED")

    def test_seal_failure_unknown(self):
        world = make_world()
        with mock.patch(
            "ai.execution.nuclei_executor.EvidenceBuilder"
        ) as builder_cls:
            instance = mock.Mock()
            instance.attach_nuclei.return_value = None
            instance.seal.side_effect = ev.EvidenceError(
                "EVIDENCE_INCOMPLETE", "missing"
            )
            builder_cls.begin.return_value = instance
            with self.assertRaises(ExecutorError) as ctx:
                run_ok(world)
        self.assertEqual(
            ctx.exception.code, "EVIDENCE_SEAL_FAILED"
        )
        row = world["ledger"].get(EX_ID)
        assert row is not None
        self.assertEqual(row.lifecycle, "UNKNOWN")

    def test_pre_launch_audit_failure_gap_no_launch(self):
        world = make_world()
        world["audit"].fail_from = 1
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUDIT_GAP")
        self.assertEqual(world["runner"].invocations, [])

    def test_post_seal_audit_gap_evidence_kept(self):
        world = make_world()
        original_append = world["audit"].append
        calls = {"n": 0}

        def flaky(record):
            calls["n"] += 1
            if calls["n"] > 3:
                raise ev.EvidenceError("AUDIT_GAP", "sink lost")
            return original_append(record)

        world["audit"].append = flaky  # type: ignore[method-assign]
        result = run_ok(world)
        self.assertTrue(result.audit_gap)
        self.assertIsNotNone(result.evidence)

    def test_replay_after_consume(self):
        # A second execution under the same authorization refuses as
        # replay at the ledger claim (at-most-once per authorization).
        from ai.execution.ledger import ExecutionRecord

        world = make_world()
        world["ledger"].put_new(
            ExecutionRecord(
                execution_id="ex-" + "f" * 32,
                authorization_id=AUTHZ_ID,
                execution_stage="single",
                idempotency_key="k" * 64,
            )
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "EXECUTION_REPLAY")
        self.assertEqual(world["runner"].invocations, [])

    def test_lifecycle_order(self):
        world = make_world()
        result = run_ok(world)
        records = world["audit"].records
        transitions = [r.transition for r in records]
        self.assertEqual(
            transitions,
            ["AUTHORIZATION", "EXECUTION_STARTED", "EVIDENCE_SEALED",
             "EXECUTION_TERMINAL"],
        )
        check_ordering(records)
        row = world["ledger"].get(EX_ID)
        assert row is not None
        self.assertEqual(row.lifecycle, "SEALED_REF")
        stored = world["store"].get(AUTHZ_ID)
        assert stored is not None
        self.assertEqual(stored.lifecycle, "CONSUMED")
        _ = result


# ------------------------------------------------------------------
# BOUNDARY (no legacy, no network, no verdicts)
# ------------------------------------------------------------------

class BoundaryTests(unittest.TestCase):
    MODULE_PATH = Path(__file__).parent / "execution" / "nuclei_executor.py"

    def _tree(self) -> ast.AST:
        return ast.parse(self.MODULE_PATH.read_text(encoding="utf-8"))

    def test_no_banned_imports(self):
        banned = {
            "subprocess", "socket", "requests", "httpx", "urllib3",
            "aiohttp", "urllib",
        }
        tree = self._tree()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    self.assertNotIn(root, banned, f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                self.assertNotIn(root, banned, f"from {node.module}")

    def test_no_process_or_transport_calls(self):
        # Name-based boundary: no process-creation, transport, or
        # resolution primitive may be referenced anywhere in the
        # module (imports are checked separately above). Generic
        # method names such as ``run`` are excluded: the internal
        # lifecycle driver legitimately uses one.
        banned_names = {
            "subprocess", "Popen", "check_output", "check_call",
            "create_subprocess_exec", "create_subprocess_shell",
            "getaddrinfo", "gethostbyname", "create_connection",
            "urlopen", "system", "execv", "execl", "spawnl", "fork",
            "getpeername", "connect", "sendall", "to_findings",
        }
        tree = self._tree()
        seen: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                seen.add(node.id)
            elif isinstance(node, ast.Attribute):
                seen.add(node.attr)
        overlap = seen & banned_names
        self.assertFalse(overlap, f"banned references: {overlap}")

    def test_no_legacy_finding_surface(self):
        text = self.MODULE_PATH.read_text(encoding="utf-8")
        tree = self._tree()
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
        self.assertNotIn("to_findings", names)
        self.assertNotIn("NucleiFinding", names)
        self.assertNotIn("to_findings", text)
        self.assertNotIn("NucleiFinding", text)

    def test_no_banned_transport_names(self):
        text = self.MODULE_PATH.read_text(encoding="utf-8")
        tree = self._tree()
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        for banned in ("subprocess", "socket", "requests", "httpx",
                       "urllib3", "aiohttp"):
            self.assertNotIn(banned, imported)

    def test_live_gate_literal_false(self):
        tree = self._tree()
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == (
                        "LIVE_NUCLEI"
                    ):
                        found = True
                        self.assertIsInstance(node.value, ast.Constant)
                        self.assertIs(node.value.value, False)
        self.assertTrue(found, "LIVE_NUCLEI assignment missing")

    def test_gate_not_configurable(self):
        text = self.MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("os.environ", text)
        self.assertNotIn("getenv", text)
        tree = self._tree()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == (
                        "LIVE_NUCLEI"
                    ):
                        self.assertIsInstance(node.value, ast.Constant)

    def test_no_verdict_names_in_module(self):
        text = self.MODULE_PATH.read_text(encoding="utf-8")
        tree = self._tree()
        defined = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                defined.add(node.name)
            if isinstance(node, ast.arg):
                defined.add(node.arg)
        for banned in ("verdict", "severity", "confirmed"):
            self.assertNotIn(banned, defined)

    def test_no_network_primitives_imported(self):
        text = self.MODULE_PATH.read_text(encoding="utf-8")
        for token in ("getaddrinfo", "gethostbyname", "urlopen",
                      "create_connection"):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
