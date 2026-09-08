"""Adversarial offline tests for Phase 5G v1 (closed-spec Browser/XSS executor).

Deterministic stdlib ``unittest``. No browser launch, no JavaScript
execution, no subprocess, no network, no DNS, no LLM, no MongoDB.
Authorization, ledger, audit, policy, and runner peers are fakes.
Random IDs are asserted by format, never by value.

NOTE: this module lives at ``ai/test_browser_executor_5g.py`` (not
``ai/test_browser_executor.py``) because that path is owned by the
pre-existing legacy verification suite, which 5G must neither modify
nor replace.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path
from unittest import mock

from ai.audit.trail import check_ordering
from ai.authorizer.service import consume_authorization, revoke_authorization
from ai.authorizer.store import InMemoryAuthorizationStore
from ai.evidence import hashing as hash_mod
from ai.evidence.builder import verify_record
from ai.evidence.scrubber import REDACTED
from ai.execution import browser_executor as bx
from ai.execution.browser_executor import (
    B5IsolatedBrowserRunner,
    BrowserExecutionSpec,
    BrowserExecutorDeps,
    BrowserRunResult,
    ExecutorError,
    FakeBrowserRunner,
    LiveBrowserRunner,
    ScriptedDialog,
    ScriptedEvalEvent,
    ScriptedHop,
    ScriptedOracleEvent,
    ScriptedPostMessage,
    build_target_string,
    context_dir_for,
    default_resource_limits,
    derive_oracle_binding,
    execute_browser,
    validate_browser_payload,
)
from ai.execution.http_executor import InMemoryAuditSink
from ai.execution.ledger import InMemoryExecutionLedger
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
from ai.verification.oracle import oracle_value_from_seed

PROGRAM = "acme"
HOST = "authorized.example.com"
SIBLING = "evil-attacker.example.com"
SUFFIX_HOST = "authorized.example.com.attacker.example"
ETLD_HOST = "example.com"
OOS_HOST = "other.example.net"
EXCLUDED = "excluded.example.com"

IP_A = "8.8.8.8"

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

GOOD_PAYLOAD = b'"><svg onload=alert(1)>'
ORIGIN = f"https://{HOST}"


# ------------------------------------------------------------------
# Payload / artifact helpers
# ------------------------------------------------------------------

def artifact_reference_for(
    content: bytes, tp_id: str = TP_ID
) -> ArtifactReference:
    digest = content_hash_for_bytes(content)
    return ArtifactReference(
        artifact_id=artifact_id_for(
            artifact_type="xss_payload",
            test_plan_id=tp_id,
            content_hash=digest,
        ),
        artifact_type="xss_payload",
        content_hash=digest,
        test_plan_id=tp_id,
        validation_state="VALID",
    )


# ------------------------------------------------------------------
# Authorization / resolution / evaluation fixtures (genuine types)
# ------------------------------------------------------------------

def make_authz(
    content: bytes = GOOD_PAYLOAD,
    *,
    authz_id: str = AUTHZ_ID,
    host: str = HOST,
    scheme: str = "https",
    port: int = 443,
    execution_class: str = "browser_verification",
    lifecycle: str = "ISSUED",
    expires_at: str = EXPIRES_AT,
    scope_hash: str = SCOPE_HASH,
    derivation: object = None,
    leases: object = None,
) -> IssuedExecutionAuthorization:
    digest = content_hash_for_bytes(content)
    kwargs: dict = {
        "authorization_id": authz_id,
        "idempotency_key": "d" * 64,
        "issuance_nonce": "e" * 32,
        "issuer_identity": "human-review-board",
        "issued_at": ISSUED_AT,
        "expires_at": expires_at,
        "lifecycle": lifecycle,  # type: ignore[arg-type]
        "record_version": 1,
        "test_plan_id": TP_ID,
        "artifact": {
            "artifact_id": artifact_id_for(
                artifact_type="xss_payload",
                test_plan_id=TP_ID,
                content_hash=digest,
            ),
            "artifact_type": "xss_payload",
            "content_hash": digest,
            "test_plan_id": TP_ID,
        },
        "target": {
            "program_name": PROGRAM,
            "host": host,
            "scheme": scheme,
            "effective_port": port,
            "scope_lists_hash": scope_hash,
        },
        "execution_class": execution_class,  # type: ignore[arg-type]
    }
    if derivation is not None:
        kwargs["xss_derivation"] = derivation
    if leases is not None:
        kwargs["stored_leases"] = leases
    return IssuedExecutionAuthorization(**kwargs)


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


def target_for(authz: IssuedExecutionAuthorization) -> str:
    return f"https://{authz.target.host}/"


def scripted_ok(
    target: str,
    oracle_value: str | None = None,
    *,
    dialogs: tuple = (),
    oracle_events: tuple = (),
    eval_events: tuple = (),
    extra_hops: tuple = (),
    **overrides,
) -> BrowserRunResult:
    hops = (ScriptedHop(url=target),) + tuple(
        ScriptedHop(url=u) for u in extra_hops
    )
    final = extra_hops[-1] if extra_hops else target
    params: dict = {
        "navigations": hops,
        "final_url": final,
        "dialogs": dialogs,
        "oracle_events": oracle_events,
        "eval_events": eval_events,
    }
    params.update(overrides)
    return BrowserRunResult(**params)


def make_world(
    content: bytes = GOOD_PAYLOAD,
    *,
    runner: FakeBrowserRunner | None = None,
    ex_id: str = EX_ID,
    authz_kwargs: dict | None = None,
    scripted: BrowserRunResult | None = None,
):
    authz = make_authz(content, **(authz_kwargs or {}))
    store = InMemoryAuthorizationStore()
    store.put_new(authz)
    resolution = make_resolution(authz, ex_id)
    evaluation = make_evaluation(authz, resolution, ex_id)
    ledger = InMemoryExecutionLedger()
    audit = InMemoryAuditSink()
    deps = BrowserExecutorDeps(
        authz_store=store,
        ledger=ledger,
        audit=audit,
        now_iso=lambda: NOW,
        monotonic=lambda: 1000.0,
    )
    if runner is None:
        runner = FakeBrowserRunner(
            scripted_ok(target_for(authz)) if scripted is None else scripted
        )
    return {
        "authz": authz,
        "store": store,
        "resolution": resolution,
        "evaluation": evaluation,
        "ledger": ledger,
        "audit": audit,
        "deps": deps,
        "runner": runner,
        "reference": artifact_reference_for(content),
        "content": content,
        "target": target_for(authz),
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
    return execute_browser(**params)


def oracle_of(world: dict, ex_id: str = EX_ID):
    binding = derive_oracle_binding(
        execution_id=ex_id,
        authorization=world["authz"],
        origin=("https", HOST, 443),
    )
    assert binding.value == oracle_value_from_seed(binding.seed)
    return binding


# ------------------------------------------------------------------
# Authorization
# ------------------------------------------------------------------

class AuthorizationTests(unittest.TestCase):
    def test_valid_authorization_seals(self):
        world = make_world()
        result = run_ok(world)
        self.assertEqual(result.outcome, "sealed")
        self.assertIsNotNone(result.evidence)
        assert result.evidence is not None
        self.assertEqual(result.evidence.execution_class, "browser_verification")
        self.assertEqual(len(world["runner"].invocations), 1)

    def test_expired_authorization_refused(self):
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
        self.assertIn(ctx.exception.code, ("AUTHZ_NOT_FOUND", "AUTHZ_NOT_LIVE"))
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_execution_class_refused(self):
        world = make_world(authz_kwargs={"execution_class": "http_probe"})
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUTHZ_BINDING_MISMATCH")
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_program_refused(self):
        world = make_world()
        res = world["resolution"]
        tampered = TargetResolution.model_validate(
            {**res.model_dump(mode="json"), "program_name": "other"}
        )
        with self.assertRaises(ExecutorError):
            run_ok(world, resolution=tampered)
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

    def test_wrong_artifact_refused(self):
        world = make_world()
        other = b'"><svg onload=alert(2)>'
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, artifact_bytes=other)
        self.assertEqual(ctx.exception.code, "ARTIFACT_REVALIDATION_FAILED")
        self.assertEqual(world["runner"].invocations, [])

    def test_replay_after_consume_refused(self):
        world = make_world()
        first = run_ok(world)
        self.assertEqual(first.outcome, "sealed")
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(len(world["runner"].invocations), 1)


# ------------------------------------------------------------------
# Target binding
# ------------------------------------------------------------------

class TargetTests(unittest.TestCase):
    def test_canonical_target_string(self):
        self.assertEqual(
            build_target_string(
                scheme="https", canonical_host=HOST, effective_port=443
            ),
            f"https://{HOST}/",
        )
        self.assertEqual(
            build_target_string(
                scheme="https", canonical_host=HOST, effective_port=8443,
                path="/app",
            ),
            f"https://{HOST}:8443/app",
        )

    def test_canonical_target_executes(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        self.assertEqual(result.spec.target_string, f"https://{HOST}/")
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

    def test_suffix_host_refused(self):
        world = make_world()
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, host=SUFFIX_HOST
        )
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID, expect=None
        )
        with self.assertRaises(ExecutorError):
            run_ok(world)
        self.assertEqual(world["runner"].invocations, [])

    def test_etld_attempt_refused(self):
        world = make_world()
        world["authz"] = make_authz(host=ETLD_HOST)
        world["store"] = InMemoryAuthorizationStore()
        world["store"].put_new(world["authz"])
        world["deps"].authz_store = world["store"]
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, host=ETLD_HOST
        )
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID, expect="DENIED"
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "TARGET_NOT_IN_SCOPE")
        self.assertEqual(world["runner"].invocations, [])

    def test_excluded_host_refused(self):
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
            ctx.exception.code, ("TARGET_NOT_IN_SCOPE", "TARGET_EXCLUDED")
        )
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_scheme_refused(self):
        world = make_world()
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, scheme="http", port=80
        )
        with self.assertRaises(ExecutorError):
            run_ok(world)
        self.assertEqual(world["runner"].invocations, [])

    def test_wrong_port_refused(self):
        world = make_world()
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, port=8443
        )
        with self.assertRaises(ExecutorError):
            run_ok(world)
        self.assertEqual(world["runner"].invocations, [])

    def test_ip_authority_refused(self):
        world = make_world()
        world["authz"] = make_authz(host="8.8.8.8")
        world["store"] = InMemoryAuthorizationStore()
        world["store"].put_new(world["authz"])
        world["deps"].authz_store = world["store"]
        world["resolution"] = make_resolution(
            world["authz"], EX_ID, host="8.8.8.8"
        )
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID, expect=None
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "TARGET_BINDING_MISMATCH")
        self.assertEqual(world["runner"].invocations, [])

    def test_resolution_mismatch_refused(self):
        world = make_world()
        other = make_resolution(world["authz"], "ex-" + "e" * 32)
        with self.assertRaises(ExecutorError):
            run_ok(world, resolution=other)
        self.assertEqual(world["runner"].invocations, [])

    def test_scope_mismatch_refused(self):
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
        self.assertEqual(ctx.exception.code, "TARGET_NOT_IN_SCOPE")
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
        self.assertEqual(world["runner"].invocations, [])


# ------------------------------------------------------------------
# Payload safety
# ------------------------------------------------------------------

class PayloadTests(unittest.TestCase):
    def _deny(self, content: bytes, feature: str):
        report = validate_browser_payload(content)
        self.assertEqual(report.decision, "DENY", report.reasons)
        self.assertIn(feature, report.denied_features)

    def test_valid_payload_allows(self):
        report = validate_browser_payload(GOOD_PAYLOAD)
        self.assertEqual(report.decision, "ALLOW")
        self.assertEqual(report.denied_features, ())
        self.assertEqual(
            report.payload_hash, content_hash_for_bytes(GOOD_PAYLOAD)
        )

    def test_oversized_payload_denied(self):
        from ai.schemas.artifact import max_bytes_for

        big = b"x" * (max_bytes_for("xss_payload") + 1)
        self._deny(big, "payload-size")

    def test_empty_payload_denied(self):
        self._deny(b"", "payload-empty")

    def test_non_utf8_denied(self):
        self._deny(b"\xff\xfe\x00\x01", "encoding")

    def test_hash_drift_refused_at_execution(self):
        world = make_world()
        ref = world["reference"].model_copy(
            update={"content_hash": "0" * 64}
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, artifact_reference=ref)
        self.assertEqual(ctx.exception.code, "ARTIFACT_REVALIDATION_FAILED")

    def test_artifact_drift_refused_at_execution(self):
        world = make_world()
        other = b'"><svg onload=alert(9)>'
        other_ref = artifact_reference_for(other)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, artifact_reference=other_ref, artifact_bytes=other)
        self.assertEqual(ctx.exception.code, "ARTIFACT_REVALIDATION_FAILED")

    def test_file_scheme_denied(self):
        self._deny(b"<img src=file:///etc/passwd>", "foreign-scheme")

    def test_data_scheme_denied(self):
        self._deny(b"<img src=data:text/html;base64,xxx>", "foreign-scheme")

    def test_blob_scheme_denied(self):
        self._deny(b"<video src=blob:https://x/y>", "foreign-scheme")

    def test_javascript_scheme_denied(self):
        self._deny(b"<a href=javascript:alert(1)>x</a>", "foreign-scheme")

    def test_absolute_url_denied(self):
        self._deny(b"<img src=https://attacker.example/x>", "absolute-url")

    def test_oob_markers_denied(self):
        for marker in (b"interactsh", b"oastify", b"webhook.site", b"dnslog"):
            with self.subTest(marker=marker):
                report = validate_browser_payload(b"x" + marker + b"y")
                self.assertEqual(report.decision, "DENY")
                self.assertIn("oob-callback", report.denied_features)

    def test_bare_oast_denied(self):
        self._deny(b"fetch(oast-server)", "oob-callback")

    def test_oast_false_positive_guard(self):
        # "toast" contains "oast" but is not an OOB marker.
        report = validate_browser_payload(b"<div>toast message</div>")
        self.assertEqual(report.decision, "ALLOW")

    def test_interactsh_denied(self):
        self._deny(b"cb=abc.interactsh.com", "oob-callback")

    def test_webhook_denied(self):
        self._deny(b"cb=https://webhook.site/x", "oob-callback")

    def test_arbitrary_iframe_denied(self):
        self._deny(b"<iframe src=/frame>", "active-primitive")

    def test_websocket_denied(self):
        self._deny(b"new WebSocket(wss://x)", "websocket")

    def test_webrtc_denied(self):
        self._deny(b"new RTCPeerConnection()", "active-primitive")

    def test_download_denied(self):
        self._deny(b"a.download('x')", "active-primitive")

    def test_serviceworker_denied(self):
        self._deny(b"navigator.serviceWorker.register()", "active-primitive")

    def test_unsafe_payload_never_executes(self):
        bad = b"<iframe src=https://attacker.example/x>"
        world = make_world(content=bad)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "PAYLOAD_REJECTED")
        self.assertEqual(world["runner"].invocations, [])

    def test_typed_input_enforced(self):
        with self.assertRaises(TypeError):
            validate_browser_payload("not-bytes")  # type: ignore[arg-type]


# ------------------------------------------------------------------
# Navigation model
# ------------------------------------------------------------------

class NavigationTests(unittest.TestCase):
    def test_same_origin_multihop_allowed(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                extra_hops=(target + "?a=1", target + "?a=1&b=2"),
            )
        )
        result = run_ok(world)
        self.assertEqual(result.outcome, "sealed")
        self.assertEqual(result.navigations_evaluated, 3)

    def test_allowed_redirect_records_chain(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, extra_hops=(target + "landing",))
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertIn("landing", result.evidence.browser.page_url.redacted_url)
        self.assertEqual(result.navigations_evaluated, 2)

    def test_cross_origin_redirect_aborts(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, extra_hops=(f"https://{SIBLING}/",))
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "NAV_CROSS_ORIGIN")

    def test_port_change_aborts(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, extra_hops=(f"https://{HOST}:8443/",))
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "NAV_PORT_CHANGE")

    def test_scheme_downgrade_aborts(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, extra_hops=(f"http://{HOST}/",))
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "NAV_DOWNGRADE")

    def test_ip_redirect_aborts(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, extra_hops=("https://8.8.8.8/",))
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "NAV_IP_AUTHORITY")

    def test_redirect_loop_aborts(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, extra_hops=(target + "a", target))
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "NAV_LOOP")

    def test_redirect_ceiling_enforced(self):
        world = make_world()
        target = world["target"]
        hops = tuple(f"{target}hop{i}" for i in range(CEILINGS["redirect_hops"] + 1))
        world["runner"] = FakeBrowserRunner(scripted_ok(target, extra_hops=hops))
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "NAV_LIMIT")

    def test_first_hop_mismatch_aborts(self):
        world = make_world()
        world["runner"] = FakeBrowserRunner(
            scripted_ok(f"https://{SIBLING}/")
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "NAV_MISMATCH")

    def test_final_url_divergence_aborts(self):
        world = make_world()
        target = world["target"]
        scripted = scripted_ok(target)
        divergent = BrowserRunResult(
            navigations=scripted.navigations,
            final_url=target + "elsewhere",
        )
        world["runner"] = FakeBrowserRunner(divergent)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "NAV_MISMATCH")


# ------------------------------------------------------------------
# Oracle (P/O separation + E1/E2/E3 observations)
# ------------------------------------------------------------------

class OracleTests(unittest.TestCase):
    def test_p_o_identity_separation(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        assert result.evidence is not None
        assert result.evidence.browser is not None
        payload_hash = result.spec.payload_hash
        oracle_hash = result.evidence.browser.executed_payload_hash
        self.assertEqual(payload_hash, content_hash_for_bytes(GOOD_PAYLOAD))
        assert oracle_hash is not None
        self.assertNotEqual(payload_hash, oracle_hash)

    def test_deterministic_derivation(self):
        world = make_world()
        first = oracle_of(world)
        second = oracle_of(world)
        self.assertEqual(first.seed, second.seed)
        self.assertEqual(first.value, second.value)
        other = derive_oracle_binding(
            execution_id="ex-" + "d" * 32,
            authorization=world["authz"],
            origin=("https", HOST, 443),
        )
        self.assertNotEqual(first.value, other.value)
        self.assertNotEqual(first.seed, other.seed)

    def test_wrong_execution_oracle_dropped(self):
        world = make_world()
        target = world["target"]
        binding = oracle_of(world)
        foreign = derive_oracle_binding(
            execution_id="ex-" + "d" * 32,
            authorization=world["authz"],
            origin=("https", HOST, 443),
        )
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                dialogs=(
                    ScriptedDialog(kind="alert", message=foreign.value,
                                   origin=ORIGIN),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertFalse(result.evidence.browser.e1_observed)
        self.assertNotIn(
            binding.value,
            (result.evidence.browser.dialog_marker_hashes or ()),
        )

    def test_wrong_origin_oracle_dropped(self):
        world = make_world()
        target = world["target"]
        binding = oracle_of(world)
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                dialogs=(
                    ScriptedDialog(kind="alert", message=binding.value,
                                   origin=f"https://{SIBLING}"),
                ),
                oracle_events=(
                    ScriptedOracleEvent(
                        channel="network", marker=binding.value,
                        url=f"https://{SIBLING}/.watch-oracle/{binding.value}",
                        is_navigation=False, origin=f"https://{SIBLING}"),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertFalse(result.evidence.browser.e1_observed)
        self.assertFalse(result.evidence.browser.e2_observed)
        self.assertEqual(result.cross_origin_dropped, 2)

    def test_e1_exact_dialog_observed(self):
        world = make_world()
        target = world["target"]
        binding = oracle_of(world)
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                dialogs=(
                    ScriptedDialog(kind="alert", message=binding.value,
                                   origin=ORIGIN),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertTrue(result.evidence.browser.e1_observed)
        self.assertEqual(result.dialogs_recorded, 1)

    def test_e1_substring_not_observed(self):
        world = make_world()
        target = world["target"]
        binding = oracle_of(world)
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                dialogs=(
                    ScriptedDialog(kind="alert",
                                   message="prefix-" + binding.value,
                                   origin=ORIGIN),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertFalse(result.evidence.browser.e1_observed)

    def test_e2_oracle_path_observed(self):
        world = make_world()
        target = world["target"]
        binding = oracle_of(world)
        url = f"{ORIGIN}/.watch-oracle/{binding.value}"
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                oracle_events=(
                    ScriptedOracleEvent(
                        channel="network", marker=binding.value, url=url,
                        is_navigation=False, origin=ORIGIN),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertTrue(result.evidence.browser.e2_observed)
        self.assertEqual(result.oracle_events_recorded, 1)

    def test_e2_navigation_excluded(self):
        world = make_world()
        target = world["target"]
        binding = oracle_of(world)
        url = f"{ORIGIN}/.watch-oracle/{binding.value}"
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                oracle_events=(
                    ScriptedOracleEvent(
                        channel="network", marker=binding.value, url=url,
                        is_navigation=True, origin=ORIGIN),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertFalse(result.evidence.browser.e2_observed)

    def test_e3_exact_eval_observed(self):
        world = make_world()
        target = world["target"]
        payload_text = GOOD_PAYLOAD.decode("utf-8")
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                eval_events=(
                    ScriptedEvalEvent(operator="eval", value=payload_text),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertTrue(result.evidence.browser.e3_observed)

    def test_e3_long_payload_disabled(self):
        payload = b"z" * 300
        report = validate_browser_payload(payload)
        self.assertEqual(report.decision, "ALLOW")
        world = make_world(content=payload)
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                eval_events=(
                    ScriptedEvalEvent(
                        operator="eval", value=payload.decode("utf-8")),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertFalse(result.evidence.browser.e3_observed)

    def test_anti_harvest_rejects_oracle_in_payload(self):
        world = make_world()
        binding = oracle_of(world)
        poisoned = b"x" + binding.value.encode("utf-8")
        report = validate_browser_payload(poisoned)
        poisoned_world = make_world(content=poisoned)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(poisoned_world)
        self.assertEqual(ctx.exception.code, "ORACLE_BINDING_MISMATCH")
        _ = report


# ------------------------------------------------------------------
# Frames / origins
# ------------------------------------------------------------------

class FrameTests(unittest.TestCase):
    def test_same_origin_subnavigation_allowed(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, extra_hops=(target + "frame-a",))
        )
        result = run_ok(world)
        self.assertEqual(result.outcome, "sealed")
        self.assertEqual(result.navigations_evaluated, 2)

    def test_cross_origin_frame_denied(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, extra_hops=(f"https://{SIBLING}/frame",))
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "NAV_CROSS_ORIGIN")

    def test_popup_aborts(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, popup_attempted=True)
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "POPUP_BLOCKED")

    def test_postmessage_observation_only(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                postmessages=(
                    ScriptedPostMessage(origin=ORIGIN, data="hello"),
                    ScriptedPostMessage(
                        origin=f"https://{SIBLING}", data="evil"),
                ),
            )
        )
        result = run_ok(world)
        self.assertEqual(result.postmessages_observed, 1)
        self.assertEqual(result.cross_origin_dropped, 1)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertFalse(result.evidence.browser.e1_observed)
        self.assertFalse(result.evidence.browser.e2_observed)

    def test_document_domain_aborts(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, document_domain_relaxed=True)
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "DOCUMENT_DOMAIN")


# ------------------------------------------------------------------
# Context isolation
# ------------------------------------------------------------------

class ContextTests(unittest.TestCase):
    def test_spec_immutable(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        with self.assertRaises(Exception):
            result.spec.target_string = "https://evil.example"  # type: ignore[misc]

    def test_fresh_profile_bound_to_execution(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        context_dir = dict(result.spec.environment)["HOME"]
        self.assertIn(EX_ID, context_dir)
        self.assertTrue(
            context_dir.startswith("/srv/watch/scratch/browser/")
        )
        self.assertIsNone(result.spec.context.persistent_profile)

    def test_no_inherited_state(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        context = result.spec.context
        self.assertTrue(context.ephemeral)
        self.assertEqual((context.contexts, context.pages), (1, 1))
        self.assertEqual(context.extensions, ())
        self.assertEqual(context.cookies, ())
        self.assertFalse(context.credentials)
        self.assertFalse(context.password_manager)
        self.assertFalse(context.sync)
        self.assertTrue(context.popups_denied)
        self.assertTrue(context.downloads_denied)
        self.assertTrue(context.serviceworkers_denied)

    def test_no_extensions_or_credentials(self):
        from ai.execution.browser_executor import BrowserContextDescriptor

        with self.assertRaises(ExecutorError):
            BrowserContextDescriptor(extensions=("evil-ext",))
        with self.assertRaises(ExecutorError):
            BrowserContextDescriptor(credentials=True)
        with self.assertRaises(ExecutorError):
            BrowserContextDescriptor(persistent_profile="/home/user/profile")

    def test_environment_allowlist_no_proxy(self):
        world = make_world()
        result = run_ok(world)
        assert result.spec is not None
        names = {name for name, _ in result.spec.environment}
        self.assertEqual(
            names, {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}
        )
        for banned in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
            self.assertNotIn(banned, names)


# ------------------------------------------------------------------
# Resources
# ------------------------------------------------------------------

class ResourceTests(unittest.TestCase):
    def test_limits_reuse_ceilings(self):
        limits = default_resource_limits()
        self.assertEqual(limits.wall_seconds, CEILINGS["browser_wall_seconds"])
        self.assertEqual(limits.pages, CEILINGS["browser_pages"])
        self.assertEqual(limits.contexts, CEILINGS["browser_contexts"])
        self.assertEqual(limits.redirects, CEILINGS["redirect_hops"])
        self.assertEqual(
            limits.exchanges, CEILINGS["requests_per_execution"]
        )
        self.assertEqual(
            limits.response_bytes, CEILINGS["response_transport_bytes"]
        )
        self.assertEqual(
            limits.scratch_bytes, CEILINGS["temp_storage_bytes"]
        )

    def test_event_bounds_present(self):
        from ai.execution.browser_executor import BROWSER_EVENT_BOUNDS

        for name in (
            "dialog_events", "frame_events", "console_entries",
            "oracle_events", "dom_observation_bytes", "storage_keys",
        ):
            self.assertIn(name, BROWSER_EVENT_BOUNDS)
            self.assertGreater(BROWSER_EVENT_BOUNDS[name], 0)
        self.assertEqual(BROWSER_EVENT_BOUNDS["popup_events"], 0)

    def test_truncated_channels_seal_incomplete(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, channels_truncated=True)
        )
        result = run_ok(world)
        self.assertEqual(result.outcome, "incomplete")
        assert result.evidence is not None
        self.assertEqual(result.evidence.lifecycle, "INCOMPLETE")
        self.assertFalse(result.evidence.complete)
        row = world["ledger"].get(EX_ID)
        assert row is not None
        self.assertEqual(row.lifecycle, "INCOMPLETE_REF")

    def test_console_over_cap_truncates_to_partial(self):
        from ai.execution.browser_executor import BROWSER_EVENT_BOUNDS

        world = make_world()
        target = world["target"]
        lines = tuple(
            f"console line {i}"
            for i in range(BROWSER_EVENT_BOUNDS["console_entries"] + 5)
        )
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, console=lines)
        )
        result = run_ok(world)
        self.assertEqual(result.outcome, "incomplete")
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertTrue(result.evidence.browser.channels_truncated)

    def test_storage_key_bound(self):
        from ai.execution.browser_executor import BROWSER_EVENT_BOUNDS

        world = make_world()
        target = world["target"]
        keys = tuple(
            f"k{i}" for i in range(BROWSER_EVENT_BOUNDS["storage_keys"] + 3)
        )
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, storage_keys=keys)
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertTrue(result.evidence.browser.channels_truncated)
        self.assertIsNotNone(result.evidence.browser.storage_keys_hash)


# ------------------------------------------------------------------
# Evidence
# ------------------------------------------------------------------

class EvidenceTests(unittest.TestCase):
    def test_browser_observation_only(self):
        world = make_world()
        result = run_ok(world)
        assert result.evidence is not None
        record = result.evidence
        self.assertEqual(record.execution_class, "browser_verification")
        self.assertIsNone(record.http)
        self.assertIsNone(record.nuclei)
        self.assertIsNotNone(record.browser)
        verify_record(record)

    def test_scrub_before_hash(self):
        world = make_world()
        target = world["target"]
        secret = "bearer abcdefghijklmnop"
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                dialogs=(
                    ScriptedDialog(kind="alert", message=f"note {secret} end",
                                   origin=ORIGIN),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        markers = result.evidence.browser.dialog_marker_hashes
        self.assertEqual(len(markers), 1)
        scrubbed = f"alert:note {REDACTED} end"
        self.assertEqual(
            markers[0], hash_mod.sha256_hex(scrubbed.encode("utf-8"))
        )
        dumped = record_dump(result.evidence)
        self.assertNotIn("abcdefghijklmnop", dumped)

    def test_payload_hash_binding(self):
        world = make_world()
        result = run_ok(world)
        assert result.evidence is not None
        assert result.spec is not None
        self.assertEqual(
            result.evidence.artifact_content_hash,
            content_hash_for_bytes(GOOD_PAYLOAD),
        )
        self.assertEqual(
            result.spec.payload_hash, content_hash_for_bytes(GOOD_PAYLOAD)
        )
        self.assertEqual(result.evidence.artifact_id, result.spec.artifact_id)

    def test_oracle_hash_binding(self):
        world = make_world()
        binding = oracle_of(world)
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertEqual(
            result.evidence.browser.executed_payload_hash,
            hash_mod.hash_text(binding.value),
        )

    def test_bounded_dialog_samples(self):
        world = make_world()
        target = world["target"]
        long_message = "m" * (8 * 1024 + 100)
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                dialogs=(
                    ScriptedDialog(kind="alert", message=long_message,
                                   origin=ORIGIN),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        markers = result.evidence.browser.dialog_marker_hashes
        self.assertEqual(len(markers), 1)
        capped = ("alert:" + long_message).encode("utf-8")[: 8 * 1024]
        self.assertEqual(markers[0], hash_mod.sha256_hex(capped))

    def test_no_classification_fields(self):
        world = make_world()
        target = world["target"]
        binding = oracle_of(world)
        world["runner"] = FakeBrowserRunner(
            scripted_ok(
                target,
                dialogs=(
                    ScriptedDialog(kind="alert", message=binding.value,
                                   origin=ORIGIN),
                ),
            )
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertTrue(result.evidence.browser.e1_observed)
        dumped = record_dump(result.evidence)
        for banned in (
            "CONFIRMED", "NOT_VULNERABLE", "VULNERABLE", "severity",
            "verdict", "finding",
        ):
            if banned == "VULNERABLE":
                continue  # covered by NOT_VULNERABLE exclusion wording
            self.assertNotIn(banned, dumped)

    def test_advisory_booleans_default_false(self):
        world = make_world()
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertFalse(result.evidence.browser.e1_observed)
        self.assertFalse(result.evidence.browser.e2_observed)
        self.assertFalse(result.evidence.browser.e3_observed)

    def test_page_url_bound_to_final(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, extra_hops=(target + "read",))
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        assert result.evidence.browser.page_url is not None
        self.assertIn(
            "read", result.evidence.browser.page_url.redacted_url
        )


def record_dump(record) -> str:
    import json as _json

    return _json.dumps(record.model_dump(mode="json"), sort_keys=True)


# ------------------------------------------------------------------
# Failure model
# ------------------------------------------------------------------

class FailureTests(unittest.TestCase):
    def test_live_runner_always_blocked(self):
        world = make_world()
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, runner=LiveBrowserRunner())
        self.assertEqual(ctx.exception.code, "BROWSER_EXECUTION_BLOCKED")

    def test_b5_placeholder_blocked(self):
        world = make_world()
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world, runner=B5IsolatedBrowserRunner())
        self.assertEqual(ctx.exception.code, "BROWSER_EXECUTION_BLOCKED")

    def test_runner_timeout_unknown(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, timed_out=True)
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "BROWSER_TIMEOUT")
        row = world["ledger"].get(EX_ID)
        assert row is not None
        self.assertEqual(row.lifecycle, "UNKNOWN")

    def test_runner_crash_unknown(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, crashed=True)
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "BROWSER_CRASH")

    def test_download_aborts(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, download_attempted=True)
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "DOWNLOAD_BLOCKED")

    def test_serviceworker_aborts(self):
        world = make_world()
        target = world["target"]
        world["runner"] = FakeBrowserRunner(
            scripted_ok(target, serviceworker_attempted=True)
        )
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "SERVICEWORKER_BLOCKED")

    def test_scope_ambiguity_no_evidence(self):
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
        self.assertEqual(ctx.exception.code, "TARGET_NOT_IN_SCOPE")
        self.assertEqual(world["runner"].invocations, [])

    def test_pre_launch_audit_gap_no_launch(self):
        world = make_world()
        world["audit"].fail_from = 1
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUDIT_GAP")
        self.assertEqual(world["runner"].invocations, [])

    def test_evidence_seal_failure_unknown(self):
        world = make_world()
        with mock.patch(
            "ai.execution.browser_executor.EvidenceBuilder"
        ) as builder_cls:
            instance = mock.Mock()
            instance.attach_browser.return_value = None
            instance.seal.side_effect = ev.EvidenceError(
                "EVIDENCE_INCOMPLETE", "missing"
            )
            builder_cls.begin.return_value = instance
            with self.assertRaises(ExecutorError) as ctx:
                run_ok(world)
        self.assertEqual(ctx.exception.code, "EVIDENCE_SEAL_FAILED")
        row = world["ledger"].get(EX_ID)
        assert row is not None
        self.assertEqual(row.lifecycle, "UNKNOWN")

    def test_consume_ambiguity_no_retry(self):
        world = make_world()
        consume_authorization(world["store"], AUTHZ_ID, now=NOW)
        with self.assertRaises(ExecutorError) as ctx:
            run_ok(world)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(world["runner"].invocations, [])

    def test_replay_refused(self):
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
        run_ok(world)
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


# ------------------------------------------------------------------
# Derivation / round binding
# ------------------------------------------------------------------

class DerivationTests(unittest.TestCase):
    def test_derivation_phase_binds_oracle(self):
        from ai.schemas.execution_authorization import XSSDerivationContract

        world = make_world()
        digest = content_hash_for_bytes(GOOD_PAYLOAD)
        derivation = XSSDerivationContract(
            source_artifact_id=world["reference"].artifact_id,
            source_content_hash=digest,
            allowed_context="html_body",
            allowed_skeleton_family="script",
            execution_phase="stored_submit",
        )
        world["authz"] = make_authz(derivation=derivation)
        world["store"] = InMemoryAuthorizationStore()
        world["store"].put_new(world["authz"])
        world["deps"].authz_store = world["store"]
        world["resolution"] = make_resolution(world["authz"], EX_ID)
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID
        )
        world["runner"] = FakeBrowserRunner(
            scripted_ok(world["target"])
        )
        result = run_ok(world)
        assert result.spec is not None
        self.assertEqual(result.spec.oracle.phase, "stored_submit")

    def test_round_id_from_leases(self):
        from ai.schemas.execution_authorization import StoredStageLeases

        world = make_world()
        leases = StoredStageLeases(round_id="sr-" + "1" * 32)
        world["authz"] = make_authz(leases=leases)
        world["store"] = InMemoryAuthorizationStore()
        world["store"].put_new(world["authz"])
        world["deps"].authz_store = world["store"]
        world["resolution"] = make_resolution(world["authz"], EX_ID)
        world["evaluation"] = make_evaluation(
            world["authz"], world["resolution"], EX_ID
        )
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertEqual(
            result.evidence.browser.round_id, "sr-" + "1" * 32
        )

    def test_no_round_without_leases(self):
        world = make_world()
        result = run_ok(world)
        assert result.evidence is not None
        assert result.evidence.browser is not None
        self.assertIsNone(result.evidence.browser.round_id)


# ------------------------------------------------------------------
# Boundary (AST)
# ------------------------------------------------------------------

class BoundaryTests(unittest.TestCase):
    MODULE_PATH = Path(__file__).parent / "execution" / "browser_executor.py"

    def _tree(self):
        import ast as _ast

        return _ast.parse(self.MODULE_PATH.read_text(encoding="utf-8"))

    def test_no_banned_imports(self):
        banned = {
            "playwright", "selenium", "chromium", "firefox",
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

    def test_no_banned_names_or_calls(self):
        banned_names = {
            "getaddrinfo", "gethostbyname", "create_connection",
            "urlopen", "system", "exec", "fork", "spawnl",
            "to_findings", "NucleiFinding", "Finding",
            "Popen", "check_output", "create_subprocess_exec",
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

    def test_no_page_evaluate_primitive(self):
        tree = self._tree()
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "evaluate":
                self.fail("page.evaluate-shaped primitive present")

    def test_no_classification_names(self):
        banned = {"verdict", "severity", "CONFIRMED", "VULNERABLE",
                  "NOT_VULNERABLE", "Finding", "finding"}
        tree = self._tree()
        defined: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                defined.add(node.name)
            if isinstance(node, ast.arg):
                defined.add(node.arg)
            if isinstance(node, ast.Name):
                defined.add(node.id)
        overlap = defined & banned
        self.assertFalse(overlap, f"classification names: {overlap}")

    def test_no_banned_string_tokens(self):
        text = self.MODULE_PATH.read_text(encoding="utf-8")
        for token in ("CONFIRMED", "NOT_VULNERABLE", "to_findings",
                      "NucleiFinding", "page.evaluate", "getaddrinfo",
                      "urlopen", "os.system"):
            self.assertNotIn(token, text)

    def test_live_gate_literal_false(self):
        tree = self._tree()
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == (
                        "LIVE_BROWSER"
                    ):
                        found = True
                        self.assertIsInstance(node.value, ast.Constant)
                        self.assertIs(node.value.value, False)
        self.assertTrue(found, "LIVE_BROWSER assignment missing")

    def test_gate_single_assignment_non_configurable(self):
        tree = self._tree()
        stores = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == (
                        "LIVE_BROWSER"
                    ):
                        stores += 1
            if isinstance(node, ast.AnnAssign):
                target = node.target
                if isinstance(target, ast.Name) and target.id == (
                    "LIVE_BROWSER"
                ):
                    stores += 1
        self.assertEqual(stores, 1, "LIVE_BROWSER must be assigned once")
        text = self.MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("os.environ", text)
        self.assertNotIn("getenv", text)
        for node in ast.walk(tree):
            if isinstance(node, ast.arg) and node.arg == "LIVE_BROWSER":
                self.fail("LIVE_BROWSER must not be a parameter")


if __name__ == "__main__":
    unittest.main()
