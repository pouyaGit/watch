"""Adversarial offline tests for Phase 5E (IP-pinned HTTP executor).

Deterministic stdlib ``unittest``. No internet, no real DNS, no real
external connections, no subprocess, no browser, no Nuclei, no LLM,
no MongoDB. All sockets, TLS, DNS, policy, ledger, and audit peers
are fakes. Random IDs are asserted by format, never by value.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import os
import unittest
from unittest import mock

from ai.audit.trail import check_ordering
from ai.authorizer.store import InMemoryAuthorizationStore
from ai.evidence import hashing as hash_mod
from ai.evidence import observations as obs
from ai.evidence.builder import verify_record
from ai.evidence.scrubber import REDACTED
from ai.execution import http_executor as hx
from ai.execution.http_executor import (
    ExecutorDeps,
    ExecutorError,
    InMemoryAuditSink,
    execute_http,
    translate_bounded_request,
)
from ai.execution.ledger import InMemoryExecutionLedger
from ai.resolver.dns import DnsError, validate_answers
from ai.resolver.inventory import scope_lists_hash_for
from ai.schemas import evidence as ev
from ai.schemas.artifact import (
    ArtifactReference,
    artifact_id_for,
    content_hash_for_bytes,
)
from ai.schemas.execution_authorization import IssuedExecutionAuthorization
from ai.schemas.scope_evaluation import ScopeEvaluation, evaluation_id_for
from ai.schemas.target_resolution import (
    DialBinding,
    TargetResolution,
    canonical_target_hash_for,
    resolution_id_for,
)
from ai.scope.evaluator import HopObservation, ScopeEvaluator
from ai.scope.policy import InMemoryPolicyStore

PROGRAM = "acme"
HOST = "authorized.example.com"
SIBLING = "evil.example.com"
OOS_HOST = "other.example.net"
EXCLUDED = "excluded.example.com"

IP_A = "8.8.8.8"
IP_B = "8.8.4.4"
IP_C = "1.1.1.1"
UNSAFE_IP = "127.0.0.1"
PRIVATE_IP = "10.9.9.9"

SCOPES = [HOST, "www.example.com"]
OOSCOPES: list[str] = []
SCOPE_HASH = scope_lists_hash_for(SCOPES, OOSCOPES)

TP_ID = "tp-" + "a" * 16
AUTHZ_ID = "authz-" + "b" * 16
EX_ID = "ex-" + "c" * 32
ISSUED_AT = "2026-01-01T00:00:00+00:00"
NOW = "2026-01-15T00:00:00+00:00"
EXPIRES_AT = "2026-02-01T00:00:00+00:00"


# ------------------------------------------------------------------
# Artifact helpers
# ------------------------------------------------------------------

def artifact_content(
    method="GET",
    path="/search",
    query=None,
    headers=None,
    body=None,
) -> bytes:
    payload = {
        "method": method,
        "path": path,
        "query_params": query if query is not None else {"q": "hello"},
        "headers": headers if headers is not None else {"accept": "text/html"},
        "body": body,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


GOOD_ARTIFACT = artifact_content()


def artifact_reference_for(content: bytes, tp_id: str = TP_ID) -> ArtifactReference:
    digest = content_hash_for_bytes(content)
    return ArtifactReference(
        artifact_id=artifact_id_for(
            artifact_type="http_request_spec",
            test_plan_id=tp_id,
            content_hash=digest,
        ),
        artifact_type="http_request_spec",
        content_hash=digest,
        test_plan_id=tp_id,
        validation_state="VALID",
    )


# ------------------------------------------------------------------
# Authorization / resolution / evaluation fixtures (genuine types)
# ------------------------------------------------------------------

def make_authz(
    content: bytes = GOOD_ARTIFACT,
    *,
    authz_id: str = AUTHZ_ID,
    host: str = HOST,
    scheme: str = "https",
    port: int = 443,
    plan_method: str = "GET",
    artifact_method: str = "GET",
    execution_class: str = "http_probe",
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
                artifact_type="http_request_spec",
                test_plan_id=TP_ID,
                content_hash=digest,
            ),
            "artifact_type": "http_request_spec",
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
) -> TargetResolution:
    host = authz.target.host
    scheme = authz.target.scheme
    port = authz.target.effective_port
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


# ------------------------------------------------------------------
# Fakes: clock, socket, TLS, hop resolution, ledger
# ------------------------------------------------------------------

class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def now(self) -> str:
        return NOW

    def monotonic(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class ScriptedSocket:
    """Byte-scripted socket: stream items are bytes or exceptions.

    The stream list is shared by reference so sequential connections
    to the same (ip, port) consume responses in order.
    """

    def __init__(self, stream, peer: str) -> None:
        self._stream = stream
        self._peer = peer
        self.sent = bytearray()
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, n: int) -> bytes:
        if not self._stream:
            return b""
        item = self._stream[0]
        if isinstance(item, BaseException):
            raise item
        assert isinstance(item, (bytes, bytearray))
        if len(item) <= n:
            self._stream.pop(0)
            return bytes(item)
        self._stream[0] = bytes(item[n:])
        return bytes(item[:n])

    def getpeername(self):  # noqa: ANN204
        return (self._peer, 443)

    def settimeout(self, timeout: float) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def http_bytes(
    status: int = 200,
    reason: str = "OK",
    headers: dict | None = None,
    body: bytes = b"hello",
    *,
    chunked: bool = False,
) -> bytes:
    head = {"Content-Type": "text/plain", "Connection": "close"}
    if headers:
        head.update(headers)
    if not chunked and body is not None and "Content-Length" not in head:
        head["Content-Length"] = str(len(body))
    lines = "".join(f"{name}: {value}\r\n" for name, value in head.items())
    out = f"HTTP/1.1 {status} {reason}\r\n{lines}\r\n".encode("latin-1")
    if body:
        out += body
    return out


class FakeSocketFactory:
    """IP-literal-only factory; records (ip, port, bytes); fails on hostnames."""

    def __init__(self, scripts: dict) -> None:
        self.scripts = scripts
        self.connects: list[tuple[str, int]] = []
        self.sockets: list[ScriptedSocket] = []

    def connect(self, ip_literal: str, port: int, timeout: float):
        try:
            ipaddress.ip_address(ip_literal)
        except ValueError:
            raise AssertionError(f"factory received non-literal: {ip_literal!r}")
        self.connects.append((ip_literal, port))
        spec = self.scripts.get((ip_literal, port))
        if spec is None:
            raise ConnectionError("no route to host")
        if spec.get("connect_exc") is not None:
            raise spec["connect_exc"]
        sock = ScriptedSocket(spec.get("stream", []), spec.get("peer", ip_literal))
        self.sockets.append(sock)
        return sock


class FakeTlsWrapper:
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.records: list[str] = []

    def wrap(self, raw_sock, *, sni_host: str, timeout: float):
        self.records.append(sni_host)
        if self.mode == "fail":
            raise ConnectionError("certificate verify failed")
        return raw_sock


class FakeHopResolver:
    """Per-hop re-resolution backed by the REAL 5D evaluator.

    Decisions come from ``ScopeEvaluator.evaluate_chain`` over the
    initial resolution; only the hop binding envelope is re-issued.
    """

    def __init__(
        self,
        policies: InMemoryPolicyStore,
        dns_mapping: dict,
        initial_resolution: TargetResolution,
        scope_hash: str = SCOPE_HASH,
    ) -> None:
        self.policies = policies
        self.dns = dns_mapping
        self.initial = initial_resolution
        self.scope_hash = scope_hash
        self.calls: list[str] = []
        self.history: list[HopObservation] = []
        self.current_url = (initial_resolution.base_authority or "") + "/"

    def resolve_hop(
        self,
        *,
        authorization,
        execution_id: str,
        canonical_host: str,
        scheme: str,
        effective_port: int,
        path: str = "/",
        query: str = "",
        now: str,
    ):
        self.calls.append(canonical_host)
        entry = self.dns.get(canonical_host)
        if isinstance(entry, BaseException):
            raise entry
        if entry is None:
            raise DnsError("DNS_NXDOMAIN", "no fixture answer for host")
        addresses = validate_answers(entry)
        program = authorization.target.program_name
        cth = canonical_target_hash_for(
            program_name=program,
            canonical_host=canonical_host,
            scheme=scheme,
            effective_port=effective_port,
        )
        policy = self.policies.get_policy(program)
        policy_hash = policy.scope_lists_hash if policy is not None else self.scope_hash
        rid = resolution_id_for(
            authorization_id=authorization.authorization_id,
            execution_id=execution_id,
            canonical_target_hash=cth,
            resolved_addresses=tuple(addresses),
            scope_lists_hash_current=policy_hash,
            snapshot_current=None,
        )
        default = {"http": 80, "https": 443}[scheme]
        resolution = TargetResolution(
            resolution_id=rid,
            authorization_id=authorization.authorization_id,
            execution_id=execution_id,
            program_name=program,
            host_as_authorized=canonical_host,
            canonical_host=canonical_host,
            host_kind="dns",
            scheme=scheme,
            effective_port=effective_port,
            base_authority=f"{scheme}://{canonical_host}"
            if effective_port == default
            else f"{scheme}://{canonical_host}:{effective_port}",
            resolved_addresses=tuple(addresses),
            dns_answer_count=len(addresses),
            dns_source="fake-dns/v1",
            dial=DialBinding(
                addresses=tuple(addresses),
                effective_port=effective_port,
                sni_host=canonical_host,
            ),
            scope_lists_hash_authorized=authorization.target.scope_lists_hash,
            scope_lists_hash_current=policy_hash,
            scope_drift=(policy_hash != authorization.target.scope_lists_hash),
            status="RESOLVED",
            canonical_target_hash=cth,
            resolved_at=now,
        )
        location = (
            f"{scheme}://{canonical_host}"
            + ("" if effective_port == default else f":{effective_port}")
            + (path if path.startswith("/") else "/" + path)
            + (f"?{query}" if query else "")
        )
        self.history.append(
            HopObservation(location=location, addresses=tuple(addresses))
        )
        evaluator = ScopeEvaluator(policy_store=self.policies)
        chained = evaluator.evaluate_chain(
            authorization,
            self.initial,
            execution_id=execution_id,
            now=now,
            hops=tuple(self.history),
        )
        if chained.decision == "ALLOWED":
            evaluation = ScopeEvaluation(
                evaluation_id=evaluation_id_for(
                    authorization_id=authorization.authorization_id,
                    execution_id=execution_id,
                    resolution_id=rid,
                    canonical_target_hash=cth,
                    scope_lists_hash_current=policy_hash,
                    chain_digest=location,
                ),
                authorization_id=authorization.authorization_id,
                execution_id=execution_id,
                resolution_id=rid,
                program_name=program,
                canonical_target_hash=cth,
                scope_lists_hash_current=policy_hash,
                decision="ALLOWED",
                evaluated_at=now,
            )
        else:
            code = chained.failure_code or "REDIRECT_NOT_IN_SCOPE"
            if code not in (
                "TARGET_NOT_IN_SCOPE",
                "TARGET_EXCLUDED",
                "REDIRECT_NOT_IN_SCOPE",
                "REDIRECT_INVALID",
                "REDIRECT_LIMIT",
                "SCOPE_DRIFT",
                "UNSAFE_ADDRESS",
                "SCOPE_POLICY_INVALID",
                "PROGRAM_NOT_FOUND",
            ):
                code = "REDIRECT_NOT_IN_SCOPE"
            evaluation = ScopeEvaluation(
                evaluation_id=evaluation_id_for(
                    authorization_id=authorization.authorization_id,
                    execution_id=execution_id,
                    resolution_id=rid,
                    canonical_target_hash=cth,
                    scope_lists_hash_current=policy_hash,
                    chain_digest=location,
                ),
                authorization_id=authorization.authorization_id,
                execution_id=execution_id,
                resolution_id=rid,
                program_name=program,
                canonical_target_hash=cth,
                scope_lists_hash_current=policy_hash,
                decision="DENIED",
                failure_code=code,  # type: ignore[arg-type]
                evaluated_at=now,
            )
        self.current_url = location
        return resolution, evaluation


class FlakyLedger(InMemoryExecutionLedger):
    """Ledger fake injecting one crash point."""

    def __init__(self, fail_mark_started: bool = False) -> None:
        super().__init__()
        self.fail_mark_started = fail_mark_started

    def mark_started(self, execution_id: str, *, started_at: str = ""):
        if self.fail_mark_started:
            raise RuntimeError("simulated crash between consume and start")
        return super().mark_started(execution_id, started_at=started_at)


def make_deps(
    authz: IssuedExecutionAuthorization,
    *,
    scripts: dict,
    dns_mapping: dict | None = None,
    policies: InMemoryPolicyStore | None = None,
    resolution: TargetResolution | None = None,
    tls_mode: str = "ok",
    ledger=None,
    audit=None,
    clock=None,
) -> tuple[ExecutorDeps, FakeSocketFactory, FakeTlsWrapper, FakeHopResolver, FakeClock]:
    store = InMemoryAuthorizationStore()
    store.put_new(authz)
    clock = clock or FakeClock()
    factory = FakeSocketFactory(scripts)
    tls = FakeTlsWrapper(tls_mode)
    policies = policies or make_policy_store()
    resolution = resolution or make_resolution(authz, EX_ID)
    hops = FakeHopResolver(
        policies, dns_mapping or {HOST: [IP_A]}, resolution
    )
    deps = ExecutorDeps(
        authz_store=store,
        ledger=ledger or InMemoryExecutionLedger(),
        audit=audit or InMemoryAuditSink(),
        hop_resolver=hops,
        socket_factory=factory,
        tls_wrapper=tls,
        now_iso=clock.now,
        monotonic=clock.monotonic,
    )
    return deps, factory, tls, hops, clock


def run_ok(
    content: bytes = GOOD_ARTIFACT,
    *,
    scripts: dict | None = None,
    method: str = "GET",
    **kwargs,
):
    authz = make_authz(content, plan_method=method, artifact_method=method)
    scripts = scripts if scripts is not None else {(IP_A, 443): {"stream": [http_bytes()]}}
    deps, factory, tls, hops, clock = make_deps(authz, scripts=scripts, **kwargs)
    resolution = make_resolution(authz, EX_ID)
    hops.initial = resolution
    evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
    result = execute_http(
        authorization=authz,
        resolution=resolution,
        evaluation=evaluation,
        artifact_reference=artifact_reference_for(content),
        artifact_bytes=content,
        execution_id=EX_ID,
        deps=deps,
    )
    return authz, resolution, evaluation, result, factory, tls, hops, deps


# ------------------------------------------------------------------
# 5E.1 — translation
# ------------------------------------------------------------------

class TranslationTests(unittest.TestCase):
    def test_allowed_methods_translate(self) -> None:
        for method in ("GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"):
            body = "a=1" if method in ("POST", "PUT", "PATCH") else None
            headers = {"accept": "text/html"}
            if body is not None:
                headers["content-type"] = "application/x-www-form-urlencoded"
            content = artifact_content(
                method=method, headers=headers, body=body
            )
            authz = make_authz(content, plan_method=method, artifact_method=method)
            resolution = make_resolution(authz, EX_ID)
            evaluation = make_evaluation(authz, resolution, EX_ID)
            req = translate_bounded_request(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
            )
            self.assertEqual(req.method, method)
            self.assertTrue(req.canonical_url.startswith("https://authorized.example.com"))

    def test_forbidden_methods_denied(self) -> None:
        for method in ("DELETE", "CONNECT", "TRACE", "FOO", "get"):
            content = artifact_content(method=method)
            authz = make_authz(content)
            resolution = make_resolution(authz, EX_ID)
            evaluation = make_evaluation(authz, resolution, EX_ID)
            with self.assertRaises(ExecutorError) as ctx:
                translate_bounded_request(
                    authorization=authz,
                    resolution=resolution,
                    evaluation=evaluation,
                    artifact_reference=artifact_reference_for(content),
                    artifact_bytes=content,
                    execution_id=EX_ID,
                )
            self.assertIn(
                ctx.exception.code,
                ("METHOD_NOT_ALLOWED", "TRANSLATION_REJECTED",
                 "ARTIFACT_REVALIDATION_FAILED"),
            )

    def test_method_pair_mismatch_denied(self) -> None:
        content = artifact_content(method="GET")
        authz = make_authz(content, plan_method="POST", artifact_method="GET")
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            translate_bounded_request(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
            )
        self.assertEqual(ctx.exception.code, "TRANSLATION_REJECTED")

    def test_host_override_rejected(self) -> None:
        content = artifact_content(headers={"host": "evil.example.com"})
        authz = make_authz(content)
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            translate_bounded_request(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
            )
        self.assertEqual(ctx.exception.code, "TRANSLATION_REJECTED")

    def test_credential_headers_rejected(self) -> None:
        for name in (
            "authorization", "cookie", "set-cookie",
            "proxy-authorization", "content-length",
            "transfer-encoding", "connection", "x-forwarded-host",
        ):
            content = artifact_content(headers={name: "x"})
            authz = make_authz(content)
            resolution = make_resolution(authz, EX_ID)
            evaluation = make_evaluation(authz, resolution, EX_ID)
            with self.assertRaises(ExecutorError) as ctx:
                translate_bounded_request(
                    authorization=authz,
                    resolution=resolution,
                    evaluation=evaluation,
                    artifact_reference=artifact_reference_for(content),
                    artifact_bytes=content,
                    execution_id=EX_ID,
                )
            self.assertIn(
                ctx.exception.code,
                ("TRANSLATION_REJECTED", "ARTIFACT_REVALIDATION_FAILED"),
                name,
            )

    def test_crlf_header_rejected(self) -> None:
        content = artifact_content(headers={"accept": "a\r\nB: c"})
        authz = make_authz(content)
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError):
            translate_bounded_request(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
            )

    def test_body_over_ceiling_rejected(self) -> None:
        content = artifact_content(
            method="POST",
            headers={
                "accept": "text/html",
                "content-type": "application/x-www-form-urlencoded",
            },
            body="a=" + "x" * 16384,
        )
        authz = make_authz(content, plan_method="POST", artifact_method="POST")
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            translate_bounded_request(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
            )
        self.assertIn(
            ctx.exception.code,
            ("TRANSLATION_REJECTED", "ARTIFACT_REVALIDATION_FAILED"),
        )

    def test_credential_query_rejected(self) -> None:
        content = artifact_content(query={"q": "hello", "api_key": "abc123"})
        authz = make_authz(content)
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            translate_bounded_request(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
            )
        self.assertEqual(ctx.exception.code, "TRANSLATION_REJECTED")

    def test_translation_failure_creates_no_socket(self) -> None:
        content = artifact_content(headers={"authorization": "Bearer x"})
        authz = make_authz(content)
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError):
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(factory.connects, [])

    def test_request_is_immutable(self) -> None:
        authz = make_authz()
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        req = translate_bounded_request(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
        )
        with self.assertRaises(Exception):
            req.method = "DELETE"  # type: ignore[misc]


# ------------------------------------------------------------------
# Authorization gate
# ------------------------------------------------------------------

class AuthorizationTests(unittest.TestCase):
    def test_expired_authorization_refused(self) -> None:
        authz = make_authz(expires_at="2026-01-02T00:00:00+00:00")
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID, expect=None)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(factory.connects, [])

    def test_consumed_authorization_refused(self) -> None:
        authz = make_authz(lifecycle="CONSUMED")
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(factory.connects, [])

    def test_revoked_authorization_refused(self) -> None:
        authz = make_authz(lifecycle="REVOKED")
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(factory.connects, [])

    def test_forged_dict_authorization_rejected_by_type(self) -> None:
        authz = make_authz()
        deps, _, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        forged = json.loads(authz.model_dump_json())
        with self.assertRaises(TypeError):
            execute_http(
                authorization=forged,  # type: ignore[arg-type]
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )

    def test_wrong_execution_id_refused(self) -> None:
        authz = make_authz()
        other_ex = "ex-" + "9" * 32
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=other_ex,
                deps=deps,
            )
        self.assertIn(
            ctx.exception.code,
            ("AUTHZ_BINDING_MISMATCH", "RESOLUTION_BINDING_MISMATCH"),
        )
        self.assertEqual(factory.connects, [])

    def test_wrong_target_refused(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        other = make_authz(host="www.example.com")
        resolution = make_resolution(other, EX_ID)
        evaluation = make_evaluation(other, resolution, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertIn(
            ctx.exception.code,
            ("RESOLUTION_BINDING_MISMATCH", "AUTHZ_BINDING_MISMATCH"),
        )
        self.assertEqual(factory.connects, [])

    def test_wrong_program_evaluation_refused(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        tampered = evaluation.model_copy(
            update={"evaluation_id": evaluation.evaluation_id}
        )
        _ = tampered
        # Evaluation bound to a different authorization triple.
        other_authz = make_authz(
            authz_id="authz-" + "f" * 16,
        )
        other_res = make_resolution(other_authz, EX_ID)
        other_eval = make_evaluation(other_authz, other_res, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=other_eval,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "AUTHZ_BINDING_MISMATCH")
        self.assertEqual(factory.connects, [])

    def test_wrong_artifact_bytes_refused(self) -> None:
        authz = make_authz()
        other_content = artifact_content(path="/other")
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=other_content,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "ARTIFACT_REVALIDATION_FAILED")
        self.assertEqual(factory.connects, [])


# ------------------------------------------------------------------
# Target / binding gate
# ------------------------------------------------------------------

class TargetTests(unittest.TestCase):
    def test_userinfo_target_refused(self) -> None:
        authz = make_authz(host="user:pass@authorized.example.com")
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertIn(
            ctx.exception.code,
            ("TARGET_BINDING_MISMATCH", "TARGET_NOT_IN_SCOPE"),
        )
        self.assertEqual(factory.connects, [])

    def test_control_target_refused(self) -> None:
        from ai.schemas.execution_authorization import TargetBinding
        base = make_authz()
        hostile_target = TargetBinding.model_construct(
            program_name=PROGRAM,
            host="authorized.example.com\n",
            scheme="https",
            effective_port=443,
            path_scope="",
            snapshot_ref=None,
            scope_policy_version="scope-policy/v1",
            scope_lists_hash=SCOPE_HASH,
        )
        authz = base.model_copy(update={"target": hostile_target})
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertIn(
            ctx.exception.code,
            ("TARGET_BINDING_MISMATCH", "TARGET_NOT_IN_SCOPE"),
        )
        self.assertEqual(factory.connects, [])

    def test_ip_initial_target_not_authorized(self) -> None:
        authz = make_authz(host=IP_A)
        deps, factory, _, _, _ = make_deps(
            authz, scripts={}, dns_mapping={IP_A: [IP_A]}
        )
        resolution = make_resolution(authz, EX_ID, addresses=(IP_A,))
        evaluation = ScopeEvaluator(
            policy_store=make_policy_store()
        ).evaluate(authz, resolution, execution_id=EX_ID, now=NOW)
        self.assertNotEqual(evaluation.decision, "ALLOWED")
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "TARGET_NOT_IN_SCOPE")
        self.assertEqual(factory.connects, [])

    def test_invalid_port_binding_refused(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        tampered = resolution.model_copy(update={"effective_port": 8443})
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=tampered,
                evaluation=make_evaluation(authz, resolution, EX_ID),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertIn(
            ctx.exception.code,
            ("RESOLUTION_BINDING_MISMATCH", "DIAL_BINDING_MISMATCH",
             "AUTHZ_BINDING_MISMATCH"),
        )
        self.assertEqual(factory.connects, [])

    def test_resolution_id_mismatch_refused(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        other_res = make_resolution(authz, EX_ID, addresses=(IP_C,))
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=other_res,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "RESOLUTION_BINDING_MISMATCH")
        self.assertEqual(factory.connects, [])

    def test_dial_binding_mismatch_refused(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID)
        tampered = resolution.model_copy(
            update={
                "dial": DialBinding(
                    addresses=(IP_C,), effective_port=443, sni_host=HOST
                )
            }
        )
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=tampered,
                evaluation=make_evaluation(authz, resolution, EX_ID),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "DIAL_BINDING_MISMATCH")
        self.assertEqual(factory.connects, [])


# ------------------------------------------------------------------
# DNS / dial binding
# ------------------------------------------------------------------

class DialTests(unittest.TestCase):
    def test_approved_ip_dialed(self) -> None:
        _, _, _, result, factory, _, _, _ = run_ok()
        self.assertEqual(result.outcome, "sealed")
        self.assertEqual(factory.connects, [(IP_A, 443)])
        self.assertEqual(result.dial_ips, (IP_A,))

    def test_first_canonical_address_dialed(self) -> None:
        ordered = validate_answers([IP_A, IP_B])
        self.assertEqual(ordered[0], IP_B)  # numeric order
        authz = make_authz()
        scripts = {(IP_B, 443): {"stream": [http_bytes()]}}
        deps, factory, _, hops, _ = make_deps(
            authz, scripts=scripts, dns_mapping={HOST: [IP_A, IP_B]}
        )
        resolution = make_resolution(authz, EX_ID, addresses=ordered)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "sealed")
        self.assertEqual(factory.connects, [(IP_B, 443)])

    def test_unsafe_address_refused(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID, addresses=(UNSAFE_IP,))
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "UNSAFE_ADDRESS")
        self.assertEqual(factory.connects, [])

    def test_private_address_refused(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID, addresses=(PRIVATE_IP,))
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "UNSAFE_ADDRESS")
        self.assertEqual(factory.connects, [])

    def test_mixed_safe_unsafe_refused_whole(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID, addresses=(IP_A, UNSAFE_IP))
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "UNSAFE_ADDRESS")
        self.assertEqual(factory.connects, [])

    def test_empty_resolution_refused(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        full = make_resolution(authz, EX_ID)
        # Empty address sets are unrepresentable via the validated
        # DialBinding constructor; build the hostile record with
        # model_construct (validation bypass) to prove fail-closed.
        empty_dial = DialBinding.model_construct(
            addresses=(), effective_port=443,
            sni_host=HOST, pin_required=True,
        )
        resolution = full.model_copy(
            update={"resolved_addresses": (), "dial": empty_dial}
        )
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "DNS_OBSERVATION_FAILED")
        self.assertEqual(factory.connects, [])

    def test_dns_ceiling_enforced(self) -> None:
        answers = (
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "8.20.20.20",
            "8.21.21.21", "8.22.22.22", "8.23.23.23", "8.24.24.24",
        )
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(authz, EX_ID, addresses=answers)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "DNS_OBSERVATION_FAILED")
        self.assertEqual(factory.connects, [])

    def test_stale_resolution_refused(self) -> None:
        authz = make_authz()
        deps, factory, _, _, _ = make_deps(authz, scripts={})
        resolution = make_resolution(
            authz, EX_ID, scope_hash_current="f" * 64
        )
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=make_evaluation(authz, resolution, EX_ID, expect=None),
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "SCOPE_DRIFT")
        self.assertEqual(factory.connects, [])

    def test_peer_mismatch_aborts(self) -> None:
        authz = make_authz()
        scripts = {(IP_A, 443): {"stream": [http_bytes()], "peer": IP_C}}
        deps, factory, _, hops, _ = make_deps(authz, scripts=scripts)
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_BINDING_FAILURE")
        self.assertEqual(factory.connects, [(IP_A, 443)])

    def test_hostname_to_factory_fails(self) -> None:
        factory = FakeSocketFactory({})
        with self.assertRaises(Exception):
            factory.connect("authorized.example.com", 443, 1.0)
        with self.assertRaises(Exception):
            factory.connect("", 443, 1.0)
        with self.assertRaises(Exception):
            factory.connect("https://authorized.example.com/", 443, 1.0)

    def test_all_dials_are_ip_literals(self) -> None:
        _, _, _, result, factory, _, _, _ = run_ok()
        self.assertEqual(result.outcome, "sealed")
        for ip, _port in factory.connects:
            ipaddress.ip_address(ip)


# ------------------------------------------------------------------
# TLS
# ------------------------------------------------------------------

class TlsTests(unittest.TestCase):
    def test_https_sends_correct_sni(self) -> None:
        _, _, _, result, _, tls, _, _ = run_ok()
        self.assertEqual(result.outcome, "sealed")
        self.assertEqual(tls.records, [HOST])

    def test_tls_failure_terminal(self) -> None:
        authz = make_authz()
        scripts = {(IP_A, 443): {"stream": [http_bytes()]}}
        deps, factory, _, hops, _ = make_deps(
            authz, scripts=scripts, tls_mode="fail"
        )
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TLS_FAILURE")

    def test_plain_http_uses_no_tls(self) -> None:
        authz = make_authz(scheme="http", port=80)
        scripts = {(IP_A, 80): {"stream": [http_bytes()]}}
        deps, factory, tls, hops, _ = make_deps(authz, scripts=scripts)
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "sealed")
        self.assertEqual(tls.records, [])
        self.assertEqual(factory.connects, [(IP_A, 80)])

    def test_sni_binding_rejects_ip(self) -> None:
        with self.assertRaises(ExecutorError) as ctx:
            hx.check_sni_binding(IP_A, IP_A)
        self.assertEqual(ctx.exception.code, "TRANSPORT_BINDING_FAILURE")
        with self.assertRaises(ExecutorError):
            hx.check_sni_binding(SIBLING, HOST)

    def test_downgrade_denied(self) -> None:
        location = "http://authorized.example.com/"
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302, headers={"Location": location}, body=b""
        )]}}
        authz, _, _, result, factory, _, _, _ = run_ok(scripts=scripts)
        _ = authz
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_INVALID")
        self.assertEqual(factory.connects, [(IP_A, 443)])

    def test_upgrade_allowed_for_probe_only(self) -> None:
        location = "https://authorized.example.com/secure"
        scripts_probe = {(IP_A, 80): {"stream": [http_bytes(
            status=302, headers={"Location": location}, body=b""
        )]}, (IP_A, 443): {"stream": [http_bytes(body=b"secure")]}}
        authz = make_authz(scheme="http", port=80)
        deps, factory, _, hops, _ = make_deps(
            authz, scripts=scripts_probe, dns_mapping={HOST: [IP_A]}
        )
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "sealed", result.error_code)
        self.assertEqual(len(result.hops), 2)

    def test_upgrade_denied_for_verification_class(self) -> None:
        content = artifact_content()
        authz = make_authz(
            content, scheme="http", port=80, execution_class="http_verification"
        )
        scripts = {(IP_A, 80): {"stream": [http_bytes(
            status=302,
            headers={"Location": "https://authorized.example.com/secure"},
            body=b"",
        )]}}
        deps, factory, _, hops, _ = make_deps(
            authz, scripts=scripts, dns_mapping={HOST: [IP_A]}
        )
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(content),
            artifact_bytes=content,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_INVALID")


# ------------------------------------------------------------------
# Host / SNI coherence
# ------------------------------------------------------------------

class HostTests(unittest.TestCase):
    def test_host_sni_canonical_triple(self) -> None:
        _, _, _, result, factory, tls, _, _ = run_ok()
        self.assertEqual(result.outcome, "sealed")
        sent = factory.sockets[0].sent.decode("latin-1")
        host_line = [ln for ln in sent.split("\r\n") if ln.startswith("Host:")][0]
        self.assertEqual(host_line, f"Host: {HOST}")
        self.assertEqual(tls.records, [HOST])
        self.assertEqual(result.hops[0].canonical_host, HOST)
        self.assertEqual(result.hops[0].sni_host, HOST)

    def test_x_forwarded_host_rejected(self) -> None:
        content = artifact_content(headers={"x-forwarded-host": HOST})
        authz = make_authz(content)
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError) as ctx:
            translate_bounded_request(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
            )
        self.assertEqual(ctx.exception.code, "TRANSLATION_REJECTED")


# ------------------------------------------------------------------
# Methods incl. redirect rewriting
# ------------------------------------------------------------------

class MethodTests(unittest.TestCase):
    def test_all_allowed_methods_execute(self) -> None:
        for method in ("GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"):
            body = "a=1" if method in ("POST", "PUT", "PATCH") else None
            headers = {"accept": "text/html"}
            if body is not None:
                headers["content-type"] = "application/x-www-form-urlencoded"
            content = artifact_content(method=method, headers=headers, body=body)
            scripts = {(IP_A, 443): {"stream": [http_bytes(body=b"ok")]}}
            authz = make_authz(content, plan_method=method, artifact_method=method)
            deps, factory, _, hops, _ = make_deps(authz, scripts=scripts)
            resolution = make_resolution(authz, EX_ID)
            hops.initial = resolution
            evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
            result = execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
                deps=deps,
            )
            self.assertEqual(result.outcome, "sealed", (method, result.error_code))
            sent = factory.sockets[0].sent.decode("latin-1")
            self.assertTrue(sent.startswith(f"{method} /"), sent.split("\r\n")[0])

    def test_redirect_301_post_becomes_get(self) -> None:
        content = artifact_content(
            method="POST",
            headers={
                "accept": "text/html",
                "content-type": "application/x-www-form-urlencoded",
            },
            body="a=1",
        )
        scripts = {
            (IP_A, 443): {"stream": [http_bytes(
                status=301,
                headers={"Location": "https://www.example.com/next"},
                body=b"",
            )]},
            (IP_B, 443): {"stream": [http_bytes(body=b"done")]},
        }
        authz = make_authz(content, plan_method="POST", artifact_method="POST")
        dns = {HOST: [IP_A], "www.example.com": [IP_B]}
        deps, factory, _, hops, _ = make_deps(authz, scripts=scripts, dns_mapping=dns)
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(content),
            artifact_bytes=content,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "sealed", result.error_code)
        self.assertEqual(len(result.hops), 2)
        second = factory.sockets[1].sent.decode("latin-1")
        self.assertTrue(second.startswith("GET /next"), second.split("\r\n")[0])
        self.assertNotIn("a=1", second)

    def test_redirect_303_becomes_get(self) -> None:
        content = artifact_content(
            method="PUT",
            headers={
                "accept": "text/html",
                "content-type": "application/x-www-form-urlencoded",
            },
            body="a=1",
        )
        scripts = {
            (IP_A, 443): {"stream": [http_bytes(
                status=303, headers={"Location": "https://www.example.com/done"}, body=b""
            )]},
            (IP_B, 443): {"stream": [http_bytes(body=b"done")]},
        }
        authz = make_authz(content, plan_method="PUT", artifact_method="PUT")
        dns = {HOST: [IP_A], "www.example.com": [IP_B]}
        deps, factory, _, hops, _ = make_deps(authz, scripts=scripts, dns_mapping=dns)
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(content),
            artifact_bytes=content,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "sealed", result.error_code)
        second = factory.sockets[1].sent.decode("latin-1")
        self.assertTrue(second.startswith("GET /done"), second.split("\r\n")[0])

    def test_redirect_307_preserves_method_and_body(self) -> None:
        content = artifact_content(
            method="POST",
            path="/submit",
            query={},
            headers={
                "accept": "text/html",
                "content-type": "application/x-www-form-urlencoded",
            },
            body="a=1",
        )
        scripts = {(IP_A, 443): {"stream": [
            http_bytes(status=307, headers={"Location": "/submit2"}, body=b""),
            http_bytes(body=b"kept"),
        ]}}
        authz = make_authz(content, plan_method="POST", artifact_method="POST")
        deps, factory, _, hops, _ = make_deps(
            authz, scripts=scripts, dns_mapping={HOST: [IP_A]}
        )
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(content),
            artifact_bytes=content,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "sealed", result.error_code)
        self.assertEqual(len(result.hops), 2)
        second = factory.sockets[1].sent
        self.assertTrue(second.startswith(b"POST /submit2"))
        self.assertTrue(second.endswith(b"a=1"))

    def test_redirect_308_preserves_method(self) -> None:
        content = artifact_content(
            method="POST",
            path="/submit",
            query={},
            headers={
                "accept": "text/html",
                "content-type": "application/x-www-form-urlencoded",
            },
            body="a=1",
        )
        scripts = {(IP_A, 443): {"stream": [
            http_bytes(status=308, headers={"Location": "/s3"}, body=b""),
            http_bytes(body=b"kept"),
        ]}}
        authz = make_authz(content, plan_method="POST", artifact_method="POST")
        deps, factory, _, hops, _ = make_deps(
            authz, scripts=scripts, dns_mapping={HOST: [IP_A]}
        )
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(content),
            artifact_bytes=content,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "sealed", result.error_code)
        second = factory.sockets[1].sent
        self.assertTrue(second.startswith(b"POST /s3"))


# ------------------------------------------------------------------
# Redirect state machine
# ------------------------------------------------------------------

def redirect_fixture(locations: list[str]):
    """Script a redirect chain; each hop served by its request host."""
    from urllib.parse import urlsplit as _split
    ip_pool = [IP_A, IP_B, IP_C, "9.9.9.9", "8.20.20.20", "8.21.21.21"]
    host_ip: dict[str, str] = {}

    def ip_for(host: str) -> str:
        if host not in host_ip:
            host_ip[host] = ip_pool[len(host_ip) % len(ip_pool)]
        return host_ip[host]

    def destination(current: str, location: str) -> str:
        if location.startswith("//"):
            return _split("https:" + location).hostname or current
        if location.startswith("/"):
            return current
        if "://" in location:
            return _split(location).hostname or current
        return current

    dns: dict[str, list[str]] = {}
    streams: dict[str, list] = {}
    current = HOST
    ip_for(current)
    for location in locations:
        dst = destination(current, location)
        ip_for(dst)
        streams.setdefault(current, []).append(
            http_bytes(status=302, headers={"Location": location}, body=b"")
        )
        current = dst
    streams.setdefault(current, []).append(http_bytes(body=b"final"))
    for host in host_ip:
        dns[host] = [host_ip[host]]
    scripts: dict = {}
    for host, stream in streams.items():
        scripts[(host_ip[host], 443)] = {"stream": stream}
    return scripts, dns


class RedirectTests(unittest.TestCase):
    def test_relative_redirect_followed(self) -> None:
        scripts, dns = redirect_fixture(["/next"])
        authz, _, _, result, factory, _, hops, _ = run_ok(
            scripts=scripts, dns_mapping=dns
        )
        _ = authz
        self.assertEqual(result.outcome, "sealed", result.error_code)
        self.assertEqual(len(result.hops), 2)
        self.assertEqual(len(hops.calls), 1)

    def test_absolute_redirect_followed(self) -> None:
        scripts, dns = redirect_fixture(["https://www.example.com/abs"])
        authz, _, _, result, factory, _, _, _ = run_ok(scripts=scripts, dns_mapping=dns)
        _ = authz
        self.assertEqual(result.outcome, "sealed", result.error_code)
        self.assertEqual(len(result.hops), 2)

    def test_scheme_relative_redirect_followed(self) -> None:
        scripts, dns = redirect_fixture(["//www.example.com/sr"])
        authz, _, _, result, _, _, _, _ = run_ok(scripts=scripts, dns_mapping=dns)
        _ = authz
        self.assertEqual(result.outcome, "sealed", result.error_code)
        self.assertEqual(len(result.hops), 2)

    def test_sibling_redirect_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302,
            headers={"Location": "https://evil.example.com/"},
            body=b"",
        )]}}
        dns = {HOST: [IP_A], SIBLING: [IP_C]}
        _, _, _, result, factory, _, _, _ = run_ok(scripts=scripts, dns_mapping=dns)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_NOT_IN_SCOPE")
        self.assertEqual(factory.connects, [(IP_A, 443)])

    def test_excluded_redirect_denied(self) -> None:
        excl_hash = scope_lists_hash_for(SCOPES, [EXCLUDED])
        policies = make_policy_store(extra={PROGRAM: (list(SCOPES), [EXCLUDED])})
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302,
            headers={"Location": f"https://{EXCLUDED}/"},
            body=b"",
        )]}}
        dns = {HOST: [IP_A], EXCLUDED: [IP_C]}
        authz = make_authz(scope_hash=excl_hash)
        deps, factory, _, hops, _ = make_deps(
            authz, scripts=scripts, dns_mapping=dns, policies=policies
        )
        resolution = make_resolution(authz, EX_ID, scope_hash_current=excl_hash)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_NOT_IN_SCOPE")

    def test_out_of_scope_redirect_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302,
            headers={"Location": f"https://{OOS_HOST}/"},
            body=b"",
        )]}}
        dns = {HOST: [IP_A], OOS_HOST: [IP_C]}
        _, _, _, result, factory, _, _, _ = run_ok(scripts=scripts, dns_mapping=dns)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_NOT_IN_SCOPE")
        self.assertEqual(factory.connects, [(IP_A, 443)])

    def test_ip_redirect_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302, headers={"Location": "https://9.9.9.9/"}, body=b""
        )]}}
        _, _, _, result, factory, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_NOT_IN_SCOPE")
        self.assertEqual(factory.connects, [(IP_A, 443)])

    def test_userinfo_redirect_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302,
            headers={"Location": "https://user:pass@www.example.com/"},
            body=b"",
        )]}}
        _, _, _, result, factory, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_INVALID")

    def test_malformed_redirect_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302, headers={"Location": "https://[::1"}, body=b""
        )]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_INVALID")

    def test_backslash_redirect_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302, headers={"Location": "/next\\evil"}, body=b""
        )]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_INVALID")

    def test_missing_location_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(status=302, body=b"")]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_INVALID")

    def test_cross_port_redirect_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302,
            headers={"Location": "https://www.example.com:8443/"},
            body=b"",
        )]}}
        dns = {HOST: [IP_A], "www.example.com": [IP_C]}
        _, _, _, result, factory, _, _, _ = run_ok(scripts=scripts, dns_mapping=dns)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_NOT_IN_SCOPE")
        self.assertEqual(factory.connects, [(IP_A, 443)])

    def test_canonical_loop_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [
            http_bytes(status=302, headers={"Location": "/a"}, body=b""),
            http_bytes(status=302, headers={"Location": "/search?q=hello"}, body=b""),
        ]}}
        _, _, _, result, factory, _, _, _ = run_ok(
            scripts=scripts, dns_mapping={HOST: [IP_A]}
        )
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_INVALID")
        self.assertEqual(len(factory.connects), 2)

    def test_five_edges_allowed_sixth_denied(self) -> None:
        locations = ["/r1", "/r2", "/r3", "/r4", "/r5"]
        scripts = {(IP_A, 443): {"stream": [
            http_bytes(status=302, headers={"Location": loc}, body=b"")
            for loc in locations
        ] + [http_bytes(body=b"end")]}}
        _, _, _, result, factory, _, _, _ = run_ok(
            scripts=scripts, dns_mapping={HOST: [IP_A]}
        )
        self.assertEqual(result.outcome, "sealed", result.error_code)
        self.assertEqual(len(result.hops), 6)
        locations6 = ["/r1", "/r2", "/r3", "/r4", "/r5", "/r6"]
        scripts6 = {(IP_A, 443): {"stream": [
            http_bytes(status=302, headers={"Location": loc}, body=b"")
            for loc in locations6
        ] + [http_bytes(body=b"end")]}}
        _, _, _, result6, factory6, _, _, _ = run_ok(
            scripts=scripts6, dns_mapping={HOST: [IP_A]}
        )
        self.assertEqual(result6.outcome, "incomplete")
        self.assertEqual(result6.error_code, "REDIRECT_LIMIT")
        self.assertEqual(len(factory6.connects), 6)

    def test_per_hop_reresolution(self) -> None:
        scripts, dns = redirect_fixture(["/a", "https://www.example.com/b", "/c"])
        _, _, _, result, _, _, hops, _ = run_ok(scripts=scripts, dns_mapping=dns)
        self.assertEqual(result.outcome, "sealed", result.error_code)
        self.assertEqual(len(result.hops), 4)
        self.assertEqual(len(hops.calls), 3)
        resolutions = {h.resolution_id for h in result.hops}
        self.assertEqual(len(resolutions), 2)
        evaluations = {h.evaluation_id for h in result.hops}
        self.assertEqual(len(evaluations), 4)

    def test_scope_drift_mid_chain_stops(self) -> None:
        scripts = {(IP_A, 443): {"stream": [
            http_bytes(status=302, headers={"Location": "/a"}, body=b""),
            http_bytes(status=302, headers={"Location": "/b"}, body=b""),
            http_bytes(body=b"end"),
        ]}}
        authz = make_authz()
        policies = make_policy_store()
        deps, factory, _, hops, _ = make_deps(
            authz, scripts=scripts,
            dns_mapping={HOST: [IP_A]}, policies=policies,
        )
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, policies)
        original_resolve = hops.resolve_hop
        calls = {"n": 0}

        def drifting_resolve(**kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                policies._programs[PROGRAM] = (list(SCOPES), [HOST])
            return original_resolve(**kwargs)

        hops.resolve_hop = drifting_resolve  # type: ignore[method-assign]
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "SCOPE_DRIFT")

    def test_no_previous_hop_inheritance(self) -> None:
        scripts = {(IP_A, 443): {"stream": [
            http_bytes(status=302, headers={"Location": "/ok"}, body=b""),
            http_bytes(
                status=302,
                headers={"Location": f"https://{OOS_HOST}/"},
                body=b"",
            ),
        ]}}
        dns = {HOST: [IP_A], OOS_HOST: [IP_C]}
        _, _, _, result, factory, _, _, _ = run_ok(scripts=scripts, dns_mapping=dns)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_NOT_IN_SCOPE")
        self.assertEqual(len(factory.connects), 2)

    def test_credential_bearing_redirect_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(
            status=302,
            headers={"Location": "/next?api_key=secret-value"},
            body=b"",
        )]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "REDIRECT_INVALID")


# ------------------------------------------------------------------
# Transport bounds
# ------------------------------------------------------------------

class TransportTests(unittest.TestCase):
    def test_connect_timeout(self) -> None:
        scripts = {(IP_A, 443): {"connect_exc": TimeoutError("connect stall")}}
        _, _, _, result, factory, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_TIMEOUT")
        self.assertEqual(result.transport_outcome, "timeout")
        self.assertEqual(factory.connects, [(IP_A, 443)])

    def test_read_timeout(self) -> None:
        scripts = {(IP_A, 443): {"stream": [TimeoutError("read stall")]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_TIMEOUT")
        self.assertEqual(result.transport_outcome, "timeout")

    def test_stall_mid_body(self) -> None:
        body = http_bytes(body=b"hello")
        head, _, payload = body.partition(b"\r\n\r\n")
        scripts = {(IP_A, 443): {"stream": [
            head + b"\r\n\r\n" + payload[:2], TimeoutError("stall")
        ]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_TIMEOUT")

    def test_wall_timeout(self) -> None:
        clock = FakeClock()

        class SlowSocket(ScriptedSocket):
            def recv(self, n: int) -> bytes:
                clock.advance(61.0)
                return super().recv(n)

        class SlowFactory(FakeSocketFactory):
            def connect(self, ip_literal: str, port: int, timeout: float):
                sock = super().connect(ip_literal, port, timeout)
                slow = SlowSocket([], ip_literal)
                slow._stream = sock._stream
                self.sockets[-1] = slow
                return slow

        authz = make_authz()
        store = InMemoryAuthorizationStore()
        store.put_new(authz)
        factory = SlowFactory({(IP_A, 443): {"stream": [http_bytes()]}})
        policies = make_policy_store()
        resolution = make_resolution(authz, EX_ID)
        hops = FakeHopResolver(policies, {HOST: [IP_A]}, resolution)
        deps = ExecutorDeps(
            authz_store=store,
            ledger=InMemoryExecutionLedger(),
            audit=InMemoryAuditSink(),
            hop_resolver=hops,
            socket_factory=factory,
            tls_wrapper=FakeTlsWrapper(),
            now_iso=clock.now,
            monotonic=clock.monotonic,
        )
        evaluation = make_evaluation(authz, resolution, EX_ID, policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_TIMEOUT")

    def test_malformed_status_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [b"BAD / HTTP\r\n\r\n"]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_FAILURE")

    def test_malformed_headers_denied(self) -> None:
        scripts = {(IP_A, 443): {"stream": [b"HTTP/1.1 200 OK\r\nNoColon\r\n\r\n"]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_FAILURE")

    def test_content_length_ok(self) -> None:
        scripts = {(IP_A, 443): {"stream": [http_bytes(body=b"0123456789")] }}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "sealed")
        self.assertIsNotNone(result.evidence)
        assert result.evidence is not None and result.evidence.http is not None
        self.assertEqual(result.evidence.http.response_status, 200)

    def test_lying_content_length_truncated(self) -> None:
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: 100\r\nConnection: close\r\n\r\nshort"
        )
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_FAILURE")

    def test_chunked_ok(self) -> None:
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        )
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "sealed", result.error_code)
        assert result.evidence is not None and result.evidence.http is not None
        self.assertEqual(result.evidence.http.response_body_sample, "hello world")

    def test_truncated_chunked_aborts(self) -> None:
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            b"5\r\nhel"
        )
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_FAILURE")

    def test_response_limit_512kib(self) -> None:
        big = b"y" * (600 * 1024)
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Connection: close\r\n\r\n" + big
        )
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "RESPONSE_LIMIT")
        assert result.evidence is not None and result.evidence.http is not None
        stored = result.evidence.http.response_body_hash
        self.assertIsNotNone(stored)

    def test_decompression_ratio_guard(self) -> None:
        bomb = gzip.compress(b"A" * 100000)
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Encoding: gzip\r\n"
            b"Content-Length: " + str(len(bomb)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + bomb
        )
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "DECOMPRESSION_LIMIT")

    def test_decompressed_output_cap(self) -> None:
        payload = os.urandom(2_100_000)
        blob = gzip.compress(payload)
        # Direct unit proof: >2MiB output at ~1x ratio hits the output cap,
        # not the ratio guard. (On the wire the 512KiB transport cap would
        # fire first; layering is asserted by test_response_limit_512kib.)
        with self.assertRaises(ExecutorError) as ctx:
            hx.decode_body(blob, "gzip")
        self.assertEqual(ctx.exception.code, "DECOMPRESSION_LIMIT")

    def test_unsupported_encoding_rejected(self) -> None:
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Encoding: br\r\nContent-Length: 5\r\n"
            b"Connection: close\r\n\r\nhello"
        )
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "DECOMPRESSION_LIMIT")

    def test_gzip_ok(self) -> None:
        blob = gzip.compress(b"hello gzip")
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Encoding: gzip\r\n"
            b"Content-Length: " + str(len(blob)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + blob
        )
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "sealed", result.error_code)
        assert result.evidence is not None and result.evidence.http is not None
        self.assertEqual(result.evidence.http.response_body_sample, "hello gzip")

    def test_1xx_skipped(self) -> None:
        raw = (
            b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n"
            + http_bytes(body=b"final")
        )
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "sealed", result.error_code)
        assert result.evidence is not None and result.evidence.http is not None
        self.assertEqual(result.evidence.http.response_status, 200)

    def test_204_no_body(self) -> None:
        raw = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "sealed", result.error_code)
        assert result.evidence is not None and result.evidence.http is not None
        self.assertEqual(result.evidence.http.response_status, 204)

    def test_304_no_body(self) -> None:
        raw = b"HTTP/1.1 304 Not Modified\r\nETag: abc\r\nConnection: close\r\n\r\n"
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "sealed", result.error_code)
        assert result.evidence is not None and result.evidence.http is not None
        self.assertEqual(result.evidence.http.response_status, 304)


# ------------------------------------------------------------------
# Evidence separation + hashing + scrubbing
# ------------------------------------------------------------------

class EvidenceTests(unittest.TestCase):
    def test_four_identities_separated(self) -> None:
        authz, resolution, evaluation, result, _, _, _, _ = run_ok()
        self.assertEqual(result.outcome, "sealed")
        hop = result.hops[0]
        self.assertEqual(hop.authorization_id, authz.authorization_id)
        self.assertEqual(hop.resolution_id, resolution.resolution_id)
        self.assertEqual(hop.evaluation_id, evaluation.evaluation_id)
        self.assertEqual(hop.execution_id, EX_ID)
        self.assertEqual(hop.dialed_ip, IP_A)
        self.assertNotEqual(
            hop.request_fingerprint,
            hx.compute_request_fingerprint(
                canonical_url=hop.canonical_url,
                method=hop.method,
                body_hash=hop.request_fingerprint,
                dialed_ip="1.2.3.4",
            ),
        )
        assert result.evidence is not None
        verify_record(result.evidence)
        self.assertEqual(result.evidence.authorization_id, authz.authorization_id)
        self.assertEqual(result.evidence.execution_id, EX_ID)
        assert result.evidence.http is not None
        self.assertEqual(result.evidence.http.dial_ips, (IP_A,))

    def test_request_and_body_hashes_bound(self) -> None:
        _, _, _, result, _, _, _, _ = run_ok()
        assert result.evidence is not None and result.evidence.http is not None
        http_obs = result.evidence.http
        self.assertRegex(http_obs.request_body_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(http_obs.response_body_hash or "", r"^[0-9a-f]{64}$")
        self.assertEqual(
            http_obs.request_body_hash,
            hash_mod.sha256_hex(b""),
        )

    def test_redirect_hop_binding(self) -> None:
        scripts, dns = redirect_fixture(["/a", "https://www.example.com/b"])
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts, dns_mapping=dns)
        self.assertEqual(result.outcome, "sealed", result.error_code)
        assert result.evidence is not None and result.evidence.http is not None
        self.assertEqual(result.evidence.http.dial_ips, result.dial_ips)
        self.assertEqual(len(result.dial_ips), 3)
        self.assertTrue(all(h.request_fingerprint for h in result.hops))

    def test_response_secret_scrubbing(self) -> None:
        raw = http_bytes(
            headers={"Set-Cookie": "session=abc123", "Server": "test-server"},
            body=b"token Bearer abcdef1234567890 end",
        )
        scripts = {(IP_A, 443): {"stream": [raw]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "sealed", result.error_code)
        assert result.evidence is not None and result.evidence.http is not None
        http_obs = result.evidence.http
        # Non-allowlisted secret headers are dropped, never persisted.
        self.assertNotIn("set-cookie", http_obs.response_headers.headers)
        self.assertTrue(http_obs.response_headers.truncated)
        self.assertEqual(
            http_obs.response_headers.headers.get("server"), "test-server"
        )
        sample = http_obs.response_body_sample or ""
        self.assertNotIn("abcdef1234567890", sample)
        self.assertIn(REDACTED, sample)
        # Hash covers the stored redacted sample, not the raw bytes.
        self.assertEqual(
            http_obs.response_body_hash,
            hash_mod.sha256_hex(sample.encode("utf-8")),
        )
        verify_record(result.evidence)

    def test_location_secret_redacted_in_chain(self) -> None:
        scripts = {(IP_A, 443): {"stream": [
            http_bytes(
                status=302, headers={"Location": "/next?token=abc"}, body=b""
            ),
            http_bytes(body=b"done"),
        ]}}
        _, _, _, result, _, _, _, _ = run_ok(
            scripts=scripts, dns_mapping={HOST: [IP_A]}
        )
        self.assertEqual(result.outcome, "sealed", result.error_code)
        assert result.evidence is not None and result.evidence.http is not None
        chain = [h.redacted_url for h in result.evidence.http.redirect_chain]
        self.assertTrue(any("token=" in url for url in chain))
        self.assertFalse(any("token=abc" in url for url in chain))

    def test_no_verdict_fields(self) -> None:
        _, _, _, result, _, _, _, _ = run_ok()
        assert result.evidence is not None
        dumped = result.evidence.model_dump(mode="json")
        blob = json.dumps(dumped).casefold()
        for forbidden in (
            "verdict", "finding", "severity", "confirmed", "not_vulnerable",
            "vulnerable", "exploited", "matched",
        ):
            self.assertNotIn(f'"{forbidden}"', blob)


# ------------------------------------------------------------------
# Crash consistency
# ------------------------------------------------------------------

class CrashTests(unittest.TestCase):
    def test_pre_start_crash_reusable_authz(self) -> None:
        content = artifact_content(headers={"authorization": "Bearer x"})
        authz = make_authz(content)
        ledger = InMemoryExecutionLedger()
        deps, factory, _, _, _ = make_deps(authz, scripts={}, ledger=ledger)
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID)
        with self.assertRaises(ExecutorError):
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(content),
                artifact_bytes=content,
                execution_id=EX_ID,
                deps=deps,
            )
        # Nothing claimed, nothing consumed: ledger empty, authz live.
        self.assertIsNone(ledger.get(EX_ID))
        self.assertEqual(factory.connects, [])

    def test_consume_start_ambiguity_unknown(self) -> None:
        authz = make_authz()
        ledger = FlakyLedger(fail_mark_started=True)
        deps, factory, _, hops, _ = make_deps(
            authz,
            scripts={(IP_A, 443): {"stream": [http_bytes()]}},
            ledger=ledger,
        )
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.error_code, "OUTCOME_UNKNOWN")
        self.assertIsNone(result.evidence)
        self.assertEqual(factory.connects, [])

    def test_post_timeout_unknown_for_post(self) -> None:
        content = artifact_content(
            method="POST",
            headers={
                "accept": "text/html",
                "content-type": "application/x-www-form-urlencoded",
            },
            body="a=1",
        )
        authz = make_authz(content, plan_method="POST", artifact_method="POST")
        scripts = {(IP_A, 443): {"stream": [TimeoutError("read stall")]}}
        deps, factory, _, hops, _ = make_deps(authz, scripts=scripts)
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(content),
            artifact_bytes=content,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.error_code, "OUTCOME_UNKNOWN")
        self.assertIsNone(result.evidence)

    def test_partial_get_response_incomplete(self) -> None:
        body = http_bytes(body=b"hello")
        head, _, payload = body.partition(b"\r\n\r\n")
        scripts = {(IP_A, 443): {"stream": [
            head + b"\r\n\r\n" + payload[:2], TimeoutError("stall")
        ]}}
        _, _, _, result, _, _, _, _ = run_ok(scripts=scripts)
        self.assertEqual(result.outcome, "incomplete")
        self.assertEqual(result.error_code, "TRANSPORT_TIMEOUT")
        self.assertIsNotNone(result.evidence)

    def test_seal_failure_unknown(self) -> None:
        authz = make_authz()
        scripts = {(IP_A, 443): {"stream": [http_bytes()]}}
        deps, _, _, hops, _ = make_deps(authz, scripts=scripts)
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)

        class FailingBuilder:
            @classmethod
            def begin(cls, **kwargs):
                raise ev.EvidenceError("EVIDENCE_INCOMPLETE", "missing: x")

        with mock.patch.object(hx, "EvidenceBuilder", FailingBuilder):
            result = execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(result.outcome, "unknown")
        self.assertEqual(result.error_code, "EVIDENCE_SEAL_FAILED")

    def test_post_seal_audit_failure_gap(self) -> None:
        authz = make_authz()
        audit = InMemoryAuditSink()
        audit.fail_from = 3
        scripts = {(IP_A, 443): {"stream": [http_bytes()]}}
        deps, _, _, hops, _ = make_deps(authz, scripts=scripts, audit=audit)
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "sealed")
        self.assertTrue(result.audit_gap)
        self.assertIsNotNone(result.evidence)

    def test_replay_after_consumed_refused(self) -> None:
        from ai.execution.ledger import ExecutionRecord
        authz = make_authz()
        ledger = InMemoryExecutionLedger()
        # Pre-bound slot under a different execution: the authorization
        # is still live, but the at-most-once slot is taken.
        ledger.put_new(
            ExecutionRecord(
                execution_id="ex-" + "8" * 32,
                authorization_id=authz.authorization_id,
                execution_stage="single",
                idempotency_key=authz.idempotency_key,
            )
        )
        deps, factory, _, hops, _ = make_deps(
            authz,
            scripts={(IP_A, 443): {"stream": [http_bytes()]}},
            ledger=ledger,
        )
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        second = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        # Replay refused before any new dial.
        self.assertEqual(second.outcome, "unknown")
        self.assertEqual(second.error_code, "EXECUTION_REPLAY")
        self.assertEqual(factory.connects, [])

    def test_second_run_after_consume_not_live(self) -> None:
        authz, _, _, first, factory, _, _, deps = run_ok()
        _ = authz
        self.assertEqual(first.outcome, "sealed")
        connects_after_first = list(factory.connects)
        resolution = make_resolution(authz, EX_ID)
        evaluation = make_evaluation(authz, resolution, EX_ID, expect=None)
        with self.assertRaises(ExecutorError) as ctx:
            execute_http(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
                artifact_bytes=GOOD_ARTIFACT,
                execution_id=EX_ID,
                deps=deps,
            )
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        self.assertEqual(factory.connects, connects_after_first)


# ------------------------------------------------------------------
# Module boundary (no second transport, no live path)
# ------------------------------------------------------------------

class BoundaryTests(unittest.TestCase):
    def test_no_raw_authority_params(self) -> None:
        import inspect
        for fn in (execute_http, translate_bounded_request):
            params = set(inspect.signature(fn).parameters)
            for banned in ("url", "host", "ip", "hostname", "authority", "target"):
                self.assertNotIn(banned, params, fn.__name__)

    def test_no_high_level_clients_in_execution_path(self) -> None:
        import ast
        import pathlib
        tree = ast.parse(pathlib.Path(hx.__file__).read_text())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
        for banned in (
            "requests", "urllib3", "httpx", "aiohttp", "socket",
            "ssl", "subprocess", "os", "sys", "importlib", "pty",
        ):
            self.assertNotIn(banned, imported, banned)
        called: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    called.add(func.attr)
                elif isinstance(func, ast.Name):
                    called.add(func.id)
        for banned in (
            "getaddrinfo", "gethostbyname", "gethostbyname_ex",
            "create_connection", "urlopen", "URLopener",
        ):
            self.assertNotIn(banned, called, banned)

    def test_no_verdict_vocabulary_in_module(self) -> None:
        import ast
        import pathlib
        tree = ast.parse(pathlib.Path(hx.__file__).read_text())
        forbidden = {
            "verdict", "finding", "severity", "confirmed",
            "not_vulnerable", "vulnerable", "exploited", "matched",
        }
        seen: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                seen.add(node.id)
            elif isinstance(node, ast.Attribute):
                seen.add(node.attr)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                seen.add(node.value)
        hits = seen & forbidden
        self.assertEqual(hits, set(), f"verdict vocabulary present: {hits}")

    def test_legacy_executor_not_imported(self) -> None:
        import pathlib
        src = pathlib.Path(hx.__file__).read_text()
        self.assertNotIn("ai.verification.http_executor", src)
        self.assertNotIn("VerificationEvidence", src)

    def test_live_gate_closed(self) -> None:
        self.assertFalse(hx.LIVE_TRAFFIC_ENABLED)
        with self.assertRaises(ExecutorError) as ctx:
            hx.RealSocketFactory().connect(IP_A, 443, 1.0)
        self.assertEqual(ctx.exception.code, "LIVE_GATE_BLOCKED")
        with self.assertRaises(ExecutorError) as ctx:
            hx.SystemTlsWrapper().wrap(object(), sni_host=HOST, timeout=1.0)
        self.assertEqual(ctx.exception.code, "LIVE_GATE_BLOCKED")

    def test_audit_ordering_valid(self) -> None:
        authz = make_authz()
        audit = InMemoryAuditSink()
        scripts = {(IP_A, 443): {"stream": [http_bytes()]}}
        deps, _, _, hops, _ = make_deps(authz, scripts=scripts, audit=audit)
        resolution = make_resolution(authz, EX_ID)
        hops.initial = resolution
        evaluation = make_evaluation(authz, resolution, EX_ID, hops.policies)
        result = execute_http(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT,
            execution_id=EX_ID,
            deps=deps,
        )
        self.assertEqual(result.outcome, "sealed")
        check_ordering(audit.records)
        transitions = [r.transition for r in audit.records]
        self.assertEqual(
            transitions,
            ["AUTHORIZATION", "EXECUTION_STARTED", "EVIDENCE_SEALED",
             "EXECUTION_TERMINAL"],
        )


if __name__ == "__main__":
    unittest.main()


