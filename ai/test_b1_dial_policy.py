"""Phase B1 live-dial policy tests (offline + localhost fixtures only).

Deterministic stdlib ``unittest``. No Internet, no production
targets, no real security testing, no external DNS, no MongoDB, no
LLM, no Nuclei, no browser automation. Sockets touch only
``127.0.0.1`` loopback fixtures created in this file; DNS answers
are scripted wire packets served by an injected fake exchange.

Coverage map (task items A-Z + security invariants):

A. basic pinned dial (loopback, live factory, peer proof)
B. DNS answer ceiling (9 answers -> DNS_TOO_MANY_ANSWERS)
C. mixed safe/unsafe answer set -> whole-set DNS_UNSAFE_ADDRESS
D. DNS answer change / rebinding -> STALE_RESOLUTION
E. stale authorization-time pin -> STALE_RESOLUTION
F. wrong selected address -> DIAL_MISMATCH, no proof
G. getpeername() mismatch -> TRANSPORT_BINDING_FAILURE
H. hostname passed to socket factory -> DIAL_BINDING_MISMATCH
I. hidden DNS lookup -> proven absent (exchange spy, single attempt)
J. proxy environment (upper) -> PROXY_DETECTED
K. lowercase proxy environment -> PROXY_DETECTED
L. TLS wrong SNI (IP as SNI) -> TLS_MISMATCH before any I/O
M. TLS wrong certificate hostname (handshake fail) -> TLS_FAILURE
N. connection reuse (double wrap) -> CONNECTION_REUSE_VIOLATION
O. redirect re-resolution (fresh DNS per hop, call counts)
P. redirect scope failure -> REDIRECT_NOT_IN_SCOPE
Q. redirect IP literal -> REDIRECT_NOT_IN_SCOPE
R. redirect port change (allowed 80 / denied 8443)
S. redirect scheme downgrade -> REDIRECT_INVALID
T. missing dial proof -> MISSING_PROOF, never seals
U. tampered dial proof -> mismatch, never seals
V. actual peer proof -> valid round trip (loopback getpeername)
W. parallel executions -> no cross-binding
X. cancellation/close during connect -> fail closed
Y. timeout during connect -> TRANSPORT_TIMEOUT
Z. post-send ambiguity -> OUTCOME_UNKNOWN, no evidence bytes
"""

from __future__ import annotations

import ast
import ipaddress
import json
import socket
import struct
import threading
import unittest
from pathlib import Path
from unittest import mock

from ai.authorizer.store import InMemoryAuthorizationStore
from ai.evidence import hashing as hash_mod
from ai.execution import dial_proof as dp
from ai.execution import egress_guard as eg
from ai.execution import http_executor as hx
from ai.execution import live_transport as lt
from ai.execution import production_address_source as pas
from ai.execution import production_hop_resolver as phr
from ai.execution.dial_proof import DialProofError
from ai.execution.egress_guard import EgressGuardError
from ai.execution.http_executor import (
    ExecutorDeps,
    InMemoryAuditSink,
    execute_http,
)
from ai.execution.ledger import InMemoryExecutionLedger
from ai.execution.live_transport import LiveTransportError
from ai.execution.production_hop_resolver import ProductionHopError
from ai.resolver.dns import DnsError
from ai.resolver.inventory import (
    AssetRecord,
    InMemoryInventoryRepository,
    ProgramRecord,
    scope_lists_hash_for,
)
from ai.schemas.artifact import (
    ArtifactReference,
    artifact_id_for,
    content_hash_for_bytes,
)
from ai.schemas.evidence import HttpObservation
from ai.schemas.execution_authorization import IssuedExecutionAuthorization
from ai.schemas.target_resolution import DialBinding
from ai.scope.evaluator import ScopeEvaluator
from ai.scope.policy import InMemoryPolicyStore

# ------------------------------------------------------------------
# Fixture constants (offline values only; never dialed except via
# 127.0.0.1 loopback fixtures below)
# ------------------------------------------------------------------

PROGRAM = "acme"
HOST = "authorized.example.com"
WWW = "www.example.com"
EVIL = "evil.example.com"
SCOPES = [HOST, WWW]
OOSCOPES: list[str] = []
SCOPE_HASH = scope_lists_hash_for(SCOPES, OOSCOPES)

IP_A = "8.8.8.8"
IP_B = "8.8.4.4"
IP_C = "1.1.1.1"
IP_D = "9.9.9.9"
IP_V6 = "2001:4860:4860::8888"
UNSAFE_LOOPBACK = "127.0.0.1"
UNSAFE_PRIVATE = "10.9.9.9"

TP_ID = "tp-" + "a" * 16
AUTHZ_ID = "authz-" + "b" * 16
EX_ID = "ex-" + "c" * 32
EX_ID_2 = "ex-" + "d" * 32
ISSUED_AT = "2026-01-01T00:00:00+00:00"
NOW = "2026-01-15T00:00:00+00:00"
EXPIRES_AT = "2026-02-01T00:00:00+00:00"

B1_NEW_MODULES = (
    "production_address_source",
    "live_transport",
    "production_hop_resolver",
    "dial_proof",
    "egress_guard",
)


def _exec_dir() -> Path:
    return Path(__file__).resolve().parent / "execution"


def _read_module(name: str) -> str:
    return (_exec_dir() / f"{name}.py").read_text(encoding="utf-8")


# ------------------------------------------------------------------
# DNS wire fixtures (scripted exchange)
# ------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out += bytes((len(raw),)) + raw
    return out + b"\x00"


def _question_end(query: bytes, offset: int) -> int:
    while True:
        length = query[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0:
            raise ValueError("compressed query unsupported in fixture")
        offset += 1 + length


def qname_of(query: bytes) -> str:
    """First question name of a scripted query (exact, no expansion)."""

    offset = 12
    end = _question_end(bytes(query), offset)
    raw = bytes(query[offset:end])
    labels: list[str] = []
    pos = 0
    while pos < len(raw):
        length = raw[pos]
        if length == 0:
            break
        pos += 1
        labels.append(raw[pos : pos + length].decode("ascii"))
        pos += length
    return ".".join(labels)


def dns_response(
    query: bytes,
    *,
    answers: list[tuple[str, int]] | None = None,
    cnames: list[tuple[str, int]] | None = None,
) -> bytes:
    """Build a minimal response echoing the query questions."""

    query = bytes(query)
    qid = struct.unpack(">H", query[:2])[0]
    # Echo both fixture questions (A + AAAA).
    off = 12
    end1 = _question_end(query, off) + 4
    end2 = _question_end(query, end1) + 4
    questions = query[12:end2]
    records = b""
    count = 0
    for target, ttl in cnames or []:
        rdata = _encode_name(target)
        records += (
            b"\xc0\x0c"
            + struct.pack(">HHIH", 5, 1, ttl, len(rdata))
            + rdata
        )
        count += 1
    for text, ttl in answers or []:
        packed = ipaddress.ip_address(text).packed
        rtype = 1 if len(packed) == 4 else 28
        records += (
            b"\xc0\x0c"
            + struct.pack(">HHIH", rtype, 1, ttl, len(packed))
            + packed
        )
        count += 1
    header = struct.pack(">HHHHHH", qid, 0x8180, 2, count, 0, 0)
    return header + questions + records


class ScriptedExchange:
    """Deterministic DNS exchange fake (records every call)."""

    def __init__(self, mapping: dict) -> None:
        # Reference semantics (no copy): tests mutate the scripted
        # answers between calls to model DNS change/rebinding.
        self.mapping = mapping
        self.calls: list[tuple[str, str, float]] = []

    def __call__(self, server_ip: str, query: bytes, timeout: float):
        name = qname_of(query)
        self.calls.append((server_ip, name, float(timeout)))
        entry = self.mapping.get(name)
        if entry is None:
            raise DnsError("DNS_NXDOMAIN", "no fixture answer for host")
        if isinstance(entry, BaseException):
            raise entry
        kind = entry[0]
        if kind == "packet":
            return dns_response(
                query, answers=entry[1], cnames=entry[2]
            )
        if kind == "garbage":
            return b"\x00\x01garbage"
        raise AssertionError(f"bad fixture entry: {entry!r}")


def packet_entry(
    answers: list[tuple[str, int]],
    cnames: list[tuple[str, int]] | None = None,
) -> tuple:
    return ("packet", list(answers), list(cnames or []))


# ------------------------------------------------------------------
# Authorization / inventory / policy fixtures (genuine types)
# ------------------------------------------------------------------

def artifact_content(
    method: str = "GET",
    path: str = "/search",
    query: dict | None = None,
    headers: dict | None = None,
    body: str | None = None,
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


def artifact_reference_for(content: bytes) -> ArtifactReference:
    digest = content_hash_for_bytes(content)
    return ArtifactReference(
        artifact_id=artifact_id_for(
            artifact_type="http_request_spec",
            test_plan_id=TP_ID,
            content_hash=digest,
        ),
        artifact_type="http_request_spec",
        content_hash=digest,
        test_plan_id=TP_ID,
        validation_state="VALID",
    )


def make_authz(
    content: bytes = GOOD_ARTIFACT,
    *,
    authz_id: str = AUTHZ_ID,
    host: str = HOST,
    scheme: str = "https",
    port: int = 443,
    plan_method: str = "GET",
    artifact_method: str = "GET",
    scope_hash: str = SCOPE_HASH,
) -> IssuedExecutionAuthorization:
    digest = content_hash_for_bytes(content)
    return IssuedExecutionAuthorization(
        authorization_id=authz_id,
        idempotency_key="d" * 64,
        issuance_nonce="e" * 32,
        issuer_identity="human-review-board",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        lifecycle="ISSUED",  # type: ignore[arg-type]
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
        execution_class="http_probe",  # type: ignore[arg-type]
        plan_method=plan_method,  # type: ignore[arg-type]
        artifact_method=artifact_method,  # type: ignore[arg-type]
    )


def make_inventory(
    hosts: tuple[str, ...] = (HOST,),
    *,
    scheme: str = "https",
    port: int = 443,
) -> InMemoryInventoryRepository:
    return InMemoryInventoryRepository(
        programs=[
            ProgramRecord(
                program_name=PROGRAM, scopes=tuple(SCOPES), ooscopes=tuple(OOSCOPES)
            )
        ],
        assets=[
            AssetRecord(
                program_name=PROGRAM,
                canonical_host=host,
                scheme=scheme,
                effective_port=port,
            )
            for host in hosts
        ],
    )


def make_policies(extra: dict | None = None) -> InMemoryPolicyStore:
    programs: dict[str, tuple] = {PROGRAM: (list(SCOPES), list(OOSCOPES))}
    if extra:
        programs.update(extra)
    return InMemoryPolicyStore(programs)


def make_source(
    mapping: dict,
    *,
    servers: tuple[str, ...] = ("192.0.2.53",),
) -> tuple[pas.ProductionAddressSource, ScriptedExchange]:
    exchange = ScriptedExchange(mapping)
    source = pas.ProductionAddressSource(
        server_ips=list(servers), exchange=exchange, now_iso=lambda: NOW
    )
    return source, exchange


def make_hop_resolver(
    mapping: dict,
    *,
    policies: InMemoryPolicyStore | None = None,
    inventory: InMemoryInventoryRepository | None = None,
) -> tuple[phr.ProductionHopResolver, ScriptedExchange]:
    source, exchange = make_source(mapping)
    resolver = phr.ProductionHopResolver(
        address_source=source,
        inventory=inventory or make_inventory(),
        policy_store=policies or make_policies(),
    )
    return resolver, exchange


# ------------------------------------------------------------------
# Loopback fixture network (127.0.0.1 only)
# ------------------------------------------------------------------

class _LoopbackHandler:
    def __init__(self, sock: socket.socket, payload: bytes, close_first: bool) -> None:
        self._sock = sock
        self._payload = payload
        self._close_first = close_first

    def run(self) -> None:
        try:
            if self._close_first:
                return
            try:
                self._sock.recv(4096)
            except OSError:
                return
            try:
                self._sock.sendall(self._payload)
            except OSError:
                pass
        finally:
            try:
                self._sock.close()
            except OSError:
                pass


def run_loopback_server(
    payload: bytes = b"hi", *, close_first: bool = False
) -> tuple[socket.socket, int, threading.Thread]:
    """Serve exactly one loopback connection, then stop accepting."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(10.0)
    port = listener.getsockname()[1]

    def _serve() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        _LoopbackHandler(conn, payload, close_first).run()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return listener, port, thread


# ------------------------------------------------------------------
# Scripted socket fakes for executor-level tests
# ------------------------------------------------------------------

class ScriptedSocket:
    def __init__(self, peer: str, recv_items: list) -> None:
        self._peer = peer
        self._recv = list(recv_items)
        self.sent = bytearray()
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, n: int) -> bytes:
        if not self._recv:
            return b""
        item = self._recv.pop(0)
        if isinstance(item, BaseException):
            raise item
        assert isinstance(item, (bytes, bytearray))
        if len(item) <= n:
            return bytes(item)
        self._recv.insert(0, bytes(item[n:]))
        return bytes(item[:n])

    def getpeername(self):  # noqa: ANN204
        return (self._peer, 443)

    def settimeout(self, timeout: float) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def http_bytes(body: bytes = b"hello") -> bytes:
    head = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
    )
    return head + body


class FakeSocketFactory:
    def __init__(self, scripts: dict) -> None:
        self.scripts = scripts
        self.connects: list[tuple[str, int]] = []

    def connect(self, ip_literal: str, port: int, timeout: float):
        ipaddress.ip_address(ip_literal)
        self.connects.append((ip_literal, port))
        spec = self.scripts.get((ip_literal, port))
        if spec is None:
            raise ConnectionError("no route to host")
        if spec.get("connect_exc") is not None:
            raise spec["connect_exc"]
        return ScriptedSocket(spec.get("peer", ip_literal), spec.get("recv", []))


class FakeTlsWrapper:
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.records: list[str] = []

    def wrap(self, raw_sock, *, sni_host: str, timeout: float):
        self.records.append(sni_host)
        if self.mode == "fail":
            raise ConnectionError("certificate verify failed")
        return raw_sock


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def now(self) -> str:
        return NOW

    def monotonic(self) -> float:
        return self.t


class NeverCalledHopResolver:
    def resolve_hop(self, **kwargs):  # noqa: ANN204
        raise AssertionError("hop resolver must not be called")


def execute_with_fakes(
    authz, resolution, evaluation, content: bytes, scripts: dict
):
    store = InMemoryAuthorizationStore()
    store.put_new(authz)
    clock = FakeClock()
    deps = ExecutorDeps(
        authz_store=store,
        ledger=InMemoryExecutionLedger(),
        audit=InMemoryAuditSink(),
        hop_resolver=NeverCalledHopResolver(),
        socket_factory=FakeSocketFactory(scripts),
        tls_wrapper=FakeTlsWrapper("ok"),
        now_iso=clock.now,
        monotonic=clock.monotonic,
    )
    return execute_http(
        authorization=authz,
        resolution=resolution,
        evaluation=evaluation,
        artifact_reference=artifact_reference_for(content),
        artifact_bytes=content,
        execution_id=EX_ID,
        deps=deps,
    )


# ==================================================================
# A. basic pinned dial (loopback live factory)
# ==================================================================

class PinnedDialTests(unittest.TestCase):
    def test_pinned_dial_and_peer_proof(self) -> None:
        listener, port, thread = run_loopback_server(b"pong")
        try:
            factory = lt.LiveSocketFactory()
            sock = factory.connect("127.0.0.1", port, 5.0)
            try:
                peer = lt.verify_socket_peer(sock, "127.0.0.1")
                self.assertEqual(peer, "127.0.0.1")
                conn_id = factory.connection_id_for(sock)
                self.assertRegex(conn_id or "", r"^conn-[0-9a-f]{32}$")
                sock.sendall(b"ping")
                self.assertEqual(sock.recv(4), b"pong")
            finally:
                lt.close_quietly(sock)
        finally:
            listener.close()
            thread.join(timeout=5.0)

    def test_each_connect_is_fresh_with_unique_id(self) -> None:
        listener, port, thread = run_loopback_server(b"x")
        try:
            factory = lt.LiveSocketFactory()
            s1 = factory.connect("127.0.0.1", port, 5.0)
            s2 = factory.connect("127.0.0.1", port, 5.0)
            try:
                self.assertIsNot(s1, s2)
                self.assertNotEqual(
                    factory.connection_id_for(s1), factory.connection_id_for(s2)
                )
            finally:
                lt.close_quietly(s1)
                lt.close_quietly(s2)
        finally:
            listener.close()
            thread.join(timeout=5.0)


# ==================================================================
# B/C. ceiling + mixed-set whole-set failure
# ==================================================================

class DnsCeilingTests(unittest.TestCase):
    def test_nine_answers_over_ceiling(self) -> None:
        answers = [(f"203.0.113.{i}", 60) for i in range(1, 10)]
        source, _ = make_source({HOST: packet_entry(answers)})
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_TOO_MANY_ANSWERS")

    def test_mixed_safe_unsafe_fails_whole_set(self) -> None:
        source, _ = make_source(
            {HOST: packet_entry([(IP_A, 60), (UNSAFE_LOOPBACK, 60)])}
        )
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_UNSAFE_ADDRESS")

    def test_private_answer_fails_closed(self) -> None:
        source, _ = make_source({HOST: packet_entry([(UNSAFE_PRIVATE, 60)])})
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_UNSAFE_ADDRESS")

    def test_mapped_ipv6_inner_private_fails_closed(self) -> None:
        source, _ = make_source({HOST: packet_entry([("::ffff:10.0.0.1", 60)])})
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_UNSAFE_ADDRESS")

    def test_cname_only_without_terminal_fails_closed(self) -> None:
        source, _ = make_source(
            {HOST: packet_entry([], cnames=[("cdn.example.net", 60)])}
        )
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_RESOLUTION_FAILED")

    def test_cname_logged_but_never_authorizes(self) -> None:
        source, exchange = make_source(
            {
                HOST: packet_entry(
                    [(IP_A, 60)], cnames=[("cdn.example.net", 60)]
                )
            }
        )
        addresses, info = source.resolve_with_info(HOST)
        self.assertEqual(addresses, (IP_A,))
        self.assertEqual(info.cname_chain, ("cdn.example.net",))
        self.assertNotIn("cdn.example.net", addresses)

    def test_malformed_packet_fails_closed(self) -> None:
        source, _ = make_source({HOST: ("garbage", [], [])})
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_MALFORMED_ANSWER")


# ==================================================================
# AddressSource conformance: order, identity, discipline
# ==================================================================

class AddressSourceConformanceTests(unittest.TestCase):
    def test_deterministic_order_regardless_of_wire_order(self) -> None:
        first = [(IP_B, 60), (IP_V6, 60), (IP_A, 60)]
        source, _ = make_source({HOST: packet_entry(first)})
        addresses, _ = source.resolve_with_info(HOST)
        again = pas.ProductionAddressSource(
            server_ips=["192.0.2.53"],
            exchange=ScriptedExchange(
                {HOST: packet_entry(list(reversed(first)))}
            ),
        )
        self.assertEqual(addresses, again.resolve(HOST))
        # Frozen numeric order: 8.8.4.4 < 8.8.8.8 < IPv6; dial takes [0].
        self.assertEqual(addresses, (IP_B, IP_A, IP_V6))

    def test_resolver_identity_version_bound(self) -> None:
        source, _ = make_source({HOST: packet_entry([(IP_A, 60)])})
        _, info = source.resolve_with_info(HOST)
        self.assertEqual(info.resolver_name, "prod-dns-stub")
        self.assertEqual(info.resolver_version, "prod-dns-stub/v1")
        self.assertEqual(info.transport, "tcp")
        self.assertEqual(info.server_ips, ("192.0.2.53",))
        self.assertRegex(info.resolver_config_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(info.ttl_seen, 60)

    def test_noncanonical_host_rejected_no_expansion(self) -> None:
        source, exchange = make_source({HOST: packet_entry([(IP_A, 60)])})
        with self.assertRaises(DnsError):
            source.resolve("Authorized.Example.Com")
        self.assertEqual(exchange.calls, [])

    def test_no_transport_configured_fails_closed(self) -> None:
        source = pas.ProductionAddressSource(
            server_ips=["192.0.2.53"], exchange=None
        )
        with self.assertRaises(DnsError) as ctx:
            source.resolve(HOST)
        self.assertEqual(ctx.exception.code, "DNS_RESOLUTION_FAILED")

    def test_single_attempt_per_hop_first_server_only(self) -> None:
        source, exchange = make_source(
            {HOST: packet_entry([(IP_A, 60)])},
            servers=("192.0.2.53", "192.0.2.54"),
        )
        source.resolve(HOST)
        self.assertEqual(len(exchange.calls), 1)
        self.assertEqual(exchange.calls[0][0], "192.0.2.53")

    def test_no_cross_hop_cache(self) -> None:
        mapping = {HOST: packet_entry([(IP_A, 60)])}
        source, exchange = make_source(mapping)
        source.resolve(HOST)
        mapping[HOST] = packet_entry([(IP_B, 60)])
        self.assertEqual(source.resolve(HOST), (IP_B,))
        self.assertEqual(len(exchange.calls), 2)

    def test_operator_servers_must_be_literals(self) -> None:
        with self.assertRaises((TypeError, ValueError)):
            pas.ProductionAddressSource(
                server_ips=["dns.example.net"], exchange=ScriptedExchange({})
            )
        with self.assertRaises((TypeError, ValueError)):
            pas.ProductionAddressSource(server_ips=[], exchange=None)

    def test_caller_cannot_select_resolver_per_call(self) -> None:
        import inspect

        params = inspect.signature(pas.ProductionAddressSource.resolve).parameters
        self.assertEqual(list(params), ["self", "canonical_host"])


# ==================================================================
# D/E. rebinding + stale authz-time pin
# ==================================================================

class RebindingTests(unittest.TestCase):
    def test_changed_answers_between_claim_and_dial_is_stale(self) -> None:
        mapping = {HOST: packet_entry([(IP_A, 60)])}
        resolver, _ = make_hop_resolver(mapping)
        authz = make_authz()
        fresh, _ = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        authz_pin = tuple(fresh.resolved_addresses)
        mapping[HOST] = packet_entry([(IP_B, 60)])
        with self.assertRaises(ProductionHopError) as ctx:
            resolver.resolve_initial(
                authorization=authz,
                execution_id=EX_ID_2,
                now=NOW,
                authz_time_addresses=authz_pin,
            )
        self.assertEqual(ctx.exception.code, "STALE_RESOLUTION")

    def test_matching_authz_pin_passes(self) -> None:
        resolver, _ = make_hop_resolver({HOST: packet_entry([(IP_A, 60)])})
        authz = make_authz()
        resolution, evaluation = resolver.resolve_initial(
            authorization=authz,
            execution_id=EX_ID,
            now=NOW,
            authz_time_addresses=(IP_A,),
        )
        self.assertEqual(resolution.status, "RESOLVED")
        self.assertEqual(evaluation.decision, "ALLOWED")


# ==================================================================
# F/G/H. selected-address, peer, hostname gates
# ==================================================================

class DialGateTests(unittest.TestCase):
    def _bindings(self, addresses=(IP_A,)):
        authz = make_authz()
        resolver, _ = make_hop_resolver({HOST: packet_entry([(a, 60) for a in addresses])})
        resolution, evaluation = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        return authz, resolution, evaluation

    def test_wrong_selected_address_never_proves(self) -> None:
        authz, resolution, evaluation = self._bindings()
        with self.assertRaises(DialProofError) as ctx:
            dp.assemble_dial_proof(
                actual_peer_ip=IP_B,
                local_sockaddr="192.0.2.7:54321",
                selected_address=IP_B,
                resolved_addresses=tuple(resolution.resolved_addresses),
                resolver_name="prod-dns-stub",
                resolver_version="prod-dns-stub/v1",
                dial_addresses=tuple(resolution.resolved_addresses),
                dial_port=443,
                dial_sni=HOST,
                resolution=resolution,
                evaluation=evaluation,
                authorization_id=authz.authorization_id,
                tls_sni=HOST,
                tls_version_negotiated="TLSv1.3",
                tls_peer_cert_hash="f" * 64,
                redirect_hop_index=0,
                connection_id="conn-" + "1" * 32,
            )
        self.assertEqual(ctx.exception.code, "DIAL_MISMATCH")

    def test_peer_mismatch_fails_closed(self) -> None:
        sock = ScriptedSocket(peer=IP_D, recv_items=[])
        with self.assertRaises(LiveTransportError) as ctx:
            lt.verify_socket_peer(sock, IP_A)
        self.assertEqual(ctx.exception.code, "TRANSPORT_BINDING_FAILURE")

    def test_hostname_to_factory_rejected(self) -> None:
        factory = lt.LiveSocketFactory()
        for hostile in (HOST, "https://8.8.8.8", "8.8.8.8/32", "", "evil.com?x=1"):
            with self.assertRaises(LiveTransportError) as ctx:
                factory.connect(hostile, 443, 1.0)
            self.assertEqual(ctx.exception.code, "DIAL_BINDING_MISMATCH")

    def test_hidden_dns_proven_absent(self) -> None:
        # The live factory performs zero resolution attempts: connecting
        # a literal against a loopback fixture requires no exchange, and
        # the production source performs exactly one injected exchange.
        listener, port, thread = run_loopback_server(b"x")
        try:
            factory = lt.LiveSocketFactory()
            sock = factory.connect("127.0.0.1", port, 5.0)
            lt.close_quietly(sock)
        finally:
            listener.close()
            thread.join(timeout=5.0)
        _, exchange = make_source({HOST: packet_entry([(IP_A, 60)])})
        source = pas.ProductionAddressSource(
            server_ips=["192.0.2.53"], exchange=exchange
        )
        source.resolve(HOST)
        self.assertEqual(len(exchange.calls), 1)


# ==================================================================
# J/K. proxy guard
# ==================================================================

class EgressGuardTests(unittest.TestCase):
    def test_uppercase_proxy_vars_detected(self) -> None:
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
            with self.assertRaises(EgressGuardError) as ctx:
                eg.check_environment({var: "http://proxy:8080", "PATH": "/usr/bin"})
            self.assertEqual(ctx.exception.code, "PROXY_DETECTED")

    def test_lowercase_proxy_vars_detected(self) -> None:
        for var in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            with self.assertRaises(EgressGuardError) as ctx:
                eg.check_environment({var: "http://proxy:8080"})
            self.assertEqual(ctx.exception.code, "PROXY_DETECTED")

    def test_pac_wpad_shapes_detected(self) -> None:
        for var in ("MY_PAC", "PAC_URL", "WPAD_URL", "CORP_WPAD_CONFIG"):
            with self.assertRaises(EgressGuardError):
                eg.check_environment({var: "x"})

    def test_empty_proxy_value_still_detected(self) -> None:
        with self.assertRaises(EgressGuardError):
            eg.check_environment({"HTTP_PROXY": ""})

    def test_clean_environment_passes_and_scrub_proves(self) -> None:
        dirty = {"PATH": "/usr/bin", "HTTP_PROXY": "http://p", "https_proxy": "http://p"}
        scrubbed = eg.scrubbed_environment(dirty)
        self.assertNotIn("HTTP_PROXY", scrubbed)
        self.assertNotIn("https_proxy", scrubbed)
        eg.check_environment(scrubbed)  # must not raise
        eg.check_environment({"PATH": "/usr/bin", "HOME": "/root"})

    def test_no_bypass_variable_exists(self) -> None:
        # No bypass identifier may exist as code (names or string
        # constants outside the module docstring): the guard offers
        # no ALLOW_/DISABLE_/SKIP_ escape hatch.
        tree = ast.parse(_read_module("egress_guard"))
        body = tree.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
        ):
            body = body[1:]
        names: list[str] = []
        for node in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(node, ast.Name):
                names.append(node.id)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                names.append(node.value)
        haystack = "\n".join(names)
        for token in ("ALLOW_", "DISABLE_", "SKIP_", "BYPASS", "INSECURE"):
            self.assertNotIn(token, haystack)

    def test_topology_allowlist(self) -> None:
        self.assertEqual(eg.assert_topology("direct"), "direct")
        for bad in ("corporate-proxy", "transparent-gateway", "", "DIRECT"):
            with self.assertRaises(EgressGuardError) as ctx:
                eg.assert_topology(bad)
            self.assertEqual(ctx.exception.code, "TOPOLOGY_UNSUPPORTED")


# ==================================================================
# L/M/N. TLS binding + reuse
# ==================================================================

class TlsBindingTests(unittest.TestCase):
    def test_ip_as_sni_rejected_before_io(self) -> None:
        wrapper = lt.LiveTlsWrapper()
        with self.assertRaises(LiveTransportError) as ctx:
            wrapper.wrap(object(), sni_host="8.8.8.8", timeout=1.0)
        self.assertEqual(ctx.exception.code, "TLS_MISMATCH")
        self.assertEqual(wrapper.sni_log, ())

    def test_handshake_failure_maps_to_tls_failure(self) -> None:
        listener, port, thread = run_loopback_server(b"x", close_first=True)
        try:
            factory = lt.LiveSocketFactory()
            sock = factory.connect("127.0.0.1", port, 5.0)
            try:
                wrapper = lt.LiveTlsWrapper()
                with self.assertRaises(LiveTransportError) as ctx:
                    wrapper.wrap(sock, sni_host=HOST, timeout=5.0)
                self.assertEqual(ctx.exception.code, "TLS_FAILURE")
                # Reuse after a consumed socket is a violation, even
                # though the first wrap failed: the socket never
                # returns to any pool.
                with self.assertRaises(LiveTransportError) as ctx2:
                    wrapper.wrap(sock, sni_host=HOST, timeout=5.0)
                self.assertEqual(ctx2.exception.code, "CONNECTION_REUSE_VIOLATION")
            finally:
                lt.close_quietly(sock)
        finally:
            listener.close()
            thread.join(timeout=5.0)


# ==================================================================
# O/P/Q/R/S. redirect chain policy
# ==================================================================

class RedirectPolicyTests(unittest.TestCase):
    def _initial(self, resolver, authz, ex_id=EX_ID):
        return resolver.resolve_initial(
            authorization=authz, execution_id=ex_id, now=NOW
        )

    def test_redirect_triggers_fresh_resolution(self) -> None:
        mapping = {
            HOST: packet_entry([(IP_A, 60)]),
            WWW: packet_entry([(IP_B, 60)]),
        }
        resolver, exchange = make_hop_resolver(mapping)
        authz = make_authz()
        self._initial(resolver, authz)
        resolution, evaluation = resolver.resolve_hop(
            authorization=authz,
            execution_id=EX_ID,
            canonical_host=WWW,
            scheme="https",
            effective_port=443,
            path="/next",
            query="",
            now=NOW,
        )
        self.assertEqual(resolution.canonical_host, WWW)
        self.assertEqual(tuple(resolution.resolved_addresses), (IP_B,))
        self.assertEqual(evaluation.decision, "ALLOWED")
        hosts = [call[1] for call in exchange.calls]
        self.assertEqual(hosts, [HOST, WWW])

    def test_redirect_to_same_host_reresolves(self) -> None:
        mapping = {HOST: packet_entry([(IP_A, 60)])}
        resolver, exchange = make_hop_resolver(mapping)
        authz = make_authz()
        self._initial(resolver, authz)
        mapping[HOST] = packet_entry([(IP_C, 60)])
        resolution, _ = resolver.resolve_hop(
            authorization=authz,
            execution_id=EX_ID,
            canonical_host=HOST,
            scheme="https",
            effective_port=443,
            path="/again",
            query="",
            now=NOW,
        )
        self.assertEqual(tuple(resolution.resolved_addresses), (IP_C,))
        self.assertEqual(len(exchange.calls), 2)

    def test_redirect_scope_failure(self) -> None:
        mapping = {
            HOST: packet_entry([(IP_A, 60)]),
            EVIL: packet_entry([(IP_B, 60)]),
        }
        resolver, _ = make_hop_resolver(mapping)
        authz = make_authz()
        self._initial(resolver, authz)
        with self.assertRaises(ProductionHopError) as ctx:
            resolver.resolve_hop(
                authorization=authz,
                execution_id=EX_ID,
                canonical_host=EVIL,
                scheme="https",
                effective_port=443,
                path="/",
                query="",
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "REDIRECT_NOT_IN_SCOPE")

    def test_redirect_ip_literal_rejected(self) -> None:
        resolver, _ = make_hop_resolver({HOST: packet_entry([(IP_A, 60)])})
        authz = make_authz()
        self._initial(resolver, authz)
        with self.assertRaises(ProductionHopError) as ctx:
            resolver.resolve_hop(
                authorization=authz,
                execution_id=EX_ID,
                canonical_host="8.8.8.8",
                scheme="https",
                effective_port=443,
                path="/",
                query="",
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "REDIRECT_NOT_IN_SCOPE")

    def test_redirect_port_change_policy(self) -> None:
        mapping = {
            HOST: packet_entry([(IP_A, 60)]),
        }
        resolver, _ = make_hop_resolver(mapping)
        authz = make_authz()
        self._initial(resolver, authz)
        # Port 80 is on the frozen allowlist {80, 443, initial}.
        ok, _ = resolver.resolve_hop(
            authorization=authz,
            execution_id=EX_ID,
            canonical_host=HOST,
            scheme="https",
            effective_port=80,
            path="/",
            query="",
            now=NOW,
        )
        self.assertEqual(ok.effective_port, 80)
        self.assertEqual(ok.dial.effective_port, 80)  # type: ignore[union-attr]
        # Port 8443 is outside the allowlist.
        with self.assertRaises(ProductionHopError) as ctx:
            resolver.resolve_hop(
                authorization=authz,
                execution_id=EX_ID,
                canonical_host=HOST,
                scheme="https",
                effective_port=8443,
                path="/",
                query="",
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "REDIRECT_NOT_IN_SCOPE")

    def test_redirect_scheme_downgrade_rejected(self) -> None:
        resolver, _ = make_hop_resolver({HOST: packet_entry([(IP_A, 60)])})
        authz = make_authz()
        self._initial(resolver, authz)
        with self.assertRaises(ProductionHopError) as ctx:
            resolver.resolve_hop(
                authorization=authz,
                execution_id=EX_ID,
                canonical_host=HOST,
                scheme="http",
                effective_port=80,
                path="/",
                query="",
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "REDIRECT_INVALID")

    def test_redirect_budget_enforced(self) -> None:
        mapping = {
            HOST: packet_entry([(IP_A, 60)]),
            WWW: packet_entry([(IP_B, 60)]),
        }
        resolver, _ = make_hop_resolver(mapping)
        authz = make_authz()
        self._initial(resolver, authz)
        for i in range(5):
            host = WWW if i % 2 == 0 else HOST
            resolver.resolve_hop(
                authorization=authz,
                execution_id=EX_ID,
                canonical_host=host,
                scheme="https",
                effective_port=443,
                path="/",
                query=f"n={i}",
                now=NOW,
            )
        with self.assertRaises(ProductionHopError) as ctx:
            resolver.resolve_hop(
                authorization=authz,
                execution_id=EX_ID,
                canonical_host=WWW,
                scheme="https",
                effective_port=443,
                path="/",
                query="n=5",
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "REDIRECT_LIMIT")

    def test_no_previous_hop_inheritance_policy_reread(self) -> None:
        mapping = {
            HOST: packet_entry([(IP_A, 60)]),
            WWW: packet_entry([(IP_B, 60)]),
        }
        policies = make_policies()
        resolver, _ = make_hop_resolver(mapping, policies=policies)
        authz = make_authz()
        self._initial(resolver, authz)
        resolver.resolve_hop(
            authorization=authz,
            execution_id=EX_ID,
            canonical_host=WWW,
            scheme="https",
            effective_port=443,
            path="/a",
            query="",
            now=NOW,
        )
        # Mid-chain policy removal must stop the chain (fresh re-read,
        # never inherited permission).
        policies._programs[PROGRAM] = ([], [])
        with self.assertRaises(ProductionHopError) as ctx:
            resolver.resolve_hop(
                authorization=authz,
                execution_id=EX_ID,
                canonical_host=WWW,
                scheme="https",
                effective_port=443,
                path="/b",
                query="",
                now=NOW,
            )
        self.assertIn(
            ctx.exception.code, ("REDIRECT_NOT_IN_SCOPE", "SCOPE_DRIFT")
        )


# ==================================================================
# T/U/V. dial proof: missing / tampered / valid
# ==================================================================

class DialProofTests(unittest.TestCase):
    def _proof_inputs(self, **over):
        authz = make_authz()
        resolver, _ = make_hop_resolver({HOST: packet_entry([(IP_A, 60)])})
        resolution, evaluation = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        params = dict(
            actual_peer_ip=IP_A,
            local_sockaddr="192.0.2.7:54321",
            selected_address=IP_A,
            resolved_addresses=tuple(resolution.resolved_addresses),
            resolver_name="prod-dns-stub",
            resolver_version="prod-dns-stub/v1",
            dial_addresses=tuple(resolution.resolved_addresses),
            dial_port=443,
            dial_sni=HOST,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authz.authorization_id,
            tls_sni=HOST,
            tls_version_negotiated="TLSv1.3",
            tls_peer_cert_hash="f" * 64,
            redirect_hop_index=0,
            connection_id="conn-" + "1" * 32,
        )
        params.update(over)
        return authz, resolution, evaluation, params

    def test_missing_proof_never_seals(self) -> None:
        authz, resolution, evaluation, _ = self._proof_inputs()
        with self.assertRaises(DialProofError) as ctx:
            dp.assert_proof_for_seal(
                proofs=[],
                resolutions=[resolution],
                evaluations=[evaluation],
                authorization_id=authz.authorization_id,
            )
        self.assertEqual(ctx.exception.code, "MISSING_PROOF")
        sealed = []
        with self.assertRaises(DialProofError):
            dp.seal_with_dial_proof(
                proofs=[],
                resolutions=[resolution],
                evaluations=[evaluation],
                authorization_id=authz.authorization_id,
                seal=lambda: sealed.append(True),
            )
        self.assertEqual(sealed, [])

    def test_tampered_proof_never_seals(self) -> None:
        import dataclasses

        authz, resolution, evaluation, params = self._proof_inputs()
        proof = dp.assemble_dial_proof(**params)
        tampered = dataclasses.replace(proof, actual_peer_ip=IP_B)
        with self.assertRaises(DialProofError):
            dp.verify_dial_proof(
                tampered,
                resolution=resolution,
                evaluation=evaluation,
                authorization_id=authz.authorization_id,
            )
        sealed = []
        with self.assertRaises(DialProofError):
            dp.seal_with_dial_proof(
                proofs=[tampered],
                resolutions=[resolution],
                evaluations=[evaluation],
                authorization_id=authz.authorization_id,
                seal=lambda: sealed.append(True),
            )
        self.assertEqual(sealed, [])

    def test_incoherent_bindings_never_assemble(self) -> None:
        # A loopback-observed peer paired against the frozen
        # resolution pin set is incoherent by construction: assembly
        # must fail closed rather than mint a proof.
        listener, port, thread = run_loopback_server(b"x")
        try:
            factory = lt.LiveSocketFactory()
            sock = factory.connect("127.0.0.1", port, 5.0)
            try:
                peer = lt.verify_socket_peer(sock, "127.0.0.1")
                local = str(sock.getsockname())
                conn_id = factory.connection_id_for(sock) or ""
            finally:
                lt.close_quietly(sock)
        finally:
            listener.close()
            thread.join(timeout=5.0)
        authz = make_authz()
        resolver, _ = make_hop_resolver({HOST: packet_entry([(IP_A, 60)])})
        resolution, evaluation = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        with self.assertRaises(DialProofError) as ctx:
            dp.assemble_dial_proof(
                actual_peer_ip=peer,
                local_sockaddr=local,
                selected_address=peer,
                resolved_addresses=tuple(resolution.resolved_addresses),
                resolver_name="prod-dns-stub",
                resolver_version="prod-dns-stub/v1",
                dial_addresses=tuple(resolution.resolved_addresses),
                dial_port=443,
                dial_sni=HOST,
                resolution=resolution,
                evaluation=evaluation,
                authorization_id=authz.authorization_id,
                tls_sni=HOST,
                tls_version_negotiated="TLSv1.3",
                tls_peer_cert_hash="f" * 64,
                redirect_hop_index=0,
                connection_id=conn_id,
            )
        self.assertEqual(ctx.exception.code, "DIAL_MISMATCH")

    def test_loopback_peer_proof_round_trip(self) -> None:
        authz, resolution, evaluation, params = self._proof_inputs()
        proof = dp.assemble_dial_proof(**params)
        verified = dp.verify_dial_proof(
            proof,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authz.authorization_id,
        )
        self.assertEqual(verified.connection_id, params["connection_id"])
        digest = dp.assert_proof_for_seal(
            proofs=[proof],
            resolutions=[resolution],
            evaluations=[evaluation],
            authorization_id=authz.authorization_id,
        )
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        sealed, returned = dp.seal_with_dial_proof(
            proofs=[proof],
            resolutions=[resolution],
            evaluations=[evaluation],
            authorization_id=authz.authorization_id,
            seal=lambda: "SEALED",
        )
        self.assertEqual((sealed, returned), ("SEALED", digest))

    def test_reused_connection_id_across_hops_rejected(self) -> None:
        authz = make_authz()
        resolver, _ = make_hop_resolver(
            {
                HOST: packet_entry([(IP_A, 60)]),
                WWW: packet_entry([(IP_B, 60)]),
            }
        )
        res0, eval0 = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        res1, eval1 = resolver.resolve_hop(
            authorization=authz,
            execution_id=EX_ID,
            canonical_host=WWW,
            scheme="https",
            effective_port=443,
            path="/",
            query="",
            now=NOW,
        )
        conn = "conn-" + "2" * 32
        _, _, _, params = self._proof_inputs()
        proof0 = dp.assemble_dial_proof(**params)
        _, _, _, params1 = self._proof_inputs()
        params1.update(
            {
                "actual_peer_ip": IP_B,
                "selected_address": IP_B,
                "resolved_addresses": tuple(res1.resolved_addresses),
                "dial_addresses": tuple(res1.resolved_addresses),
                "dial_sni": WWW,
                "resolution": res1,
                "evaluation": eval1,
                "tls_sni": WWW,
                "redirect_hop_index": 1,
                "connection_id": conn,
            }
        )
        proof1 = dp.assemble_dial_proof(**params1)
        # Same connection id on two hops => reuse => rejected.
        import dataclasses

        proof1_dup = dataclasses.replace(proof1, connection_id=proof0.connection_id)
        with self.assertRaises(DialProofError) as ctx:
            dp.assert_proof_for_seal(
                proofs=[proof0, proof1_dup],
                resolutions=[res0, res1],
                evaluations=[eval0, eval1],
                authorization_id=authz.authorization_id,
            )
        self.assertEqual(ctx.exception.code, "DIAL_MISMATCH")


# ==================================================================
# W. parallel executions
# ==================================================================

class ConcurrencyTests(unittest.TestCase):
    def test_parallel_executions_share_no_binding(self) -> None:
        mapping = {HOST: packet_entry([(IP_A, 60)])}
        resolver, _ = make_hop_resolver(mapping)
        authz = make_authz()
        results: dict[str, object] = {}
        errors: list[BaseException] = []

        def _run(ex_id: str) -> None:
            try:
                results[ex_id] = resolver.resolve_initial(
                    authorization=authz, execution_id=ex_id, now=NOW
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=_run, args=(f"ex-{i:032x}",))
            for i in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30.0)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        ids = {res[0].resolution_id for res in results.values()}  # type: ignore[union-attr]
        self.assertEqual(len(ids), 8)


# ==================================================================
# X/Y. cancellation + timeout map fail-closed
# ==================================================================

class ConnectFailureTests(unittest.TestCase):
    def test_close_during_connect_fails_closed(self) -> None:
        class _ClosingSocket:
            def settimeout(self, timeout: float) -> None:
                return None

            def connect(self, addr) -> None:  # noqa: ANN204
                raise OSError("concurrent close during connect")

            def close(self) -> None:
                return None

        with mock.patch.object(
            lt.socket, "socket", return_value=_ClosingSocket()
        ):
            with self.assertRaises(LiveTransportError) as ctx:
                lt.LiveSocketFactory().connect(IP_A, 443, 5.0)
        self.assertEqual(ctx.exception.code, "TRANSPORT_FAILURE")

    def test_timeout_during_connect_maps(self) -> None:
        class _HangingSocket:
            def settimeout(self, timeout: float) -> None:
                return None

            def connect(self, addr) -> None:  # noqa: ANN204
                raise TimeoutError("connect timed out")

            def close(self) -> None:
                return None

        with mock.patch.object(
            lt.socket, "socket", return_value=_HangingSocket()
        ):
            with self.assertRaises(LiveTransportError) as ctx:
                lt.LiveSocketFactory().connect(IP_A, 443, 5.0)
        self.assertEqual(ctx.exception.code, "TRANSPORT_TIMEOUT")

    def test_connection_refused_fails_closed(self) -> None:
        # Closed loopback port: fast, deterministic, no route needed.
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        with self.assertRaises(LiveTransportError) as ctx:
            lt.LiveSocketFactory().connect("127.0.0.1", port, 5.0)
        self.assertIn(
            ctx.exception.code, ("TRANSPORT_FAILURE", "TRANSPORT_TIMEOUT")
        )


# ==================================================================
# Z + failure-negatives: executor-level offline end to end
# ==================================================================

class ExecutorFailureTests(unittest.TestCase):
    def _genuine_pair(self, content: bytes, addresses=(IP_A,)):
        authz = make_authz(content)
        mapping = {HOST: packet_entry([(a, 60) for a in addresses])}
        resolver, _ = make_hop_resolver(mapping)
        resolution, evaluation = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        return authz, resolution, evaluation

    def test_peer_mismatch_is_incomplete_never_positive(self) -> None:
        content = GOOD_ARTIFACT
        authz, resolution, evaluation = self._genuine_pair(content)
        result = execute_with_fakes(
            authz,
            resolution,
            evaluation,
            content,
            {(IP_A, 443): {"peer": IP_D, "recv": [http_bytes()]}},
        )
        self.assertEqual(result.error_code, "TRANSPORT_BINDING_FAILURE")
        self.assertNotEqual(result.outcome, "sealed")
        self.assertIsNotNone(result.evidence)
        assert result.evidence is not None
        self.assertEqual(result.evidence.lifecycle, "INCOMPLETE")

    def test_post_send_ambiguity_is_unknown_without_bytes(self) -> None:
        content = artifact_content(
            method="POST",
            headers={
                "accept": "text/html",
                "content-type": "application/x-www-form-urlencoded",
            },
            body="a=1",
        )
        authz = make_authz(
            content, plan_method="POST", artifact_method="POST"
        )
        mapping = {HOST: packet_entry([(IP_A, 60)])}
        resolver, _ = make_hop_resolver(mapping)
        resolution, evaluation = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        result = execute_with_fakes(
            authz,
            resolution,
            evaluation,
            content,
            {(IP_A, 443): {"peer": IP_A, "recv": [TimeoutError("stall")]}},
        )
        self.assertEqual(result.error_code, "OUTCOME_UNKNOWN")
        self.assertEqual(result.outcome, "unknown")
        self.assertIsNone(result.evidence)


# ==================================================================
# Live gate: reviewed pair admitted in shape, still disabled
# ==================================================================

class LiveGateTests(unittest.TestCase):
    def _executor(self, factory, tls):
        store = InMemoryAuthorizationStore()
        return hx._PinnedHttpExecutor(
            ExecutorDeps(
                authz_store=store,
                ledger=InMemoryExecutionLedger(),
                audit=InMemoryAuditSink(),
                hop_resolver=NeverCalledHopResolver(),
                socket_factory=factory,
                tls_wrapper=tls,
                now_iso=FakeClock().now,
                monotonic=FakeClock().monotonic,
            )
        )

    def test_reviewed_pair_blocked_while_disabled(self) -> None:
        ex = self._executor(lt.LiveSocketFactory(), lt.LiveTlsWrapper())
        self.assertTrue(
            ex._is_reviewed_b1_live_pair(
                ex._deps.socket_factory, ex._deps.tls_wrapper
            )
        )
        with self.assertRaises(hx.ExecutorError) as ctx:
            ex._check_live_gate()
        self.assertEqual(ctx.exception.code, "LIVE_GATE_BLOCKED")

    def test_offline_fakes_still_pass_gate(self) -> None:
        ex = self._executor(
            FakeSocketFactory({}), FakeTlsWrapper("ok")
        )
        ex._check_live_gate()  # must not raise

    def test_classname_impostor_not_admitted(self) -> None:
        class LiveSocketFactory:  # noqa: N801  (impostor, wrong module)
            pass

        ex = self._executor(LiveSocketFactory(), lt.LiveTlsWrapper())
        self.assertFalse(
            ex._is_reviewed_b1_live_pair(
                ex._deps.socket_factory, ex._deps.tls_wrapper
            )
        )

    def test_real_socket_factory_still_blocked(self) -> None:
        ex = self._executor(hx.RealSocketFactory(), FakeTlsWrapper("ok"))
        with self.assertRaises(hx.ExecutorError) as ctx:
            ex._check_live_gate()
        self.assertEqual(ctx.exception.code, "LIVE_GATE_BLOCKED")

    def test_activation_flags_remain_false(self) -> None:
        self.assertIs(hx.LIVE_TRAFFIC_ENABLED, False)
        from ai.execution import browser_executor, nuclei_executor

        self.assertIs(nuclei_executor.LIVE_NUCLEI, False)
        self.assertIs(browser_executor.LIVE_BROWSER, False)


# ==================================================================
# 5H seam: proof-gated seal, schema untouched
# ==================================================================

class EvidenceSeamTests(unittest.TestCase):
    def test_seal_gate_returns_digest_for_audit(self) -> None:
        authz = make_authz()
        resolver, _ = make_hop_resolver({HOST: packet_entry([(IP_A, 60)])})
        resolution, evaluation = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        proof = dp.assemble_dial_proof(
            actual_peer_ip=IP_A,
            local_sockaddr="192.0.2.7:1",
            selected_address=IP_A,
            resolved_addresses=(IP_A,),
            resolver_name="prod-dns-stub",
            resolver_version="prod-dns-stub/v1",
            dial_addresses=(IP_A,),
            dial_port=443,
            dial_sni=HOST,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authz.authorization_id,
            tls_sni=HOST,
            tls_version_negotiated="TLSv1.3",
            tls_peer_cert_hash="a" * 64,
            redirect_hop_index=0,
            connection_id="conn-" + "3" * 32,
        )
        calls: list[str] = []
        record, digest = dp.seal_with_dial_proof(
            proofs=[proof],
            resolutions=[resolution],
            evaluations=[evaluation],
            authorization_id=authz.authorization_id,
            seal=lambda: calls.append("sealed") or "RECORD",
        )
        self.assertEqual(record, "RECORD")
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(calls, ["sealed"])

    def test_observation_schema_unextended_no_second_store(self) -> None:
        # v1 carries NO dial-proof fields on HttpObservation: the
        # schema stays frozen (extra=forbid rejects proof kwargs),
        # so no second evidence authority can smuggle fields in.
        with self.assertRaises(Exception):
            HttpObservation(  # type: ignore[call-arg]
                method="GET",
                request_url="https://x.invalid/",  # type: ignore[arg-type]
                request_body_hash="b" * 64,
                dial_proof_hash="c" * 64,
            )


# ==================================================================
# Static security invariants (AST / source)
# ==================================================================

class StaticSecurityTests(unittest.TestCase):
    def test_only_live_transport_imports_socket_ssl(self) -> None:
        for name in B1_NEW_MODULES:
            tree = ast.parse(_read_module(name), filename=name)
            mods: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods.add(node.module.split(".")[0])
            if name == "live_transport":
                self.assertIn("socket", mods)
                self.assertIn("ssl", mods)
            else:
                self.assertNotIn("socket", mods, name)
                self.assertNotIn("ssl", mods, name)

    def test_no_high_level_http_client_or_implicit_dns(self) -> None:
        for name in B1_NEW_MODULES:
            tree = ast.parse(_read_module(name), filename=name)
            mods: set[str] = set()
            attrs: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods.add(node.module)
                elif isinstance(node, ast.Attribute):
                    attrs.add(node.attr)
            for banned in (
                "httpx",
                "requests",
                "urllib3",
                "aiohttp",
                "http.client",
                "urllib.request",
                "subprocess",
            ):
                self.assertNotIn(banned, mods, f"{name}:{banned}")
            for banned_attr in (
                "create_connection",
                "getaddrinfo",
                "urlopen",
                "Session",
                "Popen",
                "check_output",
            ):
                self.assertNotIn(banned_attr, attrs, f"{name}:{banned_attr}")
            self.assertNotIn("shell=True", _read_module(name), name)

    def test_no_proxy_surface_outside_guard(self) -> None:
        import inspect as _inspect

        for name in B1_NEW_MODULES:
            if name == "egress_guard":
                continue
            tree = ast.parse(_read_module(name), filename=name)
            attrs: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    attrs.add(node.attr)
            for attr in attrs:
                self.assertNotIn("proxy", attr.lower(), f"{name}:{attr}")
        for name in (
            "production_address_source",
            "live_transport",
            "production_hop_resolver",
            "dial_proof",
        ):
            source = _read_module(name)
            for token in ("HTTP_PROXY", "http_proxy", "os.environ", "getenv"):
                self.assertNotIn(token, source, f"{name}:{token}")
        # Constructors take no proxy parameter anywhere in B1.
        import ai.execution.live_transport as _lt
        import ai.execution.production_address_source as _pas
        import ai.execution.production_hop_resolver as _phr

        for cls in (
            _lt.LiveSocketFactory,
            _lt.LiveTlsWrapper,
            _pas.ProductionAddressSource,
            _phr.ProductionHopResolver,
        ):
            params = _inspect.signature(cls.__init__).parameters
            for param in params:
                self.assertNotIn("proxy", param.lower(), cls.__name__)

    def test_no_caller_ip_destination_on_hop_path(self) -> None:
        import inspect as _inspect

        for method in ("resolve_hop", "resolve_initial"):
            params = _inspect.signature(
                getattr(phr.ProductionHopResolver, method)
            ).parameters
            names = [p.lower() for p in params if p not in ("self",)]
            for param in names:
                if param == "authz_time_addresses":
                    # Authorization-time pin (provenance for the
                    # STALE_RESOLUTION comparison only): never a dial
                    # destination, never overrides canonical host,
                    # port, scheme, SNI, or the resolved set.
                    continue
                self.assertNotIn("ip", param, method)
                self.assertNotIn("addr", param, method)
                self.assertNotIn("dial", param, method)
                self.assertNotIn("sni", param, method)

    def test_no_legacy_executor_import_in_b1_path(self) -> None:
        for name in B1_NEW_MODULES:
            tree = ast.parse(_read_module(name), filename=name)
            mods: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods.extend(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods.append(node.module)
            for mod in mods:
                self.assertFalse(
                    mod.startswith("ai.verification"),
                    f"{name}:{mod}",
                )
                self.assertNotIn("nuclei_runner", mod, f"{name}:{mod}")
                self.assertNotIn("legacy", mod, f"{name}:{mod}")

    def test_live_flags_are_literal_false_single_assignment(self) -> None:
        pairs = {
            "ai/execution/http_executor.py": "LIVE_TRAFFIC_ENABLED",
            "ai/execution/nuclei_executor.py": "LIVE_NUCLEI",
            "ai/execution/browser_executor.py": "LIVE_BROWSER",
        }
        root = Path(__file__).resolve().parent.parent
        for rel, flag in pairs.items():
            tree = ast.parse((root / rel).read_text(encoding="utf-8"))
            assigns = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(t, ast.Name) and t.id == flag for t in node.targets
                )
            ]
            self.assertEqual(len(assigns), 1, rel)
            self.assertIsInstance(assigns[0].value, ast.Constant, rel)
            self.assertIs(assigns[0].value.value, False, rel)

    def test_dial_binding_immutable(self) -> None:
        binding = DialBinding(addresses=(IP_A,), effective_port=443, sni_host=HOST)
        with self.assertRaises(Exception):
            binding.sni_host = EVIL  # type: ignore[misc]
        with self.assertRaises(Exception):
            binding.addresses = (IP_B,)  # type: ignore[misc]
        clone = binding.model_copy(update={"sni_host": HOST})
        self.assertEqual(tuple(clone.addresses), (IP_A,))

    def test_caller_cannot_replace_proof_pins(self) -> None:
        authz = make_authz()
        resolver, _ = make_hop_resolver({HOST: packet_entry([(IP_A, 60)])})
        resolution, evaluation = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        # Swapping the selected IP post-assembly breaks verification.
        proof = dp.assemble_dial_proof(
            actual_peer_ip=IP_A,
            local_sockaddr="192.0.2.7:1",
            selected_address=IP_A,
            resolved_addresses=(IP_A,),
            resolver_name="prod-dns-stub",
            resolver_version="prod-dns-stub/v1",
            dial_addresses=(IP_A,),
            dial_port=443,
            dial_sni=HOST,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authz.authorization_id,
            tls_sni=HOST,
            tls_version_negotiated="TLSv1.3",
            tls_peer_cert_hash="a" * 64,
            redirect_hop_index=0,
            connection_id="conn-" + "4" * 32,
        )
        swapped = resolution.model_copy(
            update={"resolved_addresses": (IP_B,)}
        )
        with self.assertRaises(DialProofError):
            dp.verify_dial_proof(
                proof,
                resolution=swapped,
                evaluation=evaluation,
                authorization_id=authz.authorization_id,
            )

    def test_resolver_order_deterministic(self) -> None:
        from ai.resolver.dns import validate_answers

        first = validate_answers([IP_B, IP_A, IP_V6])
        second = validate_answers([IP_V6, IP_B, IP_A])
        self.assertEqual(first, second)

    def test_proof_binds_resolver_identity(self) -> None:
        authz = make_authz()
        resolver, _ = make_hop_resolver({HOST: packet_entry([(IP_A, 60)])})
        resolution, evaluation = resolver.resolve_initial(
            authorization=authz, execution_id=EX_ID, now=NOW
        )
        proof = dp.assemble_dial_proof(
            actual_peer_ip=IP_A,
            local_sockaddr="192.0.2.7:1",
            selected_address=IP_A,
            resolved_addresses=(IP_A,),
            resolver_name="prod-dns-stub",
            resolver_version="prod-dns-stub/v1",
            dial_addresses=(IP_A,),
            dial_port=443,
            dial_sni=HOST,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authz.authorization_id,
            tls_sni=HOST,
            tls_version_negotiated="TLSv1.3",
            tls_peer_cert_hash="a" * 64,
            redirect_hop_index=0,
            connection_id="conn-" + "5" * 32,
        )
        self.assertEqual(proof.resolver_name, "prod-dns-stub")
        self.assertEqual(proof.resolver_version, "prod-dns-stub/v1")
        self.assertEqual(resolution.dns_source, "prod-dns-stub/v1")


if __name__ == "__main__":
    unittest.main()
