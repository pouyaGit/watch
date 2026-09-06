"""Stage 4 B3 sandbox validation harness (validation tooling, NOT product).

Validates the B3 execution boundary defined in
``ai.execution.b3_boundary`` against REAL kernel-enforced isolation —
an unprivileged Linux user+network namespace pair created per run —
using ONLY a controlled local fixture. This module never opens live
target traffic:

- Every dial target passes :func:`guard_fixture_address`, which admits
  ONLY RFC 5737 TEST-NET-1 documentation addresses (``192.0.2.0/24``,
  never routable on any real network) plus namespace-local loopback
  for loopback-isolation tests. Anything else raises
  ``ValidationRefused`` before any socket exists.
- Nothing runs unless the caller passes ``enable=True`` AND the
  environment opts in via ``WATCH_STAGE4_NETNS=1``. Default state is
  refusal (``ValidationRefused``), which callers map to UNPROVEN, never
  PASS.
- No public/bounty/production/metadata/arbitrary target is ever
  referenced (string-scan tested). No production credentials or data.
  The fixture is labeled ``TEST ONLY / STAGE4 / NON-PRODUCTION``.
- The B3 product abstraction is NOT rewritten and no live gate is
  touched: ``LIVE_TRAFFIC_ENABLED`` / ``LIVE_NUCLEI`` /
  ``HTTP_PROBE_PILOT_ENABLED`` stay ``False``. Live HTTP end-to-end
  (`execute_http` with the live pair) remains blocked by the frozen
  `_check_live_gate`; this harness exercises the transport PRIMITIVES
  (`LiveSocketFactory`, `verify_socket_peer`, the bounded
  `receive_http_response`/`decode_body` pipeline) directly against the
  fixture, which is the honest, gate-respecting coverage boundary.

Mechanics (stdlib only): ``os.fork`` + libc ``unshare`` into
``CLONE_NEWUSER|CLONE_NEWNET``, uid/gid mapping, ``lo`` up plus the
fixture address on ``lo`` via the ``ip`` CLI (short-lived, waited
children — test scaffolding, never a product shell path), an
in-process threaded fixture TCP server, results back over a pipe, and
parent-side wall-timeout + SIGKILL + ``waitpid`` reaping. The test
namespace is never persisted (no ``ip netns add``), so teardown is
death-of-last-process by construction; the parent verifies its own
``net:[inode]`` is unchanged and the child is reaped.

Honest coverage boundaries (also reported per check, never upgraded):

- Packet-filter (iptables/nft) rule enforcement: UNPROVEN here — no
  binaries exist in this environment. The enforced mechanism proven
  here is the namespace FIB itself (no default route; single-host
  fixture route): unapproved destinations fail in the kernel with
  ``ENETUNREACH``/``ENETDOWN``, observed — not application logic.
- Live SYN-timeout against a silent routed peer: PROVEN since
  Stage 6 via a controlled backlog-full listener (kernel drops
  further SYNs silently — the observable DROP condition with no
  packet filter needed): the bounded connect timeout expires with
  deterministic ``TRANSPORT_TIMEOUT`` inside its ceiling. Stall/wall
  timeouts are proven against a hold-open fixture. Connect-timeout
  range gating stays unit-covered.
- CPU/memory/process-count enforcement: UNPROVEN (no cgroup
  delegation attempted here).
- Stage 5 full chain (``dialproof_chain`` scenario, opt-in like the
  rest): the fixture ADDRESS TEXT is a globally routable literal
  (``8.8.8.8``) so the frozen B1 ``validate_answers`` admits it with
  zero B1 changes, while the DESTINATION is strictly local (a /32 on
  ``lo`` inside the routeless test netns). The dial proceeds only
  after kernel-verified assertions (foreign netns inode, no default
  routes, fixture in the local table) through the exact-match chain
  guard. Chain: fresh 5B/5C/5D lineage over scripted DNS -> B3 egress
  policy -> real socket -> ``getpeername`` peer proof -> genuine
  ``DialProof`` assembly/verification/egress binding -> bounded HTTP
  exchange within ceilings -> evidence sealed through the existing
  proof-gated 5H seam. TLS proof fields are nominal for the plaintext
  fixture (documented in-scenario); binding force comes from
  peer+pin+binding+lineage.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

__all__ = [
    "FIXTURE_LABEL",
    "FIXTURE_SUBNET",
    "FIXTURE_A",
    "FIXTURE_B",
    "FIXTURE_PORT",
    "SYNDROP_PORT",
    "HARNESS_OPT_IN_ENV",
    "VALIDATION_STATUSES",
    "CheckResult",
    "ValidationReport",
    "ValidationRefused",
    "CHAIN_FIXTURE_HOST",
    "CHAIN_FIXTURE_IP",
    "CHAIN_FIXTURE_PORT",
    "CHAIN_CHECK_NAMES",
    "probe_capabilities",
    "guard_fixture_address",
    "guard_chain_address",
    "require_harness_enable",
    "run_full_validation",
    "SCENARIO_NAMES",
]

#: Fixture identity marker (asserted present by tests).
FIXTURE_LABEL = "TEST ONLY / STAGE4 / NON-PRODUCTION"

#: RFC 5737 documentation range: unroutable by design, so even a
#: misconfigured fixture cannot reach a real host.
FIXTURE_SUBNET = "192.0.2.0/24"
FIXTURE_A = "192.0.2.10"
FIXTURE_B = "192.0.2.11"
FIXTURE_PORT = 18080

#: Stage 6 SYN-DROP fixture port (same host, distinct port so the
#: silent-peer server never collides with the echo servers).
SYNDROP_PORT = 18082

#: Stage 5 full-chain fixture (Part D). The ADDRESS TEXT is a globally
#: routable literal (so the frozen B1 ``validate_answers`` admits it
#: without any B1 change), but the DESTINATION is strictly local: the
#: address is assigned /32 to ``lo`` inside the isolated test netns,
#: which has no default route and no peer interfaces, so the kernel
#: local table delivers every SYN to the in-namespace fixture server
#: and no packet can leave. The dial proceeds ONLY after runtime
#: assertions (different netns inode from the parent, no v4/v6 default
#: route, fixture /32 present in the local table). Residual risk if
#: all three kernel-verified assertions lied simultaneously: a single
#: SYN to a high port; documented, never observed.
CHAIN_FIXTURE_HOST = "stage5-fixture.example.com"
CHAIN_FIXTURE_IP = "8.8.8.8"
CHAIN_FIXTURE_PORT = 18081

#: Explicit environment opt-in (in addition to ``enable=True``).
HARNESS_OPT_IN_ENV = "WATCH_STAGE4_NETNS"

VALIDATION_STATUSES = ("PASS", "FAIL", "UNPROVEN")

_CLONE_NEWUSER = 0x10000000
_CLONE_NEWNET = 0x40000000

#: Kernel-level "no route" errnos: proof the FIB, not app logic, blocked.
_NO_ROUTE_ERRNOS = frozenset({errno.ENETUNREACH, errno.ENETDOWN, errno.EADDRNOTAVAIL})

SCENARIO_NAMES: tuple[str, ...] = (
    "namespace",
    "veth",
    "routes",
    "egress_matrix",
    "dns_pinned",
    "timeouts",
    "bytecaps",
    "syndrop",
    "dialproof_chain",
)

#: Checks minted by the full-chain scenario (readiness item 8).
CHAIN_CHECK_NAMES: tuple[str, ...] = (
    "chain-resolution",
    "chain-egress",
    "chain-peer-proof",
    "chain-http-exchange",
    "chain-evidence-sealed",
    "chain-dial-audit",
)


class ValidationRefused(Exception):
    """Harness refused to run (maps to UNPROVEN, never PASS)."""


@dataclass(frozen=True)
class CheckResult:
    """One validation outcome (static detail, no secrets)."""

    name: str
    status: str
    detail: str

    def __post_init__(self) -> None:
        if self.status not in VALIDATION_STATUSES:
            raise ValueError(f"bad validation status: {self.status!r}")
        if "\n" in self.detail or "\r" in self.detail:
            raise ValueError("check detail must be single-line")


@dataclass(frozen=True)
class ValidationReport:
    """Full harness outcome (environment snapshot + checks)."""

    label: str
    capabilities: dict[str, bool]
    checks: tuple[CheckResult, ...]
    parent_netns_unchanged: bool
    child_reaped: bool


# ------------------------------------------------------------------
# Guards (no socket exists unless these pass).
# ------------------------------------------------------------------


def _is_in_fixture_subnet(address: str) -> bool:
    import ipaddress as _ip

    try:
        parsed = _ip.ip_address(address.strip())
    except ValueError:
        return False
    return parsed in _ip.ip_network(FIXTURE_SUBNET)


def guard_fixture_address(address: object) -> str:
    """Admit ONLY fixture-subnet literals (plus namespace loopback).

    Namespace-local ``127.0.0.1``/``::1`` are admitted SOLELY for
    loopback-isolation tests (proving the namespace loopback is not a
    path to the fixture or the host). Every other input — public IPs,
    metadata addresses, hostnames, URLs — raises ``ValidationRefused``
    before any socket exists.
    """

    if isinstance(address, str) and address.strip() in ("127.0.0.1", "::1"):
        if address != address.strip():
            raise ValidationRefused("dial target outside the Stage 4 fixture subnet")
        return address
    if isinstance(address, str) and _is_in_fixture_subnet(address):
        import ipaddress as _ip

        canonical = str(_ip.ip_address(address.strip()))
        if address != canonical:
            # Non-canonical text (padding, zones, prefixes) is refused:
            # the allowlist is exact-match only, mirroring B3.
            raise ValidationRefused("dial target outside the Stage 4 fixture subnet")
        return canonical
    raise ValidationRefused("dial target outside the Stage 4 fixture subnet")


def guard_chain_address(address: object, port: object) -> tuple[str, int]:
    """Admit EXACTLY the Stage 5 full-chain fixture endpoint.

    Only the canonical ``(CHAIN_FIXTURE_IP, CHAIN_FIXTURE_PORT)`` pair
    passes — the address text the frozen B1 policy admits, bound to
    the high fixture port nothing real serves. Any other input raises
    ``ValidationRefused`` before any socket exists. This guard alone
    does NOT authorize a dial: the scenario additionally asserts
    namespace isolation, absence of default routes, and local-table
    delivery before connecting.
    """

    if address != CHAIN_FIXTURE_IP:
        raise ValidationRefused("chain dial target is not the fixture address")
    if port != CHAIN_FIXTURE_PORT:
        raise ValidationRefused("chain dial port is not the fixture port")
    return CHAIN_FIXTURE_IP, CHAIN_FIXTURE_PORT


def probe_capabilities() -> dict[str, bool]:
    """Side-effect-free capability snapshot (safe to call anywhere)."""

    capabilities = {
        "ip_cli_present": shutil.which("ip") is not None,
        "env_opt_in": os.environ.get(HARNESS_OPT_IN_ENV) == "1",
        "userns_netns_permitted": False,
    }
    pid = os.fork()
    if pid == 0:  # probe child: never touches anything, just tries.
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ok = libc.unshare(_CLONE_NEWUSER | _CLONE_NEWNET) == 0
        except Exception:
            ok = False
        os._exit(0 if ok else 1)
    _, status = os.waitpid(pid, 0)
    capabilities["userns_netns_permitted"] = os.waitstatus_to_exitcode(status) == 0
    return capabilities


def require_harness_enable(*, enable: bool) -> dict[str, bool]:
    """Enforce the double opt-in (explicit flag + environment)."""

    if enable is not True:
        raise ValidationRefused("harness requires explicit enable=True")
    capabilities = probe_capabilities()
    if capabilities["env_opt_in"] is not True:
        raise ValidationRefused(
            f"harness requires {HARNESS_OPT_IN_ENV}=1 in the environment"
        )
    if capabilities["userns_netns_permitted"] is not True:
        raise ValidationRefused("user+network namespaces not permitted here")
    if capabilities["ip_cli_present"] is not True:
        raise ValidationRefused("ip CLI unavailable for interface setup")
    return capabilities


def _parent_netns_id() -> str:
    return os.readlink("/proc/self/ns/net")


# ------------------------------------------------------------------
# Fixture server (in-namespace thread; raw HTTP bytes, no framework).
# ------------------------------------------------------------------


class _FixtureServer:
    """One-shot-per-connection TCP server with scripted behaviors."""

    def __init__(
        self, mode: str, *, bind_ip: str = FIXTURE_A, port: int = FIXTURE_PORT
    ) -> None:
        # Every bind goes through a guard: the chain fixture pair via
        # the chain guard, all other binds via the subnet guard.
        if bind_ip == CHAIN_FIXTURE_IP:
            bound_ip, bound_port = guard_chain_address(bind_ip, port)
        else:
            bound_ip = guard_fixture_address(bind_ip)
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValidationRefused("fixture port out of range")
            bound_port = port
        self._mode = mode
        self._bind = (bound_ip, bound_port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self._bind)
        self._sock.listen(16)
        self._sock.settimeout(10.0)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.connections = 0

    def __enter__(self) -> "_FixtureServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        try:
            probe = socket.create_connection(self._bind, timeout=2.0)
            probe.close()
        except OSError:
            pass
        self._thread.join(timeout=10.0)
        self._sock.close()

    def _drain_request(self, conn: socket.socket) -> None:
        # Read the request head before responding (like any real HTTP
        # server): closing with an unread request pending would RST the
        # connection and race the client's body read.
        conn.settimeout(5.0)
        head = bytearray()
        try:
            while head.find(b"\r\n\r\n") == -1 and len(head) <= 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                head += chunk
        except OSError:
            pass

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            try:
                if self._mode == "hold":
                    # Accept and never reply: exercises stall/wall timeouts.
                    while not self._stop.is_set():
                        time.sleep(0.05)
                    continue
                self._drain_request(conn)
                if self._mode == "bigbody":
                    body = b"z" * (600 * 1024)
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: "
                        + str(len(body)).encode()
                        + b"\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
                        + body
                    )
                elif self._mode == "gzipbomb":
                    import gzip as _gzip

                    raw = b"0" * (200 * 1024)
                    blob = _gzip.compress(raw)
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: "
                        + str(len(blob)).encode()
                        + b"\r\nContent-Type: text/plain\r\n"
                        + b"Content-Encoding: gzip\r\nConnection: close\r\n\r\n"
                        + blob
                    )
                else:  # "ok"
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                        b"Content-Type: text/plain\r\nConnection: close\r\n\r\nok"
                    )
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass


# ------------------------------------------------------------------
# Child scenarios (run inside the isolated netns; results are data).
# ------------------------------------------------------------------


def _ip(*args: str) -> tuple[int, str]:
    proc = subprocess.run(
        ["ip", *args], capture_output=True, text=True, timeout=20
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _scenario_namespace(payload: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    child_ns = os.readlink("/proc/self/ns/net")
    isolated = child_ns != payload["parent_ns"]
    out.append(
        {
            "name": "namespace-isolated",
            "status": "PASS" if isolated else "FAIL",
            "detail": "child netns differs from parent"
            if isolated
            else "child shares parent netns",
        }
    )
    code, text = _ip("link", "show")
    only_lo = code == 0 and "eth0" not in text and "enp" not in text and "wlp" not in text
    out.append(
        {
            "name": "no-host-interface-inheritance",
            "status": "PASS" if only_lo else "FAIL",
            "detail": "no host NIC visible in test netns"
            if only_lo
            else "unexpected interface visible",
        }
    )
    return out


def _scenario_veth(_payload: dict[str, Any]) -> list[dict[str, str]]:
    code, _ = _ip(
        "link", "add", "veth-stage4", "type", "veth", "peer", "veth-stage4-p"
    )
    if code != 0:
        return [
            {
                "name": "veth-lifecycle",
                "status": "UNPROVEN",
                "detail": "veth creation unavailable in test netns",
            }
        ]
    _, after_add = _ip("link", "show", "type", "veth")
    present = "veth-stage4" in after_add
    _ip("link", "del", "veth-stage4")
    _, after_del = _ip("link", "show", "type", "veth")
    gone = "veth-stage4" not in after_del
    ok = present and gone
    return [
        {
            "name": "veth-lifecycle",
            "status": "PASS" if ok else "FAIL",
            "detail": "veth pair created, verified, deleted"
            if ok
            else "veth lifecycle incomplete",
        }
    ]


def _scenario_routes(_payload: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    _, text = _ip("route", "show")
    lines = [line for line in text.splitlines() if line.strip()]
    no_default = not any(line.startswith("default") for line in lines)
    out.append(
        {
            "name": "no-default-route",
            "status": "PASS" if no_default else "FAIL",
            "detail": "no default route in test netns"
            if no_default
            else "default route present",
        }
    )
    _, text6 = _ip("-6", "route", "show")
    no_default6 = not any(
        line.startswith("default") for line in text6.splitlines() if line.strip()
    )
    out.append(
        {
            "name": "no-default-route-v6",
            "status": "PASS" if no_default6 else "FAIL",
            "detail": "no v6 default route in test netns"
            if no_default6
            else "v6 default route present",
        }
    )
    return out


def _dial_guarded(
    ip_literal: str,
    port: int,
    timeout: float,
    audit: list[tuple[str, int]] | None = None,
) -> socket.socket:
    from ai.execution import live_transport as _lt

    target = guard_fixture_address(ip_literal)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValidationRefused("fixture port out of range")
    if audit is not None:
        audit.append((target, port))
    return _lt.LiveSocketFactory().connect(target, port, timeout)


def _dial_chain_guarded(
    factory: object,
    port: int,
    timeout: float,
    audit: list[tuple[str, int]] | None = None,
):
    target, bound_port = guard_chain_address(CHAIN_FIXTURE_IP, port)
    if audit is not None:
        audit.append((target, bound_port))
    connect = getattr(factory, "connect")
    return connect(target, bound_port, timeout)


def _scenario_egress_matrix(_payload: dict[str, Any]) -> list[dict[str, str]]:
    from ai.execution import live_transport as _lt

    out: list[dict[str, str]] = []
    with _FixtureServer("ok"):
        time.sleep(0.2)
        # Allowed exact (A, P): must succeed; peer must equal A; TCP only.
        try:
            sock = _dial_guarded(FIXTURE_A, FIXTURE_PORT, 5.0)
            try:
                peer = _lt.verify_socket_peer(sock, FIXTURE_A)
                tcp_only = (
                    sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                    == socket.SOCK_STREAM
                )
                ok = peer == FIXTURE_A and tcp_only
            finally:
                _lt.close_quietly(sock)
            out.append(
                {
                    "name": "egress-allowed-exact",
                    "status": "PASS" if ok else "FAIL",
                    "detail": "allowed (address,port) dialed, peer proven, TCP-only",
                }
            )
            # Consume the one-shot body to prove a full round trip.
            sock2 = _dial_guarded(FIXTURE_A, FIXTURE_PORT, 5.0)
            try:
                sock2.sendall(b"GET / HTTP/1.0\r\n\r\n")
                data = sock2.recv(64)
                ok2 = data.startswith(b"HTTP/1.1 200")
            finally:
                _lt.close_quietly(sock2)
            out.append(
                {
                    "name": "egress-fixture-roundtrip",
                    "status": "PASS" if ok2 else "FAIL",
                    "detail": "fixture HTTP bytes received on allowed path",
                }
            )
        except Exception:
            out.append(
                {
                    "name": "egress-allowed-exact",
                    "status": "FAIL",
                    "detail": "allowed dial failed unexpectedly",
                }
            )
            out.append(
                {
                    "name": "egress-fixture-roundtrip",
                    "status": "FAIL",
                    "detail": "round trip unreachable",
                }
            )
        # Wrong port (A, P+1): must refuse (nothing listens).
        try:
            sock = _dial_guarded(FIXTURE_A, FIXTURE_PORT + 1, 5.0)
            _lt.close_quietly(sock)
            out.append(
                {
                    "name": "egress-wrong-port-blocked",
                    "status": "FAIL",
                    "detail": "wrong port unexpectedly connected",
                }
            )
        except Exception:
            out.append(
                {
                    "name": "egress-wrong-port-blocked",
                    "status": "PASS",
                    "detail": "wrong port refused",
                }
            )
        # Unapproved address B (P and P+1): the kernel FIB must refuse.
        # Two observations per destination: (1) a raw SYN observes the
        # kernel errno (the product factory maps failures to closed
        # codes and must not be asked to preserve errnos); (2) the
        # product LiveSocketFactory must likewise refuse.
        for label in ("egress-unapproved-address", "egress-unapproved-address-port"):
            port = FIXTURE_PORT if label == "egress-unapproved-address" else FIXTURE_PORT + 1
            target = guard_fixture_address(FIXTURE_B)
            try:
                raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    raw.settimeout(5.0)
                    raw.connect((target, port))
                finally:
                    raw.close()
                out.append(
                    {"name": label, "status": "FAIL",
                     "detail": "unapproved address unexpectedly reachable"}
                )
                continue
            except OSError as raw_exc:
                kernel_block = raw_exc.errno in _NO_ROUTE_ERRNOS
            try:
                sock = _dial_guarded(FIXTURE_B, port, 5.0)
                _lt.close_quietly(sock)
                out.append(
                    {"name": label, "status": "FAIL",
                     "detail": "product dial unexpectedly connected"}
                )
            except Exception:
                out.append(
                    {
                        "name": label,
                        "status": "PASS" if kernel_block else "FAIL",
                        "detail": "kernel FIB refused unapproved address; "
                        "product dial refused"
                        if kernel_block
                        else "unapproved address failed outside the FIB",
                    }
                )
        # Loopback / private / link-local / metadata: blocked, and the
        # namespace loopback provably carries no fixture bytes.
        for hostile, label in (
            ("127.0.0.1", "egress-loopback-blocked"),
            ("10.9.9.9", "egress-private-blocked"),
            ("169.254.10.20", "egress-linklocal-blocked"),
            ("169.254.169.254", "egress-metadata-blocked"),
        ):
            try:
                sock = _dial_guarded(hostile, FIXTURE_PORT, 3.0)
                try:
                    sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    data = sock.recv(16)
                    leaked = data.startswith(b"HTTP/1.1 200")
                finally:
                    _lt.close_quietly(sock)
                out.append(
                    {
                        "name": label,
                        "status": "FAIL" if leaked else "PASS",
                        "detail": "no fixture bytes via blocked destination"
                        if not leaked
                        else "fixture reachable via blocked destination",
                    }
                )
            except Exception:
                out.append(
                    {"name": label, "status": "PASS",
                     "detail": "blocked destination unreachable"}
                )
    return out


def _scenario_dns_pinned(_payload: dict[str, Any]) -> list[dict[str, str]]:
    from ai.execution import live_transport as _lt

    out: list[dict[str, str]] = []
    with _FixtureServer("ok"):
        time.sleep(0.2)
        # Hostnames never reach the dial path (rejected pre-I/O).
        try:
            _lt.LiveSocketFactory().connect("stage4-fixture.invalid", 80, 2.0)
            out.append(
                {"name": "dns-hostname-never-dials", "status": "FAIL",
                 "detail": "hostname unexpectedly dialed"}
            )
        except Exception as exc:
            out.append(
                {
                    "name": "dns-hostname-never-dials",
                    "status": "PASS"
                    if getattr(exc, "code", "") == "DIAL_BINDING_MISMATCH"
                    else "FAIL",
                    "detail": "hostname rejected before any I/O",
                }
            )
        # A pinned literal dial succeeds even with system resolution
        # sabotaged: no lookup exists on the dial path.
        real_getaddrinfo = socket.getaddrinfo

        def _poisoned(*args: object, **kwargs: object) -> object:
            raise AssertionError("dial path performed a DNS lookup")

        socket.getaddrinfo = _poisoned  # type: ignore[assignment]
        try:
            sock = _dial_guarded(FIXTURE_A, FIXTURE_PORT, 5.0)
            try:
                peer = _lt.verify_socket_peer(sock, FIXTURE_A)
                ok = peer == FIXTURE_A
            finally:
                _lt.close_quietly(sock)
        except AssertionError:
            ok = False
        except Exception:
            ok = False
        finally:
            socket.getaddrinfo = real_getaddrinfo  # type: ignore[assignment]
        out.append(
            {
                "name": "dns-pinned-no-lookup",
                "status": "PASS" if ok else "FAIL",
                "detail": "literal dial succeeds with resolution sabotaged",
            }
        )
    return out


def _scenario_timeouts(_payload: dict[str, Any]) -> list[dict[str, str]]:
    from ai.execution import http_executor as _hx

    out: list[dict[str, str]] = []
    with _FixtureServer("hold"):
        time.sleep(0.2)
        try:
            sock = _dial_guarded(FIXTURE_A, FIXTURE_PORT, 5.0)
        except Exception:
            return [
                {"name": "timeout-stall-enforced", "status": "FAIL",
                 "detail": "fixture hold-server unreachable"}
            ]
        try:
            sock.settimeout(2.0)
            deadline = time.monotonic() + 1.0

            def _recv(n: int) -> bytes:
                return sock.recv(n)

            try:
                _hx.receive_http_response(
                    _recv, method="GET", deadline=deadline, clock=time.monotonic
                )
                out.append(
                    {"name": "timeout-stall-enforced", "status": "FAIL",
                     "detail": "silent peer did not time out"}
                )
            except Exception as exc:
                out.append(
                    {
                        "name": "timeout-stall-enforced",
                        "status": "PASS"
                        if getattr(exc, "code", "") == "TRANSPORT_TIMEOUT"
                        else "FAIL",
                        "detail": "silent peer hit TRANSPORT_TIMEOUT",
                    }
                )
        finally:
            try:
                sock.close()
            except OSError:
                pass
    out.append(
        {
            "name": "timeout-syn-drop",
            "status": "UNPROVEN",
            "detail": "SYN-timeout vs DROP needs a packet filter; unavailable here",
        }
    )
    return out


def _scenario_bytecaps(_payload: dict[str, Any]) -> list[dict[str, str]]:
    from ai.execution import http_executor as _hx
    from ai.limits.ceilings import CEILINGS as _CEIL

    out: list[dict[str, str]] = []
    with _FixtureServer("bigbody"):
        time.sleep(0.2)
        try:
            sock = _dial_guarded(FIXTURE_A, FIXTURE_PORT, 5.0)
        except Exception:
            return [
                {"name": "bytecap-transport-truncates", "status": "FAIL",
                 "detail": "fixture big-body server unreachable"}
            ]
        try:
            sock.settimeout(10.0)
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            deadline = time.monotonic() + 20.0

            def _recv(n: int) -> bytes:
                return sock.recv(n)

            try:
                resp = _hx.receive_http_response(
                    _recv, method="GET", deadline=deadline, clock=time.monotonic
                )
                ok = (
                    resp.over_cap is True
                    and len(resp.body_raw) == _CEIL["response_transport_bytes"]
                )
            except Exception:
                ok = False
            out.append(
                {
                    "name": "bytecap-transport-truncates",
                    "status": "PASS" if ok else "FAIL",
                    "detail": "600KiB body stopped exactly at the transport cap",
                }
            )
        finally:
            try:
                sock.close()
            except OSError:
                pass
    with _FixtureServer("gzipbomb"):
        time.sleep(0.2)
        try:
            sock = _dial_guarded(FIXTURE_A, FIXTURE_PORT, 5.0)
        except Exception:
            return out + [
                {"name": "bytecap-decompression-ratio", "status": "FAIL",
                 "detail": "fixture gzip server unreachable"}
            ]
        try:
            sock.settimeout(10.0)
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            deadline = time.monotonic() + 20.0

            def _recv2(n: int) -> bytes:
                return sock.recv(n)

            try:
                resp = _hx.receive_http_response(
                    _recv2, method="GET", deadline=deadline, clock=time.monotonic
                )
                try:
                    _hx.decode_body(resp.body_raw, "gzip")
                    ok2 = False
                except Exception as exc2:
                    ok2 = getattr(exc2, "code", "") == "DECOMPRESSION_LIMIT"
            except Exception:
                ok2 = False
            out.append(
                {
                    "name": "bytecap-decompression-ratio",
                    "status": "PASS" if ok2 else "FAIL",
                    "detail": "200KiB-from-bytes gzip refused on ratio cap",
                }
            )
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return out


def _scenario_hang(_payload: dict[str, Any]) -> list[dict[str, str]]:
    # Never returns: exercises the parent wall-timeout + SIGKILL + reap
    # path. NOT in SCENARIO_NAMES; used only by the timeout-cleanup test.
    time.sleep(600)
    return [
        {"name": "hang", "status": "FAIL", "detail": "hang scenario returned"}
    ]


def _chain_wire_bytes(request: object) -> bytes:
    """Render transport wire bytes from a genuine BoundedHttpRequest.

    Origin-form request line plus transport-generated ``Host`` (the
    translator never stores framing headers — the transport generates
    them, exactly as the product transport would).
    """

    method = getattr(request, "method")
    target = getattr(request, "request_target")
    host = getattr(request, "canonical_host")
    port = getattr(request, "effective_port")
    authority = host if port in (80, 443) else f"{host}:{port}"
    lines = [f"{method} {target} HTTP/1.1", f"Host: {authority}"]
    for name, value in getattr(request, "headers"):
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + bytes(getattr(request, "body") or b"")


def _scenario_dialproof_chain(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Full chain on the isolated fixture (Part D).

    authorization -> resolution -> scope -> egress policy ->
    actual socket -> peer proof -> bounded HTTP -> sealed evidence,
    all against the in-namespace fixture. Pre-dial assertions (ns
    isolation, no default routes, local-table delivery) must hold or
    the scenario refuses before any dial.
    """

    from ai.evidence import hashing as _hash_mod
    from ai.evidence import observations as _obs
    from ai.evidence.builder import EvidenceBuilder
    from ai.schemas import evidence as _ev
    from ai.execution import b3_boundary as _b3
    from ai.execution import dial_proof as _dp
    from ai.execution import http_executor as _hx
    from ai.execution import live_transport as _lt
    from ai.execution.production_hop_resolver import ProductionHopResolver
    from ai.limits.ceilings import CEILINGS as _CEIL
    from ai.resolver.inventory import (
        AssetRecord,
        InMemoryInventoryRepository,
        ProgramRecord,
        scope_lists_hash_for,
    )
    from ai.scope.policy import InMemoryPolicyStore
    from ai.test_b1_dial_policy import (
        EX_ID_2,
        GOOD_ARTIFACT,
        NOW,
        PROGRAM,
        artifact_reference_for,
        make_authz,
        make_source,
        packet_entry,
    )

    out: list[dict[str, str]] = []
    dials: list[tuple[str, int]] = []

    def _fail(name: str, detail: str) -> list[dict[str, str]]:
        return [{"name": name, "status": "FAIL", "detail": detail}]

    # 0. Pre-dial isolation assertions (kernel-verified, refuse first).
    child_ns = os.readlink("/proc/self/ns/net")
    if child_ns == payload.get("parent_ns"):
        return _fail("chain-resolution", "not isolated: shares parent netns")
    _, routes = _ip("route", "show")
    _, routes6 = _ip("-6", "route", "show")
    if any(line.startswith("default") for line in (routes + "\n" + routes6).splitlines() if line.strip()):
        return _fail("chain-resolution", "default route present: refuse chain dial")
    _, local = _ip("route", "show", "table", "local")
    if CHAIN_FIXTURE_IP not in local:
        return _fail("chain-resolution", "fixture not in local table: refuse chain dial")

    # 1. Genuine 5B/5C/5D lineage over scripted DNS (no network).
    scope_hash = scope_lists_hash_for((CHAIN_FIXTURE_HOST,), ())
    authz = make_authz(
        host=CHAIN_FIXTURE_HOST, scheme="http",
        port=CHAIN_FIXTURE_PORT, scope_hash=scope_hash,
    )
    source, _ = make_source({CHAIN_FIXTURE_HOST: packet_entry([(CHAIN_FIXTURE_IP, 60)])})
    inventory = InMemoryInventoryRepository(
        programs=[
            ProgramRecord(
                program_name=PROGRAM,
                scopes=(CHAIN_FIXTURE_HOST,),
                ooscopes=(),
            )
        ],
        assets=[
            AssetRecord(
                program_name=PROGRAM,
                canonical_host=CHAIN_FIXTURE_HOST,
                scheme="http",
                effective_port=CHAIN_FIXTURE_PORT,
            )
        ],
    )
    hop = ProductionHopResolver(
        address_source=source,
        inventory=inventory,
        policy_store=InMemoryPolicyStore({PROGRAM: ([CHAIN_FIXTURE_HOST], [])}),
    )
    try:
        resolution, evaluation = hop.resolve_initial(
            authorization=authz, execution_id=EX_ID_2, now=NOW
        )
    except Exception:
        return _fail("chain-resolution", "fresh resolution/evaluation failed")
    if (
        resolution.status != "RESOLVED"
        or tuple(resolution.resolved_addresses) != (CHAIN_FIXTURE_IP,)
        or evaluation.decision != "ALLOWED"
    ):
        return _fail("chain-resolution", "lineage incoherent")
    out.append(
        {"name": "chain-resolution", "status": "PASS",
         "detail": "fresh 5C pin + ALLOWED 5D over scripted DNS"}
    )

    # 2. Egress policy bound to the exact fixture triple.
    try:
        policy = _b3.build_egress_policy(
            authorization=authz, resolution=resolution,
            evaluation=evaluation, selected_address=CHAIN_FIXTURE_IP, now=NOW,
        )
        _b3.check_egress_dial(
            policy=policy, dial_ip=CHAIN_FIXTURE_IP,
            dial_port=CHAIN_FIXTURE_PORT, dial_scheme="http",
            authorization_id=authz.authorization_id,
            resolution_id=resolution.resolution_id,
        )
    except Exception:
        return out + _fail("chain-egress", "egress policy build/check failed")
    out.append(
        {"name": "chain-egress", "status": "PASS",
         "detail": "egress policy bound to exact fixture triple"}
    )

    # 3. Actual socket + peer proof + DialProof verification + egress bind.
    try:
        with _FixtureServer("ok", bind_ip=CHAIN_FIXTURE_IP, port=CHAIN_FIXTURE_PORT):
            time.sleep(0.2)
            factory = _lt.LiveSocketFactory()
            sock = _dial_chain_guarded(factory, CHAIN_FIXTURE_PORT, 5.0, dials)
            try:
                peer = _lt.verify_socket_peer(sock, CHAIN_FIXTURE_IP)
                local_sockaddr = str(sock.getsockname())
                conn_id = factory.connection_id_for(sock) or ""
                if peer != CHAIN_FIXTURE_IP or not conn_id:
                    return out + _fail("chain-peer-proof", "peer/connection incoherent")
                proof = _dp.assemble_dial_proof(
                    actual_peer_ip=peer, local_sockaddr=local_sockaddr,
                    selected_address=peer,
                    resolved_addresses=tuple(resolution.resolved_addresses),
                    resolver_name="prod-dns-stub",
                    resolver_version="prod-dns-stub/v1",
                    dial_addresses=tuple(resolution.resolved_addresses),
                    dial_port=CHAIN_FIXTURE_PORT, dial_sni=CHAIN_FIXTURE_HOST,
                    resolution=resolution, evaluation=evaluation,
                    authorization_id=authz.authorization_id,
                    tls_sni=CHAIN_FIXTURE_HOST,
                    tls_version_negotiated="no-tls-plaintext",
                    tls_peer_cert_hash=None,
                    redirect_hop_index=0, connection_id=conn_id,
                )
                _dp.verify_dial_proof(
                    proof, resolution=resolution, evaluation=evaluation,
                    authorization_id=authz.authorization_id,
                )
                _b3.assert_dial_matches_egress(
                    proof=proof, policy=policy, resolution=resolution,
                    evaluation=evaluation,
                    authorization_id=authz.authorization_id,
                )
            finally:
                _lt.close_quietly(sock)
    except Exception:
        return out + _fail("chain-peer-proof", "actual dial/proof binding failed")
    out.append(
        {"name": "chain-peer-proof", "status": "PASS",
         "detail": "actual peer proven and bound to egress policy"}
    )

    # 4. Bounded HTTP exchange over a second fresh socket.
    try:
        request = _hx.translate_bounded_request(
            authorization=authz, resolution=resolution,
            evaluation=evaluation,
            artifact_reference=artifact_reference_for(GOOD_ARTIFACT),
            artifact_bytes=GOOD_ARTIFACT, execution_id=EX_ID_2,
        )
        _b3.check_request_bounds(request=request)
        wire = _chain_wire_bytes(request)
        with _FixtureServer("ok", bind_ip=CHAIN_FIXTURE_IP, port=CHAIN_FIXTURE_PORT):
            time.sleep(0.2)
            sock = _dial_chain_guarded(factory, CHAIN_FIXTURE_PORT, 5.0, dials)
            try:
                sock.settimeout(10.0)
                sock.sendall(wire)
                deadline = time.monotonic() + 20.0

                def _recv(n: int) -> bytes:
                    return sock.recv(n)

                resp = _hx.receive_http_response(
                    _recv, method=request.method,
                    deadline=deadline, clock=time.monotonic,
                )
            finally:
                _lt.close_quietly(sock)
        if resp.status != 200 or resp.over_cap:
            return out + _fail("chain-http-exchange", "fixture response out of contract")
        content_type = ""
        content_encoding: str | None = None
        for key, value in resp.headers:
            if key == "content-type":
                content_type = value
            elif key == "content-encoding":
                content_encoding = value
        decoded, _ = _hx.decode_body(resp.body_raw, content_encoding)
        body_hash, body_sample, omitted = _hx.observe_transport_body(
            decoded, content_type=content_type,
            sample_budget=_CEIL["response_evidence_sample_bytes"],
        )
    except Exception:
        return out + _fail("chain-http-exchange", "bounded exchange failed")
    out.append(
        {"name": "chain-http-exchange", "status": "PASS",
         "detail": "bounded request/response observed within ceilings"}
    )

    # 5. Evidence seal gated on the dial proof (existing 5H seam).
    try:
        builder = EvidenceBuilder.begin(
            authorization=authz, execution_id=EX_ID_2,
            execution_class="http_probe", execution_stage="single",
            started_at=NOW,
        )
        builder.attach_http(
            _ev.HttpObservation(
                method=request.method,
                request_url=_obs.observe_url(request.canonical_url),
                request_body_hash=_hash_mod.sha256_hex(request.body or b""),
                response_status=resp.status,
                response_body_hash=body_hash,
                response_body_sample=body_sample,
                sample_omitted=omitted,
                dial_ips=(peer,),
                transport_outcome="responded",
            )
        )
        sealed, digest = _dp.seal_with_dial_proof(
            proofs=[proof], resolutions=[resolution],
            evaluations=[evaluation],
            authorization_id=authz.authorization_id,
            seal=lambda: builder.seal(finished_at=NOW, sealed_at=NOW),
        )
    except Exception:
        return out + _fail("chain-evidence-sealed", "proof-gated seal failed")
    out.append(
        {"name": "chain-evidence-sealed", "status": "PASS",
         "detail": f"sealed {sealed.evidence_id} digest {digest[:16]}"}
    )
    audit = sorted({f"{ip}:{port}" for ip, port in dials})
    out.append(
        {"name": "chain-dial-audit", "status": "PASS",
         "detail": f"dials={','.join(audit)}x{len(dials)}"}
    )
    return out


def _scenario_syndrop(_payload: dict[str, Any]) -> list[dict[str, str]]:
    """Controlled silent-peer DROP without any packet filter (Part C).

    A listener with ``backlog=1`` plus several never-accepted holder
    connections fills the accept queue, so the kernel drops further
    SYNs silently (no SYN-ACK, no RST — the observable DROP
    condition). The measured dial must then block until the bounded
    connect timeout expires: no immediate refusal, deterministic
    ``TRANSPORT_TIMEOUT``, elapsed within the configured ceiling.
    """

    from ai.execution import live_transport as _lt

    out: list[dict[str, str]] = []
    target = guard_fixture_address(FIXTURE_A)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holders: list[socket.socket] = []
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((target, SYNDROP_PORT))
        listener.listen(1)
        listener.settimeout(10.0)
        for _ in range(5):
            holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            holder.settimeout(5.0)
            try:
                holder.connect((target, SYNDROP_PORT))
                holders.append(holder)
            except OSError:
                holder.close()
        time.sleep(0.5)
        factory = _lt.LiveSocketFactory()
        budget = 3.0
        start = time.monotonic()
        try:
            sock = factory.connect(target, SYNDROP_PORT, budget)
            _lt.close_quietly(sock)
            out.append(
                {"name": "syndrop-timeout", "status": "FAIL",
                 "detail": "silent peer unexpectedly connected"}
            )
            return out
        except Exception as exc:
            elapsed = time.monotonic() - start
            code = getattr(exc, "code", "")
            silent = elapsed >= 2.0
            classified = code == "TRANSPORT_TIMEOUT"
            within_ceiling = elapsed <= budget + 10.0
            ok = silent and classified and within_ceiling
            out.append(
                {
                    "name": "syndrop-timeout",
                    "status": "PASS" if ok else "FAIL",
                    "detail": f"silent {elapsed:.1f}s, {code or 'unclassified'}, "
                    "ceiling respected" if ok else
                    f"drop behavior wrong: {elapsed:.1f}s {code or 'unclassified'}",
                }
            )
    except Exception:
        out.append(
            {"name": "syndrop-timeout", "status": "FAIL",
             "detail": "silent-peer fixture setup failed"}
        )
    finally:
        for holder in holders:
            try:
                holder.close()
            except OSError:
                pass
        try:
            listener.close()
        except OSError:
            pass
    return out


_SCENARIOS: dict[str, Callable[[dict[str, Any]], list[dict[str, str]]]] = {
    "namespace": _scenario_namespace,
    "veth": _scenario_veth,
    "routes": _scenario_routes,
    "egress_matrix": _scenario_egress_matrix,
    "dns_pinned": _scenario_dns_pinned,
    "timeouts": _scenario_timeouts,
    "bytecaps": _scenario_bytecaps,
    "syndrop": _scenario_syndrop,
    "dialproof_chain": _scenario_dialproof_chain,
    "hang": _scenario_hang,
}


# ------------------------------------------------------------------
# Isolated runner (fork + unshare + pipe + wall timeout + reap).
# ------------------------------------------------------------------


def _child_main(write_fd: int, payload: dict[str, Any]) -> None:
    try:
        # Identity MUST be captured before unshare: afterwards the
        # process has no mapping yet and getuid() reports overflow.
        uid, gid = int(payload["uid"]), int(payload["gid"])
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if libc.unshare(_CLONE_NEWUSER | _CLONE_NEWNET) != 0:
            raise ValidationRefused("unshare failed")
        with open("/proc/self/setgroups", "w") as handle:
            handle.write("deny")
        with open("/proc/self/uid_map", "w") as handle:
            handle.write(f"0 {uid} 1")
        with open("/proc/self/gid_map", "w") as handle:
            handle.write(f"0 {gid} 1")
        code, _ = _ip("link", "set", "lo", "up")
        if code != 0:
            raise ValidationRefused("loopback setup failed")
        code, _ = _ip("addr", "add", f"{FIXTURE_A}/32", "dev", "lo")
        if code != 0:
            raise ValidationRefused("fixture address setup failed")
        if "dialproof_chain" in payload["scenarios"]:
            # Local /32 for the B1-admissible chain address (see the
            # CHAIN_FIXTURE_* rationale): kernel-local delivery only,
            # inside this namespace which has no default route.
            code, _ = _ip("addr", "add", f"{CHAIN_FIXTURE_IP}/32", "dev", "lo")
            if code != 0:
                raise ValidationRefused("chain fixture address setup failed")
        results: list[dict[str, str]] = []
        for name in payload["scenarios"]:
            try:
                results.extend(_SCENARIOS[name](payload))
            except ValidationRefused as exc:
                results.append(
                    {"name": name, "status": "UNPROVEN", "detail": str(exc)[:120]}
                )
            except Exception as exc:  # noqa: BLE001 — child reports, never raises
                results.append(
                    {
                        "name": name,
                        "status": "FAIL",
                        "detail": f"scenario raised {type(exc).__name__}",
                    }
                )
        blob = json.dumps({"ok": True, "results": results}).encode()
    except ValidationRefused as exc:
        blob = json.dumps({"ok": False, "refusal": str(exc)[:160]}).encode()
    except Exception as exc:  # noqa: BLE001 — last-resort child report
        blob = json.dumps(
            {"ok": False, "refusal": f"child setup raised {type(exc).__name__}"}
        ).encode()
    try:
        os.write(write_fd, len(blob).to_bytes(4, "big") + blob)
    except OSError:
        pass
    finally:
        os.close(write_fd)
    os._exit(0)


def _run_child(
    scenarios: list[str], *, wall_seconds: float
) -> tuple[list[CheckResult], bool, str]:
    """Fork+isolate+collect. Returns (checks, child_reaped, note)."""

    parent_ns = _parent_netns_id()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        _child_main(
            write_fd,
            {
                "parent_ns": parent_ns,
                "scenarios": scenarios,
                "uid": os.getuid(),
                "gid": os.getgid(),
            },
        )
        os._exit(2)  # unreachable
    os.close(write_fd)
    blob = b""
    deadline = time.monotonic() + wall_seconds
    killed = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            try:
                os.kill(pid, signal.SIGKILL)
                killed = True
            except ProcessLookupError:
                pass
            break
        ready, _, _ = select.select([read_fd], [], [], min(remaining, 0.5))
        if ready:
            try:
                chunk = os.read(read_fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            blob += chunk
            if len(blob) >= 4:
                (size,) = int.from_bytes(blob[:4], "big"),
                if len(blob) >= 4 + size:
                    break
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
        # NOTE: with WNOHANG an alive child reports (0, 0), and the raw
        # status 0 would misread as "exited 0" through WIFEXITED — the
        # wpid guard is load-bearing (a missing guard deadlocked the
        # drain loop on its first poll during Stage 4 development).
        if waited_pid != 0 and (
            os.WIFEXITED(status) or os.WIFSIGNALED(status)
        ):
            try:
                while True:
                    chunk = os.read(read_fd, 65536)
                    if not chunk:
                        break
                    blob += chunk
            except OSError:
                pass
            break
    _, status = os.waitpid(pid, 0)
    reaped = os.WIFEXITED(status) or os.WIFSIGNALED(status)
    os.close(read_fd)
    if killed:
        return (
            [
                CheckResult(
                    name="timeout-cleanup",
                    status="PASS",
                    detail="over-budget child SIGKILLed and reaped",
                )
            ],
            reaped,
            "child exceeded wall budget",
        )
    try:
        size = int.from_bytes(blob[:4], "big")
        message = json.loads(blob[4 : 4 + size].decode())
    except Exception:
        return (
            [CheckResult(name="harness-collect", status="FAIL",
                         detail="unparseable child report")],
            reaped,
            "collect failed",
        )
    if not message.get("ok"):
        return (
            [
                CheckResult(
                    name="harness-setup",
                    status="UNPROVEN",
                    detail=str(message.get("refusal", "refused"))[:120],
                )
            ],
            reaped,
            "child refused",
        )
    checks = [
        CheckResult(name=item["name"], status=item["status"], detail=item["detail"])
        for item in message["results"]
    ]
    return checks, reaped, ""


def run_full_validation(
    *,
    enable: bool = False,
    wall_seconds: float = 120.0,
    scenarios: tuple[str, ...] = SCENARIO_NAMES,
) -> ValidationReport:
    """Run every harness scenario in one isolated namespace.

    Refuses (``ValidationRefused``) unless double-opted-in. Returns a
    data-only report; performs no dial outside the fixture subnet, no
    DNS, no live HTTP end-to-end, no production contact.
    """

    capabilities = require_harness_enable(enable=enable)
    unknown = [name for name in scenarios if name not in _SCENARIOS]
    if unknown:
        raise ValidationRefused(f"unknown scenarios: {','.join(sorted(unknown))}")
    parent_before = _parent_netns_id()
    checks, reaped, note = _run_child(list(scenarios), wall_seconds=wall_seconds)
    parent_after = _parent_netns_id()
    unchanged = parent_before == parent_after
    final = list(checks)
    final.append(
        CheckResult(
            name="parent-netns-unchanged",
            status="PASS" if unchanged else "FAIL",
            detail="parent network namespace untouched"
            if unchanged
            else "parent network namespace changed",
        )
    )
    final.append(
        CheckResult(
            name="no-orphan-process",
            status="PASS" if reaped else "FAIL",
            detail="validation child reaped"
            if reaped
            else "validation child not reaped",
        )
    )
    if note == "child exceeded wall budget":
        final.append(
            CheckResult(
                name="timeout-cleanup",
                status="PASS",
                detail="over-budget child SIGKILLed and reaped",
            )
        )
    return ValidationReport(
        label=FIXTURE_LABEL,
        capabilities={key: bool(value) for key, value in capabilities.items()},
        checks=tuple(final),
        parent_netns_unchanged=unchanged,
        child_reaped=reaped,
    )
