"""Phase 5K-live B6 remediation tests (offline only).

Deterministic stdlib ``unittest``. No live execution, no network, no
DNS, no Nuclei subprocess, no browser, no LLM, no Mongo. Sockets never
leave the process: peer-proof tests use stub ``LiveSocketFactory`` /
``LiveTlsWrapper`` subclasses (``isinstance``-admitted, behavior
overridden); process tests use an injected popen factory. Genuine
5B/5C/5D/B3 records come from the reviewed fixtures in
``ai.test_b1_dial_policy`` (same reuse pattern as
``ai.test_b3_boundary``).

Covers the 16 B6-G cases:
 1. wrong Nuclei version -> fail closed
 2. missing Nuclei binary -> fail closed
 3. argv contains retries=0
 4. forbidden proxy environment -> fail closed
 5. safe address set -> accepted
 6. mixed safe/unsafe addresses -> rejected
 7. empty address set -> rejected
 8. peer IP outside authorized set -> rejected
 9. peer IP inside authorized set -> accepted
10. hostname re-resolution cannot bypass pinned address
11. TLS hostname/SNI remains canonical
12. redirect cannot produce second destination
13. retry cannot produce second request
14. output ceiling enforced
15. subprocess timeout enforced
16. sandbox setup failure -> fail closed
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
import unittest
from unittest import mock

from ai.execution import nuclei_launcher as launcher
from ai.execution import pinned_peer as peer
from ai.execution.b3_boundary import build_egress_policy
from ai.execution.dial_proof import DialProof
from ai.execution.live_transport import (
    LiveSocketFactory,
    LiveTlsWrapper,
    LiveTransportError,
    require_ip_literal,
)
from ai.execution.nuclei_executor import (
    ExecutorError,
    argv_digest_for,
    assert_frozen_argv_supported,
    build_nuclei_argv,
    build_nuclei_environment,
    check_nuclei_runtime,
    default_resource_limits,
    require_pinned_nuclei_version,
    NucleiExecutionSpec,
)
from ai.live_validation import ControlledLiveValidationLane
from ai.resolver.dns import FakeDnsResolver, validate_answers
from ai.test_b1_dial_policy import (
    EX_ID,
    HOST,
    IP_A,
    IP_B,
    NOW,
    make_authz,
    make_hop_resolver,
    packet_entry,
)

TARGET = "https://example.com"
LANE_HOST = "example.com"
PINNED_VERSION_LINE = "[INF] Nuclei Engine Version: v3.11.1"


def _env_live():
    return mock.patch.dict(
        os.environ, {"WATCH_AI_LIVE_VALIDATION": "true"}, clear=False
    )


def _bindings(addresses=(IP_A,), *, scheme="https", port=443):
    authz = make_authz(scheme=scheme, port=port)
    table = {HOST: packet_entry([(a, 60) for a in addresses])}
    resolver, _ = make_hop_resolver(table)
    resolution, evaluation = resolver.resolve_initial(
        authorization=authz, execution_id=EX_ID, now=NOW
    )
    return authz, resolution, evaluation


def _policy(authz, resolution, evaluation, address=IP_A):
    return build_egress_policy(
        authorization=authz,
        resolution=resolution,
        evaluation=evaluation,
        selected_address=address,
        now=NOW,
    )


# ------------------------------------------------------------------
# Stub transport (offline peer-proof doubles)
# ------------------------------------------------------------------


class StubSocket:
    """In-process socket double (no file descriptor, no network)."""

    def __init__(self, peer_ip: str, local=("192.0.2.7", 54321)) -> None:
        self._peer_ip = peer_ip
        self._local = local
        self.closed = False

    def getpeername(self):
        return (self._peer_ip, 443)

    def getsockname(self):
        return self._local

    def settimeout(self, timeout) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class StubTlsSocket:
    """Post-handshake double (peer identity delegates inward)."""

    def __init__(self, inner: StubSocket) -> None:
        self._inner = inner
        self.closed = False

    def getpeername(self):
        return self._inner.getpeername()

    def version(self):
        return "TLSv1.3"

    def getpeercert(self, binary_form=False):
        if binary_form:
            return b"fake-der-certificate-bytes"
        return {}

    def settimeout(self, timeout) -> None:
        return None

    def close(self) -> None:
        self.closed = True
        self._inner.close()


class StubFactory(LiveSocketFactory):
    """Reviewed-factory subclass: literal-only dial, stub peer."""

    def __init__(self, peer_ip: str) -> None:
        super().__init__()
        self._peer_ip = peer_ip
        self.calls: list[tuple[str, int]] = []

    def connect(self, ip_literal: str, port: int, timeout: float):
        dial_ip = require_ip_literal(ip_literal)
        if not isinstance(port, int) or isinstance(port, bool):
            raise LiveTransportError("DIAL_BINDING_MISMATCH", "port rejected")
        self.calls.append((dial_ip, port))
        sock = StubSocket(self._peer_ip)
        self._issued.add(sock)
        self._ids[sock] = "conn-" + "ab" * 16
        return sock


class StubTls(LiveTlsWrapper):
    """Reviewed-wrapper subclass: SNI guard mirrored, no handshake."""

    def __init__(self) -> None:
        super().__init__()
        self.sni_seen: list[str] = []

    def wrap(self, raw_sock: object, *, sni_host: str, timeout: float):
        try:
            ipaddress.ip_address(sni_host)
        except ValueError:
            pass
        else:
            raise LiveTransportError("TLS_MISMATCH", "sni must not be an ip")
        self.sni_seen.append(sni_host)
        if isinstance(raw_sock, StubTlsSocket):
            raise LiveTransportError(
                "CONNECTION_REUSE_VIOLATION", "socket already wrapped"
            )
        return StubTlsSocket(raw_sock)  # type: ignore[arg-type]


class ForeignFactory:
    """Duck-typed impostor (must be refused: not a reviewed adapter)."""

    transport_version = "b1-live-transport/v1"

    def connect(self, ip_literal, port, timeout):
        raise AssertionError("impostor must never be called")

    def connection_id_for(self, sock):
        return None


# ------------------------------------------------------------------
# Stub process (offline launcher doubles)
# ------------------------------------------------------------------


class FakeProc:
    def __init__(
        self, *, stdout=b"", stderr=b"", returncode=0, hang=False
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self._hang = hang
        self.killed = False
        self.waited = False

    def communicate(self, timeout=None):
        if self._hang:
            raise subprocess.TimeoutExpired("nuclei", timeout)
        return (self._stdout, self._stderr)

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout=None):
        self.waited = True
        return self.returncode


def _popen_factory(proc: FakeProc, seen: dict):
    def _factory(argv, **kwargs):
        seen["argv"] = list(argv)
        seen["kwargs"] = kwargs
        assert kwargs.get("stdin") == subprocess.DEVNULL
        return proc

    return _factory


# ------------------------------------------------------------------
# B6-G 1-2: version contract
# ------------------------------------------------------------------


class VersionContractTests(unittest.TestCase):
    def test_wrong_version_fails_closed(self) -> None:
        with self.assertRaises(ExecutorError) as ctx:
            require_pinned_nuclei_version(
                "[INF] Nuclei Engine Version: v3.10.0"
            )
        self.assertEqual(ctx.exception.code, "NUCLEI_RUNTIME_UNSUPPORTED")

    def test_newer_version_fails_closed(self) -> None:
        with self.assertRaises(ExecutorError):
            require_pinned_nuclei_version(
                "[INF] Nuclei Engine Version: v9.99.9"
            )

    def test_indeterminable_version_fails_closed(self) -> None:
        for bad in ("", "v3.11.1", "nuclei", None, 12345):
            with self.assertRaises(ExecutorError):
                require_pinned_nuclei_version(bad)

    def test_missing_binary_fails_closed(self) -> None:
        with self.assertRaises(launcher.LauncherError) as ctx:
            launcher.check_nuclei_binary("/nonexistent/path/nuclei")
        self.assertEqual(ctx.exception.code, "BINARY_MISSING")
        with self.assertRaises(ExecutorError) as ctx2:
            check_nuclei_runtime(binary_present=False, version_output="x")
        self.assertEqual(ctx2.exception.code, "NUCLEI_RUNTIME_UNSUPPORTED")

    def test_pinned_version_accepted(self) -> None:
        self.assertEqual(
            require_pinned_nuclei_version(PINNED_VERSION_LINE), "v3.11.1"
        )
        self.assertEqual(
            check_nuclei_runtime(
                binary_present=True, version_output=PINNED_VERSION_LINE
            ),
            "v3.11.1",
        )

    def test_caller_cannot_choose_version(self) -> None:
        # The pin is a module constant; no parameter, env var, or
        # artifact influences it.
        import ai.execution.nuclei_executor as nx

        self.assertEqual(nx.PINNED_NUCLEI_VERSION, "v3.11.1")
        with self.assertRaises(ExecutorError):
            require_pinned_nuclei_version(
                "[INF] Nuclei Engine Version: latest"
            )


# ------------------------------------------------------------------
# B6-G 3/12/13: frozen argv bounds
# ------------------------------------------------------------------


class FrozenArgvTests(unittest.TestCase):
    def _argv(self):
        return list(
            build_nuclei_argv(
                template_path=(
                    "/srv/watch/scratch/nuclei/"
                    "ex-cccccccccccccccccccccccccccccccc/t.json"
                ),
                target_string="https://example.com",
            )
        )

    def test_argv_contains_retries_zero(self) -> None:
        argv = self._argv()
        self.assertEqual(argv[argv.index("-retries") + 1], "0")

    def test_redirect_cannot_produce_second_destination(self) -> None:
        argv = self._argv()
        self.assertIn("-disable-redirects", argv)
        for forbidden in (
            "-follow-redirects",
            "-fr",
            "-follow-host-redirects",
            "-fhr",
            "-max-redirects",
            "-mr",
            "-no-redirects",
        ):
            self.assertNotIn(forbidden, argv)
        self.assertEqual(argv.count("-u"), 1)
        launcher.assert_single_target_argv(argv)

    def test_retry_cannot_produce_second_request(self) -> None:
        argv = self._argv()
        self.assertEqual(argv[argv.index("-retries") + 1], "0")
        self.assertEqual(argv[argv.index("-concurrency") + 1], "1")
        self.assertEqual(argv[argv.index("-bulk-size") + 1], "1")
        self.assertEqual(argv.count("-t"), 1)

    def test_unsupported_flag_rejected(self) -> None:
        argv = self._argv()
        bad = list(argv) + ["-no-redirects"]
        with self.assertRaises(ExecutorError):
            assert_frozen_argv_supported(bad)
        bad2 = list(argv)
        bad2[bad2.index("-retries") + 1] = "3"
        with self.assertRaises(ExecutorError):
            assert_frozen_argv_supported(bad2)

    def test_string_command_rejected_no_shell(self) -> None:
        with self.assertRaises(launcher.LauncherError):
            launcher.run_bounded_process(
                argv="/usr/bin/nuclei -u https://example.com",  # type: ignore[arg-type]
                env=(),
                cwd="/srv/watch/scratch/nuclei",
                wall_seconds=5,
                stdout_cap_bytes=16,
                stderr_cap_bytes=16,
                memory_bytes=1024,
                cpu_seconds=1,
                proc_limit=1,
                fd_limit=8,
                file_size_bytes=1024,
            )


# ------------------------------------------------------------------
# B6-G 4: environment boundary
# ------------------------------------------------------------------


class EnvironmentBoundaryTests(unittest.TestCase):
    CLEAN = {"PATH": "/usr/bin:/bin", "HOME": "/tmp/x", "LANG": "C.UTF-8"}

    def test_clean_environment_passes(self) -> None:
        self.assertIsNone(
            launcher.require_clean_launch_environment(dict(self.CLEAN))
        )

    def test_forbidden_proxy_environment_fails_closed(self) -> None:
        for var in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ):
            with self.assertRaises(launcher.LauncherError) as ctx:
                launcher.require_clean_launch_environment(
                    {"PATH": "/usr/bin", var: "http://proxy:8080"}
                )
            self.assertEqual(ctx.exception.code, "PROXY_DETECTED")

    def test_empty_proxy_value_still_fails(self) -> None:
        with self.assertRaises(launcher.LauncherError):
            launcher.require_clean_launch_environment(
                {"PATH": "/usr/bin", "HTTP_PROXY": ""}
            )

    def test_resolver_ca_variables_fail_closed(self) -> None:
        for var in (
            "HOSTALIASES",
            "LOCALDOMAIN",
            "RES_OPTIONS",
            "GODEBUG",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
        ):
            with self.assertRaises(launcher.LauncherError) as ctx:
                launcher.require_clean_launch_environment(
                    {"PATH": "/usr/bin", var: "x"}
                )
            self.assertEqual(ctx.exception.code, "FORBIDDEN_ENVIRONMENT")

    def test_child_env_is_allowlist_only(self) -> None:
        env = build_nuclei_environment(
            scratch_dir="/srv/watch/scratch/nuclei/ex-" + "c" * 32
        )
        names = {name for name, _ in env}
        self.assertEqual(
            names, {"HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"}
        )
        # The allowlist itself passes the launch gate.
        launcher.require_clean_launch_environment(dict(env))


# ------------------------------------------------------------------
# B6-G 5/6/7: resolution boundary (+ ceiling, ordering, provenance)
# ------------------------------------------------------------------


class ResolutionBoundaryTests(unittest.TestCase):
    def test_safe_address_set_accepted(self) -> None:
        lane = ControlledLiveValidationLane(
            resolver=FakeDnsResolver(mapping={LANE_HOST: ["8.8.8.8"]})
        )
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "DRY_RUN_NOT_PERFORMED")

    def test_mixed_safe_unsafe_rejected(self) -> None:
        lane = ControlledLiveValidationLane(
            resolver=FakeDnsResolver(
                mapping={LANE_HOST: ["8.8.8.8", "127.0.0.1"]}
            )
        )
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))

    def test_empty_address_set_rejected(self) -> None:
        lane = ControlledLiveValidationLane(
            resolver=FakeDnsResolver(mapping={LANE_HOST: []})
        )
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))

    def test_over_ceiling_answer_set_rejected(self) -> None:
        addrs = [f"203.0.{i // 250}.{1 + (i % 250)}" for i in range(9)]
        with self.assertRaises(Exception):
            validate_answers(addrs)

    def test_deterministic_ordering(self) -> None:
        ordered = validate_answers(["8.8.4.4", "8.8.8.8", "1.1.1.1"])
        self.assertEqual(tuple(ordered), ("1.1.1.1", "8.8.4.4", "8.8.8.8"))

    def test_resolver_provenance_stamped(self) -> None:
        lane = ControlledLiveValidationLane(
            resolver=FakeDnsResolver(mapping={LANE_HOST: ["8.8.8.8"]})
        )
        addresses, source = lane._resolve_addresses(LANE_HOST)
        self.assertEqual(tuple(addresses), ("8.8.8.8",))
        self.assertEqual(source, "fake-dns/v1")

    def test_live_without_resolver_blocked(self) -> None:
        with _env_live():
            lane = ControlledLiveValidationLane()
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "LIVE_RESOLVER_REQUIRED")


# ------------------------------------------------------------------
# B6-G 8/9/10/11: pinned peer proof
# ------------------------------------------------------------------


class PinnedPeerTests(unittest.TestCase):
    def test_peer_inside_authorized_set_accepted(self) -> None:
        authz, resolution, evaluation = _bindings((IP_A,))
        policy = _policy(authz, resolution, evaluation, IP_A)
        factory, tls = StubFactory(IP_A), StubTls()
        proof = peer.prove_pinned_peer(
            policy=policy,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authz.authorization_id,
            socket_factory=factory,
            tls_wrapper=tls,
        )
        self.assertIsInstance(proof, DialProof)
        self.assertEqual(proof.actual_peer_ip, IP_A)
        self.assertEqual(proof.selected_address, IP_A)
        self.assertEqual(factory.calls, [(IP_A, 443)])

    def test_peer_outside_authorized_set_rejected(self) -> None:
        authz, resolution, evaluation = _bindings((IP_A,))
        policy = _policy(authz, resolution, evaluation, IP_A)
        factory, tls = StubFactory(IP_B), StubTls()
        with self.assertRaises(peer.PinnedPeerError) as ctx:
            peer.prove_pinned_peer(
                policy=policy,
                resolution=resolution,
                evaluation=evaluation,
                authorization_id=authz.authorization_id,
                socket_factory=factory,
                tls_wrapper=tls,
            )
        self.assertEqual(ctx.exception.code, "PEER_MISMATCH")

    def test_hostname_reresolution_cannot_bypass_pin(self) -> None:
        factory = StubFactory(IP_A)
        # A hostname can never reach the wire: literal gate first.
        with self.assertRaises(LiveTransportError):
            factory.connect(HOST, 443, 5.0)
        with self.assertRaises(LiveTransportError):
            require_ip_literal("authorized.example.com")
        self.assertEqual(factory.calls, [])

    def test_tls_sni_remains_canonical(self) -> None:
        authz, resolution, evaluation = _bindings((IP_A,))
        policy = _policy(authz, resolution, evaluation, IP_A)
        factory, tls = StubFactory(IP_A), StubTls()
        proof = peer.prove_pinned_peer(
            policy=policy,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authz.authorization_id,
            socket_factory=factory,
            tls_wrapper=tls,
        )
        self.assertEqual(tls.sni_seen, [HOST])
        self.assertEqual(proof.tls_sni, HOST)
        # SNI is the canonical hostname, never the dialed IP.
        self.assertNotEqual(proof.tls_sni, IP_A)

    def test_foreign_adapter_refused(self) -> None:
        authz, resolution, evaluation = _bindings((IP_A,))
        policy = _policy(authz, resolution, evaluation, IP_A)
        with self.assertRaises(peer.PinnedPeerError) as ctx:
            peer.prove_pinned_peer(
                policy=policy,
                resolution=resolution,
                evaluation=evaluation,
                authorization_id=authz.authorization_id,
                socket_factory=ForeignFactory(),
                tls_wrapper=StubTls(),
            )
        self.assertEqual(ctx.exception.code, "FOREIGN_TRANSPORT_ADAPTER")

    def test_wrong_authorization_refused(self) -> None:
        authz, resolution, evaluation = _bindings((IP_A,))
        policy = _policy(authz, resolution, evaluation, IP_A)
        with self.assertRaises(peer.PinnedPeerError):
            peer.prove_pinned_peer(
                policy=policy,
                resolution=resolution,
                evaluation=evaluation,
                authorization_id="authz-" + "0" * 16,
                socket_factory=StubFactory(IP_A),
                tls_wrapper=StubTls(),
            )

    def test_http_scheme_plaintext_proof(self) -> None:
        # Genuine http EgressPolicy (http_probe class, http scheme):
        # no TLS is performed; SNI intent stays pinned to the
        # canonical host and no handshake may migrate the peer.
        from ai.test_nuclei_executor import (
            NOW as NX_NOW,
            make_authz as make_nx_authz,
            make_evaluation as make_nx_evaluation,
            make_resolution as make_nx_resolution,
        )
        from ai.test_nuclei_executor import EX_ID as NX_EX_ID

        authz = make_nx_authz(
            scheme="http", port=80, execution_class="http_probe"
        )
        resolution = make_nx_resolution(
            authz, NX_EX_ID, scheme="http", port=80
        )
        evaluation = make_nx_evaluation(authz, resolution, NX_EX_ID)
        policy = build_egress_policy(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            selected_address=IP_A,
            now=NX_NOW,
        )
        self.assertEqual(policy.scheme, "http")
        factory, tls = StubFactory(IP_A), StubTls()
        proof = peer.prove_pinned_peer(
            policy=policy,
            resolution=resolution,
            evaluation=evaluation,
            authorization_id=authz.authorization_id,
            socket_factory=factory,
            tls_wrapper=tls,
        )
        self.assertEqual(proof.actual_peer_ip, IP_A)
        self.assertEqual(proof.tls_sni, "authorized.example.com")
        self.assertEqual(tls.sni_seen, [])
        self.assertEqual(factory.calls, [(IP_A, 80)])

    def test_nuclei_class_policy_shaped_for_sandbox(self) -> None:
        # B7-A: build_egress_policy now admits the nuclei_scan class
        # with a narrowly scoped policy shape (the exact input the B7
        # netns sandbox derives its default-deny allowlist from): the
        # B7 nuclei-egress policy identity + canonical_target_hash +
        # artifact identity/hash + the validated address set bound.
        from ai.test_nuclei_executor import (
            EX_ID as NX_EX_ID,
            make_authz as make_nx_authz,
            make_evaluation as make_nx_evaluation,
            make_resolution as make_nx_resolution,
        )
        from ai.execution.b3_boundary import NUCLEI_EGRESS_POLICY_VERSION

        authz = make_nx_authz()
        self.assertEqual(authz.execution_class, "nuclei_scan")
        resolution = make_nx_resolution(authz, NX_EX_ID)
        evaluation = make_nx_evaluation(authz, resolution, NX_EX_ID)
        policy = build_egress_policy(
            authorization=authz,
            resolution=resolution,
            evaluation=evaluation,
            selected_address=IP_A,
            now=NOW,
        )
        self.assertEqual(policy.execution_class, "nuclei_scan")
        self.assertEqual(policy.policy_version, NUCLEI_EGRESS_POLICY_VERSION)
        self.assertEqual(policy.canonical_target_hash, resolution.canonical_target_hash)
        self.assertEqual(policy.artifact_id, authz.artifact.artifact_id)
        self.assertEqual(policy.transport, "tcp")
        self.assertTrue(IP_A in tuple(policy.allowed_addresses))


# ------------------------------------------------------------------
# B6-G 14/15/16: bounded process + sandbox gate
# ------------------------------------------------------------------


class BoundedProcessTests(unittest.TestCase):
    BASE = {
        "argv": ("/usr/bin/nuclei", "-version"),
        "env": (("PATH", "/usr/bin:/bin"),),
        "cwd": "/tmp",
        "wall_seconds": 30,
        "stdout_cap_bytes": 64,
        "stderr_cap_bytes": 64,
        "memory_bytes": 512 * 1024 * 1024,
        "cpu_seconds": 60,
        "proc_limit": 1,
        "fd_limit": 64,
        "file_size_bytes": 16 * 1024 * 1024,
    }

    def test_output_ceiling_enforced(self) -> None:
        proc = FakeProc(stdout=b"x" * 65, stderr=b"")
        seen: dict = {}
        with self.assertRaises(launcher.LauncherError) as ctx:
            launcher.run_bounded_process(
                **dict(self.BASE, popen_factory=_popen_factory(proc, seen))
            )
        self.assertEqual(ctx.exception.code, "SUBPROCESS_OUTPUT_LIMIT")

    def test_output_within_cap_passes(self) -> None:
        proc = FakeProc(stdout=b"ok", stderr=b"", returncode=0)
        seen: dict = {}
        result = launcher.run_bounded_process(
            **dict(self.BASE, popen_factory=_popen_factory(proc, seen))
        )
        self.assertEqual(result.stdout, b"ok")
        self.assertFalse(result.timed_out)
        self.assertEqual(seen["argv"], ["/usr/bin/nuclei", "-version"])
        self.assertIsInstance(result.applied_limits, launcher.AppliedLimits)

    def test_subprocess_timeout_enforced(self) -> None:
        proc = FakeProc(hang=True)
        seen: dict = {}
        with self.assertRaises(launcher.LauncherError) as ctx:
            launcher.run_bounded_process(
                **dict(self.BASE, popen_factory=_popen_factory(proc, seen))
            )
        self.assertEqual(ctx.exception.code, "SUBPROCESS_TIMEOUT")
        self.assertTrue(proc.killed)
        self.assertTrue(proc.waited)

    def test_sandbox_setup_failure_fails_closed(self) -> None:
        with self.assertRaises(launcher.LauncherError) as ctx:
            launcher.require_production_sandbox(
                policy=None, execution_id=EX_ID, now=NOW
            )
        self.assertEqual(ctx.exception.code, "SANDBOX_UNAVAILABLE")

    def test_dry_run_blocked_sandbox_refused(self) -> None:
        authz, resolution, evaluation = _bindings((IP_A,))
        policy = _policy(authz, resolution, evaluation, IP_A)
        with self.assertRaises(launcher.LauncherError) as ctx:
            launcher.require_production_sandbox(
                policy=policy, execution_id=EX_ID, now=NOW
            )
        self.assertEqual(ctx.exception.code, "SANDBOX_UNAVAILABLE")

    def test_full_launch_refuses_live_egress(self) -> None:
        limits = default_resource_limits()
        argv = tuple(
            build_nuclei_argv(
                template_path=(
                    "/srv/watch/scratch/nuclei/" + EX_ID + "/abcd1234abcd1234.json"
                ),
                target_string="https://example.com",
            )
        )
        spec = NucleiExecutionSpec(
            execution_id=EX_ID,
            authorization_id="authz-" + "1" * 16,
            program_name="explicit:example.com",
            canonical_host="example.com",
            scheme="https",
            effective_port=443,
            target_string="https://example.com",
            artifact_id="artifact-" + "2" * 16,
            template_id="CVE-2026-1557",
            template_hash="f" * 64,
            argv=argv,
            argv_digest=argv_digest_for(argv),
            cwd="/srv/watch/scratch/nuclei/" + EX_ID,
            environment=build_nuclei_environment(
                scratch_dir="/srv/watch/scratch/nuclei/" + EX_ID
            ),
            stdin_policy="closed",
            stdout_cap_bytes=limits.stdout_cap_bytes,
            stderr_cap_bytes=limits.stderr_cap_bytes,
            limits=limits,
        )
        with self.assertRaises(launcher.LauncherError) as ctx:
            with mock.patch.object(
                launcher,
                "check_nuclei_binary",
                return_value="/usr/bin/nuclei",
            ):
                launcher.launch_nuclei_bounded(
                    spec=spec,
                    env_snapshot={"PATH": "/usr/bin:/bin"},
                    version_reader=lambda: PINNED_VERSION_LINE,
                )
        # The sandbox gate (not provisioned) refuses before any spawn.
        self.assertEqual(ctx.exception.code, "SANDBOX_UNAVAILABLE")
        self.assertFalse(launcher.LIVE_LAUNCH_ENABLED)


if __name__ == "__main__":
    unittest.main()
