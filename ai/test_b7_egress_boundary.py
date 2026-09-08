"""Phase 5K-live B7: production egress boundary tests (offline only).

Deterministic stdlib ``unittest``. No live execution, no network, no
DNS, no browser, no LLM, no Mongo, and no host-Netfilter changes: the
namespace materializer is a local fake backend, and process tests use
an injected popen factory. Every policy/rule check runs against
genuine 5B/5C/5D/EgressPolicy records built from the reviewed
fixtures in ``ai.test_nuclei_executor`` (same reuse pattern as the
B3/B6 suites).

Covers the B7-G/B7-H boundary contract:
 1. nuclei_scan admitted under the B7 nuclei-egress policy identity
 2. non-admitted execution class still fails closed
 3. caller-supplied approved IP outside the resolution is rejected
 4. address not in the reviewed resolution set is rejected
 5. egress dial port mismatch fails closed
 6. egress dial UDP transport fails closed
 7. private address fails closed
 8. loopback address fails closed
 9. metadata-169.254.169.254 address fails closed
10. empty resolution fails closed
11. mixed safe/unsafe resolution fails closed
12. IPv4-mapped egress literal fails closed
13. namespace create/configure failure fails closed (with teardown)
14. default-deny semantics are mandatory
15. only the approved (ip,port,tcp) rule is accepted
16. unrestricted default route is never allowed
17. host-network fallback is impossible
18. proxy environment is rejected before any spawn
19. DNS cannot leave the sandbox (no udp/53 egress)
20. teardown runs after a successful run
21. teardown runs after a child timeout
22. teardown runs after a child exception
23. the child can never run outside the sandbox prefix
24. the frozen argv is preserved inside the namespace
25. version mismatch still refuses launch
26. retries stay zero in the sandboxed argv
27. exactly one target in the sandboxed argv
28. exactly one template in the sandboxed argv
29. resource ceilings are passed to the bounded runner
30. live egress stays disabled (master switch + non-provisionable host)
"""

from __future__ import annotations

import ipaddress
import unittest
from dataclasses import replace
from unittest import mock

from ai.execution import nuclei_launcher as launcher
from ai.execution.b3_boundary import (
    B3BoundaryError,
    NUCLEI_EGRESS_POLICY_VERSION,
    build_egress_policy,
    check_egress_dial,
)
from ai.execution.netns_sandbox import (
    NetnsCapabilities,
    NetnsRuleSet,
    SandboxError,
    SandboxedRunResult,
    check_nuclei_egress_dial,
    netns_rules_for_policy,
    probe_netns_capabilities,
    require_default_deny,
    require_no_default_route,
    run_nuclei_in_sandbox,
)
from ai.execution.nuclei_executor import (
    NucleiExecutionSpec,
    argv_digest_for,
    build_nuclei_argv,
    build_nuclei_environment,
    default_resource_limits,
)
from ai.test_b1_dial_policy import IP_A, IP_B, NOW
from ai.test_b6_remediation import FakeProc, _popen_factory
from ai.test_nuclei_executor import (
    EX_ID as NX_EX_ID,
    make_authz as make_nx_authz,
    make_evaluation as make_nx_evaluation,
    make_resolution as make_nx_resolution,
)

PINNED = "[INF] Nuclei Engine Version: v3.11.1"

_METADATA = "169.254.169.254"


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


def _nuclei_bindings(addresses=(IP_A,), *, scheme="https", port=443):
    authz = make_nx_authz(scheme=scheme, port=port)
    resolution = make_nx_resolution(
        authz, NX_EX_ID, addresses=addresses, scheme=scheme, port=port
    )
    evaluation = make_nx_evaluation(authz, resolution, NX_EX_ID)
    return authz, resolution, evaluation


def _nuclei_policy(authz, resolution, evaluation, address=IP_A):
    return build_egress_policy(
        authorization=authz,
        resolution=resolution,
        evaluation=evaluation,
        selected_address=address,
        now=NOW,
    )


def _spec(environment=None):
    limits = default_resource_limits()
    argv = tuple(
        build_nuclei_argv(
            template_path=(
                "/srv/watch/scratch/nuclei/" + NX_EX_ID + "/t.json"
            ),
            target_string="https://authorized.example.com",
        )
    )
    env = environment if environment is not None else build_nuclei_environment(
        scratch_dir="/srv/watch/scratch/nuclei/" + NX_EX_ID
    )
    return NucleiExecutionSpec(
        execution_id=NX_EX_ID,
        authorization_id="authz-" + "1" * 16,
        program_name="explicit:authorized.example.com",
        canonical_host="authorized.example.com",
        scheme="https",
        effective_port=443,
        target_string="https://authorized.example.com",
        artifact_id="artifact-" + "2" * 16,
        template_id="CVE-2026-1557",
        template_hash="f" * 64,
        argv=argv,
        argv_digest=argv_digest_for(argv),
        cwd="/srv/watch/scratch/nuclei/" + NX_EX_ID,
        environment=env,
        stdin_policy="closed",
        stdout_cap_bytes=limits.stdout_cap_bytes,
        stderr_cap_bytes=limits.stderr_cap_bytes,
        limits=limits,
    )


class FakeHandle:
    def __init__(self, execution_id: str) -> None:
        self.name = "ns-" + execution_id


class FakeBackend:
    """In-process namespace materializer (never touches the kernel)."""

    name = "fake-netns-b7/v1"

    def __init__(self, *, can_create=True, fail_stage=None) -> None:
        self.can_create = can_create
        self.fail_stage = fail_stage
        self.created: list[str] = []
        self.configured: list[NetnsRuleSet] = []
        self.verified: list[str] = []
        self.prefixed: list[list[str]] = []
        self.torn: list[str] = []

    def capabilities(self) -> NetnsCapabilities:
        return NetnsCapabilities(
            unshare_ok=self.can_create,
            ip_present=True,
            netfilter_present=True,
            can_create_netns=self.can_create,
            reason="" if self.can_create else "fake: cannot create",
        )

    def create_namespace(self, execution_id: str) -> FakeHandle:
        self.created.append(execution_id)
        if not self.can_create:
            raise SandboxError(
                "SANDBOX_CAPABILITY_MISSING", "fake: cannot create"
            )
        if self.fail_stage == "create":
            raise SandboxError("SANDBOX_CREATE_FAILED", "fake create failed")
        return FakeHandle(execution_id)

    def configure(self, handle: object, ruleset: NetnsRuleSet) -> None:
        self.configured.append(ruleset)
        if self.fail_stage == "configure":
            raise SandboxError("SANDBOX_CONFIGURE_FAILED", "fake configure failed")

    def verify(self, handle: object, ruleset: NetnsRuleSet) -> bool:
        if self.fail_stage == "verify":
            return False
        self.verified.append(getattr(handle, "name", ""))
        return True

    def launch_prefix(self, handle: object, argv: list[str]) -> list[str]:
        self.prefixed.append(list(argv))
        name = getattr(handle, "name", handle)
        return ["ip", "netns", "exec", name] + list(argv)

    def teardown(self, handle: object) -> None:
        self.torn.append(getattr(handle, "name", ""))


def _spy_runner(records: list, *, result=None, error=None):
    def _runner(**kwargs):
        records.append(kwargs)
        if error is not None:
            raise error
        if result is not None:
            return result
        return launcher.BoundedProcessResult(
            exit_code=0,
            stdout=b"{}",
            stderr=b"",
            timed_out=False,
            killed=False,
            applied_limits=launcher.AppliedLimits((), ()),
        )

    return _runner


# ------------------------------------------------------------------
# B7-A: policy admission / shapes
# ------------------------------------------------------------------


class PolicyAdmissionTests(unittest.TestCase):
    def test_nuclei_scan_admitted_under_b7_policy_identity(self) -> None:
        authz, resolution, evaluation = _nuclei_bindings()
        policy = _nuclei_policy(authz, resolution, evaluation)
        self.assertEqual(policy.execution_class, "nuclei_scan")
        self.assertEqual(policy.policy_version, NUCLEI_EGRESS_POLICY_VERSION)
        self.assertEqual(policy.transport, "tcp")
        self.assertEqual(policy.approved_address, IP_A)
        self.assertEqual(policy.effective_port, 443)
        self.assertEqual(
            policy.canonical_target_hash, resolution.canonical_target_hash
        )
        self.assertEqual(policy.artifact_id, authz.artifact.artifact_id)
        self.assertEqual(policy.artifact_hash, authz.artifact.content_hash)
        self.assertEqual(tuple(policy.allowed_addresses), (IP_A,))
        self.assertEqual(policy.execution_id, NX_EX_ID)

    def test_non_admitted_execution_class_still_forbidden(self) -> None:
        authz = make_nx_authz(execution_class="http_verification")
        resolution = make_nx_resolution(authz, NX_EX_ID)
        evaluation = make_nx_evaluation(authz, resolution, NX_EX_ID)
        with self.assertRaises(B3BoundaryError) as ctx:
            build_egress_policy(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                selected_address=IP_A,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "FORBIDDEN_EXECUTION_CLASS")

    def test_caller_supplied_ip_outside_resolution_rejected(self) -> None:
        # Only IP_A was resolved; the caller asks for IP_B -> fail closed.
        authz, resolution, evaluation = _nuclei_bindings((IP_A,))
        with self.assertRaises(B3BoundaryError) as ctx:
            build_egress_policy(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                selected_address=IP_B,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "DIAL_BINDING_MISMATCH")

    def test_address_not_in_reviewed_set_rejected(self) -> None:
        # Only IP_A was resolved and selected; a dial for IP_B (never
        # in the reviewed set) is refused even at the B3 dial gate.
        authz, resolution, evaluation = _nuclei_bindings((IP_A,))
        policy = _nuclei_policy(authz, resolution, evaluation)
        with self.assertRaises(B3BoundaryError) as ctx:
            check_egress_dial(
                dial_ip=IP_B,
                dial_port=443,
                dial_scheme="https",
                policy=policy,
                authorization_id=policy.authorization_id,
                resolution_id=policy.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_empty_resolution_rejected(self) -> None:
        authz, resolution, evaluation = _nuclei_bindings()
        policy = _nuclei_policy(authz, resolution, evaluation)
        # A policy whose allowlist is empty can never produce a rule.
        tampered = replace(policy, allowed_addresses=())
        with self.assertRaises(SandboxError) as ctx:
            netns_rules_for_policy(tampered)
        self.assertEqual(ctx.exception.code, "SANDBOX_RULES_REJECTED")

    def test_mixed_safe_unsafe_resolution_rejected(self) -> None:
        # The reviewed scope layer already DENIES an unsafe-address
        # resolution (UNSAFE_ADDRESS); no policy can be built from it.
        authz = make_nx_authz()
        resolution = make_nx_resolution(authz, NX_EX_ID, addresses=(IP_A, "127.0.0.1"))
        evaluation = make_nx_evaluation(authz, resolution, NX_EX_ID, expect=None)
        with self.assertRaises(B3BoundaryError) as ctx:
            build_egress_policy(
                authorization=authz,
                resolution=resolution,
                evaluation=evaluation,
                selected_address=IP_A,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_private_address_fails_closed_at_sandbox_layer(self) -> None:
        authz, resolution, evaluation = _nuclei_bindings()
        policy = _nuclei_policy(authz, resolution, evaluation)
        tampered = replace(policy, allowed_addresses=("10.0.0.1",))
        with self.assertRaises(SandboxError) as ctx:
            netns_rules_for_policy(tampered)
        self.assertEqual(ctx.exception.code, "SANDBOX_RULES_REJECTED")

    def test_loopback_address_fails_closed_at_sandbox_layer(self) -> None:
        authz, resolution, evaluation = _nuclei_bindings()
        policy = _nuclei_policy(authz, resolution, evaluation)
        tampered = replace(policy, allowed_addresses=("127.0.0.1",))
        with self.assertRaises(SandboxError) as ctx:
            netns_rules_for_policy(tampered)
        self.assertEqual(ctx.exception.code, "SANDBOX_RULES_REJECTED")

    def test_metadata_address_fails_closed_at_sandbox_layer(self) -> None:
        authz, resolution, evaluation = _nuclei_bindings()
        policy = _nuclei_policy(authz, resolution, evaluation)
        tampered = replace(policy, allowed_addresses=(_METADATA,))
        with self.assertRaises(SandboxError) as ctx:
            netns_rules_for_policy(tampered)
        self.assertEqual(ctx.exception.code, "SANDBOX_RULES_REJECTED")


# ------------------------------------------------------------------
# B7-A/C: sandbox rule derivation + exact dial
# ------------------------------------------------------------------


class SandboxRuleTests(unittest.TestCase):
    def _policy(self, addresses=(IP_A,)):
        authz, resolution, evaluation = _nuclei_bindings(addresses)
        return _nuclei_policy(authz, resolution, evaluation)

    def test_only_approved_tuple_rule_generated(self) -> None:
        policy = self._policy((IP_A, IP_B))
        rules = netns_rules_for_policy(policy)
        accepts = [
            r for r in rules.rules if r.verdict == "ACCEPT" and r.chain == "OUTPUT"
        ]
        def _num(text: str) -> int:
            parsed = ipaddress.ip_address(text)
            return int(parsed)
        expected = sorted(
            [(IP_A, 443, "tcp"), (IP_B, 443, "tcp")],
            key=lambda t: _num(t[0]),
        )
        self.assertEqual(
            [(r.dst_ip, r.dport, r.proto) for r in accepts], expected
        )
        for r in accepts:
            self.assertEqual(r.dport, 443)
            self.assertEqual(r.proto, "tcp")
        self.assertFalse(any(r.dport is None for r in accepts))
        self.assertFalse(any(r.dport != 443 for r in accepts))

    def test_default_deny_mandatory_never_accept_only(self) -> None:
        policy = self._policy()
        rules = netns_rules_for_policy(policy)
        self.assertTrue(rules.default_drop_output)
        self.assertTrue(rules.default_drop_input)
        self.assertTrue(rules.loopback_only_inside)
        require_default_deny(rules)
        broken = NetnsRuleSet(rules=rules.rules, default_drop_output=False)
        with self.assertRaises(SandboxError) as ctx:
            require_default_deny(broken)
        self.assertEqual(ctx.exception.code, "SANDBOX_RULES_REJECTED")
        broken2 = NetnsRuleSet(rules=rules.rules, default_drop_input=False)
        with self.assertRaises(SandboxError):
            require_default_deny(broken2)

    def test_no_unrestricted_default_route(self) -> None:
        rules = netns_rules_for_policy(self._policy())
        self.assertTrue(rules.no_unrestricted_default_route)
        require_no_default_route(rules)
        broken = NetnsRuleSet(
            rules=rules.rules, no_unrestricted_default_route=False
        )
        with self.assertRaises(SandboxError) as ctx:
            require_no_default_route(broken)
        self.assertEqual(ctx.exception.code, "SANDBOX_RULES_REJECTED")

    def test_dns_cannot_leave_sandbox(self) -> None:
        rules = netns_rules_for_policy(self._policy())
        self.assertTrue(rules.dns_unavailable)
        self.assertTrue(any(r.proto == "udp" and r.dport == 53 for r in rules.rules))
        self.assertTrue(any(r.verdict == "DROP" and r.proto == "udp" for r in rules.rules))

    def test_metadata_denied_in_netfilter_by_value(self) -> None:
        rules = netns_rules_for_policy(self._policy())
        denied = [
            r for r in rules.rules
            if r.verdict == "DROP" and r.dst_ip == _METADATA
        ]
        self.assertTrue(denied)

    def test_port_mismatch_fails_closed(self) -> None:
        policy = self._policy()
        with self.assertRaises(SandboxError) as ctx:
            check_nuclei_egress_dial(
                policy=policy,
                ip=IP_A,
                port=8443,
                transport="tcp",
                authorization_id=policy.authorization_id,
                resolution_id=policy.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "SANDBOX_EGRESS_DENIED")

    def test_udp_transport_fails_closed(self) -> None:
        policy = self._policy()
        rules = netns_rules_for_policy(policy)
        self.assertFalse(any(r.proto == "udp" and r.verdict == "ACCEPT" for r in rules.rules))
        with self.assertRaises(SandboxError) as ctx:
            check_nuclei_egress_dial(
                policy=policy,
                ip=IP_A,
                port=53,
                transport="udp",
                authorization_id=policy.authorization_id,
                resolution_id=policy.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "SANDBOX_EGRESS_DENIED")

    def test_address_not_in_allowlist_fails_closed(self) -> None:
        policy = self._policy((IP_A,))
        with self.assertRaises(SandboxError) as ctx:
            check_nuclei_egress_dial(
                policy=policy,
                ip=IP_B,
                port=443,
                transport="tcp",
                authorization_id=policy.authorization_id,
                resolution_id=policy.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "SANDBOX_EGRESS_DENIED")

    def test_wrong_lineage_fails_closed(self) -> None:
        policy = self._policy()
        with self.assertRaises(SandboxError):
            check_nuclei_egress_dial(
                policy=policy,
                ip=IP_A,
                port=443,
                transport="tcp",
                authorization_id="authz-" + "0" * 16,
                resolution_id=policy.resolution_id,
            )

    def test_wrong_policy_class_fails_closed(self) -> None:
        policy = self._policy()
        # Same rules builder must refuse an http_probe-shaped policy.
        from ai.execution.b3_boundary import EgressPolicy

        probe = EgressPolicy(
            authorization_id=policy.authorization_id,
            execution_id=policy.execution_id,
            program_name=policy.program_name,
            canonical_host=policy.canonical_host,
            approved_address=IP_A,
            effective_port=443,
            scheme="https",
            scope_lists_hash=policy.scope_lists_hash,
            resolution_id=policy.resolution_id,
            evaluation_id=policy.evaluation_id,
            execution_class="http_probe",
            allowed_addresses=(IP_A,),
        )
        with self.assertRaises(SandboxError) as ctx:
            netns_rules_for_policy(probe)
        self.assertEqual(ctx.exception.code, "SANDBOX_RULES_REJECTED")

    def test_wrong_policy_version_fails_closed(self) -> None:
        policy = self._policy()
        from dataclasses import replace

        stale = replace(policy, policy_version="b3-egress-policy/v1")
        with self.assertRaises(SandboxError) as ctx:
            netns_rules_for_policy(stale)
        self.assertEqual(ctx.exception.code, "SANDBOX_RULES_REJECTED")

    def test_ipv4_mapped_egress_literal_fails_closed(self) -> None:
        authz, resolution, evaluation = _nuclei_bindings()
        policy = _nuclei_policy(authz, resolution, evaluation)
        # A mapped literal must never reach the netfilter allowlist.
        tampered = replace(policy, allowed_addresses=("::ffff:8.8.8.8",))
        with self.assertRaises(SandboxError) as ctx:
            netns_rules_for_policy(tampered)
        self.assertEqual(ctx.exception.code, "SANDBOX_RULES_REJECTED")


# ------------------------------------------------------------------
# B7-C/F: lifecycle fail-closed + teardown
# ------------------------------------------------------------------


class SandboxLifecycleTests(unittest.TestCase):
    def _run(self, backend=None, runner=None, *, environment=None,
             fail_stage=None, can_create=True):
        bind = _nuclei_bindings()
        policy = _nuclei_policy(*bind)
        spec = _spec(environment=environment)
        records: list = []
        backend = backend or FakeBackend(can_create=can_create, fail_stage=fail_stage)
        runner = runner or _spy_runner(records)
        result = run_nuclei_in_sandbox(
            spec=spec,
            policy=policy,
            execution_id=NX_EX_ID,
            backend=backend,
            bounded_runner=runner,
        )
        return result, backend, records, policy, spec

    def test_teardown_after_success(self) -> None:
        result, backend, records, _, _ = self._run()
        self.assertIsInstance(result, SandboxedRunResult)
        self.assertFalse(result.live_egress)
        self.assertEqual(backend.torn, ["ns-" + NX_EX_ID])
        self.assertEqual(backend.created, [NX_EX_ID])
        self.assertTrue(backend.verified)
        stages = {s.stage: s.ok for s in result.lifecycle}
        self.assertEqual(
            stages,
            {
                "CREATE": True,
                "CONFIGURE": True,
                "VERIFY": True,
                "EXECUTE": True,
                "COLLECT": True,
                "TEARDOWN": True,
            },
        )
        self.assertEqual(records[0]["argv"][0:4], ("ip", "netns", "exec", "ns-" + NX_EX_ID))

    def test_teardown_after_child_timeout(self) -> None:
        err = launcher.LauncherError("SUBPROCESS_TIMEOUT", "child wall deadline exceeded")
        backend = FakeBackend()
        with self.assertRaises(launcher.LauncherError) as ctx:
            self._run(backend=backend, runner=_spy_runner([], error=err))
        self.assertEqual(ctx.exception.code, "SUBPROCESS_TIMEOUT")
        self.assertEqual(backend.torn, ["ns-" + NX_EX_ID])

    def test_teardown_after_child_exception(self) -> None:
        backend = FakeBackend()
        with self.assertRaises(SandboxError) as ctx:
            self._run(backend=backend, runner=_spy_runner([], error=RuntimeError("boom")))
        self.assertEqual(ctx.exception.code, "SANDBOX_EXECUTE_FAILED")
        self.assertEqual(backend.torn, ["ns-" + NX_EX_ID])

    def test_namespace_create_failure_fails_closed(self) -> None:
        backend = FakeBackend(fail_stage="create")
        with self.assertRaises(SandboxError) as ctx:
            self._run(backend=backend)
        self.assertEqual(ctx.exception.code, "SANDBOX_CREATE_FAILED")
        self.assertEqual(backend.created, [NX_EX_ID])
        self.assertEqual(backend.torn, [])

    def test_namespace_configure_failure_fails_closed(self) -> None:
        backend = FakeBackend(fail_stage="configure")
        with self.assertRaises(SandboxError) as ctx:
            self._run(backend=backend)
        self.assertEqual(ctx.exception.code, "SANDBOX_CONFIGURE_FAILED")
        self.assertEqual(backend.torn, ["ns-" + NX_EX_ID])

    def test_namespace_verify_failure_fails_closed(self) -> None:
        backend = FakeBackend(fail_stage="verify")
        with self.assertRaises(SandboxError) as ctx:
            self._run(backend=backend)
        self.assertEqual(ctx.exception.code, "SANDBOX_VERIFY_FAILED")
        self.assertEqual(backend.torn, ["ns-" + NX_EX_ID])

    def test_capability_missing_fails_closed_no_host_fallback(self) -> None:
        backend = FakeBackend(can_create=False)
        records: list = []
        with self.assertRaises(SandboxError) as ctx:
            bind = _nuclei_bindings()
            policy = _nuclei_policy(*bind)
            run_nuclei_in_sandbox(
                spec=_spec(),
                policy=policy,
                execution_id=NX_EX_ID,
                backend=backend,
                bounded_runner=_spy_runner(records),
            )
        self.assertEqual(ctx.exception.code, "SANDBOX_CAPABILITY_MISSING")
        # No namespace was left behind and no child may ever spawn; no
        # host-network fallback exists.
        self.assertEqual(backend.created, [NX_EX_ID])
        self.assertEqual(backend.torn, [])
        self.assertEqual(records, [])

    def test_host_network_fallback_impossible(self) -> None:
        # The fake backend's launch_prefix is the ONLY way the child is
        # spawned; there is no path that calls runner with the raw
        # (non-prefixed) argv.
        result, backend, records, _, _ = self._run()
        for argv in records:
            self.assertEqual(argv["argv"][0:4], ("ip", "netns", "exec", "ns-" + NX_EX_ID))

    def test_child_cannot_run_outside_sandbox(self) -> None:
        _, backend, records, _, spec = self._run()
        frozen = list(spec.argv)
        for argv in records:
            self.assertEqual(list(argv["argv"]), ["ip", "netns", "exec", "ns-" + NX_EX_ID] + frozen)

    def test_frozen_argv_preserved_inside_namespace(self) -> None:
        _, _, records, _, spec = self._run()
        frozen = list(spec.argv)
        self.assertEqual(frozen[0], "/usr/bin/nuclei")
        self.assertIn("-disable-redirects", frozen)
        self.assertIn("-restrict-local-network-access", frozen)
        self.assertNotIn("-follow-redirects", frozen)
        for argv in records:
            self.assertEqual(list(argv["argv"])[4:], frozen)

    def test_retries_zero_target_one_template_one(self) -> None:
        _, _, records, _, spec = self._run()
        frozen = list(spec.argv)
        self.assertEqual(frozen[frozen.index("-retries") + 1], "0")
        self.assertEqual(frozen.count("-u"), 1)
        self.assertEqual(frozen.count("-t"), 1)
        for argv in records:
            inner = list(argv["argv"])[4:]
            self.assertEqual(inner[frozen.index("-retries") + 1], "0")

    def test_proxy_environment_rejected_before_spawn(self) -> None:
        bad_env = (("PATH", "/usr/bin:/bin"), ("HTTP_PROXY", "http://proxy:8080"))
        backend = FakeBackend()
        with self.assertRaises(launcher.LauncherError) as ctx:
            self._run(backend=backend, environment=bad_env)
        self.assertEqual(ctx.exception.code, "PROXY_DETECTED")
        # Child was never spawned, namespace was cleaned up.
        self.assertEqual(backend.prefixed, [])
        self.assertEqual(backend.torn, ["ns-" + NX_EX_ID])

    def test_resource_ceilings_passed_to_runner(self) -> None:
        _, _, records, _, spec = self._run()
        limits = spec.limits
        kwargs = records[0]
        self.assertEqual(kwargs["wall_seconds"], limits.wall_seconds)
        self.assertEqual(kwargs["memory_bytes"], limits.memory_bytes)
        self.assertEqual(kwargs["cpu_seconds"], limits.cpu_seconds)
        self.assertEqual(kwargs["proc_limit"], limits.proc_limit)
        self.assertEqual(kwargs["fd_limit"], limits.fd_limit)
        self.assertEqual(kwargs["file_size_bytes"], limits.file_size_bytes)
        self.assertEqual(kwargs["stdout_cap_bytes"], spec.stdout_cap_bytes)
        self.assertEqual(kwargs["stderr_cap_bytes"], spec.stderr_cap_bytes)
        self.assertEqual(kwargs["env"], spec.environment)
        self.assertEqual(kwargs["cwd"], spec.cwd)

    def test_real_bounded_runner_spawns_only_inside_namespace(self) -> None:
        cwd = "/srv/watch/scratch/nuclei/" + NX_EX_ID
        proc = FakeProc(stdout=b"{}", returncode=0)
        seen: dict = {}
        bind = _nuclei_bindings()
        policy = _nuclei_policy(*bind)
        records: list = []
        result = run_nuclei_in_sandbox(
            spec=_spec(),
            policy=policy,
            execution_id=NX_EX_ID,
            backend=FakeBackend(),
            bounded_runner=launcher.run_bounded_process,
            process_factory=_popen_factory(proc, seen),  # type: ignore[arg-type]
        )
        self.assertEqual(seen["argv"][0:4], ["ip", "netns", "exec", "ns-" + NX_EX_ID])
        self.assertEqual(seen["kwargs"].get("cwd"), cwd)
        self.assertEqual(result.child_result.exit_code, 0)
        self.assertEqual(
            [s.stage for s in result.lifecycle if s.ok],
            ["CREATE", "CONFIGURE", "VERIFY", "EXECUTE", "COLLECT", "TEARDOWN"],
        )

    def test_capability_probe_is_consistent(self) -> None:
        caps = probe_netns_capabilities()
        self.assertIsInstance(caps, NetnsCapabilities)
        self.assertEqual(bool(caps), caps.can_create_netns)


# ------------------------------------------------------------------
# B7-J: live egress stays DISABLED
# ------------------------------------------------------------------


class LiveEgressDisabledTests(unittest.TestCase):
    def test_master_switch_never_enabled(self) -> None:
        self.assertFalse(launcher.LIVE_LAUNCH_ENABLED)

    def test_launch_refuses_even_when_sandbox_provisionable(self) -> None:
        # Full gate chain with a fully-provisionable fake sandbox: the
        # master switch (B7-J) still refuses before any child spawns.
        authz, resolution, evaluation = _nuclei_bindings()
        policy = _nuclei_policy(authz, resolution, evaluation)
        spec = _spec()
        with self.assertRaises(launcher.LauncherError) as ctx:
            with mock.patch.object(
                launcher, "check_nuclei_binary", return_value="/usr/bin/nuclei"
            ):
                launcher.launch_nuclei_bounded(
                    spec=spec,
                    env_snapshot={"PATH": "/usr/bin:/bin"},
                    version_reader=lambda: PINNED,
                    egress_policy=policy,
                    backend=FakeBackend(can_create=True),
                )
        self.assertEqual(ctx.exception.code, "LIVE_LAUNCH_DISABLED")

    def test_version_mismatch_refuses_launch(self) -> None:
        spec = _spec()
        with self.assertRaises(launcher.LauncherError) as ctx:
            with mock.patch.object(
                launcher, "check_nuclei_binary", return_value="/usr/bin/nuclei"
            ):
                launcher.launch_nuclei_bounded(
                    spec=spec,
                    env_snapshot={"PATH": "/usr/bin:/bin"},
                    version_reader=lambda: "[INF] Nuclei Engine Version: v3.10.0",
                )
        self.assertEqual(ctx.exception.code, "VERSION_MISMATCH")


if __name__ == "__main__":
    unittest.main()