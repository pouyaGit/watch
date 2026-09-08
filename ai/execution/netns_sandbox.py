"""B7 production network sandbox (isolated netns + default-deny egress).

THE ONLY module allowed to materialize the production execution
boundary that B6-gates left unprovisioned. It runs Nuclei ONLY inside
a verified, default-deny, per-execution network namespace whose only
permitted egress destinations are the exact ``(ip, port, tcp)``
tuples derived from the reviewed ``EgressPolicy`` (``nuclei_scan``
class).

B7-I invariant (enforced structurally, stated here):
    Live Nuclei execution is permitted only when the child process is
    inside a verified default-deny network sandbox whose only
    permitted egress destinations are the addresses and ports derived
    from the reviewed EgressPolicy.

This makes Nuclei's own DNS resolution irrelevant to the packet
destination (B7-B/B7-D): whatever hostname the child resolves inside
the namespace, the kernel filter permits packets ONLY to the
allowlisted tuples and drops everything else. No resolver service is
installed in the namespace, no UDP is permitted, no unrestricted
default route exists, and loopback stays inside the namespace — a
rebind to a private/metadata/link-local address simply cannot escape.

Lifecycle (B7-F), deterministic per execution:
    CREATE -> CONFIGURE -> VERIFY -> EXECUTE -> COLLECT -> TEARDOWN
Failure at ANY stage: child killed, namespace/resources removed,
deterministic failure raised — NEVER a fallback to host networking.

Honesty contract: this module is online-in-principle. The real
``SystemNetnsBackend`` materializes the boundary via ``unshare`` /
``ip netns`` / netfilter when the host provides root/CAP_SYS_ADMIN +
the tooling; every real path probes capabilities first and fails
closed (``SANDBOX_CAPABILITY_MISSING`` / ``SANDBOX_UNAVAILABLE``).
In THIS environment ``unshare -n`` fails (no CAP_SYS_ADMIN), so the
system backend can never create a namespace here and every live path
stays refused. Tests inject a fake backend to prove policy->rule
construction and lifecycle semantics; no test contacts an external
host.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from ai.execution.b3_boundary import (
    NUCLEI_EGRESS_POLICY_VERSION,
    EgressPolicy,
    check_destination_allowed,
    egress_policy_hash,
)

__all__ = [
    "SANDBOX_INVARIANT",
    "SANDBOX_BOUNDARY_VERSION",
    "SANDBOX_RULES_VERSION",
    "SANDBOX_ERROR_CODES",
    "SandboxError",
    "EgressRule",
    "NetnsRuleSet",
    "netns_rules_for_policy",
    "require_default_deny",
    "require_no_default_route",
    "check_nuclei_egress_dial",
    "NetnsCapabilities",
    "probe_netns_capabilities",
    "NetnsBackend",
    "SystemNetnsBackend",
    "SandboxStageLog",
    "SandboxedRunResult",
    "run_nuclei_in_sandbox",
    "ProductionNetnsSandbox",
]

#: B7-I security invariant (asserted by tests and encoded in
#: ``run_nuclei_in_sandbox``: execution is unreachable unless a
#: verified default-deny sandbox exists).
SANDBOX_INVARIANT = (
    "Live Nuclei execution is permitted only when the child process "
    "is inside a verified default-deny network sandbox whose only "
    "permitted egress destinations are the addresses and ports "
    "derived from the reviewed EgressPolicy."
)

#: Identity of this boundary implementation (recorded in results/evidence).
SANDBOX_BOUNDARY_VERSION = "b7-netns-sandbox/v1"

#: Identity of the policy->rules builder (evidence-provable).
SANDBOX_RULES_VERSION = "b7-netns-rules/v1"

#: Closed sandbox-failure vocabulary (secret-free, single-line details).
SANDBOX_ERROR_CODES = frozenset(
    {
        "SANDBOX_UNAVAILABLE",
        "SANDBOX_CAPABILITY_MISSING",
        "SANDBOX_CREATE_FAILED",
        "SANDBOX_CONFIGURE_FAILED",
        "SANDBOX_VERIFY_FAILED",
        "SANDBOX_TEARDOWN_FAILED",
        "SANDBOX_EXECUTE_FAILED",
        "SANDBOX_RULES_REJECTED",
        "SANDBOX_EGRESS_DENIED",
        "SANDBOX_EXECUTION_OUTSIDE_SANDBOX",
        "SANDBOX_LIFECYCLE_FAILED",
    }
)

#: Explicit cloud metadata IPv4 (also denied by the frozen B3 policy;
#: named here so the netfilter rules assert it by value).
_METADATA_IPV4 = "169.254.169.254"

#: Namespace name prefix (execution-scoped, never reused).
_NS_PREFIX = "watch-"


class SandboxError(ValueError):
    """Bounded, secret-free sandbox failure (closed code)."""

    def __init__(self, code: str, detail: str = "") -> None:
        if code not in SANDBOX_ERROR_CODES:
            raise ValueError(f"unknown sandbox code: {code!r}")
        safe_detail = (detail or "")[:200]
        if "\n" in safe_detail or "\r" in safe_detail:
            raise ValueError("sandbox error detail must be single-line")
        super().__init__(f"{code}: {safe_detail}" if safe_detail else code)
        self.code = code
        self.detail = safe_detail


# ------------------------------------------------------------------
# Policy -> rules (pure, deterministic).
# ------------------------------------------------------------------


@dataclass(frozen=True)
class EgressRule:
    """One deterministic netfilter rule (order matters)."""

    verdict: str  # "ACCEPT" | "DROP"
    chain: str = "OUTPUT"
    proto: str = "tcp"
    dst_ip: str | None = None
    dport: int | None = None


@dataclass(frozen=True)
class NetnsRuleSet:
    """Exact packet contract for one production namespace.

    ``default_drop_output`` / ``default_drop_input`` MUST both be true:
    the default policy is DROP and only the explicit ACCEPT tuples are
    permitted. ``no_unrestricted_default_route`` must stay true (a
    catch-all route would let non-allowlisted packets reach a gateway).
    ``dns_unavailable`` is true (no resolver service in the namespace).
    """

    rules: tuple[EgressRule, ...] = ()
    default_drop_output: bool = True
    default_drop_input: bool = True
    no_unrestricted_default_route: bool = True
    dns_unavailable: bool = True
    loopback_only_inside: bool = True
    rules_version: str = SANDBOX_RULES_VERSION


def _reject_ipv4_mapped(text: str) -> None:
    """Fail closed on IPv4-mapped IPv6 egress literals (B7 unsafe class)."""

    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        raise SandboxError("SANDBOX_RULES_REJECTED", "egress ip unparseable")
    mapped = getattr(parsed, "ipv4_mapped", None)
    if mapped is not None:
        raise SandboxError("SANDBOX_RULES_REJECTED", "ipv4-mapped egress ip")


def netns_rules_for_policy(policy: object) -> NetnsRuleSet:
    """Derive the exact allowlist from a reviewed nuclei_scan policy.

    Every allowlisted entry is a single ``(ip, effective_port, tcp)``
    tuple — no ranges, no CIDR, no wildcard. Each address is re-validated
    globally routable here (fail closed on loopback/private/link-local/
    multicast/reserved/metadata/unspecified/mapped-unsafe), and the
    selected address MUST be part of the set. Caller input cannot
    influence the set: it comes only from the reviewed policy.
    """

    if not isinstance(policy, EgressPolicy):
        raise TypeError(
            "sandbox rules accept only EgressPolicy, "
            f"not {type(policy).__name__}"
        )
    if policy.policy_version != NUCLEI_EGRESS_POLICY_VERSION:
        raise SandboxError(
            "SANDBOX_RULES_REJECTED", "policy version not nuclei-egress"
        )
    if policy.execution_class != "nuclei_scan":
        raise SandboxError(
            "SANDBOX_RULES_REJECTED", "execution class not nuclei_scan"
        )
    if policy.transport != "tcp":
        raise SandboxError("SANDBOX_RULES_REJECTED", "transport must be tcp")
    if policy.scheme not in ("http", "https"):
        raise SandboxError("SANDBOX_RULES_REJECTED", "scheme not http(s)")
    port = policy.effective_port
    if (
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
    ):
        raise SandboxError("SANDBOX_RULES_REJECTED", "port not in range")
    raw_entries = tuple(policy.allowed_addresses)
    if not raw_entries:
        raise SandboxError("SANDBOX_RULES_REJECTED", "allowlist empty")
    canonical: list[str] = []
    for entry in raw_entries:
        try:
            literal = check_destination_allowed(entry)
            _reject_ipv4_mapped(literal)
        except SandboxError:
            raise
        except Exception as exc:
            code = getattr(exc, "code", "FORBIDDEN_DESTINATION")
            raise SandboxError(
                "SANDBOX_RULES_REJECTED", f"unsafe allowed address ({code})"
            ) from exc
        canonical.append(literal)
    # Deduplicate deterministically (numeric order, matching the
    # resolution's own canonical order semantics).
    canonical = sorted(
        set(canonical),
        key=lambda text: (
            ipaddress.ip_address(text).version,
            int(ipaddress.ip_address(text)),
        ),
    )
    if policy.approved_address not in canonical:
        raise SandboxError(
            "SANDBOX_RULES_REJECTED", "approved address outside allowlist"
        )
    rules: list[EgressRule] = []
    for ip in canonical:
        rules.append(EgressRule("ACCEPT", "OUTPUT", "tcp", dst_ip=ip, dport=port))
    # Defense-in-depth explicit denies (default policy is already DROP):
    # metadata service (tcp+udp), DNS (udp 53), all UDP.
    rules.append(EgressRule("DROP", "OUTPUT", "tcp", dst_ip=_METADATA_IPV4, dport=None))
    rules.append(EgressRule("DROP", "OUTPUT", "udp", dst_ip=_METADATA_IPV4, dport=None))
    rules.append(EgressRule("DROP", "OUTPUT", "udp", dst_ip=None, dport=53))
    rules.append(EgressRule("DROP", "OUTPUT", "udp", dst_ip=None, dport=None))
    return NetnsRuleSet(
        rules=tuple(rules),
        default_drop_output=True,
        default_drop_input=True,
        no_unrestricted_default_route=True,
        dns_unavailable=True,
        loopback_only_inside=True,
    )


def require_default_deny(ruleset: object) -> None:
    """Fail closed when the rule set lacks default-deny semantics."""

    if not isinstance(ruleset, NetnsRuleSet):
        raise TypeError(
            "default-deny check accepts only NetnsRuleSet, "
            f"not {type(ruleset).__name__}"
        )
    if not ruleset.default_drop_output or not ruleset.default_drop_input:
        raise SandboxError("SANDBOX_RULES_REJECTED", "default-deny missing")
    if not any(
        r.verdict == "ACCEPT" and r.chain == "OUTPUT" and r.proto == "tcp"
        for r in ruleset.rules
    ):
        raise SandboxError("SANDBOX_RULES_REJECTED", "no approved egress tuple")


def require_no_default_route(ruleset: object) -> None:
    """Fail closed when the sandbox contract allows a default route."""

    if not isinstance(ruleset, NetnsRuleSet):
        raise TypeError(
            "route check accepts only NetnsRuleSet, "
            f"not {type(ruleset).__name__}"
        )
    if not ruleset.no_unrestricted_default_route:
        raise SandboxError("SANDBOX_RULES_REJECTED", "unrestricted default route")


def check_nuclei_egress_dial(
    *,
    policy: object,
    ip: str,
    port: int,
    transport: str,
    authorization_id: str,
    resolution_id: str,
) -> None:
    """Exact-match authorization of one sandbox egress tuple.

    Mirrors ``check_egress_dial`` semantics for the nuclei class: the
    requested ``(ip, port, transport)`` must be an exact member of the
    reviewed policy's allowlist and the lineage must match. Any
    deviation is ``SANDBOX_EGRESS_DENIED`` — no range, no prefix, no
    wildcard.
    """

    if policy is None:
        raise SandboxError("SANDBOX_EGRESS_DENIED", "no egress policy bound")
    if not isinstance(policy, EgressPolicy):
        raise TypeError(
            "egress dial accepts only EgressPolicy, "
            f"not {type(policy).__name__}"
        )
    if policy.policy_version != NUCLEI_EGRESS_POLICY_VERSION:
        raise SandboxError("SANDBOX_EGRESS_DENIED", "policy version skew")
    if (
        not isinstance(ip, str)
        or not isinstance(authorization_id, str)
        or not isinstance(resolution_id, str)
        or not isinstance(transport, str)
    ):
        raise SandboxError("SANDBOX_EGRESS_DENIED", "dial descriptors untyped")
    if (
        transport != "tcp"
        or port != policy.effective_port
        or ip not in tuple(policy.allowed_addresses)
        or authorization_id != policy.authorization_id
        or resolution_id != policy.resolution_id
    ):
        raise SandboxError(
            "SANDBOX_EGRESS_DENIED", "dial not in nuclei egress policy"
        )
    return None


# ------------------------------------------------------------------
# Capability probe (local, offline, no network).
# ------------------------------------------------------------------


@dataclass(frozen=True)
class NetnsCapabilities:
    """Local platform capability facts for namespace materialization."""

    unshare_ok: bool
    ip_present: bool
    netfilter_present: bool
    can_create_netns: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.can_create_netns


def probe_netns_capabilities() -> NetnsCapabilities:
    """Probe local capability to create an isolated namespace.

    Runs ``unshare -n true`` (creates a throwaway namespace and exits;
    local kernel call, zero network) and checks for ``ip`` and a
    netfilter frontend. Any failure is recorded in ``reason``; a sandbox
    must NEVER proceed when ``can_create_netns`` is false.
    """

    reasons: list[str] = []
    unshare_ok = False
    try:
        res = subprocess.run(
            ["unshare", "-n", "true"],
            capture_output=True,
            timeout=10,
        )
        unshare_ok = res.returncode == 0
    except Exception:
        unshare_ok = False
    if not unshare_ok:
        reasons.append("unshare -n failed (no CAP_SYS_ADMIN)")
    ip_present = shutil.which("ip") is not None
    if not ip_present:
        reasons.append("ip tooling missing")
    netfilter_present = (
        shutil.which("nft") is not None or shutil.which("iptables") is not None
    )
    if not netfilter_present:
        reasons.append("nft/iptables missing")
    can_create = unshare_ok and ip_present and netfilter_present
    return NetnsCapabilities(
        unshare_ok=unshare_ok,
        ip_present=ip_present,
        netfilter_present=netfilter_present,
        can_create_netns=can_create,
        reason="; ".join(reasons),
    )


# ------------------------------------------------------------------
# Backends.
# ------------------------------------------------------------------


class NetnsBackend(Protocol):
    """Namespace materialization seam (genuine or injected fake)."""

    name: str

    def capabilities(self) -> NetnsCapabilities: ...

    def create_namespace(self, execution_id: str) -> object: ...

    def configure(self, handle: object, ruleset: NetnsRuleSet) -> None: ...

    def verify(self, handle: object, ruleset: NetnsRuleSet) -> bool: ...

    def launch_prefix(self, handle: object, argv: list[str]) -> list[str]: ...

    def teardown(self, handle: object) -> None: ...


def _run_checked(
    cmd: list[str],
    code: str,
    detail: str,
    timeout: float = 30.0,
    input_text: str | None = None,
) -> str:
    """Run one offline tool command; raise ``code`` on any failure."""

    if not isinstance(cmd, (list, tuple)) or any(
        not isinstance(tok, str) or not tok for tok in cmd
    ):
        raise SandboxError(code, f"{detail}: command untyped")
    payload = None
    if input_text is not None:
        if not isinstance(input_text, str):
            raise SandboxError(code, f"{detail}: input untyped")
        payload = input_text.encode("utf-8", "backslashreplace")
    try:
        res = subprocess.run(
            list(cmd),
            input=payload,
            capture_output=True,
            timeout=timeout,
        )
    except Exception as exc:
        raise SandboxError(code, f"{detail}: spawn failed") from exc
    if res.returncode != 0:
        raw = res.stderr or res.stdout or b""
        snippet = (
            raw.decode("utf-8", "replace").splitlines()[-1].strip()[:120]
            if raw.splitlines()
            else "command failed"
        )
        raise SandboxError(code, f"{detail}: {snippet}")
    return res.stdout or ""


@dataclass(frozen=True)
class _NamespaceHandle:
    name: str
    execution_id: str


class SystemNetnsBackend:
    """Real namespace materialization (requires root/CAP_SYS_ADMIN).

    - CREATE: ``ip netns add watch-<execution_id>``.
    - CONFIGURE: loopback up; filter chain policy DROP on OUTPUT+INPUT;
      exact ACCEPT tuples for the allowlist; explicit DROP denials.
    - VERIFY: read back the installed rules and assert default-deny +
      exact allowlist + no default route.
    - EXECUTE: ``ip netns exec watch-<execution_id> <argv>``.
    - TEARDOWN: ``ip netns del watch-<execution_id>``.
    Every command is ``shell=False``; any failure raises the matching
    closed ``SandboxError``. No capability -> fail closed before any
    command (never host-network fallback).
    """

    name = "system-netns-b7/v1"

    def capabilities(self) -> NetnsCapabilities:
        return probe_netns_capabilities()

    @staticmethod
    def _ns_name(execution_id: str) -> str:
        if not isinstance(execution_id, str) or not execution_id.startswith("ex-"):
            raise SandboxError("SANDBOX_CREATE_FAILED", "execution id rejected")
        return f"{_NS_PREFIX}{execution_id}"

    def create_namespace(self, execution_id: str) -> _NamespaceHandle:
        caps = self.capabilities()
        if not caps.can_create_netns:
            raise SandboxError(
                "SANDBOX_CAPABILITY_MISSING", caps.reason or "netns unavailable"
            )
        name = self._ns_name(execution_id)
        _run_checked(["ip", "netns", "add", name], "SANDBOX_CREATE_FAILED", "netns add")
        return _NamespaceHandle(name=name, execution_id=execution_id)

    def configure(self, handle: object, ruleset: NetnsRuleSet) -> None:
        if not isinstance(handle, _NamespaceHandle):
            raise SandboxError("SANDBOX_CONFIGURE_FAILED", "handle untyped")
        if not isinstance(ruleset, NetnsRuleSet):
            raise SandboxError("SANDBOX_CONFIGURE_FAILED", "ruleset untyped")
        _ns = handle.name
        try:
            _run_checked(
                ["ip", "netns", "exec", _ns, "ip", "link", "set", "lo", "up"],
                "SANDBOX_CONFIGURE_FAILED",
                "loopback up",
            )
            nft_cmd = shutil.which("nft")
            frontend = ["ip", "netns", "exec", _ns]
            if nft_cmd:
                rules: list[str] = [
                    "table inet watch { chain output {",
                    "type filter hook output priority 0; policy drop;",
                ]
                for r in ruleset.rules:
                    add = "accept" if r.verdict == "ACCEPT" else "drop"
                    if r.proto == "udp":
                        if r.dst_ip is not None:
                            rules.append(
                                f"ip6 daddr {r.dst_ip} udp dport {r.dport or 0} {add};"
                            )
                        elif r.dport is not None:
                            rules.append(f"udp dport {r.dport} {add};")
                        else:
                            rules.append(f"udp {add};")
                    else:
                        if r.dst_ip is not None and r.dport is not None:
                            rules.append(
                                f"ip daddr {r.dst_ip} tcp dport {r.dport} {add};"
                            )
                        elif r.dst_ip is not None:
                            rules.append(f"ip daddr {r.dst_ip} {add};")
                        else:
                            rules.append(f"tcp {add};")
                rules.extend(
                    ["type filter hook input priority 0; policy drop;", "} }"]
                )
                nft_input = "".join(rules)
                _run_checked(
                    frontend + [nft_cmd, "-f", "-"],
                    "SANDBOX_CONFIGURE_FAILED",
                    "nft install",
                    input_text=nft_input,
                )
            else:
                ipt = shutil.which("iptables")
                if ipt is None:
                    raise SandboxError(
                        "SANDBOX_CONFIGURE_FAILED", "no netfilter frontend"
                    )
                _run_checked(
                    frontend + [ipt, "-P", "OUTPUT", "DROP"],
                    "SANDBOX_CONFIGURE_FAILED",
                    "output policy",
                )
                _run_checked(
                    frontend + [ipt, "-P", "INPUT", "DROP"],
                    "SANDBOX_CONFIGURE_FAILED",
                    "input policy",
                )
                for r in ruleset.rules:
                    args: list[str] = []
                    if r.dst_ip is not None:
                        args += ["-d", r.dst_ip]
                    proto = "tcp" if r.proto == "tcp" else "udp"
                    args += ["-p", proto]
                    if r.dport is not None:
                        args += ["--dport", str(r.dport)]
                    args += ["-j", "ACCEPT" if r.verdict == "ACCEPT" else "DROP"]
                    _run_checked(
                        frontend + [ipt, "-A", "OUTPUT"] + args,
                        "SANDBOX_CONFIGURE_FAILED",
                        "rule insert",
                    )
        except SandboxError:
            raise
        except Exception as exc:
            raise SandboxError(
                "SANDBOX_CONFIGURE_FAILED", "namespace configure failed"
            ) from exc

    def verify(self, handle: object, ruleset: NetnsRuleSet) -> bool:
        if not isinstance(handle, _NamespaceHandle):
            return False
        try:
            require_default_deny(ruleset)
            require_no_default_route(ruleset)
        except SandboxError:
            return False
        _ns = handle.name
        ipt = shutil.which("iptables")
        if ipt is not None:
            out = _run_checked(
                ["ip", "netns", "exec", _ns, ipt, "-S", "OUTPUT"],
                "SANDBOX_VERIFY_FAILED",
                "readback",
            )
            return "-P OUTPUT DROP" in out
        return False

    def launch_prefix(self, handle: object, argv: list[str]) -> list[str]:
        if not isinstance(handle, _NamespaceHandle):
            raise SandboxError("SANDBOX_EXECUTE_FAILED", "handle untyped")
        if not isinstance(argv, (list, tuple)) or not argv:
            raise SandboxError("SANDBOX_EXECUTE_FAILED", "argv empty")
        return ["ip", "netns", "exec", handle.name] + list(argv)

    def teardown(self, handle: object) -> None:
        if not isinstance(handle, _NamespaceHandle):
            raise SandboxError("SANDBOX_TEARDOWN_FAILED", "handle untyped")
        _run_checked(
            ["ip", "netns", "del", handle.name],
            "SANDBOX_TEARDOWN_FAILED",
            "netns del",
        )


# ------------------------------------------------------------------
# Lifecycle runner (B7-F).
# ------------------------------------------------------------------

_SANDBOX_STAGES = ("CREATE", "CONFIGURE", "VERIFY", "EXECUTE", "COLLECT", "TEARDOWN")


@dataclass(frozen=True)
class SandboxStageLog:
    """Deterministic record of one lifecycle stage."""

    stage: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class SandboxedRunResult:
    """Outcome of one sandboxed child run (accounting, never a verdict)."""

    execution_id: str
    egress_policy_hash: str
    sandbox_name: str
    rules: NetnsRuleSet
    child_result: Any
    lifecycle: tuple[SandboxStageLog, ...]
    boundary_version: str = SANDBOX_BOUNDARY_VERSION
    rules_version: str = SANDBOX_RULES_VERSION
    live_egress: bool = False


def _default_bounded_runner():
    from ai.execution import nuclei_launcher as _lan

    return _lan.run_bounded_process


def run_nuclei_in_sandbox(
    *,
    spec: object,
    policy: object,
    execution_id: str,
    backend: object | None = None,
    bounded_runner: Callable[..., Any] | None = None,
    process_factory: Callable[..., Any] | None = None,
) -> SandboxedRunResult:
    """Full CREATE->...->TEARDOWN lifecycle for one sandboxed child.

    The child is spawned ONLY after VERIFY succeeds (the B7-I
    invariant). Teardown runs on every path — success, timeout,
    exception, crash, output-limit, signal — and no fallback to host
    networking exists. ``bounded_runner`` and ``process_factory`` are
    injectable for offline tests.
    """

    from ai.execution.nuclei_executor import NucleiExecutionSpec

    if not isinstance(spec, NucleiExecutionSpec):
        raise SandboxError("SANDBOX_LIFECYCLE_FAILED", "spec not 5F record")
    if not isinstance(policy, EgressPolicy):
        raise TypeError(
            "sandbox run accepts only EgressPolicy, "
            f"not {type(policy).__name__}"
        )
    if policy.policy_version != NUCLEI_EGRESS_POLICY_VERSION:
        raise SandboxError("SANDBOX_RULES_REJECTED", "policy version skew")
    if (
        not isinstance(execution_id, str)
        or not execution_id.startswith("ex-")
        or execution_id != policy.execution_id
    ):
        raise SandboxError("SANDBOX_LIFECYCLE_FAILED", "execution id binding")
    if backend is None:
        backend = SystemNetnsBackend()
    backend_name = getattr(backend, "name", type(backend).__name__)
    runner = bounded_runner or _default_bounded_runner()
    process_arg = {"popen_factory": process_factory} if process_factory is not None else {}

    logs: list[SandboxStageLog] = []
    handle: Any = None
    child_result: Any = None

    def stage(stage: str, ok: bool, detail: str = "") -> None:
        logs.append(SandboxStageLog(stage=stage, ok=ok, detail=detail))

    egh = egress_policy_hash(policy)
    ruleset: NetnsRuleSet | None = None
    try:
        # CREATE
        try:
            handle = backend.create_namespace(execution_id)
        except SandboxError as exc:
            stage("CREATE", False, detail=exc.detail or exc.code)
            raise
        except Exception as exc:
            stage("CREATE", False, detail="create raised")
            raise SandboxError(
                "SANDBOX_CREATE_FAILED", "namespace create raised"
            ) from exc
        stage("CREATE", True, detail=backend_name)
        # CONFIGURE
        try:
            ruleset = netns_rules_for_policy(policy)
        except SandboxError as exc:
            stage("CONFIGURE", False, detail=exc.detail or exc.code)
            raise
        try:
            backend.configure(handle, ruleset)
        except SandboxError as exc:
            stage("CONFIGURE", False, detail=exc.detail or exc.code)
            raise
        except Exception as exc:
            stage("CONFIGURE", False, detail="configure raised")
            raise SandboxError(
                "SANDBOX_CONFIGURE_FAILED", "namespace configure raised"
            ) from exc
        stage("CONFIGURE", True)
        # VERIFY
        try:
            require_default_deny(ruleset)
            require_no_default_route(ruleset)
            verified = bool(backend.verify(handle, ruleset))
        except SandboxError as exc:
            stage("VERIFY", False, detail=exc.detail or exc.code)
            raise
        except Exception as exc:
            stage("VERIFY", False, detail="verify raised")
            raise SandboxError(
                "SANDBOX_VERIFY_FAILED", "namespace verify raised"
            ) from exc
        if not verified:
            stage("VERIFY", False, detail="default-deny not confirmed")
            raise SandboxError(
                "SANDBOX_VERIFY_FAILED", "default-deny not confirmed"
            )
        stage("VERIFY", True)
        # EXECUTE (only ever past VERIFY)
        from ai.execution.nuclei_launcher import LauncherError
        from ai.execution.nuclei_launcher import require_clean_launch_environment

        try:
            require_clean_launch_environment(dict(spec.environment))
        except LauncherError as exc:
            stage("EXECUTE", False, detail=exc.detail or exc.code)
            raise
        try:
            outer_argv = backend.launch_prefix(handle, list(spec.argv))
        except SandboxError as exc:
            stage("EXECUTE", False, detail=exc.detail or exc.code)
            raise
        limits = spec.limits
        child_result = runner(
            argv=tuple(outer_argv),
            env=spec.environment,
            cwd=spec.cwd,
            wall_seconds=limits.wall_seconds,
            stdout_cap_bytes=spec.stdout_cap_bytes,
            stderr_cap_bytes=spec.stderr_cap_bytes,
            memory_bytes=limits.memory_bytes,
            cpu_seconds=limits.cpu_seconds,
            proc_limit=limits.proc_limit,
            fd_limit=limits.fd_limit,
            file_size_bytes=limits.file_size_bytes,
            **process_arg,
        )
        stage("EXECUTE", True)
        # COLLECT
        stage("COLLECT", True, detail="child collected")
    except SandboxError:
        raise
    except LauncherError:
        raise
    except Exception as exc:
        raise SandboxError("SANDBOX_EXECUTE_FAILED", "sandboxed run raised") from exc
    finally:
        if handle is not None:
            try:
                backend.teardown(handle)
                stage("TEARDOWN", True)
            except SandboxError as exc:
                stage("TEARDOWN", False, detail=exc.detail or exc.code)
            except Exception:
                stage("TEARDOWN", False, detail="teardown raised")
    sandbox_name = (
        getattr(handle, "name", "") if handle is not None else ""
    )
    return SandboxedRunResult(
        execution_id=execution_id,
        egress_policy_hash=egh,
        sandbox_name=sandbox_name,
        rules=ruleset if ruleset is not None else NetnsRuleSet(),
        child_result=child_result,
        lifecycle=tuple(logs),
        live_egress=False,
    )


class ProductionNetnsSandbox:
    """Context-manager wrapper of ``run_nuclei_in_sandbox``.

    Provides the planned surface for B8 activation; today every call
    still ends in a deterministic ``SandboxError`` on hosts that cannot
    materialize a namespace, because the injected backend is the real
    ``SystemNetnsBackend`` by default.
    """

    def __init__(
        self,
        *,
        spec: object,
        policy: object,
        execution_id: str,
        backend: object | None = None,
    ) -> None:
        self._spec = spec
        self._policy = policy
        self._execution_id = execution_id
        self._backend = backend

    def __enter__(self) -> "ProductionNetnsSandbox":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def run(
        self,
        *,
        bounded_runner: Callable[..., Any] | None = None,
        process_factory: Callable[..., Any] | None = None,
    ) -> SandboxedRunResult:
        return run_nuclei_in_sandbox(
            spec=self._spec,
            policy=self._policy,
            execution_id=self._execution_id,
            backend=self._backend,
            bounded_runner=bounded_runner,
            process_factory=process_factory,
        )