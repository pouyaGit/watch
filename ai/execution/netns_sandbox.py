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
    "render_nft_script",
    "check_nft_ruleset",
    "check_iptables_state",
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
# Firewall renderers (B8.1-A/D: deterministic, kernel-validated).
# ------------------------------------------------------------------

#: nft INPUT statements permitting ONLY return traffic of approved TCP
#: flows (B8.1-D). TCP-scoped on purpose: OUTPUT drops every
#: non-approved new flow, so no UDP (or other) flow can ever reach
#: ESTABLISHED state; scoping the allowance to TCP additionally removes
#: blind port-guess ingress against conntrack entries of dropped UDP
#: packets. Family matches are exact, so IPv4 and IPv6 need twin
#: statements (an ``ip protocol`` match never matches IPv6 and vice
#: versa). No inbound port is opened; no new inbound flow is admitted.
_NFT_ESTABLISHED_STATEMENTS = (
    "ct state established,related ip protocol tcp accept",
    "ct state established,related ip6 nexthdr tcp accept",
)

#: iptables/ip6tables INPUT allowance for the same contract (TCP-scoped).
_IPTABLES_ESTABLISHED_ARGS = [
    "-p",
    "tcp",
    "-m",
    "conntrack",
    "--ctstate",
    "ESTABLISHED,RELATED",
    "-j",
    "ACCEPT",
]
_IPTABLES_ESTABLISHED_LINE = "-A INPUT " + " ".join(_IPTABLES_ESTABLISHED_ARGS)


def _rule_family(dst_ip: str) -> str:
    """Return the nftables family match (``ip``/``ip6``) for a literal."""

    try:
        return "ip6" if ipaddress.ip_address(dst_ip).version == 6 else "ip"
    except ValueError:
        raise SandboxError(
            "SANDBOX_CONFIGURE_FAILED", "egress ip unparseable"
        ) from None


def _checked_port(dport: object) -> int:
    """Return a validated port, or fail closed (never render wildcards)."""

    if (
        not isinstance(dport, int)
        or isinstance(dport, bool)
        or not 1 <= dport <= 65535
    ):
        raise SandboxError("SANDBOX_CONFIGURE_FAILED", "port not in range")
    return dport


def _l3_proto_match(family: str, proto: str) -> str:
    """Render the family-correct L3 protocol match (never cross-family)."""

    if family == "ip6":
        return f"ip6 nexthdr {proto}"
    return f"ip protocol {proto}"


def render_nft_statements(rule: EgressRule) -> tuple[str, ...]:
    """Render one :class:`EgressRule` as nft statement(s).

    Only exact, narrow shapes are renderable: an ACCEPT must be a full
    ``(ip, port, tcp)`` tuple (anything broader raises instead of
    emitting an unsafe broad ACCEPT); a DROP is an exact address and/or
    port denial. Unknown shapes fail closed.
    """

    if not isinstance(rule, EgressRule):
        raise SandboxError("SANDBOX_CONFIGURE_FAILED", "rule untyped")
    if rule.chain != "OUTPUT" or rule.verdict not in ("ACCEPT", "DROP"):
        raise SandboxError("SANDBOX_CONFIGURE_FAILED", "rule shape rejected")
    if rule.proto not in ("tcp", "udp"):
        raise SandboxError("SANDBOX_CONFIGURE_FAILED", "rule proto rejected")
    if rule.verdict == "ACCEPT":
        if (
            rule.proto != "tcp"
            or rule.dst_ip is None
            or rule.dport is None
        ):
            raise SandboxError(
                "SANDBOX_CONFIGURE_FAILED", "broad accept refused"
            )
        family = _rule_family(rule.dst_ip)
        port = _checked_port(rule.dport)
        return (
            f"{family} daddr {rule.dst_ip} "
            f"{_l3_proto_match(family, 'tcp')} tcp dport {port} accept",
        )
    if rule.dst_ip is not None:
        family = _rule_family(rule.dst_ip)
        # NOTE: no anonymous L4 header after the L3 protocol match —
        # a bare ``tcp``/``udp`` match requires dport/sport detail and
        # the kernel rejects the statement (B8.1-A probe t7).
        return (
            f"{family} daddr {rule.dst_ip} "
            f"{_l3_proto_match(family, rule.proto)} drop",
        )
    if rule.proto == "udp" and rule.dport is not None:
        return (f"udp dport {_checked_port(rule.dport)} drop",)
    if rule.proto == "udp" and rule.dport is None:
        # Family-agnostic UDP denial needs both family matches
        # (``ip protocol`` never matches IPv6 and vice versa).
        return ("ip protocol udp drop", "ip6 nexthdr udp drop")
    raise SandboxError("SANDBOX_CONFIGURE_FAILED", "rule shape rejected")


def render_nft_script(ruleset: NetnsRuleSet) -> str:
    """Render the full ``table inet watch`` script for a rule set.

    Exactly two chains, one hook each (a second ``type filter hook``
    line inside a chain is a kernel syntax error — B8 blocker #1):
    OUTPUT defaults to DROP with only the exact allowlist ACCEPTs plus
    explicit DROP denials; INPUT defaults to DROP with only the
    ESTABLISHED,RELATED TCP return path. The output is validated with
    ``nft -c -f`` wherever the tool runs (see B8.1 tests).
    """

    if not isinstance(ruleset, NetnsRuleSet):
        raise SandboxError("SANDBOX_CONFIGURE_FAILED", "ruleset untyped")
    require_default_deny(ruleset)
    require_no_default_route(ruleset)
    output: list[str] = []
    for rule in ruleset.rules:
        output.extend(render_nft_statements(rule))
    body = "".join(f"    {stmt};\n" for stmt in output)
    established = "".join(f"    {stmt};\n" for stmt in _NFT_ESTABLISHED_STATEMENTS)
    return (
        "table inet watch {\n"
        "  chain output {\n"
        "    type filter hook output priority 0; policy drop;\n"
        f"{body}"
        "  }\n"
        "  chain input {\n"
        "    type filter hook input priority 0; policy drop;\n"
        f"{established}"
        "  }\n"
        "}\n"
    )


def render_iptables_plan(
    rule: EgressRule,
) -> tuple[tuple[str, list[str]], ...]:
    """Render one rule as ``(frontend, args)`` insertion plans.

    ``frontend`` is ``iptables`` (IPv4) or ``ip6tables`` (IPv6); the arg
    list is canonical — ``"-A OUTPUT " + " ".join(args)`` is exactly what
    ``iptables -S OUTPUT`` prints back, so configure and verify share one
    source of truth. Address-less rules apply to both families.
    """

    if not isinstance(rule, EgressRule):
        raise SandboxError("SANDBOX_CONFIGURE_FAILED", "rule untyped")
    if rule.chain != "OUTPUT" or rule.verdict not in ("ACCEPT", "DROP"):
        raise SandboxError("SANDBOX_CONFIGURE_FAILED", "rule shape rejected")
    if rule.proto not in ("tcp", "udp"):
        raise SandboxError("SANDBOX_CONFIGURE_FAILED", "rule proto rejected")
    verdict = "ACCEPT" if rule.verdict == "ACCEPT" else "DROP"
    if rule.verdict == "ACCEPT":
        if (
            rule.proto != "tcp"
            or rule.dst_ip is None
            or rule.dport is None
        ):
            raise SandboxError(
                "SANDBOX_CONFIGURE_FAILED", "broad accept refused"
            )
        family = _rule_family(rule.dst_ip)
        port = _checked_port(rule.dport)
        bits = "128" if family == "ip6" else "32"
        front = "ip6tables" if family == "ip6" else "iptables"
        return (
            (
                front,
                [
                    "-d",
                    f"{rule.dst_ip}/{bits}",
                    "-p",
                    "tcp",
                    "-m",
                    "tcp",
                    "--dport",
                    str(port),
                    "-j",
                    verdict,
                ],
            ),
        )
    if rule.dst_ip is not None:
        family = _rule_family(rule.dst_ip)
        bits = "128" if family == "ip6" else "32"
        front = "ip6tables" if family == "ip6" else "iptables"
        return (
            (
                front,
                ["-d", f"{rule.dst_ip}/{bits}", "-p", rule.proto, "-j", verdict],
            ),
        )
    if rule.proto == "udp" and rule.dport is not None:
        port = _checked_port(rule.dport)
        args = ["-p", "udp", "-m", "udp", "--dport", str(port), "-j", verdict]
        return (("iptables", list(args)), ("ip6tables", list(args)))
    if rule.proto == "udp" and rule.dport is None:
        args = ["-p", "udp", "-j", verdict]
        return (("iptables", list(args)), ("ip6tables", list(args)))
    raise SandboxError("SANDBOX_CONFIGURE_FAILED", "rule shape rejected")


# ------------------------------------------------------------------
# Firewall contract checkers (B8.1-C: pure, unit-testable).
# ------------------------------------------------------------------


def _normalize_nft_line(line: str) -> str:
    """Collapse whitespace and drop the trailing statement semicolon."""

    return " ".join(line.strip().rstrip(";").strip().split())


def _normalize_ctstate_sets(line: str) -> str:
    """Sort conntrack-state set members (tools canonicalize ordering).

    ``iptables -S`` prints ``--ctstate RELATED,ESTABLISHED`` while the
    installer wrote ``ESTABLISHED,RELATED``; both denote the same set.
    Normalizing avoids version-dependent string mismatch (fail-open
    risk: none — membership is compared exactly after sorting).
    """

    import re

    def _sort(match: "re.Match[str]") -> str:
        members = sorted(
            part.strip().upper()
            for part in match.group(2).split(",")
            if part.strip()
        )
        return match.group(1) + ",".join(members)

    line = re.sub(r"(ct state\s+)([A-Za-z,]+)", _sort, line)
    line = re.sub(r"(--ctstate\s+)([A-Za-z,]+)", _sort, line)
    return line


def check_nft_ruleset(ruleset_text: object, ruleset: NetnsRuleSet) -> bool:
    """Check dumped ``nft list ruleset`` output against the contract.

    Requires: exactly our table, exactly the output/input chains with
    DROP policy, the exact expected statement sets (allowlist ACCEPTs,
    explicit DROPs, ESTABLISHED return), and no NAT anywhere. Anything
    else (extra table/chain/ACCEPT, missing rule, unparseable dump) is
    False — fail closed, never an exception.
    """

    try:
        if not isinstance(ruleset_text, str) or not isinstance(
            ruleset, NetnsRuleSet
        ):
            return False
        if "type nat" in ruleset_text:
            return False
        tables: list[str] = []
        chains: dict[str, dict[str, list[str] | str | None]] = {}
        current: str | None = None
        header: str | None = None
        for raw in ruleset_text.splitlines():
            line = _normalize_nft_line(raw)
            if not line or line in ("{", "}"):
                continue
            if line.startswith("table "):
                tables.append(line.rstrip("{").strip())
                continue
            if line.startswith("chain "):
                current = line.split()[1]
                chains[current] = {"header": None, "statements": []}
                header = None
                continue
            if current is None:
                return False
            if "type filter hook" in line:
                if chains[current]["header"] is not None:
                    return False  # second hook line in one chain
                chains[current]["header"] = line
                continue
            stmts = chains[current]["statements"]
            assert isinstance(stmts, list)
            stmts.append(line)
        if tables != ["table inet watch"]:
            return False
        if set(chains) != {"output", "input"}:
            return False
        out_header = chains["output"]["header"]
        in_header = chains["input"]["header"]
        if (
            not isinstance(out_header, str)
            or "hook output" not in out_header
            or "policy drop" not in out_header
            or not isinstance(in_header, str)
            or "hook input" not in in_header
            or "policy drop" not in in_header
        ):
            return False
        expected_output: list[str] = []
        for rule in ruleset.rules:
            expected_output.extend(render_nft_statements(rule))
        out_stmts = chains["output"]["statements"]
        in_stmts = chains["input"]["statements"]
        assert isinstance(out_stmts, list) and isinstance(in_stmts, list)
        if sorted(
            _normalize_ctstate_sets(_normalize_nft_line(s)) for s in out_stmts
        ) != sorted(
            _normalize_ctstate_sets(_normalize_nft_line(s))
            for s in expected_output
        ):
            return False
        if sorted(
            _normalize_ctstate_sets(_normalize_nft_line(s)) for s in in_stmts
        ) != sorted(
            _normalize_ctstate_sets(_normalize_nft_line(s))
            for s in _NFT_ESTABLISHED_STATEMENTS
        ):
            return False
        return True
    except Exception:
        return False


def check_iptables_state(
    *,
    output_text: object,
    input_text: object,
    nat_text: object,
    expected_output_lines: tuple[str, ...],
) -> bool:
    """Check ``iptables -S`` dumps against the contract.

    Requires: OUTPUT policy DROP with exactly the expected rule lines
    (no unexpected ACCEPT, exact allowlist); INPUT policy DROP with
    exactly the ESTABLISHED return rule; NAT without any ``-A`` rule.
    Anything else is False — fail closed, never an exception.
    """

    try:
        if (
            not isinstance(output_text, str)
            or not isinstance(input_text, str)
            or not isinstance(nat_text, str)
        ):
            return False
        out_lines = [
            _normalize_ctstate_sets(line.strip())
            for line in output_text.splitlines()
            if line.strip()
        ]
        if not out_lines or out_lines[0] != "-P OUTPUT DROP":
            return False
        if sorted(out_lines[1:]) != sorted(
            _normalize_ctstate_sets(line) for line in expected_output_lines
        ):
            return False
        in_lines = [
            _normalize_ctstate_sets(line.strip())
            for line in input_text.splitlines()
            if line.strip()
        ]
        if in_lines != [
            "-P INPUT DROP",
            _normalize_ctstate_sets(_IPTABLES_ESTABLISHED_LINE),
        ]:
            return False
        for line in nat_text.splitlines():
            if line.strip().startswith("-A"):
                return False
        return True
    except Exception:
        return False


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
) -> object:
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


def _decode_command_text(raw: object) -> str | None:
    """Decode tool output to text (B8.1-B: explicit bytes handling).

    Returns the decoded string, or None when the payload is missing or
    undecodable — callers fail closed on None. Never raises.
    """

    try:
        if isinstance(raw, bytes):
            return raw.decode("utf-8", "replace")
        if isinstance(raw, str):
            return raw
        return None
    except Exception:
        return None


@dataclass(frozen=True)
class _NamespaceHandle:
    name: str
    execution_id: str


class SystemNetnsBackend:
    """Real namespace materialization (requires root/CAP_SYS_ADMIN).

    - CREATE: ``ip netns add watch-<execution_id>``.
    - CONFIGURE: loopback up; filter policy DROP on OUTPUT+INPUT; exact
      ACCEPT tuples for the allowlist; explicit DROP denials; a
      TCP-scoped ESTABLISHED,RELATED return rule on INPUT (approved
      flows can complete; nothing inbound-new is admitted).
    - VERIFY: read back the installed kernel state and assert the full
      contract (both DROP policies, exact allowlist, no unexpected
      ACCEPT, required return rule, empty NAT).
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
                # B8.1-A: single validated script (two chains, one hook
                # each, family-correct matches). Rejected by ``nft -f``
                # on any error -> SANDBOX_CONFIGURE_FAILED, never partial.
                script = render_nft_script(ruleset)
                _run_checked(
                    frontend + [nft_cmd, "-f", "-"],
                    "SANDBOX_CONFIGURE_FAILED",
                    "nft install",
                    input_text=script,
                )
            else:
                ipt4 = shutil.which("iptables")
                ipt6 = shutil.which("ip6tables")
                if ipt4 is None and ipt6 is None:
                    raise SandboxError(
                        "SANDBOX_CONFIGURE_FAILED", "no netfilter frontend"
                    )
                plan: dict[str, list[list[str]]] = {}
                for r in ruleset.rules:
                    for front, args in render_iptables_plan(r):
                        binary = ipt4 if front == "iptables" else ipt6
                        if binary is None:
                            raise SandboxError(
                                "SANDBOX_CONFIGURE_FAILED",
                                f"no {front} frontend",
                            )
                        plan.setdefault(binary, []).append(args)
                # Harden every present frontend (policies + TCP-scoped
                # ESTABLISHED return), even one carrying no allowlist
                # rules: an unhardened family would stay default-ACCEPT.
                for binary in (ipt4, ipt6):
                    if binary is None:
                        continue
                    _run_checked(
                        frontend + [binary, "-P", "OUTPUT", "DROP"],
                        "SANDBOX_CONFIGURE_FAILED",
                        "output policy",
                    )
                    _run_checked(
                        frontend + [binary, "-P", "INPUT", "DROP"],
                        "SANDBOX_CONFIGURE_FAILED",
                        "input policy",
                    )
                    _run_checked(
                        frontend + [binary, "-A", "INPUT"]
                        + list(_IPTABLES_ESTABLISHED_ARGS),
                        "SANDBOX_CONFIGURE_FAILED",
                        "established return",
                    )
                for binary, argsets in plan.items():
                    for args in argsets:
                        _run_checked(
                            frontend + [binary, "-A", "OUTPUT"] + list(args),
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
        """Verify the live kernel contract (B8.1-B/C: never crashes).

        Reads back REAL kernel state and checks the full contract:
        OUTPUT/INPUT policy DROP, the exact allowlist (no unexpected
        ACCEPT), the required ESTABLISHED TCP return rule, and empty
        NAT. Any deviation, any tool failure, any unexpected output —
        False (the caller raises ``SANDBOX_VERIFY_FAILED``). No
        exception ever escapes: bytes/str handling is explicit and the
        whole body is fail-closed.
        """

        if not isinstance(handle, _NamespaceHandle):
            return False
        try:
            require_default_deny(ruleset)
            require_no_default_route(ruleset)
        except (SandboxError, TypeError):
            return False
        try:
            _ns = handle.name
            if shutil.which("nft") is not None:
                raw = _run_checked(
                    ["ip", "netns", "exec", _ns, "nft", "list", "ruleset"],
                    "SANDBOX_VERIFY_FAILED",
                    "nft readback",
                )
                text = _decode_command_text(raw)
                if text is None:
                    return False
                return check_nft_ruleset(text, ruleset)
            ipt4 = shutil.which("iptables")
            if ipt4 is not None:
                return self._verify_iptables_family(handle, ruleset)
            return False
        except Exception:
            return False

    @staticmethod
    def _verify_iptables_family(
        handle: _NamespaceHandle, ruleset: NetnsRuleSet
    ) -> bool:
        """Verify the iptables/ip6tables legs against the shared plan."""

        _ns = handle.name
        ipt4 = shutil.which("iptables")
        ipt6 = shutil.which("ip6tables")
        if ipt4 is None and ipt6 is None:
            return False
        expected: dict[str, list[str]] = {}
        for r in ruleset.rules:
            for front, args in render_iptables_plan(r):
                binary = ipt4 if front == "iptables" else ipt6
                if binary is None:
                    return False
                expected.setdefault(binary, []).append(
                    "-A OUTPUT " + " ".join(args)
                )
        for binary in (ipt4, ipt6):
            if binary is None:
                continue
            out_raw = _run_checked(
                ["ip", "netns", "exec", _ns, binary, "-S", "OUTPUT"],
                "SANDBOX_VERIFY_FAILED",
                "readback",
            )
            in_raw = _run_checked(
                ["ip", "netns", "exec", _ns, binary, "-S", "INPUT"],
                "SANDBOX_VERIFY_FAILED",
                "readback",
            )
            nat_raw = _run_checked(
                ["ip", "netns", "exec", _ns, binary, "-t", "nat", "-S"],
                "SANDBOX_VERIFY_FAILED",
                "readback",
            )
            out_text = _decode_command_text(out_raw)
            in_text = _decode_command_text(in_raw)
            nat_text = _decode_command_text(nat_raw)
            if out_text is None or in_text is None or nat_text is None:
                return False
            if not check_iptables_state(
                output_text=out_text,
                input_text=in_text,
                nat_text=nat_text,
                expected_output_lines=tuple(expected.get(binary, ())),
            ):
                return False
        return True

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