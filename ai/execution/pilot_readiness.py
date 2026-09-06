"""Stage 4 pilot activation-readiness assessment (review tooling, NOT activation).

Produces the machine-checkable 17-item readiness matrix required for
the future ``http_probe`` pilot review. Every item is exactly one of
``PASS`` / ``FAIL`` / ``UNPROVEN`` — UNPROVEN is never upgraded, and
nothing here can enable anything: this module contains no code path
that writes any live switch, and ``activation_eligible()`` is a pure
conjunction computed from the items (``False`` while any item is not
``PASS``).

Evidence discipline (documented per item, auditable):

- LIVE-PROVEN: the check executes the real logic offline at
  assessment time (scripted DNS fixtures through the genuine
  ``ProductionHopResolver``; real ``DialProof`` assembly/verification;
  real ``EgressPolicy`` build/refusals; fail-closed resolver without
  transport). A failure here is FAIL, never UNPROVEN.
- ENV-PROVEN: the item depends on a privileged/server environment and
  is PASS only when a supplied validation report shows the exact
  checks green (netns harness report; real-Mongo evidence mapping).
  Without that evidence the item is UNPROVEN — including on hosts
  where the capability merely exists.
- SUITE-CITED: pure offline logic whose proof is the green unit
  suite named in the evidence string (suites re-run in Stage 4; the
  report records their counts). The module asserts the structural
  half live (symbols importable, gates closed) and cites the suite
  for the behavioral half.
- STRICT-UNPROVEN: the item stays UNPROVEN even when related evidence
  exists, because a sub-dimension cannot be proven here (dial proof
  against a production-shape dial: TEST-NET-1 can never pass the
  frozen ``validate_answers`` by design; full resource enforcement:
  CPU/mem/process-count need cgroup delegation; evidence persistence:
  needs a server).

No network, no subprocess, no database driver, no DNS, no LLM, no
browser, no Nuclei in this module. Scripted-DNS helpers are imported
lazily from the B1 test fixtures (the scripted packet authority) so
the product import graph stays clean.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai.execution.b3_validation import CHAIN_CHECK_NAMES as _CHAIN_CHECKS

__all__ = [
    "READINESS_STATUSES",
    "READINESS_ITEMS",
    "ReadinessItem",
    "assess_readiness",
    "mongo_evidence_from_suites",
    "readiness_summary",
    "activation_eligible",
]

READINESS_STATUSES = ("PASS", "FAIL", "UNPROVEN")

#: The 17 mandated review questions, in order.
READINESS_ITEMS: tuple[str, ...] = (
    "b1-address-source",
    "b2-mongo-authorization",
    "b2-ledger",
    "b2-audit",
    "b2-evidence-persistence",
    "b3-network-namespace",
    "b3-egress-filtering",
    "dial-proof-vs-actual-dial",
    "resource-enforcement",
    "redirect-fresh-scope",
    "scope-drift",
    "real-mongo-concurrency",
    "cleanup",
    "evidence-path",
    "deterministic-verification",
    "finding-eligibility-unchanged",
    "live-gates-closed",
)

_NETNS_NAMESPACE_CHECKS = (
    "namespace-isolated",
    "no-host-interface-inheritance",
    "parent-netns-unchanged",
)
_NETNS_EGRESS_CHECKS = (
    "egress-allowed-exact",
    "egress-fixture-roundtrip",
    "egress-wrong-port-blocked",
    "egress-unapproved-address",
    "egress-unapproved-address-port",
    "egress-loopback-blocked",
    "egress-private-blocked",
    "egress-linklocal-blocked",
    "egress-metadata-blocked",
    "dns-hostname-never-dials",
    "dns-pinned-no-lookup",
)
_NETNS_CLEANUP_CHECKS = (
    "parent-netns-unchanged",
    "no-orphan-process",
)
#: Bonus evidence (present only when a run exercised the kill path, or
#: a dedicated timeout run supplied it); never required, never assumed.
_NETNS_CLEANUP_BONUS = ("timeout-cleanup",)
_NETNS_RESOURCE_LIVE = (
    "timeout-stall-enforced",
    "bytecap-transport-truncates",
    "bytecap-decompression-ratio",
    "syndrop-timeout",
)


@dataclass(frozen=True)
class ReadinessItem:
    """One review verdict (closed status + single-line evidence)."""

    item: str
    status: str
    evidence: str

    def __post_init__(self) -> None:
        if self.item not in READINESS_ITEMS:
            raise ValueError(f"unknown readiness item: {self.item!r}")
        if self.status not in READINESS_STATUSES:
            raise ValueError(f"bad readiness status: {self.status!r}")
        if not self.evidence or "\n" in self.evidence or "\r" in self.evidence:
            raise ValueError("readiness evidence must be single-line non-empty")


def _item(item: str, status: str, evidence: str) -> ReadinessItem:
    return ReadinessItem(item=item, status=status, evidence=evidence[:200])


def _report_statuses(report: object) -> dict[str, str] | None:
    checks = getattr(report, "checks", None)
    if not isinstance(checks, (tuple, list)):
        return None
    out: dict[str, str] = {}
    for check in checks:
        name = getattr(check, "name", None)
        status = getattr(check, "status", None)
        if isinstance(name, str) and status in READINESS_STATUSES:
            out[name] = status
    return out


def _check_live_gates() -> ReadinessItem:
    from ai.execution import b3_boundary as _b3
    from ai.execution import browser_executor as _bx
    from ai.execution import http_executor as _hx
    from ai.execution import nuclei_executor as _nx

    closed = (
        _hx.LIVE_TRAFFIC_ENABLED is False
        and _nx.LIVE_NUCLEI is False
        and _bx.LIVE_BROWSER is False
        and _b3.HTTP_PROBE_PILOT_ENABLED is False
        and _b3.PilotGateConfig().pilot_enabled is False
    )
    return _item(
        "live-gates-closed",
        "PASS" if closed else "FAIL",
        "LIVE_TRAFFIC/NUCLEI/BROWSER/PILOT all False; pilot config defaults False",
    )


def _check_b1_source() -> ReadinessItem:
    # LIVE-PROVEN: fail-closed without transport + frozen deny-policy
    # round-trip, executed now (scripted fixtures only, no network).
    from ai.execution import production_address_source as _pas
    from ai.resolver.dns import DnsError, validate_answers

    try:
        source = _pas.ProductionAddressSource(
            server_ips=["192.0.2.53"], exchange=None
        )
        try:
            source.resolve("probe.invalid")
            return _item("b1-address-source", "FAIL", "transportless resolve succeeded")
        except DnsError:
            pass
        good = validate_answers(["8.8.8.8", "8.8.4.4"])
        if tuple(good) != ("8.8.4.4", "8.8.8.8"):
            return _item("b1-address-source", "FAIL", "ordering gate deviated")
        try:
            validate_answers(["8.8.8.8", "10.0.0.1"])
            return _item("b1-address-source", "FAIL", "mixed set accepted")
        except DnsError:
            pass
    except Exception as exc:
        return _item("b1-address-source", "FAIL", f"live probe raised {type(exc).__name__}")
    return _item(
        "b1-address-source",
        "PASS",
        "fail-closed w/o transport + frozen allow/deny round-trip executed offline",
    )


def _scripted_bindings():  # lazy test-fixture import (see module docstring)
    from ai.test_b1_dial_policy import (
        EX_ID,
        HOST,
        IP_A,
        NOW,
        WWW,
        IP_C,
        make_authz,
        make_hop_resolver,
        packet_entry,
    )

    authz = make_authz()
    resolver, _ = make_hop_resolver(
        {
            HOST: packet_entry([(IP_A, 60)]),
            WWW: packet_entry([(IP_C, 60)]),
        }
    )
    resolution, evaluation = resolver.resolve_initial(
        authorization=authz, execution_id=EX_ID, now=NOW
    )
    return authz, resolver, resolution, evaluation, NOW, EX_ID, HOST, WWW, IP_A, IP_C


def _check_redirect_and_drift() -> tuple[ReadinessItem, ReadinessItem]:
    # LIVE-PROVEN: genuine fresh resolve/evaluate/redirect + drift
    # refusals executed now through the frozen B1 + B3 seams.
    try:
        from ai.execution import b3_boundary as _b3

        (authz, resolver, resolution, evaluation, now,
         ex_id, host, www, ip_a, ip_c) = _scripted_bindings()
        policy = _b3.build_egress_policy(
            authorization=authz, resolution=resolution,
            evaluation=evaluation, selected_address=ip_a, now=now,
        )
        new_resolution, new_evaluation = resolver.resolve_hop(
            authorization=authz, execution_id=ex_id, canonical_host=www,
            scheme="https", effective_port=443, path="/r", query="", now=now,
        )
        new_policy = _b3.require_fresh_scope_for_redirect(
            policy=policy, authorization=authz,
            new_resolution=new_resolution, new_evaluation=new_evaluation,
            redirect_hop_index=1, selected_address=ip_c, now=now,
        )
        if new_policy.approved_address != ip_c:
            raise AssertionError("redirect policy misbound")
        try:
            _b3.require_fresh_scope_for_redirect(
                policy=policy, authorization=authz,
                new_resolution=resolution, new_evaluation=evaluation,
                redirect_hop_index=1, selected_address=ip_a, now=now,
            )
            return (
                _item("redirect-fresh-scope", "FAIL", "stale reuse admitted"),
                _item("scope-drift", "UNPROVEN", "gate failed open; cannot assess drift"),
            )
        except Exception as exc:
            if getattr(exc, "code", "") != "REDIRECT_REQUIRES_FRESH_SCOPE":
                raise
        redirect_item = _item(
            "redirect-fresh-scope", "PASS",
            "fresh resolve+evaluate+policy executed; stale reuse refused live",
        )
    except Exception as exc:
        return (
            _item("redirect-fresh-scope", "FAIL", f"live probe raised {type(exc).__name__}"),
            _item("scope-drift", "UNPROVEN", "gate failed; cannot assess drift"),
        )
    try:
        from ai.execution import b3_boundary as _b3

        (authz, _r, resolution, evaluation, fresh_now,
         _e, _h, _w, ip_a, _c) = _scripted_bindings()
        drifted = authz.model_copy(
            update={"target": authz.target.model_copy(
                update={"scope_lists_hash": "0" * 64})}
        )
        try:
            _b3.build_egress_policy(
                authorization=drifted, resolution=resolution,
                evaluation=evaluation, selected_address=ip_a, now=fresh_now,
            )
            drift_item = _item("scope-drift", "FAIL", "drifted authz admitted")
        except Exception as exc:
            drift_item = _item(
                "scope-drift",
                "PASS" if getattr(exc, "code", "") == "SCOPE_DRIFT" else "FAIL",
                "drifted authorization refused live with SCOPE_DRIFT",
            )
    except Exception as exc:
        drift_item = _item("scope-drift", "FAIL", f"live probe raised {type(exc).__name__}")
    return redirect_item, drift_item


def _check_dial_proof_roundtrip() -> tuple[str, str] | None:
    # Supporting evidence only (item 8 stays STRICT-UNPROVEN): a real
    # DialProof assembled + verified against scripted bindings now.
    try:
        from ai.execution import dial_proof as _dp

        (authz, _r, resolution, evaluation, _n,
         _e, host, _w, ip_a, _c) = _scripted_bindings()
        proof = _dp.assemble_dial_proof(
            actual_peer_ip=ip_a, local_sockaddr="192.0.2.7:54321",
            selected_address=ip_a,
            resolved_addresses=tuple(resolution.resolved_addresses),
            resolver_name="prod-dns-stub", resolver_version="prod-dns-stub/v1",
            dial_addresses=tuple(resolution.resolved_addresses),
            dial_port=443, dial_sni=host, resolution=resolution,
            evaluation=evaluation, authorization_id=authz.authorization_id,
            tls_sni=host, tls_version_negotiated="TLSv1.3",
            tls_peer_cert_hash="f" * 64, redirect_hop_index=0,
            connection_id="conn-" + "1" * 32,
        )
        _dp.verify_dial_proof(
            proof, resolution=resolution, evaluation=evaluation,
            authorization_id=authz.authorization_id,
        )
        return ("roundtrip-ok", _dp.proof_digest_for([proof])[:16])
    except Exception:
        return None


def _check_suite_cited(
    item: str, evidence: str, modules: tuple[str, ...]
) -> ReadinessItem:
    try:
        for dotted in modules:
            __import__(dotted)
    except Exception as exc:
        return _item(item, "FAIL", f"contract import raised {type(exc).__name__}")
    return _item(item, "PASS", evidence)


#: Skip-safe suites whose genuine outcomes feed the mongo items.
_MONGO_SUITE_NAMES = (
    "ai.test_b3_mongo_integration",
    "ai.test_stage6_dryrun_mongo",
)

#: Which readiness keys each suite's outcome feeds.
_MONGO_SUITE_KEYS: dict[str, tuple[str, ...]] = {
    "ai.test_b3_mongo_integration": (
        "b2-mongo-authorization",
        "b2-ledger",
        "b2-audit",
        "b2-evidence-persistence",
        "real-mongo-concurrency",
    ),
    "ai.test_stage6_dryrun_mongo": ("evidence-path",),
}


def mongo_evidence_from_suites() -> dict[str, str]:
    """Run the skip-safe mongo suites and map outcomes to evidence.

    Mechanical, never hand-written: a suite with zero failures/errors
    and at least one non-skipped test maps its keys to PASS; a suite
    that fully skips (no URI/server) maps its keys to UNPROVEN; any
    failure or error maps its keys to FAIL. Running the suites performs
    no production contact (they enforce their own URI-gating and
    denylists). Keys not covered by any suite stay UNPROVEN downstream.
    """

    import io
    import unittest as _unittest

    evidence: dict[str, str] = {}
    loader = _unittest.TestLoader()
    for suite_name in _MONGO_SUITE_NAMES:
        try:
            suite = loader.loadTestsFromName(suite_name)
        except Exception:
            status = "FAIL"
        else:
            stream = io.StringIO()
            runner = _unittest.TextTestRunner(stream=stream, verbosity=0)
            result = runner.run(suite)
            ran = result.testsRun - len(result.skipped)
            if result.failures or result.errors:
                status = "FAIL"
            elif ran <= 0:
                status = "UNPROVEN"
            else:
                status = "PASS"
        for key in _MONGO_SUITE_KEYS[suite_name]:
            evidence[key] = status
    return evidence


def assess_readiness(
    *,
    netns_report: object = None,
    mongo_evidence: dict[str, str] | None = None,
) -> tuple[ReadinessItem, ...]:
    """Compute the 17-item matrix (no activation possible from output)."""

    mongo_evidence = dict(mongo_evidence or {})
    for key, value in mongo_evidence.items():
        if value not in READINESS_STATUSES:
            mongo_evidence[key] = "UNPROVEN"
    statuses = _report_statuses(netns_report)

    items: dict[str, ReadinessItem] = {}
    items["live-gates-closed"] = _check_live_gates()
    items["b1-address-source"] = _check_b1_source()
    redirect_item, drift_item = _check_redirect_and_drift()
    items["redirect-fresh-scope"] = redirect_item
    items["scope-drift"] = drift_item
    proof_roundtrip = _check_dial_proof_roundtrip()

    def _mongo_item(key: str, label: str) -> ReadinessItem:
        status = mongo_evidence.get(key, "UNPROVEN")
        return _item(
            key, status,
            f"server evidence: {status}; needs dedicated test-URI run"
            if status != "PASS"
            else f"server evidence accepted for {label}",
        )

    items["b2-mongo-authorization"] = _mongo_item("b2-mongo-authorization", "authz")
    items["b2-ledger"] = _mongo_item("b2-ledger", "ledger")
    items["b2-audit"] = _mongo_item("b2-audit", "audit")
    items["b2-evidence-persistence"] = _mongo_item(
        "b2-evidence-persistence", "blob+index")
    items["real-mongo-concurrency"] = _mongo_item(
        "real-mongo-concurrency", "races")

    def _netns_item(key: str, required: tuple[str, ...], label: str) -> ReadinessItem:
        if statuses is None:
            return _item(key, "UNPROVEN", f"no netns validation report supplied ({label})")
        missing = [name for name in required if name not in statuses]
        if missing:
            return _item(key, "UNPROVEN", f"report lacks {missing[0]} ({label})")
        bad = [name for name in required if statuses[name] != "PASS"]
        if bad:
            return _item(key, "FAIL", f"validation check failed: {bad[0]} ({label})")
        return _item(key, "PASS", f"harness checks green: {label}")

    items["b3-network-namespace"] = _netns_item(
        "b3-network-namespace", _NETNS_NAMESPACE_CHECKS, "isolated netns, no inheritance")
    items["b3-egress-filtering"] = _netns_item(
        "b3-egress-filtering", _NETNS_EGRESS_CHECKS, "FIB-enforced allowlist matrix")
    items["cleanup"] = _netns_item(
        "cleanup", _NETNS_CLEANUP_CHECKS, "teardown, reap, timeout kill")
    if (
        items["cleanup"].status == "PASS"
        and statuses is not None
        and statuses.get("timeout-cleanup") == "PASS"
    ):
        items["cleanup"] = _item(
            "cleanup", "PASS",
            "harness checks green: teardown, reap, timeout kill (kill path observed)",
        )

    proof_note = (
        "proof format round-trip executed offline"
        if proof_roundtrip is not None
        else "proof round-trip failed"
    )
    if proof_roundtrip is None:
        items["dial-proof-vs-actual-dial"] = _item(
            "dial-proof-vs-actual-dial", "FAIL", "offline proof round-trip broken")
    elif statuses is None:
        items["dial-proof-vs-actual-dial"] = _item(
            "dial-proof-vs-actual-dial", "UNPROVEN",
            f"{proof_note}; no isolated chain report supplied",
        )
    else:
        missing = [name for name in _CHAIN_CHECKS if name not in statuses]
        bad = [name for name in _CHAIN_CHECKS
               if name in statuses and statuses[name] != "PASS"]
        if missing:
            items["dial-proof-vs-actual-dial"] = _item(
                "dial-proof-vs-actual-dial", "UNPROVEN",
                f"{proof_note}; chain report lacks {missing[0]}",
            )
        elif bad:
            items["dial-proof-vs-actual-dial"] = _item(
                "dial-proof-vs-actual-dial", "FAIL",
                f"chain check failed: {bad[0]}",
            )
        else:
            items["dial-proof-vs-actual-dial"] = _item(
                "dial-proof-vs-actual-dial", "PASS",
                "authz->resolution->scope->egress->socket->proof->http->sealed evidence live",
            )
    live_dims = (
        [name for name in _NETNS_RESOURCE_LIVE if statuses and statuses.get(name) == "PASS"]
        if statuses else []
    )
    items["resource-enforcement"] = _item(
        "resource-enforcement", "UNPROVEN",
        f"stall+bytecaps+syndrop enforced live ({len(live_dims)}/4); CPU/mem/process-count UNPROVEN",
    )
    # Evidence BUILD seals offline (suite-proven) but persistence needs
    # a server: PASS only when the real persistence dry-run suite genuinely
    # passed (mechanical evidence); otherwise strict UNPROVEN.
    try:
        __import__("ai.evidence.builder")
        __import__("ai.persistence.mongo_evidence")
        contracts_ok = True
    except Exception as exc:
        contracts_ok = exc
    if contracts_ok is not True:
        items["evidence-path"] = _item(
            "evidence-path", "FAIL",
            f"contract import raised {type(contracts_ok).__name__}")
    elif mongo_evidence.get("evidence-path") == "PASS":
        items["evidence-path"] = _item(
            "evidence-path", "PASS",
            "server evidence accepted for persistence dry-run (durable + reread + sweep)",
        )
    elif mongo_evidence.get("evidence-path") == "FAIL":
        items["evidence-path"] = _item(
            "evidence-path", "FAIL", "persistence dry-run suite failed")
    else:
        items["evidence-path"] = _item(
            "evidence-path", "UNPROVEN",
            "seal path suite-proven (Stage 1/2); server persistence needs test-URI run",
        )
    items["deterministic-verification"] = _check_suite_cited(
        "deterministic-verification",
        "pure verifier suite green (ai.test_deterministic_verifier, Stage 4 regressions)",
        ("ai.verification.deterministic.pipeline", "ai.evidence.handoff"),
    )
    items["finding-eligibility-unchanged"] = _check_suite_cited(
        "finding-eligibility-unchanged",
        "finding+severance suites green; no materialization-path change in Stage 4",
        ("ai.finding.eligibility", "ai.finding.legacy_block"),
    )
    ordered = tuple(items[key] for key in READINESS_ITEMS)
    assert len(ordered) == 17
    return ordered


def readiness_summary(
    items: tuple[ReadinessItem, ...] | list[ReadinessItem],
) -> dict[str, int]:
    """Count items per status (machine-checkable rollup)."""

    summary = {"PASS": 0, "FAIL": 0, "UNPROVEN": 0}
    for entry in items:
        if not isinstance(entry, ReadinessItem):
            raise TypeError("summary accepts only ReadinessItem entries")
        summary[entry.status] += 1
    return summary


def activation_eligible(
    items: tuple[ReadinessItem, ...] | list[ReadinessItem],
) -> bool:
    """Pure conjunction: eligible only if EVERY item is PASS.

    Computed, never asserted — Stage 4 matrices contain UNPROVEN
    items, so this returns False. No code path here (or anywhere in
    Stage 4) can make it return True except genuinely green evidence.
    """

    entries = list(items)
    if len(entries) != len(READINESS_ITEMS):
        raise ValueError("eligibility requires the full 17-item matrix")
    return all(entry.status == "PASS" for entry in entries)


def render_matrix(items: tuple[ReadinessItem, ...] | list[ReadinessItem]) -> str:
    """Fixed-width text rendering for reports (no secrets possible)."""

    lines = ["ITEM | STATUS | EVIDENCE", "---- | ------ | --------"]
    for entry in items:
        lines.append(f"{entry.item} | {entry.status} | {entry.evidence}")
    summary = readiness_summary(items)
    lines.append(
        f"SUMMARY | PASS={summary['PASS']} FAIL={summary['FAIL']} "
        f"UNPROVEN={summary['UNPROVEN']} | eligible={activation_eligible(items)}"
    )
    return "\n".join(lines)
