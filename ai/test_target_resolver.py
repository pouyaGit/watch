"""Focused Phase 5C TargetResolver tests (offline, deterministic).

Covers the 5C contract only: fail-closed canonicalization,
scheme/port rules, program isolation, DNS observation + safety +
limits, live-authorization binding, snapshot advisory semantics,
determinism, error hygiene, immutability, verdict-field absence,
network isolation, and hostile/adversarial inputs.

No network, no subprocess, no database, no LLM, no executors, no
verifiers, no findings, no scope evaluation (5D), no CONFIRMED /
NOT_VULNERABLE semantics anywhere.
"""

import re
import unittest
from pathlib import Path

from pydantic import ValidationError

from ai.authorizer import (
    InMemoryAuthorizationStore,
    consume_authorization,
    issue_authorization,
    revoke_authorization,
)
from ai.resolver import (
    AssetRecord,
    CanonicalizationError,
    DnsError,
    FakeDnsFailure,
    FakeDnsResolver,
    InMemoryInventoryRepository,
    InventoryError,
    ProgramRecord,
    TargetResolver,
    classify_address,
    scope_lists_hash_for,
    validate_answers,
)
from ai.resolver.canonicalization import (
    canonicalize_host,
    canonicalize_port,
    canonicalize_scheme,
    canonicalize_target,
)
from ai.schemas.artifact import artifact_id_for
from ai.schemas.execution_authorization import (
    ArtifactBinding,
    AuthorizationRequest,
    TargetBinding,
)
from ai.schemas.target_resolution import (
    FORBIDDEN_RESOLUTION_FIELDS,
    DialBinding,
    ResolutionError,
    ResolutionRequest,
    TargetResolution,
    base_authority_for,
    canonical_target_hash_for,
    resolution_id_for,
)

NOW = "2026-06-01T00:00:00+00:00"
EXPIRY = "2030-01-01T00:00:00+00:00"
EXE_A = "ex-" + "a" * 32
EXE_B = "ex-" + "b" * 32
SNAP_A = "a" * 64
SNAP_B = "b" * 64
GOOD_IP = "93.184.216.34"
GOOD_IP_2 = "1.1.1.1"
GOOD_IP_V6 = "2606:4700:4700::1111"

_TP_COUNTER = 0


def _next_tp_id() -> str:
    global _TP_COUNTER
    _TP_COUNTER += 1
    return "tp-%016x" % _TP_COUNTER


def _artifact_binding():
    tp_id = _next_tp_id()
    content_hash = "c" * 64
    artifact_id = artifact_id_for(
        artifact_type="http_request_spec",
        test_plan_id=tp_id,
        content_hash=content_hash,
    )
    binding = ArtifactBinding(
        artifact_id=artifact_id,
        artifact_type="http_request_spec",
        content_hash=content_hash,
        test_plan_id=tp_id,
    )
    return binding, tp_id


def _issue(
    store,
    *,
    program,
    host,
    scheme="https",
    port=443,
    scopes,
    ooscopes=(),
    snapshot=None,
    execution_class="http_probe",
    expiry=EXPIRY,
    now=NOW,
):
    artifact, tp_id = _artifact_binding()
    request = AuthorizationRequest(
        test_plan_id=tp_id,
        artifact=artifact,
        target=TargetBinding(
            program_name=program,
            host=host,
            scheme=scheme,
            effective_port=port,
            scope_lists_hash=scope_lists_hash_for(tuple(scopes), tuple(ooscopes)),
            snapshot_ref=snapshot,
        ),
        execution_class=execution_class,
        expires_at=expiry,
    )
    return issue_authorization(store, request, now=now)


def _repo(*, program, scopes, ooscopes=(), host, scheme="https",
          port=443, snapshot=None, ips=()):
    return InMemoryInventoryRepository(
        programs=[
            ProgramRecord(
                program_name=program,
                scopes=tuple(scopes),
                ooscopes=tuple(ooscopes),
            )
        ],
        assets=[
            AssetRecord(
                program_name=program,
                canonical_host=host,
                scheme=scheme,
                effective_port=port,
                snapshot_current=snapshot,
                ips_observed=tuple(ips),
            )
        ],
    )


def _resolver(repo, dns_map):
    return TargetResolver(
        inventory=repo, dns=FakeDnsResolver(dict(dns_map))
    )


def _resolve(resolver, authz, execution_id=EXE_A, now=NOW, snapshot=None):
    return resolver.resolve(
        ResolutionRequest(
            authorization=authz,
            execution_id=execution_id,
            now=now,
            snapshot_observed=snapshot,
        )
    )


def _happy_path(**over):
    """Seeded program/host/inventory/DNS/authz that fully RESOLVEs."""
    program = over.get("program", "acme")
    host = over.get("host", "target.example.com")
    scopes = over.get("scopes", ["example.com"])
    ooscopes = over.get("ooscopes", [])
    scheme = over.get("scheme", "https")
    port = over.get("port", 443)
    snapshot = over.get("snapshot", SNAP_A)
    dns_answers = over.get("dns_answers", [GOOD_IP])
    store = InMemoryAuthorizationStore()
    authz = _issue(
        store,
        program=program,
        host=host,
        scheme=scheme,
        port=port,
        scopes=scopes,
        ooscopes=ooscopes,
        snapshot=snapshot,
    )
    repo = _repo(
        program=program,
        scopes=scopes,
        ooscopes=ooscopes,
        host=host,
        scheme=scheme,
        port=port,
        snapshot=snapshot,
    )
    resolver = _resolver(repo, {host: list(dns_answers)})
    return store, authz, resolver


# ------------------------------------------------------------------
# A. Canonicalization
# ------------------------------------------------------------------


class TestCanonicalization(unittest.TestCase):
    def test_lowercase_host(self):
        host, kind = canonicalize_host("Target.EXAMPLE.COM")
        self.assertEqual(host, "target.example.com")
        self.assertEqual(kind, "dns")

    def test_trailing_dot_stripped(self):
        host, _ = canonicalize_host("target.example.com.")
        self.assertEqual(host, "target.example.com")

    def test_double_trailing_dot_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize_host("target.example.com..")

    def test_unicode_idna(self):
        host, kind = canonicalize_host("münchen.de")
        self.assertEqual(host, "xn--mnchen-3ya.de")
        self.assertEqual(kind, "dns")

    def test_malformed_unicode_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize_host("münchen..de")

    def test_invalid_labels_rejected(self):
        for bad in ["-lead.example.com", "trail-.example.com",
                    "under_score.example.com", "a..b.com", ".lead.com",
                    "toolonglabel" + "x" * 60 + ".com", ""]:
            with self.assertRaises(CanonicalizationError, msg=bad):
                canonicalize_host(bad)

    def test_whitespace_rejected_not_trimmed(self):
        for bad in [" target.example.com", "target.example.com ",
                    "target.example.com\n", "tar get.example.com",
                    "\ttarget.example.com"]:
            with self.assertRaises(CanonicalizationError, msg=repr(bad)):
                canonicalize_host(bad)

    def test_control_chars_rejected(self):
        for bad in ["targ\x00et.example.com", "targ\x1fet.example.com",
                    "targ\x7fet.example.com"]:
            with self.assertRaises(CanonicalizationError, msg=repr(bad)):
                canonicalize_host(bad)

    def test_wildcard_rejected(self):
        for bad in ["*.example.com", "*", "a.*.example.com"]:
            with self.assertRaises(CanonicalizationError, msg=bad):
                canonicalize_host(bad)

    def test_credentials_rejected(self):
        for bad in ["user:pass@target.example.com",
                    "user@target.example.com",
                    "http://target.example.com",
                    "target.example.com/path",
                    "target.example.com:443"]:
            with self.assertRaises(CanonicalizationError, msg=bad):
                canonicalize_host(bad)

    def test_ipv4_literal(self):
        host, kind = canonicalize_host("93.184.216.34")
        self.assertEqual((host, kind), ("93.184.216.34", "ipv4"))

    def test_ipv4_obfuscations_become_ipv4(self):
        host, kind = canonicalize_host("0x7f.0.0.1")
        self.assertEqual((host, kind), ("127.0.0.1", "ipv4"))
        host, kind = canonicalize_host("2130706433")
        self.assertEqual((host, kind), ("127.0.0.1", "ipv4"))
        host, kind = canonicalize_host("0177.0.0.1")
        self.assertEqual((host, kind), ("127.0.0.1", "ipv4"))
        host, kind = canonicalize_host("127.1")
        self.assertEqual((host, kind), ("127.0.0.1", "ipv4"))

    def test_ambiguous_numeric_rejected(self):
        for bad in ["999.999.999.999", "1.2.3.4.5", "08.9.9.9",
                    "0x12345678901234567890", "1.2.3.256"]:
            with self.assertRaises(CanonicalizationError, msg=bad):
                canonicalize_host(bad)

    def test_non_ip_token_is_dns_name(self):
        # "0xzz" is parseable as neither an IP (invalid hex) nor a
        # numeric literal, so it falls through to hostname rules where
        # it is a syntactically valid single label (never an address).
        host, kind = canonicalize_host("0xzz")
        self.assertEqual((host, kind), ("0xzz", "dns"))

    def test_ipv6_literal(self):
        host, kind = canonicalize_host("::1")
        self.assertEqual(kind, "ipv6")
        self.assertEqual(host, "::1")

    def test_bracketed_ipv6_unwrapped(self):
        host, kind = canonicalize_host("[2001:db8::1]")
        self.assertEqual((host, kind), ("2001:db8::1", "ipv6"))

    def test_bracketed_non_ipv6_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize_host("[93.184.216.34]")
        with self.assertRaises(CanonicalizationError):
            canonicalize_host("[not-an-ip]")

    def test_ipv6_zone_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonicalize_host("fe80::1%eth0")
        with self.assertRaises(CanonicalizationError):
            canonicalize_host("[fe80::1%eth0]")

    def test_ipv4_mapped_unfolded(self):
        host, kind = canonicalize_host("::ffff:10.0.0.1")
        self.assertEqual((host, kind), ("10.0.0.1", "ipv4"))
        host, kind = canonicalize_host("[::ffff:8.8.8.8]")
        self.assertEqual((host, kind), ("8.8.8.8", "ipv4"))

    def test_non_string_rejected_by_type(self):
        for bad in [None, 123, b"target.example.com", ["target.example.com"]]:
            with self.assertRaises(TypeError):
                canonicalize_host(bad)

    def test_error_messages_carry_no_input(self):
        try:
            canonicalize_host("user:secretpass@target.example.com")
        except CanonicalizationError as exc:
            self.assertNotIn("secretpass", str(exc))
            self.assertEqual(str(exc), "INVALID_HOST")
        else:
            self.fail("expected CanonicalizationError")


# ------------------------------------------------------------------
# B. Scheme / port
# ------------------------------------------------------------------


class TestSchemePort(unittest.TestCase):
    def test_http_and_https_accepted(self):
        self.assertEqual(canonicalize_scheme("https"), "https")
        self.assertEqual(canonicalize_scheme("http"), "http")
        self.assertEqual(canonicalize_scheme("HTTPS"), "https")

    def test_unsupported_schemes_rejected(self):
        for bad in ["ftp", "file", "javascript", "data", "gopher", "",
                    "https ", " http"]:
            with self.assertRaises(CanonicalizationError, msg=repr(bad)):
                canonicalize_scheme(bad)

    def test_default_ports(self):
        port, explicit = canonicalize_port("http", None)
        self.assertEqual((port, explicit), (80, False))
        port, explicit = canonicalize_port("https", None)
        self.assertEqual((port, explicit), (443, False))

    def test_explicit_default_is_canonical_equivalent(self):
        default = canonicalize_target("target.example.com", "https", None)
        explicit = canonicalize_target("target.example.com", "https", 443)
        self.assertEqual(default.effective_port, explicit.effective_port)
        self.assertTrue(explicit.port_explicit)
        self.assertFalse(default.port_explicit)
        self.assertEqual(
            canonical_target_hash_for(
                program_name="acme",
                canonical_host=default.canonical_host,
                scheme=default.scheme,
                effective_port=default.effective_port,
            ),
            canonical_target_hash_for(
                program_name="acme",
                canonical_host=explicit.canonical_host,
                scheme=explicit.scheme,
                effective_port=explicit.effective_port,
            ),
        )
        self.assertEqual(
            base_authority_for(
                scheme="https", canonical_host="target.example.com",
                effective_port=443, host_kind="dns",
            ),
            "https://target.example.com",
        )

    def test_non_default_ports(self):
        port, explicit = canonicalize_port("https", 8443)
        self.assertEqual((port, explicit), (8443, True))
        self.assertEqual(
            base_authority_for(
                scheme="https", canonical_host="target.example.com",
                effective_port=8443, host_kind="dns",
            ),
            "https://target.example.com:8443",
        )

    def test_no_scheme_upgrade_or_port_rewrite(self):
        http = canonicalize_target("target.example.com", "http", None)
        https = canonicalize_target("target.example.com", "https", None)
        self.assertNotEqual(http.scheme, https.scheme)
        self.assertNotEqual(http.effective_port, https.effective_port)

    def test_invalid_ports_rejected(self):
        for bad in [0, -1, 65536, 99999, "443", 443.0, True, False,
                    float("nan")]:
            with self.assertRaises(CanonicalizationError, msg=repr(bad)):
                canonicalize_port("https", bad)


# ------------------------------------------------------------------
# C. Program isolation
# ------------------------------------------------------------------


class TestProgramIsolation(unittest.TestCase):
    def _two_program_world(self):
        scopes_a = ["example.com"]
        scopes_b = ["example.com"]
        store = InMemoryAuthorizationStore()
        authz_a = _issue(store, program="prog-a",
                         host="shared.example.com", scopes=scopes_a)
        repo = InMemoryInventoryRepository(
            programs=[
                ProgramRecord(program_name="prog-a", scopes=tuple(scopes_a)),
                ProgramRecord(program_name="prog-b", scopes=tuple(scopes_b)),
            ],
            assets=[
                # Same host exists under BOTH programs with distinct rows.
                AssetRecord(program_name="prog-a",
                            canonical_host="shared.example.com"),
                AssetRecord(program_name="prog-b",
                            canonical_host="shared.example.com"),
            ],
        )
        return store, authz_a, repo

    def test_exact_program_host_accepted(self):
        _, authz_a, repo = self._two_program_world()
        resolver = _resolver(repo, {"shared.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz_a)
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.program_name, "prog-a")

    def test_same_host_other_program_never_matches(self):
        # Authorization for prog-a must resolve prog-a's row even though
        # prog-b owns an identical hostname: the pair key isolates.
        _, authz_a, repo = self._two_program_world()
        row_b = repo.get_asset("prog-b", "shared.example.com")
        self.assertIsNotNone(row_b)
        resolver = _resolver(repo, {"shared.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz_a)
        self.assertEqual(result.program_name, "prog-a")
        self.assertNotEqual(result.program_name, "prog-b")

    def test_wrong_program_rejected(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="prog-zzz",
                       host="shared.example.com", scopes=["example.com"])
        _, _, repo = self._two_program_world()
        resolver = _resolver(repo, {"shared.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "TARGET_PROGRAM_GONE")

    def test_no_global_host_lookup(self):
        # Host exists (under prog-b) but the authorized program has no
        # asset row: resolution dies instead of borrowing prog-b's row.
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="prog-a",
                       host="only-in-b.example.com", scopes=["example.com"])
        repo = InMemoryInventoryRepository(
            programs=[ProgramRecord(program_name="prog-a",
                                    scopes=("example.com",))],
            assets=[AssetRecord(program_name="prog-b",
                                canonical_host="only-in-b.example.com")],
        )
        resolver = _resolver(repo, {"only-in-b.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "TARGET_GONE")


# ------------------------------------------------------------------
# D. DNS
# ------------------------------------------------------------------


class TestDnsObservation(unittest.TestCase):
    def test_one_valid_answer(self):
        _, authz, resolver = _happy_path(dns_answers=[GOOD_IP])
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.resolved_addresses, (GOOD_IP,))
        self.assertEqual(result.dns_answer_count, 1)

    def test_multiple_answers_sorted(self):
        _, authz, resolver = _happy_path(dns_answers=[GOOD_IP_2, GOOD_IP])
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "RESOLVED")
        # Deterministic numeric order regardless of answer order.
        self.assertEqual(result.resolved_addresses, (GOOD_IP_2, GOOD_IP))

    def test_too_many_answers_fail_closed(self):
        answers = ["45.0.0.%d" % i for i in range(1, 10)]  # 9 > ceiling 8
        _, authz, resolver = _happy_path(dns_answers=answers)
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "RESOLUTION_FAILED")
        self.assertEqual(result.failure_code, "DNS_TOO_MANY_ANSWERS")
        self.assertEqual(result.resolved_addresses, ())

    def test_answer_ceiling_matches_frozen_limit(self):
        from ai.limits.ceilings import CEILINGS

        from ai.resolver.dns import MAX_DNS_ANSWERS

        self.assertEqual(MAX_DNS_ANSWERS, CEILINGS["dns_answers"])
        self.assertEqual(MAX_DNS_ANSWERS, 8)
        # Exactly at ceiling resolves; one more fails.
        ok_answers = ["45.0.0.%d" % i for i in range(1, 9)]
        _, authz, resolver = _happy_path(dns_answers=ok_answers)
        self.assertEqual(_resolve(resolver, authz).status, "RESOLVED")

    def test_nxdomain(self):
        _, authz, resolver = _happy_path()
        empty = TargetResolver(
            inventory=resolver._inventory, dns=FakeDnsResolver({})
        )
        result = _resolve(empty, authz)
        self.assertEqual(result.status, "RESOLUTION_FAILED")
        self.assertEqual(result.failure_code, "DNS_NXDOMAIN")

    def test_servfail_and_timeout(self):
        for code in ("DNS_SERVFAIL", "DNS_TIMEOUT"):
            _, authz, resolver = _happy_path()
            failing = TargetResolver(
                inventory=resolver._inventory,
                dns=FakeDnsResolver(
                    {"target.example.com": FakeDnsFailure(code)}
                ),
            )
            result = _resolve(failing, authz)
            self.assertEqual(result.status, "RESOLUTION_FAILED")
            self.assertEqual(result.failure_code, code)

    def test_malformed_answer(self):
        _, authz, resolver = _happy_path(dns_answers=["not-an-ip"])
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "RESOLUTION_FAILED")
        self.assertEqual(result.failure_code, "DNS_MALFORMED_ANSWER")

    def test_empty_answer_set(self):
        _, authz, resolver = _happy_path(dns_answers=[])
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "RESOLUTION_FAILED")
        self.assertEqual(result.failure_code, "DNS_RESOLUTION_FAILED")

    def test_private_address_denied(self):
        for bad in ["10.0.0.5", "172.16.9.9", "192.168.1.1", "100.64.0.1"]:
            _, authz, resolver = _happy_path(dns_answers=[bad])
            result = _resolve(resolver, authz)
            self.assertEqual(result.status, "RESOLUTION_FAILED", msg=bad)
            self.assertEqual(result.failure_code, "DNS_UNSAFE_ADDRESS")

    def test_loopback_denied(self):
        for bad in ["127.0.0.1", "::1"]:
            _, authz, resolver = _happy_path(dns_answers=[bad])
            result = _resolve(resolver, authz)
            self.assertEqual(result.failure_code, "DNS_UNSAFE_ADDRESS",
                             msg=bad)

    def test_link_local_and_metadata_denied(self):
        for bad in ["169.254.10.20", "169.254.169.254", "fe80::1"]:
            _, authz, resolver = _happy_path(dns_answers=[bad])
            result = _resolve(resolver, authz)
            self.assertEqual(result.failure_code, "DNS_UNSAFE_ADDRESS",
                             msg=bad)

    def test_multicast_and_reserved_denied(self):
        for bad in ["224.0.0.1", "ff02::1", "240.0.0.1", "0.0.0.0",
                    "192.0.2.1", "2001:db8::1"]:
            _, authz, resolver = _happy_path(dns_answers=[bad])
            result = _resolve(resolver, authz)
            self.assertEqual(result.failure_code, "DNS_UNSAFE_ADDRESS",
                             msg=bad)

    def test_ipv6_unique_local_denied(self):
        _, authz, resolver = _happy_path(dns_answers=["fc00::1"])
        result = _resolve(resolver, authz)
        self.assertEqual(result.failure_code, "DNS_UNSAFE_ADDRESS")

    def test_ipv4_mapped_inner_denied(self):
        _, authz, resolver = _happy_path(dns_answers=["::ffff:10.0.0.1"])
        result = _resolve(resolver, authz)
        self.assertEqual(result.failure_code, "DNS_UNSAFE_ADDRESS")

    def test_mixed_safe_unsafe_fails_whole_set(self):
        _, authz, resolver = _happy_path(dns_answers=[GOOD_IP, "10.0.0.5"])
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "RESOLUTION_FAILED")
        self.assertEqual(result.failure_code, "DNS_UNSAFE_ADDRESS")
        # No silent discard: nothing resolvable leaks out.
        self.assertEqual(result.resolved_addresses, ())
        self.assertIsNone(result.dial)

    def test_classify_address_pure_function(self):
        self.assertEqual(classify_address(GOOD_IP), GOOD_IP)
        self.assertEqual(classify_address("::ffff:8.8.8.8"), "8.8.8.8")
        with self.assertRaises(DnsError):
            classify_address("10.1.2.3")
        with self.assertRaises(DnsError):
            classify_address("garbage")
        with self.assertRaises(DnsError):
            classify_address("")
        with self.assertRaises(DnsError):
            classify_address(None)

    def test_validate_answers_order_independent(self):
        first = validate_answers([GOOD_IP_2, GOOD_IP])
        second = validate_answers([GOOD_IP, GOOD_IP_2, GOOD_IP])
        self.assertEqual(first, second)


# ------------------------------------------------------------------
# E. Authorization binding
# ------------------------------------------------------------------


class TestAuthorizationBinding(unittest.TestCase):
    def test_valid_live_authorization_resolves(self):
        _, authz, resolver = _happy_path()
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.authorization_id,
                         authz.authorization_id)

    def test_expired_authorization_refused(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme", host="target.example.com",
                       scopes=["example.com"], expiry="2020-01-01T00:00:00+00:00",
                       now="2019-01-01T00:00:00+00:00")
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com")
        resolver = _resolver(repo, {"target.example.com": [GOOD_IP]})
        from ai.schemas.evidence import EvidenceError

        with self.assertRaises(EvidenceError) as ctx:
            _resolve(resolver, authz, now=NOW)
        self.assertIn("AUTHZ_NOT_LIVE", str(ctx.exception))

    def test_consumed_authorization_never_resolves_again(self):
        store, authz, resolver = _happy_path()
        first = _resolve(resolver, authz)
        self.assertEqual(first.status, "RESOLVED")
        consume_authorization(store, authz.authorization_id, now=NOW)
        refreshed = store.get(authz.authorization_id)
        self.assertEqual(refreshed.lifecycle, "CONSUMED")
        from ai.schemas.evidence import EvidenceError

        with self.assertRaises(EvidenceError) as ctx:
            _resolve(resolver, refreshed)
        self.assertIn("AUTHZ_NOT_LIVE", str(ctx.exception))

    def test_revoked_authorization_refused(self):
        store, authz, resolver = _happy_path()
        revoke_authorization(store, authz.authorization_id)
        refreshed = store.get(authz.authorization_id)
        from ai.schemas.evidence import EvidenceError

        with self.assertRaises(EvidenceError):
            _resolve(resolver, refreshed)

    def test_dict_forgery_rejected_by_type(self):
        _, authz, resolver = _happy_path()
        forged = authz.model_dump(mode="json")
        self.assertIsInstance(forged, dict)
        with self.assertRaises(TypeError):
            resolver.resolve(
                ResolutionRequest(
                    authorization=forged,  # type: ignore[arg-type]
                    execution_id=EXE_A,
                    now=NOW,
                )
            )

    def test_none_and_string_forgery_rejected(self):
        _, _, resolver = _happy_path()
        for bad in (None, "authz-" + "a" * 16, 12345):
            with self.assertRaises(TypeError):
                resolver.resolve(
                    ResolutionRequest(
                        authorization=bad,  # type: ignore[arg-type]
                        execution_id=EXE_A,
                        now=NOW,
                    )
                )

    def test_tampered_binding_surfaces_as_drift_or_gone(self):
        # A record whose binding was altered after issuance cannot ride
        # the original inventory: forged scope hash -> SCOPE_DRIFT.
        _, authz, resolver = _happy_path()
        tampered_target = authz.target.model_copy(
            update={"scope_lists_hash": "f" * 64}
        )
        tampered = authz.model_copy(update={"target": tampered_target})
        result = _resolve(resolver, tampered)
        self.assertEqual(result.status, "SCOPE_DRIFT")

    def test_wrong_execution_id_shape_rejected(self):
        _, authz, resolver = _happy_path()
        for bad in ("", "ex-short", "ex-" + "z" * 32, None, 123):
            with self.assertRaises((ResolutionError, TypeError), msg=repr(bad)):
                resolver.resolve(
                    ResolutionRequest(
                        authorization=authz, execution_id=bad, now=NOW  # type: ignore[arg-type]
                    )
                )

    def test_replay_with_new_execution_gets_new_resolution(self):
        _, authz, resolver = _happy_path()
        first = _resolve(resolver, authz, execution_id=EXE_A)
        second = _resolve(resolver, authz, execution_id=EXE_B)
        self.assertEqual(first.status, "RESOLVED")
        self.assertEqual(second.status, "RESOLVED")
        self.assertNotEqual(first.resolution_id, second.resolution_id)
        self.assertEqual(first.canonical_target_hash,
                         second.canonical_target_hash)


# ------------------------------------------------------------------
# F. Snapshot / freshness
# ------------------------------------------------------------------


class TestSnapshotFreshness(unittest.TestCase):
    def test_valid_binding_recorded(self):
        _, authz, resolver = _happy_path(snapshot=SNAP_A)
        result = _resolve(resolver, authz, snapshot=SNAP_A)
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.snapshot_ref, SNAP_A)
        self.assertEqual(result.snapshot_observed, SNAP_A)
        self.assertEqual(result.snapshot_current, SNAP_A)
        self.assertTrue(result.snapshot_match)
        self.assertFalse(result.snapshot_stale)

    def test_stale_snapshot_is_advisory_not_blocking(self):
        _, authz, resolver = _happy_path(snapshot=SNAP_A)
        # Inventory moved on; the authorized ref is stale history.
        stale_repo = _repo(program="acme", scopes=["example.com"],
                           host="target.example.com", snapshot=SNAP_B)
        stale_resolver = TargetResolver(
            inventory=stale_repo, dns=resolver._dns
        )
        result = _resolve(stale_resolver, authz, snapshot=SNAP_A)
        self.assertEqual(result.status, "RESOLVED")
        self.assertTrue(result.snapshot_stale)

    def test_mismatched_snapshot_observed(self):
        _, authz, resolver = _happy_path(snapshot=SNAP_A)
        result = _resolve(resolver, authz, snapshot=SNAP_B)
        self.assertEqual(result.status, "RESOLVED")
        self.assertFalse(result.snapshot_match)

    def test_historical_snapshot_alone_grants_nothing(self):
        # A snapshot hash without a live authorization is not a
        # resolution input at all: no typed context -> TypeError.
        _, _, resolver = _happy_path()
        with self.assertRaises(TypeError):
            resolver.resolve(
                ResolutionRequest(
                    authorization=SNAP_A,  # type: ignore[arg-type]
                    execution_id=EXE_A,
                    now=NOW,
                )
            )
        with self.assertRaises(TypeError):
            resolver.resolve({"snapshot": SNAP_A})  # type: ignore[arg-type]

    def test_absent_snapshots_stay_null(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme", host="target.example.com",
                       scopes=["example.com"], snapshot=None)
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com", snapshot=None)
        resolver = _resolver(repo, {"target.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "RESOLVED")
        self.assertIsNone(result.snapshot_ref)
        self.assertIsNone(result.snapshot_match)
        self.assertIsNone(result.snapshot_stale)


# ------------------------------------------------------------------
# G. Determinism
# ------------------------------------------------------------------


class TestDeterminism(unittest.TestCase):
    def test_same_input_same_resolution(self):
        _, authz, resolver = _happy_path()
        first = _resolve(resolver, authz)
        second = _resolve(resolver, authz)
        self.assertEqual(first.resolution_id, second.resolution_id)
        self.assertEqual(first, second)

    def test_canonical_hash_stable(self):
        left = canonical_target_hash_for(
            program_name="acme", canonical_host="target.example.com",
            scheme="https", effective_port=443)
        right = canonical_target_hash_for(
            program_name="acme", canonical_host="target.example.com",
            scheme="https", effective_port=443)
        self.assertEqual(left, right)
        self.assertRegex(left, r"^[0-9a-f]{64}$")

    def test_dns_order_does_not_change_identity(self):
        _, authz, first_resolver = _happy_path(
            dns_answers=[GOOD_IP, GOOD_IP_2])
        _, _, second_resolver = _happy_path(
            dns_answers=[GOOD_IP_2, GOOD_IP])
        first = _resolve(first_resolver, authz)
        second = _resolve(second_resolver, authz)
        self.assertEqual(first.resolution_id, second.resolution_id)

    def test_scope_list_order_does_not_change_hash(self):
        self.assertEqual(
            scope_lists_hash_for(["b.com", "a.com"], []),
            scope_lists_hash_for(["a.com", "b.com"], []),
        )

    def test_resolution_id_changes_with_binding(self):
        _, authz, resolver = _happy_path()
        base = _resolve(resolver, authz)
        other_exe = _resolve(resolver, authz, execution_id=EXE_B)
        self.assertNotEqual(base.resolution_id, other_exe.resolution_id)


# ------------------------------------------------------------------
# H. Error safety
# ------------------------------------------------------------------


class TestErrorSafety(unittest.TestCase):
    def test_raw_adapter_exceptions_collapse(self):
        class ExplodingDns:
            name = "exploding/v1"

            def resolve(self, host):
                raise RuntimeError("mongodb://admin:s3cret@db:27017 boom")

        _, authz, resolver = _happy_path()
        collapsing = TargetResolver(
            inventory=resolver._inventory, dns=ExplodingDns()  # type: ignore[arg-type]
        )
        result = _resolve(collapsing, authz)
        self.assertEqual(result.status, "RESOLUTION_FAILED")
        self.assertEqual(result.failure_code, "DNS_RESOLUTION_FAILED")
        dumped = result.model_dump_json()
        self.assertNotIn("s3cret", dumped)
        self.assertNotIn("mongodb://", dumped)
        self.assertNotIn("boom", dumped)

    def test_dns_error_codes_closed(self):
        with self.assertRaises(ValueError):
            DnsError("NOT_A_CODE")
        err = DnsError("DNS_TIMEOUT")
        self.assertEqual(err.code, "DNS_TIMEOUT")

    def test_resolution_error_secret_screened(self):
        with self.assertRaises(ValueError):
            ResolutionError("DNS_TIMEOUT", "token bearer abc123")
        with self.assertRaises(ValueError):
            ResolutionError("DNS_TIMEOUT", "line1\nline2")

    def test_resolution_error_codes_closed(self):
        with self.assertRaises(ValueError):
            ResolutionError("MADE_UP")
        err = ResolutionError("DNS_NXDOMAIN", "static context")
        self.assertIn("DNS_NXDOMAIN", str(err))

    def test_failure_records_bounded_and_secret_free(self):
        answers = ["10.9.9.%d" % i for i in range(1, 10)]
        _, authz, resolver = _happy_path(dns_answers=answers)
        result = _resolve(resolver, authz)
        dumped = result.model_dump_json()
        self.assertLessEqual(len(dumped), 4096)
        for marker in ("password", "secret", "mongodb://", "bearer "):
            self.assertNotIn(marker, dumped.casefold())


# ------------------------------------------------------------------
# I. Immutability / no rebind
# ------------------------------------------------------------------


class TestImmutability(unittest.TestCase):
    def test_resolution_is_frozen(self):
        _, authz, resolver = _happy_path()
        result = _resolve(resolver, authz)
        with self.assertRaises(ValidationError):
            result.canonical_host = "evil.example.com"  # type: ignore[misc]
        with self.assertRaises(ValidationError):
            result.program_name = "other"  # type: ignore[misc]
        with self.assertRaises(ValidationError):
            result.resolved_addresses = ("9.9.9.9",)  # type: ignore[misc]
        with self.assertRaises(ValidationError):
            result.authorization_id = "authz-" + "f" * 16  # type: ignore[misc]
        with self.assertRaises(ValidationError):
            result.status = "RESOLVED"  # type: ignore[misc]

    def test_dial_binding_is_frozen(self):
        _, authz, resolver = _happy_path()
        result = _resolve(resolver, authz)
        assert result.dial is not None
        with self.assertRaises(ValidationError):
            result.dial.sni_host = "evil.example.com"  # type: ignore[misc]

    def test_no_rebind_api(self):
        for name in ("replace_target", "set_host", "rebind", "update",
                     "replace_ip", "replace_program", "replace_authorization",
                     "mutate", "with_target"):
            self.assertFalse(hasattr(TargetResolution, name), msg=name)
        _, authz, resolver = _happy_path()
        result = _resolve(resolver, authz)
        for name in ("replace_target", "rebind", "update"):
            self.assertFalse(hasattr(result, name), msg=name)

    def test_new_target_requires_new_resolution(self):
        store, authz, resolver = _happy_path()
        first = _resolve(resolver, authz)
        second = _resolve(resolver, authz, execution_id=EXE_B)
        self.assertNotEqual(first.resolution_id, second.resolution_id)
        # The first record is untouched by the second resolution.
        self.assertEqual(first.execution_id, EXE_A)


# ------------------------------------------------------------------
# J. Boundary (no verdict fields)
# ------------------------------------------------------------------


class TestBoundary(unittest.TestCase):
    def test_no_verdict_or_scope_fields(self):
        for model in (TargetResolution, DialBinding):
            overlap = FORBIDDEN_RESOLUTION_FIELDS.intersection(
                set(model.model_fields)
            )
            self.assertEqual(overlap, set(), msg=model.__name__)
        _, authz, resolver = _happy_path()
        result = _resolve(resolver, authz)
        payload = result.model_dump()
        for forbidden in FORBIDDEN_RESOLUTION_FIELDS:
            self.assertNotIn(forbidden, payload)

    def test_scope_view_has_facts_only(self):
        _, authz, resolver = _happy_path()
        result = _resolve(resolver, authz)
        view = result.scope_view()
        for forbidden in FORBIDDEN_RESOLUTION_FIELDS:
            self.assertNotIn(forbidden, view)
        for required in ("program_name", "canonical_host", "scheme",
                         "effective_port", "resolved_addresses",
                         "scope_lists_hash_current", "snapshot_current",
                         "dns_answer_count", "resolution_id",
                         "authorization_id", "execution_id", "status"):
            self.assertIn(required, view)

    def test_extra_fields_forbidden(self):
        _, authz, resolver = _happy_path()
        result = _resolve(resolver, authz)
        with self.assertRaises(ValidationError):
            TargetResolution(
                **{**result.model_dump(), "scope_allowed": True}
            )
        with self.assertRaises(ValidationError):
            TargetResolution(
                **{**result.model_dump(), "verdict": "x"}
            )


# ------------------------------------------------------------------
# K. Network isolation (static, source-level)
# ------------------------------------------------------------------


class TestNetworkIsolation(unittest.TestCase):
    RESOLVER_FILES = (
        "ai/resolver/__init__.py",
        "ai/resolver/canonicalization.py",
        "ai/resolver/dns.py",
        "ai/resolver/inventory.py",
        "ai/resolver/resolver.py",
        "ai/schemas/target_resolution.py",
    )

    BANNED_IMPORTS = (
        "socket", "requests", "httpx", "urllib", "subprocess", "ssl",
        "dns", "dnspython", "playwright", "selenium", "pymongo",
        "mongoengine", "openai", "openrouter", "anthropic", "curl",
        "wget", "nuclei", "browser",
    )

    IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([a-zA-Z0-9_]+)")

    def test_no_live_network_or_llm_imports(self):
        root = Path(__file__).resolve().parent.parent
        for rel in self.RESOLVER_FILES:
            text = (root / rel).read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), start=1):
                match = self.IMPORT_RE.match(line)
                if not match:
                    continue
                module = match.group(1)
                self.assertNotIn(
                    module, self.BANNED_IMPORTS,
                    msg=f"{rel}:{lineno}: banned import {module!r}",
                )

    def test_no_database_driver_reference(self):
        root = Path(__file__).resolve().parent.parent
        for rel in self.RESOLVER_FILES:
            text = (root / rel).read_text(encoding="utf-8")
            self.assertNotIn("mongoengine", text, msg=rel)
            self.assertNotIn("pymongo", text, msg=rel)


# ------------------------------------------------------------------
# Adversarial suite (18 hostile cases, all must fail closed)
# ------------------------------------------------------------------


class TestAdversarial(unittest.TestCase):
    def _resolve_host(self, authz_host, inventory_host=None,
                      dns_answers=(GOOD_IP,), scopes=("example.com",)):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme", host=authz_host,
                       scopes=list(scopes))
        target_host = inventory_host or "target.example.com"
        repo = _repo(program="acme", scopes=list(scopes), host=target_host)
        resolver = _resolver(repo, {target_host: list(dns_answers)})
        return _resolve(resolver, authz)

    def test_01_unicode_confusion(self):
        # Lookalike Unicode host must not canonicalize to the real slot.
        result = self._resolve_host("tаrget.example.com")  # Cyrillic 'а'
        self.assertNotEqual(result.canonical_host, "target.example.com")
        self.assertEqual(result.status, "TARGET_GONE")

    def test_02_trailing_dot_bypass(self):
        result = self._resolve_host("target.example.com.",
                                    inventory_host="target.example.com")
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.canonical_host, "target.example.com")

    def test_03_case_mismatch(self):
        result = self._resolve_host("TARGET.EXAMPLE.COM",
                                    inventory_host="target.example.com")
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.canonical_host, "target.example.com")

    def test_04_ipv6_textual_variants(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme",
                       host="2606:4700:4700:0000:0000:0000:0000:1111",
                       scopes=["example.com"])
        repo = _repo(program="acme", scopes=["example.com"],
                     host="2606:4700:4700::1111", scheme="https", port=443)
        resolver = _resolver(
            repo, {"2606:4700:4700::1111": ["2606:4700:4700::1111"]})
        result = _resolve(resolver, authz)
        # Global unicast v6 textual variants converge to one identity.
        self.assertEqual(result.canonical_host, "2606:4700:4700::1111")
        self.assertEqual(result.status, "RESOLVED")

    def test_05_ipv4_mapped_ipv6(self):
        # ::ffff:10.0.0.1 unfolds to private IPv4 and dies at DNS safety.
        self.assertEqual(
            self._resolve_host("::ffff:10.0.0.1",
                               inventory_host="10.0.0.1",
                               dns_answers=["::ffff:10.0.0.1"]).failure_code,
            "DNS_UNSAFE_ADDRESS",
        )

    def test_06_localhost_aliases(self):
        for alias in ("localhost",):
            store = InMemoryAuthorizationStore()
            authz = _issue(store, program="acme", host=alias,
                           scopes=["example.com"])
            repo = _repo(program="acme", scopes=["example.com"], host=alias)
            resolver = _resolver(repo, {alias: ["127.0.0.1"]})
            result = _resolve(resolver, authz)
            self.assertEqual(result.status, "RESOLUTION_FAILED")
            self.assertEqual(result.failure_code, "DNS_UNSAFE_ADDRESS")

    def test_07_private_ip_via_dns(self):
        result = self._resolve_host("target.example.com",
                                    dns_answers=["93.184.216.34", "10.9.9.9"])
        self.assertEqual(result.status, "RESOLUTION_FAILED")
        self.assertEqual(result.failure_code, "DNS_UNSAFE_ADDRESS")

    def test_08_dns_rebinding_model(self):
        # First answer pins; a second resolution observing rotation gets
        # a DIFFERENT resolution id (never silently the same target).
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme", host="target.example.com",
                       scopes=["example.com"])
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com")
        first = _resolve(
            _resolver(repo, {"target.example.com": [GOOD_IP]}), authz)
        second = _resolve(
            _resolver(repo, {"target.example.com": [GOOD_IP_2]}), authz)
        self.assertEqual(first.status, "RESOLVED")
        self.assertEqual(second.status, "RESOLVED")
        self.assertEqual(first.resolved_addresses, (GOOD_IP,))
        self.assertEqual(second.resolved_addresses, (GOOD_IP_2,))
        self.assertNotEqual(first.resolution_id, second.resolution_id)
        # And the dial binding pins exactly what was resolved.
        assert first.dial is not None
        self.assertEqual(first.dial.addresses, (GOOD_IP,))
        self.assertTrue(first.dial.pin_required)
        self.assertEqual(first.dial.sni_host, "target.example.com")

    def test_09_too_many_dns_answers(self):
        answers = ["45.1.1.%d" % i for i in range(1, 12)]
        result = self._resolve_host("target.example.com", dns_answers=answers)
        self.assertEqual(result.failure_code, "DNS_TOO_MANY_ANSWERS")

    def test_10_cross_program_same_host(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="prog-a", host="shared.example.com",
                       scopes=["example.com"])
        repo = InMemoryInventoryRepository(
            programs=[
                ProgramRecord(program_name="prog-a", scopes=("example.com",)),
                ProgramRecord(program_name="prog-b", scopes=("example.com",)),
            ],
            assets=[
                AssetRecord(program_name="prog-b",
                            canonical_host="shared.example.com"),
            ],
        )
        resolver = _resolver(repo, {"shared.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        # prog-a has no row: TARGET_GONE, never prog-b's row.
        self.assertEqual(result.status, "TARGET_GONE")

    def test_11_stale_target_intelligence(self):
        # A stale snapshot hash authorizes nothing: resolution still
        # requires live inventory + live DNS observation.
        _, authz, resolver = _happy_path(snapshot=SNAP_A)
        result = _resolve(resolver, authz, snapshot="d" * 64)
        self.assertEqual(result.status, "RESOLVED")
        self.assertFalse(result.snapshot_match)
        # ...and without the authorization itself, nothing resolves.
        with self.assertRaises(TypeError):
            resolver.resolve(
                ResolutionRequest(
                    authorization={"snapshot_hash": "d" * 64},  # type: ignore[arg-type]
                    execution_id=EXE_A,
                    now=NOW,
                )
            )

    def test_12_forged_authorization(self):
        _, authz, resolver = _happy_path()
        # Shape-alike dict forgery dies by type.
        with self.assertRaises(TypeError):
            resolver.resolve(
                ResolutionRequest(
                    authorization=authz.model_dump(mode="json"),  # type: ignore[arg-type]
                    execution_id=EXE_A,
                    now=NOW,
                )
            )
        # Binding forgery surfaces as drift (never silent success on
        # the attacker's terms).
        tampered = authz.model_copy(
            update={"target": authz.target.model_copy(
                update={"host": "evil.example.com"})}
        )
        result = _resolve(resolver, tampered)
        self.assertIn(result.status, ("TARGET_GONE", "SCOPE_DRIFT",
                                      "RESOLUTION_FAILED"))

    def test_13_consumed_authorization_replay(self):
        store, authz, resolver = _happy_path()
        _resolve(resolver, authz, execution_id=EXE_A)
        consume_authorization(store, authz.authorization_id, now=NOW)
        replayed = store.get(authz.authorization_id)
        from ai.schemas.evidence import EvidenceError

        with self.assertRaises(EvidenceError) as ctx:
            _resolve(resolver, replayed, execution_id=EXE_B)
        self.assertIn("AUTHZ_NOT_LIVE", str(ctx.exception))

    def test_14_sibling_host_redirect_metadata(self):
        # A sibling host is a different slot: authorizing www does not
        # resolve api, even inside one registrable domain.
        result = self._resolve_host("api.example.com",
                                    inventory_host="target.example.com")
        self.assertEqual(result.status, "TARGET_GONE")

    def test_15_arbitrary_host_header(self):
        # Resolver input comes only from the authorized binding; there
        # is no Host-header parameter anywhere in the request shape.
        _, authz, resolver = _happy_path()
        request = ResolutionRequest(
            authorization=authz, execution_id=EXE_A, now=NOW)
        self.assertFalse(hasattr(request, "host_header"))
        self.assertFalse(hasattr(request, "host"))
        with self.assertRaises(TypeError):
            resolver.resolve(
                {"authorization": authz, "host_header": "evil.com",  # type: ignore[arg-type]
                 "execution_id": EXE_A, "now": NOW}
            )

    def test_16_malformed_ports(self):
        store = InMemoryAuthorizationStore()
        for bad_port in (0, 70000):
            with self.assertRaises(Exception, msg=repr(bad_port)):
                _issue(store, program="acme", host="target.example.com",
                       scopes=["example.com"], port=bad_port)

    def test_17_scheme_confusion(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme", host="target.example.com",
                       scopes=["example.com"], scheme="https", port=443)
        # Inventory moved to plaintext http: reassignment, never a
        # silent scheme downgrade inside a RESOLVED record.
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com", scheme="http", port=80)
        resolver = _resolver(repo, {"target.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "TARGET_REASSIGNED")
        self.assertTrue(result.reassigned)

    def test_18_credentials_in_target(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme",
                       host="admin:s3cret@target.example.com",
                       scopes=["example.com"])
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com")
        resolver = _resolver(repo, {"target.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "RESOLUTION_FAILED")
        self.assertEqual(result.failure_code, "TARGET_MALFORMED")
        self.assertNotIn("s3cret", result.model_dump_json())


# ------------------------------------------------------------------
# Scope drift / reassignment / gone outcomes
# ------------------------------------------------------------------


class TestInventoryOutcomes(unittest.TestCase):
    def test_target_gone(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme", host="gone.example.com",
                       scopes=["example.com"])
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com")
        resolver = _resolver(repo, {"gone.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "TARGET_GONE")
        self.assertIsNone(result.failure_code)

    def test_program_gone(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="vanished", host="target.example.com",
                       scopes=["example.com"])
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com")
        resolver = _resolver(repo, {"target.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "TARGET_PROGRAM_GONE")

    def test_scope_drift(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme", host="target.example.com",
                       scopes=["example.com"])
        repo = _repo(program="acme", scopes=["example.com", "added.com"],
                     host="target.example.com")
        resolver = _resolver(repo, {"target.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "SCOPE_DRIFT")
        self.assertTrue(result.scope_drift)
        self.assertEqual(result.resolved_addresses, ())

    def test_reassigned_port(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="acme", host="target.example.com",
                       scopes=["example.com"], scheme="https", port=443)
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com", scheme="https", port=8443)
        resolver = _resolver(repo, {"target.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz)
        self.assertEqual(result.status, "TARGET_REASSIGNED")

    def test_historical_ips_never_authority(self):
        # Inventory remembers stale IPs; fresh DNS disagrees. The pinned
        # binding follows FRESH observation, never the remembered list.
        _, authz, _ = _happy_path()
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com", snapshot=SNAP_A,
                     ips=("10.99.99.99", "192.0.2.99"))
        resolver = _resolver(repo, {"target.example.com": [GOOD_IP]})
        result = _resolve(resolver, authz, snapshot=SNAP_A)
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.resolved_addresses, (GOOD_IP,))
        assert result.dial is not None
        self.assertNotIn("10.99.99.99", result.dial.addresses)

    def test_resolved_record_shape(self):
        _, authz, resolver = _happy_path()
        result = _resolve(resolver, authz)
        self.assertEqual(result.base_authority, "https://target.example.com")
        self.assertEqual(result.dns_source, "fake-dns/v1")
        self.assertEqual(result.resolver_version, "target-resolver/v1")
        self.assertRegex(result.resolution_id, r"^res-[0-9a-f]{16}$")
        self.assertRegex(result.canonical_target_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(result.resolved_at, NOW)
        expected_id = resolution_id_for(
            authorization_id=authz.authorization_id,
            execution_id=EXE_A,
            canonical_target_hash=result.canonical_target_hash,
            resolved_addresses=result.resolved_addresses,
            scope_lists_hash_current=result.scope_lists_hash_current,
            snapshot_current=result.snapshot_current,
        )
        self.assertEqual(result.resolution_id, expected_id)


class TestInventoryRecords(unittest.TestCase):
    def test_non_canonical_asset_rejected(self):
        with self.assertRaises(InventoryError):
            AssetRecord(program_name="acme", canonical_host="UPPER.com")

    def test_asset_requires_pair_shape(self):
        with self.assertRaises(InventoryError):
            AssetRecord(program_name="", canonical_host="target.example.com")

    def test_repository_has_no_write_surface(self):
        repo = _repo(program="acme", scopes=["example.com"],
                     host="target.example.com")
        for name in ("put", "save", "insert", "update", "delete", "upsert",
                     "add_program", "add_asset", "learn"):
            self.assertFalse(hasattr(repo, name), msg=name)

    def test_unknown_dns_error_code_rejected(self):
        with self.assertRaises(ValueError):
            FakeDnsFailure("NOPE")


if __name__ == "__main__":
    unittest.main()
