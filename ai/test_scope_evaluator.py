"""Focused Phase 5D ScopeEvaluator tests (offline, deterministic).

Covers the 5D contract only: strict policy compilation, exact-host
and label-aware wildcard matching, absolute exclusion, program
isolation, scheme/port defaults, dual address gating, live
authorization + resolution binding, scope drift, pure redirect
per-hop evaluation, canonicalization reuse, immutability, boundary
prohibitions, dependency isolation, eTLD+1 absence, and 30 hostile
adversarial cases.

No network, no DNS, no subprocess, no database, no LLM, no
executors, no verifiers, no findings, no live transport.
"""

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
    FakeDnsResolver,
    InMemoryInventoryRepository,
    ProgramRecord,
    TargetResolver,
    scope_lists_hash_for,
)
from ai.schemas.artifact import artifact_id_for
from ai.schemas.execution_authorization import (
    ArtifactBinding,
    AuthorizationRequest,
    TargetBinding,
)
from ai.schemas.scope_evaluation import (
    FORBIDDEN_SCOPE_FIELDS,
    ScopeError,
    ScopeEvaluation,
    evaluation_id_for,
)
from ai.schemas.target_resolution import DialBinding
from ai.schemas.target_resolution import ResolutionRequest
from ai.scope import (
    MAX_POLICY_ENTRIES,
    HopObservation,
    InMemoryPolicyStore,
    PolicyError,
    ScopeEvaluator,
    compile_entry,
    compile_policy,
    require_allowed,
)
from ai.scope.matcher import (
    match_exclusions,
    match_inclusions,
    match_rule,
)

NOW = "2026-06-01T00:00:00+00:00"
EXPIRY = "2030-01-01T00:00:00+00:00"
EXE_A = "ex-" + "a" * 32
EXE_B = "ex-" + "b" * 32
GOOD_IP = "93.184.216.34"
GOOD_IP_2 = "1.1.1.1"

_TP_COUNTER = 1000


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
    return (
        ArtifactBinding(
            artifact_id=artifact_id,
            artifact_type="http_request_spec",
            content_hash=content_hash,
            test_plan_id=tp_id,
        ),
        tp_id,
    )


def _issue(store, *, program, host, scheme="https", port=443, scopes,
           ooscopes=(), execution_class="http_probe", expiry=EXPIRY,
           now=NOW):
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
        ),
        execution_class=execution_class,
        expires_at=expiry,
    )
    return issue_authorization(store, request, now=now)


def _world(*, program="acme", host="target.example.com", scopes,
           ooscopes=(), scheme="https", port=443,
           execution_class="http_probe", dns_answers=(GOOD_IP,),
           inv_scopes=None, inv_ooscopes=None, inv_scheme=None,
           inv_port=None, execution_id=EXE_A, now=NOW):
    """Genuine 5B authz + 5C resolution + 5D evaluator, all consistent."""
    store = InMemoryAuthorizationStore()
    authz = _issue(
        store, program=program, host=host, scheme=scheme, port=port,
        scopes=list(scopes), ooscopes=list(ooscopes),
        execution_class=execution_class,
    )
    from ai.resolver.canonicalization import canonicalize_target

    authority = canonicalize_target(host, scheme, port)
    repo = InMemoryInventoryRepository(
        programs=[
            ProgramRecord(
                program_name=program,
                scopes=tuple(
                    inv_scopes if inv_scopes is not None else scopes
                ),
                ooscopes=tuple(
                    inv_ooscopes if inv_ooscopes is not None else ooscopes
                ),
            )
        ],
        assets=[
            AssetRecord(
                program_name=program,
                canonical_host=authority.canonical_host,
                scheme=inv_scheme or authority.scheme,
                effective_port=(
                    inv_port
                    if inv_port is not None
                    else authority.effective_port
                ),
            )
        ],
    )
    resolver = TargetResolver(
        inventory=repo,
        dns=FakeDnsResolver({authority.canonical_host: list(dns_answers)}),
    )
    resolution = resolver.resolve(
        ResolutionRequest(
            authorization=authz, execution_id=execution_id, now=now
        )
    )
    assert resolution.status == "RESOLVED", resolution
    evaluator = ScopeEvaluator(
        policy_store=InMemoryPolicyStore(
            {program: (list(scopes), list(ooscopes))}
        )
    )
    return store, authz, resolution, evaluator


def _world_unresolved(*, program="acme", host, scopes, ooscopes=(),
                      execution_id=EXE_A, now=NOW):
    """Same as _world but without the RESOLVED assertion.

    For hostile inputs the 5C gate itself fails closed; the 5D
    assertion is then that the evaluator additionally refuses the
    non-RESOLVED record (defense in depth, never a bypass).
    """
    store = InMemoryAuthorizationStore()
    authz = _issue(
        store, program=program, host=host, scopes=list(scopes),
        ooscopes=list(ooscopes),
    )
    from ai.resolver.canonicalization import canonicalize_target

    try:
        authority = canonicalize_target(host, "https", 443)
        canonical = authority.canonical_host
    except Exception:
        canonical = host
    repo = InMemoryInventoryRepository(
        programs=[
            ProgramRecord(
                program_name=program,
                scopes=tuple(scopes),
                ooscopes=tuple(ooscopes),
            )
        ],
        assets=(
            [
                AssetRecord(
                    program_name=program,
                    canonical_host=canonical,
                )
            ]
            if "@" not in host and " " not in host and host
            else []
        ),
    )
    resolver = TargetResolver(
        inventory=repo,
        dns=FakeDnsResolver({canonical: [GOOD_IP]}),
    )
    resolution = resolver.resolve(
        ResolutionRequest(
            authorization=authz, execution_id=execution_id, now=now
        )
    )
    evaluator = ScopeEvaluator(
        policy_store=InMemoryPolicyStore(
            {program: (list(scopes), list(ooscopes))}
        )
    )
    return store, authz, resolution, evaluator


def _evaluate(evaluator, authz, resolution, execution_id=EXE_A, now=NOW):
    return evaluator.evaluate(
        authz, resolution, execution_id=execution_id, now=now
    )


# ------------------------------------------------------------------
# A. Policy compilation
# ------------------------------------------------------------------


class TestPolicyCompilation(unittest.TestCase):
    def test_valid_exact_host(self):
        policy = compile_policy(
            program_name="acme", scopes=["example.com"], ooscopes=[]
        )
        self.assertEqual(len(policy.inclusions), 1)
        rule = policy.inclusions[0]
        self.assertEqual(rule.kind, "exact")
        self.assertEqual(rule.host, "example.com")
        self.assertEqual(rule.text, "example.com")

    def test_valid_wildcard(self):
        policy = compile_policy(
            program_name="acme", scopes=["*.example.com"], ooscopes=[]
        )
        rule = policy.inclusions[0]
        self.assertEqual(rule.kind, "wildcard")
        self.assertEqual(rule.host, "example.com")
        self.assertEqual(rule.text, "*.example.com")

    def test_canonicalization_at_compile(self):
        policy = compile_policy(
            program_name="acme",
            scopes=["Example.COM.", "API.Example.COM"],
            ooscopes=[],
        )
        texts = sorted(rule.text for rule in policy.inclusions)
        self.assertEqual(texts, ["api.example.com", "example.com"])

    def test_malformed_entries_fail_policy_closed(self):
        bad_entries = [
            "", "   ", "under_score.example.com", "-lead.example.com",
            "a..b.com", "trail-.example.com", "user@example.com",
            "http://example.com", "example.com/path", "example.com:443",
            "example.com?x=1", "93.184.216.34", "10.0.0.1", "::1",
            "127.1", "0x7f.0.0.1", "10.0.0.0/8", "192.168.0.0/16",
            "*.*.example.com", "api.*.example.com", "*example.com",
            "*.", "*", "*.com", "localhost", "singlelabel",
            "targ\ret.example.com", "targ\x00et.example.com",
            "*.under_score.example.com", "*.a..b.com",
        ]
        for bad in bad_entries:
            with self.subTest(entry=bad):
                with self.assertRaises(PolicyError) as ctx:
                    compile_policy(
                        program_name="acme", scopes=[bad], ooscopes=[]
                    )
                self.assertEqual(ctx.exception.code, "SCOPE_POLICY_INVALID")
                # Hostile entry text never reflected.
                self.assertNotIn(bad.strip()[:8] if bad.strip() else "X",
                                 str(ctx.exception))

    def test_malformed_ooscope_fails_whole_policy(self):
        with self.assertRaises(PolicyError):
            compile_policy(
                program_name="acme",
                scopes=["example.com"],
                ooscopes=["not an entry!!"],
            )

    def test_no_best_effort_partial_compile(self):
        # One bad entry poisons the batch: no partial policy escapes.
        with self.assertRaises(PolicyError):
            compile_policy(
                program_name="acme",
                scopes=["example.com", ""],
                ooscopes=[],
            )

    def test_entry_ceiling_enforced(self):
        many = ["h%d.example.com" % i for i in range(MAX_POLICY_ENTRIES + 1)]
        with self.assertRaises(PolicyError):
            compile_policy(
                program_name="acme", scopes=many, ooscopes=[]
            )
        self.assertEqual(MAX_POLICY_ENTRIES, 1024)
        ok = ["h%d.example.com" % i for i in range(MAX_POLICY_ENTRIES)]
        policy = compile_policy(
            program_name="acme", scopes=ok, ooscopes=[]
        )
        self.assertEqual(len(policy.inclusions), MAX_POLICY_ENTRIES)

    def test_policy_hash_reuses_5c_function(self):
        policy = compile_policy(
            program_name="acme",
            scopes=["b.example.com", "a.example.com"],
            ooscopes=["x.example.com"],
        )
        self.assertEqual(
            policy.scope_lists_hash,
            scope_lists_hash_for(
                ("b.example.com", "a.example.com"), ("x.example.com",)
            ),
        )
        # Order-independent, like the 5B/5C basis.
        other = compile_policy(
            program_name="acme",
            scopes=["a.example.com", "b.example.com"],
            ooscopes=["x.example.com"],
        )
        self.assertEqual(policy.scope_lists_hash, other.scope_lists_hash)

    def test_idna_entry_compiled(self):
        policy = compile_policy(
            program_name="acme", scopes=["münchen.de"], ooscopes=[]
        )
        self.assertEqual(policy.inclusions[0].host, "xn--mnchen-3ya.de")

    def test_compile_entry_source_typed(self):
        with self.assertRaises(TypeError):
            compile_entry("example.com", "bogus")


# ------------------------------------------------------------------
# B. Exact host
# ------------------------------------------------------------------


class TestExactHost(unittest.TestCase):
    def _eval(self, host):
        _, authz, resolution, evaluator = _world(
            host=host, scopes=["example.com"]
        )
        return _evaluate(evaluator, authz, resolution)

    def test_exact_match_allowed(self):
        result = self._eval("example.com")
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(result.include_rule, "example.com")
        self.assertIsNone(result.exclude_rule)
        self.assertIsNone(result.failure_code)

    def test_subhosts_denied(self):
        for host in ("www.example.com", "api.example.com",
                     "foo.api.example.com", "deep.a.b.example.com"):
            with self.subTest(host=host):
                result = self._eval(host)
                self.assertEqual(result.decision, "DENIED")
                self.assertEqual(result.failure_code, "TARGET_NOT_IN_SCOPE")

    def test_lookalike_denied(self):
        result = self._eval("evil-example.com")
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "TARGET_NOT_IN_SCOPE")


# ------------------------------------------------------------------
# C. Wildcard
# ------------------------------------------------------------------


class TestWildcard(unittest.TestCase):
    def _eval(self, host):
        _, authz, resolution, evaluator = _world(
            host=host, scopes=["*.example.com"]
        )
        return _evaluate(evaluator, authz, resolution)

    def test_one_label_allowed(self):
        for host in ("api.example.com", "foo.example.com", "a.example.com"):
            with self.subTest(host=host):
                result = self._eval(host)
                self.assertEqual(result.decision, "ALLOWED")
                self.assertEqual(result.include_rule, "*.example.com")

    def test_apex_denied(self):
        result = self._eval("example.com")
        self.assertEqual(result.decision, "DENIED")

    def test_depth_denied(self):
        result = self._eval("foo.api.example.com")
        self.assertEqual(result.decision, "DENIED")

    def test_suffix_lookalike_denied(self):
        result = self._eval("evil-example.com")
        self.assertEqual(result.decision, "DENIED")


# ------------------------------------------------------------------
# D. Program isolation
# ------------------------------------------------------------------


class TestProgramIsolation(unittest.TestCase):
    def test_same_host_never_uses_other_policy(self):
        store = InMemoryAuthorizationStore()
        authz_a = _issue(store, program="prog-a", host="example.com",
                         scopes=["example.com"])
        authz_b = _issue(store, program="prog-b", host="example.com",
                         scopes=["other.com"])
        _, _, resolution_a, _ = _world(program="prog-a", host="example.com",
                                       scopes=["example.com"])
        _ = authz_a, resolution_a
        # prog-b's policy (other.com) must DENY example.com even though
        # prog-a would allow it: evaluation is pair-keyed.
        store_b = InMemoryAuthorizationStore()
        authz_b2 = _issue(store_b, program="prog-b", host="example.com",
                          scopes=["other.com"])
        from ai.resolver.canonicalization import canonicalize_target

        authority = canonicalize_target("example.com", "https", 443)
        repo = InMemoryInventoryRepository(
            programs=[ProgramRecord(program_name="prog-b",
                                    scopes=("other.com",))],
            assets=[AssetRecord(program_name="prog-b",
                                canonical_host="example.com")],
        )
        resolver = TargetResolver(
            inventory=repo, dns=FakeDnsResolver({"example.com": [GOOD_IP]})
        )
        resolution_b = resolver.resolve(
            ResolutionRequest(authorization=authz_b2, execution_id=EXE_A,
                              now=NOW)
        )
        self.assertEqual(resolution_b.status, "RESOLVED")
        evaluator = ScopeEvaluator(
            policy_store=InMemoryPolicyStore(
                {
                    "prog-a": (["example.com"], []),
                    "prog-b": (["other.com"], []),
                }
            )
        )
        result = _evaluate(evaluator, authz_b2, resolution_b)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.program_name, "prog-b")

    def test_unknown_program_denied(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        lonely = ScopeEvaluator(policy_store=InMemoryPolicyStore({}))
        result = _evaluate(lonely, authz, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "PROGRAM_NOT_FOUND")

    def test_no_host_keyed_lookup(self):
        store_obj = InMemoryPolicyStore({"acme": (["example.com"], [])})
        self.assertFalse(hasattr(store_obj, "get_scope"))
        self.assertFalse(hasattr(store_obj, "get_policy_for_host"))
        with self.assertRaises(TypeError):
            store_obj.get_policy(12345)  # type: ignore[arg-type]


# ------------------------------------------------------------------
# E. Exclusion (absolute)
# ------------------------------------------------------------------


class TestExclusion(unittest.TestCase):
    def test_wildcard_in_exact_out_denied(self):
        _, authz, resolution, evaluator = _world(
            host="admin.example.com",
            scopes=["*.example.com"],
            ooscopes=["admin.example.com"],
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "TARGET_EXCLUDED")
        self.assertEqual(result.exclude_rule, "admin.example.com")
        self.assertEqual(result.include_rule, "*.example.com")

    def test_exact_in_exact_out_denied(self):
        _, authz, resolution, evaluator = _world(
            host="example.com",
            scopes=["example.com"],
            ooscopes=["example.com"],
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "TARGET_EXCLUDED")

    def test_wildcard_out_spares_apex(self):
        # OUT *.example.com does not match the apex: apex stays allowed,
        # subhosts denied. No specificity games — pure label matching.
        _, authz, resolution, evaluator = _world(
            host="example.com",
            scopes=["example.com"],
            ooscopes=["*.example.com"],
        )
        apex = _evaluate(evaluator, authz, resolution)
        self.assertEqual(apex.decision, "ALLOWED")
        _, authz2, resolution2, evaluator2 = _world(
            host="www.example.com",
            scopes=["example.com", "*.example.com"],
            ooscopes=["*.example.com"],
        )
        sub = _evaluate(evaluator2, authz2, resolution2)
        self.assertEqual(sub.decision, "DENIED")
        self.assertEqual(sub.failure_code, "TARGET_EXCLUDED")

    def test_non_matching_exclusion_allows(self):
        _, authz, resolution, evaluator = _world(
            host="api.example.com",
            scopes=["*.example.com"],
            ooscopes=["admin.example.com"],
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")


# ------------------------------------------------------------------
# F/G. Scheme / port
# ------------------------------------------------------------------


class TestSchemePort(unittest.TestCase):
    def test_http_and_https_supported(self):
        for scheme in ("http", "https"):
            _, authz, resolution, evaluator = _world(
                host="example.com", scopes=["example.com"], scheme=scheme
            )
            result = _evaluate(evaluator, authz, resolution)
            self.assertEqual(result.decision, "ALLOWED", msg=scheme)

    def test_no_scheme_rewrite(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"], scheme="http"
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")
        # http stays http: nothing upgraded the record.
        self.assertEqual(resolution.scheme, "http")

    def test_custom_port_allowed_via_resolved_port(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"],
            scheme="https", port=8443,
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(resolution.effective_port, 8443)

    def test_default_port_equivalence(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"],
            scheme="https", port=443,
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")


# ------------------------------------------------------------------
# H/I. IP safety + multi-address
# ------------------------------------------------------------------


class TestAddressGate(unittest.TestCase):
    def test_safe_address_allowed(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"],
            dns_answers=(GOOD_IP,),
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(len(result.address_decisions), 1)
        self.assertEqual(result.address_decisions[0].address, GOOD_IP)
        self.assertEqual(result.address_decisions[0].outcome, "ALLOW")

    def test_all_safe_multi_allowed(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"],
            dns_answers=(GOOD_IP, GOOD_IP_2),
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(len(result.address_decisions), 2)

    def test_hand_built_unsafe_resolution_denied(self):
        # 5D re-classifies locally: even a RESOLVED-shaped record with
        # unsafe pinned addresses cannot pass the dual gate.
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        tampered = resolution.model_copy(
            update={
                "resolved_addresses": ("10.9.9.9",),
                "dial": DialBinding(
                    addresses=("10.9.9.9",),
                    effective_port=443,
                    sni_host="example.com",
                ),
            }
        )
        result = _evaluate(evaluator, authz, tampered)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "UNSAFE_ADDRESS")

    def test_unsafe_classes_denied(self):
        for bad in ("127.0.0.1", "::1", "10.0.0.1", "192.168.1.1",
                    "169.254.169.254", "224.0.0.1", "0.0.0.0",
                    "100.64.0.1", "fc00::1", "fe80::1", "::ffff:10.0.0.1"):
            with self.subTest(address=bad):
                _, authz, resolution, evaluator = _world(
                    host="example.com", scopes=["example.com"]
                )
                tampered = resolution.model_copy(
                    update={
                        "resolved_addresses": (bad,),
                        "dial": DialBinding(
                            addresses=(bad,),
                            effective_port=443,
                            sni_host="example.com",
                        ),
                    }
                )
                result = _evaluate(evaluator, authz, tampered)
                self.assertEqual(result.decision, "DENIED")
                self.assertEqual(result.failure_code, "UNSAFE_ADDRESS")

    def test_non_ip_address_rejected_at_boundary(self):
        # Non-IP strings cannot even be constructed into a dial
        # binding (fail-closed at the typed boundary).
        with self.assertRaises(ValidationError):
            DialBinding(
                addresses=("not-an-ip",),
                effective_port=443,
                sni_host="example.com",
            )


# ------------------------------------------------------------------
# J. Authorization binding
# ------------------------------------------------------------------


class TestAuthorizationBinding(unittest.TestCase):
    def test_valid_live_continues(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")

    def test_expired_denied(self):
        # Issue while live, resolve while live, evaluate after expiry:
        # liveness is re-asserted at 5D entry and must deny.
        store = InMemoryAuthorizationStore()
        authz = _issue(
            store, program="acme", host="example.com",
            scopes=["example.com"], expiry="2020-01-01T00:00:00+00:00",
            now="2019-01-01T00:00:00+00:00",
        )
        repo = InMemoryInventoryRepository(
            programs=[ProgramRecord(program_name="acme",
                                    scopes=("example.com",))],
            assets=[AssetRecord(program_name="acme",
                                canonical_host="example.com")],
        )
        res = TargetResolver(
            inventory=repo, dns=FakeDnsResolver({"example.com": [GOOD_IP]})
        ).resolve(
            ResolutionRequest(authorization=authz, execution_id=EXE_A,
                              now="2019-06-01T00:00:00+00:00")
        )
        self.assertEqual(res.status, "RESOLVED")
        evaluator = ScopeEvaluator(
            policy_store=InMemoryPolicyStore({"acme": (["example.com"], [])})
        )
        result = evaluator.evaluate(authz, res, execution_id=EXE_A, now=NOW)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "AUTHZ_NOT_LIVE")

    def test_consumed_denied(self):
        store, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        consume_authorization(store, authz.authorization_id, now=NOW)
        consumed = store.get(authz.authorization_id)
        result = _evaluate(evaluator, consumed, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "AUTHZ_NOT_LIVE")

    def test_revoked_denied(self):
        store, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        revoke_authorization(store, authz.authorization_id)
        revoked = store.get(authz.authorization_id)
        result = _evaluate(evaluator, revoked, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "AUTHZ_NOT_LIVE")

    def test_wrong_program_denied(self):
        store, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        tampered_target = authz.target.model_copy(
            update={"program_name": "other"}
        )
        tampered = authz.model_copy(update={"target": tampered_target})
        result = _evaluate(evaluator, tampered, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertIn(
            result.failure_code,
            ("TARGET_BINDING_MISMATCH", "RESOLUTION_BINDING_MISMATCH"),
        )

    def test_wrong_execution_denied(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        result = _evaluate(evaluator, authz, resolution,
                           execution_id=EXE_B)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "AUTHZ_BINDING_MISMATCH")

    def test_malformed_execution_rejected(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        with self.assertRaises(ScopeError) as ctx:
            _evaluate(evaluator, authz, resolution, execution_id="nope")
        self.assertEqual(ctx.exception.code, "INVALID_REQUEST")

    def test_forged_inputs_rejected_by_type(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        with self.assertRaises(TypeError):
            evaluator.evaluate(
                authz.model_dump(mode="json"), resolution,
                execution_id=EXE_A, now=NOW,
            )
        with self.assertRaises(TypeError):
            evaluator.evaluate(
                authz, resolution.model_dump(mode="json"),
                execution_id=EXE_A, now=NOW,
            )
        with self.assertRaises(TypeError):
            evaluator.evaluate(
                None, resolution, execution_id=EXE_A, now=NOW
            )


# ------------------------------------------------------------------
# K. Resolution binding
# ------------------------------------------------------------------


class TestResolutionBinding(unittest.TestCase):
    def _base(self):
        return _world(host="example.com", scopes=["example.com"])

    def test_matching_resolution_allows(self):
        _, authz, resolution, evaluator = self._base()
        self.assertEqual(
            _evaluate(evaluator, authz, resolution).decision, "ALLOWED"
        )

    def test_non_resolved_status_rejected(self):
        _, authz, resolution, evaluator = self._base()
        failed = resolution.model_copy(update={"status": "TARGET_GONE"})
        result = _evaluate(evaluator, authz, failed)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "RESOLUTION_BINDING_MISMATCH")

    def test_wrong_host_rejected(self):
        _, authz, resolution, evaluator = self._base()
        tampered = resolution.model_copy(
            update={"canonical_host": "other.example.com"}
        )
        result = _evaluate(evaluator, authz, tampered)
        self.assertEqual(result.decision, "DENIED")
        self.assertIn(
            result.failure_code,
            ("RESOLUTION_BINDING_MISMATCH", "TARGET_NOT_CANONICAL"),
        )

    def test_wrong_scheme_rejected(self):
        _, authz, resolution, evaluator = self._base()
        tampered = resolution.model_copy(update={"scheme": "http"})
        result = _evaluate(evaluator, authz, tampered)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "RESOLUTION_BINDING_MISMATCH")

    def test_wrong_port_rejected(self):
        _, authz, resolution, evaluator = self._base()
        tampered = resolution.model_copy(update={"effective_port": 8443})
        result = _evaluate(evaluator, authz, tampered)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "RESOLUTION_BINDING_MISMATCH")

    def test_wrong_target_hash_rejected(self):
        _, authz, resolution, evaluator = self._base()
        tampered = resolution.model_copy(
            update={"canonical_target_hash": "f" * 64}
        )
        result = _evaluate(evaluator, authz, tampered)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "RESOLUTION_BINDING_MISMATCH")

    def test_resolution_id_echo_integrity(self):
        # resolution_id has no independent source inside evaluate():
        # it is echoed self-consistently into the decision (and into
        # evaluation_id), and the triple is enforced at transport
        # entry by require_allowed (tested separately). Forging it
        # buys nothing: the decision still binds the real authz,
        # program, host, hash, and policy.
        store, authz, resolution, evaluator = self._base()
        other = resolution.model_copy(
            update={"resolution_id": "res-" + "b" * 16}
        )
        result = _evaluate(evaluator, authz, other)
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(result.resolution_id, "res-" + "b" * 16)
        self.assertNotEqual(
            result.evaluation_id,
            _evaluate(evaluator, authz, resolution).evaluation_id,
        )
        # ...while the transport gate rejects a triple mismatch.
        with self.assertRaises(ScopeError):
            require_allowed(
                result,
                authorization_id=authz.authorization_id,
                execution_id=EXE_A,
                resolution_id=resolution.resolution_id,
            )

    def test_dial_mismatch_rejected(self):
        _, authz, resolution, evaluator = self._base()
        for patch in (
            {"sni_host": "evil.example.com"},
            {"effective_port": 8443},
            {"pin_required": False},
        ):
            with self.subTest(patch=patch):
                tampered = resolution.model_copy(
                    update={"dial": resolution.dial.model_copy(
                        update=patch)}
                )
                result = _evaluate(evaluator, authz, tampered)
                self.assertEqual(result.decision, "DENIED")
                self.assertEqual(
                    result.failure_code, "DIAL_BINDING_MISMATCH"
                )

    def test_missing_dial_rejected(self):
        _, authz, resolution, evaluator = self._base()
        tampered = resolution.model_copy(update={"dial": None})
        result = _evaluate(evaluator, authz, tampered)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "DIAL_BINDING_MISMATCH")


# ------------------------------------------------------------------
# L. Scope drift
# ------------------------------------------------------------------


class TestScopeDrift(unittest.TestCase):
    def test_same_hash_continues(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")

    def test_changed_policy_denied(self):
        store, authz, resolution, _ = _world(
            host="example.com", scopes=["example.com"]
        )
        drifted = ScopeEvaluator(
            policy_store=InMemoryPolicyStore(
                {"acme": (["example.com", "added.com"], [])}
            )
        )
        result = _evaluate(drifted, authz, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "SCOPE_DRIFT")

    def test_version_string_cannot_override_hash(self):
        store, authz, resolution, _ = _world(
            host="example.com", scopes=["example.com"]
        )
        drifted = ScopeEvaluator(
            policy_store=InMemoryPolicyStore(
                {"acme": (["example.com", "added.com"], [],
                          "scope-policy/v999")}
            )
        )
        result = _evaluate(drifted, authz, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "SCOPE_DRIFT")


# ------------------------------------------------------------------
# M. Redirects
# ------------------------------------------------------------------


class TestRedirects(unittest.TestCase):
    def _chain(self, host="example.com", scopes=("example.com",),
               ooscopes=(), hops=(), **kw):
        _, authz, resolution, evaluator = _world(
            host=host, scopes=list(scopes), ooscopes=list(ooscopes), **kw
        )
        return evaluator.evaluate_chain(
            authz, resolution, execution_id=EXE_A, now=NOW,
            hops=tuple(hops),
        )

    def test_no_hops_returns_initial(self):
        result = self._chain()
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(result.hop_decisions, ())

    def test_same_host_hop_allowed(self):
        result = self._chain(
            hops=(HopObservation(location="/next", addresses=(GOOD_IP,)),)
        )
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(len(result.hop_decisions), 1)
        self.assertEqual(result.hop_decisions[0].decision, "ALLOWED")
        self.assertEqual(
            result.hop_decisions[0].canonical_host, "example.com"
        )

    def test_sibling_hop_denied(self):
        result = self._chain(
            hops=(HopObservation(
                location="https://api.example.com/x", addresses=(GOOD_IP,)),)
        )
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "REDIRECT_NOT_IN_SCOPE")

    def test_explicitly_scoped_sibling_allowed(self):
        result = self._chain(
            scopes=("example.com", "*.example.com"),
            hops=(HopObservation(
                location="https://api.example.com/x", addresses=(GOOD_IP,)),)
        )
        self.assertEqual(result.decision, "ALLOWED")

    def test_out_of_scope_hop_denied(self):
        result = self._chain(
            hops=(HopObservation(
                location="https://evil.com/x", addresses=(GOOD_IP,)),)
        )
        self.assertEqual(result.decision, "DENIED")

    def test_userinfo_hop_denied(self):
        result = self._chain(
            hops=(HopObservation(
                location="https://user:pass@example.com/",
                addresses=(GOOD_IP,)),)
        )
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "REDIRECT_INVALID")

    def test_malformed_location_denied(self):
        for bad in ("https://", "https://[not-ip]/", "ftp://example.com/x",
                    "", "https://exam ple.com/"):
            with self.subTest(location=bad):
                result = self._chain(
                    hops=(HopObservation(location=bad,
                                         addresses=(GOOD_IP,)),)
                )
                self.assertEqual(result.decision, "DENIED")

    def test_scheme_downgrade_denied(self):
        result = self._chain(
            hops=(HopObservation(location="http://example.com/",
                                 addresses=(GOOD_IP,)),)
        )
        self.assertEqual(result.decision, "DENIED")

    def test_scheme_upgrade_probe_only(self):
        up = self._chain(
            host="example.com", scopes=("example.com",),
            hops=(HopObservation(location="https://example.com/",
                                 addresses=(GOOD_IP,)),),
            scheme="http",
        )
        self.assertEqual(up.decision, "ALLOWED")
        self.assertTrue(up.hop_decisions[0].upgraded)
        down = ScopeEvaluator(
            policy_store=InMemoryPolicyStore({"acme": (["example.com"], [])})
        )
        store = InMemoryAuthorizationStore()
        authz = _issue(
            store, program="acme", host="example.com", scheme="http",
            port=80, scopes=["example.com"], execution_class="nuclei_scan",
        )
        from ai.resolver.canonicalization import canonicalize_target

        authority = canonicalize_target("example.com", "http", 80)
        repo = InMemoryInventoryRepository(
            programs=[ProgramRecord(program_name="acme",
                                    scopes=("example.com",))],
            assets=[AssetRecord(program_name="acme",
                                canonical_host="example.com",
                                scheme="http", effective_port=80)],
        )
        res = TargetResolver(
            inventory=repo, dns=FakeDnsResolver({"example.com": [GOOD_IP]})
        ).resolve(
            ResolutionRequest(authorization=authz, execution_id=EXE_A,
                              now=NOW)
        )
        self.assertEqual(res.status, "RESOLVED")
        denied = down.evaluate_chain(
            authz, res, execution_id=EXE_A, now=NOW,
            hops=(HopObservation(location="https://example.com/",
                                 addresses=(GOOD_IP,)),),
        )
        self.assertEqual(denied.decision, "DENIED")

    def test_cross_port_independently_evaluated(self):
        # https:443 -> https:8443 hop: port outside allowlist -> DENY
        # with no inheritance from the allowed initial target.
        result = self._chain(
            hops=(HopObservation(location="https://example.com:8443/",
                                 addresses=(GOOD_IP,)),)
        )
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "REDIRECT_NOT_IN_SCOPE")

    def test_loop_denied(self):
        result = self._chain(
            hops=(
                HopObservation(location="/a", addresses=(GOOD_IP,)),
                HopObservation(location="/a", addresses=(GOOD_IP,)),
            )
        )
        self.assertEqual(result.decision, "DENIED")

    def test_case_dot_loop_caught_canonically(self):
        # Raw strings differ; canonical URLs collide -> loop caught.
        result = self._chain(
            hops=(
                HopObservation(location="/A", addresses=(GOOD_IP,)),
                HopObservation(location="/a", addresses=(GOOD_IP,)),
            )
        )
        # Paths are case-sensitive: distinct canonical URLs, both hops
        # same-host allowed (documents canonical-compare semantics).
        self.assertEqual(result.decision, "ALLOWED")

    def test_sixth_edge_denied(self):
        hops = tuple(
            HopObservation(location="/h%d" % i, addresses=(GOOD_IP,))
            for i in range(6)
        )
        result = self._chain(hops=hops)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "REDIRECT_LIMIT")
        self.assertEqual(len(result.hop_decisions), 5)

    def test_five_edges_allowed(self):
        hops = tuple(
            HopObservation(location="/h%d" % i, addresses=(GOOD_IP,))
            for i in range(5)
        )
        result = self._chain(hops=hops)
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(len(result.hop_decisions), 5)

    def test_relative_and_scheme_relative(self):
        result = self._chain(
            hops=(HopObservation(location="../up", addresses=(GOOD_IP,)),)
        )
        self.assertEqual(result.decision, "ALLOWED")
        other = self._chain(
            hops=(HopObservation(location="//evil.com/x",
                                 addresses=(GOOD_IP,)),)
        )
        self.assertEqual(other.decision, "DENIED")

    def test_hop_without_addresses_inconclusive(self):
        result = self._chain(
            hops=(HopObservation(location="/next", addresses=()),)
        )
        self.assertEqual(result.decision, "INCONCLUSIVE")
        self.assertFalse(result.is_authorizing())
        with self.assertRaises(ScopeError):
            require_allowed(
                result, authorization_id=result.authorization_id,
                execution_id=result.execution_id,
                resolution_id=result.resolution_id,
            )

    def test_hop_unsafe_address_denied(self):
        result = self._chain(
            hops=(HopObservation(location="/next",
                                 addresses=("10.0.0.9",)),)
        )
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "UNSAFE_ADDRESS")

    def test_mid_chain_drift_stops(self):
        _, authz, resolution, _ = _world(
            host="example.com", scopes=["example.com"]
        )

        class DriftingStore:
            def __init__(self):
                self.calls = 0

            def get_policy(self, program_name):
                self.calls += 1
                if self.calls == 1:
                    return InMemoryPolicyStore(
                        {"acme": (["example.com"], [])}
                    ).get_policy(program_name)
                return InMemoryPolicyStore(
                    {"acme": (["example.com", "added.com"], [])}
                ).get_policy(program_name)

        evaluator = ScopeEvaluator(policy_store=DriftingStore())
        result = evaluator.evaluate_chain(
            authz, resolution, execution_id=EXE_A, now=NOW,
            hops=(HopObservation(location="/next", addresses=(GOOD_IP,)),),
        )
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "SCOPE_DRIFT")

    def test_hop_type_checked(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        with self.assertRaises(TypeError):
            evaluator.evaluate_chain(
                authz, resolution, execution_id=EXE_A, now=NOW,
                hops=("/next",),  # type: ignore[list-item]
            )


# ------------------------------------------------------------------
# N. Canonicalization reuse
# ------------------------------------------------------------------


class TestCanonicalization(unittest.TestCase):
    def test_recanonicalization_enforced(self):
        _, authz, resolution, evaluator = _world(
            host="Example.COM.", scopes=["example.com"]
        )
        # 5C canonicalized; 5D re-canonicalizes and agrees.
        self.assertEqual(resolution.canonical_host, "example.com")
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")

    def test_no_second_canonicalizer(self):
        import ai.scope.evaluator as evaluator_module
        import ai.scope.matcher as matcher_module
        import ai.scope.policy as policy_module

        for module in (evaluator_module, matcher_module, policy_module):
            source = Path(module.__file__).read_text(encoding="utf-8")
            self.assertNotIn("def canonicalize_host", source)
            self.assertNotIn(".encode(\"idna\")", source)
            self.assertNotIn(".encode('idna')", source)

    def test_idna_and_case_converge(self):
        _, authz, resolution, evaluator = _world(
            host="API.Example.COM.", scopes=["*.example.com"]
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(resolution.canonical_host, "api.example.com")


# ------------------------------------------------------------------
# O/P/Q. Boundaries: verdicts, dependencies, eTLD+1
# ------------------------------------------------------------------


class TestBoundaries(unittest.TestCase):
    def test_no_verdict_fields(self):
        from ai.schemas.scope_evaluation import (
            AddressDecision,
            HopDecision,
        )

        for model in (ScopeEvaluation, AddressDecision, HopDecision):
            overlap = FORBIDDEN_SCOPE_FIELDS.intersection(
                set(model.model_fields)
            )
            self.assertEqual(overlap, set(), msg=model.__name__)
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        payload = _evaluate(evaluator, authz, resolution).model_dump()
        for forbidden in FORBIDDEN_SCOPE_FIELDS:
            self.assertNotIn(forbidden, payload)
        with self.assertRaises(ValidationError):
            ScopeEvaluation(
                **{**payload, "scope_allowed": True}
            )
        with self.assertRaises(ValidationError):
            ScopeEvaluation(**{**payload, "verdict": "x"})

    def test_inconclusive_never_authorizes(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        result = evaluator.evaluate_chain(
            authz, resolution, execution_id=EXE_A, now=NOW,
            hops=(HopObservation(location="/x", addresses=()),),
        )
        self.assertEqual(result.decision, "INCONCLUSIVE")
        self.assertFalse(result.is_authorizing())

    def test_no_banned_imports(self):
        banned = (
            "socket", "requests", "httpx", "subprocess", "ssl",
            "tldextract", "pymongo", "mongoengine", "openai", "openrouter",
            "anthropic", "playwright", "selenium", "nuclei",
        )
        import re as _re

        import_re = _re.compile(r"^\s*(?:import|from)\s+([a-zA-Z0-9_]+)")
        root = Path(__file__).resolve().parent.parent
        files = [
            "ai/scope/__init__.py",
            "ai/scope/policy.py",
            "ai/scope/matcher.py",
            "ai/scope/evaluator.py",
            "ai/schemas/scope_evaluation.py",
        ]
        for rel in files:
            text = (root / rel).read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), start=1):
                match = import_re.match(line)
                if match:
                    self.assertNotIn(
                        match.group(1), banned,
                        msg=f"{rel}:{lineno}",
                    )
            # urllib.parse is transport-adjacent stdlib: the redirect
            # join/split use is allow-listed here and asserted below.
            self.assertNotIn("EvidenceRecord", text, msg=rel)
            self.assertNotIn("get_domain_name", text, msg=rel)

    def test_urllib_use_is_join_split_only(self):
        import ai.scope.evaluator as module

        text = Path(module.__file__).read_text(encoding="utf-8")
        self.assertIn("from urllib.parse import urljoin, urlsplit", text)
        self.assertNotIn("urlopen", text)
        self.assertNotIn("Request(", text)

    def test_etld1_regression(self):
        # api.example.com must NOT become allowed merely because
        # example.com is in scope. The legacy helper is absent.
        _, authz, resolution, evaluator = _world(
            host="api.example.com", scopes=["example.com"]
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "DENIED")
        import ai.scope.evaluator as module

        text = Path(module.__file__).read_text(encoding="utf-8")
        self.assertNotIn("tldextract", text)
        self.assertNotIn("registrable", text.casefold())

    def test_immutable_records(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        result = _evaluate(evaluator, authz, resolution)
        with self.assertRaises(ValidationError):
            result.decision = "ALLOWED"  # type: ignore[misc]
        with self.assertRaises(ValidationError):
            result.program_name = "other"  # type: ignore[misc]
        policy = compile_policy(
            program_name="acme", scopes=["example.com"], ooscopes=[]
        )
        with self.assertRaises(Exception):
            policy.program_name = "other"  # type: ignore[misc]
        for name in ("replace", "rebind", "mutate", "update", "patch"):
            self.assertFalse(hasattr(ScopeEvaluation, name), msg=name)

    def test_deterministic_ids(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        first = _evaluate(evaluator, authz, resolution)
        second = _evaluate(evaluator, authz, resolution)
        self.assertEqual(first.evaluation_id, second.evaluation_id)
        self.assertEqual(first, second)
        self.assertRegex(first.evaluation_id, r"^se-[0-9a-f]{16}$")
        expected = evaluation_id_for(
            authorization_id=authz.authorization_id,
            execution_id=EXE_A,
            resolution_id=resolution.resolution_id,
            canonical_target_hash=resolution.canonical_target_hash,
            scope_lists_hash_current=first.scope_lists_hash_current,
        )
        self.assertEqual(first.evaluation_id, expected)

    def test_require_allowed_gate(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        allowed = _evaluate(evaluator, authz, resolution)
        self.assertIs(
            require_allowed(
                allowed,
                authorization_id=authz.authorization_id,
                execution_id=EXE_A,
                resolution_id=resolution.resolution_id,
            ),
            allowed,
        )
        denied = _evaluate(
            ScopeEvaluator(policy_store=InMemoryPolicyStore({})),
            authz, resolution,
        )
        with self.assertRaises(ScopeError):
            require_allowed(
                denied,
                authorization_id=authz.authorization_id,
                execution_id=EXE_A,
                resolution_id=resolution.resolution_id,
            )
        with self.assertRaises(ScopeError):
            require_allowed(
                allowed,
                authorization_id=authz.authorization_id,
                execution_id=EXE_B,
                resolution_id=resolution.resolution_id,
            )
        with self.assertRaises(TypeError):
            require_allowed(
                {"decision": "ALLOWED"},  # type: ignore[arg-type]
                authorization_id=authz.authorization_id,
                execution_id=EXE_A,
                resolution_id=resolution.resolution_id,
            )


# ------------------------------------------------------------------
# Adversarial suite (30 hostile cases, all fail closed)
# ------------------------------------------------------------------


class TestAdversarial(unittest.TestCase):
    def _eval_host(self, host, scopes, ooscopes=(), **kw):
        _, authz, resolution, evaluator = _world(
            host=host, scopes=list(scopes), ooscopes=list(ooscopes), **kw
        )
        return _evaluate(evaluator, authz, resolution)

    def _chain_host(self, host, scopes, hops, ooscopes=(), **kw):
        _, authz, resolution, evaluator = _world(
            host=host, scopes=list(scopes), ooscopes=list(ooscopes), **kw
        )
        return evaluator.evaluate_chain(
            authz, resolution, execution_id=EXE_A, now=NOW,
            hops=tuple(hops),
        )

    def test_01_evil_prefix(self):
        result = self._eval_host("evil-example.com", ["example.com"])
        self.assertEqual(result.decision, "DENIED")

    def test_02_evil_sibling(self):
        result = self._eval_host(
            "evil.example.com", ["example.com", "*.example.com"]
        )
        # evil.example.com matches *.example.com here (operator listed
        # it): documents that wildcard breadth is operator intent, and
        # exclusion is the control.
        self.assertEqual(result.decision, "ALLOWED")
        excluded = self._eval_host(
            "evil.example.com", ["example.com", "*.example.com"],
            ooscopes=["evil.example.com"],
        )
        self.assertEqual(excluded.decision, "DENIED")
        self.assertEqual(excluded.failure_code, "TARGET_EXCLUDED")

    def test_03_depth_against_wildcard(self):
        result = self._eval_host("foo.api.example.com", ["*.example.com"])
        self.assertEqual(result.decision, "DENIED")

    def test_04_apex_against_wildcard(self):
        result = self._eval_host("example.com", ["*.example.com"])
        self.assertEqual(result.decision, "DENIED")

    def test_05_unicode_confusable(self):
        # Cyrillic 'а' host: 5C canonicalizes it (via IDNA) to a
        # DIFFERENT slot that never equals the real one, so policy
        # never matches it — homoglyph cannot ride the real slot.
        _, authz, resolution, evaluator = _world_unresolved(
            host="exаmple.com", scopes=["example.com"]
        )
        self.assertNotEqual(resolution.canonical_host, "example.com")
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "TARGET_NOT_IN_SCOPE")

    def test_06_trailing_dot(self):
        result = self._eval_host("example.com.", ["example.com"])
        self.assertEqual(result.decision, "ALLOWED")
        self.assertEqual(
            result.include_rule, "example.com"
        )

    def test_07_userinfo_redirect(self):
        result = self._chain_host(
            "example.com", ["example.com"],
            [HopObservation(location="https://u:p@example.com/",
                            addresses=(GOOD_IP,))],
        )
        self.assertEqual(result.decision, "DENIED")

    def test_08_scheme_relative_evil(self):
        result = self._chain_host(
            "example.com", ["example.com"],
            [HopObservation(location="//evil.example.com/",
                            addresses=(GOOD_IP,))],
        )
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "REDIRECT_NOT_IN_SCOPE")

    def test_09_malformed_location(self):
        result = self._chain_host(
            "example.com", ["example.com"],
            [HopObservation(location="https://[::1", addresses=(GOOD_IP,))],
        )
        self.assertEqual(result.decision, "DENIED")

    def test_10_encoded_host(self):
        result = self._chain_host(
            "example.com", ["example.com"],
            [HopObservation(location="https://%65xample.com/",
                            addresses=(GOOD_IP,))],
        )
        self.assertEqual(result.decision, "DENIED")

    def test_11_ipv4_obfuscation(self):
        # Decimal/octal/hex forms canonicalize to 127.0.0.1 at 5C. IP
        # candidates never match host-only policy: DENY at scope even
        # when observation succeeds.
        _, authz, resolution, evaluator = _world_unresolved(
            host="2130706433", scopes=["example.com"]
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "TARGET_NOT_IN_SCOPE")

    def test_12_mapped_ipv6(self):
        _, authz, resolution, evaluator = _world_unresolved(
            host="::ffff:7f00:1", scopes=["example.com"]
        )
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "DENIED")

    def test_13_localhost(self):
        _, authz, resolution, evaluator = _world_unresolved(
            host="localhost", scopes=["example.com"]
        )
        self.assertEqual(resolution.status, "RESOLUTION_FAILED")
        result = _evaluate(evaluator, authz, resolution)
        self.assertEqual(result.decision, "DENIED")

    def test_14_metadata_ip(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        tampered = resolution.model_copy(
            update={
                "resolved_addresses": ("169.254.169.254",),
                "dial": DialBinding(
                    addresses=("169.254.169.254",),
                    effective_port=443,
                    sni_host="example.com",
                ),
            }
        )
        result = _evaluate(evaluator, authz, tampered)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "UNSAFE_ADDRESS")

    def test_15_private_dns_result(self):
        result = self._chain_host(
            "example.com", ["example.com"],
            [HopObservation(location="/x", addresses=("192.168.9.9",))],
        )
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "UNSAFE_ADDRESS")

    def test_16_mixed_addresses(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        tampered = resolution.model_copy(
            update={
                "resolved_addresses": (GOOD_IP, "10.1.2.3"),
                "dial": DialBinding(
                    addresses=(GOOD_IP, "10.1.2.3"),
                    effective_port=443,
                    sni_host="example.com",
                ),
            }
        )
        result = _evaluate(evaluator, authz, tampered)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "UNSAFE_ADDRESS")

    def test_17_cross_program(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(store, program="prog-a", host="example.com",
                       scopes=["example.com"])
        from ai.resolver.canonicalization import canonicalize_target

        authority = canonicalize_target("example.com", "https", 443)
        repo = InMemoryInventoryRepository(
            programs=[ProgramRecord(program_name="prog-a",
                                    scopes=("example.com",))],
            assets=[AssetRecord(program_name="prog-a",
                                canonical_host="example.com")],
        )
        resolution = TargetResolver(
            inventory=repo, dns=FakeDnsResolver({"example.com": [GOOD_IP]})
        ).resolve(
            ResolutionRequest(authorization=authz, execution_id=EXE_A,
                              now=NOW)
        )
        evaluator = ScopeEvaluator(
            policy_store=InMemoryPolicyStore({"prog-b": (["example.com"], [])})
        )
        result = _evaluate(evaluator, authz, resolution)
        # prog-a has no policy in this store: pair-keyed miss, DENY.
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "PROGRAM_NOT_FOUND")

    def test_18_scope_drift(self):
        _, authz, resolution, _ = _world(
            host="example.com", scopes=["example.com"]
        )
        drifted = ScopeEvaluator(
            policy_store=InMemoryPolicyStore(
                {"acme": (["example.com", "new.example.com"], [])}
            )
        )
        result = _evaluate(drifted, authz, resolution)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "SCOPE_DRIFT")

    def test_19_stale_authorization(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(
            store, program="acme", host="example.com",
            scopes=["example.com"], expiry="2020-01-01T00:00:00+00:00",
            now="2019-01-01T00:00:00+00:00",
        )
        from ai.resolver.canonicalization import canonicalize_target

        authority = canonicalize_target("example.com", "https", 443)
        repo = InMemoryInventoryRepository(
            programs=[ProgramRecord(program_name="acme",
                                    scopes=("example.com",))],
            assets=[AssetRecord(program_name="acme",
                                canonical_host="example.com")],
        )
        res = TargetResolver(
            inventory=repo, dns=FakeDnsResolver({"example.com": [GOOD_IP]})
        ).resolve(
            ResolutionRequest(authorization=authz, execution_id=EXE_A,
                              now="2019-06-01T00:00:00+00:00")
        )
        evaluator = ScopeEvaluator(
            policy_store=InMemoryPolicyStore({"acme": (["example.com"], [])})
        )
        result = evaluator.evaluate(authz, res, execution_id=EXE_A, now=NOW)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "AUTHZ_NOT_LIVE")

    def test_20_consumed_authorization(self):
        store, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        consume_authorization(store, authz.authorization_id, now=NOW)
        result = _evaluate(evaluator, store.get(authz.authorization_id),
                           resolution)
        self.assertEqual(result.decision, "DENIED")

    def test_21_forged_authorization(self):
        _, authz, resolution, evaluator = _world(
            host="example.com", scopes=["example.com"]
        )
        with self.assertRaises(TypeError):
            evaluator.evaluate(
                {"authorization_id": authz.authorization_id},
                resolution, execution_id=EXE_A, now=NOW,
            )

    def test_22_sibling_redirect(self):
        result = self._chain_host(
            "api.example.com", ["api.example.com"],
            [HopObservation(location="https://evil.example.com/",
                            addresses=(GOOD_IP,))],
        )
        self.assertEqual(result.decision, "DENIED")

    def test_23_redirect_loop(self):
        result = self._chain_host(
            "example.com", ["example.com"],
            [
                HopObservation(location="/loop", addresses=(GOOD_IP,)),
                HopObservation(location="/loop", addresses=(GOOD_IP,)),
            ],
        )
        self.assertEqual(result.decision, "DENIED")

    def test_24_hop_overflow(self):
        hops = [HopObservation(location="/%d" % i, addresses=(GOOD_IP,))
                for i in range(6)]
        result = self._chain_host("example.com", ["example.com"], hops)
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "REDIRECT_LIMIT")

    def test_25_port_confusion(self):
        result = self._chain_host(
            "example.com", ["example.com"],
            [HopObservation(location="https://example.com:8443/",
                            addresses=(GOOD_IP,))],
        )
        self.assertEqual(result.decision, "DENIED")

    def test_26_scheme_downgrade(self):
        result = self._chain_host(
            "example.com", ["example.com"],
            [HopObservation(location="http://example.com/",
                            addresses=(GOOD_IP,))],
        )
        self.assertEqual(result.decision, "DENIED")

    def test_27_scheme_upgrade_non_probe(self):
        store = InMemoryAuthorizationStore()
        authz = _issue(
            store, program="acme", host="example.com", scheme="http",
            port=80, scopes=["example.com"],
            execution_class="browser_verification",
        )
        from ai.resolver.canonicalization import canonicalize_target

        authority = canonicalize_target("example.com", "http", 80)
        repo = InMemoryInventoryRepository(
            programs=[ProgramRecord(program_name="acme",
                                    scopes=("example.com",))],
            assets=[AssetRecord(program_name="acme",
                                canonical_host="example.com",
                                scheme="http", effective_port=80)],
        )
        resolution = TargetResolver(
            inventory=repo, dns=FakeDnsResolver({"example.com": [GOOD_IP]})
        ).resolve(
            ResolutionRequest(authorization=authz, execution_id=EXE_A,
                              now=NOW)
        )
        self.assertEqual(resolution.status, "RESOLVED")
        evaluator = ScopeEvaluator(
            policy_store=InMemoryPolicyStore({"acme": (["example.com"], [])})
        )
        result = evaluator.evaluate_chain(
            authz, resolution, execution_id=EXE_A, now=NOW,
            hops=(HopObservation(location="https://example.com/",
                                 addresses=(GOOD_IP,)),),
        )
        self.assertEqual(result.decision, "DENIED")

    def test_28_cdn_assumption(self):
        # A provider-owned hostname is denied without an explicit rule,
        # even when it "serves" the in-scope site.
        result = self._chain_host(
            "example.com", ["example.com"],
            [HopObservation(location="https://d111.cloudfront.net/",
                            addresses=(GOOD_IP,))],
        )
        self.assertEqual(result.decision, "DENIED")

    def test_29_certificate_trust_attempt(self):
        # Same-TLS-certificate sibling: still a different host, still
        # denied. Certificates never authorize scope.
        result = self._chain_host(
            "shop.example.com", ["shop.example.com"],
            [HopObservation(location="https://admin.example.com/",
                            addresses=(GOOD_IP,))],
        )
        self.assertEqual(result.decision, "DENIED")

    def test_30_etld1_assumption(self):
        result = self._eval_host("api.example.com", ["example.com"])
        self.assertEqual(result.decision, "DENIED")
        self.assertEqual(result.failure_code, "TARGET_NOT_IN_SCOPE")


class TestPolicyStore(unittest.TestCase):
    def test_unknown_program_none(self):
        store = InMemoryPolicyStore({"acme": (["example.com"], [])})
        self.assertIsNone(store.get_policy("ghost"))

    def test_malformed_seed_fails_on_read(self):
        store = InMemoryPolicyStore({"acme": ([""], [])})
        with self.assertRaises(PolicyError):
            store.get_policy("acme")

    def test_no_write_surface(self):
        store = InMemoryPolicyStore({"acme": (["example.com"], [])})
        for name in ("put", "save", "insert", "update", "delete", "upsert",
                     "add", "learn", "set_policy"):
            self.assertFalse(hasattr(store, name), msg=name)

    def test_matcher_type_gates(self):
        policy = compile_policy(
            program_name="acme", scopes=["*.example.com"], ooscopes=[]
        )
        with self.assertRaises(TypeError):
            match_rule("not-a-rule", "api.example.com")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            match_inclusions(policy.inclusions, "")  # type: ignore[arg-type]
        self.assertTrue(
            match_rule(policy.inclusions[0], "api.example.com")
        )
        self.assertIsNone(
            match_exclusions(policy.exclusions, "api.example.com")
        )


if __name__ == "__main__":
    unittest.main()
