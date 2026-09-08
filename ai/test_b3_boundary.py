"""Stage 3 B3 sandbox / egress / http_probe-pilot boundary tests.

Deterministic stdlib ``unittest``. Offline only: no Internet, no
production targets, no production Mongo, no live sockets (the only
sockets in this file are the pre-existing 127.0.0.1 loopback fixtures
owned by ``ai.test_b1_dial_policy``, reused here only through its
pure fixture helpers — this module opens no socket itself), no DNS,
no subprocess, no LLM, no Nuclei, no browser.

Coverage map (Stage 3 task items 1-28):

 1. closed-by-default pilot gate
 2. exact egress destination binding
 3. wrong address rejected
 4. wrong port rejected
 5. wrong scheme rejected
 6. wrong authorization rejected
 7. stale authorization rejected
 8. scope drift rejected
 9. missing address rejected
10. conflicting address rejected
11. redirect requires fresh scope
12. private destination rejected
13. localhost/loopback rejected
14. metadata destination rejected
15. arbitrary URL override rejected
16. host-header-only authorization rejected
17. dial proof mismatch rejected
18. request size bound
19. response size bound
20. redirect bound
21. timeout cleanup
22. resource cleanup
23. no subprocess
24. no Nuclei
25. no browser
26. live gates remain closed by default
27. no legacy XssFindings path
28. no retired materialization path

Plus: sandbox acquire/release accounting, egress-hash determinism,
dial-proof happy path, redirect happy path (old policy never
authorizes the next hop), pilot full-pass structural evaluation
(explicitly enabled test-only config; still zero I/O), and module
hygiene (no socket/ssl/subprocess/pymongo/mongoengine/database/
playwright/high-level-HTTP-client imports in the B3 module).
"""

from __future__ import annotations

import ast
import dataclasses
import unittest
from pathlib import Path
from unittest import mock

from ai.execution import b3_boundary as b3
from ai.execution import dial_proof as dp
from ai.execution import http_executor as hx
from ai.execution.b3_boundary import B3BoundaryError
from ai.limits.ceilings import CEILINGS
from ai.test_b1_dial_policy import (
    EX_ID,
    HOST,
    IP_A,
    IP_B,
    IP_C,
    NOW,
    PROGRAM,
    SCOPE_HASH,
    WWW,
    GOOD_ARTIFACT,
    artifact_reference_for,
    make_authz,
    make_hop_resolver,
    packet_entry,
)


def _bindings(addresses=(IP_A,), *, host=HOST, mapping=None):
    authz = make_authz()
    table = dict(mapping) if mapping else {host: packet_entry([(a, 60) for a in addresses])}
    resolver, _ = make_hop_resolver(table)
    resolution, evaluation = resolver.resolve_initial(
        authorization=authz, execution_id=EX_ID, now=NOW
    )
    return authz, resolver, resolution, evaluation


def _proof(authz, resolution, evaluation, *, peer=IP_A, hop=0, conn="conn-" + "1" * 32):
    return dp.assemble_dial_proof(
        actual_peer_ip=peer,
        local_sockaddr="192.0.2.7:54321",
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
        redirect_hop_index=hop,
        connection_id=conn,
    )


def _policy(authz, resolution, evaluation, address=IP_A):
    return b3.build_egress_policy(
        authorization=authz,
        resolution=resolution,
        evaluation=evaluation,
        selected_address=address,
        now=NOW,
    )


def _request(authz, resolution, evaluation, content=GOOD_ARTIFACT):
    return hx.translate_bounded_request(
        authorization=authz,
        resolution=resolution,
        evaluation=evaluation,
        artifact_reference=artifact_reference_for(content),
        artifact_bytes=content,
        execution_id=EX_ID,
    )


def _pilot_kwargs(**overrides):
    authz, _, resolution, evaluation = _bindings()
    policy = _policy(authz, resolution, evaluation)
    proof = _proof(authz, resolution, evaluation)
    request = _request(authz, resolution, evaluation)
    sandbox = b3.acquire_sandbox(policy=policy, execution_id=EX_ID, now=NOW)
    kwargs = {
        "config": b3.PilotGateConfig(pilot_enabled=True),
        "authorization": authz,
        "resolution": resolution,
        "evaluation": evaluation,
        "policy": policy,
        "proof": proof,
        "request": request,
        "sandbox": sandbox,
        "ledger_admitted": True,
        "evidence_path_ready": True,
        "verifier_path_ready": True,
        "now": NOW,
    }
    kwargs.update(overrides)
    return kwargs


def _read_b3_source() -> str:
    return (Path(__file__).resolve().parent / "execution" / "b3_boundary.py").read_text()


# ==================================================================
# 2. exact egress destination binding (+ 6/7/8/9/10 coherent rejects)
# ==================================================================


class EgressPolicyTests(unittest.TestCase):
    def test_exact_binding_admitted(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        self.assertEqual(policy.approved_address, IP_A)
        self.assertEqual(policy.effective_port, 443)
        self.assertEqual(policy.scheme, "https")
        self.assertEqual(policy.authorization_id, authz.authorization_id)
        self.assertEqual(policy.resolution_id, resolution.resolution_id)
        self.assertEqual(policy.evaluation_id, evaluation.evaluation_id)
        self.assertEqual(policy.scope_lists_hash, SCOPE_HASH)
        self.assertEqual(policy.policy_version, b3.B3_POLICY_VERSION)
        checked = b3.check_egress_dial(
            policy=policy,
            dial_ip=IP_A,
            dial_port=443,
            dial_scheme="https",
            authorization_id=authz.authorization_id,
            resolution_id=resolution.resolution_id,
        )
        self.assertEqual(checked, policy)
        self.assertRegex(b3.egress_policy_hash(policy), r"^[0-9a-f]{64}$")

    def test_wrong_address_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_egress_dial(
                policy=policy, dial_ip=IP_B, dial_port=443,
                dial_scheme="https", authorization_id=authz.authorization_id,
                resolution_id=resolution.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_wrong_port_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_egress_dial(
                policy=policy, dial_ip=IP_A, dial_port=8443,
                dial_scheme="https", authorization_id=authz.authorization_id,
                resolution_id=resolution.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_wrong_scheme_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_egress_dial(
                policy=policy, dial_ip=IP_A, dial_port=443,
                dial_scheme="http", authorization_id=authz.authorization_id,
                resolution_id=resolution.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_wrong_authorization_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_egress_dial(
                policy=policy, dial_ip=IP_A, dial_port=443,
                dial_scheme="https", authorization_id="authz-" + "f" * 16,
                resolution_id=resolution.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_wrong_resolution_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_egress_dial(
                policy=policy, dial_ip=IP_A, dial_port=443,
                dial_scheme="https", authorization_id=authz.authorization_id,
                resolution_id="r" * 64,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_stale_policy_version_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        stale = dataclasses.replace(policy, policy_version="b3-egress-policy/v0")
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_egress_dial(
                policy=stale, dial_ip=IP_A, dial_port=443,
                dial_scheme="https", authorization_id=authz.authorization_id,
                resolution_id=resolution.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "STALE_EGRESS_POLICY")

    def test_missing_policy_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_egress_dial(
                policy=None, dial_ip=IP_A, dial_port=443,
                dial_scheme="https", authorization_id=authz.authorization_id,
                resolution_id=resolution.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "MISSING_EGRESS_POLICY")
        with self.assertRaises(B3BoundaryError) as ctx2:
            b3.build_egress_policy(
                authorization=authz, resolution=resolution,
                evaluation=evaluation, selected_address="",
                now=NOW,
            )
        self.assertEqual(ctx2.exception.code, "MISSING_EGRESS_POLICY")

    def test_conflicting_address_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.build_egress_policy(
                authorization=authz, resolution=resolution,
                evaluation=evaluation, selected_address=IP_C,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "DIAL_BINDING_MISMATCH")

    def test_stale_authorization_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        revoked = authz.model_copy(update={"lifecycle": "REVOKED"})
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.build_egress_policy(
                authorization=revoked, resolution=resolution,
                evaluation=evaluation, selected_address=IP_A,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "STALE_AUTHORIZATION")
        expired = authz.model_copy(update={"lifecycle": "EXPIRED"})
        with self.assertRaises(B3BoundaryError) as ctx2:
            b3.build_egress_policy(
                authorization=expired, resolution=resolution,
                evaluation=evaluation, selected_address=IP_A,
                now=NOW,
            )
        self.assertEqual(ctx2.exception.code, "STALE_AUTHORIZATION")

    def test_scope_drift_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        drifted_target = authz.target.model_copy(
            update={"scope_lists_hash": "0" * 64}
        )
        drifted = authz.model_copy(update={"target": drifted_target})
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.build_egress_policy(
                authorization=drifted, resolution=resolution,
                evaluation=evaluation, selected_address=IP_A,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "SCOPE_DRIFT")

    def test_denied_scope_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        denied = evaluation.model_copy(update={"decision": "DENIED"})
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.build_egress_policy(
                authorization=authz, resolution=resolution,
                evaluation=denied, selected_address=IP_A,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_forbidden_execution_class_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        nuclei_authz = authz.model_copy(update={"execution_class": "nuclei"})
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.build_egress_policy(
                authorization=nuclei_authz, resolution=resolution,
                evaluation=evaluation, selected_address=IP_A,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "FORBIDDEN_EXECUTION_CLASS")


# ==================================================================
# Freshness policy (Part E: issued_at <= now < expires_at, 5B-identical)
# ==================================================================


class FreshnessPolicyTests(unittest.TestCase):
    ISSUED = "2026-01-01T00:00:00+00:00"
    EXPIRES = "2026-02-01T00:00:00+00:00"

    def _windowed(self, issued: str, expires: str):
        authz, _, resolution, evaluation = _bindings()
        return (
            authz.model_copy(update={"issued_at": issued, "expires_at": expires}),
            resolution,
            evaluation,
        )

    def test_open_instant_valid_closed_instant_stale(self) -> None:
        authz, resolution, evaluation = self._windowed(self.ISSUED, self.EXPIRES)
        # now == issued_at is valid (window is closed on the left).
        policy = b3.build_egress_policy(
            authorization=authz, resolution=resolution,
            evaluation=evaluation, selected_address=IP_A, now=self.ISSUED,
        )
        self.assertEqual(policy.approved_address, IP_A)
        # One microsecond before expiry is valid ...
        b3.check_authorization_freshness(
            authorization=authz, now="2026-01-31T23:59:59.999999+00:00"
        )
        # ... but now == expires_at is already expired (exclusive right).
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.build_egress_policy(
                authorization=authz, resolution=resolution,
                evaluation=evaluation, selected_address=IP_A, now=self.EXPIRES,
            )
        self.assertEqual(ctx.exception.code, "STALE_AUTHORIZATION")
        self.assertIn("expired", ctx.exception.detail)

    def test_not_yet_valid_refused(self) -> None:
        authz, resolution, evaluation = self._windowed(self.ISSUED, self.EXPIRES)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_authorization_freshness(
                authorization=authz, now="2025-12-31T23:59:59+00:00"
            )
        self.assertEqual(ctx.exception.code, "STALE_AUTHORIZATION")
        self.assertIn("not yet valid", ctx.exception.detail)

    def test_naive_instants_read_as_utc_like_5b(self) -> None:
        # The single frozen rule (5B-identical): naive == UTC. A naive
        # window denoting the same instants as the aware window is
        # equally fresh — no ambiguous timestamp behavior.
        authz, _, _, _ = _bindings()
        naive = authz.model_copy(
            update={"issued_at": "2026-01-01T00:00:00",
                    "expires_at": "2026-02-01T00:00:00"}
        )
        b3.check_authorization_freshness(authorization=naive, now=NOW)
        b3.check_authorization_freshness(
            authorization=naive, now="2026-01-15T00:00:00"
        )

    def test_malformed_and_inverted_windows_refused(self) -> None:
        authz, _, _, _ = _bindings()
        malformed = authz.model_copy(update={"expires_at": "not-a-time"})
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_authorization_freshness(authorization=malformed, now=NOW)
        self.assertEqual(ctx.exception.code, "STALE_AUTHORIZATION")
        inverted = authz.model_copy(
            update={"issued_at": self.EXPIRES, "expires_at": self.ISSUED}
        )
        with self.assertRaises(B3BoundaryError) as ctx2:
            b3.check_authorization_freshness(authorization=inverted, now=NOW)
        self.assertEqual(ctx2.exception.code, "STALE_AUTHORIZATION")
        with self.assertRaises(TypeError):
            b3.check_authorization_freshness(
                authorization={"authorization_id": "x"}, now=NOW
            )

    def test_expired_authorization_denies_pilot_gate(self) -> None:
        expired = _pilot_kwargs()["authorization"].model_copy(
            update={"expires_at": "2026-01-02T00:00:00+00:00"}
        )
        allowed, denials = b3.evaluate_pilot_gate(
            **_pilot_kwargs(authorization=expired)
        )
        self.assertFalse(allowed)
        self.assertTrue(
            any(d.startswith("authorization_fresh") for d in denials), denials
        )

    def test_redirect_past_expiry_refused(self) -> None:
        # Fresh redirect pair under the live window first.
        live_authz, resolver, resolution, evaluation = _bindings(
            mapping={
                HOST: packet_entry([(IP_A, 60)]),
                WWW: packet_entry([(IP_C, 60)]),
            }
        )
        live_policy = _policy(live_authz, resolution, evaluation)
        new_resolution, new_evaluation = resolver.resolve_hop(
            authorization=live_authz, execution_id=EX_ID, canonical_host=WWW,
            scheme="https", effective_port=443, path="/r", query="", now=NOW,
        )
        # The same authorization re-presented after expiry cannot fund
        # the redirect hop, even with genuinely fresh bindings.
        late = live_authz.model_copy(
            update={"expires_at": "2026-01-10T00:00:00+00:00"}
        )
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.require_fresh_scope_for_redirect(
                policy=live_policy, authorization=late,
                new_resolution=new_resolution, new_evaluation=new_evaluation,
                redirect_hop_index=1, selected_address=IP_C,
                now="2026-01-15T00:00:00+00:00",
            )
        self.assertEqual(ctx.exception.code, "STALE_AUTHORIZATION")
        self.assertIn("expired", ctx.exception.detail)


# ==================================================================
# 12/13/14. forbidden destinations
# ==================================================================


class ForbiddenDestinationTests(unittest.TestCase):
    def test_private_rejected(self) -> None:
        for hostile in ("10.9.9.9", "192.168.1.10", "172.16.0.4", "fc00::1"):
            self.assertTrue(b3.is_forbidden_destination(hostile), hostile)
            with self.assertRaises(B3BoundaryError) as ctx:
                b3.check_destination_allowed(hostile)
            self.assertEqual(ctx.exception.code, "FORBIDDEN_DESTINATION")

    def test_localhost_loopback_rejected(self) -> None:
        for hostile in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::"):
            self.assertTrue(b3.is_forbidden_destination(hostile), hostile)
            with self.assertRaises(B3BoundaryError) as ctx:
                b3.check_destination_allowed(hostile)
            self.assertEqual(ctx.exception.code, "FORBIDDEN_DESTINATION")

    def test_link_local_and_metadata_rejected(self) -> None:
        for hostile in ("169.254.169.254", "169.254.10.20", "fe80::1", "224.0.0.1"):
            self.assertTrue(b3.is_forbidden_destination(hostile), hostile)
            with self.assertRaises(B3BoundaryError) as ctx:
                b3.check_destination_allowed(hostile)
            self.assertEqual(ctx.exception.code, "FORBIDDEN_DESTINATION")

    def test_garbage_rejected(self) -> None:
        for hostile in ("", "not-an-ip", "https://8.8.8.8", "8.8.8.8/32", None, 12345):
            self.assertTrue(b3.is_forbidden_destination(hostile), repr(hostile))

    def test_globally_routable_not_forbidden(self) -> None:
        self.assertFalse(b3.is_forbidden_destination(IP_A))
        self.assertEqual(b3.check_destination_allowed(IP_A), IP_A)


# ==================================================================
# 11. redirect safety
# ==================================================================


class RedirectSafetyTests(unittest.TestCase):
    def _redirect_bindings(self):
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
        return authz, resolver, resolution, evaluation

    def test_redirect_requires_fresh_scope(self) -> None:
        authz, _, resolution, evaluation = self._redirect_bindings()
        policy = _policy(authz, resolution, evaluation)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.require_fresh_scope_for_redirect(
                policy=policy, authorization=authz,
                new_resolution=resolution, new_evaluation=evaluation,
                redirect_hop_index=1, selected_address=IP_A,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "REDIRECT_REQUIRES_FRESH_SCOPE")

    def test_redirect_happy_path_builds_new_policy(self) -> None:
        authz, resolver, resolution, evaluation = self._redirect_bindings()
        policy = _policy(authz, resolution, evaluation)
        new_resolution, new_evaluation = resolver.resolve_hop(
            authorization=authz, execution_id=EX_ID, canonical_host=WWW,
            scheme="https", effective_port=443, path="/r", query="", now=NOW,
        )
        self.assertNotEqual(new_resolution.resolution_id, resolution.resolution_id)
        new_policy = b3.require_fresh_scope_for_redirect(
            policy=policy, authorization=authz,
            new_resolution=new_resolution, new_evaluation=new_evaluation,
            redirect_hop_index=1, selected_address=IP_C,
            now=NOW,
        )
        self.assertEqual(new_policy.approved_address, IP_C)
        self.assertEqual(new_policy.canonical_host, WWW)
        # The old policy never authorizes the next hop's dial.
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_egress_dial(
                policy=policy, dial_ip=IP_C, dial_port=443,
                dial_scheme="https", authorization_id=authz.authorization_id,
                resolution_id=new_resolution.resolution_id,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_redirect_denied_evaluation_rejected(self) -> None:
        authz, resolver, resolution, evaluation = self._redirect_bindings()
        policy = _policy(authz, resolution, evaluation)
        new_resolution, new_evaluation = resolver.resolve_hop(
            authorization=authz, execution_id=EX_ID, canonical_host=WWW,
            scheme="https", effective_port=443, path="/r", query="", now=NOW,
        )
        denied = new_evaluation.model_copy(update={"decision": "DENIED"})
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.require_fresh_scope_for_redirect(
                policy=policy, authorization=authz,
                new_resolution=new_resolution, new_evaluation=denied,
                redirect_hop_index=1, selected_address=IP_C,
                now=NOW,
            )
        self.assertEqual(ctx.exception.code, "REDIRECT_NOT_IN_SCOPE")

    def test_redirect_target_gate(self) -> None:
        # IP-literal redirect destinations are never in scope.
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_redirect_target(
                location_host="127.0.0.1", location_scheme="https",
                location_port=443, current_scheme="https",
                execution_class="http_probe",
            )
        self.assertEqual(ctx.exception.code, "REDIRECT_NOT_IN_SCOPE")
        # https downgrade denied.
        with self.assertRaises(B3BoundaryError) as ctx2:
            b3.check_redirect_target(
                location_host=WWW, location_scheme="http",
                location_port=80, current_scheme="https",
                execution_class="http_probe",
            )
        self.assertEqual(ctx2.exception.code, "REDIRECT_INVALID")
        # Non-http_probe classes cannot redirect at all.
        with self.assertRaises(B3BoundaryError) as ctx3:
            b3.check_redirect_target(
                location_host=WWW, location_scheme="https",
                location_port=443, current_scheme="https",
                execution_class="nuclei",
            )
        self.assertEqual(ctx3.exception.code, "FORBIDDEN_EXECUTION_CLASS")
        # Well-formed https target passes the structural pre-check
        # (still NOT authorized — fresh scope required before any dial).
        self.assertEqual(
            b3.check_redirect_target(
                location_host=WWW, location_scheme="https",
                location_port=443, current_scheme="https",
                execution_class="http_probe",
            ),
            WWW,
        )


# ==================================================================
# 15/16. URL/host-header override rejection + 17. dial proof binding
# ==================================================================


class OverrideAndProofTests(unittest.TestCase):
    def test_arbitrary_url_override_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        # A raw URL string is not a policy and never authorizes a dial.
        with self.assertRaises(TypeError):
            b3.check_egress_dial(
                policy="https://authorized.example.com/",
                dial_ip=IP_A, dial_port=443, dial_scheme="https",
                authorization_id=authz.authorization_id,
                resolution_id=resolution.resolution_id,
            )
        with self.assertRaises(TypeError):
            b3.check_request_bounds(request="https://authorized.example.com/")
        with self.assertRaises(TypeError):
            b3.check_request_bounds(request={"url": "https://authorized.example.com/"})

    def test_host_header_only_authorization_rejected(self) -> None:
        # The 5E translator forbids caller-supplied Host headers, so no
        # request carrying "Host: <other>" can even be built; and B3
        # never reads a Host header — only lineage-bound policy fields.
        from ai.test_b1_dial_policy import artifact_content as _content

        authz, _, resolution, evaluation = _bindings()
        hostile = _content(headers={"host": "evil.example.com"})
        with self.assertRaises(hx.ExecutorError):
            hx.translate_bounded_request(
                authorization=authz, resolution=resolution,
                evaluation=evaluation,
                artifact_reference=artifact_reference_for(hostile),
                artifact_bytes=hostile, execution_id=EX_ID,
            )
        policy = _policy(authz, resolution, evaluation)
        # Same IP but a foreign resolution id is not the same target.
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_egress_dial(
                policy=policy, dial_ip=IP_A, dial_port=443,
                dial_scheme="https", authorization_id=authz.authorization_id,
                resolution_id="0" * 64,
            )
        self.assertEqual(ctx.exception.code, "EGRESS_DENIED")

    def test_dial_proof_happy_path(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        proof = _proof(authz, resolution, evaluation)
        verified = b3.assert_dial_matches_egress(
            proof=proof, policy=policy, resolution=resolution,
            evaluation=evaluation, authorization_id=authz.authorization_id,
        )
        self.assertEqual(verified.actual_peer_ip, IP_A)

    def test_dial_proof_mismatch_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings(
            addresses=(IP_A, IP_B)
        )
        policy_a = _policy(authz, resolution, evaluation, address=IP_A)
        proof_b = _proof(authz, resolution, evaluation, peer=IP_B)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.assert_dial_matches_egress(
                proof=proof_b, policy=policy_a, resolution=resolution,
                evaluation=evaluation, authorization_id=authz.authorization_id,
            )
        self.assertEqual(ctx.exception.code, "DIAL_PROOF_MISMATCH")

    def test_missing_dial_proof_rejected(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.assert_dial_matches_egress(
                proof=None, policy=policy, resolution=resolution,
                evaluation=evaluation, authorization_id=authz.authorization_id,
            )
        self.assertEqual(ctx.exception.code, "DIAL_PROOF_MISMATCH")


# ==================================================================
# 18/19/20. bounds
# ==================================================================


class BoundTests(unittest.TestCase):
    def test_request_bound_admitted(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        request = _request(authz, resolution, evaluation)
        self.assertTrue(
            b3.check_request_bounds(request=request).startswith("https://")
        )

    def test_request_body_bound(self) -> None:
        from ai.test_b1_dial_policy import artifact_content as _content

        authz, _, resolution, evaluation = _bindings()
        big = _content(
            method="POST", body="x" * (CEILINGS["request_body_bytes"] + 1),
            headers={"accept": "text/html", "content-type": "application/x-www-form-urlencoded"},
        )
        # Translation itself enforces the frozen ceiling first ...
        with self.assertRaises(hx.ExecutorError):
            hx.translate_bounded_request(
                authorization=make_authz(
                    content=big, plan_method="POST", artifact_method="POST"
                ),
                resolution=resolution, evaluation=evaluation,
                artifact_reference=artifact_reference_for(big),
                artifact_bytes=big, execution_id=EX_ID,
            )
        # ... and B3 independently refuses an over-ceiling body object.
        request = _request(authz, resolution, evaluation)
        forged = dataclasses.replace(
            request, body=b"x" * (CEILINGS["request_body_bytes"] + 1)
        )
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_request_bounds(request=forged)
        self.assertEqual(ctx.exception.code, "REQUEST_BOUND_REJECTED")

    def test_request_url_and_header_bounds(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        request = _request(authz, resolution, evaluation)
        forged_url = dataclasses.replace(
            request, canonical_url="https://x.example/" + "y" * b3.B3_MAX_URL_LENGTH
        )
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_request_bounds(request=forged_url)
        self.assertEqual(ctx.exception.code, "REQUEST_BOUND_REJECTED")
        forged_headers = dataclasses.replace(
            request,
            headers=tuple((f"x-h-{i}", "v") for i in range(b3.B3_MAX_REQUEST_HEADERS + 1)),
        )
        with self.assertRaises(B3BoundaryError) as ctx2:
            b3.check_request_bounds(request=forged_headers)
        self.assertEqual(ctx2.exception.code, "REQUEST_BOUND_REJECTED")
        forged_value = dataclasses.replace(
            request, headers=(("accept", "v" * (b3.B3_MAX_HEADER_VALUE + 1)),)
        )
        with self.assertRaises(B3BoundaryError) as ctx3:
            b3.check_request_bounds(request=forged_value)
        self.assertEqual(ctx3.exception.code, "REQUEST_BOUND_REJECTED")
        forged_method = dataclasses.replace(request, method="DELETE")
        with self.assertRaises(B3BoundaryError) as ctx4:
            b3.check_request_bounds(request=forged_method)
        self.assertEqual(ctx4.exception.code, "REQUEST_BOUND_REJECTED")

    def test_response_budget(self) -> None:
        b3.check_response_budget(bytes_received=1024, decompressed_bytes=1024)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_response_budget(
                bytes_received=CEILINGS["response_transport_bytes"] + 1
            )
        self.assertEqual(ctx.exception.code, "RESPONSE_BOUND_EXCEEDED")
        with self.assertRaises(B3BoundaryError) as ctx2:
            b3.check_response_budget(
                bytes_received=64,
                decompressed_bytes=CEILINGS["decompressed_bytes"] + 1,
            )
        self.assertEqual(ctx2.exception.code, "RESPONSE_BOUND_EXCEEDED")

    def test_redirect_bound(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        for bad_hop in (0, -1, CEILINGS["redirect_hops"] + 1, "1"):
            with self.assertRaises(B3BoundaryError) as ctx:
                b3.require_fresh_scope_for_redirect(
                    policy=policy, authorization=authz,
                    new_resolution=resolution, new_evaluation=evaluation,
                    redirect_hop_index=bad_hop, selected_address=IP_A,
                    now=NOW,
                )
            self.assertEqual(ctx.exception.code, "REDIRECT_LIMIT")


# ==================================================================
# 21/22. sandbox lifetime + resource cleanup
# ==================================================================


class SandboxTests(unittest.TestCase):
    def test_acquire_records_blocked_boundary(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        spec = b3.acquire_sandbox(policy=policy, execution_id=EX_ID, now=NOW)
        self.assertEqual(spec.mode, "dry-run-blocked")
        self.assertIn(spec.mode, b3.SANDBOX_MODES)
        self.assertEqual(spec.egress_policy_hash, b3.egress_policy_hash(policy))
        self.assertEqual(spec.wall_seconds, CEILINGS["http_wall_seconds"])
        self.assertEqual(
            spec.connect_timeout_seconds, CEILINGS["connect_timeout_seconds"]
        )
        self.assertEqual(
            spec.response_transport_cap, CEILINGS["response_transport_bytes"]
        )
        self.assertEqual(spec.max_redirect_hops, CEILINGS["redirect_hops"])
        self.assertEqual(spec.max_requests, CEILINGS["requests_per_execution"])

    def test_release_on_completion_timeout_failure(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        spec = b3.acquire_sandbox(policy=policy, execution_id=EX_ID, now=NOW)
        for reason in ("completed", "timeout", "failed"):
            release = b3.release_sandbox(
                spec=spec, reason=reason, released_at=NOW
            )
            self.assertEqual(release.reason, reason)
            self.assertEqual(release.execution_id, EX_ID)
            self.assertEqual(
                release.egress_policy_hash, b3.egress_policy_hash(policy)
            )
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.release_sandbox(spec=spec, reason="leaked", released_at=NOW)
        self.assertEqual(ctx.exception.code, "RESOURCE_LIMIT")

    def test_acquire_rejects_incoherent_inputs(self) -> None:
        authz, _, resolution, evaluation = _bindings()
        policy = _policy(authz, resolution, evaluation)
        with self.assertRaises(B3BoundaryError):
            b3.acquire_sandbox(policy=policy, execution_id="ex-bad", now=NOW)
        with self.assertRaises(B3BoundaryError):
            b3.acquire_sandbox(policy=policy, execution_id=EX_ID, now="")
        with self.assertRaises(TypeError):
            b3.acquire_sandbox(policy="not-a-policy", execution_id=EX_ID, now=NOW)


# ==================================================================
# 1/24/25/26. pilot gate + live switches
# ==================================================================


class PilotGateTests(unittest.TestCase):
    def test_gate_closed_by_default(self) -> None:
        self.assertIs(b3.HTTP_PROBE_PILOT_ENABLED, False)
        self.assertEqual(b3.PilotGateConfig().pilot_enabled, False)
        allowed, denials = b3.evaluate_pilot_gate(
            **_pilot_kwargs(config=b3.PilotGateConfig())
        )
        self.assertFalse(allowed)
        self.assertIn("pilot gate closed by default", denials)
        with self.assertRaises(B3BoundaryError) as ctx:
            b3.check_pilot_gate(**_pilot_kwargs(config=b3.PilotGateConfig()))
        self.assertEqual(ctx.exception.code, "PILOT_GATE_CLOSED")

    def test_gate_full_pass_structural_only(self) -> None:
        # An explicitly enabled TEST-ONLY config with fully coherent
        # bindings evaluates allowed — yet performs zero I/O, opens no
        # socket, and leaves every live switch False.
        allowed, denials = b3.evaluate_pilot_gate(**_pilot_kwargs())
        self.assertTrue(allowed, denials)
        self.assertEqual(denials, ())
        b3.check_pilot_gate(**_pilot_kwargs())
        self.assertIs(hx.LIVE_TRAFFIC_ENABLED, False)
        self.assertIs(b3.HTTP_PROBE_PILOT_ENABLED, False)

    def test_gate_denies_each_missing_condition(self) -> None:
        base = _pilot_kwargs()
        cases = [
            ("ledger_admitted", False),
            ("evidence_path_ready", False),
            ("verifier_path_ready", False),
            ("now", "2000-01-01T00:00:00+00:00"),
        ]
        for field, bad in cases:
            kwargs = dict(base)
            kwargs[field] = bad
            allowed, denials = b3.evaluate_pilot_gate(**kwargs)
            self.assertFalse(allowed, field)
            self.assertTrue(denials, field)
        # Stale authorization denies the gate.
        kwargs = dict(base)
        kwargs["authorization"] = base["authorization"].model_copy(
            update={"lifecycle": "REVOKED"}
        )
        allowed, denials = b3.evaluate_pilot_gate(**kwargs)
        self.assertFalse(allowed)
        # Untyped config denies the gate.
        kwargs = dict(base)
        kwargs["config"] = {"pilot_enabled": True}
        allowed, _ = b3.evaluate_pilot_gate(**kwargs)
        self.assertFalse(allowed)
        # Non-bool pilot flag never enables.
        with self.assertRaises(TypeError):
            b3.PilotGateConfig(pilot_enabled="false")  # type: ignore[arg-type]

    def test_master_switch_tamper_detected(self) -> None:
        with mock.patch.object(b3, "HTTP_PROBE_PILOT_ENABLED", True):
            allowed, denials = b3.evaluate_pilot_gate(**_pilot_kwargs())
        self.assertFalse(allowed)
        self.assertTrue(any("tampered" in denial for denial in denials))

    def test_live_gates_remain_closed(self) -> None:
        from ai.execution import browser_executor as bx
        from ai.execution import nuclei_executor as nx

        self.assertIs(hx.LIVE_TRAFFIC_ENABLED, False)
        self.assertIs(nx.LIVE_NUCLEI, False)
        self.assertIs(bx.LIVE_BROWSER, False)
        b3.assert_nuclei_browser_blocked()

    def test_gate_covers_all_fifteen_checks(self) -> None:
        self.assertEqual(len(b3.PILOT_GATE_CHECKS), 15)


# ==================================================================
# 23/27/28 + module hygiene
# ==================================================================


class ModuleHygieneTests(unittest.TestCase):
    BANNED_ROOTS = frozenset(
        {
            "socket",
            "ssl",
            "subprocess",
            "os",
            "sys",
            "requests",
            "httpx",
            "urllib",
            "http",
            "pymongo",
            "mongoengine",
            "database",
            "playwright",
            "selenium",
        }
    )

    def test_no_live_or_side_effect_imports(self) -> None:
        tree = ast.parse(_read_b3_source())
        roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    roots.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    roots.add(node.module.split(".")[0])
        banned = roots & self.BANNED_ROOTS
        self.assertEqual(banned, set(), f"banned imports in b3_boundary: {banned}")

    def test_no_subprocess_or_shell_shapes(self) -> None:
        source = _read_b3_source()
        for shape in (
            "popen",
            "check_output",
            "check_call",
            "os.system",
            "os.exec",
            "os.fork",
            "shell=True",
            "__import__",
            "eval(",
            "exec(",
        ):
            self.assertNotIn(shape, source, f"dangerous shape: {shape}")

    def test_no_legacy_or_retired_paths(self) -> None:
        import re as _re

        source = _read_b3_source()
        tree = ast.parse(source)
        self.assertNotIn("XssFinding", source)
        # The retired 5J materialization seam is a callable import
        # (`materialize(...)` / `ai.verification...materialization`);
        # ordinary prose ("materialized") is not a code path.
        self.assertIsNone(
            _re.search(r"materialize\s*\(", source),
            "retired materialization call present",
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotIn(
                    "materialization",
                    node.module,
                    "retired materialization import present",
                )
        self.assertNotIn("NOT_VULNERABLE", source)
        self.assertNotIn("CONFIRMED", source)

    def test_no_enablement_assignment(self) -> None:
        tree = ast.parse(_read_b3_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in (
                        "LIVE_TRAFFIC_ENABLED",
                        "HTTP_PROBE_PILOT_ENABLED",
                        "LIVE_NUCLEI",
                        "LIVE_BROWSER",
                    ):
                        self.assertIsNot(
                            getattr(node.value, "value", None),
                            True,
                            f"{target.id} must never be assigned True",
                        )

    def test_no_live_connection_performed(self) -> None:
        # Structural proof: the B3 module exposes no callable that can
        # dial, and the pilot gate performs no I/O (evaluate twice with
        # identical inputs, no socket module touched by this package).
        import socket as _socket

        with mock.patch.object(
            _socket, "socket", side_effect=AssertionError("no dial allowed")
        ):
            b3.evaluate_pilot_gate(**_pilot_kwargs())
            b3.evaluate_pilot_gate(
                **_pilot_kwargs(config=b3.PilotGateConfig())
            )


if __name__ == "__main__":
    unittest.main()
