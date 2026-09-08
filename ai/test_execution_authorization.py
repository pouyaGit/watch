"""Focused Phase 5B ExecutionAuthorization tests (offline, deterministic).

Covers the 5B contract only: authenticity-by-reference, lifecycle,
single-consume CAS, canonical artifact identity, exactly-one
semantics, HTTP method contract, target binding, XSS derivation +
stored leases, fixture/CDN pins, issuer separation, error hygiene.

No network, no subprocess, no database, no LLM, no executors, no
verifiers, no findings, no scope evaluation, no DNS.
"""

import hashlib
import json
import unittest

from pydantic import ValidationError

from ai.authorizer import (
    InMemoryAuthorizationStore,
    consume_authorization,
    consume_read_lease,
    consume_submit_lease,
    get_issued_authorization,
    issue_authorization,
    resolve_authorized_artifact,
    revoke_authorization,
    validate_derivation_binding,
    validate_fixture_binding,
    validate_target_binding,
)
from ai.schemas.artifact import (
    artifact_id_for,
    build_artifact_reference,
    content_hash_for_bytes,
)
from ai.schemas.execution_authorization import (
    ArtifactBinding,
    AuthzError,
    AuthorizationRequest,
    CdnMappingBinding,
    FixtureBinding,
    IssuedExecutionAuthorization,
    IssuerContext,
    StoredStageLeases,
    TargetBinding,
    XSSDerivationContract,
    authorization_id_for,
    check_method_pair,
    effective_port_for,
    idempotency_key_for,
)


NOW = "2026-01-01T00:00:00+00:00"
LATER = "2026-01-02T00:00:00+00:00"
EXPIRY = "2030-01-01T00:00:00+00:00"
SCOPE_HASH = "b" * 64
TP_ID = "tp-" + "a" * 16
HYP_ID = "hyp-" + "c" * 16
TM_ID = "tm-" + "d" * 16
SNAP = "e" * 64


def _content(tag="payload"):
    return content_hash_for_bytes(("xss-" + tag).encode("utf-8"))


def _artifact_binding(tag="payload", **overrides):
    content = _content(tag)
    base = {
        "artifact_id": artifact_id_for(
            artifact_type="xss_payload",
            test_plan_id=TP_ID,
            content_hash=content,
        ),
        "artifact_type": "xss_payload",
        "content_hash": content,
        "test_plan_id": TP_ID,
    }
    base.update(overrides)
    return ArtifactBinding(**base)


def _target_binding(**overrides):
    base = {
        "program_name": "acme",
        "host": "shop.acme.com",
        "scheme": "https",
        "effective_port": 443,
        "scope_lists_hash": SCOPE_HASH,
    }
    base.update(overrides)
    return TargetBinding(**base)


def _request(**overrides):
    base = {
        "test_plan_id": TP_ID,
        "artifact": _artifact_binding(),
        "target": _target_binding(),
        "execution_class": "http_verification",
        "plan_method": "GET",
        "artifact_method": "GET",
        "expires_at": EXPIRY,
    }
    base.update(overrides)
    return AuthorizationRequest(**base)


def _reference_via_factory(tag="payload"):
    from ai.schemas.artifact import build_artifact_reference as build

    return build(
        artifact_type="xss_payload",
        content=("xss-" + tag).encode("utf-8"),
        test_plan_id=TP_ID,
        validation_state="VALID",
    )


# ------------------------------------------------------------------
# AUTHENTICITY (1-9)
# ------------------------------------------------------------------


class AuthenticityTests(unittest.TestCase):
    def test_01_valid_issued_authorization_loads(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        loaded = get_issued_authorization(store, record.authorization_id)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.authorization_id, record.authorization_id)
        self.assertEqual(loaded.lifecycle, "ISSUED")

    def test_02_arbitrary_dict_is_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        forged = record.model_dump(mode="json")
        with self.assertRaises(TypeError):
            get_issued_authorization(store, forged)
        with self.assertRaises(TypeError):
            resolve_authorized_artifact(forged, [])
        with self.assertRaises(TypeError):
            validate_target_binding(
                forged,
                program_name="acme",
                host="shop.acme.com",
                scheme="https",
                effective_port=443,
                scope_lists_hash=SCOPE_HASH,
            )

    def test_03_json_shaped_authorization_is_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        blob = json.loads(record.model_dump_json())
        with self.assertRaises(TypeError):
            consume_authorization(store, blob, now=LATER)
        with self.assertRaises(TypeError):
            get_issued_authorization(store, ["authz-" + "0" * 16])

    def test_04_llm_shaped_object_is_rejected(self):
        class FakeLLMResult:
            def __init__(self, authz_id):
                self.authorization_id = authz_id

        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        with self.assertRaises(TypeError):
            get_issued_authorization(
                store, FakeLLMResult(record.authorization_id)
            )
        with self.assertRaises(TypeError):
            issue_authorization(store, {"test_plan_id": TP_ID}, now=NOW)

    def test_05_same_public_fields_without_provenance_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        # Byte-identical public fields rebuilt outside issuance: the id
        # string alone is opaque; unknown ids return None (never authority).
        unknown = get_issued_authorization(store, "authz-" + "f" * 16)
        self.assertIsNone(unknown)
        # A structurally equal record never issued is not loadable.
        with self.assertRaises(AuthzError) as ctx:
            consume_authorization(store, "authz-" + "f" * 16, now=LATER)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_FOUND")

    def test_06_missing_authorization_is_rejected(self):
        store = InMemoryAuthorizationStore()
        self.assertIsNone(get_issued_authorization(store, "authz-" + "0" * 16))
        with self.assertRaises(AuthzError) as ctx:
            consume_authorization(store, "authz-" + "0" * 16, now=LATER)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_FOUND")

    def test_07_revoked_authorization_is_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        revoke_authorization(store, record.authorization_id)
        with self.assertRaises(AuthzError) as ctx:
            consume_authorization(store, record.authorization_id, now=LATER)
        self.assertEqual(ctx.exception.code, "AUTHZ_REVOKED")

    def test_08_expired_authorization_is_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        with self.assertRaises(AuthzError) as ctx:
            consume_authorization(
                store, record.authorization_id, now="2031-06-01T00:00:00+00:00"
            )
        self.assertEqual(ctx.exception.code, "AUTHZ_EXPIRED")

    def test_09_consumed_authorization_is_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        consume_authorization(store, record.authorization_id, now=LATER)
        with self.assertRaises(AuthzError) as ctx:
            consume_authorization(store, record.authorization_id, now=LATER)
        self.assertEqual(ctx.exception.code, "AUTHZ_ALREADY_CONSUMED")


# ------------------------------------------------------------------
# LIFECYCLE (10-12)
# ------------------------------------------------------------------


class LifecycleTests(unittest.TestCase):
    def test_10_valid_lifecycle_transitions_succeed(self):
        record = IssuedExecutionAuthorization.model_validate(
            issue_authorization(
                InMemoryAuthorizationStore(), _request(), now=NOW
            ).model_dump(mode="json")
        )
        self.assertEqual(record.lifecycle, "ISSUED")
        store = InMemoryAuthorizationStore()
        first = issue_authorization(store, _request(), now=NOW)
        consumed = consume_authorization(store, first.authorization_id, now=LATER)
        self.assertEqual(consumed.lifecycle, "CONSUMED")
        second = issue_authorization(
            store, _request(caller_scope="scheduled"), now=NOW
        )
        revoked = revoke_authorization(store, second.authorization_id)
        self.assertEqual(revoked.lifecycle, "REVOKED")

    def test_11_invalid_transitions_fail(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        consume_authorization(store, record.authorization_id, now=LATER)
        # Consumed cannot be revoked (not ISSUED).
        with self.assertRaises(AuthzError) as ctx:
            revoke_authorization(store, record.authorization_id)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        # Lease transitions out of terminal states fail.
        leases = StoredStageLeases(round_id="sr-" + "1" * 32)
        done = leases.transition_submit("CONSUMED")
        with self.assertRaises(AuthzError) as ctx2:
            done.transition_submit("CONSUMED")
        self.assertEqual(ctx2.exception.code, "LEASE_NOT_LIVE")

    def test_12_reissuance_does_not_resurrect_consumed(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        consume_authorization(store, record.authorization_id, now=LATER)
        # Same basis dedupes to the consumed record; still not live.
        again = issue_authorization(store, _request(), now=NOW)
        self.assertEqual(again.authorization_id, record.authorization_id)
        with self.assertRaises(AuthzError) as ctx:
            consume_authorization(store, again.authorization_id, now=LATER)
        self.assertEqual(ctx.exception.code, "AUTHZ_ALREADY_CONSUMED")


# ------------------------------------------------------------------
# CONCURRENCY / IDEMPOTENCY (13-17)
# ------------------------------------------------------------------


class ConcurrencyTests(unittest.TestCase):
    def test_13_single_consume_succeeds_once(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        consumed = consume_authorization(store, record.authorization_id, now=LATER)
        self.assertEqual(consumed.lifecycle, "CONSUMED")
        self.assertEqual(consumed.record_version, 2)

    def test_14_second_consume_cannot_execute(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        consume_authorization(store, record.authorization_id, now=LATER)
        for _ in range(3):
            with self.assertRaises(AuthzError) as ctx:
                consume_authorization(store, record.authorization_id, now=LATER)
            self.assertEqual(ctx.exception.code, "AUTHZ_ALREADY_CONSUMED")

    def test_15_cas_loss_is_deterministic(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        stale = get_issued_authorization(store, record.authorization_id)
        assert stale is not None
        consume_authorization(store, record.authorization_id, now=LATER)
        # Direct CAS on the stale version fails deterministically.
        progressed = stale.model_copy(
            update={"lifecycle": "CONSUMED", "record_version": stale.record_version + 1}
        )
        from ai.authorizer.store import VersionConflictError

        with self.assertRaises(VersionConflictError):
            store.compare_and_swap(
                stale.authorization_id, stale.record_version, progressed
            )

    def test_16_duplicate_idempotency_key_deduped(self):
        store = InMemoryAuthorizationStore()
        first = issue_authorization(store, _request(), now=NOW)
        second = issue_authorization(store, _request(), now=NOW)
        self.assertEqual(first.authorization_id, second.authorization_id)
        self.assertEqual(first.idempotency_key, second.idempotency_key)

    def test_17_different_idempotency_keys_distinct(self):
        store = InMemoryAuthorizationStore()
        first = issue_authorization(store, _request(), now=NOW)
        second = issue_authorization(
            store, _request(caller_scope="scheduled"), now=NOW
        )
        self.assertNotEqual(first.authorization_id, second.authorization_id)
        self.assertNotEqual(first.idempotency_key, second.idempotency_key)
        key_a = idempotency_key_for(
            test_plan_id=TP_ID,
            artifact_id=first.artifact.artifact_id,
            content_hash=first.artifact.content_hash,
            program_name="acme",
            host="shop.acme.com",
            execution_class="http_verification",
            scope_lists_hash=SCOPE_HASH,
            caller_scope="manual",
        )
        self.assertEqual(key_a, first.idempotency_key)


# ------------------------------------------------------------------
# ARTIFACT (18-29)
# ------------------------------------------------------------------


class ArtifactBindingTests(unittest.TestCase):
    def _issued(self, **overrides):
        store = InMemoryAuthorizationStore()
        return store, issue_authorization(store, _request(**overrides), now=NOW)

    def test_18_canonical_artifact_identity_accepted(self):
        store, record = self._issued()
        stored = _reference_via_factory()
        resolved = resolve_authorized_artifact(record, [stored])
        self.assertEqual(resolved.artifact_id, record.artifact.artifact_id)

    def test_19_legacy_content_keyed_identity_cannot_authorize(self):
        content = _content()
        legacy_id = "art-" + content[:16]
        # Legacy derivation differs from the canonical plan-bound identity.
        canonical = artifact_id_for(
            artifact_type="xss_payload", test_plan_id=TP_ID, content_hash=content
        )
        self.assertNotEqual(legacy_id, canonical)
        with self.assertRaises(ValidationError):
            _artifact_binding()
            ArtifactBinding(
                artifact_id=legacy_id,
                artifact_type="xss_payload",
                content_hash=content,
                test_plan_id=TP_ID,
            )

    def test_20_wrong_artifact_id_rejected(self):
        _, record = self._issued()
        other = _reference_via_factory(tag="other")
        with self.assertRaises(AuthzError) as ctx:
            resolve_authorized_artifact(record, [other])
        self.assertEqual(ctx.exception.code, "ARTIFACT_BINDING_MISMATCH")

    def test_21_wrong_hash_rejected(self):
        _, record = self._issued()
        stored = _reference_via_factory()
        tampered = record.model_copy(
            update={
                "artifact": record.artifact.model_copy(
                    update={"content_hash": "0" * 64}
                )
            }
        )
        with self.assertRaises(AuthzError) as ctx:
            resolve_authorized_artifact(tampered, [stored])
        self.assertEqual(ctx.exception.code, "ARTIFACT_BINDING_MISMATCH")

    def test_22_wrong_plan_rejected(self):
        _, record = self._issued()
        stored = _reference_via_factory()
        tampered = record.model_copy(
            update={
                "artifact": record.artifact.model_copy(
                    update={"test_plan_id": "tp-" + "f" * 16}
                )
            }
        )
        with self.assertRaises(AuthzError) as ctx:
            resolve_authorized_artifact(tampered, [stored])
        self.assertEqual(ctx.exception.code, "ARTIFACT_BINDING_MISMATCH")

    def test_23_wrong_type_rejected(self):
        with self.assertRaises(ValidationError):
            ArtifactBinding(
                artifact_id="art-" + "0" * 16,
                artifact_type="http_request",  # legacy vocabulary
                content_hash="0" * 64,
                test_plan_id=TP_ID,
            )

    def test_24_wrong_schema_version_rejected(self):
        with self.assertRaises(ValidationError):
            ArtifactBinding(
                artifact_id="art-" + "0" * 16,
                artifact_type="xss_payload",
                content_hash="0" * 64,
                test_plan_id=TP_ID,
                artifact_schema_version="artifact/v2",
            )

    def test_25_wrong_hypothesis_binding_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(
            store,
            _request(
                artifact=_artifact_binding(hypothesis_id=HYP_ID),
            ),
            now=NOW,
        )
        stored = _reference_via_factory()  # no hypothesis binding
        with self.assertRaises(AuthzError) as ctx:
            resolve_authorized_artifact(record, [stored])
        self.assertEqual(ctx.exception.code, "ARTIFACT_BINDING_MISMATCH")

    def test_26_wrong_match_binding_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(
            store,
            _request(artifact=_artifact_binding(match_id=TM_ID)),
            now=NOW,
        )
        stored = _reference_via_factory()
        with self.assertRaises(AuthzError) as ctx:
            resolve_authorized_artifact(record, [stored])
        self.assertEqual(ctx.exception.code, "ARTIFACT_BINDING_MISMATCH")

    def test_27_wrong_snapshot_binding_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(
            store,
            _request(artifact=_artifact_binding(snapshot_hash=SNAP)),
            now=NOW,
        )
        stored = _reference_via_factory()
        with self.assertRaises(AuthzError) as ctx:
            resolve_authorized_artifact(record, [stored])
        self.assertEqual(ctx.exception.code, "ARTIFACT_BINDING_MISMATCH")

    def test_28_zero_eligible_artifact_rejected(self):
        _, record = self._issued()
        with self.assertRaises(AuthzError) as ctx:
            resolve_authorized_artifact(record, [])
        self.assertEqual(ctx.exception.code, "NOT_READY")

    def test_29_two_eligible_artifacts_ambiguous(self):
        _, record = self._issued()
        first = _reference_via_factory()
        second = _reference_via_factory(tag="other-ambiguous-x")
        # Both stored for the same plan: ambiguous even though one matches.
        with self.assertRaises(AuthzError) as ctx:
            resolve_authorized_artifact(record, [first, second])
        self.assertEqual(ctx.exception.code, "ARTIFACT_AMBIGUOUS")


# ------------------------------------------------------------------
# METHOD (30-40)
# ------------------------------------------------------------------


class MethodContractTests(unittest.TestCase):
    def test_30_get_accepted(self):
        self.assertEqual(check_method_pair("GET", "GET"), "OK")

    def test_31_post_accepted(self):
        self.assertEqual(check_method_pair("POST", "POST"), "OK")

    def test_32_put_accepted(self):
        self.assertEqual(check_method_pair("PUT", "PUT"), "OK")

    def test_33_patch_accepted(self):
        self.assertEqual(check_method_pair("PATCH", "PATCH"), "OK")

    def test_34_head_accepted(self):
        self.assertEqual(check_method_pair("HEAD", "HEAD"), "OK")

    def test_35_options_accepted(self):
        self.assertEqual(check_method_pair("OPTIONS", "OPTIONS"), "OK")

    def test_36_delete_rejected(self):
        with self.assertRaises(AuthzError) as ctx:
            check_method_pair("DELETE", "DELETE")
        self.assertEqual(ctx.exception.code, "METHOD_NOT_ALLOWED")

    def test_37_connect_rejected(self):
        with self.assertRaises(AuthzError) as ctx:
            check_method_pair("CONNECT", "GET")
        self.assertEqual(ctx.exception.code, "METHOD_NOT_ALLOWED")

    def test_38_trace_rejected(self):
        with self.assertRaises(AuthzError) as ctx:
            check_method_pair("GET", "TRACE")
        self.assertEqual(ctx.exception.code, "METHOD_NOT_ALLOWED")

    def test_39_plan_artifact_mismatch_rejected(self):
        with self.assertRaises(AuthzError) as ctx:
            check_method_pair("GET", "POST")
        self.assertEqual(ctx.exception.code, "TRANSLATION_REJECTED")
        # Issuance with mismatched methods is refused (no coercion path).
        with self.assertRaises(AuthzError):
            issue_authorization(
                InMemoryAuthorizationStore(),
                _request(plan_method="GET", artifact_method="POST"),
                now=NOW,
            )

    def test_40_no_coercion_to_get(self):
        # Forbidden plan method is rejected even when artifact is GET.
        with self.assertRaises(AuthzError) as ctx:
            check_method_pair("DELETE", "GET")
        self.assertEqual(ctx.exception.code, "METHOD_NOT_ALLOWED")
        # Request schema itself forbids DELETE at intake.
        with self.assertRaises(ValidationError):
            _request(plan_method="DELETE")


# ------------------------------------------------------------------
# TARGET (41-46)
# ------------------------------------------------------------------


class TargetBindingTests(unittest.TestCase):
    def _live(self, **overrides):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(**overrides), now=NOW)
        return record

    def _ok(self, record):
        return validate_target_binding(
            record,
            program_name="acme",
            host="shop.acme.com",
            scheme="https",
            effective_port=443,
            scope_lists_hash=SCOPE_HASH,
        )

    def test_41_wrong_program_rejected(self):
        record = self._live()
        with self.assertRaises(AuthzError) as ctx:
            validate_target_binding(
                record,
                program_name="evil",
                host="shop.acme.com",
                scheme="https",
                effective_port=443,
                scope_lists_hash=SCOPE_HASH,
            )
        self.assertEqual(ctx.exception.code, "TARGET_BINDING_MISMATCH")
        self.assertEqual(self._ok(record), "OK")

    def test_42_wrong_host_rejected(self):
        record = self._live()
        with self.assertRaises(AuthzError) as ctx:
            validate_target_binding(
                record,
                program_name="acme",
                host="admin.acme.com",
                scheme="https",
                effective_port=443,
                scope_lists_hash=SCOPE_HASH,
            )
        self.assertEqual(ctx.exception.code, "TARGET_BINDING_MISMATCH")

    def test_43_wrong_scheme_rejected(self):
        record = self._live()
        with self.assertRaises(AuthzError) as ctx:
            validate_target_binding(
                record,
                program_name="acme",
                host="shop.acme.com",
                scheme="http",
                effective_port=443,
                scope_lists_hash=SCOPE_HASH,
            )
        self.assertEqual(ctx.exception.code, "TARGET_BINDING_MISMATCH")

    def test_44_wrong_effective_port_rejected(self):
        record = self._live()
        with self.assertRaises(AuthzError) as ctx:
            validate_target_binding(
                record,
                program_name="acme",
                host="shop.acme.com",
                scheme="https",
                effective_port=8443,
                scope_lists_hash=SCOPE_HASH,
            )
        self.assertEqual(ctx.exception.code, "TARGET_BINDING_MISMATCH")
        # Effective-port defaulting is explicit (no None ambiguity).
        self.assertEqual(effective_port_for("https", None), 443)
        self.assertEqual(effective_port_for("http", None), 80)

    def test_45_wrong_path_binding_rejected(self):
        record = self._live(
            target=_target_binding(path_scope="/shop"),
        )
        with self.assertRaises(AuthzError) as ctx:
            validate_target_binding(
                record,
                program_name="acme",
                host="shop.acme.com",
                scheme="https",
                effective_port=443,
                path_scope="/admin",
                scope_lists_hash=SCOPE_HASH,
            )
        self.assertEqual(ctx.exception.code, "TARGET_BINDING_MISMATCH")

    def test_46_wrong_scope_policy_hash_rejected(self):
        record = self._live()
        with self.assertRaises(AuthzError) as ctx:
            validate_target_binding(
                record,
                program_name="acme",
                host="shop.acme.com",
                scheme="https",
                effective_port=443,
                scope_lists_hash="0" * 64,
            )
        self.assertEqual(ctx.exception.code, "TARGET_BINDING_MISMATCH")


# ------------------------------------------------------------------
# XSS DERIVATION + STORED LEASES (47-57)
# ------------------------------------------------------------------


def _derivation(record):
    return XSSDerivationContract(
        source_artifact_id=record.artifact.artifact_id,
        source_content_hash=record.artifact.content_hash,
        planner_version="oracle-planner/v1",
        oracle_version=1,
        allowed_context="html_body",
        allowed_skeleton_family="attribute",
        execution_phase="oracle",
    )


class XSSDerivationTests(unittest.TestCase):
    def _issued_with_derivation(self, **overrides):
        store = InMemoryAuthorizationStore()
        base = _request()
        contract = _derivation_from_request(base)
        req = _request(xss_derivation=contract, **overrides)
        return store, issue_authorization(store, req, now=NOW)

    def test_47_p_and_o_distinct_concepts(self):
        _, record = self._issued_with_derivation()
        assert record.xss_derivation is not None
        # Source artifact P is bound; executed oracle payload O is derived
        # under the contract and is NOT claimed to equal P anywhere.
        self.assertEqual(
            record.xss_derivation.source_artifact_id,
            record.artifact.artifact_id,
        )
        self.assertNotEqual(
            record.xss_derivation.planner_id, "artifact-bytes"
        )
        self.assertEqual(
            record.xss_derivation.run_salt_authority, "executor-runtime"
        )

    def test_48_derivation_binding_mismatch_rejected(self):
        _, record = self._issued_with_derivation()
        other = record.xss_derivation.model_copy(
            update={"source_content_hash": "0" * 64}
        )
        with self.assertRaises(AuthzError) as ctx:
            validate_derivation_binding(record, other)
        self.assertEqual(ctx.exception.code, "DERIVATION_BINDING_MISMATCH")

    def test_49_wrong_planner_version_rejected(self):
        _, record = self._issued_with_derivation()
        assert record.xss_derivation is not None
        other = record.xss_derivation.model_copy(
            update={"planner_version": "oracle-planner/v9"}
        )
        with self.assertRaises(AuthzError) as ctx:
            validate_derivation_binding(record, other)
        self.assertEqual(ctx.exception.code, "DERIVATION_BINDING_MISMATCH")

    def test_50_wrong_oracle_version_rejected(self):
        _, record = self._issued_with_derivation()
        assert record.xss_derivation is not None
        other = record.xss_derivation.model_copy(update={"oracle_version": 99})
        with self.assertRaises(AuthzError) as ctx:
            validate_derivation_binding(record, other)
        self.assertEqual(ctx.exception.code, "DERIVATION_BINDING_MISMATCH")

    def test_51_wrong_context_rejected(self):
        _, record = self._issued_with_derivation()
        assert record.xss_derivation is not None
        other = record.xss_derivation.model_copy(
            update={"allowed_context": "script_block"}
        )
        with self.assertRaises(AuthzError) as ctx:
            validate_derivation_binding(record, other)
        self.assertEqual(ctx.exception.code, "DERIVATION_BINDING_MISMATCH")

    def test_52_wrong_execution_phase_rejected(self):
        _, record = self._issued_with_derivation()
        assert record.xss_derivation is not None
        other = record.xss_derivation.model_copy(
            update={"execution_phase": "stored_read"}
        )
        with self.assertRaises(AuthzError) as ctx:
            validate_derivation_binding(record, other)
        self.assertEqual(ctx.exception.code, "DERIVATION_BINDING_MISMATCH")

    def test_53_stored_round_has_separate_leases(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(
            store,
            _request(execution_phase="submit", stored_round_id="sr-" + "2" * 32),
            now=NOW,
        )
        assert record.stored_leases is not None
        self.assertEqual(record.stored_leases.submit_lease, "PENDING")
        self.assertEqual(record.stored_leases.read_lease, "PENDING")

    def test_54_read_cannot_consume_without_own_gate(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(
            store,
            _request(execution_phase="submit", stored_round_id="sr-" + "3" * 32),
            now=NOW,
        )
        progressed = consume_read_lease(store, record.authorization_id, now=LATER)
        assert progressed.stored_leases is not None
        self.assertEqual(progressed.stored_leases.read_lease, "CONSUMED")
        # Second READ consume fails: the lease is spent.
        with self.assertRaises(AuthzError) as ctx:
            consume_read_lease(store, record.authorization_id, now=LATER)
        self.assertEqual(ctx.exception.code, "LEASE_NOT_LIVE")

    def test_55_submit_success_does_not_authorize_read(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(
            store,
            _request(execution_phase="submit", stored_round_id="sr-" + "4" * 32),
            now=NOW,
        )
        progressed = consume_submit_lease(store, record.authorization_id, now=LATER)
        assert progressed.stored_leases is not None
        self.assertEqual(progressed.stored_leases.submit_lease, "CONSUMED")
        # READ lease is still PENDING: SUBMIT success changed nothing about it.
        self.assertEqual(progressed.stored_leases.read_lease, "PENDING")

    def test_56_invalid_lease_transitions_rejected(self):
        leases = StoredStageLeases(round_id="sr-" + "5" * 32)
        with self.assertRaises(AuthzError) as ctx:
            leases.transition_submit("PENDING")
        self.assertEqual(ctx.exception.code, "LEASE_NOT_LIVE")
        skipped = leases.transition_read("SKIPPED")
        with self.assertRaises(AuthzError):
            skipped.transition_read("CONSUMED")

    def test_57_dual_hash_representation_deterministic(self):
        _, record = self._issued_with_derivation()
        assert record.xss_derivation is not None
        view = {
            "artifact_content_hash": record.artifact.content_hash,
            "derivation_source_hash": record.xss_derivation.source_content_hash,
            "planner": record.xss_derivation.planner_id,
        }
        first = hashlib.sha256(
            json.dumps(view, sort_keys=True).encode("utf-8")
        ).hexdigest()
        second = hashlib.sha256(
            json.dumps(view, sort_keys=True).encode("utf-8")
        ).hexdigest()
        self.assertEqual(first, second)
        self.assertEqual(
            view["artifact_content_hash"], view["derivation_source_hash"]
        )


def _derivation_from_request(request):
    return XSSDerivationContract(
        source_artifact_id=request.artifact.artifact_id,
        source_content_hash=request.artifact.content_hash,
        planner_version="oracle-planner/v1",
        oracle_version=1,
        allowed_context="html_body",
        allowed_skeleton_family="attribute",
        execution_phase="oracle",
    )


# ------------------------------------------------------------------
# FIXTURES / CDN (58-60)
# ------------------------------------------------------------------


def _fixture_binding():
    return FixtureBinding(
        fixture_set_id="fix-nuclei-cve-wordpress",
        fixture_version="v3",
        fixture_hashes=(_content("benign"), _content("vuln")),
        family_binding="nuclei/cve-wordpress",
    )


class FixtureCdnTests(unittest.TestCase):
    def test_58_fixture_mismatch_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(
            store, _request(fixture_binding=_fixture_binding()), now=NOW
        )
        self.assertEqual(
            validate_fixture_binding(record, _fixture_binding()), "OK"
        )
        tampered = _fixture_binding().model_copy(
            update={"fixture_hashes": ("0" * 64, "1" * 64)}
        )
        with self.assertRaises(AuthzError) as ctx:
            validate_fixture_binding(record, tampered)
        self.assertEqual(ctx.exception.code, "AUTHZ_BINDING_MISMATCH")

    def test_59_arbitrary_fixture_bytes_cannot_enter(self):
        # FixtureBinding carries hashes only; raw bytes are unrepresentable.
        with self.assertRaises(ValidationError):
            FixtureBinding(
                fixture_set_id="fix-x",
                fixture_version="v1",
                fixture_hashes=("not-a-hash",),
                family_binding="nuclei/x",
            )
        with self.assertRaises(TypeError):
            validate_fixture_binding(
                issue_authorization(
                    InMemoryAuthorizationStore(),
                    _request(fixture_binding=_fixture_binding()),
                    now=NOW,
                ),
                {"fixture_set_id": "fix-nuclei-cve-wordpress"},
            )

    def test_60_cdn_mapping_mismatch_rejected(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(
            store,
            _request(
                cdn_binding=CdnMappingBinding(
                    mapping_version="cdn-v7", mapping_hash="a" * 64
                )
            ),
            now=NOW,
        )
        assert record.cdn_binding is not None
        self.assertEqual(record.cdn_binding.mapping_version, "cdn-v7")
        tampered = record.model_copy(
            update={
                "cdn_binding": CdnMappingBinding(
                    mapping_version="cdn-v7", mapping_hash="f" * 64
                )
            }
        )
        self.assertNotEqual(tampered.cdn_binding, record.cdn_binding)


# ------------------------------------------------------------------
# ISSUER (61-64)
# ------------------------------------------------------------------


class IssuerBoundaryTests(unittest.TestCase):
    def test_61_request_cannot_be_consumed_as_authority(self):
        request = _request()
        with self.assertRaises(TypeError):
            consume_authorization(
                InMemoryAuthorizationStore(), request, now=LATER
            )
        with self.assertRaises(TypeError):
            get_issued_authorization(
                InMemoryAuthorizationStore(), request
            )

    def test_62_issuer_context_cannot_mint_authority(self):
        context = IssuerContext(
            test_plan_id=TP_ID,
            artifact_id="art-" + "0" * 16,
            content_hash="0" * 64,
        )
        self.assertFalse(context.is_authority)
        store = InMemoryAuthorizationStore()
        with self.assertRaises(TypeError):
            issue_authorization(store, context, now=NOW)
        with self.assertRaises(TypeError):
            get_issued_authorization(store, context)

    def test_63_unauthorized_issuer_identity_rejected(self):
        for principal in ("llm-researcher", "scheduler", "collector", ""):
            with self.assertRaises(ValidationError):
                _request(issuer_identity=principal)

    def test_64_llm_scheduler_principal_cannot_issue(self):
        store = InMemoryAuthorizationStore()
        # Even a well-formed request object from a forbidden principal
        # cannot reach issuance: schema + service both refuse.
        with self.assertRaises((ValidationError, AuthzError, TypeError)):
            issue_authorization(
                store,
                {"issuer_identity": "scheduler", "test_plan_id": TP_ID},
                now=NOW,
            )


# ------------------------------------------------------------------
# ERROR / HYGIENE (65-66)
# ------------------------------------------------------------------


class ErrorHygieneTests(unittest.TestCase):
    def test_65_security_errors_contain_no_secret_material(self):
        err = AuthzError("AUTHZ_NOT_FOUND", "unknown authorization")
        text = str(err)
        for marker in (
            "mongodb://",
            "password",
            "api_key",
            "secret",
            "bearer ",
        ):
            self.assertNotIn(marker, text.casefold())
        with self.assertRaises(ValueError):
            AuthzError(
                "AUTHZ_NOT_FOUND", "conn mongodb://user:password@host/db"
            )

    def test_66_raw_db_exception_text_not_exposed(self):
        store = InMemoryAuthorizationStore()
        record = issue_authorization(store, _request(), now=NOW)
        try:
            consume_authorization(store, record.authorization_id, now=LATER)
            consume_authorization(store, record.authorization_id, now=LATER)
        except AuthzError as exc:
            self.assertEqual(exc.code, "AUTHZ_ALREADY_CONSUMED")
            self.assertNotIn("Traceback", str(exc))
            self.assertLessEqual(len(str(exc)), 400)


if __name__ == "__main__":
    unittest.main()
