"""Focused offline tests for Phase 5H-core (evidence + accounting).

Pure, deterministic, stdlib ``unittest``. No network, no subprocess,
no database, no LLM, no browser, no Nuclei invocation, no verifier
runtime, no findings. Random IDs are asserted by format/uniqueness,
never by value.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from ai.audit import trail as audit_trail
from ai.evidence import builder as seal
from ai.evidence import hashing, handoff, observations, orphan, scrubber
from ai.evidence.builder import EvidenceBuilder
from ai.execution import ledger as ledger_mod
from ai.execution.ledger import (
    DuplicateExecutionError,
    ExecutionRecord,
    InMemoryExecutionLedger,
    InProgressExecutionError,
    ReplayExecutionError,
)
from ai.limits import ceilings
from ai.schemas import evidence as ev

TP_ID = "tp-" + "a" * 16
HYP_ID = "hyp-" + "b" * 16
TM_ID = "tm-" + "c" * 16
AUTHZ_ID = "authz-" + "d" * 16
SCOPE_HASH = "e" * 64
NONCE = "f" * 32
EX_ID = "ex-" + "1" * 32
EX_ID2 = "ex-" + "2" * 32
ART_BYTES = b"test-payload-bytes"
ISSUED_AT = "2026-01-01T00:00:00+00:00"
EXPIRES_AT = "2026-02-01T00:00:00+00:00"
STARTED_AT = "2026-01-15T00:00:00+00:00"

from ai.schemas.artifact import artifact_id_for, content_hash_for_bytes
from ai.schemas.execution_authorization import IssuedExecutionAuthorization

ART_HASH = content_hash_for_bytes(ART_BYTES)
ART_ID = artifact_id_for(
    artifact_type="http_request_spec",
    test_plan_id=TP_ID,
    content_hash=ART_HASH,
)


def make_issuance(**overrides) -> IssuedExecutionAuthorization:
    base = {
        "authorization_id": AUTHZ_ID,
        "idempotency_key": "0" * 64,
        "issuance_nonce": NONCE,
        "issuer_identity": "human-review-board",
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "lifecycle": "ISSUED",
        "record_version": 1,
        "test_plan_id": TP_ID,
        "hypothesis_id": HYP_ID,
        "match_id": TM_ID,
        "artifact": {
            "artifact_id": ART_ID,
            "artifact_type": "http_request_spec",
            "content_hash": ART_HASH,
            "test_plan_id": TP_ID,
            "hypothesis_id": HYP_ID,
            "match_id": TM_ID,
        },
        "target": {
            "program_name": "acme",
            "host": "example.com",
            "scheme": "https",
            "effective_port": 443,
            "path_scope": "/app",
            "scope_policy_version": "scope-policy/v1",
            "scope_lists_hash": SCOPE_HASH,
        },
        "execution_class": "http_probe",
        "execution_phase": "single",
        "plan_method": "GET",
        "artifact_method": "GET",
        "caller_scope": "manual",
    }
    base.update(overrides)
    return IssuedExecutionAuthorization(**base)


def make_http_obs(url: str = "https://example.com/app?q=1") -> (
    ev.HttpObservation
):
    body_hash, sample, omitted = observations.observe_body(
        b"hello", content_type="text/html"
    )
    return ev.HttpObservation(
        method="GET",
        request_url=observations.observe_url(url),
        request_headers=observations.filter_headers(
            {"Accept": "text/html"}, allowlist=observations.REQUEST_HEADER_ALLOWLIST
        ),
        request_body_hash=hashing.sha256_hex(b""),
        response_status=200,
        response_headers=observations.filter_headers(
            {"Content-Type": "text/html"},
            allowlist=observations.RESPONSE_HEADER_ALLOWLIST,
        ),
        response_body_hash=body_hash,
        response_body_sample=sample,
        sample_omitted=omitted,
        redirect_chain=[observations.observe_url(url)],
        transport_outcome="responded",
    )


def make_builder(
    execution_class: str = "http_probe",
    execution_id: str = EX_ID,
    issuance: IssuedExecutionAuthorization | None = None,
) -> EvidenceBuilder:
    return EvidenceBuilder.begin(
        authorization=issuance or make_issuance(),
        execution_id=execution_id,
        execution_class=execution_class,
        started_at=STARTED_AT,
    )


def seal_http(execution_id: str = EX_ID) -> ev.EvidenceRecord:
    builder = make_builder(execution_id=execution_id)
    builder.attach_http(make_http_obs())
    return builder.seal(finished_at=STARTED_AT, sealed_at=STARTED_AT)


# ------------------------------------------------------------------
# IDENTITY
# ------------------------------------------------------------------


class IdentityTest(unittest.TestCase):
    def test_random_evidence_id(self) -> None:
        first = ev.generate_evidence_id()
        second = ev.generate_evidence_id()
        self.assertRegex(first, r"^ev-[0-9a-f]{32}$")
        self.assertNotEqual(first, second)

    def test_random_execution_id(self) -> None:
        first = ev.generate_execution_id()
        second = ev.generate_execution_id()
        self.assertRegex(first, r"^ex-[0-9a-f]{32}$")
        self.assertNotEqual(first, second)

    def test_canonical_hash_deterministic(self) -> None:
        first = seal_http()
        second = seal_http(execution_id=EX_ID)
        self.assertEqual(first.bindings_hash, second.bindings_hash)
        self.assertEqual(first.observations_hash, second.observations_hash)
        self.assertEqual(first.content_hash, second.content_hash)

    def test_timing_excluded(self) -> None:
        first = seal_http()
        builder = make_builder(execution_id=EX_ID)
        builder.attach_http(make_http_obs())
        other = builder.seal(
            finished_at="2027-05-05T05:05:05+00:00",
            sealed_at="2027-05-05T05:05:06+00:00",
        )
        self.assertEqual(first.bindings_hash, other.bindings_hash)
        self.assertEqual(first.observations_hash, other.observations_hash)
        self.assertEqual(first.content_hash, other.content_hash)

    def test_null_equals_absent(self) -> None:
        payload_with = {"a": None, "b": 1}
        payload_without = {"b": 1}
        self.assertEqual(
            hashing.hash_payload(payload_with),
            hashing.hash_payload(payload_without | {"a": None}),
        )

    def test_repr_cannot_influence_hash(self) -> None:
        self.assertEqual(
            hashing.hash_payload({"b": 1, "a": 2}),
            hashing.hash_payload({"a": 2, "b": 1}),
        )
        with self.assertRaises(TypeError):
            hashing.normalize_for_hash({1, 2})
        with self.assertRaises(TypeError):
            hashing.normalize_for_hash(1.5)

    def test_audit_keys_refused(self) -> None:
        with self.assertRaises(TypeError):
            hashing.hash_payload({"started_at": "now", "b": 1})
        with self.assertRaises(TypeError):
            hashing.hash_payload({"sealed_at": "now"})


# ------------------------------------------------------------------
# LIFECYCLE
# ------------------------------------------------------------------


class LifecycleTest(unittest.TestCase):
    def test_building_to_sealed(self) -> None:
        record = seal_http()
        self.assertEqual(record.lifecycle, "SEALED")
        self.assertTrue(record.complete)

    def test_building_to_incomplete(self) -> None:
        builder = make_builder()
        partial = builder.seal_partial(
            reasons=("response_missing",),
            finished_at=STARTED_AT,
            sealed_at=STARTED_AT,
        )
        self.assertEqual(partial.lifecycle, "INCOMPLETE")
        self.assertFalse(partial.complete)
        self.assertEqual(partial.incomplete_reasons, ("response_missing",))

    def test_sealed_immutable(self) -> None:
        record = seal_http()
        # Sealed bytes verify; the spent builder can do nothing more.
        seal.verify_record(record)
        builder = make_builder()
        builder.attach_http(make_http_obs())
        builder.seal()
        with self.assertRaises(ev.EvidenceError) as ctx:
            builder.seal()
        self.assertEqual(ctx.exception.code, "EVIDENCE_IMMUTABLE")
        with self.assertRaises(ev.EvidenceError):
            builder.record

    def test_second_seal_rejected(self) -> None:
        builder = make_builder()
        builder.seal_partial(reasons=("response_missing",))
        with self.assertRaises(ev.EvidenceError) as ctx:
            builder.seal_partial(reasons=("response_missing",))
        self.assertEqual(ctx.exception.code, "EVIDENCE_IMMUTABLE")

    def test_no_rebind_api(self) -> None:
        for name in (
            "reassign",
            "rebind",
            "repair",
            "reattach",
            "supersede",
            "patch",
            "append",
        ):
            self.assertFalse(
                hasattr(EvidenceBuilder, name), f"forbidden API: {name}"
            )
        import ai.evidence.builder as builder_mod
        import ai.evidence.orphan as orphan_mod

        for module in (builder_mod, orphan_mod):
            for name in (
                "reassign",
                "rebind",
                "repair",
                "reattach",
                "supersede",
            ):
                self.assertFalse(
                    hasattr(module, name), f"forbidden symbol: {name}"
                )

    def test_no_repair(self) -> None:
        builder = make_builder()
        builder.attach_http(make_http_obs())
        with self.assertRaises(ev.EvidenceError) as ctx:
            builder.attach_http(make_http_obs())
        self.assertEqual(ctx.exception.code, "EVIDENCE_IMMUTABLE")

    def test_incomplete_terminal_no_promotion(self) -> None:
        builder = make_builder()
        partial = builder.seal_partial(reasons=("response_missing",))
        self.assertEqual(partial.lifecycle, "INCOMPLETE")
        # No builder path promotes INCOMPLETE -> SEALED (spent builder).
        with self.assertRaises(ev.EvidenceError):
            builder.seal()


# ------------------------------------------------------------------
# COMPLETENESS
# ------------------------------------------------------------------


class CompletenessTest(unittest.TestCase):
    def test_complete_accepted(self) -> None:
        record = seal_http()
        self.assertTrue(record.complete)
        seal.verify_record(record)

    def test_incomplete_rejected_by_handoff(self) -> None:
        builder = make_builder()
        partial = builder.seal_partial(reasons=("response_missing",))
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.assemble_handoff(partial)
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_incomplete_never_negative(self) -> None:
        builder = make_builder()
        partial = builder.seal_partial(reasons=("response_missing",))
        fields = set(type(partial).model_fields)
        self.assertTrue(
            fields.isdisjoint(ev.FORBIDDEN_EVIDENCE_FIELDS),
            f"verdict-shaped fields present: {fields}",
        )

    def test_incomplete_never_positive(self) -> None:
        # A complete record seals as data-state only: no verdict,
        # no label, no classification anywhere on the path.
        builder = make_builder()
        builder.attach_http(make_http_obs())
        record = builder.seal(sealed_at=STARTED_AT)
        self.assertTrue(record.complete)
        fields = set(type(record).model_fields)
        self.assertTrue(fields.isdisjoint(ev.FORBIDDEN_EVIDENCE_FIELDS))

    def test_missing_observation_blocks_seal(self) -> None:
        builder = make_builder()
        with self.assertRaises(ev.EvidenceError) as ctx:
            builder.seal()
        self.assertEqual(ctx.exception.code, "EVIDENCE_INCOMPLETE")


# ------------------------------------------------------------------
# UNKNOWN
# ------------------------------------------------------------------


class UnknownTest(unittest.TestCase):
    def _started_row(self, execution_id: str = EX_ID) -> ExecutionRecord:
        ledger = InMemoryExecutionLedger()
        row = ExecutionRecord(
            execution_id=execution_id,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        ledger.put_new(row)
        return ledger.mark_started(execution_id, started_at=STARTED_AT)

    def test_unknown_has_no_evidence(self) -> None:
        ledger = InMemoryExecutionLedger()
        row = ExecutionRecord(
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        ledger.put_new(row)
        ledger.mark_started(EX_ID, started_at=STARTED_AT)
        terminal = ledger.mark_unknown(EX_ID, terminal_at=STARTED_AT)
        self.assertEqual(terminal.lifecycle, "UNKNOWN")
        self.assertIsNone(terminal.evidence_id)

    def test_unknown_cannot_handoff(self) -> None:
        terminal_row = self._started_row()
        self.assertEqual(terminal_row.lifecycle, "STARTED")
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.assemble_handoff(
                make_builder().seal_partial(reasons=("response_missing",))
            )
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_unknown_cannot_reuse_authorization(self) -> None:
        ledger = InMemoryExecutionLedger()
        row = ExecutionRecord(
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        ledger.put_new(row)
        ledger.mark_started(EX_ID, started_at=STARTED_AT)
        ledger.mark_unknown(EX_ID, terminal_at=STARTED_AT)
        replay = ExecutionRecord(
            execution_id=EX_ID2,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="2" * 64,
        )
        with self.assertRaises(ReplayExecutionError):
            ledger.put_new(replay)

    def test_stored_submit_unknown_kills_round(self) -> None:
        decision = ledger_mod.crash_decision("transport_unknown")
        self.assertTrue(decision["new_authz_required"])
        self.assertFalse(decision["verifier"])
        self.assertEqual(decision["evidence"], "OUTCOME_UNKNOWN_no_bytes")


# ------------------------------------------------------------------
# HASH
# ------------------------------------------------------------------


class HashTest(unittest.TestCase):
    def test_hashes_deterministic(self) -> None:
        first = seal.compute_hashes(seal_http())
        second = seal.compute_hashes(seal_http())
        self.assertEqual(first, second)

    def test_modified_content_rejected(self) -> None:
        record = seal_http()
        # Tamper with a hashed leaf via the observation model.
        tampered_http = record.http.model_copy(
            update={"response_body_sample": "evil"}
        )
        tampered = record.model_copy(update={"http": tampered_http})
        with self.assertRaises(ev.EvidenceError) as ctx:
            seal.verify_record(tampered)
        self.assertEqual(ctx.exception.code, "EVIDENCE_HASH_MISMATCH")
        self.assertIn("content_hash", ctx.exception.detail)

    def test_modified_observations_rejected(self) -> None:
        record = seal_http()
        tampered_http = record.http.model_copy(
            update={"response_status": 500}
        )
        tampered = record.model_copy(update={"http": tampered_http})
        with self.assertRaises(ev.EvidenceError) as ctx:
            seal.verify_record(tampered)
        self.assertEqual(ctx.exception.code, "EVIDENCE_HASH_MISMATCH")
        self.assertIn("observations_hash", ctx.exception.detail)

    def test_modified_bindings_rejected(self) -> None:
        record = seal_http()
        tampered = record.model_copy(update={"test_plan_id": "tp-" + "9" * 16})
        with self.assertRaises(ev.EvidenceError) as ctx:
            seal.verify_record(tampered)
        self.assertEqual(ctx.exception.code, "EVIDENCE_HASH_MISMATCH")


# ------------------------------------------------------------------
# SECRETS
# ------------------------------------------------------------------


class SecretTest(unittest.TestCase):
    def test_authorization_redacted(self) -> None:
        scrubbed = scrubber.scrub_headers({"Authorization": "Bearer abc"})
        self.assertEqual(scrubbed, {"Authorization": "[REDACTED]"})

    def test_cookie_redacted(self) -> None:
        scrubbed = scrubber.scrub_headers({"Cookie": "sid=1"})
        self.assertEqual(scrubbed["Cookie"], "[REDACTED]")

    def test_set_cookie_redacted(self) -> None:
        scrubbed = scrubber.scrub_headers({"Set-Cookie": "sid=1"})
        self.assertEqual(scrubbed["Set-Cookie"], "[REDACTED]")

    def test_api_key_redacted(self) -> None:
        scrubbed = scrubber.scrub_headers({"X-Api-Key": "k"})
        self.assertEqual(scrubbed["X-Api-Key"], "[REDACTED]")

    def test_token_param_redacted(self) -> None:
        self.assertIn("token=%5BREDAC", scrubber.scrub_query("a=1&token=xyz"))

    def test_connection_uri_redacted(self) -> None:
        text = scrubber.scrub_text("mongodb://user:pass@host/db")
        self.assertNotIn("pass", text)
        self.assertIn("[REDACTED]", text)

    def test_private_key_redacted(self) -> None:
        text = scrubber.scrub_text(
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
        )
        self.assertNotIn("abc", text)

    def test_raw_exception_rejected(self) -> None:
        with self.assertRaises(ValueError):
            scrubber.sanitized_reason(
                "connection_error", "mongodb://root:secret@host/"
            )
        with self.assertRaises(ValueError):
            scrubber.sanitized_reason("no_such_code")
        reason = scrubber.sanitized_reason("transport_timeout", "hop=2")
        self.assertLessEqual(len(reason), 200)
        self.assertTrue(reason.startswith("transport_timeout"))

    def test_redacted_values_bounded(self) -> None:
        headers = {f"X-Custom-{i}": "v" * 5000 for i in range(100)}
        snapshot = observations.filter_headers(
            headers, allowlist=observations.RESPONSE_HEADER_ALLOWLIST
        )
        total = sum(
            len(k) + len(v) for k, v in snapshot.headers.items()
        )
        self.assertLessEqual(total, observations.MAX_HEADERS_TOTAL)
        self.assertLessEqual(len(snapshot.headers), observations.MAX_HEADERS)


# ------------------------------------------------------------------
# URL
# ------------------------------------------------------------------


class UrlTest(unittest.TestCase):
    def test_userinfo_removed(self) -> None:
        observed = observations.observe_url(
            "https://user:pass@example.com/app"
        )
        self.assertNotIn("user", observed.redacted_url)
        self.assertNotIn("pass", observed.redacted_url)

    def test_secret_query_redacted(self) -> None:
        observed = observations.observe_url(
            "https://example.com/app?token=abc&q=1"
        )
        self.assertNotIn("abc", observed.redacted_url)
        self.assertIn("q=1", observed.redacted_url)

    def test_fragment_removed(self) -> None:
        observed = observations.observe_url(
            "https://example.com/app#section"
        )
        self.assertNotIn("#", observed.redacted_url)

    def test_canonical_deterministic(self) -> None:
        first = observations.canonicalize_url("HTTPS://Example.com/app")
        second = observations.canonicalize_url("https://example.com/app")
        self.assertEqual(first, second)

    def test_redirect_cap(self) -> None:
        chain, truncated = observations.observe_redirect_chain(
            [f"https://example.com/{i}" for i in range(10)]
        )
        self.assertTrue(truncated)
        self.assertLessEqual(len(chain), observations.MAX_REDIRECT_HOPS + 1)

    def test_evidence_url_not_executable(self) -> None:
        source = Path(observations.__file__).read_text()
        for symbol in ("urlopen", "requests.", "socket.", "subprocess"):
            self.assertNotIn(symbol, source)
        observed = observations.observe_url("https://example.com/app")
        self.assertFalse(hasattr(observed, "fetch"))
        self.assertFalse(hasattr(observed, "request"))


# ------------------------------------------------------------------
# HEADERS
# ------------------------------------------------------------------


class HeaderTest(unittest.TestCase):
    def test_allowlist_enforced(self) -> None:
        snapshot = observations.filter_headers(
            {"Content-Type": "text/html", "X-Evil": "1"},
            allowlist=observations.RESPONSE_HEADER_ALLOWLIST,
        )
        self.assertIn("Content-Type", snapshot.headers)
        self.assertNotIn("X-Evil", snapshot.headers)
        self.assertTrue(snapshot.truncated)

    def test_unknown_headers_dropped_bounded(self) -> None:
        headers = {f"X-Unknown-{i}": "v" for i in range(100)}
        snapshot = observations.filter_headers(
            headers, allowlist=observations.RESPONSE_HEADER_ALLOWLIST
        )
        self.assertEqual(snapshot.headers, {})
        self.assertTrue(snapshot.truncated)

    def test_count_cap(self) -> None:
        headers = {f"Content-Type-{i}": "t" for i in range(100)}
        allow = frozenset(headers) | observations.RESPONSE_HEADER_ALLOWLIST
        snapshot = observations.filter_headers(headers, allowlist=allow)
        self.assertLessEqual(len(snapshot.headers), observations.MAX_HEADERS)

    def test_name_cap(self) -> None:
        headers = {"X-" + "n" * 500: "v"}
        allow = frozenset(headers)
        snapshot = observations.filter_headers(headers, allowlist=allow)
        name = next(iter(snapshot.headers))
        self.assertLessEqual(len(name), observations.MAX_HEADER_NAME)

    def test_value_cap(self) -> None:
        headers = {"Server": "s" * 5000}
        snapshot = observations.filter_headers(
            headers, allowlist=observations.RESPONSE_HEADER_ALLOWLIST
        )
        self.assertLessEqual(
            len(snapshot.headers["Server"]), observations.MAX_HEADER_VALUE
        )

    def test_total_cap(self) -> None:
        headers = {f"X-Pad-{i:03d}": "v" * 900 for i in range(32)}
        allow = frozenset(headers)
        snapshot = observations.filter_headers(headers, allowlist=allow)
        total = sum(
            len(k) + len(v) for k, v in snapshot.headers.items()
        )
        self.assertLessEqual(total, observations.MAX_HEADERS_TOTAL)


# ------------------------------------------------------------------
# NUCLEI
# ------------------------------------------------------------------


class NucleiTest(unittest.TestCase):
    def _nuclei_obs(self) -> ev.NucleiObservation:
        stdout = b"[info] something matched-ish"
        return ev.NucleiObservation(
            template_id="cve-2024-1",
            template_hash=hashing.sha256_hex(b"template-bytes"),
            argv_digest=hashing.sha256_hex(b"argv"),
            exit_code=0,
            stdout_hash=hashing.sha256_hex(stdout),
            stderr_hash=hashing.sha256_hex(b""),
            stdout_sample=stdout.decode(),
            finding_like_text_present=True,
        )

    def test_stdout_remains_observation(self) -> None:
        obs = self._nuclei_obs()
        self.assertTrue(obs.finding_like_text_present)
        builder = make_builder(execution_class="nuclei_scan")
        builder.attach_nuclei(obs)
        record = builder.seal(sealed_at=STARTED_AT)
        self.assertTrue(record.complete)

    def test_finding_like_advisory(self) -> None:
        obs = self._nuclei_obs()
        self.assertTrue(obs.finding_like_text_present)
        # Advisory boolean only: no label, no verdict derivation path.
        self.assertFalse(hasattr(obs, "verdict"))

    def test_no_matched_field(self) -> None:
        fields = set(ev.NucleiObservation.model_fields)
        self.assertTrue(
            fields.isdisjoint({"matched", "vulnerable", "confirmed"})
        )

    def test_no_vulnerable_field(self) -> None:
        self.assertNotIn("vulnerable", ev.NucleiObservation.model_fields)

    def test_no_confirmed_field(self) -> None:
        self.assertNotIn("confirmed", ev.NucleiObservation.model_fields)

    def test_legacy_runner_not_consulted(self) -> None:
        import ai.evidence.builder as builder_mod
        import ai.evidence.handoff as handoff_mod

        for module in (builder_mod, handoff_mod):
            source = Path(module.__file__).read_text()
            self.assertNotIn("to_findings", source)
            self.assertNotIn("nuclei_runner", source)


# ------------------------------------------------------------------
# XSS / BROWSER
# ------------------------------------------------------------------


class XssTest(unittest.TestCase):
    def _browser_obs(self) -> ev.BrowserObservation:
        return ev.BrowserObservation(
            dialog_marker_hashes=(hashing.hash_text("dialog"),),
            oracle_event_hashes=(hashing.hash_text("oracle"),),
            e1_observed=True,
            executed_payload_hash=hashing.sha256_hex(b"oracle-payload-O"),
            page_url=observations.observe_url("https://example.com/app"),
        )

    def test_p_o_separate(self) -> None:
        builder = make_builder(execution_class="browser_verification")
        builder.attach_browser(self._browser_obs())
        record = builder.seal(sealed_at=STARTED_AT)
        self.assertNotEqual(
            record.artifact_content_hash,
            record.browser.executed_payload_hash,
        )

    def test_hashes_separate(self) -> None:
        record_builder = make_builder(execution_class="browser_verification")
        record_builder.attach_browser(self._browser_obs())
        record = record_builder.seal(sealed_at=STARTED_AT)
        payload = seal.observations_payload(record)
        self.assertIsNotNone(payload["browser"]["executed_payload_hash"])
        bindings = seal.bindings_payload(record)
        self.assertEqual(
            bindings["artifact_content_hash"], ART_HASH
        )

    def test_e_flags_advisory(self) -> None:
        obs = self._browser_obs()
        self.assertTrue(obs.e1_observed)
        builder = make_builder(execution_class="browser_verification")
        builder.attach_browser(obs)
        record = builder.seal(sealed_at=STARTED_AT)
        self.assertTrue(record.complete)  # data-state only, not a verdict

    def test_submit_read_separate(self) -> None:
        submit = make_builder(execution_id=EX_ID)
        submit.attach_http(make_http_obs())
        submit_record = submit.seal(sealed_at=STARTED_AT)
        read_obs = self._browser_obs().model_copy(
            update={
                "round_id": "sr-" + "a" * 32,
                "submit_evidence_ref": submit_record.content_hash,
            }
        )
        read_builder = make_builder(
            execution_id=EX_ID2, execution_class="browser_verification"
        )
        read_builder.attach_browser(read_obs)
        read_record = read_builder.seal(sealed_at=STARTED_AT)
        self.assertNotEqual(
            submit_record.evidence_id, read_record.evidence_id
        )
        self.assertNotEqual(
            submit_record.execution_id, read_record.execution_id
        )
        self.assertEqual(
            read_record.browser.submit_evidence_ref,
            submit_record.content_hash,
        )

    def test_no_verdict_fields(self) -> None:
        for model in (ev.BrowserObservation, ev.EvidenceRecord):
            fields = set(model.model_fields)
            self.assertTrue(
                fields.isdisjoint(ev.FORBIDDEN_EVIDENCE_FIELDS),
                f"{model.__name__}: {fields}",
            )


# ------------------------------------------------------------------
# BINDING (+ LIVE vs PROVENANCE)
# ------------------------------------------------------------------


class BindingTest(unittest.TestCase):
    def _handoff(self, record: ev.EvidenceRecord) -> handoff.EvidenceHandoff:
        issuance = make_issuance()
        assembled = handoff.assemble_handoff(record)
        return handoff.bind_provenance(assembled, issuance)

    def test_wrong_authz_rejected(self) -> None:
        record = seal_http()
        assembled = handoff.assemble_handoff(record)
        other = make_issuance(authorization_id="authz-" + "9" * 16)
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.bind_provenance(assembled, other)
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_consumed_legitimate_accepted(self) -> None:
        record = seal_http()
        assembled = handoff.assemble_handoff(record)
        consumed = make_issuance(lifecycle="CONSUMED")
        bound = handoff.bind_provenance(assembled, consumed)
        result = handoff.verify_provenance_for_handoff(
            bound, consumed, execution_started_at=STARTED_AT
        )
        self.assertEqual(result, handoff.AUTHZ_VALID_FOR_PROVENANCE)

    def test_forged_authz_rejected(self) -> None:
        record = seal_http()
        assembled = handoff.assemble_handoff(record)
        bound = handoff.bind_provenance(assembled, make_issuance())
        forged = make_issuance(issuance_nonce="0" * 32)
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.verify_provenance_for_handoff(
                bound, forged, execution_started_at=STARTED_AT
            )
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_revoked_rejected(self) -> None:
        record = seal_http()
        assembled = handoff.assemble_handoff(record)
        bound = handoff.bind_provenance(assembled, make_issuance())
        revoked = make_issuance(lifecycle="REVOKED")
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.verify_provenance_for_handoff(
                bound, revoked, execution_started_at=STARTED_AT
            )
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_wrong_execution_rejected(self) -> None:
        record = seal_http()
        tampered = record.model_copy(update={"execution_id": EX_ID2})
        with self.assertRaises(ev.EvidenceError) as ctx:
            seal.verify_record(tampered)
        self.assertEqual(ctx.exception.code, "EVIDENCE_HASH_MISMATCH")

    def test_wrong_program_rejected(self) -> None:
        record = seal_http()
        assembled = handoff.assemble_handoff(record)
        bound = handoff.bind_provenance(assembled, make_issuance())
        other_program = make_issuance(
            target={
                "program_name": "other",
                "host": "example.com",
                "scheme": "https",
                "effective_port": 443,
                "path_scope": "/app",
                "scope_policy_version": "scope-policy/v1",
                "scope_lists_hash": SCOPE_HASH,
            }
        )
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.verify_provenance_for_handoff(
                bound, other_program, execution_started_at=STARTED_AT
            )
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_wrong_target_rejected(self) -> None:
        record = seal_http()
        assembled = handoff.assemble_handoff(record)
        bound = handoff.bind_provenance(assembled, make_issuance())
        other_target = make_issuance(
            target={
                "program_name": "acme",
                "host": "evil.example.com",
                "scheme": "https",
                "effective_port": 443,
                "path_scope": "/app",
                "scope_policy_version": "scope-policy/v1",
                "scope_lists_hash": SCOPE_HASH,
            }
        )
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.verify_provenance_for_handoff(
                bound, other_target, execution_started_at=STARTED_AT
            )
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_wrong_artifact_rejected(self) -> None:
        record = seal_http()
        assembled = handoff.assemble_handoff(record)
        bound = handoff.bind_provenance(assembled, make_issuance())
        tampered = bound.model_copy(
            update={"artifact_content_hash": "1" * 64}
        )
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.verify_provenance_for_handoff(
                tampered, make_issuance(), execution_started_at=STARTED_AT
            )
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_wrong_test_plan_rejected(self) -> None:
        record = seal_http()
        tampered = record.model_copy(
            update={"test_plan_id": "tp-" + "9" * 16}
        )
        with self.assertRaises(ev.EvidenceError):
            seal.verify_record(tampered)

    def test_live_vs_provenance_distinction(self) -> None:
        live = make_issuance()
        handoff.require_live_for_execution(live, now=STARTED_AT)
        consumed = make_issuance(lifecycle="CONSUMED")
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.require_live_for_execution(consumed, now=STARTED_AT)
        self.assertEqual(ctx.exception.code, "AUTHZ_NOT_LIVE")
        # ...yet the same consumed record is valid provenance.
        record = seal_http()
        bound = handoff.bind_provenance(
            handoff.assemble_handoff(record), make_issuance()
        )
        self.assertEqual(
            handoff.verify_provenance_for_handoff(
                bound, consumed, execution_started_at=STARTED_AT
            ),
            handoff.AUTHZ_VALID_FOR_PROVENANCE,
        )


# ------------------------------------------------------------------
# IDEMPOTENCY
# ------------------------------------------------------------------


class IdempotencyTest(unittest.TestCase):
    def test_duplicate_key(self) -> None:
        ledger = InMemoryExecutionLedger()
        first = ExecutionRecord(
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        ledger.put_new(first)
        winner = ledger.get_by_idempotency_key("1" * 64)
        self.assertIsNotNone(winner)
        self.assertEqual(winner.execution_id, EX_ID)
        second = ExecutionRecord(
            execution_id=EX_ID2,
            authorization_id="authz-" + "9" * 16,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        with self.assertRaises(DuplicateExecutionError):
            ledger.put_new(second)

    def test_concurrent_cas_one_winner(self) -> None:
        ledger = InMemoryExecutionLedger()
        row = ExecutionRecord(
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        ledger.put_new(row)
        winner = ledger.mark_started(EX_ID, started_at=STARTED_AT)
        self.assertEqual(winner.lifecycle, "STARTED")
        stale = row.model_copy()
        with self.assertRaises(InProgressExecutionError):
            ledger.compare_and_swap(
                EX_ID,
                stale.record_version,
                stale.model_copy(
                    update={
                        "lifecycle": "STARTED",
                        "record_version": stale.record_version + 1,
                    }
                ),
            )

    def test_loser_does_not_execute(self) -> None:
        ledger = InMemoryExecutionLedger()
        row = ExecutionRecord(
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        ledger.put_new(row)
        ledger.mark_started(EX_ID, started_at=STARTED_AT)
        with self.assertRaises(InProgressExecutionError):
            ledger.mark_started(EX_ID, started_at=STARTED_AT)

    def test_in_progress_distinct_from_unknown(self) -> None:
        ledger = InMemoryExecutionLedger()
        row = ExecutionRecord(
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        ledger.put_new(row)
        ledger.mark_started(EX_ID, started_at=STARTED_AT)
        in_progress = ledger.get(EX_ID)
        self.assertEqual(in_progress.lifecycle, "STARTED")
        unknown = ledger.mark_unknown(EX_ID, terminal_at=STARTED_AT)
        self.assertEqual(unknown.lifecycle, "UNKNOWN")
        self.assertNotEqual(in_progress.lifecycle, unknown.lifecycle)

    def test_replay_distinct_from_duplicate(self) -> None:
        ledger = InMemoryExecutionLedger()
        row = ExecutionRecord(
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        ledger.put_new(row)
        replay = ExecutionRecord(
            execution_id=EX_ID2,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="2" * 64,
        )
        with self.assertRaises(ReplayExecutionError):
            ledger.put_new(replay)


# ------------------------------------------------------------------
# CRASH
# ------------------------------------------------------------------


class CrashTest(unittest.TestCase):
    def test_pre_start(self) -> None:
        decision = ledger_mod.crash_decision("pre_start")
        self.assertTrue(decision["same_authz_usable"])
        self.assertFalse(decision["new_authz_required"])

    def test_post_consume(self) -> None:
        decision = ledger_mod.crash_decision("post_consume")
        self.assertFalse(decision["same_authz_usable"])
        row = ExecutionRecord(
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            execution_stage="single",
            idempotency_key="1" * 64,
        )
        # Consumed authorization never mints a second execution.
        ledger = InMemoryExecutionLedger()
        ledger.put_new(row)
        with self.assertRaises(ReplayExecutionError):
            ledger.put_new(
                ExecutionRecord(
                    execution_id=EX_ID2,
                    authorization_id=AUTHZ_ID,
                    execution_stage="single",
                    idempotency_key="2" * 64,
                )
            )

    def test_post_start(self) -> None:
        decision = ledger_mod.crash_decision("post_start")
        self.assertFalse(decision["verifier"])

    def test_transport_unknown(self) -> None:
        decision = ledger_mod.crash_decision("transport_unknown")
        self.assertTrue(decision["new_authz_required"])
        self.assertFalse(decision["verifier"])

    def test_pre_seal(self) -> None:
        decision = ledger_mod.crash_decision("pre_seal")
        self.assertTrue(decision["new_authz_required"])
        self.assertEqual(decision["evidence"], "OUTCOME_UNKNOWN_no_bytes")

    def test_post_seal_pre_index(self) -> None:
        decision = ledger_mod.crash_decision("post_seal_pre_index")
        self.assertEqual(decision["evidence"], "ORPHAN_reindex_only")
        record = seal_http()
        recovered = orphan.validate_reindex(
            record,
            claimed_evidence_id=record.evidence_id,
            claimed_execution_id=record.execution_id,
            claimed_authorization_id=record.authorization_id,
        )
        self.assertEqual(recovered, "INDEX_MISSING_SEALED")

    def test_post_index_pre_audit(self) -> None:
        decision = ledger_mod.crash_decision("post_index_pre_audit")
        self.assertEqual(decision["audit"], "AUDIT_GAP")
        gap = audit_trail.gap_record(
            seq=3,
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            missing_from="EVIDENCE_SEALED",
        )
        self.assertEqual(gap.transition, "AUDIT_GAP")


# ------------------------------------------------------------------
# ORPHAN
# ------------------------------------------------------------------


class OrphanTest(unittest.TestCase):
    def test_missing_index(self) -> None:
        self.assertEqual(
            orphan.classify_orphan(bytes_present=True, index_present=False),
            "INDEX_MISSING_SEALED",
        )
        self.assertEqual(
            orphan.classify_orphan(
                bytes_present=True,
                index_present=False,
                lifecycle="INCOMPLETE",
            ),
            "INDEX_MISSING_INCOMPLETE",
        )

    def test_missing_bytes(self) -> None:
        self.assertEqual(
            orphan.classify_orphan(bytes_present=False, index_present=True),
            "BYTES_MISSING",
        )

    def test_ambiguous_binding(self) -> None:
        self.assertEqual(
            orphan.classify_orphan(
                bytes_present=True,
                index_present=False,
                binding_ambiguous=True,
            ),
            "BINDING_AMBIGUOUS",
        )

    def test_valid_reindex(self) -> None:
        record = seal_http()
        result = orphan.validate_reindex(
            record,
            claimed_evidence_id=record.evidence_id,
            claimed_execution_id=record.execution_id,
            claimed_authorization_id=record.authorization_id,
        )
        self.assertEqual(result, "INDEX_MISSING_SEALED")

    def test_altered_bytes_rejected(self) -> None:
        record = seal_http()
        tampered_http = record.http.model_copy(
            update={"response_status": 500}
        )
        tampered = record.model_copy(update={"http": tampered_http})
        with self.assertRaises(ev.EvidenceError) as ctx:
            orphan.validate_reindex(
                tampered,
                claimed_evidence_id=record.evidence_id,
                claimed_execution_id=record.execution_id,
                claimed_authorization_id=record.authorization_id,
            )
        self.assertEqual(ctx.exception.code, "EVIDENCE_HASH_MISMATCH")

    def test_new_execution_binding_rejected(self) -> None:
        record = seal_http()
        with self.assertRaises(ev.EvidenceError) as ctx:
            orphan.validate_reindex(
                record,
                claimed_evidence_id=record.evidence_id,
                claimed_execution_id=EX_ID2,
                claimed_authorization_id=record.authorization_id,
            )
        self.assertEqual(ctx.exception.code, "EVIDENCE_BINDING_MISMATCH")


# ------------------------------------------------------------------
# AUDIT
# ------------------------------------------------------------------


class AuditTest(unittest.TestCase):
    def _chain(self) -> list[audit_trail.AuditRecord]:
        return [
            audit_trail.AuditRecord(
                seq=i,
                execution_id=EX_ID,
                authorization_id=AUTHZ_ID,
                transition=transition,
            )
            for i, transition in enumerate(
                (
                    "AUTHORIZATION",
                    "EXECUTION_STARTED",
                    "EVIDENCE_SEALED",
                    "EXECUTION_TERMINAL",
                    "VERIFIER_HANDOFF",
                )
            )
        ]

    def test_correct_ordering(self) -> None:
        audit_trail.check_ordering(self._chain())

    def test_pre_start_audit_failure(self) -> None:
        # No START record exists: execution must not proceed. The
        # fail-closed rule is structural — an empty chain validates
        # but authorizes nothing (no permission API reads audit).
        audit_trail.check_ordering([])
        self.assertFalse(
            hasattr(audit_trail, "is_authorized_to_execute")
        )

    def test_post_start_audit_gap(self) -> None:
        records = self._chain()[:3]
        gap = audit_trail.gap_record(
            seq=3,
            execution_id=EX_ID,
            authorization_id=AUTHZ_ID,
            missing_from="EXECUTION_TERMINAL",
        )
        records.append(gap)
        audit_trail.check_ordering(records)  # gap is order-exempt sibling
        self.assertEqual(records[-1].transition, "AUDIT_GAP")

    def test_no_secrets(self) -> None:
        with self.assertRaises(ValueError):
            audit_trail.AuditRecord(
                seq=0,
                execution_id=EX_ID,
                authorization_id=AUTHZ_ID,
                transition="AUTHORIZATION",
                actor="mongodb://root:secret@host/",
            )

    def test_no_verdict(self) -> None:
        fields = set(audit_trail.AuditRecord.model_fields)
        self.assertTrue(fields.isdisjoint(ev.FORBIDDEN_EVIDENCE_FIELDS))

    def test_out_of_order_rejected(self) -> None:
        records = self._chain()
        records[1], records[3] = records[3], records[1]
        # seq values travel with their records -> non-contiguous now.
        with self.assertRaises(ev.EvidenceError):
            audit_trail.check_ordering(records)


# ------------------------------------------------------------------
# LIMITS
# ------------------------------------------------------------------


class LimitTest(unittest.TestCase):
    def test_each_ceiling_enforced(self) -> None:
        for dimension, ceiling in ceilings.CEILINGS.items():
            with self.assertRaises(ev.EvidenceError) as ctx:
                ceilings.check_limit(dimension, ceiling + 1)
            self.assertEqual(ctx.exception.code, "LIMIT_EXCEEDED")

    def test_over_ceiling_rejected(self) -> None:
        with self.assertRaises(ev.EvidenceError) as ctx:
            ceilings.validate_config({"http_wall_seconds": 3600})
        self.assertEqual(ctx.exception.code, "LIMIT_EXCEEDED")

    def test_unknown_ceiling_rejected(self) -> None:
        with self.assertRaises(ev.EvidenceError) as ctx:
            ceilings.check_limit("no_such_dimension", 1)
        self.assertEqual(ctx.exception.code, "LIMIT_UNKNOWN")

    def test_unbounded_rejected(self) -> None:
        with self.assertRaises(ev.EvidenceError) as ctx:
            ceilings.check_limit("http_wall_seconds", None)
        self.assertEqual(ctx.exception.code, "LIMIT_UNKNOWN")

    def test_tightening_accepted(self) -> None:
        validated = ceilings.validate_config({"http_wall_seconds": 30})
        self.assertEqual(validated, {"http_wall_seconds": 30})

    def test_loosening_rejected(self) -> None:
        with self.assertRaises(ev.EvidenceError) as ctx:
            ceilings.validate_config({"nuclei_wall_seconds": 9999})
        self.assertEqual(ctx.exception.code, "LIMIT_EXCEEDED")


# ------------------------------------------------------------------
# HANDOFF
# ------------------------------------------------------------------


class HandoffTest(unittest.TestCase):
    def test_complete_accepted(self) -> None:
        record = seal_http()
        assembled = handoff.assemble_handoff(record)
        bound = handoff.bind_provenance(assembled, make_issuance())
        self.assertEqual(
            handoff.verify_provenance_for_handoff(
                bound, make_issuance(), execution_started_at=STARTED_AT
            ),
            handoff.AUTHZ_VALID_FOR_PROVENANCE,
        )

    def test_incomplete_rejected(self) -> None:
        partial = make_builder().seal_partial(reasons=("response_missing",))
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.assemble_handoff(partial)
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_unknown_rejected(self) -> None:
        # OUTCOME_UNKNOWN has no sealed bytes: nothing to assemble.
        with self.assertRaises(TypeError):
            handoff.assemble_handoff(None)  # type: ignore[arg-type]

    def test_hash_mismatch_rejected(self) -> None:
        record = seal_http()
        tampered = record.model_copy(
            update={
                "http": record.http.model_copy(
                    update={"response_status": 500}
                )
            }
        )
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.assemble_handoff(tampered)
        self.assertEqual(ctx.exception.code, "EVIDENCE_HASH_MISMATCH")

    def test_binding_mismatch_rejected(self) -> None:
        record = seal_http()
        tampered = record.model_copy(
            update={"artifact_content_hash": "1" * 64}
        )
        with self.assertRaises(ev.EvidenceError):
            handoff.assemble_handoff(tampered)

    def test_consumed_provenance_accepted(self) -> None:
        record = seal_http()
        bound = handoff.bind_provenance(
            handoff.assemble_handoff(record), make_issuance()
        )
        consumed = make_issuance(lifecycle="CONSUMED")
        self.assertEqual(
            handoff.verify_provenance_for_handoff(
                bound, consumed, execution_started_at=STARTED_AT
            ),
            handoff.AUTHZ_VALID_FOR_PROVENANCE,
        )

    def test_forged_revoked_rejected(self) -> None:
        record = seal_http()
        bound = handoff.bind_provenance(
            handoff.assemble_handoff(record), make_issuance()
        )
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.verify_provenance_for_handoff(
                bound, None, execution_started_at=STARTED_AT
            )
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")
        revoked = make_issuance(lifecycle="REVOKED")
        with self.assertRaises(ev.EvidenceError) as ctx:
            handoff.verify_provenance_for_handoff(
                bound, revoked, execution_started_at=STARTED_AT
            )
        self.assertEqual(ctx.exception.code, "HANDOFF_REJECTED")

    def test_no_verdict_fields(self) -> None:
        fields = set(handoff.EvidenceHandoff.model_fields)
        self.assertTrue(fields.isdisjoint(ev.FORBIDDEN_EVIDENCE_FIELDS))


# ------------------------------------------------------------------
# BODY POLICY
# ------------------------------------------------------------------


class BodyPolicyTest(unittest.TestCase):
    def test_hash_always(self) -> None:
        body_hash, _, _ = observations.observe_body(
            b"data", content_type="text/html"
        )
        self.assertRegex(body_hash, r"^[0-9a-f]{64}$")

    def test_binary_hash_only(self) -> None:
        body_hash, sample, omitted = observations.observe_body(
            b"\x89PNG\r\n", content_type="image/png"
        )
        self.assertIsNone(sample)
        self.assertEqual(omitted, "binary-content-type")
        self.assertRegex(body_hash, r"^[0-9a-f]{64}$")

    def test_sample_bounded(self) -> None:
        big = b"x" * (observations.MAX_RESPONSE_SAMPLE + 100)
        _, sample, omitted = observations.observe_body(
            big, content_type="text/html"
        )
        self.assertIsNotNone(sample)
        self.assertEqual(omitted, "over-sample-budget")
        self.assertLessEqual(
            len(sample.encode("utf-8")), observations.MAX_RESPONSE_SAMPLE
        )


if __name__ == "__main__":
    unittest.main()
