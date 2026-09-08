"""Offline tests for the controlled live-validation lane (Phase 5K-live).

Deterministic stdlib ``unittest``. No live execution: the FakeNucleiRunner
path proves the lane reaches the existing 5F executor without ever
touching network, DNS, subprocess, browser, LLM, or Mongo. The lane's
live gate is exercised via env patching; a ``LiveNucleiRunner`` injection
proves the lane never reduces the executor's own block.
"""

from __future__ import annotations

import os
import re
import unittest
from unittest import mock

from ai.execution.nuclei_executor import (
    FakeNucleiRunner,
    LiveNucleiRunner,
)
from ai.resolver.dns import FakeDnsResolver
from ai.live_validation import ControlledLiveValidationLane
from ai.live_validation.config import (
    LiveValidationDisabled,
    live_validation_enabled,
    require_live_validation_enabled,
)
from ai.live_validation.gates import (
    HARD_SCOPE_CVE_ID,
    PINNED_TEMPLATE_DIGEST,
    PINNED_TEMPLATE_BYTES,
    resolve_pinned_candidate,
    validate_template_safety,
)
from ai.live_validation.lane import _deterministic_tp_id
from ai.live_validation.schemas import LiveValidationResult
from ai.live_validation.seam import OfflineVerifiedSeam

TARGET = "https://example.com"
HOST = "example.com"
PINNED_DIGEST = "f5ba287d518652b8b222a8c030931360c2f9398de8204a60de2c4c4c1f0b1b8d"

EX_ID_RE = re.compile(r"^ex-[0-9a-f]{32}$")
AUTHZ_ID_RE = re.compile(r"^authz-[0-9a-f]{16}$")
TP_ID_RE = re.compile(r"^tp-[0-9a-f]{16}$")

FINDING_LIKE_OUTPUT = (
    "[INF] [CVE-2026-1557] matched vulnerable endpoint status 200/403 "
    "body carries DB_NAME DB_PASSWORD"
)


def _env_live(*, enabled: bool = True):
    return mock.patch.dict(
        os.environ,
        {"WATCH_AI_LIVE_VALIDATION": "true" if enabled else "false"},
        clear=False,
    )


def _live_resolver(*, addresses: list[str] | None = None):
    """Reviewed-resolver injection for live-mode offline tests.

    B6-C: live execution resolves exactly once through a reviewed
    ``DnsResolver`` (never the test-only mapping). The default answer
    is the globally-routable pinned address.
    """
    return FakeDnsResolver(mapping={HOST: list(addresses or ["8.8.8.8"])})


# ---------------------------------------------------------------------------
# Gates / pinned constants
# ---------------------------------------------------------------------------


class PinnedTemplateTests(unittest.TestCase):
    def test_pinned_digest_is_frozen(self) -> None:
        self.assertEqual(PINNED_TEMPLATE_DIGEST, PINNED_DIGEST)

    def test_pinned_bytes_len(self) -> None:
        self.assertEqual(len(PINNED_TEMPLATE_BYTES), 354)

    def test_hard_scope_cve(self) -> None:
        self.assertEqual(HARD_SCOPE_CVE_ID, "CVE-2026-1557")

    def test_candidate_resolution_and_safety(self) -> None:
        candidate = resolve_pinned_candidate("CVE-2026-1557")
        self.assertEqual(candidate.cve_id, "CVE-2026-1557")
        passed, reasons = validate_template_safety(candidate)
        self.assertTrue(passed, reasons)

    def test_unsupported_cve_rejected(self) -> None:
        with self.assertRaises(ValueError):
            resolve_pinned_candidate("CVE-2026-9999")

    def test_candidate_self_describing(self) -> None:
        candidate = resolve_pinned_candidate(HARD_SCOPE_CVE_ID)
        # The pinned template targets the CVE endpoint + param.
        self.assertEqual(
            candidate.template.path,
            "/wp-content/plugins/wp-responsive-images/image_handler.php",
        )
        self.assertEqual(candidate.template.query_params, {"src": "/wp-config.php"})
        kinds = {f.fixture_kind for f in candidate.fixtures}
        self.assertEqual(kinds, {"benign", "vulnerable"})


# ---------------------------------------------------------------------------
# Config gate
# ---------------------------------------------------------------------------


class ConfigGateTests(unittest.TestCase):
    def test_disabled_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(live_validation_enabled())

    def test_truthy_variants(self) -> None:
        for value in ("1", "true", "TRUE", "yes", "on", "Yes"):
            with mock.patch.dict(os.environ, {"WATCH_AI_LIVE_VALIDATION": value}, clear=True):
                self.assertTrue(live_validation_enabled())

    def test_falsy_variants(self) -> None:
        for value in ("0", "false", "no", "off", "", "banana"):
            with mock.patch.dict(os.environ, {"WATCH_AI_LIVE_VALIDATION": value}, clear=True):
                self.assertFalse(live_validation_enabled())

    def test_require_raises_when_disabled(self) -> None:
        with mock.patch.dict(os.environ, {"WATCH_AI_LIVE_VALIDATION": "false"}, clear=True):
            with self.assertRaises(LiveValidationDisabled):
                require_live_validation_enabled()

    def test_require_passes_when_enabled(self) -> None:
        with mock.patch.dict(os.environ, {"WATCH_AI_LIVE_VALIDATION": "true"}, clear=True):
            require_live_validation_enabled()  # must not raise


# ---------------------------------------------------------------------------
# Output boundary schemas
# ---------------------------------------------------------------------------


class ResultSchemaTests(unittest.TestCase):
    def test_boundary_forbids_verdict_fields(self) -> None:
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            LiveValidationResult(
                cve_id="CVE-2026-1557",
                target=TARGET,
                mode="dry_run",
                status="BLOCKED",
                research_only=True,
                verdict="vulnerable",  # forbidden shape
            )

    def test_authoritative_is_always_false(self) -> None:
        lane = ControlledLiveValidationLane()
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertIs(result.authoritative, False)
        self.assertIs(result.live_validation, True)

    def test_cve_id_must_be_cve_shaped(self) -> None:
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            LiveValidationResult(
                cve_id="NOT-A-CVE",
                target=None,
                mode="dry_run",
                status="BLOCKED",
                research_only=True,
            )


# ---------------------------------------------------------------------------
# Lane: dry-run gate chain (zero network)
# ---------------------------------------------------------------------------


class DryRunGateChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lane = ControlledLiveValidationLane()

    def test_dry_run_all_gates_pass_and_execution_not_performed(self) -> None:
        result = self.lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "DRY_RUN_NOT_PERFORMED")
        self.assertTrue(result.research_only)
        decisions = {g.gate: g.decision for g in result.gates}
        self.assertEqual(
            decisions,
            {
                "config": "PASS",
                "target": "PASS",
                "candidate": "PASS",
                "template": "PASS",
                "authorization": "PASS",
                "scope": "PASS",
                "egress": "PASS",
                "execution": "NOT_PERFORMED",
                "verification": "NOT_PERFORMED",
            },
        )
        self.assertIsNone(result.execution)
        self.assertIsNone(result.verification)

    def test_dry_run_default_mode(self) -> None:
        result = self.lane.run("CVE-2026-1557", TARGET)
        self.assertEqual(result.mode, "dry_run")
        self.assertEqual(result.status, "BLOCKED")

    def test_runner_never_touched_in_dry_run(self) -> None:
        invoked = []

        def spy_factory():
            invoked.append(True)
            return FakeNucleiRunner()

        lane = ControlledLiveValidationLane(runner_factory=spy_factory)
        lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(invoked, [])


# ---------------------------------------------------------------------------
# Lane: gate-level blocks
# ---------------------------------------------------------------------------


class GateBlockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lane = ControlledLiveValidationLane()

    def test_missing_target_blocks(self) -> None:
        result = self.lane.run("CVE-2026-1557", None, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "TARGET_REQUIRED")

    def test_empty_target_blocks(self) -> None:
        result = self.lane.run("CVE-2026-1557", "   ", mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "TARGET_REQUIRED")

    def test_non_string_target_blocks(self) -> None:
        result = self.lane.run("CVE-2026-1557", 12345, mode="dry_run")  # type: ignore[arg-type]
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "TARGET_REQUIRED")

    def test_invalid_target_blocks(self) -> None:
        result = self.lane.run("CVE-2026-1557", "not a host://", mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("TARGET_INVALID"))

    def test_wrong_cve_blocks(self) -> None:
        result = self.lane.run("CVE-2026-9999", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("CVE_MISMATCH"))

    def test_scope_denied_when_policy_omits_program(self) -> None:
        from ai.scope.policy import InMemoryPolicyStore

        lane = ControlledLiveValidationLane(
            policy_store=InMemoryPolicyStore({})
        )
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))

    def test_scope_denied_on_unsafe_address(self) -> None:
        lane = ControlledLiveValidationLane(
            dns_mapping={HOST: ["127.0.0.1"]}
        )
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))


# ---------------------------------------------------------------------------
# Lane: live mode
# ---------------------------------------------------------------------------


class LiveModeTests(unittest.TestCase):
    def test_live_without_env_gate_blocks(self) -> None:
        with _env_live(enabled=False):
            lane = ControlledLiveValidationLane()
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "LIVE_VALIDATION_DISABLED")
        self.assertFalse(result.research_only)

    def test_live_no_match(self) -> None:
        with _env_live():
            lane = ControlledLiveValidationLane(resolver=_live_resolver())
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertEqual(result.status, "NO_MATCH")
        self.assertIsNone(result.blocked_reason)
        self.assertIsNotNone(result.execution)
        self.assertFalse(result.execution.finding_like_text_present)
        self.assertEqual(result.verification.reason_code, "nuclei_no_advisory_signal")

    def test_live_advisory_match_verified(self) -> None:
        with _env_live():
            lane = ControlledLiveValidationLane(
                resolver=_live_resolver(),
                runner_factory=lambda: FakeNucleiRunner(
                    stdout=FINDING_LIKE_OUTPUT, exit_code=0
                )
            )
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertEqual(result.status, "VERIFIED")
        self.assertIsNotNone(result.execution)
        self.assertTrue(result.execution.finding_like_text_present)
        self.assertEqual(
            result.verification.outcome_detail, "nuclei_advisory_weak"
        )
        # POTENTIAL ceiling: never finding-eligible from advisory text.
        self.assertFalse(result.verification.finding_eligible)

    def test_live_result_has_deterministic_hash_when_verified(self) -> None:
        with _env_live():
            lane = ControlledLiveValidationLane(
                resolver=_live_resolver(),
                runner_factory=lambda: FakeNucleiRunner(
                    stdout=FINDING_LIKE_OUTPUT, exit_code=0
                )
            )
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", result.result_hash))

    def test_live_runner_injection_does_not_open_network(self) -> None:
        # The lane accepts only 5F runner types; anything else raises at
        # the executor boundary and blocks (never reduces safety).
        with _env_live():
            lane = ControlledLiveValidationLane(
                resolver=_live_resolver(),
                runner_factory=lambda: object()  # type: ignore[arg-type]
            )
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertEqual(result.status, "BLOCKED")
        self.assertIn("execution", {g.gate for g in result.gates})

    def test_live_nuclei_runner_keeps_executor_block(self) -> None:
        with _env_live():
            lane = ControlledLiveValidationLane(
                resolver=_live_resolver(), runner_factory=LiveNucleiRunner
            )
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertEqual(result.status, "BLOCKED")
        self.assertIn("NUCLEI_EXECUTION_BLOCKED", result.blocked_reason)


# ---------------------------------------------------------------------------
# Lane: verification rejection -> MATCH_UNVERIFIED
# ---------------------------------------------------------------------------


class _NullSeam:
    """A seam whose read_verified returns nothing (gate MUST fail)."""

    def read_verified(self, evidence_id: str):
        return None

    def read_authorization(self, authorization_id: str):
        return None


class VerificationRejectionTests(unittest.TestCase):
    def test_bad_seam_leads_to_match_unverified(self) -> None:
        class BadSeamLane(ControlledLiveValidationLane):
            def _build_seam(self, evidence, envelope):
                return _NullSeam()

        with _env_live():
            lane = BadSeamLane(resolver=_live_resolver())
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertEqual(result.status, "MATCH_UNVERIFIED")
        self.assertTrue(result.blocked_reason.startswith("VERIFIER_REJECTED"))
        # Evidence survives for review even when verification is blocked.
        self.assertIsNotNone(result.execution)

    def test_status_mapping_never_produces_verdict(self) -> None:
        # Exercising the pure final-status resolver over a fabricated
        # classification outcome (incl. the unresolved branch).
        from types import SimpleNamespace

        resolve = ControlledLiveValidationLane._resolve_final_status

        advisory = SimpleNamespace(
            result=SimpleNamespace(outcome_detail="nuclei_advisory_weak", reason_code="x")
        )
        self.assertEqual(resolve(advisory), ("VERIFIED", None))

        no_signal = SimpleNamespace(
            result=SimpleNamespace(
                outcome_detail="insufficient_evidence",
                reason_code="nuclei_no_advisory_signal",
            )
        )
        self.assertEqual(resolve(no_signal), ("NO_MATCH", None))

        ambiguous = SimpleNamespace(
            result=SimpleNamespace(
                outcome_detail="insufficient_evidence",
                reason_code="argv_digest_mismatch",
            )
        )
        status, reason = resolve(ambiguous)
        self.assertEqual(status, "MATCH_UNVERIFIED")
        self.assertEqual(reason, "argv_digest_mismatch")

        none_result = SimpleNamespace(result=None)
        status, _ = resolve(none_result)
        self.assertEqual(status, "MATCH_UNVERIFIED")


# ---------------------------------------------------------------------------
# Determinism / id formats / binding correctness
# ---------------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    def test_tp_id_is_deterministic_and_shaped(self) -> None:
        first = _deterministic_tp_id("CVE-2026-1557", TARGET)
        second = _deterministic_tp_id("CVE-2026-1557", TARGET)
        self.assertEqual(first, second)
        self.assertTrue(TP_ID_RE.match(first))

    def test_lane_ids_match_frozen_formats(self) -> None:
        with _env_live():
            lane = ControlledLiveValidationLane(resolver=_live_resolver())
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertTrue(EX_ID_RE.match(result.execution.execution_id))
        self.assertTrue(
            AUTHZ_ID_RE.match(result.execution.authorization_id)
        )
        self.assertTrue(re.fullmatch(r"ev-[0-9a-f]{32}", result.execution.evidence_id))

    def test_authz_scope_hash_equals_policy_scope_hash(self) -> None:
        # The lane's single-host policy and the issued authorization must
        # agree on the canonical scope-lists hash or the scope gate dies.
        from ai.resolver.inventory import scope_lists_hash_for

        class CaptureAuthzLane(ControlledLiveValidationLane):
            def __init__(self, *args, **kwargs):  # noqa: D107
                super().__init__(*args, **kwargs)
                self.issued_authz = None

            def _issue_and_verify_authz(self, *args, **kwargs):
                authz, reason = super()._issue_and_verify_authz(*args, **kwargs)
                self.issued_authz = authz
                return authz, reason

        lane = CaptureAuthzLane()
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertIsNotNone(lane.issued_authz)
        scope_gate = next(g for g in result.gates if g.gate == "scope")
        self.assertEqual(scope_gate.decision, "PASS")
        self.assertEqual(
            lane.issued_authz.target.scope_lists_hash,
            scope_lists_hash_for(("example.com",), ()),
        )


# ---------------------------------------------------------------------------
# OfflineVerifiedSeam
# ---------------------------------------------------------------------------


class OfflineSeamTests(unittest.TestCase):
    def test_seam_requires_complete_record(self) -> None:
        from ai.schemas import evidence as ev

        record = ev.EvidenceRecord(  # incomplete, empty
            evidence_id="ev-" + "a" * 32,
            execution_id="ex-" + "b" * 32,
            authorization_id="authz-" + "c" * 16,
            execution_stage="single",
            execution_class="nuclei_scan",
            artifact_id="art-" + "d" * 16,
            artifact_content_hash="0" * 64,
            target=ev.TargetIdentity(program_name="p", host="h"),
            program_name="p",
            test_plan_id="tp-" + "e" * 16,
        )
        with self.assertRaises(ValueError):
            OfflineVerifiedSeam(
                sealed_record=record,
                envelope=b"",
                authz_store=__import__(
                    "ai.authorizer.store", fromlist=["InMemoryAuthorizationStore"]
                ).InMemoryAuthorizationStore(),
            )

    def test_seam_read_verified_returns_record(self) -> None:
        from ai.authorizer.store import InMemoryAuthorizationStore
        from ai.schemas import evidence as ev

        record = ev.EvidenceRecord(
            evidence_id="ev-" + "a" * 32,
            execution_id="ex-" + "b" * 32,
            authorization_id="authz-" + "c" * 16,
            execution_stage="single",
            execution_class="nuclei_scan",
            artifact_id="art-" + "d" * 16,
            artifact_content_hash="0" * 64,
            target=ev.TargetIdentity(program_name="p", host="h"),
            program_name="p",
            test_plan_id="tp-" + "e" * 16,
            complete=True,
            lifecycle="SEALED",
            bindings_hash="1" * 64,
            observations_hash="2" * 64,
            content_hash="3" * 64,
        )
        store = InMemoryAuthorizationStore()
        seam = OfflineVerifiedSeam(
            sealed_record=record,
            envelope=b"{}",
            authz_store=store,
        )
        read = seam.read_verified(record.evidence_id)
        self.assertEqual(read.record, record)
        self.assertIsNone(read.index)
        self.assertIsNone(seam.read_verified("ev-" + "f" * 32))


# ---------------------------------------------------------------------------
# CLI integration (dry-run printer must stay zero-network)
# ---------------------------------------------------------------------------


class CliValidateLiveTests(unittest.TestCase):
    def test_cli_dry_run_prints_network_not_performed(self) -> None:
        from io import StringIO
        from unittest import mock as um

        from ai.research_cli import run_validate_live

        import argparse

        args = argparse.Namespace(
            cve="CVE-2026-1557",
            target=TARGET,
            live=False,
        )
        with um.patch("sys.stdout", new_callable=StringIO) as buf:
            code = run_validate_live(args)
        self.assertEqual(code, 0)
        out = buf.getvalue()
        self.assertIn("MODE: DRY_RUN", out)
        self.assertIn("NETWORK_EXECUTION: NOT_PERFORMED", out)
        self.assertIn("AUTHORIZATION: PASS", out)
        self.assertIn("SCOPE: PASS", out)

    def test_cli_live_flag_blocks_without_env(self) -> None:
        from io import StringIO
        from unittest import mock as um

        from ai.research_cli import run_validate_live

        import argparse

        args = argparse.Namespace(
            cve="CVE-2026-1557",
            target=TARGET,
            live=True,
        )
        with _env_live(enabled=False):
            with um.patch("sys.stdout", new_callable=StringIO) as buf:
                code = run_validate_live(args)
        self.assertEqual(code, 0)
        out = buf.getvalue()
        self.assertIn("MODE: LIVE", out)
        self.assertIn("STATUS: BLOCKED", out)
        self.assertIn("LIVE_VALIDATION_DISABLED", out)

    def test_cli_parser_has_validate_live_subcommand(self) -> None:
        from ai.research_cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["validate-live", "--cve", "CVE-2026-1557",
                                  "--target", TARGET])
        self.assertEqual(args.command, "validate-live")
        self.assertFalse(args.live)


# ---------------------------------------------------------------------------
# B4: H2 — shared target canonicalization
# ---------------------------------------------------------------------------


class B4CanonicalizationTests(unittest.TestCase):
    def _parse(self, target):
        from ai.live_validation.lane import _parse_raw_target
        return _parse_raw_target(target)

    def test_userinfo_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._parse("user:pass@example.com")
        with self.assertRaises(ValueError):
            self._parse("user@example.com")

    def test_trailing_dot_stripped(self) -> None:
        scheme, host, port = self._parse("https://example.com.")
        self.assertEqual(host, "example.com")

    def test_case_normalized(self) -> None:
        scheme, host, port = self._parse("https://EXAMPLE.COM")
        self.assertEqual(host, "example.com")

    def test_encoded_separators_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._parse("example.com%2eattacker.com")
        with self.assertRaises(ValueError):
            self._parse("example.com%40attacker.com")

    def test_decimal_ip_unfolded(self) -> None:
        scheme, host, port = self._parse("https://2130706433")
        self.assertEqual(host, "127.0.0.1")

    def test_hex_ip_unfolded(self) -> None:
        scheme, host, port = self._parse("http://0x7f.0.0.1")
        self.assertEqual(host, "127.0.0.1")

    def test_ipv4_mapped_ipv6_unfolded(self) -> None:
        scheme, host, port = self._parse("http://[::ffff:127.0.0.1]")
        self.assertEqual(host, "127.0.0.1")

    def test_unsupported_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._parse("ftp://example.com")

    def test_malformed_port_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._parse("https://example.com:99999")
        with self.assertRaises(ValueError):
            self._parse("https://example.com:0")

    def test_missing_host_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._parse("https://")


# ---------------------------------------------------------------------------
# B4: B2 — DNS pinning / anti-rebinding
# ---------------------------------------------------------------------------


class B4DnsPinningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lane = ControlledLiveValidationLane()

    def test_safe_resolution_passes(self) -> None:
        result = self.lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "DRY_RUN_NOT_PERFORMED")

    def test_private_answer_blocks(self) -> None:
        lane = ControlledLiveValidationLane(dns_mapping={HOST: ["10.0.0.1"]})
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))

    def test_loopback_answer_blocks(self) -> None:
        lane = ControlledLiveValidationLane(dns_mapping={HOST: ["127.0.0.1"]})
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))

    def test_link_local_answer_blocks(self) -> None:
        lane = ControlledLiveValidationLane(dns_mapping={HOST: ["169.254.1.1"]})
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))

    def test_metadata_answer_blocks(self) -> None:
        lane = ControlledLiveValidationLane(
            dns_mapping={HOST: ["169.254.169.254"]}
        )
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))

    def test_mixed_safe_unsafe_blocks(self) -> None:
        # 8.8.8.8 is globally routable, 127.0.0.1 is loopback.
        lane = ControlledLiveValidationLane(
            dns_mapping={HOST: ["8.8.8.8", "127.0.0.1"]}
        )
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))

    def test_ipv4_mapped_ipv6_loopback_blocks(self) -> None:
        # ::ffff:127.0.0.1 is IPv4-mapped IPv6 of loopback -> denied.
        lane = ControlledLiveValidationLane(
            dns_mapping={HOST: ["::ffff:127.0.0.1"]}
        )
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(result.blocked_reason.startswith("SCOPE_DENIED"))


# ---------------------------------------------------------------------------
# B4: B3 — egress boundary guard
# ---------------------------------------------------------------------------


class B4EgressBoundaryTests(unittest.TestCase):
    def test_egress_gate_passes_for_global_address(self) -> None:
        with _env_live():
            lane = ControlledLiveValidationLane(
                resolver=_live_resolver(addresses=["8.8.8.8"])
            )
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        # The egress gate allowed the global address (8.8.8.8), then the
        # offline FakeNucleiRunner produces no signal -> NO_MATCH.
        gates = {g.gate: g.decision for g in result.gates}
        self.assertEqual(gates.get("egress"), "PASS")
        self.assertEqual(result.status, "NO_MATCH")

    def test_egress_gate_blocks_unsafe_address(self) -> None:
        with _env_live():
            lane = ControlledLiveValidationLane(
                resolver=_live_resolver(addresses=["127.0.0.1"])
            )
            result = lane.run("CVE-2026-1557", TARGET, mode="live")
        self.assertEqual(result.status, "BLOCKED")
        gates = {g.gate: g.decision for g in result.gates}
        self.assertNotEqual(gates.get("egress"), "PASS")


# ---------------------------------------------------------------------------
# B4: B1 — Nuclei redirect / OOB containment (argv)
# ---------------------------------------------------------------------------


class B4NucleiContainmentTests(unittest.TestCase):
    def _argv(self):
        from ai.execution.nuclei_executor import build_nuclei_argv
        argv = build_nuclei_argv(
            template_path="/srv/watch/scratch/nuclei/ex-cccccccccccccccccccccccccccccccc/t.json",
            target_string="https://example.com",
        )
        return list(argv)

    def test_redirect_disabled_flag_present(self) -> None:
        argv = self._argv()
        self.assertIn("-disable-redirects", argv)
        # Redirect-enabling flags must never appear (budget is zero).
        for forbidden in (
            "-follow-redirects",
            "-follow-host-redirects",
            "-max-redirects",
            "-no-redirects",
        ):
            self.assertNotIn(forbidden, argv)

    def test_interactsh_oob_disabled_flag_present(self) -> None:
        argv = self._argv()
        self.assertIn("-no-interactsh", argv)
        self.assertNotIn("-disable-interactsh", argv)

    def test_update_check_disabled(self) -> None:
        argv = self._argv()
        self.assertIn("-disable-update-check", argv)

    def test_fixed_executable_and_no_shell(self) -> None:
        argv = self._argv()
        self.assertEqual(argv[0], "/usr/bin/nuclei")
        for flag in ("-t", "-u"):
            self.assertIn(flag, argv)
        # shell=False is enforced by absence of any shell-interpolable
        # marker; argv is purely structural.
        self.assertNotIn(";", argv)
        self.assertNotIn("&&", argv)
        self.assertNotIn("$(", argv)

    def test_retry_and_concurrency_bounded(self) -> None:
        argv = self._argv()
        # bulk-size already pins concurrency to 1 for this CVE.
        self.assertEqual(argv[argv.index("-bulk-size") + 1], "1")
        self.assertEqual(argv[argv.index("-timeout") + 1], "5")
        # B6-B/F: explicit retry/concurrency bounds (upstream retries
        # default is 1; concurrency default is 25).
        self.assertEqual(argv[argv.index("-retries") + 1], "0")
        self.assertEqual(argv[argv.index("-concurrency") + 1], "1")
        self.assertIn("-restrict-local-network-access", argv)
        self.assertIn("-jsonl", argv)
        self.assertNotIn("-json", argv)


# ---------------------------------------------------------------------------
# B4: H1 — evidence redaction (Nuclei observation output)
# ---------------------------------------------------------------------------


class B4EvidenceRedactionTests(unittest.TestCase):
    def _scrub(self, text):
        from ai.evidence import scrubber
        return scrubber.scrub_text(text)

    def test_cookie_redacted(self) -> None:
        self.assertNotIn("sessionid", self._scrub("Set-Cookie: sessionid=abc123"))

    def test_set_cookie_redacted(self) -> None:
        self.assertNotIn("abc123", self._scrub("Set-Cookie: sess=abc123"))

    def test_authorization_redacted(self) -> None:
        self.assertNotIn("Bearer", self._scrub("Authorization: Bearer abc.def.ghi"))

    def test_api_key_redacted(self) -> None:
        self.assertNotIn("12345", self._scrub("X-Api-Key: 12345secret"))

    def test_token_redacted(self) -> None:
        self.assertNotIn("abcdef", self._scrub("token=abcdef123456"))

    def test_session_redacted(self) -> None:
        self.assertNotIn("xyz", self._scrub("session: xyz98765"))

    def test_password_redacted(self) -> None:
        self.assertNotIn("secret123", self._scrub("DB_PASSWORD secret123"))

    def test_secure_cve_evidence_preserved(self) -> None:
        # The word-matcher evidence (bare tokens) must NOT be destroyed.
        out = self._scrub(
            "[INF] [CVE-2026-1557] matched vulnerable endpoint "
            "status 200/403 body carries DB_NAME DB_PASSWORD"
        )
        self.assertIn("[CVE-2026-1557]", out)
        self.assertIn("DB_NAME", out)
        self.assertIn("DB_PASSWORD", out)
        self.assertIn("200", out)
        self.assertIn("403", out)
        self.assertIn("vulnerable", out)


# ---------------------------------------------------------------------------
# B4: fail-closed guarantees (dry-run never performs network)
# ---------------------------------------------------------------------------


class B4FailClosedTests(unittest.TestCase):
    def test_dry_run_never_touches_network(self) -> None:
        lane = ControlledLiveValidationLane()
        result = lane.run("CVE-2026-1557", TARGET, mode="dry_run")
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.blocked_reason, "DRY_RUN_NOT_PERFORMED")


if __name__ == "__main__":
    unittest.main()