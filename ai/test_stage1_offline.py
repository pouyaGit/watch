"""Stage 1 offline authorized pipeline tests (fully dry-run, no live I/O).

Stdlib ``unittest`` only. No network, no DNS, no subprocess, no
MongoDB, no browser, no Nuclei, no LLM, no Git. Every dependency is an
in-memory fake; all assertions are deterministic.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from ai import stage1_offline_pipeline as stage1
from ai.evidence.builder import verify_record
from ai.evidence.store import parse_envelope, canonical_envelope_bytes
from ai.scope.evaluator import HopObservation
from ai.stage1_offline_pipeline import (
    EndpointView,
    Stage1Config,
    Stage1Error,
    run_stage1,
)


def _endpoint(
    *,
    program: str = "acme",
    subdomain: str = "example.com",
    path: str = "/search",
    url: str = "https://example.com/search?q=1",
    params: tuple[str, ...] = ("q",),
) -> EndpointView:
    return EndpointView(
        program_name=program,
        subdomain=subdomain,
        path=path,
        example_url=url,
        params=params,
    )


def _config(**overrides) -> Stage1Config:
    base = {
        "scopes": ("example.com",),
        "ooscopes": (),
    }
    base.update(overrides)
    return Stage1Config(**base)


class HappyPathTests(unittest.TestCase):
    def test_full_offline_chain(self) -> None:
        result = run_stage1(_endpoint(), _config())
        self.assertTrue(result.verification_outcome.accepted)
        self.assertIsNotNone(result.verification_outcome.result)
        outcome = result.verification_outcome.result.outcome
        # Synthetic http_probe evidence carries no oracle marker, so the
        # frozen 5I classifier must answer UNKNOWN (or at most
        # POTENTIAL); CONFIRMED here would mean we manufactured proof.
        self.assertIn(outcome, ("UNKNOWN", "POTENTIAL"))
        self.assertNotEqual(outcome, "CONFIRMED")
        self.assertNotEqual(outcome, "NOT_VULNERABLE")
        # Exec spec only: canonical target + path, no transport.
        self.assertIn("example.com", result.exec_spec.canonical_url)
        self.assertIn("/search", result.exec_spec.canonical_url)
        # Sealed evidence is complete and hash-valid.
        self.assertEqual(result.evidence_record.lifecycle, "SEALED")
        self.assertTrue(result.evidence_record.complete)
        verify_record(result.evidence_record)
        # 5J dry-run refuses non-CONFIRMED without error.
        self.assertIsNotNone(result.materialization_outcome)
        self.assertFalse(result.materialization_outcome.accepted)

    def test_evidence_envelope_round_trip(self) -> None:
        result = run_stage1(_endpoint(), _config())
        raw = canonical_envelope_bytes(result.evidence_record)
        reparsed = parse_envelope(raw)
        verify_record(reparsed)
        self.assertEqual(
            reparsed.content_hash, result.evidence_record.content_hash
        )
        self.assertEqual(
            reparsed.bindings_hash, result.evidence_record.bindings_hash
        )


class ScopeTests(unittest.TestCase):
    def test_denied_scope_stops_before_execution(self) -> None:
        endpoint = _endpoint(
            subdomain="other.example.net",
            url="https://other.example.net/search?q=1",
        )
        with self.assertRaises(Stage1Error) as ctx:
            run_stage1(endpoint, _config())
        self.assertEqual(ctx.exception.code, "SCOPE_DENIED")

    def test_inconclusive_scope_chain_stops(self) -> None:
        config = _config(
            redirect_hops=(HopObservation(location="/next", addresses=()),)
        )
        with self.assertRaises(Stage1Error) as ctx:
            run_stage1(_endpoint(), config)
        self.assertEqual(ctx.exception.code, "SCOPE_INCONCLUSIVE")

    def test_excluded_host_denied(self) -> None:
        endpoint = _endpoint(
            subdomain="excluded.example.com",
            url="https://excluded.example.com/search?q=1",
        )
        config = _config(ooscopes=("excluded.example.com",))
        with self.assertRaises(Stage1Error) as ctx:
            run_stage1(endpoint, config)
        self.assertEqual(ctx.exception.code, "SCOPE_DENIED")


class AuthorizationFailureTests(unittest.TestCase):
    def test_expired_authorization_request_fails_closed(self) -> None:
        config = _config(expires_at=stage1.STAGE1_ISSUED_AT)
        with self.assertRaises(Stage1Error) as ctx:
            run_stage1(_endpoint(), config)
        self.assertEqual(ctx.exception.code, "AUTHZ_FAILED")


class DeterminismTests(unittest.TestCase):
    def test_repeatable_content_hashes(self) -> None:
        # The 5B issuance nonce and evidence_id are random HANDLES by
        # architecture design (handles, not content identity), so two
        # independent runs can never be byte-identical. Repeatability
        # is therefore asserted with a shared store (idempotent
        # issuance returns the same authorization) on every
        # deterministic contract: plan/artifact identity, the sealed
        # evidence triple, and the classification outcome/reason.
        from ai.authorizer.store import InMemoryAuthorizationStore
        from ai.verification.deterministic.result import compute_result_hash

        store = InMemoryAuthorizationStore()
        first = run_stage1(_endpoint(), _config(), authz_store=store)
        second = run_stage1(_endpoint(), _config(), authz_store=store)
        self.assertEqual(
            first.authorization.authorization_id,
            second.authorization.authorization_id,
        )
        self.assertEqual(
            first.test_plan.test_plan_id, second.test_plan.test_plan_id
        )
        self.assertEqual(
            first.artifact_reference.artifact_id,
            second.artifact_reference.artifact_id,
        )
        for name in (
            "bindings_hash",
            "observations_hash",
            "content_hash",
        ):
            self.assertEqual(
                getattr(first.evidence_record, name),
                getattr(second.evidence_record, name),
            )
        self.assertEqual(
            first.verification_outcome.result.outcome,
            second.verification_outcome.result.outcome,
        )
        self.assertEqual(
            first.verification_outcome.result.reason_code,
            second.verification_outcome.result.reason_code,
        )
        # The evidence handle itself is random: handles must differ
        # while content stays identical.
        self.assertNotEqual(
            first.evidence_record.evidence_id,
            second.evidence_record.evidence_id,
        )
        _ = compute_result_hash  # hash helper stays importable offline


class LiveBlockedTests(unittest.TestCase):
    def test_live_gates_stay_closed(self) -> None:
        from ai.execution import http_executor as hx
        from ai.execution import nuclei_executor as nx

        self.assertIs(hx.LIVE_TRAFFIC_ENABLED, False)
        self.assertIs(nx.LIVE_NUCLEI, False)

    def test_live_runners_refuse(self) -> None:
        from ai.execution.http_executor import (
            RealSocketFactory,
        )
        from ai.execution.http_executor import (
            ExecutorError as HttpExecutorError,
        )
        from ai.execution.nuclei_executor import (
            LiveNucleiRunner,
        )
        from ai.execution.nuclei_executor import (
            ExecutorError as NucleiExecutorError,
        )

        with self.assertRaises(NucleiExecutorError):
            LiveNucleiRunner().launch(object())
        with self.assertRaises(HttpExecutorError):
            RealSocketFactory().connect("8.8.8.8", 443, 1.0)

    def test_no_live_or_legacy_execution(self) -> None:
        # Importing the deterministic 5I package also executes the
        # parent ``ai.verification`` package ``__init__`` (which names
        # the legacy modules for offline unit tests). That import-time
        # presence is not execution: assert the legacy entry points
        # stay fenced, and — order-independently — that a pipeline run
        # itself introduces no live/database modules (snapshot diff,
        # since other test modules may have loaded them at collection).
        import ai.verification.verifier as legacy_verifier

        before = set(sys.modules)
        run_stage1(_endpoint(), _config())
        introduced = set(sys.modules) - before
        self.assertTrue(legacy_verifier.LEGACY_NON_PRODUCTION)
        for module in ("database.db", "playwright"):
            self.assertNotIn(module, introduced)
        source = Path(stage1.__file__).read_text(encoding="utf-8")
        imports = [
            line.strip()
            for line in source.splitlines()
            if line.strip().startswith(("import ", "from "))
        ]
        self.assertTrue(
            any("verification.deterministic" in line for line in imports)
        )
        for line in imports:
            self.assertNotIn("verification.verifier", line)
            self.assertNotIn("verification.http_executor", line)
            self.assertNotIn("verification.browser_executor", line)
            self.assertNotIn("verification.composite_executor", line)
            self.assertNotIn("verification.xss_pipeline", line)


class NoLegacyWriteTests(unittest.TestCase):
    def test_pipeline_never_touches_legacy_store(self) -> None:
        # The pipeline docstring names the legacy collection to
        # document its absence; the enforceable check is on IMPORT
        # lines (code that could actually reach the store).
        source = Path(stage1.__file__).read_text(encoding="utf-8")
        imports = [
            line.strip()
            for line in source.splitlines()
            if line.strip().startswith(("import ", "from "))
        ]
        for line in imports:
            for token in (
                "XssFindings",
                "database.db",
                "mongoengine",
                "pymongo",
            ):
                self.assertNotIn(token, line)
        before = set(sys.modules)
        run_stage1(_endpoint(), _config())
        introduced = set(sys.modules) - before
        self.assertNotIn("database.db", introduced)


if __name__ == "__main__":
    unittest.main()
