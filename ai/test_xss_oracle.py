from __future__ import annotations
import unittest
from ai.verification.oracle import (
    JS_W_SOURCE,
    ORACLE_PATH_PREFIX,
    ORACLE_VERSION,
    OraclePlanner,
    PreExecutionInput,
    anti_harvest_violations,
    build_oracle_snippet,
    evaluate_e1_dialog,
    evaluate_e2_network,
    evaluate_e3_eval,
    fnv1a32,
    is_valid_oracle_value,
    is_valid_seed,
    oracle_seed,
    oracle_value_from_seed,
    validate_oracle_pair,
)
from ai.verification.verifier import (
    build_oracle_verification_attempt,
)
_ENDPOINT = "https://target.example.com/path"


class OracleAttemptFactoryTests(unittest.TestCase):
    """Verifier oracle-attempt factory (seed binds to candidate
    identity; attempt stays distinct; unsupported context yields no
    oracle attempt)."""

    def setUp(self):
        from ai.schemas.xss import XSSCase, XSSContext
        from ai.schemas.xss_verification import (
            VerificationMode,
            build_verification_attempt,
        )

        self.XSSCase = XSSCase
        self.XSSContext = XSSContext
        self.candidate = build_verification_attempt(
            case_id="case-1",
            endpoint=_ENDPOINT,
            method="GET",
            parameter="q",
            parameter_location="query",
            payload="<img src=x onerror=1>",
            payload_origin="model_generated",
            knowledge_ids=[],
            source_ids=[],
            based_on_pattern="LLM pattern",
            mode=VerificationMode.BROWSER_EXECUTION,
            phase="browser",
        )

    def _case(self, context_type: str):
        return self.XSSCase(
            case_id="case-1",
            target="target.example.com",
            endpoint=_ENDPOINT,
            method="GET",
            parameter="q",
            parameter_location="query",
            context=self.XSSContext(type=context_type),
        )

    def test_seed_binds_to_candidate_identity(self):
        # The oracle seed must derive from the CANDIDATE's attempt_id
        # (not the oracle attempt's own), breaking the circular
        # seed/payload dependency.
        case = self._case("script_block")
        oracle = build_oracle_verification_attempt(
            case=case, candidate=self.candidate, run_salt="salt-1"
        )
        self.assertIsNotNone(oracle)
        oracle = oracle  # type: ignore[assignment]
        self.assertEqual(
            oracle.oracle_seed,
            oracle_seed("salt-1", self.candidate.attempt_id, "oracle"),
        )
        self.assertEqual(
            oracle.oracle_value, oracle_value_from_seed(oracle.oracle_seed)
        )
        validate_oracle_pair(oracle.oracle_seed, oracle.oracle_value)  # type: ignore[arg-type]

    def test_attempt_identity_distinct_from_candidate(self):
        case = self._case("script_block")
        oracle = build_oracle_verification_attempt(
            case=case, candidate=self.candidate, run_salt="salt-1"
        )
        self.assertIsNotNone(oracle)
        oracle = oracle  # type: ignore[assignment]
        self.assertNotEqual(oracle.attempt_id, self.candidate.attempt_id)
        self.assertEqual(
            oracle.logical_pair_id, self.candidate.logical_pair_id
        )
        self.assertEqual(oracle.phase, "oracle")
        self.assertEqual(oracle.oracle_identity, self.candidate.attempt_id)
        self.assertEqual(oracle.oracle_version, ORACLE_VERSION)
        self.assertEqual(oracle.mode.value, "browser_execution")

    def test_deterministic(self):
        case = self._case("script_block")
        a = build_oracle_verification_attempt(
            case=case, candidate=self.candidate, run_salt="salt-1"
        )
        b = build_oracle_verification_attempt(
            case=case, candidate=self.candidate, run_salt="salt-1"
        )
        self.assertEqual(a.attempt_id, b.attempt_id)
        self.assertEqual(a.oracle_seed, b.oracle_seed)
        self.assertEqual(a.oracle_value, b.oracle_value)
        self.assertEqual(a.payload, b.payload)

    def test_run_salt_changes_oracle(self):
        case = self._case("script_block")
        a = build_oracle_verification_attempt(
            case=case, candidate=self.candidate, run_salt="run-A"
        )
        b = build_oracle_verification_attempt(
            case=case, candidate=self.candidate, run_salt="run-B"
        )
        self.assertNotEqual(a.oracle_seed, b.oracle_seed)
        self.assertNotEqual(a.oracle_value, b.oracle_value)

    def test_payload_contains_seed_once_never_value(self):
        case = self._case("script_block")
        oracle = build_oracle_verification_attempt(
            case=case, candidate=self.candidate, run_salt="salt-1"
        )
        self.assertIsNotNone(oracle)
        oracle = oracle  # type: ignore[assignment]
        self.assertEqual(oracle.payload.count(oracle.oracle_seed), 1)
        self.assertNotIn(oracle.oracle_value, oracle.payload)

    def test_unsupported_context_yields_no_oracle_attempt(self):
        # unknown context: NO oracle attempt, no fallback skeleton.
        case = self._case("unknown")
        oracle = build_oracle_verification_attempt(
            case=case, candidate=self.candidate, run_salt="salt-1"
        )
        self.assertIsNone(oracle)

    def test_anti_harvest_holds_on_oracle_attempt(self):
        # The verifier's PreExecutionInput for an oracle attempt must
        # hold: D in payload/bound-input/intended/actual URL generate
        # violations; the oracle request itself is separate.
        case = self._case("script_block")
        oracle = build_oracle_verification_attempt(
            case=case, candidate=self.candidate, run_salt="salt-1"
        )
        self.assertIsNotNone(oracle)
        oracle = oracle  # type: ignore[assignment]
        pre = PreExecutionInput(
            payload=oracle.payload,
            bound_input=(
                f"{oracle.payload}~~{oracle.correlation_token}"
            ),
            intended_request_url=f"{oracle.endpoint}?q=probe",
            actual_request_url=f"{oracle.endpoint}?q=probe",
        )
        self.assertEqual(
            anti_harvest_violations(
                oracle.oracle_seed, oracle.oracle_value, pre
            ),
            [],
        )
        # D in a pre-execution string is a violation.
        bad = PreExecutionInput(
            payload=oracle.payload,
            intended_request_url=oracle.endpoint + (
                "?" + oracle.oracle_value
            ),
        )
        violations = anti_harvest_violations(
            oracle.oracle_seed, oracle.oracle_value, bad
        )
        self.assertTrue(
            any(
                v.startswith("oracle_value_on_wire:")
                for v in violations
            )
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
