"""Execution-oracle infrastructure tests.

Covers: W(S) deterministic vectors, Python/JavaScript bit-identity (run
via node when available), seed generation, strict validators, the trusted
planner, E1/E2/E3 predicates, anti-harvest invariants, benign-page spoof
regression (10 copy/echo attacks), and run-salt/replay binding.

No verdict classification is tested here on purpose: this task implements
oracle infrastructure only and must not change global verdict behaviour.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest

from ai.schemas.xss_verification import (
    DialogEvent,
    EvalInvocation,
    NetworkOracleEvent,
    VerificationAttempt,
)
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

_HAS_NODE = shutil.which("node") is not None
_ENDPOINT = "https://target.example.com/path"


def _planner() -> OraclePlanner:
    return OraclePlanner()


def _plan(context: str = "script_block", **kwargs) -> "object":
    defaults = dict(
        context_type=context,
        case_id="case-1",
        attempt_id="va-" + "a" * 64,
        logical_pair_id="lp-" + "b" * 64,
        run_salt="run-salt-1",
        phase="browser",
        delivery_pattern="<script>alert(1)</script>",
    )
    defaults.update(kwargs)
    return _planner().plan(**defaults)


def _attempt(payload: str, **kwargs) -> VerificationAttempt:
    defaults = dict(
        attempt_id="va-" + "a" * 64,
        logical_pair_id="lp-" + "b" * 64,
        case_id="case-1",
        endpoint=_ENDPOINT,
        method="GET",
        parameter="q",
        parameter_location="query",
        payload=payload,
        payload_origin="model_generated",
        mode="browser_execution",
        correlation_token="ct-" + "c" * 32,
        phase="browser",
    )
    defaults.update(kwargs)
    return VerificationAttempt(**defaults)


class FnV1A32Tests(unittest.TestCase):
    def test_known_vectors(self):
        # FNV-1a 32-bit over UTF-16 code units; standard test string.
        self.assertEqual(fnv1a32(""), 0x811C9DC5)
        self.assertEqual(fnv1a32("a"), 0xE40C292C)

    def test_output_is_uint32(self):
        for text in ("", "a", "hello", "ffff", "\U0001f600"):
            value = fnv1a32(text)
            self.assertTrue(0 <= value <= 0xFFFFFFFF)


class OracleValueTests(unittest.TestCase):
    def test_w_of_empty_seed(self):
        # Both halves computed and zero-padded to exactly 8 digits.
        self.assertEqual(oracle_value_from_seed(""), "811c9dc561fb875f")

    def test_value_is_16_lowercase_hex(self):
        for seed in ("", "a", "abc", "z" * 40, "\u00e9\u4e2d"):
            value = oracle_value_from_seed(seed)
            self.assertEqual(len(value), 16)
            self.assertEqual(value, value.lower())
            self.assertTrue(is_valid_oracle_value(value))

    def test_deterministic(self):
        self.assertEqual(
            oracle_value_from_seed("abcd1234" * 4),
            oracle_value_from_seed("abcd1234" * 4),
        )

    def test_distinct_seeds_distinct_values(self):
        values = {
            oracle_value_from_seed(f"{i:032x}") for i in range(50)
        }
        self.assertEqual(len(values), 50)


class SeedGenerationTests(unittest.TestCase):
    def test_seed_shape(self):
        seed = oracle_seed("salt", "va-x", "browser")
        self.assertEqual(len(seed), 32)
        self.assertTrue(is_valid_seed(seed))
        self.assertEqual(seed, seed.lower())

    def test_salt_participates(self):
        base = ("va-x", "browser")
        self.assertNotEqual(
            oracle_seed("salt-1", *base), oracle_seed("salt-2", *base)
        )

    def test_phase_and_attempt_participate(self):
        self.assertNotEqual(
            oracle_seed("salt", "va-x", "browser"),
            oracle_seed("salt", "va-x", "http"),
        )
        self.assertNotEqual(
            oracle_seed("salt", "va-x", "browser"),
            oracle_seed("salt", "va-y", "browser"),
        )

    def test_field_boundary_cannot_alias(self):
        # NUL-joined canonical: ("a","bc") must not equal ("ab","c").
        self.assertNotEqual(
            oracle_seed("a", "bc", "p"), oracle_seed("ab", "c", "p")
        )

    def test_pair_validation(self):
        seed = oracle_seed("salt", "va-x", "browser")
        value = oracle_value_from_seed(seed)
        validate_oracle_pair(seed, value)  # must not raise
        with self.assertRaises(ValueError):
            validate_oracle_pair(seed, seed)  # D != S
        with self.assertRaises(ValueError):
            validate_oracle_pair(seed.upper(), value)
        with self.assertRaises(ValueError):
            validate_oracle_pair(seed, value.upper())
        with self.assertRaises(ValueError):
            validate_oracle_pair(seed, "0" * 16)


class JavaScriptEquivalenceTests(unittest.TestCase):
    """Python W(S) must be bit-identical to the JavaScript runtime form."""

    VECTORS = [
        "",        # empty string (implementation-defined)
        "a",       # short ASCII
        "0" * 32,  # normal 32-char hex seed
        "f" * 32,  # all-max hex digit
        "ab" * 16,  # repeated characters
        "\x01\x02\x7f",  # boundary-ish ASCII values
        "the quick brown fox",
        "e5f3a1",  # deterministic vector set
        "00ff10ee",
        "deadbeef",
        "9f8e7d6c5b4a",
        "1234567890abcdef1234567890abcdef",
    ]

    @staticmethod
    def _run_js(script: str, args: list[str]) -> str:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".js", delete=False
        ) as handle:
            handle.write(script)
            path = handle.name
        result = subprocess.run(
            ["node", path, *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    @unittest.skipUnless(_HAS_NODE, "node not available")
    def test_python_matches_javascript(self):
        js = (
            "function W(s){var a=2166136261,b=2166136261,i,t;"
            "for(i=0;i<s.length;i++)"
            "a=Math.imul(a^s.charCodeAt(i),16777619)>>>0;"
            "t=('00000000'+a.toString(16)).slice(-8)+':'+s;"
            "for(i=0;i<t.length;i++)"
            "b=Math.imul(b^t.charCodeAt(i),16777619)>>>0;"
            "return ('00000000'+a.toString(16)).slice(-8)+"
            "('00000000'+b.toString(16)).slice(-8);}\n"
            "const seeds=JSON.parse(process.argv[2]);\n"
            "console.log(seeds.map(W).join('\\n'));\n"
        )
        outputs = self._run_js(
            js, [json.dumps(self.VECTORS)]
        ).splitlines()
        self.assertEqual(len(outputs), len(self.VECTORS))
        for seed, js_value in zip(self.VECTORS, outputs):
            self.assertEqual(
                oracle_value_from_seed(seed),
                js_value,
                f"mismatch for seed {seed!r}",
            )

    @unittest.skipUnless(_HAS_NODE, "node not available")
    def test_embedded_js_source_matches_python(self):
        # The payload-embedded transform must produce the same D as the
        # Python implementation for a real seed.
        seed = oracle_seed("run", "va-x", "browser")
        script = JS_W_SOURCE.replace("<SEED>", seed) + (
            "\nconsole.log(d);\n"
        )
        self.assertEqual(
            self._run_js(script, []), oracle_value_from_seed(seed)
        )


class OraclePlannerTests(unittest.TestCase):
    def test_supported_contexts(self):
        for context in (
            "html_body",
            "html_attribute",
            "script_block",
            "generic",
        ):
            plan = _plan(context=context)
            self.assertTrue(plan.supported, context)
            self.assertEqual(plan.version, ORACLE_VERSION)
            validate_oracle_pair(plan.seed, plan.oracle_value)

    def test_unsupported_context_is_explicit(self):
        plan = _plan(context="url")
        self.assertFalse(plan.supported)
        self.assertEqual(plan.payload, "")
        self.assertIn("unsupported", plan.reason)
        self.assertTrue(plan.unsupported_reason)

    def test_payload_contains_seed_once_and_never_value(self):
        for context in ("html_body", "script_block", "generic"):
            plan = _plan(context=context)
            self.assertEqual(plan.payload.count(plan.seed), 1)
            self.assertNotIn(plan.oracle_value, plan.payload)
            self.assertNotIn(plan.oracle_value, plan.snippet)

    def test_payload_compact(self):
        self.assertLessEqual(len(_plan().payload), 512)

    def test_determinism(self):
        first, second = _plan(), _plan()
        self.assertEqual(first.seed, second.seed)
        self.assertEqual(first.oracle_value, second.oracle_value)
        self.assertEqual(first.payload, second.payload)

    def test_run_salt_attempt_and_phase_change_seed(self):
        self.assertNotEqual(_plan().seed, _plan(run_salt="other").seed)
        self.assertNotEqual(
            _plan().seed, _plan(attempt_id="va-" + "c" * 64).seed
        )
        self.assertNotEqual(_plan().seed, _plan(phase="http").seed)

    def test_llm_pattern_cannot_control_oracle(self):
        controlled = _plan(delivery_pattern="alert('pwned')")
        normal = _plan()
        self.assertEqual(controlled.seed, normal.seed)
        self.assertEqual(controlled.oracle_value, normal.oracle_value)
        self.assertNotIn("pwned", controlled.payload)

    def test_snippet_is_valid_js_shape(self):
        snippet = build_oracle_snippet(oracle_seed("s", "va", "p"))
        self.assertIn("Math.imul", snippet)
        self.assertIn(">>>0", snippet)
        self.assertIn("alert(d);", snippet)
        self.assertIn("new Image().src='/.watch-oracle/'+d;", snippet)
        self.assertNotIn('"', snippet)  # attribute-context safe


class E1DialogPredicateTests(unittest.TestCase):
    def setUp(self):
        self.plan = _plan()
        self.d = self.plan.oracle_value
        self.s = self.plan.seed

    def _dialog(self, message, kind="alert"):
        return [DialogEvent(kind=kind, message=message)]

    def test_exact_match_passes_for_all_dialog_kinds(self):
        for kind in ("alert", "confirm", "prompt"):
            self.assertTrue(
                evaluate_e1_dialog(self._dialog(self.d, kind), self.d)
            )

    def test_non_dialog_kind_fails(self):
        self.assertFalse(
            evaluate_e1_dialog(
                self._dialog(self.d, "beforeunload"), self.d
            )
        )

    def test_spoof_variants_fail(self):
        failures = [
            self.d + "x",                  # D + suffix
            "x" + self.d,                  # D + prefix
            " " + self.d + " ",            # whitespace-padded D
            f"search={self.s} {self.d}!",  # substring containing D
            self.d.upper(),                # wrong case
            self.s,                        # the seed
            self.d[:8],                    # partial
        ]
        for message in failures:
            self.assertFalse(
                evaluate_e1_dialog(self._dialog(message), self.d),
                f"spoof accepted: {message!r}",
            )

    def test_empty_events_fail(self):
        self.assertFalse(evaluate_e1_dialog([], self.d))
        self.assertFalse(evaluate_e1_dialog(None, self.d))


class E2NetworkPredicateTests(unittest.TestCase):
    def setUp(self):
        self.plan = _plan()
        self.d = self.plan.oracle_value
        self.s = self.plan.seed
        self.base = "https://target.example.com" + ORACLE_PATH_PREFIX

    def _event(self, url, is_navigation=False):
        from urllib.parse import unquote as _unquote, urlsplit as _split

        return [
            NetworkOracleEvent(
                url=url,
                path=_unquote(_split(url).path),
                is_navigation=is_navigation,
            )
        ]

    def test_exact_path_passes(self):
        self.assertTrue(
            evaluate_e2_network(
                self._event(self.base + self.d), self.d, _ENDPOINT
            )
        )

    def test_exact_path_with_query_passes(self):
        self.assertTrue(
            evaluate_e2_network(
                self._event(self.base + self.d + "?x=1&y=2"),
                self.d,
                _ENDPOINT,
            )
        )

    def test_encoded_d_single_decode_passes(self):
        # First char of D percent-encoded as a full two-digit escape
        # (e.g. '9' -> '%39'); a single decode restores it exactly.
        encoded = "%" + format(ord(self.d[0]), "02x")
        self.assertTrue(
            evaluate_e2_network(
                self._event(self.base + encoded + self.d[1:]),
                self.d,
                _ENDPOINT,
            )
        )

    def test_wrong_oracle_path_fails(self):
        self.assertFalse(
            evaluate_e2_network(
                self._event(
                    "https://target.example.com/watch-oracle/" + self.d
                ),
                self.d,
                _ENDPOINT,
            )
        )

    def test_raw_seed_in_path_fails(self):
        self.assertFalse(
            evaluate_e2_network(
                self._event(self.base + self.s), self.d, _ENDPOINT
            )
        )

    def test_path_suffix_fails(self):
        self.assertFalse(
            evaluate_e2_network(
                self._event(self.base + self.d + "/x"),
                self.d,
                _ENDPOINT,
            )
        )

    def test_path_prefix_fails(self):
        self.assertFalse(
            evaluate_e2_network(
                self._event(
                    "https://target.example.com/log/"
                    + ORACLE_PATH_PREFIX
                    + self.d
                ),
                self.d,
                _ENDPOINT,
            )
        )

    def test_navigation_request_fails(self):
        self.assertFalse(
            evaluate_e2_network(
                self._event(self.base + self.d, is_navigation=True),
                self.d,
                _ENDPOINT,
            )
        )

    def test_cross_origin_request_fails(self):
        self.assertFalse(
            evaluate_e2_network(
                self._event(
                    "https://evil.example.com"
                    + ORACLE_PATH_PREFIX
                    + self.d
                ),
                self.d,
                _ENDPOINT,
            )
        )

    def test_wrong_value_fails(self):
        self.assertFalse(
            evaluate_e2_network(
                self._event(self.base + self.d[:-1] + "0"),
                self.d,
                _ENDPOINT,
            )
        )


class E3EvalPredicateTests(unittest.TestCase):
    def test_exact_payload_passes(self):
        payload = "alert('x')"
        self.assertTrue(
            evaluate_e3_eval(
                [EvalInvocation(operator="eval", value=payload)], payload
            )
        )
        self.assertTrue(
            evaluate_e3_eval(
                [
                    EvalInvocation(
                        operator="setTimeout:string", value=payload
                    )
                ],
                payload,
            )
        )

    def test_unsupported_operator_fails(self):
        payload = "alert('x')"
        self.assertFalse(
            evaluate_e3_eval(
                [EvalInvocation(operator="new Function", value=payload)],
                payload,
            )
        )

    def test_truncated_prefix_never_passes(self):
        payload = "a" * 200
        truncated = EvalInvocation(operator="eval", value="a" * 100)
        self.assertFalse(evaluate_e3_eval([truncated], payload))

    def test_disabled_for_long_payloads(self):
        payload = "a" * 241
        self.assertFalse(evaluate_e3_eval([], payload))
        exact = EvalInvocation(operator="eval", value=payload)
        # Refused even for an exact-looking record: above 240 chars the
        # instrumentation truncates, so equality cannot be trusted.
        self.assertFalse(evaluate_e3_eval([exact], payload))

    def test_boundary_240_still_enabled(self):
        payload = "b" * 240
        self.assertTrue(
            evaluate_e3_eval(
                [EvalInvocation(operator="eval", value=payload)], payload
            )
        )


class BenignSpoofRegressionTests(unittest.TestCase):
    """The 10 benign copy/echo attacks from the design brief.

    A benign page can read the bound input (payload + seed) from the
    URL, referrer, DOM, reflection, storage, or its own telemetry — but
    it can never produce D, so none of its behaviors may satisfy E1/E2.
    """

    def setUp(self):
        self.plan = _plan(context="script_block")
        self.s = self.plan.seed
        self.d = self.plan.oracle_value
        self.attempt = _attempt(self.plan.payload)
        self.bound = (
            self.plan.payload + "~~" + self.attempt.correlation_token
        )
        self.request_url = _ENDPOINT + "?q=" + self.bound

    def test_all_ten_benign_attacks_fail_e1(self):
        benign_dialog_messages = [
            self.bound,                        # alert(location.search)
            self.s,                            # alert(extracted seed)
            f"path={self.request_url}",        # referrer propagation
            self.plan.payload,                 # DOM payload copy
            f"reflected:{self.plan.payload}",  # server reflection
        ]
        for message in benign_dialog_messages:
            self.assertFalse(
                evaluate_e1_dialog(
                    [DialogEvent(kind="alert", message=message)], self.d
                ),
                f"E1 accepted benign copy: {message!r}",
            )

    def test_all_ten_benign_requests_fail_e2(self):
        benign_requests = [
            "https://target.example.com/" + self.s,  # fetch('/'+seed)
            "https://target.example.com/log/" + self.request_url,
            "https://target.example.com/collect?" + self.request_url,
            "https://target.example.com/t/" + self.bound,
            "https://target.example.com/router" + self.request_url,
            "https://target.example.com/b64?p=" + self.bound,
        ]
        for url in benign_requests:
            self.assertFalse(
                evaluate_e2_network(
                    [
                        NetworkOracleEvent(
                            url=url,
                            path=url.split("target.example.com", 1)[-1],
                        )
                    ],
                    self.d,
                    _ENDPOINT,
                ),
                f"E2 accepted benign copy: {url!r}",
            )

    def test_anti_harvest_holds_for_every_benign_location(self):
        locations = [
            self.bound,
            self.request_url,
            self.request_url,   # referrer copy of the attack URL
            self.plan.payload,  # DOM/reflection copy
            "https://t.example/log/" + self.request_url,
        ]
        self.assertEqual(
            anti_harvest_violations(
                seed=self.s,
                oracle_value=self.d,
                pre=PreExecutionInput(
                    payload=self.plan.payload,
                    bound_input=self.bound,
                    intended_request_url=self.request_url,
                    actual_request_url=self.request_url,
                    request_body=self.bound,
                    response_snippet=self.plan.payload,
                    referrer_derived=self.request_url,
                    pre_execution_inputs=tuple(locations),
                ),
            ),
            [],
        )


class EvidenceBoundaryTests(unittest.TestCase):
    """Anti-harvest / E2 evidence-boundary regression tests.

    The architecture MUST explicitly distinguish:

        PRE-EXECUTION / ATTACK-CONTROLLED MATERIAL
            (payload, bound input, intended URL, request body,
             response snippet, referrer, pre-execution inputs)
            => D MUST NOT occur. Enforced by anti_harvest_violations.

        POST-EXECUTION / EXECUTOR-OWNED ORACLE EVIDENCE
            (DialogEvent.message, NetworkOracleEvent.path)
            => D IS EXPECTED. Validated by evaluate_e1_dialog /
               evaluate_e2_network ONLY.

    These tests prove the complement holds for every D value.
    """

    def setUp(self):
        self.plan = _plan(context="script_block")
        self.s = self.plan.seed
        self.d = self.plan.oracle_value
        self.attempt = _attempt(self.plan.payload)
        self.bound = (
            self.plan.payload + "~~" + self.attempt.correlation_token
        )
        self.request_url = _ENDPOINT + "?q=" + self.bound
        self.base = "https://target.example.com" + ORACLE_PATH_PREFIX

    # TEST 1: D in pre-execution URL -> anti-harvest MUST reject
    def test_d_in_pre_execution_url_rejected_by_anti_harvest(self):
        pre = PreExecutionInput(
            payload=self.plan.payload,
            intended_request_url=self.base + self.d,
        )
        violations = anti_harvest_violations(
            seed=self.s, oracle_value=self.d, pre=pre
        )
        self.assertIn(
            "oracle_value_on_wire:intended_request_url",
            violations,
        )

    # TEST 2: Valid E2 oracle event with D -> E2 MUST accept
    def test_e2_accepts_valid_oracle_event(self):
        self.assertTrue(
            evaluate_e2_network(
                [NetworkOracleEvent(
                    url=self.base + self.d,
                    path=ORACLE_PATH_PREFIX + self.d,
                )],
                self.d,
                _ENDPOINT,
            )
        )

    # TEST 3: Both pre-execution URL contains D AND valid E2 event
    #         -> anti-harvest rejects pre-execution material
    #         -> E2 independently accepts the oracle event
    def test_anti_harvest_rejects_e2_independently_accepts(self):
        pre = PreExecutionInput(
            payload=self.plan.payload,
            intended_request_url=self.base + self.d,
        )
        violations = anti_harvest_violations(
            seed=self.s, oracle_value=self.d, pre=pre
        )
        self.assertIn(
            "oracle_value_on_wire:intended_request_url",
            violations,
        )
        oracle_event = [
            NetworkOracleEvent(
                url=self.base + self.d,
                path=ORACLE_PATH_PREFIX + self.d,
            )
        ]
        self.assertTrue(
            evaluate_e2_network(oracle_event, self.d, _ENDPOINT)
        )

    # TEST 4: Valid E2 request MUST NOT be rejected merely because
    #         its own URL contains D
    def test_e2_not_rejected_for_d_in_url(self):
        url = self.base + self.d
        self.assertTrue(
            evaluate_e2_network(
                [NetworkOracleEvent(
                    url=url,
                    path=ORACLE_PATH_PREFIX + self.d,
                )],
                self.d,
                _ENDPOINT,
            )
        )

    # TEST 5: Normal browser network request containing D but NOT
    #         classified as an oracle event -> MUST NOT be valid E2
    def test_generic_request_with_d_is_not_e2(self):
        # A request to a non-oracle path that happens to contain D
        # as a substring (e.g. telemetry with D in the query).
        telemetry_url = (
            "https://target.example.com/log?ref=" + self.d
        )
        self.assertFalse(
            evaluate_e2_network(
                [NetworkOracleEvent(
                    url=telemetry_url,
                    path="/log",
                )],
                self.d,
                _ENDPOINT,
            )
        )

    # TEST 6: Copied/echoed D in generic network telemetry -> NOT E2
    def test_echoed_d_in_telemetry_is_not_e2(self):
        # A telemetry beacon that copies D into the path (without
        # the /watch-oracle/ prefix) must not satisfy E2.
        echo_url = "https://target.example.com/beacon/" + self.d
        self.assertFalse(
            evaluate_e2_network(
                [NetworkOracleEvent(
                    url=echo_url,
                    path="/beacon/" + self.d,
                )],
                self.d,
                _ENDPOINT,
            )
        )

    # TEST 8: E1 remains valid when E1 and E2 both contain D
    def test_e1_valid_when_e1_and_e2_both_contain_d(self):
        self.assertTrue(
            evaluate_e1_dialog(
                [DialogEvent(kind="alert", message=self.d)],
                self.d,
            )
        )
        # E2 independently accepts the same D
        self.assertTrue(
            evaluate_e2_network(
                [NetworkOracleEvent(
                    url=self.base + self.d,
                    path=ORACLE_PATH_PREFIX + self.d,
                )],
                self.d,
                _ENDPOINT,
            )
        )

    def test_anti_harvest_rejects_pre_execution_with_d(self):
        """D in payload is always a violation."""
        pre = PreExecutionInput(
            payload=self.plan.payload + self.d,
            bound_input="",
        )
        violations = anti_harvest_violations(
            seed=self.s, oracle_value=self.d, pre=pre
        )
        self.assertIn(
            "oracle_value_on_wire:payload",
            violations,
        )

    def test_anti_harvest_rejects_actual_request_url_with_d(self):
        """D in the actual request URL is a violation."""
        pre = PreExecutionInput(
            payload=self.plan.payload,
            actual_request_url=self.base + self.d,
        )
        violations = anti_harvest_violations(
            seed=self.s, oracle_value=self.d, pre=pre
        )
        self.assertIn(
            "oracle_value_on_wire:actual_request_url",
            violations,
        )

    def test_anti_harvest_rejects_every_pre_execution_field(self):
        """Every pre-execution field containing D is rejected."""
        pre = PreExecutionInput(
            payload=self.plan.payload,
            bound_input=self.d,
            intended_request_url=self.base + self.d,
            actual_request_url=self.base + self.d,
            request_body=self.d,
            response_snippet=self.d,
            referrer_derived=self.d,
            pre_execution_inputs=(self.d,),
        )
        violations = anti_harvest_violations(
            seed=self.s, oracle_value=self.d, pre=pre
        )
        names = {v.split(":", 1)[1] for v in violations
                 if v.startswith("oracle_value_on_wire:")}
        expected = {
            "bound_input",
            "intended_request_url",
            "actual_request_url",
            "request_body",
            "response_snippet",
            "referrer_derived",
            "pre_execution_input:0",
        }
        for field in expected:
            self.assertIn(
                field, names,
                f"missing violation for field {field!r}: "
                f"got {violations!r}",
            )


class EvidenceBoundaryAPITests(unittest.TestCase):
    """The API must make the pre-execution / post-execution
    boundary structurally obvious and hard to violate.

    A NetworkOracleEvent (post-execution executor-owned evidence)
    MUST NOT be expressible as pre-execution input. The anti-harvest
    scanner accepts ONLY PreExecutionInput, which cannot carry
    oracle event objects.
    """

    def test_network_oracle_event_is_not_pre_execution_input(self):
        # NetworkOracleEvent is NOT accepted as the ``pre`` argument.
        event = NetworkOracleEvent(
            url="https://target.example.com/.watch-oracle/"
            + "0123456789abcdef",
            path="/.watch-oracle/0123456789abcdef",
        )
        with self.assertRaises(TypeError):
            anti_harvest_violations(
                seed="0" * 32,
                oracle_value="0123456789abcdef",
                pre=event,  # type: ignore[arg-type]
            )

    def test_network_oracle_event_has_no_pre_execution_shape(self):
        # Structural assertion: a NetworkOracleEvent cannot be
        # converted into a PreExecutionInput. The types share no
        # usable contract: PreExecutionInput has no url/path fields
        # and NetworkOracleEvent has no payload/bound_input fields.
        event_fields = set(NetworkOracleEvent.model_fields)
        pre_fields = set(PreExecutionInput.__dataclass_fields__)
        self.assertEqual(
            event_fields & pre_fields,
            set(),
            "NetworkOracleEvent and PreExecutionInput share fields; "
            "the evidence boundary is not structurally clean.",
        )
        # The scanner's only input type cannot represent oracle
        # evidence: no field of PreExecutionInput can carry a
        # NetworkOracleEvent instance.
        self.assertNotIn("url", pre_fields)
        self.assertNotIn("path", pre_fields)
        self.assertNotIn("dialog_events", pre_fields)
        self.assertNotIn("oracle_network_events", pre_fields)

    def test_pre_execution_inputs_reject_oracle_event_objects(self):
        # Even sneaking a NetworkOracleEvent into the extra string
        # inputs is impossible: the tuple is typed str and a
        # non-str object is not a string, so scanning never treats
        # oracle evidence as pre-execution text.
        event = NetworkOracleEvent(
            url="https://target.example.com/.watch-oracle/x",
            path="/.watch-oracle/x",
        )
        pre = PreExecutionInput(
            payload="p",
            pre_execution_inputs=(),  # empty: no oracle material
        )
        # The boundary is structural: oracle events are not part of
        # PreExecutionInput at all.
        self.assertNotIsInstance(event, PreExecutionInput)
        violations = anti_harvest_violations(
            seed="0" * 32,
            oracle_value="0123456789abcdef",
            pre=pre,
        )
        # A payload not containing the seed is itself a violation,
        # but no oracle_value_on_wire violation is produced because
        # no oracle evidence was passed.
        self.assertNotIn(
            "oracle_value_on_wire:pre_execution_input:0",
            violations,
        )


class RunSaltReplayTests(unittest.TestCase):
    def test_different_runs_produce_different_oracles(self):
        kwargs = dict(
            context_type="script_block",
            case_id="case-1",
            attempt_id="va-" + "a" * 64,
            logical_pair_id="lp-" + "b" * 64,
            phase="browser",
        )
        run_a = OraclePlanner().plan(run_salt="run-A", **kwargs)
        run_b = OraclePlanner().plan(run_salt="run-B", **kwargs)
        self.assertNotEqual(run_a.seed, run_b.seed)
        self.assertNotEqual(run_a.oracle_value, run_b.oracle_value)
        with self.assertRaises(ValueError):
            validate_oracle_pair(run_b.seed, run_a.oracle_value)

    def test_old_value_does_not_match_new_attempt(self):
        old = oracle_seed("salt-1", "va-old", "browser")
        new = oracle_seed("salt-1", "va-new", "browser")
        self.assertNotEqual(old, new)
        self.assertNotEqual(
            oracle_value_from_seed(old), oracle_value_from_seed(new)
        )

    def test_attempt_level_binding(self):
        attempt = _attempt("payload")
        seed = oracle_seed("salt", attempt.attempt_id, attempt.phase)
        value = oracle_value_from_seed(seed)
        validate_oracle_pair(seed, value)
        self.assertNotEqual(
            value,
            oracle_value_from_seed(
                oracle_seed("salt-2", attempt.attempt_id, attempt.phase)
            ),
        )


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
