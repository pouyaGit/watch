"""Focused unit tests for ``XSSCaseBuilder``.

The builder is a narrow deterministic adapter from the Watch
``Endpoints`` inventory to :class:`ai.schemas.xss.XSSCase`
objects (ONE CASE PER PARAMETER). These tests prove only the
builder contract — no verifier, executor, or orchestrator
behaviour is exercised, and no MongoDB, network, or browser
is touched (programs and endpoints are pure fakes; the
MongoDB lookups are injected/lazy).
"""

from __future__ import annotations

import re
import unittest

from ai.schemas.xss import XSSCase
from ai.verification import XSSCaseBuilder
from ai.verification import xss_case_builder as builder_module


# =====================================================================
# Fakes: pure in-memory Programs / Endpoints rows.
# =====================================================================


class _FakeProgram:
    """Fake Programs row: program_name, scopes, ooscopes."""

    def __init__(self, program_name, scopes, ooscopes=None):
        self.program_name = program_name
        self.scopes = list(scopes or [])
        self.ooscopes = list(ooscopes or [])


class _FakeEndpoint:
    """Fake Endpoints row (subset of the real fields)."""

    def __init__(
        self,
        *,
        program_name="acme",
        subdomain="app.example.com",
        path="/search",
        example_url="https://app.example.com/search",
        params=None,
        params_from_crawl=None,
        params_from_x8=None,
        x8_checked=True,
        param_records=None,
    ):
        self.program_name = program_name
        self.subdomain = subdomain
        self.path = path
        self.example_url = example_url
        self.params = list(params or [])
        self.params_from_crawl = list(params_from_crawl or [])
        self.params_from_x8 = list(params_from_x8 or [])
        self.x8_checked = x8_checked
        # None/absent -> legacy row (no provenance); the real
        # mongoengine field defaults to [].
        self.param_records = (
            list(param_records) if param_records is not None else None
        )


def _in_scope_program() -> _FakeProgram:
    return _FakeProgram(
        program_name="acme",
        scopes=["example.com"],
        ooscopes=[],
    )


def _builder(program=None):
    """Builder with an injected program lookup (no MongoDB)."""
    program = (
        program if program is not None else _in_scope_program()
    )

    def _lookup(program_name):
        # Deterministic: any non-unknown name resolves to the
        # same fake program; names never resolve to None here
        # (missing-program behaviour is tested separately).
        if program.program_name == program_name:
            return program
        return program if program_name == "acme" else None

    return XSSCaseBuilder(program_lookup=_lookup)


def _eligible_endpoint(**overrides) -> _FakeEndpoint:
    kwargs = dict(
        params=["q", "redirect"],
    )
    kwargs.update(overrides)
    return _FakeEndpoint(**kwargs)


def _strip_timestamps(case: XSSCase) -> dict:
    # created_at/updated_at are schema-owned build-time
    # metadata; determinism applies to every content field.
    dump = case.model_dump()
    dump.pop("created_at", None)
    dump.pop("updated_at", None)
    return dump


# =====================================================================
# Core contract: one case per parameter, deterministic
# =====================================================================


class BuilderCoreTests(unittest.TestCase):
    def test_one_case_per_parameter(self):
        cases = _builder().build(
            _eligible_endpoint(params=["q", "redirect"])
        )

        self.assertEqual(len(cases), 2)
        self.assertEqual(
            sorted(c.parameter for c in cases),
            ["q", "redirect"],
        )
        for case in cases:
            self.assertIsNotNone(case.parameter)

    def test_parameters_deterministic_and_deduplicated(self):
        cases = _builder().build(
            _eligible_endpoint(
                params=["b", "a", "b", "", "a", None]
            )
        )

        self.assertEqual(
            [c.parameter for c in cases], ["a", "b"]
        )
        # Deterministic order across repeated builds with a
        # differently ordered raw list.
        again = _builder().build(
            _eligible_endpoint(
                params=["a", "b", "", "b", "a", None]
            )
        )
        self.assertEqual(
            [c.parameter for c in cases],
            [c.parameter for c in again],
        )

    def test_get_and_query_defaults(self):
        cases = _builder().build(_eligible_endpoint())

        self.assertTrue(cases)
        for case in cases:
            self.assertEqual(case.method, "GET")
            self.assertEqual(case.parameter_location, "query")

    def test_case_id_deterministic(self):
        endpoint = _eligible_endpoint(params=["q"])

        first = _builder().build(endpoint)
        second = _builder().build(
            _eligible_endpoint(params=["q"])
        )

        self.assertEqual(len(first), 1)
        self.assertEqual(first[0].case_id, second[0].case_id)
        # Repository style: "case-" prefix + bounded hex hash.
        self.assertRegex(
            first[0].case_id, r"^case-[0-9a-f]{32}$"
        )

    def test_same_input_produces_identical_cases(self):
        endpoint = _eligible_endpoint(params=["q", "redirect"])

        first = _builder().build(endpoint)
        second = _builder().build(endpoint)

        self.assertEqual(len(first), 2)
        self.assertEqual(
            [_strip_timestamps(c) for c in first],
            [_strip_timestamps(c) for c in second],
        )

    def test_different_parameters_yield_different_case_ids(self):
        cases = _builder().build(
            _eligible_endpoint(params=["q", "redirect"])
        )
        self.assertNotEqual(
            cases[0].case_id, cases[1].case_id
        )


# =====================================================================
# Scope safety
# =====================================================================


class BuilderScopeTests(unittest.TestCase):
    def test_missing_program_rejected(self):
        builder = XSSCaseBuilder(program_lookup=lambda name: None)
        cases = builder.build(
            _eligible_endpoint(program_name="ghost")
        )
        self.assertEqual(cases, [])

    def test_out_of_scope_host_rejected(self):
        # app.example.com has registrable domain example.com,
        # which is NOT in this program's scopes.
        program = _FakeProgram(
            program_name="acme",
            scopes=["other.com"],
            ooscopes=[],
        )
        cases = _builder(program).build(_eligible_endpoint())
        self.assertEqual(cases, [])

    def test_ooscope_host_rejected(self):
        program = _FakeProgram(
            program_name="acme",
            scopes=["example.com"],
            ooscopes=["app.example.com"],
        )
        cases = _builder(program).build(_eligible_endpoint())
        self.assertEqual(cases, [])

    def test_unknown_program_never_produces_a_case(self):
        # Even a maximally permissive lookup must not rescue a
        # program named "Unknown" (any casing / whitespace).
        permissive = _FakeProgram(
            program_name="Unknown",
            scopes=["example.com", "*"],
            ooscopes=[],
        )
        for name in (
            "Unknown", "unknown", "UNKNOWN", "", "  ", None,
        ):
            builder = XSSCaseBuilder(
                program_lookup=lambda _name: permissive
            )
            endpoint = _FakeEndpoint(
                program_name=name,
                params=["q"],
                example_url="https://app.example.com/search",
            )
            self.assertEqual(builder.build(endpoint), [], name)

    def test_deep_subdomain_of_in_scope_domain_is_eligible(self):
        # Existing Watch semantics: the registrable domain of
        # the host must be listed in scopes, so a deep
        # subdomain of an in-scope domain is fine.
        program = _FakeProgram(
            program_name="acme",
            scopes=["example.com"],
            ooscopes=[],
        )
        cases = _builder(program).build(
            _FakeEndpoint(
                subdomain="deep.app.example.com",
                example_url="https://deep.app.example.com/x",
                params=["q"],
            )
        )
        self.assertEqual([c.parameter for c in cases], ["q"])

    def test_scope_drift_on_recorded_subdomain_rejected(self):
        # The example_url hostname is in scope, but the
        # endpoint's recorded subdomain no longer is (scope
        # list changed since ingestion). Rejection is the
        # safe direction.
        program = _FakeProgram(
            program_name="acme",
            scopes=["safe.com"],
            ooscopes=[],
        )
        cases = _builder(program).build(
            _FakeEndpoint(
                subdomain="app.example.com",
                example_url="https://safe.com/search",
                params=["q"],
            )
        )
        self.assertEqual(cases, [])


# =====================================================================
# URL / host handling
# =====================================================================


class BuilderUrlTests(unittest.TestCase):
    def test_invalid_url_rejected(self):
        for bad in (
            "",
            None,
            "not-a-url",
            "app.example.com/search",
            "https:///search",
            "https://[bad",
            "https://app.example.com:port/x",
        ):
            cases = _builder().build(
                _eligible_endpoint(example_url=bad, params=["q"])
            )
            self.assertEqual(cases, [], repr(bad))

    def test_non_http_url_rejected(self):
        for bad in (
            "ftp://app.example.com/search",
            "file:///etc/passwd",
            "javascript://app.example.com/x",
            "ws://app.example.com/x",
        ):
            cases = _builder().build(
                _eligible_endpoint(example_url=bad, params=["q"])
            )
            self.assertEqual(cases, [], repr(bad))

    def test_https_is_eligible(self):
        cases = _builder().build(
            _FakeEndpoint(
                example_url="https://app.example.com/search",
                params=["q"],
            )
        )
        self.assertEqual([c.parameter for c in cases], ["q"])

    def test_endpoint_url_preserved_verbatim(self):
        # The URL is the execution base: no normalization, no
        # parameter stripping, no rewriting — including an
        # existing query component.
        url = "https://APP.example.com/search?utm=x#frag"
        cases = _builder().build(
            _FakeEndpoint(example_url=url, params=["q"])
        )
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].endpoint, url)

    def test_target_is_the_endpoint_hostname(self):
        cases = _builder().build(
            _eligible_endpoint(
                example_url="https://app.example.com/search"
            )
        )
        self.assertEqual(cases[0].target, "app.example.com")


# =====================================================================
# Parameter handling
# =====================================================================


class BuilderParameterTests(unittest.TestCase):
    def test_no_params_produces_no_cases(self):
        for params in ([], None):
            cases = _builder().build(
                _eligible_endpoint(params=params)
            )
            self.assertEqual(cases, [])

    def test_parameter_names_are_not_transformed(self):
        # No decoding, no renaming, no whitespace stripping:
        # names survive byte-identically (only empty names are
        # dropped).
        raw = ["Q_Str%41", "redirect_url", "  spaced  ", "a.b"]
        cases = _builder().build(
            _eligible_endpoint(params=raw)
        )
        self.assertEqual(
            sorted(c.parameter for c in cases),
            sorted(raw),
        )

    def test_crawl_and_x8_params_not_merged_or_duplicated(self):
        # The candidate set is Endpoint.params ONLY; crawl/x8
        # sources never create extra or duplicate cases.
        cases = _builder().build(
            _eligible_endpoint(
                params=["q"],
                params_from_crawl=["extra1", "q"],
                params_from_x8=["extra2", "q"],
            )
        )
        self.assertEqual([c.parameter for c in cases], ["q"])


# =====================================================================
# Field defaults and discovery evidence
# =====================================================================


class BuilderFieldDefaultTests(unittest.TestCase):
    def setUp(self):
        self.cases = _builder().build(
            _eligible_endpoint(params=["q"])
        )
        self.assertEqual(len(self.cases), 1)
        self.case = self.cases[0]

    def test_input_value_remains_none(self):
        self.assertIsNone(self.case.input_value)

    def test_xss_type_remains_unknown(self):
        self.assertEqual(self.case.xss_type, "unknown")

    def test_status_remains_new(self):
        self.assertEqual(self.case.status, "NEW")

    def test_confidence_remains_zero(self):
        self.assertEqual(self.case.confidence, 0.0)

    def test_context_is_the_default_xsscontext(self):
        default_case = XSSCase(
            case_id="x", target="t", endpoint="e"
        )
        self.assertEqual(self.case.context, default_case.context)

    def test_framework_waf_technology_knowledge_left_empty(self):
        # No inference: no deterministic Watch source is joined
        # for these, so they stay empty/None.
        self.assertIsNone(self.case.framework)
        self.assertIsNone(self.case.waf)
        self.assertEqual(self.case.technology, [])
        self.assertEqual(self.case.retrieved_knowledge_ids, [])

    def test_source_type_is_endpoint(self):
        self.assertEqual(self.case.source_type, "endpoint")

    def test_discovery_evidence_deterministic_and_traceable(self):
        endpoint = _eligible_endpoint(params=["q"])

        first = _builder().build(endpoint)
        second = _builder().build(endpoint)

        self.assertEqual(
            first[0].discovery_evidence,
            second[0].discovery_evidence,
        )
        joined = "\n".join(first[0].discovery_evidence)
        # Traces back to program, endpoint, parameter.
        self.assertIn("program_name:acme", joined)
        self.assertIn("endpoint_subdomain:app.example.com", joined)
        self.assertIn("endpoint_path:/search", joined)
        self.assertIn("parameter:q", joined)

    def test_discovery_evidence_contains_no_secrets(self):
        cases = _builder().build(
            _eligible_endpoint(
                params=["q"],
                params_from_crawl=["token"],
            )
        )
        joined = "\n".join(cases[0].discovery_evidence).lower()
        for forbidden in (
            "password", "secret", "authorization", "cookie",
            "api_key", "apikey", "bearer",
        ):
            self.assertNotIn(forbidden, joined)
        # Bounded entries: no arbitrary database dumps.
        for entry in cases[0].discovery_evidence:
            self.assertLessEqual(len(entry), 200)


# =====================================================================
# Method / location provenance (param_records)
# =====================================================================


class BuilderMethodLocationTests(unittest.TestCase):
    def _endpoint(self, records, **overrides):
        return _FakeEndpoint(param_records=records, **overrides)

    def test_crawl_get_query_record(self):
        cases = _builder().build(
            self._endpoint(
                [{"name": "q", "method": "GET", "location": "query",
                  "source": "crawl"}]
            )
        )
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].method, "GET")
        self.assertEqual(cases[0].parameter_location, "query")
        self.assertEqual(cases[0].parameter, "q")
        self.assertIn("discovered_by:crawl",
                      "\n".join(cases[0].discovery_evidence))

    def test_x8_get_query_record(self):
        cases = _builder().build(
            self._endpoint(
                [{"name": "q", "method": "GET", "location": "query",
                  "source": "x8"}]
            )
        )
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].method, "GET")
        self.assertEqual(cases[0].parameter_location, "query")
        self.assertIn("discovered_by:x8",
                      "\n".join(cases[0].discovery_evidence))

    def test_x8_post_body_record(self):
        cases = _builder().build(
            self._endpoint(
                [{"name": "q", "method": "POST", "location": "body",
                  "source": "x8"}]
            )
        )
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].method, "POST")
        self.assertEqual(cases[0].parameter_location, "body")
        self.assertEqual(cases[0].parameter, "q")

    def test_x8_put_body_record(self):
        cases = _builder().build(
            self._endpoint(
                [{"name": "q", "method": "PUT", "location": "body",
                  "source": "x8"}]
            )
        )
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].method, "PUT")
        self.assertEqual(cases[0].parameter_location, "body")

    def test_same_parameter_different_method_location_creates_two_cases(self):
        cases = _builder().build(
            self._endpoint(
                [
                    {"name": "q", "method": "GET", "location": "query",
                     "source": "x8"},
                    {"name": "q", "method": "POST", "location": "body",
                     "source": "x8"},
                ]
            )
        )
        self.assertEqual(len(cases), 2)
        self.assertEqual(
            {(c.method, c.parameter_location) for c in cases},
            {("GET", "query"), ("POST", "body")},
        )

    def test_dedup_is_order_independent(self):
        forward = [
            {"name": "q", "method": "GET", "location": "query",
             "source": "x8"},
            {"name": "q", "method": "GET", "location": "query",
             "source": "crawl"},
            {"name": "r", "method": "POST", "location": "body",
             "source": "crawl"},
        ]
        reverse = list(reversed(forward))

        first = _builder().build(self._endpoint(forward))
        second = _builder().build(self._endpoint(reverse))

        self.assertEqual(len(first), 2)
        self.assertEqual(
            [(c.method, c.parameter_location, c.parameter) for c in first],
            [(c.method, c.parameter_location, c.parameter) for c in second],
        )

    def test_unsupported_location_record_creates_no_case(self):
        cases = _builder().build(
            self._endpoint(
                [
                    {"name": "hdr", "method": "GET", "location": "headers",
                     "source": "x8"},
                    {"name": "hv", "method": "GET", "location": "headervalue",
                     "source": "x8"},
                    {"name": "p", "method": "POST", "location": "path",
                     "source": "x8"},
                    {"name": "q", "method": "GET", "location": "unknown",
                     "source": "x8"},
                ]
            )
        )
        self.assertEqual(cases, [])

    def test_record_missing_method_or_location_is_not_defaulted(self):
        cases = _builder().build(
            self._endpoint(
                [
                    {"name": "nomethod", "location": "query",
                     "source": "x8"},
                    {"name": "nolocation", "method": "GET",
                     "source": "x8"},
                    {"name": "empty", "method": "", "location": "query",
                     "source": "x8"},
                    {"name": "q", "method": "GET", "location": "query",
                     "source": "x8"},
                ]
            )
        )
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].parameter, "q")

    def test_legacy_empty_param_records_falls_back_to_get_query(self):
        cases = _builder().build(
            _FakeEndpoint(
                params=["q", "redirect"],
                param_records=None,
            )
        )
        self.assertEqual(len(cases), 2)
        for case in cases:
            self.assertEqual(case.method, "GET")
            self.assertEqual(case.parameter_location, "query")
            self.assertIn("discovered_by:crawl",
                          "\n".join(case.discovery_evidence))

    def test_legacy_empty_list_param_records_also_falls_back(self):
        cases = _builder().build(
            _FakeEndpoint(
                params=["q"],
                param_records=[],
            )
        )
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].method, "GET")
        self.assertEqual(cases[0].parameter_location, "query")

    def test_case_id_differs_between_get_query_and_post_body(self):
        cases = _builder().build(
            self._endpoint(
                [
                    {"name": "q", "method": "GET", "location": "query",
                     "source": "x8"},
                    {"name": "q", "method": "POST", "location": "body",
                     "source": "x8"},
                ]
            )
        )
        self.assertEqual(len(cases), 2)
        self.assertNotEqual(cases[0].case_id, cases[1].case_id)

    def test_method_location_record_order_is_deterministic(self):
        records = [
            {"name": "b", "method": "POST", "location": "body",
             "source": "x8"},
            {"name": "a", "method": "GET", "location": "query",
             "source": "x8"},
            {"name": "a", "method": "POST", "location": "body",
             "source": "x8"},
        ]
        cases = _builder().build(self._endpoint(records))
        # Sorted by (method, location, name).
        self.assertEqual(
            [(c.method, c.parameter_location, c.parameter) for c in cases],
            [
                ("GET", "query", "a"),
                ("POST", "body", "a"),
                ("POST", "body", "b"),
            ],
        )

    def test_mixed_supported_and_unsupported_only_supported_become_cases(self):
        cases = _builder().build(
            self._endpoint(
                [
                    {"name": "q", "method": "GET", "location": "query",
                     "source": "crawl"},
                    {"name": "hdr", "method": "GET", "location": "headers",
                     "source": "x8"},
                    {"name": "r", "method": "PUT", "location": "body",
                     "source": "x8"},
                ]
            )
        )
        self.assertEqual(len(cases), 2)
        self.assertEqual(
            {(c.method, c.parameter_location) for c in cases},
            {("GET", "query"), ("PUT", "body")},
        )

    def test_record_evidence_contains_method_location_source(self):
        cases = _builder().build(
            self._endpoint(
                [{"name": "q", "method": "PUT", "location": "body",
                  "source": "x8"}]
            )
        )
        joined = "\n".join(cases[0].discovery_evidence)
        self.assertIn("method:PUT", joined)
        self.assertIn("parameter_location:body", joined)
        self.assertIn("discovered_by:x8", joined)


# =====================================================================
# Bounded pending cursor and module purity
# =====================================================================


class BuilderPendingAndPurityTests(unittest.TestCase):
    def test_build_pending_is_bounded_and_deterministic(self):
        endpoints = [
            _eligible_endpoint(params=["q", "redirect"]),
            _eligible_endpoint(params=["p"]),
            _eligible_endpoint(
                program_name="ghost", params=["x"]
            ),  # missing program -> filtered
        ]

        cases = _builder().build_pending(
            endpoints=endpoints, limit=2
        )
        self.assertEqual(len(cases), 2)

        all_cases = _builder().build_pending(
            endpoints=endpoints, limit=50
        )
        # ghost is missing its program: only acme cases remain.
        self.assertEqual(len(all_cases), 3)

        self.assertEqual(
            _builder().build_pending(endpoints=endpoints, limit=0),
            [],
        )

    def test_module_is_not_an_ai_runtime_component(self):
        # No LLM/network/browser/DB runtime imports at module
        # import time; the MongoDB helpers are lazy.
        for forbidden in (
            "HTTPEvidenceExecutor",
            "BrowserEvidenceExecutor",
            "XSSVerifier",
            "Endpoints",
            "Programs",
            "requests",
            "playwright",
            "openai",
        ):
            self.assertFalse(
                hasattr(builder_module, forbidden), forbidden
            )

    def test_default_builder_constructs_without_database(self):
        # Constructing the production default must not open a
        # MongoDB connection (lazy import); only invoking the
        # default lookups would.
        builder = XSSCaseBuilder()
        self.assertIsNotNone(builder)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()



