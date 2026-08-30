"""Focused unit tests for the Watch-layer XSS verification job
(``watch_xss_verify.run_job`` and its Mongo adapters).

The job is a run loop connecting already-tested components::

    Endpoints rows (faked)
        ↓ builder.build (real XSSCaseBuilder with fake program
          lookup, or a fake builder for pure loop tests)
    XSSCase objects
        ↓ pipeline.run (fake XSSVerificationPipeline)
    XSSVerificationResult
        ↓ persist (fake callable or fake XssFindings collection)

These tests prove ONLY the job-loop contract:

1. Eligible cases are executed and persisted.
2. Cases whose case_id is already verified are skipped before
   the pipeline runs.
3. ``--max-cases`` / ``max_cases`` stops after N newly verified
   cases, checked between cases.
4. ``--max-minutes`` stops when the time budget is exhausted,
   checked between cases (injectable deterministic clock).
5. One case failing (analysis/verification or persistence) is
   logged and later cases still run.
6. POST/body and PUT/body cases reach the pipeline unchanged —
   they are never downgraded to GET.
7. Finding persistence maps the case/result into one document
   and duplicate case_ids are a benign skip.
8. Log lines carry program, endpoint, method, parameter,
   location and case_id; credential values never appear.

No MongoDB, HTTP, browser, or LLM is touched anywhere: loop
collaborators are injected fakes, and the lazy ``database.db`` /
``mongoengine.errors`` imports are satisfied from fake modules
for the duration of each Mongo-adapter test.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
import types
import unittest
from unittest import mock

from ai.schemas.xss import XSSCase
from ai.schemas.xss_finding import XSSFinding
from ai.schemas.xss_verification import (
    XSSVerificationAudit,
    XSSVerificationResult,
)
from ai.verification import XSSCaseBuilder

import watch_xss_verify


# =====================================================================
# Fakes: pure in-process collaborators. No MongoDB, HTTP, browser
# or LLM is ever constructed.
# =====================================================================


class _EndpointRow:
    """Minimal Endpoints row: the loop only reads program_name
    for logging; eligibility is builder territory."""

    def __init__(self, program_name="acme"):
        self.program_name = program_name


class _FakeBuilder:
    """Fake XSSCaseBuilder: returns the same canned cases for
    every endpoint."""

    def __init__(self, cases=()):
        self.cases = list(cases)
        self.endpoints = []

    def build(self, endpoint):
        self.endpoints.append(endpoint)
        return list(self.cases)


class _FakePipeline:
    """Fake XSSVerificationPipeline: records the exact case
    objects it receives. Per-call outcomes may be scripted
    (results or exceptions); the default is an empty result."""

    def __init__(self, outcomes=None):
        self.cases = []
        self._outcomes = (
            list(outcomes) if outcomes is not None else None
        )

    def run(self, case):
        self.cases.append(case)
        if self._outcomes:
            outcome = self._outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        return _make_result(case.case_id)


class _FakePersist:
    """Fake persistence callable: records (case, result) pairs.
    Per-call outcomes may be scripted (True / False / exception);
    the default is True."""

    def __init__(self, outcomes=None):
        self.calls = []
        self._outcomes = (
            list(outcomes) if outcomes is not None else None
        )

    def __call__(self, case, result):
        self.calls.append((case, result))
        if self._outcomes:
            outcome = self._outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        return True


class _FakeClock:
    """Deterministic monotonic clock returning scripted values
    and sticking at the last one afterwards."""

    def __init__(self, times):
        self._times = list(times)
        self._last = self._times[-1] if self._times else 0.0

    def __call__(self):
        if self._times:
            self._last = self._times.pop(0)
        return self._last


# =====================================================================
# Fixtures: real schema objects (validation and serialization
# are part of the persistence contract).
# =====================================================================


def _make_case(
    case_id,
    *,
    method="GET",
    parameter="q",
    location="query",
):
    return XSSCase(
        case_id=case_id,
        target="app.example.com",
        endpoint="https://app.example.com/search",
        method=method,
        parameter=parameter,
        parameter_location=location,
        xss_type="reflected",
        discovery_evidence=[
            "program_name:acme",
            "endpoint_subdomain:app.example.com",
            "endpoint_path:/search",
            f"parameter:{parameter}",
            f"method:{method}",
            f"parameter_location:{location}",
            "discovered_by:x8",
        ],
    )


def _make_finding(
    case_id,
    *,
    finding_id="find-1",
    status="CONFIRMED",
    confidence=0.9,
    method="GET",
    parameter="q",
    location="query",
):
    return XSSFinding(
        finding_id=finding_id,
        case_id=case_id,
        target="app.example.com",
        endpoint="https://app.example.com/search",
        method=method,
        parameter=parameter,
        parameter_location=location,
        xss_type="reflected",
        context_type="html_attribute",
        status=status,
        confidence=confidence,
        payload_reference="<img src=x onerror=alert(1)>",
        verification_mode="http_reflection",
        attempt_id="att-1",
    )


def _make_result(case_id, findings=None):
    return XSSVerificationResult(
        case_id=case_id,
        attempts=[],
        evidence=[],
        findings=list(findings or []),
        audit=XSSVerificationAudit(),
    )


def _run_job(
    cases,
    *,
    outcomes=None,
    persist=None,
    already_verified=None,
    endpoints=None,
    clock=None,
    log_lines=None,
    **kwargs,
):
    """Drive run_job with injected fakes; return the summary and
    every collaborator the test may want to inspect."""

    builder = _FakeBuilder(cases)
    pipeline = _FakePipeline(outcomes)
    if persist is None:
        persist = _FakePersist()
    if already_verified is None:

        def already_verified(case_id):
            return False

    if endpoints is None:
        endpoints = [_EndpointRow()]
    if log_lines is None:
        log_lines = []

    summary = watch_xss_verify.run_job(
        builder=builder,
        pipeline=pipeline,
        endpoints=endpoints,
        already_verified=already_verified,
        persist=persist,
        clock=clock or time.monotonic,
        log_fn=log_lines.append,
        **kwargs,
    )
    return summary, builder, pipeline, persist, log_lines


# =====================================================================
# Real XSSCaseBuilder with the existing fake-program pattern
# (mirrors ai/test_xss_case_builder.py) for provenance-sensitive
# duplicate-prevention coverage.
# =====================================================================


class _FakeProgram:
    def __init__(self, program_name, scopes, ooscopes=None):
        self.program_name = program_name
        self.scopes = list(scopes or [])
        self.ooscopes = list(ooscopes or [])


class _BuilderEndpoint:
    """Fake Endpoints row shaped for the real XSSCaseBuilder."""

    def __init__(
        self,
        *,
        program_name="acme",
        subdomain="app.example.com",
        path="/search",
        example_url="https://app.example.com/search",
        params=None,
        param_records=None,
    ):
        self.program_name = program_name
        self.subdomain = subdomain
        self.path = path
        self.example_url = example_url
        self.params = list(params or [])
        self.params_from_crawl = []
        self.params_from_x8 = []
        self.x8_checked = True
        self.param_records = (
            list(param_records) if param_records is not None else None
        )


def _real_builder():
    program = _FakeProgram("acme", ["example.com"], [])

    def _lookup(name):
        return program if name == "acme" else None

    return XSSCaseBuilder(program_lookup=_lookup)


def _post_body_endpoint():
    return _BuilderEndpoint(
        params=["q"],
        param_records=[
            {
                "name": "q",
                "method": "POST",
                "location": "body",
                "source": "x8",
            }
        ],
    )


# =====================================================================
# Fake Mongo layer: satisfies the lazy ``database.db`` and
# ``mongoengine.errors`` imports without touching a database.
# =====================================================================


class _FakeNotUniqueError(Exception):
    """Fake mongoengine.errors.NotUniqueError."""


class _FakeQuery:
    """Fake QuerySet slice: objects(...).only("id").first()."""

    def __init__(self, first_result):
        self._first = first_result
        self.only_args = None

    def only(self, *fields):
        self.only_args = fields
        return self

    def first(self):
        return self._first


class _FakeXssFindings:
    """Fake XssFindings collection modelling the unique case_id
    index (a duplicate save raises NotUniqueError)."""

    saved = []
    saved_case_ids = set()
    first_result = None
    queries = []
    last_query = None

    @classmethod
    def reset(cls):
        cls.saved = []
        cls.saved_case_ids = set()
        cls.first_result = None
        cls.queries = []
        cls.last_query = None

    def __init__(self, **values):
        self.values = values

    @classmethod
    def objects(cls, **query):
        cls.last_query = query
        query_obj = _FakeQuery(cls.first_result)
        cls.queries.append(query_obj)
        return query_obj

    def save(self):
        case_id = (self.values or {}).get("case_id")
        if case_id in _FakeXssFindings.saved_case_ids:
            raise _FakeNotUniqueError(
                "E11000 duplicate key error dup key: case_id"
            )
        _FakeXssFindings.saved_case_ids.add(case_id)
        _FakeXssFindings.saved.append(self)


@contextlib.contextmanager
def _fake_database():
    """Satisfy watch_xss_verify's lazy ``database.db`` and
    ``mongoengine.errors`` imports with fake modules; the real
    database package is never imported."""

    db_module = types.ModuleType("database.db")
    db_module.XssFindings = _FakeXssFindings
    errors_module = types.ModuleType("mongoengine.errors")
    errors_module.NotUniqueError = _FakeNotUniqueError
    with mock.patch.dict(
        sys.modules,
        {
            "database.db": db_module,
            "mongoengine.errors": errors_module,
        },
    ):
        yield


# =====================================================================
# Run loop: execution and already-verified skipping
# =====================================================================


class RunJobExecutionTests(unittest.TestCase):
    def test_eligible_cases_run_and_persist(self):
        cases = [_make_case("case-a"), _make_case("case-b")]
        result_a = _make_result("case-a")
        result_b = _make_result("case-b")

        summary, _builder, pipeline, persist, lines = _run_job(
            cases, outcomes=[result_a, result_b]
        )

        self.assertEqual(summary["verified"], 2)
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["stopped"], "endpoints_exhausted")
        self.assertGreaterEqual(summary["elapsed_minutes"], 0.0)
        # The exact case objects reached the pipeline...
        self.assertIs(pipeline.cases[0], cases[0])
        self.assertIs(pipeline.cases[1], cases[1])
        # ...and the exact (case, result) pairs reached persistence.
        self.assertEqual(len(persist.calls), 2)
        self.assertIs(persist.calls[0][0], cases[0])
        self.assertIs(persist.calls[0][1], result_a)
        self.assertIs(persist.calls[1][0], cases[1])
        self.assertIs(persist.calls[1][1], result_b)
        self.assertEqual(
            len([line for line in lines if line.startswith("[case]")]),
            2,
        )

    def test_already_verified_case_is_skipped(self):
        cases = [_make_case("case-old"), _make_case("case-new")]
        seen = []

        def already_verified(case_id):
            seen.append(case_id)
            return case_id == "case-old"

        summary, _b, pipeline, persist, lines = _run_job(
            cases, already_verified=already_verified
        )

        self.assertEqual(summary["verified"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["failed"], 0)
        # The already-verified case never reached the pipeline
        # and was never persisted again.
        self.assertEqual(
            [c.case_id for c in pipeline.cases], ["case-new"]
        )
        self.assertEqual(len(persist.calls), 1)
        self.assertEqual(seen, ["case-old", "case-new"])
        joined = "\n".join(lines)
        self.assertIn("[skip]", joined)
        self.assertIn("reason=already_verified", joined)
        self.assertIn("case_id=case-old", joined)


# =====================================================================
# Run loop: bounds (checked BEFORE each case, clean stop)
# =====================================================================


class RunJobBoundsTests(unittest.TestCase):
    def test_max_cases_bound_stops_between_cases(self):
        cases = [_make_case(f"case-{i}") for i in range(5)]

        summary, _b, pipeline, persist, lines = _run_job(
            cases, max_cases=2
        )

        self.assertEqual(summary["verified"], 2)
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["stopped"], "max_cases")
        # Exactly the first two cases were attempted, then the
        # loop stopped cleanly between cases.
        self.assertEqual(len(pipeline.cases), 2)
        self.assertIs(pipeline.cases[0], cases[0])
        self.assertIs(pipeline.cases[1], cases[1])
        self.assertEqual(len(persist.calls), 2)
        self.assertIn("stopped=max_cases", "\n".join(lines))

    def test_max_cases_non_positive_falls_back_to_default(self):
        for value in (None, 0, -1):
            summary, _b, pipeline, _p, _l = _run_job(
                [_make_case("case-a")], max_cases=value
            )
            self.assertEqual(summary["verified"], 1, repr(value))
            self.assertEqual(
                summary["stopped"],
                "endpoints_exhausted",
                repr(value),
            )
            self.assertEqual(len(pipeline.cases), 1, repr(value))

    def test_max_minutes_bound_stops_between_cases(self):
        cases = [_make_case(f"case-{i}") for i in range(3)]
        # start=0, first bound check=0 (run case 1), second
        # bound check=700s (>= 10 min budget) -> clean stop.
        clock = _FakeClock([0.0, 0.0, 700.0])

        summary, _b, pipeline, _p, lines = _run_job(
            cases, max_minutes=10.0, clock=clock
        )

        self.assertEqual(summary["verified"], 1)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["stopped"], "max_minutes")
        self.assertEqual(len(pipeline.cases), 1)
        self.assertIs(pipeline.cases[0], cases[0])
        self.assertIn("stopped=max_minutes", "\n".join(lines))


# =====================================================================
# Run loop: failure isolation
# =====================================================================


class RunJobFailureIsolationTests(unittest.TestCase):
    def test_pipeline_failure_does_not_stop_later_cases(self):
        cases = [_make_case("case-a"), _make_case("case-b")]
        boom = RuntimeError("verification exploded")

        summary, _b, pipeline, persist, lines = _run_job(
            cases, outcomes=[boom]
        )

        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["verified"], 1)
        self.assertEqual(summary["stopped"], "endpoints_exhausted")
        # Both cases were attempted despite the first failure.
        self.assertEqual(len(pipeline.cases), 2)
        self.assertIs(pipeline.cases[1], cases[1])
        # The failed case was not persisted.
        self.assertEqual(len(persist.calls), 1)
        joined = "\n".join(lines)
        self.assertIn("[fail]", joined)
        self.assertIn("RuntimeError", joined)
        self.assertIn("case_id=case-a", joined)
        self.assertEqual(
            len([line for line in lines if line.startswith("[case]")]),
            1,
        )

    def test_persist_failure_does_not_stop_later_cases(self):
        cases = [_make_case("case-a"), _make_case("case-b")]
        persist = _FakePersist(outcomes=[RuntimeError("mongo down")])

        summary, _b, pipeline, persist, lines = _run_job(
            cases, persist=persist
        )

        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["verified"], 1)
        self.assertEqual(len(pipeline.cases), 2)
        self.assertEqual(len(persist.calls), 2)
        joined = "\n".join(lines)
        self.assertIn("stage=persist", joined)
        self.assertIn("case_id=case-a", joined)

    def test_persist_race_duplicate_is_skipped(self):
        persist = _FakePersist(outcomes=[False])

        summary, _b, _p, persist, lines = _run_job(
            [_make_case("case-a")], persist=persist
        )

        self.assertEqual(summary["verified"], 0)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["failed"], 0)
        self.assertIn("reason=persist_race", "\n".join(lines))


# =====================================================================
# Run loop: POST/PUT body provenance reaches the pipeline unchanged
# =====================================================================


class RunJobMethodPreservationTests(unittest.TestCase):
    def test_post_body_case_reaches_pipeline_unchanged(self):
        post_case = _make_case(
            "case-post", method="POST", location="body"
        )

        summary, _b, pipeline, _p, _l = _run_job([post_case])

        self.assertEqual(summary["verified"], 1)
        # Identity: no copy, no rebuild, no method rewrite.
        self.assertIs(pipeline.cases[0], post_case)
        self.assertEqual(pipeline.cases[0].method, "POST")
        self.assertEqual(
            pipeline.cases[0].parameter_location, "body"
        )

    def test_put_body_case_reaches_pipeline_unchanged(self):
        put_case = _make_case(
            "case-put", method="PUT", location="body"
        )

        summary, _b, pipeline, _p, _l = _run_job([put_case])

        self.assertEqual(summary["verified"], 1)
        self.assertIs(pipeline.cases[0], put_case)
        self.assertEqual(pipeline.cases[0].method, "PUT")
        self.assertEqual(
            pipeline.cases[0].parameter_location, "body"
        )

    def test_post_put_body_cases_are_not_downgraded_to_get(self):
        post_case = _make_case(
            "case-post", method="POST", location="body"
        )
        put_case = _make_case(
            "case-put", method="PUT", location="body"
        )

        summary, _b, pipeline, _p, lines = _run_job(
            [post_case, put_case]
        )

        self.assertEqual(summary["verified"], 2)
        self.assertEqual(
            [
                (c.method, c.parameter_location)
                for c in pipeline.cases
            ],
            [("POST", "body"), ("PUT", "body")],
        )
        joined = "\n".join(lines)
        self.assertIn("method=POST", joined)
        self.assertIn("method=PUT", joined)
        # The browser-executor POST/PUT limitation must never
        # downgrade a body case: GET never appears as a method.
        self.assertNotIn("method=GET", joined)


# =====================================================================
# Run loop: logging contract
# =====================================================================


class RunJobLoggingTests(unittest.TestCase):
    def test_case_logs_carry_full_identifiers(self):
        case = _make_case(
            "case-log", method="POST", parameter="q", location="body"
        )

        _s, _b, _p, _pe, lines = _run_job([case])

        case_lines = [
            line for line in lines if line.startswith("[case]")
        ]
        self.assertEqual(len(case_lines), 1)
        line = case_lines[0]
        self.assertIn("program=acme", line)
        self.assertIn(
            "endpoint=https://app.example.com/search", line
        )
        self.assertIn("method=POST", line)
        self.assertIn("parameter=q", line)
        self.assertIn("location=body", line)
        self.assertIn("case_id=case-log", line)

    def test_skip_logs_carry_identifiers_too(self):
        _s, _b, _p, _pe, lines = _run_job(
            [_make_case("case-old")],
            already_verified=lambda case_id: True,
        )

        skip_lines = [
            line for line in lines if line.startswith("[skip]")
        ]
        self.assertEqual(len(skip_lines), 1)
        line = skip_lines[0]
        for fragment in (
            "program=acme",
            "endpoint=https://app.example.com/search",
            "method=GET",
            "parameter=q",
            "location=query",
            "case_id=case-old",
        ):
            self.assertIn(fragment, line)

    def test_secrets_are_not_logged(self):
        secret = "sk-or-v1-SUPERSECRET0123456789abcdef"

        with mock.patch.dict(
            os.environ,
            {
                "OPENROUTER_API_KEY": secret,
                "AVALAI_API_KEY": secret,
            },
        ):
            summary, _b, _p, _pe, lines = _run_job(
                [_make_case("case-a")]
            )

        self.assertEqual(summary["verified"], 1)
        joined = "\n".join(lines)
        self.assertNotIn(secret, joined)
        self.assertNotIn("OPENROUTER_API_KEY", joined)
        self.assertNotIn("AVALAI_API_KEY", joined)


# =====================================================================
# Mongo adapters (fake database.db / mongoengine.errors modules)
# =====================================================================


class MongoAdapterTests(unittest.TestCase):
    def setUp(self):
        _FakeXssFindings.reset()

    def _post_body_case_and_result(self):
        case = _real_builder().build(_post_body_endpoint())[0]
        finding = _make_finding(
            case.case_id, status="CONFIRMED", confidence=0.9
        )
        return case, _make_result(case.case_id, findings=[finding])

    def test_mongo_persist_persists_finding_document(self):
        case, result = self._post_body_case_and_result()

        with _fake_database():
            persisted = watch_xss_verify.mongo_persist(case, result)

        self.assertTrue(persisted)
        self.assertEqual(len(_FakeXssFindings.saved), 1)
        values = _FakeXssFindings.saved[0].values
        self.assertEqual(values["case_id"], case.case_id)
        self.assertEqual(values["finding_id"], "find-1")
        self.assertEqual(values["finding_ids"], ["find-1"])
        self.assertEqual(values["program_name"], "acme")
        self.assertEqual(values["subdomain"], "app.example.com")
        self.assertEqual(values["path"], "/search")
        self.assertEqual(values["endpoint"], case.endpoint)
        self.assertEqual(values["method"], "POST")
        self.assertEqual(values["parameter"], "q")
        self.assertEqual(values["parameter_location"], "body")
        self.assertEqual(values["status"], "CONFIRMED")
        self.assertEqual(values["confidence"], 0.9)
        self.assertEqual(values["finding_count"], 1)
        self.assertEqual(values["runner"], "watch_xss_verify")
        # Full evidence payload is serialized for later reporting.
        self.assertEqual(
            values["findings"],
            [f.model_dump(mode="json") for f in result.findings],
        )
        self.assertEqual(
            values["verification_audit"],
            result.audit.model_dump(mode="json"),
        )
        self.assertIsInstance(values["discovery_evidence"], list)

    def test_mongo_persist_duplicate_case_id_returns_false(self):
        case, result = self._post_body_case_and_result()

        with _fake_database():
            self.assertTrue(
                watch_xss_verify.mongo_persist(case, result)
            )
            # The unique case_id index turns the repeated write
            # into a benign False, not an exception.
            self.assertFalse(
                watch_xss_verify.mongo_persist(case, result)
            )

        self.assertEqual(len(_FakeXssFindings.saved), 1)

    def test_mongo_already_verified_reflects_existing_case_id(self):
        with _fake_database():
            self.assertFalse(
                watch_xss_verify.mongo_already_verified("case-x")
            )
            _FakeXssFindings.first_result = object()
            self.assertTrue(
                watch_xss_verify.mongo_already_verified("case-x")
            )

        self.assertEqual(
            _FakeXssFindings.last_query, {"case_id": "case-x"}
        )

    def test_duplicate_case_id_never_persists_twice_in_run(self):
        # Real builder: two identical endpoints yield the same
        # deterministic case_id; the second write is a benign
        # skip and the loop reports it as such.
        endpoints = [_post_body_endpoint(), _post_body_endpoint()]
        lines = []

        with _fake_database():
            summary = watch_xss_verify.run_job(
                builder=_real_builder(),
                pipeline=_FakePipeline(),
                endpoints=endpoints,
                log_fn=lines.append,
            )

        self.assertEqual(summary["verified"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["failed"], 0)
        self.assertIn("reason=persist_race", "\n".join(lines))
        self.assertEqual(len(_FakeXssFindings.saved), 1)


# =====================================================================
# Document mapping (pure data helpers)
# =====================================================================


class FindingDocumentTests(unittest.TestCase):
    def test_case_status_precedence(self):
        inconclusive = _make_finding(
            "case-s",
            finding_id="find-i",
            status="INCONCLUSIVE",
            confidence=0.1,
        )
        potential = _make_finding(
            "case-s",
            finding_id="find-p",
            status="POTENTIAL",
            confidence=0.5,
        )
        confirmed = _make_finding(
            "case-s",
            finding_id="find-c",
            status="CONFIRMED",
            confidence=0.9,
        )
        self.assertEqual(
            watch_xss_verify.case_status([]), "INCONCLUSIVE"
        )
        self.assertEqual(
            watch_xss_verify.case_status([inconclusive]),
            "INCONCLUSIVE",
        )
        self.assertEqual(
            watch_xss_verify.case_status([inconclusive, potential]),
            "POTENTIAL",
        )
        self.assertEqual(
            watch_xss_verify.case_status([potential, confirmed]),
            "CONFIRMED",
        )

    def test_finding_document_values_mapping(self):
        case = _make_case("case-doc", method="POST", location="body")
        potential = _make_finding(
            "case-doc",
            finding_id="find-a",
            status="POTENTIAL",
            confidence=0.4,
            method="POST",
            location="body",
        )
        confirmed = _make_finding(
            "case-doc",
            finding_id="find-b",
            status="CONFIRMED",
            confidence=0.9,
            method="POST",
            location="body",
        )
        result = _make_result(
            "case-doc", findings=[potential, confirmed]
        )

        values = watch_xss_verify._finding_document_values(
            case, result
        )

        self.assertEqual(values["case_id"], "case-doc")
        # finding_id is the first serialized finding.
        self.assertEqual(values["finding_id"], "find-a")
        self.assertEqual(values["finding_ids"], ["find-a", "find-b"])
        self.assertEqual(values["status"], "CONFIRMED")
        self.assertEqual(values["confidence"], 0.9)
        self.assertEqual(values["finding_count"], 2)
        self.assertEqual(values["endpoint"], case.endpoint)
        self.assertEqual(values["method"], "POST")
        self.assertEqual(values["parameter"], "q")
        self.assertEqual(values["parameter_location"], "body")
        # Provenance extracted from the bounded discovery evidence.
        self.assertEqual(values["program_name"], "acme")
        self.assertEqual(values["subdomain"], "app.example.com")
        self.assertEqual(values["path"], "/search")
        self.assertEqual(values["runner"], "watch_xss_verify")
        self.assertEqual(
            values["findings"],
            [f.model_dump(mode="json") for f in result.findings],
        )
        self.assertEqual(
            values["verification_audit"],
            result.audit.model_dump(mode="json"),
        )

    def test_finding_document_values_bounds_findings(self):
        findings = [
            _make_finding(
                "case-bound",
                finding_id=f"find-{i}",
                status="INCONCLUSIVE",
                confidence=0.1,
            )
            for i in range(
                watch_xss_verify.FINDING_DOCUMENT_LIMIT + 5
            )
        ]
        result = _make_result("case-bound", findings=findings)

        values = watch_xss_verify._finding_document_values(
            _make_case("case-bound"), result
        )

        self.assertEqual(
            len(values["findings"]),
            watch_xss_verify.FINDING_DOCUMENT_LIMIT,
        )
        self.assertEqual(
            values["finding_count"],
            watch_xss_verify.FINDING_DOCUMENT_LIMIT,
        )
        self.assertEqual(
            len(values["finding_ids"]),
            watch_xss_verify.FINDING_DOCUMENT_LIMIT,
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
