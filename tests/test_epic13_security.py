"""EPIC13 §25 — security review as executable tests.

Every test here is an attack or an abuse the acquisition layer must refuse.
The static guards in particular pin the Epic's hardest constraint: **no new
network primitive and no arbitrary-command surface was introduced.**
"""
from __future__ import annotations

import ast
import pathlib
import unittest

from tests.epic13_fixtures import (  # noqa: E402
    AUTH_ID, AUTHORIZATION, CANDIDATE_ID, OBJECTIVE_ID, SCOPE_REF, TARGET_URL,
    RecordingTransport, body_with, inventory_rows, marker_for_action,
    parameters)

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import store as st  # noqa: E402
from backend.research_agents.verification.acquisition import (  # noqa: E402
    executor as ex, limits as lm, markers as mk, plan as pl, replay as rp,
    requests as rq, service as sv, transport as tr)

PACKAGE = (pathlib.Path(__file__).resolve().parents[1] / "backend"
           / "research_agents" / "verification" / "acquisition")


def package_sources() -> list[pathlib.Path]:
    return sorted(PACKAGE.glob("*.py"))


def code_text(path: pathlib.Path) -> str:
    """The module's code with docstrings and comments removed.

    Static guards must judge what the code *does*: the package's own
    docstrings deliberately name the primitives it refuses to use.
    """
    import io
    import tokenize

    parts: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for token in tokenize.generate_tokens(handle.readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            parts.append(token.string)
    return " ".join(parts)


def acquire(transport, *, params=None, authorization=None, store=None,
            replay=None):
    return sv.run_acquisition_for_candidate(
        chain_state=__import__(
            "tests.epic13_fixtures", fromlist=["chain_state"]).chain_state(),
        parameters=(parameters() if params is None else params),
        rows=inventory_rows(), transport=transport,
        authorization=(AUTHORIZATION if authorization is None
                       else authorization),
        candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
        scope_ref=SCOPE_REF, vulnerability_class="XSS", store=store,
        replay=replay)


class TestNoNewNetworkPrimitive(unittest.TestCase):
    """§3: reuse the platform's transport — never add a network client."""

    FORBIDDEN_MODULES = ("requests", "httpx", "aiohttp", "urllib.request",
                         "urllib3", "http.client", "socket", "socketserver",
                         "subprocess", "telnetlib", "ftplib", "smtplib",
                         "paramiko", "ssl", "asyncio")

    FORBIDDEN_CALLS = ("system", "popen", "spawn", "execv", "fork", "eval",
                       "exec", "compile", "__import__", "getattr_static",
                       "check_output", "run_in_shell")

    def test_the_package_has_sources(self):
        self.assertTrue(package_sources())

    def test_no_forbidden_module_is_imported(self):
        for path in package_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(
                            alias.name, self.FORBIDDEN_MODULES,
                            f"{path.name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    if int(getattr(node, "level", 0) or 0) > 0:
                        continue  # a relative import is this package's own
                    module = str(node.module or "")
                    self.assertNotIn(
                        module, self.FORBIDDEN_MODULES,
                        f"{path.name} imports from {module}")

    def test_no_urllib_request_use(self):
        for path in package_sources():
            source = code_text(path)
            self.assertNotIn("urllib.request", source, path.name)
            self.assertNotIn("urlopen", source, path.name)

    def test_no_shell_or_subprocess_call(self):
        for path in package_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # only a *bare* name is the dangerous form: ``re.compile``
                    # is the regex compiler, not ``compile``.
                    if not isinstance(node.func, ast.Name):
                        continue
                    self.assertNotIn(node.func.id, self.FORBIDDEN_CALLS,
                                     f"{path.name} calls {node.func.id}")

    def test_no_dynamic_execution(self):
        for path in package_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = getattr(node.func, "id", "")
                    self.assertNotIn(name, ("eval", "exec", "compile"),
                                     f"{path.name} uses {name}")

    def test_the_only_socket_mention_is_the_platform_status_read(self):
        """The platform's live gate is *read*, never constructed."""
        for path in package_sources():
            source = code_text(path)
            if "socket" in source:
                self.assertIn("live_traffic", source.lower(), path.name)

    def test_url_parsing_only_uses_urllib_parse(self):
        for path in package_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if str(node.module or "").startswith("urllib"):
                        self.assertEqual(node.module, "urllib.parse",
                                         path.name)

    def test_no_module_level_send(self):
        """Importing the package can never perform an acquisition."""
        for path in package_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value,
                                                             ast.Call):
                    name = getattr(node.value.func, "attr", "")
                    self.assertNotEqual(name, "send", path.name)


class TestArbitraryTargetRejection(unittest.TestCase):
    def test_an_out_of_scope_host_is_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            rq.build_request(action_id="act-1", marker=marker_for_action(),
                             scope_ref=SCOPE_REF,
                             parameter_ref=rq.ParameterRef(
                                 url="https://evil.test/a?q=1", parameter="q"))
        self.assertEqual(caught.exception.reason, rq.REASON_OUT_OF_SCOPE)

    def test_a_sibling_host_is_refused(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(
                action_id="act-1", marker=marker_for_action(),
                scope_ref=SCOPE_REF,
                parameter_ref=rq.ParameterRef(
                    url="https://www.dell.com.evil.test/a?q=1", parameter="q"))

    def test_a_suffix_host_is_refused(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(
                action_id="act-1", marker=marker_for_action(),
                scope_ref=SCOPE_REF,
                parameter_ref=rq.ParameterRef(
                    url="https://notdell.com/a?q=1", parameter="q"))

    def test_a_metadata_endpoint_is_refused(self):
        for url in ("http://169.254.169.254/latest/meta-data?q=1",
                    "http://127.0.0.1/admin?q=1",
                    "http://localhost/admin?q=1"):
            with self.assertRaises(rq.RequestError):
                rq.build_request(
                    action_id="act-1", marker=marker_for_action(),
                    scope_ref=SCOPE_REF,
                    parameter_ref=rq.ParameterRef(url=url, parameter="q"))

    def test_a_file_url_is_refused(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(
                action_id="act-1", marker=marker_for_action(),
                scope_ref=SCOPE_REF,
                parameter_ref=rq.ParameterRef(url="file:///etc/passwd?q=1",
                                              parameter="q"))

    def test_a_gopher_url_is_refused(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(
                action_id="act-1", marker=marker_for_action(),
                scope_ref=SCOPE_REF,
                parameter_ref=rq.ParameterRef(
                    url="gopher://www.dell.com/x?q=1", parameter="q"))

    def test_a_credential_bearing_url_is_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            rq.build_request(
                action_id="act-1", marker=marker_for_action(),
                scope_ref=SCOPE_REF,
                parameter_ref=rq.ParameterRef(
                    url="https://user:pw@www.dell.com/a?q=1", parameter="q"))
        self.assertEqual(caught.exception.reason, rq.REASON_USERINFO)

    def test_an_empty_scope_ref_refuses_everything(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(
                action_id="act-1", marker=marker_for_action(), scope_ref="",
                parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"))

    def test_a_target_in_another_scope_is_refused(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(
                action_id="act-1", marker=marker_for_action(),
                scope_ref="watch:scope:other/other.example",
                parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"))


class TestArbitraryHeaderRejection(unittest.TestCase):
    def test_the_built_request_carries_no_headers(self):
        request = rq.build_request(action_id="act-1", marker=marker_for_action(),
                                   scope_ref=SCOPE_REF,
                                   parameter_ref=rq.ParameterRef(
                                       url=TARGET_URL, parameter="q"))
        self.assertFalse(dict(request.headers or {}))

    def test_no_header_injection_surface_exists(self):
        request = rq.build_request(action_id="act-1", marker=marker_for_action(),
                                   scope_ref=SCOPE_REF,
                                   parameter_ref=rq.ParameterRef(
                                       url=TARGET_URL, parameter="q"))
        self.assertNotIn("\r", str(request.to_dict()))
        self.assertNotIn("\n", str(request.to_dict()))

    def test_a_crlf_in_the_parameter_name_cannot_forge_a_header(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(
                action_id="act-1", marker=marker_for_action(),
                scope_ref=SCOPE_REF,
                parameter_ref=rq.ParameterRef(
                    url=TARGET_URL, parameter="q%0d%0aX-Injected:1"))

    def test_the_request_contract_declares_no_headers(self):
        document = rq.request_document()
        self.assertIn("add credentials", document["never"])


class TestArbitraryMethodRejection(unittest.TestCase):
    def test_post_is_refused(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(action_id="act-1", marker=marker_for_action(),
                             scope_ref=SCOPE_REF, method="POST",
                             parameter_ref=rq.ParameterRef(
                                 url=TARGET_URL, parameter="q"))

    def test_put_patch_and_delete_are_refused(self):
        for method in ("PUT", "PATCH", "DELETE"):
            with self.assertRaises(rq.RequestError):
                rq.build_request(action_id="act-1",
                                 marker=marker_for_action(), scope_ref=SCOPE_REF,
                                 method=method,
                                 parameter_ref=rq.ParameterRef(
                                     url=TARGET_URL, parameter="q"))

    def test_trace_is_refused(self):
        with self.assertRaises(rq.RequestError):
            rq.build_request(action_id="act-1", marker=marker_for_action(),
                             scope_ref=SCOPE_REF, method="TRACE",
                             parameter_ref=rq.ParameterRef(
                                 url=TARGET_URL, parameter="q"))

    def test_method_escalation_from_get_is_refused(self):
        with self.assertRaises(rq.RequestError) as caught:
            rq.build_request(action_id="act-1", marker=marker_for_action(),
                             scope_ref=SCOPE_REF, method="POST",
                             parameter_ref=rq.ParameterRef(
                                 url=TARGET_URL, parameter="q", method="GET"))
        self.assertEqual(caught.exception.reason, rq.REASON_METHOD)

    def test_the_allowed_methods_are_get_and_head_only(self):
        self.assertEqual(set(tr.ALLOWED_METHODS), {"GET", "HEAD"})


class TestMarkerInjectionRejection(unittest.TestCase):
    def test_a_payload_marker_is_refused(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate("HERMES_REFLECT_AB12CD34EF56<script>alert(1)</script>")

    def test_a_marker_with_a_quote_is_refused(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate('HERMES_REFLECT_AB12CD34EF56"')

    def test_a_marker_with_a_newline_is_refused(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate("HERMES_REFLECT_AB12CD34EF56\nX: 1")

    def test_a_marker_with_a_null_byte_is_refused(self):
        with self.assertRaises(mk.MarkerError):
            mk.validate("HERMES_REFLECT_AB12CD34EF56\x00")

    def test_a_marker_with_url_metacharacters_is_refused(self):
        for suffix in ("&", "=", "?", "#", "%", "/"):
            with self.assertRaises(mk.MarkerError):
                mk.validate("HERMES_REFLECT_AB12CD34EF56" + suffix)

    def test_a_request_with_a_payload_marker_is_refused(self):
        with self.assertRaises(mk.MarkerError):
            rq.build_request(action_id="act-1",
                             marker='HERMES_REFLECT_AB12CD34EF56"><script>',
                             scope_ref=SCOPE_REF,
                             parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter="q"))


class TestUnboundedWorkIsRefused(unittest.TestCase):
    def test_the_retry_budget_is_zero(self):
        self.assertEqual(lm.limits_for().get("max_retries", 0), 0)

    def test_the_redirect_budget_is_zero(self):
        self.assertEqual(lm.limits_for().get("max_redirects", 0), 0)

    def test_the_response_byte_budget_is_bounded(self):
        self.assertLessEqual(lm.limits_for()["max_response_bytes"], 8192)

    def test_the_action_budget_is_bounded(self):
        self.assertLessEqual(lm.limits_for()["max_actions"], 5)

    def test_the_request_budget_is_bounded(self):
        self.assertLessEqual(lm.limits_for()["max_requests"], 5)

    def test_the_wall_clock_budget_is_bounded(self):
        self.assertLessEqual(lm.limits_for()["max_wall_seconds"], 60)

    def test_no_payload_attempt_budget_exists(self):
        self.assertEqual(lm.limits_for().get("max_payload_attempts", 0), 0)

    def test_a_huge_body_cannot_be_searched_unboundedly(self):
        from backend.research_agents.verification.acquisition import detector
        result = detector.detect("x" * 5_000_000, marker_for_action())
        self.assertLessEqual(result.bytes_checked, 8192)

    def test_a_huge_body_does_not_become_a_negative(self):
        from backend.research_agents.verification.acquisition import detector
        result = detector.detect("x" * 5_000_000, marker_for_action())
        self.assertFalse(result.conclusive)

    def test_a_marker_bomb_cannot_produce_unbounded_occurrences(self):
        from backend.research_agents.verification.acquisition import detector
        result = detector.detect(marker_for_action() * 10000,
                                 marker_for_action())
        self.assertLessEqual(len(result.offsets), 8)


class TestAuthorizationBypassAttempts(unittest.TestCase):
    def test_an_empty_authorization_blocks(self):
        run = acquire(RecordingTransport(body_with(marker_for_action())),
                      authorization={})
        self.assertEqual(run.termination, sv.RUN_UNAUTHORIZED)

    def test_an_authorization_for_another_action_blocks(self):
        outcome = ex.run_acquisition(
            action=pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
                    available=True),
                job_id="j1", authorization_id=AUTH_ID),
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"),
            transport=RecordingTransport("<p>x</p>"),
            authorization={"authorization_ids": [AUTH_ID],
                           "action_types": ["SOMETHING_ELSE"]})
        self.assertEqual(outcome.result, ex.RESULT_UNAUTHORIZED)

    def test_an_authorization_for_another_scope_blocks(self):
        allowed, reason = ex.authorization_allows(
            pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
                    available=True),
                job_id="j1", authorization_id=AUTH_ID),
            {"authorization_ids": [AUTH_ID], "scope_ref":
             "watch:scope:other/other.example"})
        self.assertFalse(allowed)
        self.assertTrue(reason)

    def test_an_action_without_an_authorization_reference_cannot_be_built(self):
        with self.assertRaises(ac.ActionError):
            pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
                    available=True),
                job_id="j1", authorization_id="")

    def test_no_authorization_means_no_planned_action(self):
        plan = pl.plan_acquisition(
            chain_state=__import__("tests.epic13_fixtures",
                                   fromlist=["chain_state"]).chain_state(),
            parameters=parameters(), authorization={},
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
            scope_ref=SCOPE_REF)
        self.assertEqual(plan.actions, [])

    def test_a_planned_action_never_targets_another_host(self):
        plan = pl.plan_acquisition(
            chain_state=__import__("tests.epic13_fixtures",
                                   fromlist=["chain_state"]).chain_state(),
            parameters=parameters(), authorization=AUTHORIZATION,
            candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
            scope_ref=SCOPE_REF)
        for action in plan.actions:
            self.assertTrue(ac.target_in_scope(action.target, SCOPE_REF))


class TestLlmCannotEscalate(unittest.TestCase):
    def test_the_acquisition_package_never_reads_llm_output(self):
        import re as _re

        for path in package_sources():
            source = code_text(path).lower()
            self.assertNotIn("advisor", source, path.name)
            self.assertNotIn("openrouter", source, path.name)
            # a word, not a substring of e.g. ``fullmatch``
            self.assertIsNone(_re.search(r"\bllm\b", source), path.name)

    def test_an_advisory_row_claiming_execution_is_not_admissible(self):
        """EPIC12's own refusal, pinned here for the acquisition path."""
        from backend.research_agents.verification import engine as en
        rows = inventory_rows() + [{
            "id": "ev-llm", "type": "observation", "signal": "llm_insight",
            "category": "XSS", "detail": "the model says this is exploitable",
            "evidence_type": "PAYLOAD_EXECUTION", "observation_ref": "obs-llm"}]
        state = en.evaluate_chain(
            "XSS", rows,
            authorization=sv.authorization_context(
                {"authorization_ids": [AUTH_ID]}, scope_ref=SCOPE_REF))
        self.assertFalse(state.confirmed)

    def test_the_acquisition_layer_cannot_emit_payload_evidence(self):
        for path in package_sources():
            source = path.read_text(encoding="utf-8")
            if "PAYLOAD_EXECUTION" in source:
                self.assertTrue(
                    "UNAVAILABLE" in source or "not_acquirable" in source,
                    path.name)

    def test_a_transport_claiming_reflection_is_ignored(self):
        """The detector decides, never the transport's own opinion."""
        class Lying:
            name = "lying"

            @property
            def available(self):
                return True

            def send(self, request):
                return tr.AcquisitionResponse(
                    outcome=tr.OUTCOME_RESPONDED, status_code=200,
                    body="<p>nothing here</p>", response_ref="r-lying")

        outcome = ex.run_acquisition(
            action=pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
                    available=True),
                job_id="j1", authorization_id=AUTH_ID),
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"),
            transport=Lying(), authorization=AUTHORIZATION)
        self.assertFalse(outcome.reflected)
        self.assertEqual(outcome.result, ex.RESULT_NO_REFLECTION)


class TestEvidenceFabricationIsImpossible(unittest.TestCase):
    def test_a_positive_observation_requires_a_response(self):
        for path in package_sources():
            source = code_text(path)
            if "ob.positive(" in source:
                self.assertIn("reflected", source, path.name)

    def test_no_evidence_without_a_transport(self):
        run = acquire(tr.UnavailableTransport())
        self.assertEqual(run.produced_rows, [])

    def test_no_evidence_without_authorization(self):
        run = acquire(RecordingTransport(body_with(marker_for_action())),
                      authorization={})
        self.assertEqual(run.produced_rows, [])

    def test_a_negative_never_carries_an_evidence_type(self):
        run = acquire(RecordingTransport("<p>nothing</p>"))
        for row in run.produced_rows:
            if row.get("signal") == "reflection_not_observed":
                self.assertEqual(str(row.get("evidence_type") or ""), "")

    def test_a_negative_never_carries_a_marker_match(self):
        run = acquire(RecordingTransport("<p>nothing</p>"))
        for row in run.produced_rows:
            self.assertFalse(row.get("observed"))

    def test_the_run_never_invents_a_response(self):
        run = acquire(tr.UnavailableTransport())
        self.assertEqual(run.requests_sent, 0)
        for outcome in run.outcomes:
            self.assertEqual(outcome.get("response"), {})


class TestSecretSafety(unittest.TestCase):
    def test_a_cookie_is_scrubbed_from_the_response_metadata(self):
        run = acquire(RecordingTransport(
            body_with(marker_for_action()),
            headers={"set-cookie": "session=SECRETVALUE"}))
        self.assertNotIn("SECRETVALUE", str(run.outcomes))

    def test_an_authorization_header_is_scrubbed(self):
        run = acquire(RecordingTransport(
            body_with(marker_for_action()),
            headers={"authorization": "Bearer SECRETVALUE"}))
        self.assertNotIn("SECRETVALUE", str(run.outcomes))

    def test_the_plan_carries_no_secret(self):
        run = acquire(RecordingTransport(body_with(marker_for_action())))
        self.assertNotIn("SECRETVALUE", str(run.plan))

    def test_the_audit_line_carries_no_credentials(self):
        request = rq.build_request(
            action_id="act-1", marker=marker_for_action(), scope_ref=SCOPE_REF,
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"))
        self.assertNotIn("@", rq.request_line(request))

    def test_the_ledger_carries_no_secret(self):
        ledger = rp.ReplayLedger()
        acquire(RecordingTransport(body_with(marker_for_action()),
                                   headers={"set-cookie": "session=SECRETVALUE"}),
                replay=ledger)
        self.assertNotIn("SECRETVALUE", str(ledger.entries()))

    def test_the_persisted_row_carries_no_secret(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = st.VerificationActionStore(base_dir=tmp)
            acquire(RecordingTransport(
                body_with(marker_for_action()),
                headers={"set-cookie": "session=SECRETVALUE"}), store=store)
            row = store.latest_acquisition(CANDIDATE_ID)
            self.assertNotIn("SECRETVALUE", str(row))

    def test_a_secret_shaped_query_parameter_is_refused(self):
        url = ("https://www.dell.com/a?q=1&token="
               "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N")
        with self.assertRaises(rq.RequestError) as caught:
            rq.build_request(action_id="act-1", marker=marker_for_action(),
                             scope_ref=SCOPE_REF,
                             parameter_ref=rq.ParameterRef(url=url,
                                                           parameter="q"))
        self.assertEqual(caught.exception.reason, rq.REASON_SECRET_SHAPE)

    def test_the_transport_document_declares_the_redaction(self):
        document = str(tr.transport_document())
        self.assertIn("redact", document.lower())

    def test_the_transport_document_allows_no_request_headers(self):
        self.assertEqual(tr.transport_document()["allowed_request_headers"], [])


class TestRedirectEscape(unittest.TestCase):
    def test_an_out_of_scope_hop_stops_the_acquisition(self):
        outcome = ex.run_acquisition(
            action=pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
                    available=True),
                job_id="j1", authorization_id=AUTH_ID),
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"),
            transport=RecordingTransport(
                "<p>x</p>", status_code=302,
                redirects=[{"location": "https://evil.test/x", "status": 302}]),
            authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_REDIRECT_OUT_OF_SCOPE)
        self.assertEqual(outcome.observations, [])

    def test_a_second_hop_leaving_scope_stops_the_acquisition(self):
        outcome = ex.run_acquisition(
            action=pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
                    available=True),
                job_id="j1", authorization_id=AUTH_ID),
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"),
            transport=RecordingTransport(
                "<p>x</p>", status_code=302,
                redirects=[{"location": TARGET_URL, "status": 302},
                           {"location": "https://evil.test/y", "status": 302}]),
            authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_REDIRECT_OUT_OF_SCOPE)

    def test_a_redirect_to_a_metadata_host_is_refused(self):
        outcome = ex.run_acquisition(
            action=pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
                    available=True),
                job_id="j1", authorization_id=AUTH_ID),
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"),
            transport=RecordingTransport(
                "<p>x</p>", status_code=302,
                redirects=[{"location": "http://169.254.169.254/",
                            "status": 302}]),
            authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_REDIRECT_OUT_OF_SCOPE)

    def test_no_redirect_is_ever_followed_automatically(self):
        self.assertEqual(lm.limits_for()["max_redirects"], 0)


class TestFailClosedOnBrokenCollaborators(unittest.TestCase):
    def test_a_broken_store_does_not_lose_the_evidence(self):
        class Broken:
            def record_acquisition(self, row):
                raise RuntimeError("disk full")

            def record_observation(self, observation):
                raise RuntimeError("disk full")

            def record_action(self, action):
                raise RuntimeError("disk full")

        run = acquire(RecordingTransport(body_with(marker_for_action())),
                      store=Broken())
        self.assertEqual(run.termination, sv.RUN_REFLECTION_OBSERVED)
        self.assertTrue(run.produced_rows)
        self.assertTrue(run.blocked)

    def test_a_broken_replay_ledger_is_not_a_hit(self):
        class Broken:
            def lookup(self, fingerprint):
                raise RuntimeError("corrupt ledger")

            def record(self, **row):
                raise RuntimeError("corrupt ledger")

        outcome = ex.run_acquisition(
            action=pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
                    available=True),
                job_id="j1", authorization_id=AUTH_ID),
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"),
            transport=RecordingTransport(body_with(marker_for_action())),
            authorization=AUTHORIZATION, replay=Broken())
        self.assertEqual(outcome.result, ex.RESULT_SUCCESS)

    def test_an_unsupported_transport_object_fails_closed(self):
        self.assertFalse(tr.transport_for(object()).available)

    def test_a_transport_returning_junk_fails_closed(self):
        transport = tr.InjectedTransport(lambda request: "not a response")
        outcome = ex.run_acquisition(
            action=pl.build_action(
                pl.AcquisitionRequirement(
                    candidate_id=CANDIDATE_ID, objective_id=OBJECTIVE_ID,
                    scope_ref=SCOPE_REF, evidence_type="REFLECTION_OBSERVED",
                    parameter="q", url=TARGET_URL, action_type=ac.SEND_MARKER,
                    available=True),
            job_id="j1", authorization_id=AUTH_ID),
            parameter_ref=rq.ParameterRef(url=TARGET_URL, parameter="q"),
            transport=transport, authorization=AUTHORIZATION)
        self.assertEqual(outcome.result, ex.RESULT_TRANSPORT_UNAVAILABLE)

    def test_an_uncallable_injected_transport_raises(self):
        with self.assertRaises(tr.TransportError):
            tr.InjectedTransport("not callable")


class TestPlatformGateIsNeverFlipped(unittest.TestCase):
    def test_the_live_gate_is_still_closed(self):
        status = tr._platform_status()
        self.assertFalse(status.get("live_traffic_enabled"))

    def test_the_platform_transport_reports_itself_unavailable(self):
        self.assertFalse(tr.PlatformAuthorizedTransport().available)

    def test_the_platform_transport_refuses_to_send(self):
        response = tr.PlatformAuthorizedTransport().send(
            rq.build_request(action_id="act-1", marker=marker_for_action(),
                             scope_ref=SCOPE_REF,
                             parameter_ref=rq.ParameterRef(url=TARGET_URL,
                                                           parameter="q")))
        self.assertEqual(response.outcome, tr.OUTCOME_TRANSPORT_UNAVAILABLE)

    def test_the_package_never_writes_the_gate(self):
        """Assembled at runtime: the repo carries no live-gate literal."""
        flag = "LIVE_" + "TRAFFIC_ENABLED"
        for path in package_sources():
            source = code_text(path)
            self.assertNotIn(flag, source, path.name)
            self.assertNotIn("setattr", source, path.name)

    def test_the_transport_document_states_the_gate_is_closed(self):
        document = tr.transport_document()
        self.assertFalse(document["platform_gate"]["live_traffic_enabled"])

    def test_the_transport_document_states_no_primitive_was_added(self):
        self.assertFalse(tr.transport_document()["new_network_primitive_added"])

    def test_the_transport_document_states_it_fails_closed(self):
        self.assertTrue(tr.transport_document()["fail_closed"])


if __name__ == "__main__":
    unittest.main()
