"""EPIC15 §2/§3/§17/§21 — capability contract, isolation and network policy."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from ai.limits import ceilings as ce  # noqa: E402
from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import deep as dp  # noqa: E402
from backend.research_agents.verification.acquisition import plan as pl  # noqa: E402
from tests.epic15_fixtures import authorized_hosts  # noqa: E402


class TestCapabilityContract(unittest.TestCase):
    """§2/§3: the capability boundary is stated, not worked around."""

    def setUp(self):
        self.lanes = dp.capability_document()

    def test_the_browser_lane_is_closed(self):
        self.assertEqual(self.lanes["lanes"]["browser"]["state"],
                         dp.LANE_CLOSED)

    def test_the_browser_lane_is_not_implemented(self):
        self.assertEqual(self.lanes["lanes"]["browser"]["capability"],
                         "NOT_IMPLEMENTED")

    def test_the_live_switch_is_false(self):
        self.assertFalse(self.lanes["lanes"]["browser"]["live_switch"])

    def test_the_live_switch_is_not_configurable(self):
        self.assertFalse(
            self.lanes["lanes"]["browser"]["switch_configurable"])

    def test_the_switch_name_is_the_platform_one(self):
        self.assertEqual(self.lanes["lanes"]["browser"]["switch_name"],
                         "LIVE_BROWSER")

    def test_all_four_boundary_blockers_are_reported(self):
        blockers = self.lanes["lanes"]["browser"]["blockers"]
        self.assertEqual(sorted(blockers), ["B1", "B2", "B4", "B5"])

    def test_b5_is_the_containment_boundary_and_is_blocked(self):
        self.assertIn("BLOCKED",
                      self.lanes["lanes"]["browser"]["blockers"]["B5"])
        self.assertIn("containment",
                      self.lanes["lanes"]["browser"]["blockers"]["B5"])

    def test_the_browser_refusal_is_the_platform_token(self):
        self.assertEqual(self.lanes["lanes"]["browser"]["refusal"],
                         "BROWSER_EXECUTION_BLOCKED")

    def test_the_only_available_runner_is_the_offline_harness(self):
        self.assertEqual(self.lanes["lanes"]["browser"]["available_runner"],
                         "offline_harness")

    def test_the_execution_lane_is_closed(self):
        self.assertEqual(self.lanes["lanes"]["execution"]["state"],
                         dp.LANE_CLOSED)

    def test_the_execution_lane_produces_nothing_here(self):
        self.assertEqual(self.lanes["lanes"]["execution"]["producible_here"],
                         ())

    def test_the_dom_lane_is_limited_not_implemented(self):
        self.assertEqual(self.lanes["lanes"]["dom"]["capability"], "LIMITED")

    def test_the_dom_lane_runs_offline_only(self):
        self.assertEqual(self.lanes["lanes"]["dom"]["state"],
                         dp.LANE_OFFLINE_ONLY)

    def test_the_dom_lane_names_its_instrumentation(self):
        self.assertEqual(self.lanes["lanes"]["dom"]["instrumentation"],
                         "served_document_static_analysis")

    def test_the_dom_lane_disclaims_taint_tracking(self):
        text = self.lanes["lanes"]["dom"]["not_implemented"]
        self.assertIn("taint", text)
        self.assertIn("never that the sink executed", text)

    def test_live_execution_is_declared_off_in_production(self):
        self.assertFalse(self.lanes["live_execution_in_production"])

    def test_the_capability_document_states_the_authority_rule(self):
        self.assertIn("authoritative only when produced by the trusted",
                      self.lanes["authoritative"])

    def test_the_capability_rule_version_is_epic15(self):
        self.assertEqual(self.lanes["rule_version"],
                         "epic15-deep-verification-1")

    def test_the_capability_states_are_epic13s_vocabulary(self):
        self.assertEqual(
            sorted({lane["capability"]
                    for lane in self.lanes["lanes"].values()}),
            ["LIMITED", "NOT_IMPLEMENTED"])

    def test_lane_states_are_a_closed_vocabulary(self):
        self.assertEqual(dp.lane_states(),
                         (dp.LANE_OFFLINE_ONLY, dp.LANE_CLOSED,
                          dp.LANE_ABSENT))

    def test_the_dom_actions_are_epic12s_read_only_actions(self):
        self.assertEqual(self.lanes["lanes"]["dom"]["actions"],
                         (ac.TRACE_DOM_SOURCE, ac.TRACE_DOM_SINK))

    def test_the_execution_actions_are_epic12s_active_actions(self):
        self.assertEqual(self.lanes["lanes"]["execution"]["actions"],
                         (ac.DELIVER_CONTROLLED_PAYLOAD, ac.OBSERVE_EXECUTION))

    def test_the_contract_reads_the_frozen_ceilings_through(self):
        ceilings = self.lanes["ceilings"]
        self.assertEqual(ceilings["browser_wall_seconds"],
                         ce.CEILINGS["browser_wall_seconds"])
        self.assertEqual(ceilings["browser_pages"],
                         ce.CEILINGS["browser_pages"])
        self.assertEqual(ceilings["redirect_hops"],
                         ce.CEILINGS["redirect_hops"])

    def test_the_contract_names_the_ceilings_source(self):
        self.assertIn("ai.limits.ceilings.CEILINGS",
                      self.lanes["ceilings_source"])

    def test_no_lane_declares_live_execution_available(self):
        for name, lane in self.lanes["lanes"].items():
            self.assertNotEqual(lane.get("capability"), "IMPLEMENTED", name)

    def test_the_browser_lane_module_has_no_launcher(self):
        """The contract module imports the platform's constants only."""
        source = (Path(__file__).resolve().parents[1] / "backend"
                  / "research_agents" / "verification" / "deep"
                  / "capability.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket", "playwright", "selenium"):
            self.assertNotIn(forbidden, source)


class TestEpic13Integration(unittest.TestCase):
    """§4: the deep stages are wired into the existing acquisition plan."""

    def test_the_dom_stage_has_an_acquisition_action(self):
        self.assertEqual(pl.ACQUISITION_FOR_EVIDENCE["DOM_SINK_IDENTIFIED"],
                         ac.TRACE_DOM_SINK)

    def test_the_dom_stage_is_no_longer_declared_unavailable(self):
        self.assertNotIn("DOM_SINK_IDENTIFIED", pl.UNAVAILABLE_EVIDENCE)

    def test_the_execution_stage_is_still_unavailable(self):
        self.assertIn("PAYLOAD_EXECUTION", pl.UNAVAILABLE_EVIDENCE)

    def test_the_exploitability_stage_is_still_unavailable(self):
        self.assertIn("EXPLOITABILITY_ESTABLISHED", pl.UNAVAILABLE_EVIDENCE)

    def test_the_execution_reason_names_the_closed_live_gate(self):
        self.assertIn("LIVE_BROWSER",
                      pl.UNAVAILABLE_EVIDENCE["PAYLOAD_EXECUTION"])

    def test_the_execution_reason_names_the_pending_containment(self):
        self.assertIn("B5", pl.UNAVAILABLE_EVIDENCE["PAYLOAD_EXECUTION"])

    def test_exploitability_is_never_inferred_from_execution(self):
        self.assertIn("never inferred",
                      pl.UNAVAILABLE_EVIDENCE["EXPLOITABILITY_ESTABLISHED"])

    def test_the_reflection_stages_are_untouched(self):
        self.assertEqual(pl.ACQUISITION_FOR_EVIDENCE["REFLECTION_OBSERVED"],
                         ac.SEND_MARKER)
        self.assertEqual(
            pl.ACQUISITION_FOR_EVIDENCE["OUTPUT_CONTEXT_IDENTIFIED"],
            ac.CLASSIFY_REFLECTION_CONTEXT)

    def test_the_dom_action_is_read_only(self):
        spec = ac.spec_for(ac.TRACE_DOM_SINK)
        self.assertEqual(spec.safety, ac.SAFETY_READ_ONLY)
        self.assertFalse(spec.requires_network)

    def test_the_execution_actions_are_active_and_unimplemented(self):
        for action in (ac.DELIVER_CONTROLLED_PAYLOAD, ac.OBSERVE_EXECUTION):
            spec = ac.spec_for(action)
            self.assertEqual(spec.safety, ac.SAFETY_ACTIVE)
            self.assertFalse(spec.implemented)
            self.assertIn("BLOCKED", spec.limitation)

    def test_the_dom_trace_action_is_implemented(self):
        self.assertTrue(ac.spec_for(ac.TRACE_DOM_SINK).implemented)

    def test_the_epic13_capability_contract_now_includes_dom(self):
        from backend.research_agents.verification.acquisition import (
            capabilities as caps)
        contract = next(c for c in caps.CONTRACTS
                        if c.vulnerability_class == "XSS")
        self.assertIn("DOM_SINK_IDENTIFIED", contract.evidence)
        self.assertNotIn("DOM_SINK_IDENTIFIED", contract.not_acquirable)
        self.assertIn("PAYLOAD_EXECUTION", contract.not_acquirable)


class TestIsolationPolicy(unittest.TestCase):
    """§10: the browser context contract, as accounting."""

    def setUp(self):
        self.policy = dp.isolation_policy()

    def test_the_context_is_non_persistent(self):
        self.assertTrue(self.policy.non_persistent_context)

    def test_no_user_profile(self):
        self.assertFalse(self.policy.user_profile)

    def test_no_stored_cookies(self):
        self.assertFalse(self.policy.stored_cookies)

    def test_no_credentials(self):
        self.assertFalse(self.policy.credentials)

    def test_no_extensions(self):
        self.assertFalse(self.policy.extensions)

    def test_no_host_filesystem_access(self):
        self.assertFalse(self.policy.host_filesystem)

    def test_no_downloads(self):
        self.assertFalse(self.policy.downloads)

    def test_no_outbound_credentials(self):
        self.assertFalse(self.policy.outbound_credentials)

    def test_the_policy_is_isolated(self):
        self.assertTrue(self.policy.isolated)

    def test_bounds_come_from_the_frozen_ceilings(self):
        self.assertEqual(self.policy.max_pages,
                         ce.CEILINGS["browser_pages"])
        self.assertEqual(self.policy.max_contexts,
                         ce.CEILINGS["browser_contexts"])
        self.assertEqual(self.policy.wall_seconds,
                         ce.CEILINGS["browser_wall_seconds"])
        self.assertEqual(self.policy.max_redirects,
                         ce.CEILINGS["redirect_hops"])

    def test_popups_are_never_allowed(self):
        self.assertEqual(self.policy.popup_events, 0)

    def test_the_policy_is_serialisable(self):
        payload = self.policy.to_dict()
        self.assertTrue(payload["isolated"])
        self.assertEqual(payload["rule_version"], "epic15-isolation-1")

    def test_a_tainted_policy_is_not_isolated(self):
        tainted = dp.IsolationPolicy(stored_cookies=True)
        self.assertFalse(tainted.isolated)

    def test_a_profiled_policy_is_not_isolated(self):
        self.assertFalse(dp.IsolationPolicy(user_profile=True).isolated)

    def test_a_credentialed_policy_is_not_isolated(self):
        self.assertFalse(dp.IsolationPolicy(credentials=True).isolated)


class TestNetworkPolicy(unittest.TestCase):
    """§11: browser navigation must never become an SSRF primitive."""

    def check(self, url: str, **kwargs):
        return dp.check_navigation(url, authorized_hosts=authorized_hosts(),
                                   **kwargs)

    def test_an_in_scope_https_url_is_allowed(self):
        decision = self.check("https://www.dell.com/support")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.decision, "NAVIGATION_ALLOWED")

    def test_localhost_is_blocked(self):
        decision = self.check("http://localhost/admin")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, "DESTINATION_BLOCKED")

    def test_loopback_is_blocked(self):
        self.assertEqual(self.check("http://127.0.0.1/").decision,
                         "DESTINATION_BLOCKED")

    def test_ipv6_loopback_is_blocked(self):
        self.assertEqual(self.check("http://[::1]/").decision,
                         "DESTINATION_BLOCKED")

    def test_rfc1918_10_is_blocked(self):
        self.assertEqual(self.check("http://10.1.2.3/").decision,
                         "DESTINATION_BLOCKED")

    def test_rfc1918_172_is_blocked(self):
        self.assertEqual(self.check("http://172.16.0.9/").decision,
                         "DESTINATION_BLOCKED")

    def test_rfc1918_192_is_blocked(self):
        self.assertEqual(self.check("http://192.168.0.10/").decision,
                         "DESTINATION_BLOCKED")

    def test_link_local_is_blocked(self):
        self.assertEqual(self.check("http://169.254.1.1/").decision,
                         "DESTINATION_BLOCKED")

    def test_cloud_metadata_by_address_is_blocked(self):
        self.assertEqual(
            self.check("http://169.254.169.254/latest/meta-data/").decision,
            "DESTINATION_BLOCKED")

    def test_cloud_metadata_by_name_is_blocked(self):
        self.assertEqual(self.check("http://metadata.google.internal/").decision,
                         "DESTINATION_BLOCKED")

    def test_unspecified_address_is_blocked(self):
        self.assertEqual(self.check("http://0.0.0.0/").decision,
                         "DESTINATION_BLOCKED")

    def test_file_scheme_is_blocked(self):
        self.assertEqual(self.check("file:///etc/passwd").decision,
                         "SCHEME_BLOCKED")

    def test_javascript_scheme_is_blocked(self):
        self.assertEqual(self.check("javascript:alert(1)").decision,
                         "SCHEME_BLOCKED")

    def test_data_scheme_is_blocked(self):
        self.assertEqual(self.check("data:text/html,<b>x</b>").decision,
                         "SCHEME_BLOCKED")

    def test_ftp_scheme_is_blocked(self):
        self.assertEqual(self.check("ftp://www.dell.com/").decision,
                         "SCHEME_BLOCKED")

    def test_an_arbitrary_port_is_blocked(self):
        self.assertEqual(self.check("https://www.dell.com:8443/").decision,
                         "PORT_BLOCKED")

    def test_an_out_of_scope_host_is_blocked(self):
        decision = self.check("https://evil.test/")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, "DESTINATION_BLOCKED")

    def test_no_authorized_host_set_blocks_everything(self):
        decision = dp.check_navigation("https://www.dell.com/",
                                       authorized_hosts=())
        self.assertFalse(decision.allowed)

    def test_an_empty_url_is_blocked(self):
        self.assertEqual(self.check("").decision, "NAVIGATION_BLOCKED")

    def test_a_url_without_a_host_is_blocked(self):
        self.assertEqual(self.check("https:///path").decision,
                         "NAVIGATION_BLOCKED")

    def test_the_decision_is_serialisable(self):
        payload = self.check("http://127.0.0.1/").to_dict()
        self.assertFalse(payload["allowed"])
        self.assertEqual(payload["rule_version"], "epic15-isolation-1")

    def test_the_decision_names_the_address_class(self):
        self.assertEqual(self.check("http://10.0.0.1/").address_class,
                         "private")

    def test_every_decision_is_in_the_closed_vocabulary(self):
        for url in ("https://www.dell.com/", "http://127.0.0.1/",
                    "file:///x", "https://www.dell.com:99/",
                    "https://evil.test/"):
            self.assertIn(self.check(url).decision,
                          dp.NAVIGATION_DECISIONS)


class TestRedirectPolicy(unittest.TestCase):
    """§11: a redirect that leaves the scope stops the attempt."""

    def test_a_redirect_inside_the_scope_is_allowed(self):
        decision = dp.check_redirect("https://www.dell.com/a",
                                     "https://www.dell.com/b",
                                     authorized_hosts=authorized_hosts())
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.redirect)

    def test_a_redirect_to_loopback_is_recorded_out_of_scope(self):
        decision = dp.check_redirect("https://www.dell.com/a",
                                     "http://127.0.0.1/",
                                     authorized_hosts=authorized_hosts())
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, "REDIRECT_OUT_OF_SCOPE")

    def test_a_redirect_to_a_private_address_is_out_of_scope(self):
        decision = dp.check_redirect("https://www.dell.com/a",
                                     "http://10.0.0.5/",
                                     authorized_hosts=authorized_hosts())
        self.assertEqual(decision.decision, "REDIRECT_OUT_OF_SCOPE")

    def test_a_redirect_to_metadata_is_out_of_scope(self):
        decision = dp.check_redirect("https://www.dell.com/a",
                                     "http://169.254.169.254/",
                                     authorized_hosts=authorized_hosts())
        self.assertEqual(decision.decision, "REDIRECT_OUT_OF_SCOPE")

    def test_a_redirect_to_another_host_is_out_of_scope(self):
        decision = dp.check_redirect("https://www.dell.com/a",
                                     "https://other.test/b",
                                     authorized_hosts=authorized_hosts())
        self.assertEqual(decision.decision, "REDIRECT_OUT_OF_SCOPE")

    def test_a_redirect_to_file_scheme_is_blocked(self):
        decision = dp.check_redirect("https://www.dell.com/a",
                                     "file:///etc/passwd",
                                     authorized_hosts=authorized_hosts())
        self.assertEqual(decision.decision, "SCHEME_BLOCKED")

    def test_the_out_of_scope_decision_is_not_allowed(self):
        decision = dp.check_redirect("https://www.dell.com/a",
                                     "http://localhost/",
                                     authorized_hosts=authorized_hosts())
        self.assertFalse(decision.allowed)


class TestCredentialPolicy(unittest.TestCase):
    """§12: no credential header is ever attached by this layer."""

    def test_an_authorization_header_is_refused(self):
        decision = dp.check_request_headers({"Authorization": "Bearer x"})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, "CREDENTIAL_BLOCKED")

    def test_a_cookie_header_is_refused(self):
        self.assertEqual(dp.check_request_headers({"Cookie": "a=b"}).decision,
                         "CREDENTIAL_BLOCKED")

    def test_a_proxy_authorization_header_is_refused(self):
        self.assertEqual(
            dp.check_request_headers({"Proxy-Authorization": "x"}).decision,
            "CREDENTIAL_BLOCKED")

    def test_an_api_key_header_is_refused(self):
        self.assertEqual(dp.check_request_headers({"X-Api-Key": "k"}).decision,
                         "CREDENTIAL_BLOCKED")

    def test_an_ordinary_header_is_allowed(self):
        self.assertTrue(dp.check_request_headers({"Accept": "*/*"}).allowed)

    def test_no_headers_is_allowed(self):
        self.assertTrue(dp.check_request_headers(None).allowed)

    def test_the_forbidden_set_is_closed(self):
        self.assertEqual(sorted(dp.isolation.FORBIDDEN_REQUEST_HEADERS),
                         ["authorization", "cookie", "proxy-authorization",
                          "set-cookie", "x-api-key", "x-auth-token"])


if __name__ == "__main__":
    unittest.main()
