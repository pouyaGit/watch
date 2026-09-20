"""Focused tests for the controlled watchlist evidence acquisition workflow.

No MongoDB, no VPS, no production, no real network: every acquisition test
injects a deterministic fake transport and a fake resolver. The test suite
performs zero socket activity (the default httpx-backed send is patched to
fail loudly if it is ever reached).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from ai.research_agent.transport import TransportResult
from ai.research_agent.watchlist_evidence_acquire import (
    APPLICATION_RESPONSE,
    HTTP_GET,
    HTTP_HEAD,
    NEXT_ACTION,
    REDIRECT_NONE,
    REDIRECT_SAME_HOST,
    STATE_ACQUIRED,
    STATE_BLOCKED,
    STATE_EMPTY,
    STATE_FAILED,
    STATE_OUT_OF_SCOPE,
    AcquisitionRequest,
    acquire_evidence,
    reevaluate_candidate_with_evidence,
)
from ai.research_agent.watchlist_evidence_gaps import (
    COMPONENT_IDENTITY,
    MISSING,
    analyze_candidate,
)

PUBLIC_IP = "93.184.216.34"
TARGET = "https://dell.example.com/"


def public_resolver(host):
    return [PUBLIC_IP]


_DEFAULT_RESULT = object()


def make_send(result=_DEFAULT_RESULT, *, status=200, headers=None, body=b"",
              url=TARGET):
    calls = []

    def send(method, target, req_headers, timeout, params):
        calls.append(
            {
                "method": method,
                "url": target,
                "headers": dict(req_headers or {}),
                "timeout": timeout,
                "params": params,
            }
        )
        if callable(result):
            return result(method, target, len(calls))
        if result is not _DEFAULT_RESULT:
            return result
        return TransportResult(
            status=status,
            headers=dict(headers or {}),
            body=body,
            final_url=target,
            url=target,
        )

    send.calls = calls
    return send


def request(**overrides):
    values = {
        "program": "dell",
        "target": TARGET,
        "evidence_type": APPLICATION_RESPONSE,
        "method": HTTP_HEAD,
        "scope_allowed_hosts": ("dell.example.com",),
    }
    values.update(overrides)
    return AcquisitionRequest(**values)


def dell_shaped_entry():
    return {
        "cve_id": "CVE-2026-1557",
        "program": "dell",
        "match_state": "WEAK",
        "confidence": "MEDIUM",
        "strongest_match_type": "TECHNOLOGY",
        "strongest_confidence": "MEDIUM",
        "matched_component": "",
        "matched_version": "",
        "matched_parameter": "src",
        "match_summary": (
            "Technology match exists, but affected component is not observed."
        ),
        "research_status": "NOT YET SUFFICIENT",
        "version_state": "UNKNOWN",
        "version_association_state": "FAMILY_MISMATCH",
        "version_association_reason": "observed version family mismatch",
        "resolved_blockers": [],
        "remaining_blockers": ["generic_technology_only"],
        "missing": ["PRODUCT", "COMPONENT", "PLUGIN", "VERSION", "PATH"],
        "match_row_count": 1,
        "match_rows": [
            {
                "match_id": "am-" + "2" * 16,
                "match_type": "TECHNOLOGY",
                "matched_value": "WordPress",
                "confidence": "MEDIUM",
            }
        ],
        "queue": {
            "present": True,
            "queue_id": "rq-" + "a" * 16,
            "relevance": "LOW",
            "relevance_score": 20,
            "priority_class": "CRITICAL_RESEARCH",
            "priority_score": 80,
            "queue_score": 56,
            "blockers": ["only generic technology match"],
            "reasons": ["critical research priority"],
            "unknown_factors": ["asset component/path not observed"],
        },
    }


class TestRequestValidation(unittest.TestCase):
    def test_01_valid_scoped_acquisition(self):
        send = make_send(
            status=200,
            headers={
                "Content-Type": "text/html",
                "Content-Length": "1234",
                "Server": "nginx",
            },
        )
        result = acquire_evidence(
            request(target="https://dell.example.com/?token=topsecret"),
            send=send,
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_ACQUIRED)
        self.assertEqual(result["evidence_count"], 1)
        record = result["evidence"][0]
        self.assertTrue(record["evidence_id"].startswith("wev-"))
        self.assertEqual(record["evidence_type"], APPLICATION_RESPONSE)
        self.assertEqual(record["source"], APPLICATION_RESPONSE)
        self.assertEqual(record["method"], HTTP_HEAD)
        self.assertEqual(record["confidence_state"], "LOW")
        self.assertEqual(record["identity_claims"], [])
        self.assertIsNone(record["artifact_reference"])
        self.assertGreaterEqual(len(record["observations"]), 3)
        self.assertTrue(send.calls[0]["headers"]["User-Agent"].startswith("Watch"))
        blob = json.dumps(result, sort_keys=True)
        self.assertNotIn("topsecret", blob)
        self.assertTrue(record["target"]["query_present"])

    def test_02_missing_target_rejected(self):
        result = acquire_evidence(
            request(target="  "), send=make_send(), resolver=public_resolver
        )
        self.assertEqual(result["state"], STATE_BLOCKED)
        self.assertEqual(result["evidence"], [])
        codes = {error["code"] for error in result["errors"]}
        self.assertIn("MISSING_TARGET", codes)

    def test_03_missing_evidence_type_rejected(self):
        result = acquire_evidence(
            request(evidence_type=""),
            send=make_send(),
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_BLOCKED)
        codes = {error["code"] for error in result["errors"]}
        self.assertIn("MISSING_EVIDENCE_TYPE", codes)

    def test_04_unsupported_method_rejected(self):
        result = acquire_evidence(
            request(method="TCP_CONNECT"),
            send=make_send(),
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_BLOCKED)
        codes = {error["code"] for error in result["errors"]}
        self.assertIn("UNSUPPORTED_METHOD", codes)

    def test_05_out_of_scope_target_rejected(self):
        result = acquire_evidence(
            request(target="https://other.example.com/"),
            send=make_send(),
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_OUT_OF_SCOPE)
        self.assertEqual(result["evidence"], [])
        codes = {error["code"] for error in result["errors"]}
        self.assertIn("OUT_OF_SCOPE_HOST", codes)

        private = acquire_evidence(
            request(target="http://127.0.0.1/", scope_allowed_hosts=("127.0.0.1",)),
            send=make_send(),
            resolver=public_resolver,
        )
        self.assertEqual(private["state"], STATE_OUT_OF_SCOPE)
        codes = {error["code"] for error in private["errors"]}
        self.assertIn("PRIVATE_OR_RESERVED", codes)

        no_scope = acquire_evidence(
            request(scope_allowed_hosts=()),
            send=make_send(),
            resolver=public_resolver,
        )
        self.assertEqual(no_scope["state"], STATE_BLOCKED)
        codes = {error["code"] for error in no_scope["errors"]}
        self.assertIn("MISSING_SCOPE", codes)


class TestBoundedCollector(unittest.TestCase):
    def test_06_request_budget_enforced(self):
        def redirect_then_ok(method, target, call_index):
            return TransportResult(
                status=302,
                headers={"Location": "/next"},
                body=b"",
                final_url=target,
                url=target,
            )

        send = make_send(redirect_then_ok)
        result = acquire_evidence(
            request(
                method=HTTP_GET,
                max_requests=1,
                redirect_policy=REDIRECT_SAME_HOST,
            ),
            send=send,
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_BLOCKED)
        self.assertEqual(result["blocked_reason"], "REQUEST_BUDGET")
        self.assertEqual(len(send.calls), 1)

        over_budget = acquire_evidence(
            request(max_requests=99), send=make_send(), resolver=public_resolver
        )
        self.assertEqual(over_budget["state"], STATE_BLOCKED)
        codes = {error["code"] for error in over_budget["errors"]}
        self.assertIn("INVALID_MAX_REQUESTS", codes)

        bad_timeout = acquire_evidence(
            request(timeout=999), send=make_send(), resolver=public_resolver
        )
        codes = {error["code"] for error in bad_timeout["errors"]}
        self.assertIn("INVALID_TIMEOUT", codes)

    def test_07_response_size_limit(self):
        body = b"A" * 200
        result = acquire_evidence(
            request(method=HTTP_GET, max_bytes=64),
            send=make_send(
                status=200, headers={"Content-Type": "text/plain"}, body=body
            ),
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_ACQUIRED)
        meta = result["response_metadata"]
        self.assertEqual(meta["body_bytes"], 64)
        self.assertTrue(meta["body_truncated"])
        self.assertEqual(
            meta["body_sha256"], hashlib.sha256(body[:64]).hexdigest()
        )
        observations = {
            item["observation"] for item in result["evidence"][0]["observations"]
        }
        self.assertIn("body_truncated", observations)

    def test_08_redirect_policy(self):
        # NONE: the redirect is recorded but never followed.
        one_hop = make_send(
            status=301,
            headers={"Location": "https://dell.example.com/next"},
        )
        result = acquire_evidence(
            request(redirect_policy=REDIRECT_NONE),
            send=one_hop,
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_ACQUIRED)
        self.assertEqual(len(one_hop.calls), 1)
        self.assertFalse(result["redirect"]["followed"])
        self.assertEqual(result["redirect"]["not_followed_reason"], "POLICY_NONE")

        # SAME_HOST: one same-host hop is followed within budget.
        def same_host(method, target, call_index):
            if call_index == 1:
                return TransportResult(
                    status=302,
                    headers={"Location": "/next"},
                    body=b"",
                    final_url=target,
                    url=target,
                )
            return TransportResult(
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"",
                final_url=target,
                url=target,
            )

        same = make_send(same_host)
        result = acquire_evidence(
            request(
                redirect_policy=REDIRECT_SAME_HOST,
                max_requests=2,
            ),
            send=same,
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_ACQUIRED)
        self.assertEqual(len(same.calls), 2)
        self.assertTrue(result["redirect"]["followed"])
        self.assertEqual(result["redirect"]["hops"], 1)

        # SAME_HOST but off-scope: blocked, never followed.
        off_scope = make_send(
            status=302,
            headers={"Location": "https://other.example.com/next"},
        )
        result = acquire_evidence(
            request(
                redirect_policy=REDIRECT_SAME_HOST,
                max_requests=2,
            ),
            send=off_scope,
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_BLOCKED)
        self.assertEqual(result["blocked_reason"], "REDIRECT_OUT_OF_SCOPE")
        self.assertEqual(len(off_scope.calls), 1)

    def test_09_sensitive_headers_never_persisted(self):
        result = acquire_evidence(
            request(headers=(("Authorization", "Bearer abc123secret"),)),
            send=make_send(),
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_BLOCKED)
        codes = {error["code"] for error in result["errors"]}
        self.assertIn("SENSITIVE_HEADER", codes)

        allowed = acquire_evidence(
            request(headers=(("Accept", "application/json"),)),
            send=make_send(status=200, headers={"Content-Type": "text/html"}),
            resolver=public_resolver,
        )
        self.assertEqual(allowed["state"], STATE_ACQUIRED)
        meta = allowed["request_metadata"]
        self.assertEqual(meta["sent_header_names"], ["accept", "user-agent"])
        blob = json.dumps(allowed, sort_keys=True).lower()
        self.assertNotIn("application/json", blob)
        self.assertNotIn("authorization", blob)
        self.assertNotIn("bearer abc123secret", blob)

    def test_10_evidence_record_has_provenance(self):
        result = acquire_evidence(
            request(),
            send=make_send(status=200, headers={"Content-Type": "text/html"}),
            resolver=public_resolver,
        )
        record = result["evidence"][0]
        provenance = record["provenance"]
        for key in (
            "program",
            "requested_target",
            "collected_at",
            "method",
            "evidence_type",
            "rule_version",
            "collector",
        ):
            self.assertTrue(provenance[key])
        self.assertEqual(
            provenance["scope_allowed_hosts"], ["dell.example.com"]
        )
        self.assertEqual(provenance["redirect_chain"], [TARGET])
        self.assertEqual(record["request_metadata"]["requests_made"], 1)

    def test_11_failed_request_is_failed_not_evidence(self):
        result = acquire_evidence(
            request(), send=make_send(None), resolver=public_resolver
        )
        self.assertEqual(result["state"], STATE_FAILED)
        self.assertEqual(result["evidence"], [])
        self.assertEqual(result["confidence_state"], "NONE")
        self.assertEqual(result["blocked_reason"], "TRANSPORT_FAILURE")

    def test_12_empty_response_is_empty(self):
        result = acquire_evidence(
            request(),
            send=make_send(status=204, headers={}, body=b""),
            resolver=public_resolver,
        )
        self.assertEqual(result["state"], STATE_EMPTY)
        self.assertEqual(result["evidence"], [])

        bare = acquire_evidence(
            request(method=HTTP_GET),
            send=make_send(status=200, headers={}, body=b""),
            resolver=public_resolver,
        )
        self.assertEqual(bare["state"], STATE_EMPTY)
        self.assertEqual(bare["evidence"], [])


class TestGapIntegration(unittest.TestCase):
    def test_13_does_not_mutate_source_candidate(self):
        candidate = dell_shaped_entry()
        before = copy.deepcopy(candidate)
        result = acquire_evidence(
            request(),
            send=make_send(status=200, headers={"Content-Type": "text/html"}),
            resolver=public_resolver,
        )
        reevaluate_candidate_with_evidence(candidate, result)
        self.assertEqual(candidate, before)

    def test_14_evidence_passes_through_gap_analyzer(self):
        candidate = dell_shaped_entry()
        result = acquire_evidence(
            request(),
            send=make_send(status=200, headers={"Content-Type": "text/html"}),
            resolver=public_resolver,
        )
        reevaluation = reevaluate_candidate_with_evidence(candidate, result)
        self.assertEqual(reevaluation["acquired_evidence_count"], 1)
        self.assertEqual(
            reevaluation["base_finding_readiness"],
            reevaluation["updated_finding_readiness"],
        )
        updated_dimensions = {
            dim["evidence_type"]: dim["state"]
            for dim in reevaluation["updated_gap"]["dimensions"]
        }
        self.assertEqual(len(updated_dimensions), 8)

        attached = copy.deepcopy(candidate)
        attached["acquired_evidence"] = result["evidence"]
        direct = analyze_candidate(attached)
        self.assertEqual(
            direct["finding_readiness"],
            reevaluation["updated_finding_readiness"],
        )

    def test_15_insufficient_evidence_never_becomes_component_confirmation(self):
        candidate = dell_shaped_entry()
        base = analyze_candidate(candidate)
        result = acquire_evidence(
            request(),
            send=make_send(status=200, headers={"Content-Type": "text/html"}),
            resolver=public_resolver,
        )
        reevaluation = reevaluate_candidate_with_evidence(candidate, result)
        # Component identity was and remains unresolved.
        updated_dimensions = {
            dim["evidence_type"]: dim["state"]
            for dim in reevaluation["updated_gap"]["dimensions"]
        }
        self.assertEqual(updated_dimensions[COMPONENT_IDENTITY], MISSING)
        self.assertEqual(
            reevaluation["updated_gap"]["finding_readiness"],
            base["finding_readiness"],
        )
        self.assertFalse(reevaluation["changed"])
        self.assertEqual(reevaluation["state_changes"], [])
        self.assertEqual(reevaluation["identity_claims"], [])
        blob = json.dumps(reevaluation, sort_keys=True).lower()
        self.assertNotIn("exploitable", blob)
        self.assertNotIn('"vulnerable"', blob)

    def test_16_deterministic_normalization(self):
        headers_one = {"Content-Type": "text/html", "Server": "nginx", "X-A": "1"}
        headers_two = {"x-a": "1", "server": "nginx", "content-type": "text/html"}
        first = acquire_evidence(
            request(method=HTTP_GET),
            send=make_send(status=200, headers=headers_one, body=b"<html/>"),
            resolver=public_resolver,
        )
        second = acquire_evidence(
            request(method=HTTP_GET),
            send=make_send(status=200, headers=headers_two, body=b"<html/>"),
            resolver=public_resolver,
        )
        self.assertEqual(first, second)
        self.assertEqual(
            first["evidence"][0]["evidence_id"],
            second["evidence"][0]["evidence_id"],
        )

    def test_17_no_automatic_follow_up_acquisition(self):
        send = make_send(status=200, headers={"Content-Type": "text/html"})
        result = acquire_evidence(
            request(), send=send, resolver=public_resolver
        )
        self.assertEqual(result["state"], STATE_ACQUIRED)
        self.assertEqual(len(send.calls), 1)
        self.assertEqual(result["next_action"], NEXT_ACTION)

    def test_18_unit_suite_never_reaches_default_network_send(self):
        from ai.research_agent import watchlist_evidence_acquire as module

        def explode():
            raise AssertionError("default network send must never be reached")

        with mock.patch.object(module, "_default_send_fn", explode):
            result = acquire_evidence(
                request(),
                send=make_send(status=200, headers={"Content-Type": "text/html"}),
                resolver=public_resolver,
            )
        self.assertEqual(result["state"], STATE_ACQUIRED)


def _cli_args(root, **overrides):
    values = {
        "program": "dell",
        "target": TARGET,
        "evidence_type": APPLICATION_RESPONSE,
        "method": HTTP_HEAD,
        "scope_host": ["dell.example.com"],
        "scope_id": "",
        "timeout": 10.0,
        "max_bytes": 65536,
        "max_requests": 1,
        "redirect_policy": REDIRECT_NONE,
        "candidate_cve": "",
        "snapshot_root": str(root),
        "apply": False,
        "json": True,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class TestAcquireCli(unittest.TestCase):
    def test_cli_requires_explicit_scope_flags(self):
        from ai import research_cli

        parser = research_cli.build_parser()
        args = parser.parse_args(
            [
                "agent",
                "evidence-acquire",
                "--program",
                "dell",
                "--target",
                TARGET,
                "--evidence-type",
                APPLICATION_RESPONSE,
                "--method",
                HTTP_HEAD,
                "--scope-host",
                "dell.example.com",
                "--json",
            ]
        )
        self.assertEqual(args.agent_command, "evidence-acquire")
        self.assertEqual(args.scope_host, ["dell.example.com"])
        self.assertFalse(args.apply)
        with self.assertRaises(SystemExit):
            parser.parse_args(
                ["agent", "evidence-acquire", "--program", "dell"]
            )

    def test_cli_read_only_and_apply_atomic(self):
        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = make_send(status=200, headers={"Content-Type": "text/html"})

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_evidence_acquire(
                    _cli_args(root), send=fake, resolver=public_resolver
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["state"], STATE_ACQUIRED)
            self.assertFalse((root / "evidence").exists())

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_evidence_acquire(
                    _cli_args(root, apply=True),
                    send=make_send(
                        status=200, headers={"Content-Type": "text/html"}
                    ),
                    resolver=public_resolver,
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertTrue(payload["written"])
            files = sorted((root / "evidence" / "dell").glob("wev-*.json"))
            self.assertEqual(len(files), 1)
            first_bytes = files[0].read_bytes()

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_evidence_acquire(
                    _cli_args(root, apply=True),
                    send=make_send(
                        status=200, headers={"Content-Type": "text/html"}
                    ),
                    resolver=public_resolver,
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertFalse(payload["written"])
            self.assertEqual(
                sorted((root / "evidence" / "dell").glob("wev-*.json")), files
            )
            self.assertEqual(files[0].read_bytes(), first_bytes)

    def test_cli_reevaluates_local_candidate_without_mutation(self):
        from ai import research_cli

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            program_dir = root / "dell"
            program_dir.mkdir(parents=True)
            snapshot = {
                "snapshot_id": "watch-20260918T144218Z",
                "program": "dell",
                "entries": [dell_shaped_entry()],
            }
            snapshot_path = program_dir / "watch-20260918T144218Z.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            before = snapshot_path.read_bytes()

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = research_cli.run_agent_evidence_acquire(
                    _cli_args(root, candidate_cve="CVE-2026-1557"),
                    send=make_send(
                        status=200, headers={"Content-Type": "text/html"}
                    ),
                    resolver=public_resolver,
                )
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            reevaluation = payload["reevaluation"]
            self.assertEqual(reevaluation["cve_id"], "CVE-2026-1557")
            updated = {
                dim["evidence_type"]: dim["state"]
                for dim in reevaluation["updated_gap"]["dimensions"]
            }
            self.assertEqual(updated[COMPONENT_IDENTITY], MISSING)
            # The source snapshot is untouched.
            self.assertEqual(snapshot_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
