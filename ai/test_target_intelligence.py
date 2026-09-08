"""Focused tests for read-only Target Intelligence (Phase 3A).

PROJECTION tests: they prove the projector turns existing recon
inventory into normalized, deterministically identified
TargetIntelligence objects with no network, no LLM, no
subprocess, no database writes, no version comparison, no pattern
matching, and no scope/verdict/target authority. Fixtures mirror
the real database/db.py documents field-for-field.
"""

import unittest

from pydantic import ValidationError

from ai.researcher import target_intelligence as ti_module
from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ParamRecord,
    ProgramRecord,
    TargetIntelError,
    UrlRecord,
    SubdomainRecord,
    project_program,
    project_subdomain,
)
from ai.schemas.target_intelligence import (
    PROJECTION_VERSION,
    TargetIntelligence,
)


# ------------------------------------------------------------------
# Fixtures mirroring database/db.py documents
# ------------------------------------------------------------------


def _program(name="acme", **overrides):
    base = dict(
        program_name=name,
        scopes=["acme.com"],
        ooscopes=["internal.acme.com"],
        record_id=f"prog-{name}",
    )
    base.update(overrides)
    return ProgramRecord(**base)


def _subdomain(program="acme", sub="app.acme.com", **overrides):
    base = dict(
        program_name=program,
        subdomain=sub,
        scope="acme.com",
        providers=["subfinder"],
        record_id=f"sub-{sub}",
    )
    base.update(overrides)
    return SubdomainRecord(**base)


def _http(program="acme", sub="app.acme.com", **overrides):
    base = dict(
        program_name=program,
        subdomain=sub,
        scope="acme.com",
        ips=["93.184.216.34"],
        tech=["nginx:1.24.0", "jQuery:3.7.1"],
        title="Acme App",
        status_code=200,
        headers=(("Server", "nginx/1.24.0"), ("X-Powered-By", "PHP")),
        url="https://app.acme.com/",
        final_url="https://app.acme.com/home",
        favicon="abc123",
        last_update="2026-08-04 10:00:00",
        record_id=f"http-{sub}",
    )
    base.update(overrides)
    return HttpRecord(**base)


def _url(program="acme", sub="app.acme.com", **overrides):
    base = dict(
        program_name=program,
        subdomain=sub,
        url="https://app.acme.com/search?q=x",
        path="/search",
        params=["q"],
        sources=["katana"],
        status_code=200,
        last_update="2026-08-04 10:05:00",
        record_id="url-search",
    )
    base.update(overrides)
    return UrlRecord(**base)


def _endpoint(program="acme", sub="app.acme.com", **overrides):
    base = dict(
        program_name=program,
        subdomain=sub,
        path="/search",
        example_url="https://app.acme.com/search?q=x",
        params=["q"],
        params_from_crawl=["q"],
        params_from_x8=[],
        x8_checked=False,
        hit_count=3,
        param_records=(
            ParamRecord(
                name="q", method="GET", location="query",
                source="crawl",
            ),
        ),
        last_update="2026-08-04 10:06:00",
        record_id="ep-search",
    )
    base.update(overrides)
    return EndpointRecord(**base)


def _full_inventory(program="acme", sub="app.acme.com"):
    return dict(
        https=[_http(program, sub)],
        urls=[_url(program, sub)],
        endpoints=[_endpoint(program, sub)],
    )


# ------------------------------------------------------------------
# Schema
# ------------------------------------------------------------------


class SchemaTests(unittest.TestCase):
    def test_valid_target_intelligence(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        intel = result.intelligence
        self.assertIsInstance(intel, TargetIntelligence)
        self.assertTrue(intel.intelligence_id.startswith("ti-"))
        self.assertEqual(
            intel.projection_version, PROJECTION_VERSION
        )
        # Serialization round-trip.
        clone = TargetIntelligence.model_validate(
            intel.model_dump(mode="json")
        )
        self.assertEqual(
            clone.model_dump(mode="json"),
            intel.model_dump(mode="json"),
        )

    def test_invalid_id_rejected(self):
        intel = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        ).intelligence
        with self.assertRaises(ValidationError):
            TargetIntelligence.model_validate(
                {
                    **intel.model_dump(mode="json"),
                    "intelligence_id": "bogus",
                }
            )

    def test_unknown_fields_rejected(self):
        intel = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        ).intelligence
        for malicious in (
            {"scope_allowed": True},
            {"target_affected": True},
            {"verdict": "CONFIRMED"},
            {"command": "curl attacker.example"},
            {"match_score": 0.99},
            {"execution_allowed": True},
            {"evidence": []},
        ):
            with self.assertRaises(ValidationError):
                TargetIntelligence.model_validate(
                    {**intel.model_dump(mode="json"), **malicious}
                )

    def test_forbidden_authority_fields_absent(self):
        fields = set(TargetIntelligence.model_fields)
        for forbidden in (
            "scope_allowed",
            "execution_allowed",
            "authorized_target",
            "target_affected",
            "match_score",
            "verdict",
            "confirmed",
            "verified",
            "evidence",
            "finding_status",
            "affected",
        ):
            self.assertNotIn(forbidden, fields)

    def test_deterministic_identity(self):
        first = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        ).intelligence
        second = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        ).intelligence
        self.assertEqual(first.intelligence_id, second.intelligence_id)
        self.assertEqual(first.target_key, second.target_key)
        self.assertEqual(first.snapshot_hash, second.snapshot_hash)


# ------------------------------------------------------------------
# Program / subdomain relationships
# ------------------------------------------------------------------


class RelationshipTests(unittest.TestCase):
    def test_program_relationship_preserved(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        intel = result.intelligence
        self.assertEqual(intel.program_name, "acme")
        self.assertEqual(intel.subdomain, "app.acme.com")
        self.assertEqual(
            intel.source_refs.program_record_id, "prog-acme"
        )
        self.assertEqual(
            intel.source_refs.subdomain_record_id,
            "sub-app.acme.com",
        )

    def test_subdomain_relationship_preserved(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        refs = result.intelligence.source_refs
        self.assertEqual(refs.http_record_ids, ["http-app.acme.com"])
        self.assertEqual(refs.url_record_ids, ["url-search"])
        self.assertEqual(refs.endpoint_record_ids, ["ep-search"])

    def test_cross_program_records_excluded(self):
        program_a = _program("a")
        sub_a = _subdomain("a", "x.a.com")
        https = [_http("a", "x.a.com"), _http("b", "y.b.com")]
        urls = [_url("a", "x.a.com"), _url("b", "y.b.com")]
        endpoints = [
            _endpoint("a", "x.a.com"),
            _endpoint("b", "y.b.com"),
        ]
        result = project_subdomain(
            program_a, sub_a, https=https, urls=urls,
            endpoints=endpoints,
        )
        intel = result.intelligence
        blob = intel.model_dump_json()
        self.assertNotIn("y.b.com", blob)
        self.assertNotIn("http-y.b.com", blob)
        self.assertEqual(len(intel.http_observations), 1)
        self.assertEqual(len(intel.url_observations), 1)
        self.assertEqual(len(intel.endpoint_observations), 1)

    def test_cross_subdomain_rows_excluded(self):
        https = [
            _http("acme", "app.acme.com"),
            _http("acme", "other.acme.com"),
        ]
        result = project_subdomain(
            _program(), _subdomain(), https=https, urls=[],
            endpoints=[],
        )
        self.assertEqual(len(result.intelligence.http_observations), 1)

    def test_mismatched_subdomain_program_rejected(self):
        with self.assertRaises(TargetIntelError):
            project_subdomain(
                _program("a"), _subdomain("b", "y.b.com")
            )

    def test_missing_relationship_rows_skipped(self):
        bad_url = UrlRecord(
            program_name="", subdomain="", url="https://x.test/",
            record_id="url-orphan",
        )
        result = project_subdomain(
            _program(), _subdomain(), https=[], urls=[bad_url],
            endpoints=[],
        )
        self.assertEqual(result.intelligence.url_observations, [])
        self.assertTrue(
            any(
                item.reason == "missing_relationship"
                for item in result.skipped
            )
        )

    def test_wrong_input_types_rejected(self):
        with self.assertRaises(TypeError):
            project_subdomain("acme", _subdomain())
        with self.assertRaises(TypeError):
            project_subdomain(_program(), {"subdomain": "x"})
        with self.assertRaises(TypeError):
            project_subdomain(
                _program(), _subdomain(), https=["nope"]
            )

    def test_no_cross_program_leakage_in_program_projection(self):
        program_a = _program("a")
        subs = [_subdomain("a", "x.a.com"), _subdomain("b", "y.b.com")]
        https = [_http("a", "x.a.com"), _http("b", "y.b.com")]
        result = project_program(
            program_a, subs, https=https, urls=[], endpoints=[]
        )
        self.assertEqual(len(result.intelligence), 1)
        self.assertEqual(
            result.intelligence[0].subdomain, "x.a.com"
        )


# ------------------------------------------------------------------
# Technology / version observations
# ------------------------------------------------------------------


class TechnologyTests(unittest.TestCase):
    def test_technology_and_version_preserved(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        techs = {
            item.name: item.observed_version
            for item in result.intelligence.technologies
        }
        self.assertEqual(techs["nginx"], "1.24.0")
        self.assertEqual(techs["jQuery"], "3.7.1")
        raws = {
            item.raw_label for item in result.intelligence.technologies
        }
        self.assertIn("nginx:1.24.0", raws)

    def test_versionless_technology_preserved(self):
        http = _http(tech=["Apache HTTP Server"])
        result = project_subdomain(
            _program(), _subdomain(), https=[http], urls=[],
            endpoints=[],
        )
        techs = result.intelligence.technologies
        self.assertEqual(len(techs), 1)
        self.assertEqual(techs[0].name, "Apache HTTP Server")
        self.assertIsNone(techs[0].observed_version)

    def test_no_version_comparison_performed(self):
        # A newer-looking and older-looking label coexist with no
        # judgment attached: no affected/unaffected output exists.
        http = _http(tech=["nginx:1.24.0", "nginx:0.5.0"])
        result = project_subdomain(
            _program(), _subdomain(), https=[http], urls=[],
            endpoints=[],
        )
        blob = result.intelligence.model_dump_json().lower()
        self.assertNotIn("affected", blob)
        self.assertNotIn("match", blob)
        versions = sorted(
            item.observed_version
            for item in result.intelligence.technologies
        )
        self.assertEqual(versions, ["0.5.0", "1.24.0"])

    def test_duplicate_technologies_deterministic(self):
        http = _http(tech=["nginx:1.24.0", "nginx:1.24.0"])
        result = project_subdomain(
            _program(), _subdomain(), https=[http], urls=[],
            endpoints=[],
        )
        self.assertEqual(len(result.intelligence.technologies), 1)

    def test_no_confidence_manufactured(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        blob = result.intelligence.model_dump_json()
        self.assertNotIn("confidence", blob)

    def test_malicious_tech_label_stays_inert(self):
        http = _http(
            tech=["nginx; curl attacker.example", "1.2.3\nX: true"]
        )
        result = project_subdomain(
            _program(), _subdomain(), https=[http], urls=[],
            endpoints=[],
        )
        names = [
            item.name for item in result.intelligence.technologies
        ]
        self.assertIn("nginx; curl attacker.example", names)
        # The newline-carrying label is skipped, never normalized.
        self.assertEqual(len(names), 1)
        self.assertTrue(
            any(
                item.reason == "invalid_observation"
                for item in result.skipped
            )
        )


# ------------------------------------------------------------------
# HTTP / URL / endpoint observations
# ------------------------------------------------------------------


class InventoryObservationTests(unittest.TestCase):
    def test_http_observation_projected(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        (obs,) = result.intelligence.http_observations
        self.assertEqual(obs.status_code, 200)
        self.assertEqual(obs.title, "Acme App")
        self.assertEqual(obs.ips, ["93.184.216.34"])
        self.assertEqual(
            obs.header_names, ["Server", "X-Powered-By"]
        )
        self.assertEqual(obs.url, "https://app.acme.com/")

    def test_url_metadata_projected_without_fetching(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        (obs,) = result.intelligence.url_observations
        self.assertEqual(obs.scheme, "https")
        self.assertEqual(obs.host, "app.acme.com")
        self.assertEqual(obs.path, "/search")
        self.assertEqual(obs.params, ["q"])
        self.assertEqual(obs.sources, ["katana"])

    def test_endpoint_projected(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        (obs,) = result.intelligence.endpoint_observations
        self.assertEqual(obs.path, "/search")
        self.assertEqual(obs.params, ["q"])
        self.assertEqual(len(obs.param_details), 1)
        detail = obs.param_details[0]
        self.assertEqual(
            (detail.name, detail.method, detail.location,
             detail.source),
            ("q", "GET", "query", "crawl"),
        )
        self.assertEqual(obs.hit_count, 3)
        self.assertFalse(obs.x8_checked)

    def test_malformed_url_skipped_safely(self):
        urls = [
            _url(),
            _url(url="not a url", record_id="url-bad"),
        ]
        result = project_subdomain(
            _program(), _subdomain(), https=[], urls=urls,
            endpoints=[],
        )
        self.assertEqual(len(result.intelligence.url_observations), 1)
        self.assertTrue(
            any(
                item.reason == "malformed_url"
                for item in result.skipped
            )
        )

    def test_unknown_param_vocabulary_skipped(self):
        bad = ParamRecord(
            name="q", method="TRACE", location="cookie",
            source="manual",
        )
        endpoint = _endpoint(param_records=(bad,))
        result = project_subdomain(
            _program(), _subdomain(), https=[], urls=[],
            endpoints=[endpoint],
        )
        (obs,) = result.intelligence.endpoint_observations
        self.assertEqual(obs.param_details, [])
        self.assertTrue(
            any(
                item.reason == "invalid_observation"
                for item in result.skipped
            )
        )

    def test_duplicate_endpoint_rows_deterministic(self):
        endpoints = [_endpoint(), _endpoint()]
        result = project_subdomain(
            _program(), _subdomain(), https=[], urls=[],
            endpoints=endpoints,
        )
        self.assertEqual(
            len(result.intelligence.endpoint_observations), 1
        )

    def test_hostile_url_preserved_as_data(self):
        url = _url(
            url="https://attacker.example/collect?x=1",
            record_id="url-evil",
        )
        result = project_subdomain(
            _program(), _subdomain(), https=[], urls=[url],
            endpoints=[],
        )
        (obs,) = result.intelligence.url_observations
        self.assertEqual(obs.host, "attacker.example")


# ------------------------------------------------------------------
# Determinism
# ------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    def test_same_input_same_output(self):
        first = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        ).intelligence
        second = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        ).intelligence
        self.assertEqual(
            first.model_dump(mode="json"),
            second.model_dump(mode="json"),
        )

    def test_shuffled_input_same_output(self):
        kwargs = _full_inventory()
        ordered = project_subdomain(
            _program(), _subdomain(), **kwargs
        ).intelligence
        shuffled = project_subdomain(
            _program(),
            _subdomain(),
            https=list(reversed(kwargs["https"])),
            urls=list(reversed(kwargs["urls"])),
            endpoints=list(reversed(kwargs["endpoints"])),
        ).intelligence
        self.assertEqual(
            ordered.model_dump(mode="json"),
            shuffled.model_dump(mode="json"),
        )

    def test_stable_ordering(self):
        http = _http(tech=["php:8.1.0", "nginx:1.24.0", "Apache"])
        result = project_subdomain(
            _program(), _subdomain(), https=[http], urls=[],
            endpoints=[],
        )
        names = [
            item.name for item in result.intelligence.technologies
        ]
        self.assertEqual(names, sorted(names, key=str.casefold))

    def test_stable_identity_across_inventory_change(self):
        before = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        ).intelligence
        changed = dict(_full_inventory())
        changed["https"] = [_http(tech=["nginx:1.25.0"])]
        after = project_subdomain(
            _program(), _subdomain(), **changed
        ).intelligence
        self.assertEqual(
            before.intelligence_id, after.intelligence_id
        )
        self.assertEqual(before.target_key, after.target_key)
        self.assertNotEqual(before.snapshot_hash, after.snapshot_hash)

    def test_program_projection_ordered(self):
        program = _program()
        subs = [
            _subdomain("acme", "b.acme.com"),
            _subdomain("acme", "a.acme.com"),
        ]
        result = project_program(program, subs)
        self.assertEqual(
            [item.subdomain for item in result.intelligence],
            ["a.acme.com", "b.acme.com"],
        )


# ------------------------------------------------------------------
# Security boundary
# ------------------------------------------------------------------


class SecurityBoundaryTests(unittest.TestCase):
    def test_no_llm_network_subprocess_or_db_symbols(self):
        names = set(ti_module.__dict__)
        for forbidden in (
            "openrouter",
            "openai",
            "anthropic",
            "LLMProvider",
            "requests",
            "urllib3",
            "httpx",
            "socket",
            "subprocess",
            "os",
            "sys",
            "mongoengine",
            "pymongo",
            "database",
            "PatternStore",
            "project_claim",
            "compare_version",
            "match_technology",
            "Hypothesis",
        ):
            self.assertNotIn(forbidden, names)

    def test_projection_runs_with_network_disabled(self):
        import socket

        original = socket.socket

        def _blocked(*args, **kwargs):
            raise AssertionError("network access attempted")

        socket.socket = _blocked
        try:
            result = project_program(
                _program(),
                [_subdomain()],
                https=[_http()],
                urls=[_url()],
                endpoints=[_endpoint()],
            )
        finally:
            socket.socket = original
        self.assertEqual(len(result.intelligence), 1)

    def test_no_database_writes(self):
        seen = []

        class WriteTrap:
            def __init__(self, **fields):
                self.__dict__.update(fields)

            def __getattr__(self, name):
                if name in {
                    "save", "update", "delete", "insert", "upsert",
                    "reload", "modify", "objects", "save_all",
                }:
                    seen.append(name)
                    raise AssertionError(
                        f"database write attempted: {name}"
                    )
                raise AttributeError(name)

        trap_http = WriteTrap(
            program_name="acme", subdomain="app.acme.com",
            scope="acme.com", ips=[], tech=["nginx:1.24.0"],
            title="t", status_code=200, headers={}, url="",
            final_url="", favicon="", last_update=None, id="h1",
        )
        http = HttpRecord.from_document(trap_http)
        result = project_subdomain(
            _program(), _subdomain(), https=[http], urls=[],
            endpoints=[],
        )
        self.assertEqual(seen, [])
        self.assertEqual(len(result.intelligence.technologies), 1)

    def test_hostile_url_never_fetched(self):
        urls = [
            _url(
                url="https://attacker.example/?x=1",
                record_id="url-evil",
            ),
            _url(
                url="file:///etc/passwd", record_id="url-file"
            ),
        ]
        result = project_subdomain(
            _program(), _subdomain(), https=[], urls=urls,
            endpoints=[],
        )
        hosts = [
            item.host for item in result.intelligence.url_observations
        ]
        self.assertIn("attacker.example", hosts)
        # Non-http(s) scheme is not projected as a web target.
        self.assertNotIn("", hosts)
        self.assertTrue(
            any(
                item.reason == "malformed_url"
                for item in result.skipped
            )
        )

    def test_command_like_strings_remain_inert(self):
        http = _http(
            tech=["nginx; curl attacker.example"],
            title="x; rm -rf /",
        )
        url = _url(url="https://app.acme.com/?c=;eval(1)")
        result = project_subdomain(
            _program(), _subdomain(), https=[http], urls=[url],
            endpoints=[],
        )
        blob = result.intelligence.model_dump(mode="json")
        for forbidden in (
            "scope_allowed", "target_affected", "verdict",
            "command", "tool_call", "match_score", "affected",
        ):
            self.assertNotIn(forbidden, blob)

    def test_scope_snapshot_grants_nothing(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        snapshot = result.intelligence.scope_snapshot
        self.assertEqual(snapshot.program_scopes, ["acme.com"])
        self.assertEqual(
            snapshot.program_ooscopes, ["internal.acme.com"]
        )
        self.assertEqual(snapshot.subdomain_scope, "acme.com")
        blob = result.intelligence.model_dump(mode="json")
        for forbidden in (
            "scope_allowed", "execution_allowed",
            "authorized_target", "allow_scope",
        ):
            self.assertNotIn(forbidden, blob)

    def test_verdict_fields_impossible(self):
        result = project_subdomain(
            _program(), _subdomain(), **_full_inventory()
        )
        blob = result.intelligence.model_dump(mode="json")
        for forbidden in (
            "CONFIRMED", "VERIFIED", "NOT_VULNERABLE", "EXPLOITED",
            "target_affected", "finding_status", "evidence",
        ):
            self.assertNotIn(forbidden, blob)


# ------------------------------------------------------------------
# Integration with real-shaped documents
# ------------------------------------------------------------------


class DocumentAdapterTests(unittest.TestCase):
    def test_from_document_duck_typing(self):
        class FakeDoc:
            id = "507f1f77bcf86cd799439011"
            program_name = "acme"
            subdomain = "app.acme.com"
            scope = "acme.com"
            ips = ["93.184.216.34"]
            tech = ["nginx:1.24.0"]
            title = "t"
            status_code = 200
            headers = {"Server": "nginx"}
            url = "https://app.acme.com/"
            final_url = "https://app.acme.com/"
            favicon = ""

        http = HttpRecord.from_document(FakeDoc())
        self.assertEqual(http.record_id, "507f1f77bcf86cd799439011")
        self.assertEqual(http.tech, ("nginx:1.24.0",))
        result = project_subdomain(
            _program(), _subdomain(), https=[http], urls=[],
            endpoints=[],
        )
        techs = result.intelligence.technologies
        self.assertEqual(len(techs), 1)
        self.assertEqual(techs[0].observed_version, "1.24.0")

    def test_full_round_trip_serialization(self):
        result = project_program(
            _program(),
            [_subdomain()],
            https=[_http()],
            urls=[_url()],
            endpoints=[_endpoint()],
        )
        (intel,) = result.intelligence
        clone = TargetIntelligence.model_validate(
            intel.model_dump(mode="json")
        )
        self.assertEqual(clone.intelligence_id, intel.intelligence_id)
        self.assertEqual(clone.snapshot_hash, intel.snapshot_hash)
        self.assertEqual(
            [item.name for item in clone.technologies],
            ["jQuery", "nginx"],
        )
        self.assertEqual(result.skipped, ())


if __name__ == "__main__":
    unittest.main()
