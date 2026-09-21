"""Tests for aec/surface (EPIC 4 Part 1: Attack Surface Adapter).

Normalizes Watch asset-intelligence shapes (record/candidate mappings as
produced by backend.attack_surface, consumed as plain data — never
imported) into ResearchCandidateDrafts. Deterministic, no network, no
writes, no conclusions about any target.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

SURFACE_DIR = Path(__file__).resolve().parents[1] / "aec" / "surface"
MODULES = ("models.py", "adapter.py")

NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "subprocess", "asyncio",
    "ai", "watch_xss_verify", "backend",
})

REFUSAL_CODES = frozenset({
    "INVALID_INPUT",
    "MISSING_ENDPOINT",
    "MISSING_ASSET",
    "MISSING_CATEGORY",
    "UNKNOWN_CATEGORY",
})


def surface_record(**overrides):
    """Mirror of AttackSurfaceRecord.to_dict() (backend shape, plain data)."""
    record = {
        "program": "pilot",
        "subdomain": "Example.COM",
        "url": "/api/user?id=",
        "endpoint": "/api/user",
        "parameter": "id",
        "method": "get",
        "location": "query",
        "technology": ["PHP", "php", "Laravel"],
        "source": "watch",
        "last_update": None,
    }
    record.update(overrides)
    return record


def surface_candidate(**overrides):
    """Mirror of AttackSurfaceCandidate.to_dict() (backend shape)."""
    candidate = {
        "id": "cand-001",
        "category": "IDOR_CANDIDATE",
        "confidence": "MEDIUM",
        "score": 72,
        "endpoint": "/api/user",
        "parameter": "id",
        "method": "GET",
        "reasons": ["object-reference-signal"],
        "status": "NEW",
        "created_at": None,
        "program": "pilot",
        "subdomain": "example.com",
        "url": "/api/user?id=",
        "location": "query",
        "technology": ["php"],
        "source": "watch",
        "rule_version": "v1",
    }
    candidate.update(overrides)
    return candidate


class TestAdaptRecord(unittest.TestCase):
    def test_valid_record_adapts(self):
        from aec.surface import adapter

        outcome = adapter.adapt_record(surface_record(), default_category="idor")
        self.assertTrue(outcome.ok, outcome.refusal_code)
        draft = outcome.draft
        self.assertEqual(draft.asset, "example.com")
        self.assertEqual(draft.endpoint, "/api/user")
        self.assertEqual(draft.parameters, ("id",))
        self.assertEqual(draft.research_category, "idor")

    def test_normalization_rules(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertEqual(draft.asset, "example.com")
        self.assertEqual(draft.technology, ("laravel", "php"))
        self.assertEqual(draft.method, "GET")

    def test_explicit_category_wins(self):
        from aec.surface import adapter

        record = surface_record()
        record["category"] = "SSRF_CANDIDATE"
        draft = adapter.adapt_record(record, default_category="idor").draft
        self.assertEqual(draft.research_category, "ssrf")

    def test_candidate_suffix_stripped(self):
        from aec.surface import adapter

        record = surface_record()
        record["category"] = "XSS_CANDIDATE"
        draft = adapter.adapt_record(record).draft
        self.assertEqual(draft.research_category, "xss")

    def test_endpoint_case_preserved(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(
            surface_record(endpoint="/API/User"), default_category="idor"
        ).draft
        self.assertEqual(draft.endpoint, "/API/User")

    def test_empty_parameter_yields_no_parameters(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(
            surface_record(parameter=""), default_category="idor"
        ).draft
        self.assertEqual(draft.parameters, ())

    def test_source_reference_carried(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertTrue(draft.source_reference)

    def test_gap_states_first_observation(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertIn("initial-observation", draft.evidence_gap["required"])
        self.assertIn("initial-observation", draft.evidence_gap["missing"])

    def test_candidate_id_is_content_hash(self):
        import hashlib
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        # Source reference is the record url verbatim.
        basis = "/api/user?id=|example.com|/api/user|id|idor"
        expected = "rc-" + hashlib.sha256(basis.encode()).hexdigest()[:12]
        self.assertEqual(draft.candidate_id, expected)

    def test_same_record_same_draft(self):
        from aec.surface import adapter

        first = adapter.adapt_record(surface_record(), default_category="idor")
        second = adapter.adapt_record(surface_record(), default_category="idor")
        self.assertEqual(first, second)


class TestAdaptCandidate(unittest.TestCase):
    def test_classified_candidate_adapts(self):
        from aec.surface import adapter

        outcome = adapter.adapt_candidate(surface_candidate())
        self.assertTrue(outcome.ok)
        draft = outcome.draft
        self.assertEqual(draft.research_category, "idor")
        self.assertEqual(draft.source_reference, "cand-001")
        self.assertIn("MEDIUM", draft.classification_notes)

    def test_confidence_carried_verbatim(self):
        from aec.surface import adapter

        draft = adapter.adapt_candidate(surface_candidate(confidence="HIGH")).draft
        self.assertIn("HIGH", draft.classification_notes)

    def test_candidate_reasons_preserved(self):
        from aec.surface import adapter

        draft = adapter.adapt_candidate(surface_candidate()).draft
        self.assertIn("object-reference-signal", draft.classification_notes)


class TestRefusals(unittest.TestCase):
    def test_invalid_inputs_refused(self):
        from aec.surface import adapter

        for bad in (None, "x", 42, ["endpoint"]):
            outcome = adapter.adapt_record(bad)
            self.assertFalse(outcome.ok)
            self.assertEqual(outcome.refusal_code, "INVALID_INPUT")

    def test_missing_endpoint_refused(self):
        from aec.surface import adapter

        outcome = adapter.adapt_record(surface_record(endpoint=""))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_ENDPOINT")

    def test_missing_asset_refused(self):
        from aec.surface import adapter

        outcome = adapter.adapt_record(surface_record(subdomain=""))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_ASSET")

    def test_missing_category_refused_without_default(self):
        from aec.surface import adapter

        outcome = adapter.adapt_record(surface_record())
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_CATEGORY")

    def test_unknown_category_refused(self):
        from aec.surface import adapter

        outcome = adapter.adapt_record(
            surface_record(), default_category="sqli"
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "UNKNOWN_CATEGORY")

    def test_candidate_refusals_closed(self):
        from aec.surface import adapter

        outcome = adapter.adapt_candidate(surface_candidate(category="NOPE"))
        self.assertFalse(outcome.ok)
        self.assertIn(outcome.refusal_code, {"UNKNOWN_CATEGORY", "MISSING_CATEGORY"})

    def test_refusal_vocabulary_closed(self):
        from aec.surface import adapter

        codes = {
            adapter.adapt_record(None).refusal_code,
            adapter.adapt_record(surface_record(endpoint="")).refusal_code,
            adapter.adapt_record(surface_record(subdomain="")).refusal_code,
            adapter.adapt_record(surface_record()).refusal_code,
            adapter.adapt_record(
                surface_record(), default_category="nope").refusal_code,
        }
        self.assertLessEqual(codes, REFUSAL_CODES)


class TestCaseBridge(unittest.TestCase):
    def test_draft_converts_to_case_kwargs(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        kwargs = adapter.to_case_kwargs(draft)
        self.assertEqual(kwargs["case_id"], draft.candidate_id)
        self.assertEqual(kwargs["host"], "example.com")
        self.assertEqual(kwargs["endpoint"], "/api/user")
        self.assertEqual(kwargs["parameter"], "id")
        self.assertEqual(kwargs["category"], "idor")

    def test_no_url_invented(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertEqual(adapter.to_case_kwargs(draft)["url"], "")

    def test_parameterless_draft_maps_empty_parameter(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(
            surface_record(parameter=""), default_category="idor"
        ).draft
        self.assertEqual(adapter.to_case_kwargs(draft)["parameter"], "")

    def test_kwargs_build_real_caseref(self):
        from aec.models import CaseRef
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        case = CaseRef(**adapter.to_case_kwargs(draft))
        self.assertEqual(case.host, "example.com")


class TestSerialization(unittest.TestCase):
    def test_draft_round_trip(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        text = adapter.serialize_draft(draft)
        self.assertEqual(
            json.dumps(json.loads(text), sort_keys=True, separators=(",", ":")),
            text,
        )

    def test_draft_dict_has_stable_keys(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertEqual(
            sorted(draft.to_dict()),
            ["asset", "candidate_id", "classification_notes", "endpoint",
             "evidence_gap", "method", "parameters", "research_category",
             "source_reference", "technology"],
        )

    def test_drafts_are_frozen(self):
        import dataclasses
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        with self.assertRaises(dataclasses.FrozenInstanceError):
            draft.asset = "other.com"


class TestSafetyGuards(unittest.TestCase):
    def test_modules_have_no_network_or_backend_imports(self):
        for name in MODULES:
            tree = ast.parse((SURFACE_DIR / name).read_text())
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
            self.assertLessEqual(imported & NETWORK_MODULES, set(), name)

    def test_modules_perform_no_filesystem_writes(self):
        for name in MODULES:
            tree = ast.parse((SURFACE_DIR / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    called = ""
                    if isinstance(func, ast.Name):
                        called = func.id
                    elif isinstance(func, ast.Attribute):
                        called = func.attr
                    self.assertNotIn(called, {"write_text", "mkdir", "makedirs"}, name)
                    if called == "open":
                        modes = [
                            a.value for a in node.args[1:]
                            if isinstance(a, ast.Constant) and isinstance(a.value, str)
                        ]
                        for mode in modes:
                            self.assertNotIn("w", mode.replace("U", ""), name)

    def test_no_backend_import_in_source(self):
        for name in MODULES:
            source = (SURFACE_DIR / name).read_text()
            self.assertNotIn("attack_surface", source, name)
            self.assertNotIn("observed_inventory", source, name)


class TestNormalizationTables(unittest.TestCase):
    def test_technology_dedup_sorted_lower(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(
            surface_record(technology=["Node", "node", " PHP ", ""]),
            default_category="idor",
        ).draft
        self.assertEqual(draft.technology, ("node", "php"))

    def test_method_uppercased(self):
        from aec.surface import adapter

        for raw, expected in (("get", "GET"), ("Head", "HEAD"), ("post", "POST")):
            draft = adapter.adapt_record(
                surface_record(method=raw), default_category="idor"
            ).draft
            self.assertEqual(draft.method, expected, raw)

    def test_method_defaults_get(self):
        from aec.surface import adapter

        record = surface_record()
        del record["method"]
        draft = adapter.adapt_record(record, default_category="idor").draft
        self.assertEqual(draft.method, "GET")

    def test_asset_key_fallback(self):
        from aec.surface import adapter

        record = surface_record(subdomain="")
        record["asset"] = "Other.COM"
        draft = adapter.adapt_record(record, default_category="idor").draft
        self.assertEqual(draft.asset, "other.com")

    def test_category_whitespace_and_case(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(
            surface_record(), default_category="  Idor_Candidate  "
        ).draft
        self.assertEqual(draft.research_category, "idor")

    def test_all_known_categories_adapt(self):
        from aec.surface import adapter

        for category in ("idor", "xss", "ssrf", "file_upload", "authz"):
            outcome = adapter.adapt_record(
                surface_record(), default_category=category
            )
            self.assertTrue(outcome.ok, category)
            self.assertEqual(outcome.draft.research_category, category)

    def test_distinct_records_distinct_ids(self):
        from aec.surface import adapter

        first = adapter.adapt_record(surface_record(), default_category="idor").draft
        second = adapter.adapt_record(
            surface_record(endpoint="/other"), default_category="idor"
        ).draft
        self.assertNotEqual(first.candidate_id, second.candidate_id)

    def test_id_prefix_and_length(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertTrue(draft.candidate_id.startswith("rc-"))
        self.assertEqual(len(draft.candidate_id), 15)

    def test_notes_empty_for_plain_records(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertEqual(draft.classification_notes, ())

    def test_candidate_missing_id_uses_url(self):
        from aec.surface import adapter

        candidate = surface_candidate()
        del candidate["id"]
        draft = adapter.adapt_candidate(candidate).draft
        self.assertEqual(draft.source_reference, "/api/user?id=")

    def test_candidate_missing_endpoint_refused(self):
        from aec.surface import adapter

        outcome = adapter.adapt_candidate(surface_candidate(endpoint=""))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_ENDPOINT")

    def test_candidate_invalid_input_refused(self):
        from aec.surface import adapter

        outcome = adapter.adapt_candidate(["not", "a", "mapping"])
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "INVALID_INPUT")

    def test_candidate_missing_category_refused(self):
        from aec.surface import adapter

        candidate = surface_candidate()
        del candidate["category"]
        outcome = adapter.adapt_candidate(candidate)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_CATEGORY")

    def test_empty_reasons_ok(self):
        from aec.surface import adapter

        draft = adapter.adapt_candidate(surface_candidate(reasons=[])).draft
        self.assertEqual(draft.classification_notes, ("MEDIUM",))

    def test_non_string_technology_ignored(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(
            surface_record(technology="php"), default_category="idor"
        ).draft
        self.assertEqual(draft.technology, ())

    def test_non_string_parameter_treated_empty(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(
            surface_record(parameter=42), default_category="idor"
        ).draft
        self.assertEqual(draft.parameters, ())

    def test_gap_required_equals_missing_fresh(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertEqual(
            draft.evidence_gap["required"], draft.evidence_gap["missing"]
        )

    def test_outcome_refusal_has_no_draft(self):
        from aec.surface import adapter

        outcome = adapter.adapt_record(None)
        self.assertIsNone(outcome.draft)
        self.assertEqual(outcome.refusal_code, "INVALID_INPUT")

    def test_whitespace_endpoint_carried_verbatim(self):
        from aec.surface import adapter

        # Empty-string check is exact; whitespace passes the gate but is
        # carried verbatim — pinned so a future trim changes this test.
        outcome = adapter.adapt_record(
            surface_record(endpoint="   "), default_category="idor"
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.draft.endpoint, "   ")

    def test_case_kwargs_evidence_gap_none(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertIsNone(adapter.to_case_kwargs(draft)["evidence_gap"])

    def test_case_kwargs_program_pilot(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertEqual(adapter.to_case_kwargs(draft)["program"], "pilot")

    def test_case_kwargs_method_carried(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(
            surface_record(method="HEAD"), default_category="idor"
        ).draft
        self.assertEqual(adapter.to_case_kwargs(draft)["method"], "HEAD")

    def test_serialize_keys_sorted(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        text = adapter.serialize_draft(draft)
        self.assertLess(text.index('"asset"'), text.index('"endpoint"'))

    def test_candidate_and_record_same_surface_same_id_shape(self):
        from aec.surface import adapter

        record_draft = adapter.adapt_record(
            surface_record(), default_category="idor"
        ).draft
        candidate_draft = adapter.adapt_candidate(surface_candidate()).draft
        for draft in (record_draft, candidate_draft):
            self.assertTrue(draft.candidate_id.startswith("rc-"))
            self.assertEqual(draft.research_category, "idor")


    def test_research_category_key_accepted(self):
        from aec.surface import adapter

        record = surface_record()
        record["research_category"] = "ssrf"
        draft = adapter.adapt_record(record).draft
        self.assertEqual(draft.research_category, "ssrf")

    def test_source_fallback_watch(self):
        from aec.surface import adapter

        record = surface_record(url="", source="")
        record["source"] = ""
        draft = adapter.adapt_record(record, default_category="idor").draft
        self.assertEqual(draft.source_reference, "watch")

    def test_suffix_only_category_refused(self):
        from aec.surface import adapter

        # "_candidate" strips to an empty token: nothing was named.
        outcome = adapter.adapt_record(
            surface_record(), default_category="_candidate"
        )
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_CATEGORY")

    def test_numeric_category_refused(self):
        from aec.surface import adapter

        outcome = adapter.adapt_record(surface_record(), default_category=42)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal_code, "MISSING_CATEGORY")

    def test_list_parameters_preserved_shape(self):
        from aec.surface import adapter

        candidate = surface_candidate(parameter="q")
        draft = adapter.adapt_candidate(candidate).draft
        self.assertEqual(draft.parameters, ("q",))

    def test_adapt_record_ignores_extra_keys(self):
        from aec.surface import adapter

        record = surface_record(extra_key="extra_value", score=99)
        draft = adapter.adapt_record(record, default_category="xss").draft
        self.assertNotIn("extra_key", draft.to_dict())
        self.assertEqual(draft.research_category, "xss")

    def test_draft_equality_by_value(self):
        from aec.surface import adapter

        first = adapter.adapt_record(surface_record(), default_category="idor").draft
        second = adapter.adapt_record(surface_record(), default_category="idor").draft
        self.assertEqual(first, second)

    def test_adapt_candidate_technology_normalized(self):
        from aec.surface import adapter

        draft = adapter.adapt_candidate(
            surface_candidate(technology=["PHP", "php", ""])
        ).draft
        self.assertEqual(draft.technology, ("php",))

    def test_case_kwargs_confidence_neutral(self):
        from aec.surface import adapter

        draft = adapter.adapt_record(surface_record(), default_category="idor").draft
        # Neutral default: the adapter makes no claim about the surface.
        self.assertEqual(adapter.to_case_kwargs(draft)["confidence"], "MEDIUM")

    def test_outcome_equality_by_value(self):
        from aec.surface import adapter

        self.assertEqual(
            adapter.adapt_record(surface_record(), default_category="idor"),
            adapter.adapt_record(surface_record(), default_category="idor"),
        )

    def test_subdomain_preferred_over_asset(self):
        from aec.surface import adapter

        record = surface_record(subdomain="sub.example.com")
        record["asset"] = "other.example.com"
        draft = adapter.adapt_record(record, default_category="idor").draft
        self.assertEqual(draft.asset, "sub.example.com")

    def test_known_categories_closed(self):
        from aec.surface import models

        self.assertEqual(
            set(models.KNOWN_CATEGORIES),
            {"idor", "xss", "ssrf", "file_upload", "authz"},
        )

    def test_refusal_codes_closed(self):
        from aec.surface import models

        self.assertEqual(
            set(models.REFUSAL_CODES),
            {
                "INVALID_INPUT", "MISSING_ENDPOINT", "MISSING_ASSET",
                "MISSING_CATEGORY", "UNKNOWN_CATEGORY",
            },
        )


if __name__ == "__main__":
    unittest.main()
