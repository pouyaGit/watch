"""tests/test_product_api_contract.py — Stage R28.2 v1 contract tests.

Uses synthetic API JSON only. Imports ONLY the external client contract
module (never Watch internal schemas) to prove the public boundary is
self-contained.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, "/opt/watch")

from clients import product_api_contract as contract


def valid_item(**over):
    item = {
        "opportunity_id": "op-27deff4809384156",
        "lead_id": "rl-af7ecfba1a86fc83",
        "cve_id": "CVE-2026-1557",
        "program": "dell",
        "opportunity_class": "BLOCKED",
        "money_score": 53,
        "money_priority": "P3_MEDIUM",
        "confidence": "HIGH",
        "evidence_quality": "HIGH",
        "estimated_minutes": 90,
        "current_status": "BLOCKED",
        "recommended_action": "VERIFY_ASSET_MATCH",
        "why_now": ["PUBLIC_POC", "EXPLOIT_AVAILABLE"],
        "why_valuable": ["research priority score 80"],
        "blockers": ["only generic technology match"],
        "next_step": "Confirm affected component/plugin presence.",
        "research_status": "RESEARCH_COMPLETED",
        "outcome_status": "NONE",
        "session_status": "NONE",
        "research_only": True,
        "api_version": "v1",
    }
    item.update(over)
    return item


def envelope(**over):
    body = {
        "api_version": "v1",
        "research_only": True,
        "total": 1,
        "offset": 0,
        "limit": 50,
        "items": [valid_item()],
    }
    body.update(over)
    return body


def summary(**over):
    body = {
        "api_version": "v1",
        "research_only": True,
        "total": 1,
        "by_class": {"BLOCKED": 1},
        "by_action": {"VERIFY_ASSET_MATCH": 1},
        "by_status": {"BLOCKED": 1},
        "top_opportunities": [valid_item()],
    }
    body.update(over)
    return body


def research_status(**over):
    body = {
        "api_version": "v1",
        "research_only": True,
        "product_api_version": "v1",
        "opportunity_count": 2,
        "ready_count": 0,
        "blocked_count": 2,
        "in_progress_count": 0,
        "completed_count": 0,
        "evidence_available": True,
        "outcomes_available": False,
        "sessions_available": False,
    }
    body.update(over)
    return body


class TestOpportunityContract(unittest.TestCase):
    def test_exact_field_set(self):
        self.assertEqual(len(contract.REQUIRED_FIELDS), 21)
        self.assertEqual(set(contract.FIELD_SET),
                         set(contract.REQUIRED_FIELDS))
        contract.validate_opportunity(valid_item())

    def test_missing_field_rejected(self):
        item = valid_item()
        del item["money_score"]
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(item)

    def test_extra_field_rejected(self):
        item = valid_item()
        item["extra_internal_field"] = 1
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(item)

    def test_forbidden_fields_rejected(self):
        for field in contract.FORBIDDEN_FIELDS:
            with self.subTest(field=field):
                item = valid_item()
                item[field] = "x"
                with self.assertRaises(contract.ContractError):
                    contract.validate_opportunity(item)

    def test_wrong_api_version(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(valid_item(api_version="v2"))
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(valid_item(api_version=""))

    def test_research_only_false(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(valid_item(research_only=False))

    def test_invalid_money_score(self):
        for bad in (-1, 101, "53", 53.0, True, None):
            with self.subTest(bad=bad):
                with self.assertRaises(contract.ContractError):
                    contract.validate_opportunity(
                        valid_item(money_score=bad))

    def test_invalid_priority(self):
        for bad in ("P9_HIGH", "P3", "p3_medium", "", "P3_low-"):
            with self.subTest(bad=bad):
                with self.assertRaises(contract.ContractError):
                    contract.validate_opportunity(
                        valid_item(money_priority=bad))

    def test_invalid_opportunity_class(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(
                valid_item(opportunity_class="VULNERABLE"))
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(
                valid_item(opportunity_class="SOMETHING"))

    def test_invalid_action(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(
                valid_item(recommended_action="EXECUTE"))
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(
                valid_item(recommended_action="SCAN"))

    def test_invalid_status_and_quality(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(
                valid_item(current_status="RUNNING"))
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(
                valid_item(confidence="SURE"))
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(
                valid_item(evidence_quality="MAYBE"))

    def test_invalid_ids_and_lists(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(valid_item(lead_id="lead-1"))
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(valid_item(cve_id="1234"))
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(
                valid_item(why_now="not-a-list"))
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(valid_item(blockers=[1, 2]))

    def test_negative_estimated_minutes(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_opportunity(
                valid_item(estimated_minutes=-1))

    def test_deterministic_parsing(self):
        first = contract.validate_opportunity(valid_item())
        second = contract.validate_opportunity(valid_item())
        self.assertEqual(first, second)
        self.assertEqual(list(first.keys()), list(second.keys()))


class TestEnvelopeContract(unittest.TestCase):
    def test_list_envelope(self):
        contract.validate_list_envelope(envelope())
        contract.validate_list_envelope(envelope(items=[]))

    def test_list_envelope_bad_items(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_list_envelope(envelope(items=[{"bad": 1}]))
        with self.assertRaises(contract.ContractError):
            contract.validate_list_envelope(
                envelope(items=[valid_item(api_version="v2")]))

    def test_list_envelope_missing_fields(self):
        body = envelope()
        del body["total"]
        with self.assertRaises(contract.ContractError):
            contract.validate_list_envelope(body)
        with self.assertRaises(contract.ContractError):
            contract.validate_list_envelope(envelope(api_version="v2"))
        with self.assertRaises(contract.ContractError):
            contract.validate_list_envelope(envelope(research_only=False))

    def test_limit_bounds(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_list_envelope(envelope(limit=0))
        with self.assertRaises(contract.ContractError):
            contract.validate_list_envelope(envelope(limit=101))

    def test_detail(self):
        contract.validate_detail(valid_item())
        with self.assertRaises(contract.ContractError):
            contract.validate_detail({"api_version": "v1"})

    def test_summary(self):
        contract.validate_summary(summary())
        with self.assertRaises(contract.ContractError):
            contract.validate_summary(summary(research_only=False))
        missing = summary()
        del missing["by_class"]
        with self.assertRaises(contract.ContractError):
            contract.validate_summary(missing)

    def test_research_status(self):
        contract.validate_research_status(research_status())
        with self.assertRaises(contract.ContractError):
            contract.validate_research_status(
                research_status(product_api_version="v2"))
        with self.assertRaises(contract.ContractError):
            contract.validate_research_status(
                research_status(evidence_available="yes"))

    def test_error_envelope(self):
        body = {"api_version": "v1", "research_only": True,
                "error": {"code": "NOT_FOUND",
                          "message": "research opportunity not found"}}
        contract.validate_error_envelope(body)
        with self.assertRaises(contract.ContractError):
            contract.validate_error_envelope(
                {"api_version": "v1", "research_only": True,
                 "error": {"code": "TEAPOT", "message": "x"}})
        with self.assertRaises(contract.ContractError):
            contract.validate_error_envelope(
                {"api_version": "v1", "research_only": True,
                 "error": {"code": "NOT_FOUND"}})

    def test_contract_error_has_code(self):
        exc = contract.ContractError("boom")
        self.assertEqual(exc.code, "CONTRACT_ERROR")


class TestBoundary(unittest.TestCase):
    def test_no_internal_imports(self):
        import ast
        for rel in ("clients/product_api_contract.py",
                    "clients/product_api_client.py",
                    "clients/__init__.py"):
            source = (Path("/opt/watch") / rel).read_text(encoding="utf-8")
            tree = ast.parse(source)
            modules: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    modules.append(node.module)
            for module in modules:
                self.assertFalse(
                    module.startswith("backend")
                    or module.startswith("ai."),
                    f"{rel} imports internal module {module!r}")

    def test_contract_version_pinned(self):
        self.assertEqual(contract.PRODUCT_API_VERSION, "v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
