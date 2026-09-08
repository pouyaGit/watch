"""Focused tests for the deterministic Target Matcher (Phase 3B).

MATCH != VULNERABLE: these tests prove the matcher joins research
patterns with target intelligence into read-only RELEVANCE
statements with no finding, verdict, scope, execution, LLM,
network, subprocess, or database authority. Fixtures build real
Phase 2A patterns (via factories) and real Phase 3A
TargetIntelligence (via the read-only projector).
"""

import ast
import unittest
from pathlib import Path

from pydantic import ValidationError

from ai.correlator.version import evaluate_version_constraint
from ai.researcher import target_matcher as matcher_module
from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ParamRecord,
    ProgramRecord,
    SubdomainRecord,
    UrlRecord,
    project_subdomain,
)
from ai.researcher.target_matcher import (
    match_pattern_to_target,
    match_patterns_to_target,
)
from ai.schemas.hypothesis import ResearchProvenance
from ai.schemas.research_pattern import (
    build_attack_pattern,
    build_vulnerability_pattern,
)
from ai.schemas.target_match import (
    MATCHER_VERSION,
    TargetPatternMatch,
    deterministic_score_for,
    match_id_for,
)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


def _provenance(tag="a"):
    import hashlib
    digest = hashlib.sha256(tag.encode("utf-8")).hexdigest()[:16]
    return ResearchProvenance(claim_ids=["clm-" + digest])


def _vuln(products=None, constraints=None, surface=None, tag="a",
           kind="PRODUCT_VULNERABILITY", vuln_ids=None):
    facts = {}
    if products is not None:
        facts["products"] = products
    if constraints is not None:
        facts["version_constraints"] = constraints
    if surface is not None:
        facts["attack_surface"] = surface
    if vuln_ids is not None:
        facts["vulnerability_ids"] = vuln_ids
    if not facts.get("products") and not facts.get("vulnerability_ids"):
        facts["products"] = [{"product": "FooCMS"}]
    return build_vulnerability_pattern(
        pattern_kind=kind,
        title="Research pattern",
        description="Deterministic test pattern.",
        facts=facts,
        provenance=_provenance(tag),
    )


def _attack(technique="stored xss", context=None, sinks=None,
            observables=None, tag="b"):
    facts = {"technique": technique}
    if context is not None:
        facts["technology_context"] = context
    if sinks is not None:
        facts["sink_characteristics"] = sinks
    if observables is not None:
        facts["expected_observables"] = [
            {"observation_kind": "behavior", "description": label}
            for label in observables
        ]
    if not sinks and not observables:
        facts["sink_characteristics"] = ["html body"]
    return build_attack_pattern(
        pattern_kind="TECHNIQUE",
        title="Attack technique",
        description="Deterministic test technique.",
        facts=facts,
        provenance=_provenance(tag),
    )


def _target(program="acme", sub="app.acme.com", tech=("FooCMS:4.1.0",),
            urls=(), endpoints=()):
    prog = ProgramRecord(
        program_name=program, scopes=[program + ".com"],
        ooscopes=[], record_id="prog-" + program,
    )
    subrec = SubdomainRecord(
        program_name=program, subdomain=sub, scope=program + ".com",
        record_id="sub-" + sub,
    )
    https = []
    if tech is not None:
        https.append(
            HttpRecord(
                program_name=program, subdomain=sub,
                tech=list(tech), record_id="http-" + sub,
            )
        )
    return project_subdomain(
        prog, subrec, https=https, urls=list(urls),
        endpoints=list(endpoints),
    ).intelligence


def _endpoint(program="acme", sub="app.acme.com", path="/search",
              params=("q",), details=None, record_id="ep-1"):
    if details is None:
        details = (
            ParamRecord(
                name="q", method="GET", location="query",
                source="crawl",
            ),
        )
    return EndpointRecord(
        program_name=program, subdomain=sub, path=path,
        example_url=f"https://{sub}{path}",
        params=params, param_records=details, record_id=record_id,
    )


def _url(program="acme", sub="app.acme.com",
         url="https://app.acme.com/search?q=x", record_id="url-1"):
    return UrlRecord(
        program_name=program, subdomain=sub, url=url,
        path="/search", params=["q"], sources=["katana"],
        record_id=record_id,
    )


def _imports_of(module_path):
    tree = ast.parse(Path(module_path).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


# ------------------------------------------------------------------
# Contract
# ------------------------------------------------------------------


class MatchContractTests(unittest.TestCase):
    def test_valid_match(self):
        target = _target()
        pattern = _vuln()
        result = match_pattern_to_target(pattern, target)
        self.assertIsInstance(result, TargetPatternMatch)
        self.assertEqual(result.pattern_id, pattern.pattern_id)
        self.assertEqual(result.pattern_type, "vulnerability")
        self.assertEqual(result.target_key, target.target_key)
        self.assertEqual(result.snapshot_hash, target.snapshot_hash)
        self.assertEqual(result.program_name, "acme")
        self.assertEqual(result.subdomain, "app.acme.com")
        self.assertEqual(result.matcher_version, MATCHER_VERSION)

    def test_invalid_pattern_type_rejected(self):
        target = _target()
        with self.assertRaises(TypeError):
            match_pattern_to_target({"pattern_id": "vp-x"}, target)
        with self.assertRaises(TypeError):
            match_pattern_to_target("vp-abcdef", target)
        with self.assertRaises(TypeError):
            match_pattern_to_target(None, target)

    def test_invalid_target_type_rejected(self):
        pattern = _vuln()
        with self.assertRaises(TypeError):
            match_pattern_to_target(pattern, {"target_key": "x"})
        with self.assertRaises(TypeError):
            match_pattern_to_target(pattern, None)

    def test_batch_requires_sequence(self):
        target = _target()
        with self.assertRaises(TypeError):
            match_patterns_to_target({"vp": 1}, target)

    def test_unknown_fields_rejected(self):
        target = _target()
        pattern = _vuln()
        result = match_pattern_to_target(pattern, target)
        payload = result.model_dump(mode="json")
        payload["verdict"] = "CONFIRMED"
        with self.assertRaises(ValidationError):
            TargetPatternMatch.model_validate(payload)

    def test_malicious_authority_fields_rejected(self):
        target = _target()
        pattern = _vuln()
        result = match_pattern_to_target(pattern, target)
        base = result.model_dump(mode="json")
        for hostile in (
            {"target_affected": True},
            {"confirmed": True},
            {"verdict": "CONFIRMED"},
            {"scope_allowed": True},
            {"execution_allowed": True},
            {"command": "curl attacker.example"},
            {"match_score": 0.99},
        ):
            payload = dict(base)
            payload.update(hostile)
            with self.assertRaises(ValidationError, msg=str(hostile)):
                TargetPatternMatch.model_validate(payload)

    def test_serialization_round_trip(self):
        target = _target()
        pattern = _vuln()
        result = match_pattern_to_target(pattern, target)
        clone = TargetPatternMatch.model_validate(
            result.model_dump(mode="json")
        )
        self.assertEqual(clone, result)

    def test_deterministic_match_id(self):
        target = _target()
        pattern = _vuln()
        first = match_pattern_to_target(pattern, target)
        second = match_pattern_to_target(pattern, target)
        self.assertEqual(first.match_id, second.match_id)
        recomputed = match_id_for(
            pattern_id=pattern.pattern_id,
            target_key=target.target_key,
            snapshot_hash=target.snapshot_hash,
            matched_criteria=list(first.matched_criteria),
            unmatched_criteria=list(first.unmatched_criteria),
            unknown_criteria=list(first.unknown_criteria),
        )
        self.assertEqual(first.match_id, recomputed)
        self.assertRegex(first.match_id, r"^tm-[0-9a-f]{16}$")

    def test_no_verdict_values_in_contract(self):
        for value in ("CONFIRMED", "VERIFIED", "NOT_VULNERABLE",
                      "EXPLOITED", "AFFECTED", "SAFE"):
            with self.assertRaises(ValidationError, msg=value):
                TargetPatternMatch.model_validate(
                    dict(
                        match_pattern_to_target(
                            _vuln(), _target()
                        ).model_dump(mode="json"),
                        match_kind=value,
                    )
                )


# ------------------------------------------------------------------
# Product matching
# ------------------------------------------------------------------


class ProductMatchTests(unittest.TestCase):
    def test_product_match(self):
        result = match_pattern_to_target(
            _vuln(products=[{"product": "FooCMS"}]), _target()
        )
        self.assertIn("product", result.matched_criteria)
        self.assertNotIn("product", result.unmatched_criteria)

    def test_product_mismatch_is_no_match(self):
        result = match_pattern_to_target(
            _vuln(products=[{"product": "BarCMS"}]), _target()
        )
        self.assertEqual(result.match_kind, "NO_MATCH")
        self.assertIn("product", result.unmatched_criteria)

    def test_case_normalization(self):
        result = match_pattern_to_target(
            _vuln(products=[{"product": "foocms"}]), _target()
        )
        self.assertIn("product", result.matched_criteria)

    def test_product_alias_match(self):
        result = match_pattern_to_target(
            _vuln(products=[{
                "product": "Apache HTTP Server",
                "aliases": ["Apache"],
            }]),
            _target(tech=("Apache:2.4.59",)),
        )
        self.assertIn("product", result.matched_criteria)

    def test_unrelated_product_no_match(self):
        result = match_pattern_to_target(
            _vuln(products=[{"product": "WordPress"}]),
            _target(tech=("nginx:1.24.0",)),
        )
        self.assertEqual(result.match_kind, "NO_MATCH")

    def test_generic_technology_does_not_overmatch(self):
        # "Python" must not match an unrelated package product.
        result = match_pattern_to_target(
            _vuln(products=[{"product": "GitPython"}]),
            _target(tech=("Python:3.11.0",)),
        )
        self.assertEqual(result.match_kind, "NO_MATCH")

    def test_multiple_technologies(self):
        target = _target(
            tech=("nginx:1.24.0", "php:8.1.0", "laravel:10.0.0")
        )
        result = match_pattern_to_target(
            _vuln(products=[{"product": "Laravel"}]), target
        )
        self.assertIn("product", result.matched_criteria)

    def test_duplicate_technology_observations(self):
        target = _target(tech=("FooCMS:4.1.0", "FooCMS:4.1.0"))
        result = match_pattern_to_target(
            _vuln(products=[{"product": "FooCMS"}]), target
        )
        self.assertIn("product", result.matched_criteria)
        self.assertEqual(result.match_kind, "MATCH")

    def test_no_substring_match(self):
        result = match_pattern_to_target(
            _vuln(products=[{"product": "Foo"}]), _target()
        )
        self.assertEqual(result.match_kind, "NO_MATCH")


# ------------------------------------------------------------------
# Version matching (constraint evaluator + matcher wiring)
# ------------------------------------------------------------------


class VersionConstraintUnitTests(unittest.TestCase):
    def test_exact_match(self):
        outcome = evaluate_version_constraint(
            "4.2.1", constraint_kind="EXACT", version="4.2.1"
        )
        self.assertEqual(outcome.status, "MATCH")

    def test_exact_mismatch(self):
        outcome = evaluate_version_constraint(
            "4.2.2", constraint_kind="EXACT", version="4.2.1"
        )
        self.assertEqual(outcome.status, "MISMATCH")

    def test_lower_bound(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.5.0", constraint_kind="LOWER_BOUND",
                version="4.0.0",
            ).status, "MATCH",
        )
        self.assertEqual(
            evaluate_version_constraint(
                "3.9.0", constraint_kind="LOWER_BOUND",
                version="4.0.0",
            ).status, "MISMATCH",
        )

    def test_upper_bound(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.1.0", constraint_kind="UPPER_BOUND",
                version="4.2.1", upper_inclusive=True,
            ).status, "MATCH",
        )
        self.assertEqual(
            evaluate_version_constraint(
                "4.5.0", constraint_kind="UPPER_BOUND",
                version="4.2.1", upper_inclusive=True,
            ).status, "MISMATCH",
        )

    def test_range(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.1.0", constraint_kind="RANGE", version="4.0.0",
                upper_version="4.2.1",
            ).status, "MATCH",
        )
        self.assertEqual(
            evaluate_version_constraint(
                "4.5.0", constraint_kind="RANGE", version="4.0.0",
                upper_version="4.2.1",
            ).status, "MISMATCH",
        )

    def test_inclusive_lower(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.0.0", constraint_kind="RANGE", version="4.0.0",
                upper_version="4.2.1", lower_inclusive=True,
            ).status, "MATCH",
        )

    def test_exclusive_lower(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.0.0", constraint_kind="RANGE", version="4.0.0",
                upper_version="4.2.1", lower_inclusive=False,
            ).status, "MISMATCH",
        )

    def test_inclusive_upper(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.2.1", constraint_kind="UPPER_BOUND",
                version="4.2.1", upper_inclusive=True,
            ).status, "MATCH",
        )

    def test_exclusive_upper(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.2.1", constraint_kind="UPPER_BOUND",
                version="4.2.1", upper_inclusive=False,
            ).status, "MISMATCH",
        )

    def test_unknown_constraint(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.1.0", constraint_kind="UNKNOWN"
            ).status, "INCONCLUSIVE",
        )

    def test_unknown_target_version(self):
        self.assertEqual(
            evaluate_version_constraint(
                None, constraint_kind="EXACT", version="4.2.1"
            ).status, "INCONCLUSIVE",
        )

    def test_malformed_versions_are_inconclusive(self):
        self.assertEqual(
            evaluate_version_constraint(
                "not a version!!!", constraint_kind="EXACT",
                version="4.2.1",
            ).status, "INCONCLUSIVE",
        )
        self.assertEqual(
            evaluate_version_constraint(
                "4.1.0", constraint_kind="EXACT",
                version="also bad!!!",
            ).status, "INCONCLUSIVE",
        )

    def test_fixed_newer_is_mismatch(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.2.2", constraint_kind="FIXED", version="4.2.2"
            ).status, "MISMATCH",
        )
        self.assertEqual(
            evaluate_version_constraint(
                "5.0.0", constraint_kind="FIXED", version="4.2.2"
            ).status, "MISMATCH",
        )

    def test_fixed_older_is_inconclusive_never_match(self):
        outcome = evaluate_version_constraint(
            "4.1.0", constraint_kind="FIXED", version="4.2.2"
        )
        self.assertEqual(outcome.status, "INCONCLUSIVE")

    def test_unknown_kind_is_inconclusive(self):
        self.assertEqual(
            evaluate_version_constraint(
                "4.1.0", constraint_kind="SOMETHING_ELSE"
            ).status, "INCONCLUSIVE",
        )


class VersionMatchTests(unittest.TestCase):
    def _match(self, constraints, tech=("FooCMS:4.1.0",)):
        return match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                constraints=constraints,
            ),
            _target(tech=tech),
        )

    def test_upper_bound_match(self):
        result = self._match([{
            "constraint_kind": "UPPER_BOUND", "version": "4.2.1",
            "upper_inclusive": True,
        }])
        self.assertEqual(result.match_kind, "MATCH")
        self.assertIn("version", result.matched_criteria)

    def test_upper_bound_mismatch_is_no_match(self):
        result = self._match(
            [{
                "constraint_kind": "UPPER_BOUND",
                "version": "4.2.1", "upper_inclusive": True,
            }],
            tech=("FooCMS:4.5.0",),
        )
        self.assertEqual(result.match_kind, "NO_MATCH")
        self.assertIn("version", result.unmatched_criteria)

    def test_exact_match(self):
        result = self._match([{
            "constraint_kind": "EXACT", "version": "4.1.0",
        }])
        self.assertEqual(result.match_kind, "MATCH")

    def test_exact_mismatch(self):
        result = self._match(
            [{"constraint_kind": "EXACT", "version": "4.2.1"}]
        )
        self.assertEqual(result.match_kind, "NO_MATCH")

    def test_lower_bound(self):
        result = self._match([{
            "constraint_kind": "LOWER_BOUND", "version": "4.0.0",
        }])
        self.assertEqual(result.match_kind, "MATCH")

    def test_range(self):
        result = self._match([{
            "constraint_kind": "RANGE", "version": "4.0.0",
            "upper_version": "4.2.1",
        }])
        self.assertEqual(result.match_kind, "MATCH")

    def test_exclusive_bounds_honored(self):
        matched = self._match([{
            "constraint_kind": "RANGE", "version": "4.0.0",
            "upper_version": "4.1.0", "upper_inclusive": True,
        }])
        self.assertEqual(matched.match_kind, "MATCH")
        missed = self._match(
            [{
                "constraint_kind": "RANGE", "version": "4.0.0",
                "upper_version": "4.1.0", "upper_inclusive": False,
            }]
        )
        self.assertEqual(missed.match_kind, "NO_MATCH")

    def test_fixed_at_or_newer_is_no_match(self):
        result = self._match(
            [{"constraint_kind": "FIXED", "version": "4.1.0"}]
        )
        self.assertEqual(result.match_kind, "NO_MATCH")

    def test_fixed_older_is_not_a_match(self):
        result = self._match(
            [{"constraint_kind": "FIXED", "version": "4.2.2"}]
        )
        self.assertNotEqual(result.match_kind, "MATCH")
        self.assertIn("version", result.unknown_criteria)

    def test_unknown_constraint_is_unknown(self):
        result = self._match(
            [{"constraint_kind": "UNKNOWN", "raw": "unclear"}]
        )
        self.assertIn("version", result.unknown_criteria)
        self.assertEqual(result.match_kind, "INCONCLUSIVE")

    def test_unknown_target_version_is_inconclusive(self):
        result = self._match(
            [{
                "constraint_kind": "UPPER_BOUND",
                "version": "4.2.1", "upper_inclusive": True,
            }],
            tech=("FooCMS",),
        )
        self.assertEqual(result.match_kind, "INCONCLUSIVE")
        self.assertIn("version", result.unknown_criteria)

    def test_malformed_target_version_is_inconclusive(self):
        # "1.2.x" passes the observation token filter and still
        # product-matches, but packaging cannot parse it: the
        # comparator must yield INCONCLUSIVE, never a guess.
        result = self._match(
            [{"constraint_kind": "EXACT", "version": "4.2.1"}],
            tech=("FooCMS:1.2.x",),
        )
        self.assertEqual(result.match_kind, "INCONCLUSIVE")
        self.assertIn("version", result.unknown_criteria)

    def test_malformed_constraint_version_is_inconclusive(self):
        outcome = evaluate_version_constraint(
            "4.1.0", constraint_kind="UPPER_BOUND",
            version="9" * 64 + "!!!",
        )
        self.assertEqual(outcome.status, "INCONCLUSIVE")

    def test_product_mismatch_with_version_match(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "BarCMS"}],
                constraints=[{
                    "constraint_kind": "EXACT", "version": "4.1.0",
                }],
            ),
            _target(),
        )
        self.assertEqual(result.match_kind, "NO_MATCH")
        self.assertIn("product", result.unmatched_criteria)
        self.assertNotIn("version", result.matched_criteria)

    def test_product_match_with_unknown_version(self):
        result = self._match(
            [{
                "constraint_kind": "UPPER_BOUND",
                "version": "4.2.1", "upper_inclusive": True,
            }],
            tech=("FooCMS",),
        )
        self.assertEqual(result.match_kind, "INCONCLUSIVE")
        self.assertNotEqual(result.match_kind, "MATCH")

    def test_version_without_product_anchor_never_matches(self):
        pattern = build_vulnerability_pattern(
            pattern_kind="VULNERABILITY",
            title="CVE pattern",
            description="Identifier-anchored pattern.",
            facts={
                "vulnerability_ids": ["CVE-2026-12345"],
                "version_constraints": [{
                    "constraint_kind": "EXACT", "version": "4.1.0",
                }],
            },
            provenance=_provenance("c"),
        )
        result = match_pattern_to_target(pattern, _target())
        self.assertNotEqual(result.match_kind, "MATCH")
        self.assertIn("version", result.unknown_criteria)


# ------------------------------------------------------------------
# Attack surface
# ------------------------------------------------------------------


class AttackSurfaceTests(unittest.TestCase):
    def _target_with_endpoint(self, **overrides):
        return _target(endpoints=[_endpoint(**overrides)])

    def test_path_match(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/search",
                }],
            ),
            self._target_with_endpoint(),
        )
        self.assertIn("path", result.matched_criteria)

    def test_path_mismatch(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/admin",
                }],
            ),
            self._target_with_endpoint(),
        )
        self.assertIn("path", result.unmatched_criteria)

    def test_method_match(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/search",
                    "method": "GET",
                }],
            ),
            self._target_with_endpoint(),
        )
        self.assertIn("method", result.matched_criteria)

    def test_method_mismatch(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/search",
                    "method": "POST",
                }],
            ),
            self._target_with_endpoint(),
        )
        self.assertIn("method", result.unmatched_criteria)

    def test_parameter_match(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "parameter",
                    "parameter": "q",
                }],
            ),
            self._target_with_endpoint(),
        )
        self.assertIn("parameter", result.matched_criteria)

    def test_parameter_mismatch(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "parameter",
                    "parameter": "bio",
                }],
            ),
            self._target_with_endpoint(),
        )
        self.assertIn("parameter", result.unmatched_criteria)

    def test_parameter_location_match(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "parameter",
                    "parameter": "q",
                    "parameter_location": "query",
                }],
            ),
            self._target_with_endpoint(),
        )
        self.assertIn("parameter_location", result.matched_criteria)

    def test_unrepresentable_location_is_unknown(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "parameter",
                    "parameter": "q",
                    "parameter_location": "cookie",
                }],
            ),
            self._target_with_endpoint(),
        )
        self.assertIn("parameter_location", result.unknown_criteria)
        self.assertNotIn(
            "parameter_location", result.matched_criteria
        )

    def test_endpoint_mismatch_with_product_is_partial(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/admin",
                }],
            ),
            self._target_with_endpoint(),
        )
        self.assertEqual(result.match_kind, "PARTIAL_MATCH")

    def test_multiple_endpoints(self):
        target = _target(endpoints=[
            _endpoint(path="/search", record_id="ep-1"),
            _endpoint(
                path="/profile", params=("bio",),
                details=(
                    ParamRecord(
                        name="bio", method="POST",
                        location="body", source="x8",
                    ),
                ),
                record_id="ep-2",
            ),
        ])
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/profile",
                    "method": "POST",
                    "parameter": "bio",
                    "parameter_location": "body",
                }],
            ),
            target,
        )
        for criterion in (
            "path", "method", "parameter", "parameter_location"
        ):
            self.assertIn(criterion, result.matched_criteria)

    def test_url_observations_feed_surface(self):
        target = _target(urls=[_url()])
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/search",
                }],
            ),
            target,
        )
        self.assertIn("path", result.matched_criteria)


# ------------------------------------------------------------------
# Attack patterns
# ------------------------------------------------------------------


class AttackPatternTests(unittest.TestCase):
    def test_technology_context_match_is_partial(self):
        result = match_pattern_to_target(
            _attack(context=["FooCMS"]), _target()
        )
        self.assertIn("technology_context", result.matched_criteria)
        # Technique content has no target representation: an attack
        # pattern can never claim a full MATCH.
        self.assertEqual(result.match_kind, "PARTIAL_MATCH")
        self.assertIn("technique", result.unknown_criteria)

    def test_technology_context_mismatch(self):
        result = match_pattern_to_target(
            _attack(context=["BarCMS"]), _target()
        )
        self.assertEqual(result.match_kind, "NO_MATCH")
        self.assertIn(
            "technology_context", result.unmatched_criteria
        )

    def test_technique_alone_is_inconclusive(self):
        pattern = build_attack_pattern(
            pattern_kind="TECHNIQUE",
            title="Bare technique",
            description="No context, only sink.",
            facts={
                "technique": "stored xss",
                "sink_characteristics": ["html body"],
            },
            provenance=_provenance("d"),
        )
        result = match_pattern_to_target(pattern, _target())
        self.assertEqual(result.match_kind, "INCONCLUSIVE")

    def test_attack_never_full_match(self):
        target = _target()
        pattern = _attack(context=["FooCMS"])
        result = match_pattern_to_target(pattern, target)
        self.assertNotEqual(result.match_kind, "MATCH")


# ------------------------------------------------------------------
# Result semantics
# ------------------------------------------------------------------


class ResultSemanticsTests(unittest.TestCase):
    def test_match_is_not_confirmed(self):
        target = _target()
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            constraints=[{
                "constraint_kind": "UPPER_BOUND",
                "version": "4.2.1", "upper_inclusive": True,
            }],
        )
        result = match_pattern_to_target(pattern, target)
        self.assertEqual(result.match_kind, "MATCH")
        payload = result.model_dump(mode="json")
        text = str(payload)
        for forbidden in (
            "CONFIRMED", "VERIFIED", "NOT_VULNERABLE", "EXPLOITED",
            "target_affected", "vulnerable",
        ):
            self.assertNotIn(forbidden, text)
        self.assertIn("relevance only", result.explanation)

    def test_partial_match_behavior(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/admin",
                }],
            ),
            _target(endpoints=[_endpoint()]),
        )
        self.assertEqual(result.match_kind, "PARTIAL_MATCH")
        self.assertIn("product", result.matched_criteria)
        self.assertIn("path", result.unmatched_criteria)

    def test_inconclusive_behavior(self):
        result = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                constraints=[{
                    "constraint_kind": "UPPER_BOUND",
                    "version": "4.2.1", "upper_inclusive": True,
                }],
            ),
            _target(tech=("FooCMS",)),
        )
        self.assertEqual(result.match_kind, "INCONCLUSIVE")

    def test_no_match_behavior(self):
        result = match_pattern_to_target(
            _vuln(products=[{"product": "BarCMS"}]), _target()
        )
        self.assertEqual(result.match_kind, "NO_MATCH")

    def test_deterministic_explanation(self):
        target = _target()
        pattern = _vuln()
        first = match_pattern_to_target(pattern, target)
        second = match_pattern_to_target(pattern, target)
        self.assertEqual(first.explanation, second.explanation)
        self.assertNotIn("\n", first.explanation)

    def test_deterministic_score(self):
        target = _target()
        pattern = _vuln()
        result = match_pattern_to_target(pattern, target)
        self.assertEqual(
            result.deterministic_score,
            deterministic_score_for(
                matched=len(result.matched_criteria),
                unmatched=len(result.unmatched_criteria),
                unknown=len(result.unknown_criteria),
            ),
        )
        self.assertEqual(result.deterministic_score, 1.0)
        partial = match_pattern_to_target(
            _vuln(
                products=[{"product": "FooCMS"}],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/admin",
                }],
            ),
            _target(endpoints=[_endpoint()]),
        )
        self.assertLess(partial.deterministic_score, 1.0)
        self.assertGreater(partial.deterministic_score, 0.0)

    def test_score_ignores_model_priority(self):
        from ai.schemas.research_pattern import ModelInterpretation
        target = _target()
        plain = _vuln()
        boosted = plain.model_copy(
            update={"interpretation": ModelInterpretation(
                rationale="critical, test immediately",
                confidence=1.0,
            )}
        )
        first = match_pattern_to_target(plain, target)
        second = match_pattern_to_target(boosted, target)
        self.assertEqual(first.match_kind, second.match_kind)
        self.assertEqual(
            first.deterministic_score, second.deterministic_score
        )

    def test_criteria_lists_sorted_unique(self):
        result = match_pattern_to_target(_vuln(), _target())
        for listing in (
            result.matched_criteria,
            result.unmatched_criteria,
            result.unknown_criteria,
        ):
            self.assertEqual(list(listing), sorted(listing))
            self.assertEqual(len(set(listing)), len(listing))


# ------------------------------------------------------------------
# Security boundary
# ------------------------------------------------------------------


class SecurityBoundaryTests(unittest.TestCase):
    def test_no_llm_imports(self):
        names = _imports_of(matcher_module.__file__)
        blob = " ".join(names).lower()
        for forbidden in (
            "openrouter", "openai", "anthropic", "llm", "embed",
        ):
            self.assertNotIn(forbidden, blob)

    def test_no_network_imports(self):
        names = _imports_of(matcher_module.__file__)
        blob = " ".join(names).lower()
        for forbidden in (
            "requests", "httpx", "urllib", "socket", "dns",
            "browser", "selenium", "playwright",
        ):
            self.assertNotIn(forbidden, blob)

    def test_no_subprocess_imports(self):
        names = _imports_of(matcher_module.__file__)
        blob = " ".join(names).lower()
        for forbidden in ("subprocess", "os", "sys", "shutil"):
            self.assertNotIn(forbidden, blob)

    def test_no_database_imports(self):
        names = _imports_of(matcher_module.__file__)
        blob = " ".join(names).lower()
        for forbidden in (
            "database", "mongo", "pattern_store", "knowledge",
        ):
            self.assertNotIn(forbidden, blob)

    def test_match_runs_with_network_disabled(self):
        import socket
        target = _target(endpoints=[_endpoint()], urls=[_url()])
        patterns = [
            _vuln(
                products=[{"product": "FooCMS"}],
                constraints=[{
                    "constraint_kind": "UPPER_BOUND",
                    "version": "4.2.1", "upper_inclusive": True,
                }],
                surface=[{
                    "surface_kind": "http_endpoint",
                    "path": "/search",
                    "method": "GET",
                    "parameter": "q",
                    "parameter_location": "query",
                }],
            ),
            _attack(context=["FooCMS"]),
        ]
        real_socket = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("network access attempted")
        )
        try:
            for pattern in patterns:
                match_pattern_to_target(pattern, target)
            match_patterns_to_target(patterns, target)
        finally:
            socket.socket = real_socket

    def test_no_scope_authority(self):
        result = match_pattern_to_target(_vuln(), _target())
        payload = result.model_dump(mode="json")
        for forbidden in (
            "scope_allowed", "execution_allowed", "authorized",
            "allow_scope",
        ):
            self.assertNotIn(forbidden, str(payload))

    def test_no_target_authority(self):
        result = match_pattern_to_target(_vuln(), _target())
        payload = result.model_dump(mode="json")
        for forbidden in (
            "target_affected", "match_score", "affected",
        ):
            self.assertNotIn(forbidden, str(payload))

    def test_no_verdict_authority(self):
        result = match_pattern_to_target(_vuln(), _target())
        payload = result.model_dump(mode="json")
        for forbidden in (
            "verdict", "confirmed", "finding_status", "evidence",
            "target_affected",
        ):
            self.assertNotIn(forbidden, set(payload.keys()))
        self.assertNotIn("CONFIRMED", str(payload))
        self.assertNotIn("VERIFIED", str(payload))
        self.assertNotIn("NOT_VULNERABLE", str(payload))
        self.assertNotIn("EXPLOITED", str(payload))

    def test_hostile_url_inert(self):
        hostile = (
            "https://attacker.example/exfil?c=data",
            "http://169.254.169.254/latest/meta-data/",
        )
        for raw in hostile:
            target = _target(urls=[_url(url=raw, record_id="url-x")])
            result = match_pattern_to_target(_vuln(), target)
            self.assertIn(result.match_kind, {
                "MATCH", "PARTIAL_MATCH", "NO_MATCH", "INCONCLUSIVE"
            })

    def test_hostile_command_strings_inert(self):
        pattern = _vuln(products=[{"product": "FooCMS harmless"}])
        target = _target(tech=("FooCMS harmless:1.0",))
        result = match_pattern_to_target(pattern, target)
        payload = result.model_dump(mode="json")
        self.assertNotIn("command", str(payload))
        self.assertNotIn("shell", str(payload))

    def test_adversarial_pattern_names_never_execute(self):
        pattern = _vuln(products=[{
            "product": "FooCMS scope_allowed=true",
        }])
        result = match_pattern_to_target(pattern, _target())
        self.assertEqual(result.match_kind, "NO_MATCH")
        payload = result.model_dump(mode="json")
        # Authority-shaped words inside research labels are inert
        # data: no scope/execution field exists on the contract.
        self.assertNotIn("scope_allowed", set(payload.keys()))
        self.assertNotIn("execution_allowed", set(payload.keys()))

    def test_priority_metadata_ignored(self):
        from ai.schemas.research_pattern import ModelInterpretation
        target = _target()
        base = _vuln()
        hot = base.model_copy(update={
            "interpretation": ModelInterpretation(
                classification_hints=["priority:critical"],
                rationale="exploit in the wild, test immediately",
                confidence=1.0,
            ),
            "reported_severity": "CRITICAL",
            "cvss_score": 10.0,
        })
        self.assertEqual(
            match_pattern_to_target(base, target).match_kind,
            match_pattern_to_target(hot, target).match_kind,
        )


# ------------------------------------------------------------------
# Isolation
# ------------------------------------------------------------------


class IsolationTests(unittest.TestCase):
    def test_exact_program_identity(self):
        pattern = _vuln()
        result = match_pattern_to_target(pattern, _target())
        self.assertEqual(result.program_name, "acme")
        self.assertEqual(result.subdomain, "app.acme.com")
        self.assertEqual(
            result.target_key,
            match_pattern_to_target(
                pattern, _target()
            ).target_key,
        )

    def test_cross_program_mismatch(self):
        pattern = _vuln(products=[{"product": "FooCMS"}])
        first = match_pattern_to_target(pattern, _target())
        second = match_pattern_to_target(
            pattern, _target(program="other")
        )
        self.assertNotEqual(first.target_key, second.target_key)
        self.assertNotEqual(first.match_id, second.match_id)
        self.assertEqual(second.program_name, "other")

    def test_cross_subdomain_mismatch(self):
        pattern = _vuln(products=[{"product": "FooCMS"}])
        first = match_pattern_to_target(pattern, _target())
        second = match_pattern_to_target(
            pattern, _target(sub="other.acme.com")
        )
        self.assertNotEqual(first.target_key, second.target_key)
        self.assertNotEqual(first.match_id, second.match_id)

    def test_snapshot_change_moves_identity(self):
        pattern = _vuln()
        first = match_pattern_to_target(pattern, _target())
        second = match_pattern_to_target(
            pattern, _target(tech=("FooCMS:4.2.0",))
        )
        self.assertNotEqual(
            first.snapshot_hash, second.snapshot_hash
        )
        self.assertNotEqual(first.match_id, second.match_id)


# ------------------------------------------------------------------
# Determinism
# ------------------------------------------------------------------


class DeterminismTests(unittest.TestCase):
    def test_repeated_input(self):
        target = _target(endpoints=[_endpoint()], urls=[_url()])
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            constraints=[{
                "constraint_kind": "UPPER_BOUND",
                "version": "4.2.1", "upper_inclusive": True,
            }],
        )
        self.assertEqual(
            match_pattern_to_target(pattern, target),
            match_pattern_to_target(pattern, target),
        )

    def test_shuffled_technologies(self):
        first = _target(tech=("nginx:1.24.0", "FooCMS:4.1.0"))
        second = _target(tech=("FooCMS:4.1.0", "nginx:1.24.0"))
        pattern = _vuln()
        self.assertEqual(
            match_pattern_to_target(pattern, first),
            match_pattern_to_target(pattern, second),
        )

    def test_shuffled_endpoints(self):
        first = _target(endpoints=[
            _endpoint(path="/a", record_id="ep-a"),
            _endpoint(path="/b", record_id="ep-b"),
        ])
        second = _target(endpoints=[
            _endpoint(path="/b", record_id="ep-b"),
            _endpoint(path="/a", record_id="ep-a"),
        ])
        pattern = _vuln()
        self.assertEqual(
            match_pattern_to_target(pattern, first),
            match_pattern_to_target(pattern, second),
        )

    def test_shuffled_pattern_list(self):
        target = _target()
        patterns = [_vuln(tag="a"), _attack(tag="b"),
                    _vuln(tag="c")]
        forward = match_patterns_to_target(patterns, target)
        backward = match_patterns_to_target(
            list(reversed(patterns)), target
        )
        self.assertEqual(forward, backward)

    def test_duplicate_observations(self):
        plain = _target(tech=("FooCMS:4.1.0",))
        if hasattr(plain, "model_copy"):
            doubled = plain.model_copy(update={
                "technologies": list(plain.technologies)
                + list(plain.technologies),
            })
        else:
            doubled = plain
        pattern = _vuln()
        self.assertEqual(
            match_pattern_to_target(pattern, plain).match_kind,
            match_pattern_to_target(pattern, doubled).match_kind,
        )

    def test_patterns_independent(self):
        target = _target()
        solo = match_pattern_to_target(_vuln(tag="a"), target)
        batch = match_patterns_to_target(
            [_vuln(tag="a"), _vuln(tag="z")], target
        )
        self.assertIn(solo, batch)


# ------------------------------------------------------------------
# Integration (no database / network / LLM)
# ------------------------------------------------------------------


class IntegrationTests(unittest.TestCase):
    def test_projector_store_matcher_chain(self):
        import tempfile
        from ai.knowledge.pattern_store import PatternStore
        from ai.researcher.pattern_projector import (
            GroundedClaim,
            project_claim,
        )
        from ai.schemas.ingestion import ExtractedClaim

        claim = ExtractedClaim.model_validate({
            "evidence_class": "EXPLICIT",
            "rationale": "research notes FooCMS handling",
            "evidence_snippets": [{
                "text": "FooCMS handling",
                "section": "notes",
            }],
            "title": "FooCMS notes",
            "summary": "FooCMS research summary",
            "technologies": ["FooCMS"],
            "contexts": ["html body"],
            "techniques": [],
            "payload_patterns": [],
            "verification_patterns": [],
            "xss_types": [],
            "wafs": [],
            "tags": [],
            "confidence": 0.9,
            "forbidden_values": [],
            "strict_payloads": False,
        })
        grounded = GroundedClaim(
            claim=claim,
            claim_id="clm-" + "e" * 16,
            knowledge_id="kb-" + "e" * 16,
            source_id="src-" + "e" * 16,
            research_hash="f" * 64,
        )
        patterns = project_claim(grounded)
        self.assertTrue(patterns)
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PatternStore(root_dir=tmpdir)
            stored = [store.put(item).pattern for item in patterns]
            target = _target()
            results = match_patterns_to_target(stored, target)
            self.assertEqual(len(results), len(stored))
            kinds = {item.match_kind for item in results}
            self.assertTrue(kinds <= {
                "MATCH", "PARTIAL_MATCH", "NO_MATCH",
                "INCONCLUSIVE",
            })

    def test_ti_projection_to_match(self):
        target = _target(endpoints=[_endpoint()], urls=[_url()])
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            constraints=[{
                "constraint_kind": "UPPER_BOUND",
                "version": "4.2.1", "upper_inclusive": True,
            }],
            surface=[{
                "surface_kind": "http_endpoint",
                "path": "/search",
                "method": "GET",
                "parameter": "q",
                "parameter_location": "query",
            }],
        )
        result = match_pattern_to_target(pattern, target)
        self.assertEqual(result.match_kind, "MATCH")
        self.assertEqual(
            set(result.matched_criteria),
            {"product", "version", "path", "method", "parameter",
             "parameter_location"},
        )


if __name__ == "__main__":
    unittest.main()
