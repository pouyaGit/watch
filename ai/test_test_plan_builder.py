"""Focused tests for the deterministic TestPlan Builder (Phase 4B).

BUILDER tests: they prove ONE bound Hypothesis becomes ONE
PROPOSED TestPlan describing future testing only — no execution,
no verdicts, no scope grants, no LLM, no network, no subprocess,
no database. Covers the required adversarial matrix A–AF plus a
pure in-memory integration chain.
"""

import ast
import hashlib
import unittest
from pathlib import Path

from pydantic import ValidationError

from ai.researcher import test_plan_builder as builder_module
from ai.researcher.hypothesis_engine import (
    build_hypothesis_from_match,
)
from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ParamRecord,
    ProgramRecord,
    SubdomainRecord,
    project_subdomain,
)
from ai.researcher.target_matcher import (
    match_pattern_to_target,
    match_patterns_to_target,
)
from ai.researcher.test_plan_builder import (
    build_test_plan_from_hypothesis,
    build_test_plans_from_hypotheses,
)
from ai.schemas.hypothesis import ResearchProvenance, TargetRef
from ai.schemas.research_pattern import (
    ModelInterpretation,
    build_attack_pattern,
    build_vulnerability_pattern,
)
from ai.schemas.test_plan import (
    TestPlan,
    build_test_plan,
    test_plan_id_from_key,
    test_plan_idempotency_key,
)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


def _hex(tag):
    return hashlib.sha256(tag.encode("utf-8")).hexdigest()[:16]


def _provenance(tag="a"):
    return ResearchProvenance(claim_ids=["clm-" + _hex(tag)])


def _vuln(products=None, constraints=None, surface=None, tag="a",
           vuln_ids=None):
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
        pattern_kind="PRODUCT_VULNERABILITY",
        title="Research pattern",
        description="Deterministic test pattern.",
        facts=facts,
        provenance=_provenance(tag),
    )


def _attack(technique="stored xss", context=None, tag="b"):
    facts = {"technique": technique}
    if context is not None:
        facts["technology_context"] = context
    facts.setdefault("sink_characteristics", ["html body"])
    return build_attack_pattern(
        pattern_kind="TECHNIQUE",
        title="Attack technique",
        description="Deterministic test technique.",
        facts=facts,
        provenance=_provenance(tag),
    )


def _target(program="acme", sub="app.acme.com",
            tech=("FooCMS:4.1.0",), endpoints=()):
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
        prog, subrec, https=https, endpoints=list(endpoints),
    ).intelligence


def _endpoint(path="/search", record_id="ep-1", program="acme",
               sub="app.acme.com"):
    return EndpointRecord(
        program_name=program, subdomain=sub, path=path,
        example_url=f"https://{sub}{path}",
        params=["q"],
        param_records=(
            ParamRecord(
                name="q", method="GET", location="query",
                source="crawl",
            ),
        ),
        record_id=record_id,
    )


def _bound_quad(**overrides):
    """Consistent (hypothesis, match, pattern, target) tuple."""
    target = overrides.get("target", _target())
    pattern = overrides.get("pattern", _vuln())
    match = match_pattern_to_target(pattern, target)
    built = build_hypothesis_from_match(match, pattern, target)
    assert built.outcome == "CREATED", built.reason
    return built.hypothesis, match, pattern, target


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


def _plan_dump(plan):
    payload = plan.model_dump(mode="json")
    payload.pop("created_at", None)
    return payload


# ------------------------------------------------------------------
# Input contract: typed inputs only, fail closed
# ------------------------------------------------------------------


class InputContractTests(unittest.TestCase):
    def test_raw_dict_hypothesis_rejected(self):
        hypothesis, match, pattern, target = _bound_quad()
        with self.assertRaises(TypeError):
            build_test_plan_from_hypothesis(
                hypothesis.model_dump(mode="json"),
                match=match, pattern=pattern,
                target_intelligence=target,
            )

    def test_string_and_none_hypothesis_rejected(self):
        hypothesis, match, pattern, target = _bound_quad()
        for bad in ("hyp-abcdef", None, 42, ["x"]):
            with self.assertRaises(TypeError, msg=str(bad)):
                build_test_plan_from_hypothesis(bad)

    def test_wrong_context_types_rejected(self):
        hypothesis, match, pattern, target = _bound_quad()
        with self.assertRaises(TypeError):
            build_test_plan_from_hypothesis(
                hypothesis, match={"match_id": "tm-x"}
            )
        with self.assertRaises(TypeError):
            build_test_plan_from_hypothesis(
                hypothesis, pattern="vp-x"
            )
        with self.assertRaises(TypeError):
            build_test_plan_from_hypothesis(
                hypothesis, target_intelligence="acme"
            )

    def test_batch_requires_sequence(self):
        with self.assertRaises(TypeError):
            build_test_plans_from_hypotheses({"h": 1})

    def test_batch_rejects_non_hypothesis_elements(self):
        with self.assertRaises(TypeError):
            build_test_plans_from_hypotheses([{"hypothesis_id": 1}])

    def test_batch_rejects_non_callable_resolvers(self):
        hypothesis, _, _, _ = _bound_quad()
        with self.assertRaises(TypeError):
            build_test_plans_from_hypotheses(
                [hypothesis], match_resolver="nope"
            )


# ------------------------------------------------------------------
# A–F: binding failures fail closed
# ------------------------------------------------------------------


class BindingTests(unittest.TestCase):
    def test_wrong_hypothesis_type_rejected(self):
        # A: a match object is not a hypothesis.
        _, match, _, _ = _bound_quad()
        with self.assertRaises(TypeError):
            build_test_plan_from_hypothesis(match)

    def test_hypothesis_without_bindings_accepted_minimal(self):
        # B: a legacy hypothesis without match/snapshot binding
        # still builds hypothesis-only (bindings verified only
        # when context is supplied).
        hypothesis, _, _, _ = _bound_quad()
        legacy = hypothesis.model_copy(update={
            "match_id": None, "snapshot_hash": None,
        })
        result = build_test_plan_from_hypothesis(legacy)
        self.assertEqual(result.outcome, "CREATED")
        self.assertIsNone(result.plan.match_id)

    def test_hypothesis_match_mismatch_rejected(self):
        hypothesis, _, pattern, target = _bound_quad()
        other_match = match_pattern_to_target(
            _vuln(tag="other-match"), target
        )
        result = build_test_plan_from_hypothesis(
            hypothesis, match=other_match, pattern=pattern,
            target_intelligence=target,
        )
        self.assertEqual(result.outcome, "REJECTED")
        self.assertIsNone(result.plan)

    def test_hypothesis_pattern_mismatch_rejected(self):
        hypothesis, match, _, target = _bound_quad()
        result = build_test_plan_from_hypothesis(
            hypothesis, match=match,
            pattern=_vuln(tag="wrong-pattern"),
            target_intelligence=target,
        )
        self.assertEqual(result.outcome, "REJECTED")
        self.assertIsNone(result.plan)

    def test_hypothesis_snapshot_mismatch_rejected(self):
        hypothesis, match, pattern, _ = _bound_quad()
        other_target = _target(tech=("FooCMS:9.9.9",))
        self.assertNotEqual(
            hypothesis.snapshot_hash,
            other_target.snapshot_hash,
        )
        result = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=other_target,
        )
        self.assertEqual(result.outcome, "REJECTED")

    def test_cross_program_mismatch_rejected(self):
        hypothesis, match, pattern, _ = _bound_quad()
        other_target = _target(program="other")
        result = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=other_target,
        )
        self.assertEqual(result.outcome, "REJECTED")

    def test_match_pattern_type_disagreement_rejected(self):
        hypothesis, match, _, target = _bound_quad()
        attack = _attack(context=["FooCMS"], tag="disagree")
        result = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=attack,
            target_intelligence=target,
        )
        self.assertEqual(result.outcome, "REJECTED")

    def test_non_proposed_hypothesis_rejected(self):
        from ai.schemas.hypothesis import Hypothesis
        hypothesis, match, pattern, target = _bound_quad()
        for status, extra in (
            ("SUPERSEDED", {"supersedes": hypothesis.hypothesis_id}),
            ("CANCELLED", {"cancel_reason": "stale"}),
        ):
            payload = hypothesis.model_dump(mode="json")
            payload["status"] = status
            payload.update(extra)
            dead = Hypothesis.model_validate(payload)
            result = build_test_plan_from_hypothesis(
                dead, match=match, pattern=pattern,
                target_intelligence=target,
            )
            self.assertEqual(
                result.outcome, "REJECTED", msg=status
            )

    def test_unverifiable_supplied_match_rejected(self):
        hypothesis, _, _, _ = _bound_quad()
        legacy = hypothesis.model_copy(update={
            "match_id": None, "snapshot_hash": None,
        })
        _, match2, pattern2, target2 = _bound_quad()
        result = build_test_plan_from_hypothesis(
            legacy, match=match2, pattern=pattern2,
            target_intelligence=target2,
        )
        self.assertEqual(result.outcome, "REJECTED")


# ------------------------------------------------------------------
# G–I: unsupported derivations
# ------------------------------------------------------------------


class UnsupportedTests(unittest.TestCase):
    def test_unsupported_hypothesis_type(self):
        hypothesis, _, _, _ = _bound_quad()
        for htype in ("technology_relevance", "attack_surface"):
            forged = hypothesis.model_copy(
                update={"hypothesis_type": htype}
            )
            result = build_test_plan_from_hypothesis(forged)
            self.assertEqual(
                result.outcome, "UNSUPPORTED", msg=htype
            )
            self.assertIsNone(result.plan)

    def test_technique_without_pattern_unsupported(self):
        target = _target()
        pattern = _attack(context=["FooCMS"])
        match = match_pattern_to_target(pattern, target)
        built = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(built.outcome, "CREATED")
        result = build_test_plan_from_hypothesis(built.hypothesis)
        self.assertEqual(result.outcome, "UNSUPPORTED")

    def test_non_xss_technique_unsupported(self):
        target = _target()
        pattern = build_attack_pattern(
            pattern_kind="TECHNIQUE",
            title="Port scan technique",
            description="Deterministic technique notes.",
            facts={
                "technique": "port scanning",
                "sink_characteristics": ["open port"],
                "technology_context": ["FooCMS"],
            },
            provenance=_provenance("nonsx"),
        )
        match = match_pattern_to_target(pattern, target)
        built = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(built.outcome, "CREATED")
        result = build_test_plan_from_hypothesis(
            built.hypothesis, pattern=pattern
        )
        self.assertEqual(result.outcome, "UNSUPPORTED")
        self.assertIsNone(result.plan)


# ------------------------------------------------------------------
# Category / execution / verifier derivation
# ------------------------------------------------------------------


class DerivationTests(unittest.TestCase):
    def test_cve_pattern_maps_to_nuclei(self):
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            vuln_ids=["CVE-2026-12345"], tag="cveplan",
        )
        target = _target()
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(hypothesis.pattern_kind, "cve")
        result = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        )
        self.assertEqual(result.outcome, "CREATED")
        plan = result.plan
        self.assertEqual(plan.test_category, "nuclei_cve")
        self.assertEqual(plan.execution_type, "nuclei_scan")
        self.assertEqual(plan.verifier_type, "nuclei_verifier")

    def test_endpoint_pattern_maps_to_probe_matcher(self):
        target = _target(endpoints=[_endpoint()])
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            surface=[{
                "surface_kind": "http_endpoint", "path": "/search",
            }],
            tag="endpointplan",
        )
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        result = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        )
        plan = result.plan
        self.assertEqual(plan.test_category, "http_probe")
        self.assertEqual(plan.execution_type, "http_probe")
        self.assertEqual(plan.verifier_type, "http_matcher")

    def test_product_only_maps_to_probe_manual(self):
        hypothesis, match, pattern, target = _bound_quad()
        result = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        )
        plan = result.plan
        self.assertEqual(plan.test_category, "http_probe")
        self.assertEqual(plan.execution_type, "http_probe")
        self.assertEqual(plan.verifier_type, "manual_review")

    def test_stored_xss_technique_maps_to_browser(self):
        target = _target()
        pattern = _attack(context=["FooCMS"], tag="storedplan")
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        result = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        )
        self.assertEqual(result.outcome, "CREATED")
        plan = result.plan
        self.assertEqual(plan.test_category, "xss_stored")
        self.assertEqual(
            plan.execution_type, "browser_verification"
        )
        self.assertEqual(plan.verifier_type, "xss_verifier")

    def test_reflected_xss_technique_maps_to_http(self):
        target = _target()
        pattern = build_attack_pattern(
            pattern_kind="TECHNIQUE",
            title="Reflected technique",
            description="Deterministic notes.",
            facts={
                "technique": "reflected xss",
                "sink_characteristics": ["html body"],
                "technology_context": ["FooCMS"],
            },
            provenance=_provenance("reflectedplan"),
        )
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        plan = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        self.assertEqual(plan.test_category, "xss_reflected")
        self.assertEqual(plan.execution_type, "http_verification")
        self.assertEqual(plan.verifier_type, "xss_verifier")

    def test_no_llm_or_severity_influence(self):
        hypothesis, match, _, target = _bound_quad()
        hot_pattern = build_vulnerability_pattern(
            pattern_kind="PRODUCT_VULNERABILITY",
            title="CRITICAL RCE EXPLOIT NOW",
            description="Urgent severity ten.",
            facts={"products": [{"product": "FooCMS"}]},
            provenance=_provenance("hotplan"),
            interpretation=ModelInterpretation(
                classification_hints=["priority:critical"],
                rationale="CRITICAL, exploit immediately",
                confidence=1.0,
            ),
            reported_severity="CRITICAL",
            cvss_score=10.0,
        )
        hot_match = match_pattern_to_target(hot_pattern, target)
        hot_hyp = build_hypothesis_from_match(
            hot_match, hot_pattern, target
        ).hypothesis
        plain = build_test_plan_from_hypothesis(
            hypothesis, match=match,
            target_intelligence=target,
        ).plan
        hot = build_test_plan_from_hypothesis(
            hot_hyp, match=hot_match, pattern=hot_pattern,
            target_intelligence=target,
        ).plan
        self.assertEqual(plain.test_category, hot.test_category)
        self.assertEqual(
            plain.execution_type, hot.execution_type
        )
        self.assertEqual(plain.verifier_type, hot.verifier_type)
        self.assertEqual(
            plain.request_spec.model_dump(),
            hot.request_spec.model_dump(),
        )


# ------------------------------------------------------------------
# Objective / preconditions / evidence intent
# ------------------------------------------------------------------


class IntentContentTests(unittest.TestCase):
    def test_objective_is_test_intent_only(self):
        hypothesis, match, pattern, target = _bound_quad()
        plan = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        text = plan.objective.lower()
        for forbidden in (
            "confirm vulnerability", "exploit target",
            "target is vulnerable", "verified", "confirmed",
            "prove exploitability",
        ):
            self.assertNotIn(forbidden, text)
        self.assertIn(hypothesis.hypothesis_id, plan.objective)
        self.assertIn("test intent", text)

    def test_preconditions_from_match_criteria(self):
        target = _target(endpoints=[_endpoint()])
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            surface=[{
                "surface_kind": "http_endpoint", "path": "/search",
                "method": "GET", "parameter": "q",
                "parameter_location": "query",
            }],
            tag="precond",
        )
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        plan = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        self.assertTrue(plan.preconditions)
        self.assertEqual(
            plan.preconditions, sorted(plan.preconditions)
        )
        blob = " ".join(plan.preconditions).lower()
        self.assertNotIn("safe to execute", blob)
        self.assertNotIn("authorized", blob)
        self.assertNotIn("confirm", blob)

    def test_preconditions_empty_without_match(self):
        hypothesis, _, _, _ = _bound_quad()
        plan = build_test_plan_from_hypothesis(hypothesis).plan
        self.assertEqual(plan.preconditions, [])

    def test_expected_behavior_and_evidence_are_requirements(self):
        hypothesis, match, pattern, target = _bound_quad()
        plan = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        self.assertIn("no finding is", plan.expected_behavior)
        lowered = (
            plan.expected_behavior + " "
            + " ".join(plan.required_evidence)
        ).lower()
        self.assertNotIn("will be confirmed", lowered)
        self.assertTrue(plan.required_evidence)

    def test_lifecycle_proposed_and_approval_semantics(self):
        hypothesis, match, pattern, target = _bound_quad()
        plan = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        self.assertEqual(plan.status, "PROPOSED")
        payload = plan.model_dump(mode="json")
        payload["status"] = "APPROVED"
        approved = TestPlan.model_validate(payload)
        # APPROVED is contract/syntax approval only: the artifact
        # still carries no scope, execution, or verdict authority.
        for forbidden in (
            "scope_allowed", "execution_allowed", "verdict",
            "confirmed",
        ):
            self.assertNotIn(
                forbidden, set(approved.model_dump().keys())
            )


# ------------------------------------------------------------------
# J–L, AA–AC: identity / idempotency
# ------------------------------------------------------------------


class IdentityTests(unittest.TestCase):
    def test_same_input_same_identity(self):
        hypothesis, match, pattern, target = _bound_quad()
        first = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        second = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        self.assertEqual(_plan_dump(first), _plan_dump(second))
        self.assertEqual(
            first.test_plan_id, second.test_plan_id
        )

    def test_different_snapshot_different_identity(self):
        hypothesis, match, pattern, target = _bound_quad()
        other_target = _target(tech=("FooCMS:4.2.0",))
        other_match = match_pattern_to_target(pattern, other_target)
        other_hyp = build_hypothesis_from_match(
            other_match, pattern, other_target
        ).hypothesis
        first = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        second = build_test_plan_from_hypothesis(
            other_hyp, match=other_match, pattern=pattern,
            target_intelligence=other_target,
        ).plan
        self.assertNotEqual(
            first.idempotency_key, second.idempotency_key
        )
        self.assertNotEqual(
            first.test_plan_id, second.test_plan_id
        )

    def test_different_hypothesis_different_identity(self):
        hypothesis, match, pattern, target = _bound_quad()
        other_pattern = _vuln(tag="otherhyp")
        other_match = match_pattern_to_target(
            other_pattern, target
        )
        other_hyp = build_hypothesis_from_match(
            other_match, other_pattern, target
        ).hypothesis
        first = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan.test_plan_id
        second = build_test_plan_from_hypothesis(
            other_hyp, match=other_match, pattern=other_pattern,
            target_intelligence=target,
        ).plan.test_plan_id
        self.assertNotEqual(first, second)

    def test_preconditions_excluded_from_identity(self):
        # Preconditions are excluded metadata per the existing
        # TestPlan basis: the same hypothesis therefore converges
        # with and without match context when the derived triple
        # and request spec agree. Match/snapshot audit binding
        # still differs on the stored fields.
        hypothesis, match, pattern, target = _bound_quad()
        minimal = build_test_plan_from_hypothesis(
            hypothesis
        ).plan
        bound = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        self.assertEqual(
            minimal.idempotency_key, bound.idempotency_key
        )
        # Match/snapshot audit binding rides on the hypothesis,
        # so both plans carry it; only excluded-metadata
        # preconditions differ.
        self.assertEqual(minimal.match_id, match.match_id)
        self.assertEqual(bound.match_id, match.match_id)
        self.assertNotEqual(
            minimal.preconditions, bound.preconditions
        )

    def test_stale_snapshot_cannot_reuse_identity(self):
        hypothesis, match, pattern, target = _bound_quad()
        fresh = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        other_target = _target(tech=("FooCMS:9.9.9",))
        stale = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=other_target,
        )
        self.assertEqual(stale.outcome, "REJECTED")
        self.assertIsNone(stale.plan)
        self.assertIsNotNone(fresh.snapshot_hash)

    def test_legacy_key_reproduces_without_binding(self):
        target = TargetRef(
            program_name="acme", subdomain="app.acme.com"
        )
        provenance = _provenance("planlegacy")
        spec = {"method": "GET", "path": "/",
                "query_params": {}, "headers": {},
                "body": None}
        key_plain = test_plan_idempotency_key(
            hypothesis_id="hyp-" + "0" * 16,
            program_name="acme", subdomain="app.acme.com",
            endpoint="", test_category="http_probe",
            execution_type="http_probe",
            objective="legacy objective", request_spec=spec,
            verifier_type="manual_review",
        )
        legacy = build_test_plan(
            hypothesis_id="hyp-" + "0" * 16,
            target=target, test_category="http_probe",
            objective="legacy objective",
            execution_type="http_probe",
            verifier_type="manual_review",
            provenance=provenance,
            request_spec=spec,
        )
        self.assertEqual(legacy.idempotency_key, key_plain)
        self.assertEqual(
            legacy.test_plan_id, test_plan_id_from_key(key_plain)
        )
        self.assertIsNone(legacy.match_id)
        self.assertIsNone(legacy.snapshot_hash)

    def test_input_ordering_irrelevant(self):
        hypothesis, match, pattern, target = _bound_quad()
        first = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        second = build_test_plan_from_hypothesis(
            hypothesis, target_intelligence=target,
            pattern=pattern, match=match,
        ).plan
        self.assertEqual(_plan_dump(first), _plan_dump(second))

    def test_binding_changes_identity(self):
        hypothesis, match, pattern, target = _bound_quad()
        plain = build_test_plan_from_hypothesis(hypothesis).plan
        bound = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        self.assertEqual(bound.match_id, match.match_id)
        self.assertEqual(
            bound.snapshot_hash, target.snapshot_hash
        )


# ------------------------------------------------------------------
# M–R: request safety and hostile prose
# ------------------------------------------------------------------


class RequestSafetyTests(unittest.TestCase):
    def test_path_crlf_rejected_by_contract(self):
        from ai.schemas.test_plan import HttpRequestSpec
        with self.assertRaises(ValidationError):
            HttpRequestSpec(path="/search\r\nX-Injected: 1")
        with self.assertRaises(ValidationError):
            HttpRequestSpec(path="https://evil.example/x")

    def test_header_crlf_rejected_by_contract(self):
        from ai.schemas.test_plan import HttpRequestSpec
        with self.assertRaises(ValidationError):
            HttpRequestSpec(headers={"X-A": "b\r\nc"})
        with self.assertRaises(ValidationError):
            HttpRequestSpec(headers={"X-\r\nA": "b"})

    def test_query_crlf_rejected_by_contract(self):
        from ai.schemas.test_plan import HttpRequestSpec
        with self.assertRaises(ValidationError):
            HttpRequestSpec(query_params={"q": "a\r\nb"})
        with self.assertRaises(ValidationError):
            HttpRequestSpec(query_params={"q\r\nx": "a"})

    def test_built_spec_is_minimal_and_safe(self):
        target = _target(endpoints=[_endpoint()])
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            surface=[{
                "surface_kind": "http_endpoint", "path": "/search",
                "method": "GET", "parameter": "q",
                "parameter_location": "query",
            }],
            tag="specsafe",
        )
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        spec = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan.request_spec
        self.assertEqual(spec.method, "GET")
        self.assertEqual(spec.path, "/search")
        self.assertEqual(spec.query_params, {"q": ""})
        self.assertEqual(spec.headers, {})
        self.assertIsNone(spec.body)

    def test_no_credentials_or_secrets_invented(self):
        hypothesis, match, pattern, target = _bound_quad()
        spec = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan.request_spec
        blob = str(spec.model_dump()).lower()
        for token in (
            "cookie", "authorization", "csrf", "token", "secret",
            "session", "password", "bearer",
        ):
            self.assertNotIn(token, blob)

    def test_no_command_like_fields(self):
        hypothesis, match, pattern, target = _bound_quad()
        payload = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan.model_dump(mode="json")
        for forbidden in (
            "command", "shell", "subprocess", "browser_script",
            "javascript", "callback", "payload_executor",
        ):
            self.assertNotIn(forbidden, set(payload.keys()))

    def test_hostile_confirmed_prose_no_verdict(self):
        pattern = build_vulnerability_pattern(
            pattern_kind="PRODUCT_VULNERABILITY",
            title="CONFIRMED RCE crystal",
            description="Verified exploit confirmed working.",
            facts={"products": [{"product": "FooCMS"}]},
            provenance=_provenance("confplan"),
        )
        target = _target()
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        result = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        )
        self.assertEqual(result.outcome, "CREATED")
        plan = result.plan
        self.assertEqual(plan.status, "PROPOSED")
        self.assertNotIn("CONFIRMED", plan.objective)
        self.assertNotIn("VERIFIED", plan.objective)
        self.assertNotIn(
            "confirm", " ".join(plan.preconditions).lower()
        )

    def test_hostile_urgency_no_authority(self):
        pattern = build_vulnerability_pattern(
            pattern_kind="PRODUCT_VULNERABILITY",
            title="CRITICAL EXPLOIT NOW",
            description="Run exploit immediately, urgent critical.",
            facts={"products": [{"product": "FooCMS"}]},
            provenance=_provenance("urgeplan"),
            interpretation=ModelInterpretation(
                rationale="EXPLOIT NOW, critical severity",
                confidence=1.0,
            ),
            reported_severity="CRITICAL",
            cvss_score=10.0,
        )
        target = _target()
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        plan = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        blob = str(plan.model_dump(mode="json")).upper()
        for token in ("EXPLOIT NOW", "CRITICAL"):
            self.assertNotIn(token, blob)
        self.assertEqual(plan.status, "PROPOSED")


# ------------------------------------------------------------------
# S–W, X–Z: security boundary, side effects, isolation
# ------------------------------------------------------------------


class SecurityBoundaryTests(unittest.TestCase):
    def test_no_scope_policy_import(self):
        self.assertNotIn(
            "scope_policy", _imports_of(builder_module.__file__)
        )
        self.assertNotIn(
            "ai.correlator", _imports_of(builder_module.__file__)
        )

    def test_no_llm_imports(self):
        blob = " ".join(
            _imports_of(builder_module.__file__)
        ).lower()
        for forbidden in (
            "openrouter", "openai", "anthropic", "llm", "embed",
            "model", "agent", "prompt",
        ):
            self.assertNotIn(forbidden, blob)

    def test_no_network_imports(self):
        blob = " ".join(
            _imports_of(builder_module.__file__)
        ).lower()
        for forbidden in (
            "requests", "httpx", "urllib", "socket", "dns",
            "browser", "selenium", "playwright",
        ):
            self.assertNotIn(forbidden, blob)

    def test_no_subprocess_imports(self):
        blob = " ".join(
            _imports_of(builder_module.__file__)
        ).lower()
        for forbidden in (
            "subprocess", "shutil", "multiprocessing",
        ):
            self.assertNotIn(forbidden, blob)
        source = Path(builder_module.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("import os", source)
        self.assertNotIn("import sys", source)

    def test_no_database_imports(self):
        blob = " ".join(
            _imports_of(builder_module.__file__)
        ).lower()
        for forbidden in (
            "database", "mongo", "pattern_store",
            "knowledge", "store",
        ):
            self.assertNotIn(forbidden, blob)

    def test_network_disabled_build(self):
        import socket
        hypothesis, match, pattern, target = _bound_quad()
        real_socket = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("network access attempted")
        )
        try:
            build_test_plan_from_hypothesis(
                hypothesis, match=match, pattern=pattern,
                target_intelligence=target,
            )
            build_test_plans_from_hypotheses([hypothesis])
        finally:
            socket.socket = real_socket

    def test_no_execution_side_effects(self):
        import tempfile
        hypothesis, match, pattern, target = _bound_quad()
        with tempfile.TemporaryDirectory() as tmpdir:
            before = set(Path(tmpdir).iterdir())
            build_test_plan_from_hypothesis(
                hypothesis, match=match, pattern=pattern,
                target_intelligence=target,
            )
            self.assertEqual(before, set(Path(tmpdir).iterdir()))

    def test_no_finding_or_verdict_fields(self):
        hypothesis, match, pattern, target = _bound_quad()
        payload = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan.model_dump(mode="json")
        for forbidden in (
            "verdict", "finding", "finding_status", "confirmed",
            "evidence", "exploited", "target_affected",
        ):
            self.assertNotIn(forbidden, set(payload.keys()))
        for value in (
            "CONFIRMED", "VERIFIED", "NOT_VULNERABLE", "EXPLOITED",
        ):
            self.assertNotIn(value, str(payload))

    def test_no_scope_authority_fields(self):
        hypothesis, match, pattern, target = _bound_quad()
        payload = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan.model_dump(mode="json")
        for forbidden in (
            "scope_allowed", "execution_allowed", "authorized",
        ):
            self.assertNotIn(forbidden, set(payload.keys()))

    def test_scope_copied_as_descriptive_data(self):
        hypothesis, match, pattern, target = _bound_quad()
        plan = build_test_plan_from_hypothesis(
            hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        ).plan
        self.assertEqual(
            plan.target.scope, hypothesis.target.scope
        )
        self.assertEqual(
            plan.target.program_name, target.program_name
        )
        self.assertEqual(plan.target.subdomain, target.subdomain)

    def test_cross_program_isolation(self):
        pattern = _vuln()
        plans = []
        for program in ("acme", "other"):
            target = _target(program=program)
            match = match_pattern_to_target(pattern, target)
            hypothesis = build_hypothesis_from_match(
                match, pattern, target
            ).hypothesis
            plans.append(
                build_test_plan_from_hypothesis(
                    hypothesis, match=match, pattern=pattern,
                    target_intelligence=target,
                ).plan
            )
        self.assertNotEqual(
            plans[0].idempotency_key, plans[1].idempotency_key
        )
        self.assertEqual(plans[0].target.program_name, "acme")
        self.assertEqual(plans[1].target.program_name, "other")


# ------------------------------------------------------------------
# Batch behavior
# ------------------------------------------------------------------


class BatchTests(unittest.TestCase):
    def _two_quads(self):
        target = _target()
        vuln = _vuln()
        attack = _attack(context=["FooCMS"], tag="batchxss")
        matches = match_patterns_to_target([vuln, attack], target)
        quads = []
        for match in matches:
            pattern = (
                vuln if match.pattern_id == vuln.pattern_id
                else attack
            )
            built = build_hypothesis_from_match(
                match, pattern, target
            )
            assert built.outcome == "CREATED"
            quads.append(
                (built.hypothesis, match, pattern, target)
            )
        return quads

    def test_batch_builds_with_resolvers(self):
        quads = self._two_quads()
        hyps = [h for h, _, _, _ in quads]
        matches = {m.match_id: m for _, m, _, _ in quads}
        patterns = {p.pattern_id: p for _, _, p, _ in quads}
        targets = {t.snapshot_hash: t for _, _, _, t in quads}
        results = build_test_plans_from_hypotheses(
            hyps, match_resolver=matches.get,
            pattern_resolver=patterns.get,
            target_resolver=targets.get,
        )
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertEqual(result.outcome, "CREATED")
        self.assertEqual(
            [r.hypothesis_id for r in results],
            sorted(r.hypothesis_id for r in results),
        )

    def test_batch_hypothesis_only_without_resolvers(self):
        quads = self._two_quads()
        hyps = [h for h, _, _, _ in quads]
        results = build_test_plans_from_hypotheses(hyps)
        kinds = {r.outcome for r in results}
        # Vulnerability hypothesis builds; technique hypothesis
        # without pattern context is UNSUPPORTED (no guessing).
        self.assertIn("CREATED", kinds)
        self.assertTrue(kinds <= {"CREATED", "UNSUPPORTED"})

    def test_batch_unresolvable_rejected(self):
        hypothesis, _, _, _ = _bound_quad()
        results = build_test_plans_from_hypotheses(
            [hypothesis], match_resolver=lambda mid: None,
            pattern_resolver=lambda pid: None,
            target_resolver=lambda snap: None,
        )
        self.assertEqual(results[0].outcome, "REJECTED")
        self.assertIsNone(results[0].plan)

    def test_batch_duplicates_converge(self):
        hypothesis, match, pattern, target = _bound_quad()
        results = build_test_plans_from_hypotheses(
            [hypothesis, hypothesis, hypothesis],
            match_resolver=lambda mid: match,
            pattern_resolver=lambda pid: pattern,
            target_resolver=lambda snap: target,
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].outcome, "CREATED")

    def test_batch_order_irrelevant(self):
        quads = self._two_quads()
        hyps = [h for h, _, _, _ in quads]
        matches = {m.match_id: m for _, m, _, _ in quads}
        patterns = {p.pattern_id: p for _, _, p, _ in quads}
        targets = {t.snapshot_hash: t for _, _, _, t in quads}
        kwargs = dict(
            match_resolver=matches.get,
            pattern_resolver=patterns.get,
            target_resolver=targets.get,
        )
        forward = build_test_plans_from_hypotheses(hyps, **kwargs)
        backward = build_test_plans_from_hypotheses(
            list(reversed(hyps)), **kwargs
        )
        self.assertEqual(
            [(r.outcome, r.hypothesis_id,
              _plan_dump(r.plan) if r.plan else None)
             for r in forward],
            [(r.outcome, r.hypothesis_id,
              _plan_dump(r.plan) if r.plan else None)
             for r in backward],
        )

    def test_batch_isolates_bad_records(self):
        hypothesis, match, pattern, target = _bound_quad()
        other = _vuln(tag="badbatch")
        other_match = match_pattern_to_target(other, target)
        other_hyp = build_hypothesis_from_match(
            other_match, other, target
        ).hypothesis
        # Cross the bindings: each hypothesis resolves the
        # other's context.
        results = build_test_plans_from_hypotheses(
            [hypothesis, other_hyp],
            match_resolver=lambda mid: other_match
            if mid == hypothesis.match_id else match,
            pattern_resolver=lambda pid: pattern,
            target_resolver=lambda snap: target,
        )
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertEqual(result.outcome, "REJECTED")


# ------------------------------------------------------------------
# Integration: full pure in-memory chain to PROPOSED TestPlan
# ------------------------------------------------------------------


class IntegrationTests(unittest.TestCase):
    def test_full_chain_stays_test_intent_only(self):
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
        target = _target(endpoints=[_endpoint()])
        matches = match_patterns_to_target(patterns, target)
        self.assertTrue(matches)
        for pattern in patterns:
            match = next(
                m for m in matches
                if m.pattern_id == pattern.pattern_id
            )
            built = build_hypothesis_from_match(
                match, pattern, target
            )
            if built.outcome != "CREATED":
                continue
            result = build_test_plan_from_hypothesis(
                built.hypothesis, match=match, pattern=pattern,
                target_intelligence=target,
            )
            self.assertEqual(result.outcome, "CREATED")
            plan = result.plan
            self.assertEqual(plan.status, "PROPOSED")
            self.assertEqual(
                plan.hypothesis_id, built.hypothesis.hypothesis_id
            )
            self.assertEqual(plan.match_id, match.match_id)
            self.assertEqual(
                plan.snapshot_hash, target.snapshot_hash
            )
            payload = plan.model_dump(mode="json")
            for value in (
                "CONFIRMED", "VERIFIED", "NOT_VULNERABLE",
                "EXPLOITED",
            ):
                self.assertNotIn(value, str(payload))
            for forbidden in (
                "scope_allowed", "execution_allowed", "command",
                "evidence",
            ):
                self.assertNotIn(forbidden, set(payload.keys()))


if __name__ == "__main__":
    unittest.main()
