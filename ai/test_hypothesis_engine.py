"""Focused tests for the deterministic Hypothesis Engine (Phase 4A).

ENGINE tests: they prove eligible TargetPatternMatch records bind
to exactly one Research Pattern and one Target Intelligence
snapshot to produce PROPOSED Hypothesis objects that remain
relevance proposals only — no verdicts, no scope grants, no
execution authority, no LLM, no network, no subprocess, no
database. Covers the required adversarial matrix A–AI plus the
pure in-memory integration chain.
"""

import ast
import hashlib
import unittest
from pathlib import Path

from pydantic import ValidationError

from ai.researcher import hypothesis_engine as engine_module
from ai.researcher.hypothesis_engine import (
    ELIGIBLE_MATCH_KINDS,
    EngineResult,
    build_hypotheses_from_matches,
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
from ai.schemas.hypothesis import (
    Hypothesis,
    ResearchProvenance,
    build_hypothesis,
    hypothesis_id_from_key,
    hypothesis_idempotency_key,
)
from ai.schemas.research_pattern import (
    ModelInterpretation,
    build_attack_pattern,
    build_vulnerability_pattern,
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


def _attack(technique="stored xss", context=None, sinks=None,
            tag="b"):
    facts = {"technique": technique}
    if context is not None:
        facts["technology_context"] = context
    if sinks is not None:
        facts["sink_characteristics"] = sinks
    else:
        facts["sink_characteristics"] = ["html body"]
    return build_attack_pattern(
        pattern_kind="TECHNIQUE",
        title="Attack technique",
        description="Deterministic test technique.",
        facts=facts,
        provenance=_provenance(tag),
    )


def _target(program="acme", sub="app.acme.com",
            tech=("FooCMS:4.1.0",), endpoints=(), urls=()):
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
        urls=list(urls),
    ).intelligence


def _endpoint(path="/search", record_id="ep-1"):
    return EndpointRecord(
        program_name="acme", subdomain="app.acme.com", path=path,
        example_url=f"https://app.acme.com{path}",
        params=["q"],
        param_records=(
            ParamRecord(
                name="q", method="GET", location="query",
                source="crawl",
            ),
        ),
        record_id=record_id,
    )


def _eligible_triple(**overrides):
    """A MATCH triple: pattern + target + match, all consistent."""
    target = overrides.get("target", _target())
    pattern = overrides.get("pattern", _vuln())
    match = match_pattern_to_target(pattern, target)
    assert match.match_kind == "MATCH", match.match_kind
    return match, pattern, target


def _identity_dump(hypothesis):
    """Identity-relevant content: excludes audit-only created_at."""
    payload = hypothesis.model_dump(mode="json")
    payload.pop("created_at", None)
    return payload


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
# A–E: binding rejections; X–Z: input contract
# ------------------------------------------------------------------


class InputContractTests(unittest.TestCase):
    def test_raw_dict_match_rejected(self):
        match, pattern, target = _eligible_triple()
        with self.assertRaises(TypeError):
            build_hypothesis_from_match(
                match.model_dump(mode="json"), pattern, target
            )

    def test_raw_dict_pattern_rejected(self):
        match, pattern, target = _eligible_triple()
        with self.assertRaises(TypeError):
            build_hypothesis_from_match(
                match, pattern.model_dump(mode="json"), target
            )

    def test_raw_dict_target_rejected(self):
        match, pattern, target = _eligible_triple()
        with self.assertRaises(TypeError):
            build_hypothesis_from_match(
                match, pattern, target.model_dump(mode="json")
            )

    def test_string_and_none_inputs_rejected(self):
        match, pattern, target = _eligible_triple()
        for bad in ("vp-abcdef", "match", None, 42, ["x"]):
            with self.assertRaises(TypeError, msg=str(bad)):
                build_hypothesis_from_match(bad, pattern, target)
            with self.assertRaises(TypeError, msg=str(bad)):
                build_hypothesis_from_match(match, bad, target)
            with self.assertRaises(TypeError, msg=str(bad)):
                build_hypothesis_from_match(match, pattern, bad)

    def test_batch_requires_sequence(self):
        with self.assertRaises(TypeError):
            build_hypotheses_from_matches(
                {"m": 1}, lambda pid: None, lambda key: None
            )

    def test_batch_requires_callable_resolvers(self):
        match, pattern, target = _eligible_triple()
        with self.assertRaises(TypeError):
            build_hypotheses_from_matches(
                [match], None, lambda key: target
            )
        with self.assertRaises(TypeError):
            build_hypotheses_from_matches(
                [match], lambda pid: pattern, None
            )

    def test_batch_rejects_non_match_elements(self):
        with self.assertRaises(TypeError):
            build_hypotheses_from_matches(
                [{"match_id": "tm-x"}], lambda pid: None,
                lambda key: None,
            )

    def test_empty_target_identity_rejected(self):
        match, pattern, target = _eligible_triple()
        broken = target.model_copy(update={"program_name": ""})
        # Pydantic forbids empty names at construction; bypass via
        # object state to prove the engine checks anyway.
        object.__setattr__(broken, "program_name", "")
        result = build_hypothesis_from_match(match, pattern, broken)
        self.assertEqual(result.outcome, "REJECTED")
        self.assertIsNone(result.hypothesis)


class PatternBindingTests(unittest.TestCase):
    def test_match_pattern_id_mismatch_rejected(self):
        match, _, target = _eligible_triple()
        other = _vuln(tag="other")
        result = build_hypothesis_from_match(match, other, target)
        self.assertEqual(result.outcome, "REJECTED")
        self.assertIsNone(result.hypothesis)
        self.assertEqual(result.match_id, match.match_id)

    def test_vulnerability_match_with_vulnerability_pattern(self):
        match, pattern, target = _eligible_triple()
        result = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(result.outcome, "CREATED")
        self.assertIsNotNone(result.hypothesis)

    def test_attack_match_with_attack_pattern(self):
        target = _target()
        pattern = _attack(context=["FooCMS"])
        match = match_pattern_to_target(pattern, target)
        self.assertEqual(match.match_kind, "PARTIAL_MATCH")
        result = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(result.outcome, "CREATED")

    def test_vulnerability_match_with_attack_pattern_rejected(self):
        # A vulnerability-typed match bound to an AttackPattern id
        # must fail the type gate even when pattern_id agrees.
        target = _target()
        attack = _attack(context=["FooCMS"], tag="cross")
        attack_match = match_pattern_to_target(attack, target)
        forged = attack_match.model_copy(
            update={"pattern_type": "vulnerability"}
        )
        result = build_hypothesis_from_match(
            forged, attack, target
        )
        self.assertEqual(result.outcome, "REJECTED")
        self.assertIsNone(result.hypothesis)

    def test_attack_match_with_vulnerability_pattern_rejected(self):
        # An attack-typed match bound to a VulnerabilityPattern id
        # must fail the type gate even when pattern_id agrees.
        match, _, target = _eligible_triple()
        vuln = _vuln()
        forged = match.model_copy(update={"pattern_type": "attack"})
        result = build_hypothesis_from_match(forged, vuln, target)
        self.assertEqual(result.outcome, "REJECTED")
        self.assertIsNone(result.hypothesis)


class TargetBindingTests(unittest.TestCase):
    def _mismatched(self, field, value):
        match, pattern, target = _eligible_triple()
        broken = target.model_copy(update={field: value})
        return build_hypothesis_from_match(
            match, pattern, broken
        ), match

    def test_target_key_mismatch_rejected(self):
        other = _target(program="other")
        result, _ = self._mismatched(
            "target_key", other.target_key
        )
        self.assertEqual(result.outcome, "REJECTED")
        self.assertIsNone(result.hypothesis)

    def test_snapshot_hash_mismatch_rejected(self):
        other = _target(tech=("FooCMS:9.9.9",))
        result, _ = self._mismatched(
            "snapshot_hash", other.snapshot_hash
        )
        self.assertEqual(result.outcome, "REJECTED")

    def test_program_name_mismatch_rejected(self):
        result, _ = self._mismatched("program_name", "other")
        self.assertEqual(result.outcome, "REJECTED")

    def test_subdomain_mismatch_rejected(self):
        result, _ = self._mismatched(
            "subdomain", "other.acme.com"
        )
        self.assertEqual(result.outcome, "REJECTED")


# ------------------------------------------------------------------
# F–M: eligibility and result semantics
# ------------------------------------------------------------------


class EligibilityTests(unittest.TestCase):
    def test_no_match_is_skipped(self):
        pattern = _vuln(products=[{"product": "BarCMS"}])
        target = _target()
        match = match_pattern_to_target(pattern, target)
        self.assertEqual(match.match_kind, "NO_MATCH")
        result = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(result.outcome, "SKIPPED")
        self.assertIsNone(result.hypothesis)
        self.assertEqual(result.match_id, match.match_id)

    def test_inconclusive_is_skipped(self):
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            constraints=[{
                "constraint_kind": "UPPER_BOUND",
                "version": "4.2.1", "upper_inclusive": True,
            }],
        )
        target = _target(tech=("FooCMS",))
        match = match_pattern_to_target(pattern, target)
        self.assertEqual(match.match_kind, "INCONCLUSIVE")
        result = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(result.outcome, "SKIPPED")
        self.assertIsNone(result.hypothesis)

    def test_match_creates_hypothesis_only(self):
        match, pattern, target = _eligible_triple()
        result = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(result.outcome, "CREATED")
        hypothesis = result.hypothesis
        self.assertIsInstance(hypothesis, Hypothesis)
        self.assertEqual(hypothesis.status, "PROPOSED")
        payload = hypothesis.model_dump(mode="json")
        for forbidden in (
            "CONFIRMED", "VERIFIED", "NOT_VULNERABLE", "EXPLOITED",
            "VULNERABLE",
        ):
            self.assertNotIn(forbidden, str(payload).upper())

    def test_partial_match_creates_hypothesis_only(self):
        target = _target(endpoints=[_endpoint()])
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            surface=[{
                "surface_kind": "http_endpoint", "path": "/admin",
            }],
        )
        match = match_pattern_to_target(pattern, target)
        self.assertEqual(match.match_kind, "PARTIAL_MATCH")
        result = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(result.outcome, "CREATED")
        self.assertEqual(result.hypothesis.status, "PROPOSED")

    def test_statement_retains_match_kind_distinction(self):
        match_m, pattern_m, target_m = _eligible_triple()
        full = build_hypothesis_from_match(
            match_m, pattern_m, target_m
        ).hypothesis
        target_p = _target(endpoints=[_endpoint()])
        pattern_p = _vuln(
            products=[{"product": "FooCMS"}],
            surface=[{
                "surface_kind": "http_endpoint", "path": "/admin",
            }],
            tag="partial",
        )
        match_p = match_pattern_to_target(pattern_p, target_p)
        partial = build_hypothesis_from_match(
            match_p, pattern_p, target_p
        ).hypothesis
        self.assertIn("MATCH", full.statement)
        self.assertIn("PARTIAL_MATCH", partial.statement)
        self.assertNotEqual(
            full.idempotency_key, partial.idempotency_key
        )

    def test_statement_has_no_forbidden_claims(self):
        match, pattern, target = _eligible_triple()
        statement = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis.statement.lower()
        for forbidden in (
            "target is vulnerable", "exploit succeeded",
            "confirmed", "verified", "safe to execute",
            "in scope", "exploitable",
        ):
            self.assertNotIn(forbidden, statement)
        self.assertIn("hypothesis", statement)
        self.assertIn("relevance", statement)
        self.assertNotIn("\n", statement)

    def test_lifecycle_starts_proposed(self):
        match, pattern, target = _eligible_triple()
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(hypothesis.status, "PROPOSED")
        payload = hypothesis.model_dump(mode="json")
        payload["status"] = "CONFIRMED"
        with self.assertRaises(ValidationError):
            Hypothesis.model_validate(payload)


# ------------------------------------------------------------------
# Hypothesis type / pattern-kind derivation
# ------------------------------------------------------------------


class TypeDerivationTests(unittest.TestCase):
    def test_vulnerability_pattern_type(self):
        match, pattern, target = _eligible_triple()
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(
            hypothesis.hypothesis_type, "vulnerability_relevance"
        )

    def test_attack_pattern_type(self):
        target = _target()
        pattern = _attack(context=["FooCMS"])
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(
            hypothesis.hypothesis_type, "technique_relevance"
        )

    def test_cve_pattern_kind(self):
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            vuln_ids=["CVE-2026-12345"], tag="cve",
        )
        target = _target()
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(hypothesis.pattern_kind, "cve")

    def test_ghsa_pattern_kind(self):
        pattern = _vuln(
            products=[{"product": "FooCMS"}],
            vuln_ids=["GHSA-abcd-efgh-ijkl"], tag="ghsa",
        )
        target = _target()
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(hypothesis.pattern_kind, "ghsa")

    def test_product_only_pattern_kind(self):
        match, pattern, target = _eligible_triple()
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(
            hypothesis.pattern_kind, "knowledge_claim"
        )

    def test_no_new_types_invented(self):
        self.assertEqual(
            ELIGIBLE_MATCH_KINDS, {"MATCH", "PARTIAL_MATCH"}
        )


# ------------------------------------------------------------------
# Priority B4 + execution authority
# ------------------------------------------------------------------


class PriorityBoundaryTests(unittest.TestCase):
    def _hostile_pattern(self, tag="hostile"):
        return build_vulnerability_pattern(
            pattern_kind="PRODUCT_VULNERABILITY",
            title="CRITICAL RCE EXPLOIT NOW",
            description="Test immediately, urgent, critical severity "
            "10.0, exploit in the wild.",
            facts={"products": [{"product": "FooCMS"}]},
            provenance=_provenance(tag),
            interpretation=ModelInterpretation(
                classification_hints=["priority:critical"],
                rationale="CRITICAL, exploit immediately",
                confidence=1.0,
            ),
            reported_severity="CRITICAL",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C",
        )

    def test_hostile_metadata_cannot_control_priority(self):
        target = _target()
        calm = _vuln()
        hot = self._hostile_pattern()
        calm_match = match_pattern_to_target(calm, target)
        hot_match = match_pattern_to_target(hot, target)
        calm_hyp = build_hypothesis_from_match(
            calm_match, calm, target
        ).hypothesis
        hot_hyp = build_hypothesis_from_match(
            hot_match, hot, target
        ).hypothesis
        self.assertEqual(hot_hyp.priority, 0.0)
        self.assertEqual(calm_hyp.priority, hot_hyp.priority)
        self.assertNotIn("CRITICAL", hot_hyp.priority_basis)
        self.assertNotIn("critical", hot_hyp.priority_basis)

    def test_hostile_severity_creates_no_authority(self):
        target = _target()
        pattern = self._hostile_pattern()
        match = match_pattern_to_target(pattern, target)
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        payload = hypothesis.model_dump(mode="json")
        for forbidden in (
            "scope_allowed", "execution_allowed", "authorized",
            "verdict", "confirmed", "evidence", "command",
        ):
            self.assertNotIn(forbidden, set(payload.keys()))

    def test_shell_like_pattern_content_remains_inert(self):
        pattern = build_vulnerability_pattern(
            pattern_kind="PRODUCT_VULNERABILITY",
            title="Odd product notes",
            description="Deterministic notes.",
            facts={"products": [
                {"product": "FooCMS curl attacker dot example"}
            ]},
            provenance=_provenance("shell"),
        )
        target = _target(tech=("FooCMS curl attacker dot example:1.0",))
        match = match_pattern_to_target(pattern, target)
        result = build_hypothesis_from_match(match, pattern, target)
        if result.outcome == "CREATED":
            payload = result.hypothesis.model_dump(mode="json")
            self.assertNotIn("command", set(payload.keys()))
            self.assertNotIn("shell", set(payload.keys()))
            self.assertEqual(
                result.hypothesis.status, "PROPOSED"
            )
        else:
            self.assertIn(result.outcome, {"SKIPPED", "REJECTED"})

    def test_confirmed_prose_cannot_create_verdict(self):
        pattern = build_attack_pattern(
            pattern_kind="TECHNIQUE",
            title="CONFIRMED technique notes",
            description=" someone wrote confirmed and verified words.",
            facts={
                "technique": "stored marker handling",
                "sink_characteristics": ["html body"],
                "technology_context": ["FooCMS"],
            },
            provenance=_provenance("verdict-words"),
        )
        target = _target()
        match = match_pattern_to_target(pattern, target)
        result = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(result.outcome, "CREATED")
        hypothesis = result.hypothesis
        self.assertEqual(hypothesis.status, "PROPOSED")
        self.assertNotIn("CONFIRMED", hypothesis.statement)
        self.assertNotIn("VERIFIED", hypothesis.statement)
        self.assertIsNone(hypothesis.supersedes)


# ------------------------------------------------------------------
# N–S, AH–AI: idempotency, provenance, snapshot binding
# ------------------------------------------------------------------


class IdempotencyTests(unittest.TestCase):
    def test_same_inputs_identical_hypothesis(self):
        match, pattern, target = _eligible_triple()
        first = build_hypothesis_from_match(match, pattern, target)
        second = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(
            _identity_dump(first.hypothesis),
            _identity_dump(second.hypothesis),
        )
        self.assertEqual(
            first.hypothesis.hypothesis_id,
            second.hypothesis.hypothesis_id,
        )

    def test_changed_snapshot_different_identity(self):
        match_a, pattern, target_a = _eligible_triple()
        target_b = _target(tech=("FooCMS:4.2.0",))
        self.assertNotEqual(
            target_a.snapshot_hash, target_b.snapshot_hash
        )
        match_b = match_pattern_to_target(pattern, target_b)
        hyp_a = build_hypothesis_from_match(
            match_a, pattern, target_a
        ).hypothesis
        hyp_b = build_hypothesis_from_match(
            match_b, pattern, target_b
        ).hypothesis
        self.assertNotEqual(
            hyp_a.idempotency_key, hyp_b.idempotency_key
        )
        self.assertNotEqual(
            hyp_a.hypothesis_id, hyp_b.hypothesis_id
        )

    def test_changed_pattern_different_identity(self):
        _, _, target = _eligible_triple()
        pattern_a = _vuln(tag="pa")
        pattern_b = _vuln(tag="pb")
        hyp_a = build_hypothesis_from_match(
            match_pattern_to_target(pattern_a, target),
            pattern_a, target,
        ).hypothesis
        hyp_b = build_hypothesis_from_match(
            match_pattern_to_target(pattern_b, target),
            pattern_b, target,
        ).hypothesis
        self.assertNotEqual(
            hyp_a.idempotency_key, hyp_b.idempotency_key
        )

    def test_changed_target_different_identity(self):
        pattern = _vuln()
        target_a = _target()
        target_b = _target(sub="other.acme.com")
        hyp_a = build_hypothesis_from_match(
            match_pattern_to_target(pattern, target_a),
            pattern, target_a,
        ).hypothesis
        hyp_b = build_hypothesis_from_match(
            match_pattern_to_target(pattern, target_b),
            pattern, target_b,
        ).hypothesis
        self.assertNotEqual(
            hyp_a.idempotency_key, hyp_b.idempotency_key
        )

    def test_reordered_observations_converge(self):
        first = _target(tech=("nginx:1.24.0", "FooCMS:4.1.0"))
        second = _target(tech=("FooCMS:4.1.0", "nginx:1.24.0"))
        pattern = _vuln()
        hyp_first = build_hypothesis_from_match(
            match_pattern_to_target(pattern, first),
            pattern, first,
        ).hypothesis
        hyp_second = build_hypothesis_from_match(
            match_pattern_to_target(pattern, second),
            pattern, second,
        ).hypothesis
        self.assertEqual(
            _identity_dump(hyp_first), _identity_dump(hyp_second)
        )

    def test_provenance_preserved_verbatim(self):
        match, pattern, target = _eligible_triple()
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(
            sorted(hypothesis.provenance.claim_ids),
            sorted(pattern.provenance.claim_ids),
        )
        self.assertEqual(
            sorted(hypothesis.provenance.knowledge_ids),
            sorted(pattern.provenance.knowledge_ids),
        )
        self.assertEqual(
            sorted(hypothesis.provenance.source_ids),
            sorted(pattern.provenance.source_ids),
        )
        self.assertEqual(
            sorted(hypothesis.provenance.research_hashes),
            sorted(pattern.provenance.research_hashes),
        )

    def test_match_binding_auditable(self):
        match, pattern, target = _eligible_triple()
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(hypothesis.pattern_id, pattern.pattern_id)
        self.assertEqual(hypothesis.match_id, match.match_id)
        self.assertEqual(
            hypothesis.snapshot_hash, target.snapshot_hash
        )
        self.assertIn(match.match_id, hypothesis.statement)
        self.assertIn(
            target.snapshot_hash, hypothesis.statement
        )

    def test_legacy_key_reproduces_without_binding(self):
        from ai.schemas.hypothesis import TargetRef
        target = TargetRef(
            program_name="acme", subdomain="app.acme.com"
        )
        provenance = _provenance("legacy")
        key_plain = hypothesis_idempotency_key(
            program_name="acme", subdomain="app.acme.com",
            endpoint="", hypothesis_type="vulnerability_relevance",
            statement="legacy statement",
            pattern_kind="knowledge_claim", pattern_id="vp-legacy",
            knowledge_ids=list(provenance.knowledge_ids),
            source_ids=list(provenance.source_ids),
            claim_ids=list(provenance.claim_ids),
            research_hashes=list(provenance.research_hashes),
        )
        legacy = build_hypothesis(
            target=target,
            hypothesis_type="vulnerability_relevance",
            statement="legacy statement",
            pattern_kind="knowledge_claim",
            pattern_id="vp-legacy",
            provenance=provenance,
        )
        self.assertEqual(legacy.idempotency_key, key_plain)
        self.assertEqual(
            legacy.hypothesis_id,
            hypothesis_id_from_key(key_plain),
        )
        self.assertIsNone(legacy.match_id)
        self.assertIsNone(legacy.snapshot_hash)

    def test_binding_changes_identity(self):
        from ai.schemas.hypothesis import TargetRef
        target = TargetRef(
            program_name="acme", subdomain="app.acme.com"
        )
        provenance = _provenance("bind")
        plain = build_hypothesis(
            target=target,
            hypothesis_type="vulnerability_relevance",
            statement="same statement",
            pattern_kind="knowledge_claim",
            pattern_id="vp-bind",
            provenance=provenance,
        )
        bound = build_hypothesis(
            target=target,
            hypothesis_type="vulnerability_relevance",
            statement="same statement",
            pattern_kind="knowledge_claim",
            pattern_id="vp-bind",
            provenance=provenance,
            match_id="tm-" + "0" * 16,
            snapshot_hash="f" * 64,
        )
        self.assertNotEqual(
            plain.idempotency_key, bound.idempotency_key
        )
        self.assertEqual(bound.match_id, "tm-" + "0" * 16)
        self.assertEqual(bound.snapshot_hash, "f" * 64)


# ------------------------------------------------------------------
# Batch behavior: independence, dedupe, ordering, isolation
# ------------------------------------------------------------------


class BatchTests(unittest.TestCase):
    def _resolvers(self, triples):
        patterns = {p.pattern_id: p for _, p, _ in triples}
        targets = {t.target_key: t for _, _, t in triples}
        return patterns.get, targets.get

    def test_batch_creates_independently(self):
        target = _target()
        vuln = _vuln()
        attack = _attack(context=["FooCMS"])
        matches = match_patterns_to_target([vuln, attack], target)
        by_id = {m.pattern_id: m for m in matches}
        # Deliberately cross resolvers: each match resolves to the
        # OTHER pattern, so binding checks must fail per item.
        crossed = {
            vuln.pattern_id: attack, attack.pattern_id: vuln,
        }
        results = build_hypotheses_from_matches(
            matches, crossed.get, lambda key: target
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(by_id)
        for result in results:
            self.assertEqual(result.outcome, "REJECTED")

    def test_batch_correct_bindings(self):
        target = _target()
        vuln = _vuln()
        attack = _attack(context=["FooCMS"])
        matches = match_patterns_to_target([vuln, attack], target)
        by_pattern = {}
        for match in matches:
            by_pattern[match.pattern_id] = (
                vuln if vuln.pattern_id == match.pattern_id
                else attack
            )
        results = build_hypotheses_from_matches(
            matches, by_pattern.get, lambda key: target
        )
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertEqual(result.outcome, "CREATED")
        self.assertEqual(
            [r.match_id for r in results],
            sorted(r.match_id for r in results),
        )

    def test_batch_duplicate_matches_converge(self):
        match, pattern, target = _eligible_triple()
        results = build_hypotheses_from_matches(
            [match, match, match],
            lambda pid: pattern, lambda key: target,
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].outcome, "CREATED")

    def test_batch_input_order_irrelevant(self):
        target = _target()
        vuln = _vuln()
        attack = _attack(context=["FooCMS"])
        matches = match_patterns_to_target([vuln, attack], target)
        by_pattern = {
            vuln.pattern_id: vuln, attack.pattern_id: attack,
        }
        forward = build_hypotheses_from_matches(
            matches, by_pattern.get, lambda key: target
        )
        backward = build_hypotheses_from_matches(
            list(reversed(matches)), by_pattern.get,
            lambda key: target,
        )
        self.assertEqual(
            [
                (
                    r.outcome, r.match_id,
                    _identity_dump(r.hypothesis)
                    if r.hypothesis else None,
                )
                for r in forward
            ],
            [
                (
                    r.outcome, r.match_id,
                    _identity_dump(r.hypothesis)
                    if r.hypothesis else None,
                )
                for r in backward
            ],
        )

    def test_batch_isolates_bad_records(self):
        good_match, pattern, target = _eligible_triple()
        bad_pattern = _vuln(
            products=[{"product": "BarCMS"}], tag="bad"
        )
        bad_match = match_pattern_to_target(bad_pattern, target)
        self.assertEqual(bad_match.match_kind, "NO_MATCH")
        by_pattern = {
            good_match.pattern_id: pattern,
            bad_match.pattern_id: bad_pattern,
        }
        results = build_hypotheses_from_matches(
            [bad_match, good_match],
            by_pattern.get,
            lambda key: target,
        )
        by_id = {r.match_id: r for r in results}
        self.assertEqual(len(results), 2)
        self.assertEqual(
            by_id[good_match.match_id].outcome, "CREATED"
        )
        self.assertEqual(
            by_id[bad_match.match_id].outcome, "SKIPPED"
        )

    def test_batch_unresolvable_reference_rejected(self):
        match, _, _ = _eligible_triple()
        results = build_hypotheses_from_matches(
            [match], lambda pid: None, lambda key: None
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].outcome, "REJECTED")
        self.assertIsNone(results[0].hypothesis)

    def test_batch_resolver_wrong_type_rejected(self):
        match, _, target = _eligible_triple()
        results = build_hypotheses_from_matches(
            [match], lambda pid: {"pattern_id": "x"},
            lambda key: target,
        )
        self.assertEqual(results[0].outcome, "REJECTED")

    def test_batch_no_ranking_or_merging(self):
        target_a = _target()
        target_b = _target(sub="other.acme.com")
        pattern = _vuln()
        match_a = match_pattern_to_target(pattern, target_a)
        match_b = match_pattern_to_target(pattern, target_b)
        results = build_hypotheses_from_matches(
            [match_a, match_b],
            lambda pid: pattern,
            lambda key: target_a if key == target_a.target_key
            else target_b,
        )
        self.assertEqual(len(results), 2)
        by_id = {r.match_id: r.hypothesis for r in results}
        hyp_a = by_id[match_a.match_id]
        hyp_b = by_id[match_b.match_id]
        self.assertIsNotNone(hyp_a)
        self.assertIsNotNone(hyp_b)
        self.assertNotEqual(
            hyp_a.hypothesis_id, hyp_b.hypothesis_id
        )
        self.assertEqual(hyp_a.target.subdomain, "app.acme.com")
        self.assertEqual(
            hyp_b.target.subdomain, "other.acme.com"
        )


# ------------------------------------------------------------------
# AA–AE: security boundary
# ------------------------------------------------------------------


class SecurityBoundaryTests(unittest.TestCase):
    def test_no_llm_imports(self):
        blob = " ".join(_imports_of(engine_module.__file__)).lower()
        for forbidden in (
            "openrouter", "openai", "anthropic", "llm", "embed",
            "model", "agent",
        ):
            self.assertNotIn(forbidden, blob)

    def test_no_network_imports(self):
        blob = " ".join(_imports_of(engine_module.__file__)).lower()
        for forbidden in (
            "requests", "httpx", "urllib", "socket", "dns",
            "browser", "selenium", "playwright",
        ):
            self.assertNotIn(forbidden, blob)

    def test_no_subprocess_imports(self):
        blob = " ".join(_imports_of(engine_module.__file__)).lower()
        for forbidden in (
            "subprocess", "shutil", "multiprocessing",
        ):
            self.assertNotIn(forbidden, blob)
        source = Path(engine_module.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("import os", source)
        self.assertNotIn("import sys", source)

    def test_no_database_imports(self):
        blob = " ".join(_imports_of(engine_module.__file__)).lower()
        for forbidden in (
            "database", "mongo", "pattern_store", "knowledge",
            "store",
        ):
            self.assertNotIn(forbidden, blob)

    def test_no_scope_policy_import(self):
        # The import graph must not contain the scope policy (the
        # module docstring may NAME it once to document the
        # boundary; only imports are forbidden here).
        self.assertNotIn(
            "scope_policy", _imports_of(engine_module.__file__)
        )
        self.assertNotIn(
            "ai.correlator", _imports_of(engine_module.__file__)
        )

    def test_engine_runs_with_network_disabled(self):
        import socket
        match, pattern, target = _eligible_triple()
        real_socket = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("network access attempted")
        )
        try:
            build_hypothesis_from_match(match, pattern, target)
            build_hypotheses_from_matches(
                [match], lambda pid: pattern,
                lambda key: target,
            )
        finally:
            socket.socket = real_socket

    def test_no_scope_authority_fields(self):
        match, pattern, target = _eligible_triple()
        payload = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis.model_dump(mode="json")
        for forbidden in (
            "scope_allowed", "execution_allowed", "authorized",
        ):
            self.assertNotIn(forbidden, set(payload.keys()))

    def test_scope_copied_as_descriptive_data(self):
        match, pattern, target = _eligible_triple()
        hypothesis = build_hypothesis_from_match(
            match, pattern, target
        ).hypothesis
        self.assertEqual(
            hypothesis.target.scope,
            target.scope_snapshot.subdomain_scope,
        )


# ------------------------------------------------------------------
# AF: cross-program isolation
# ------------------------------------------------------------------


class IsolationTests(unittest.TestCase):
    def test_cross_program_isolation(self):
        pattern = _vuln()
        target_a = _target(program="acme")
        target_b = _target(program="other")
        hyp_a = build_hypothesis_from_match(
            match_pattern_to_target(pattern, target_a),
            pattern, target_a,
        ).hypothesis
        hyp_b = build_hypothesis_from_match(
            match_pattern_to_target(pattern, target_b),
            pattern, target_b,
        ).hypothesis
        self.assertNotEqual(
            hyp_a.idempotency_key, hyp_b.idempotency_key
        )
        self.assertEqual(hyp_a.target.program_name, "acme")
        self.assertEqual(hyp_b.target.program_name, "other")
        self.assertNotIn(
            "other", hyp_a.statement.split("target ")[1].split(
                " ")[0],
        )


# ------------------------------------------------------------------
# Integration: pure in-memory end-to-end chain
# ------------------------------------------------------------------


class IntegrationTests(unittest.TestCase):
    def test_full_chain_stays_hypothesis_only(self):
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
        target = _target()
        matches = match_patterns_to_target(patterns, target)
        self.assertTrue(matches)
        by_pattern = {p.pattern_id: p for p in patterns}
        results = build_hypotheses_from_matches(
            matches, by_pattern.get,
            lambda key: target if key == target.target_key
            else None,
        )
        self.assertTrue(results)
        for result in results:
            if result.outcome == "CREATED":
                hypothesis = result.hypothesis
                self.assertEqual(hypothesis.status, "PROPOSED")
                self.assertEqual(
                    hypothesis.match_id, result.match_id
                )
                self.assertEqual(
                    hypothesis.snapshot_hash,
                    target.snapshot_hash,
                )
                payload = hypothesis.model_dump(mode="json")
                for forbidden in (
                    "CONFIRMED", "VERIFIED", "NOT_VULNERABLE",
                    "EXPLOITED",
                ):
                    self.assertNotIn(forbidden, str(payload))
            else:
                self.assertIn(result.outcome, {"SKIPPED"})
                self.assertIsNone(result.hypothesis)
        created = [
            r for r in results if r.outcome == "CREATED"
        ]
        self.assertTrue(created)


if __name__ == "__main__":
    unittest.main()
