"""Focused tests for the persistent Pattern Store (Phase 2C).

STORAGE tests: they prove PatternStore persists Phase 2A patterns
with deterministic identity, idempotent writes, explicit conflict
handling, semantic grouping, an allowlisted lifecycle, fail-closed
corruption handling, atomic file-backed persistence, and no
execution/scope/target/finding authority. No network, no LLM, no
subprocess, no MongoDB is used (temporary directories only).
"""

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ai.knowledge import pattern_store as store_module
from ai.knowledge.pattern_store import (
    InvalidPatternTransitionError,
    PatternCorruptError,
    PatternIdentityConflictError,
    PatternNotFoundError,
    PatternStore,
    PatternStoreError,
)
from ai.schemas.hypothesis import ResearchProvenance
from ai.schemas.research_pattern import (
    AttackPattern,
    VulnerabilityPattern,
    build_attack_pattern,
    build_vulnerability_pattern,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_CLM1 = "clm-" + "c" * 16
_CLM2 = "clm-" + "d" * 16
_KB = "kb-" + "a" * 16
_SRC = "src-" + "b" * 16
_HASH1 = "e" * 64
_HASH2 = "f" * 64
_CREATED = "2026-01-01T00:00:00+00:00"


def _prov(**overrides):
    base = dict(
        knowledge_ids=[_KB],
        source_ids=[_SRC],
        claim_ids=[_CLM1],
        research_hashes=[_HASH1],
    )
    base.update(overrides)
    return ResearchProvenance(**base)


def _vp(**overrides):
    base = dict(
        pattern_kind="PRODUCT_VULNERABILITY",
        title="FooCMS profile bio stored XSS",
        description=(
            "Research claims FooCMS renders the profile bio "
            "without output encoding."
        ),
        facts={"products": [{"product": "FooCMS"}]},
        provenance=_prov(),
        created_at=_CREATED,
    )
    base.update(overrides)
    return build_vulnerability_pattern(**base)


def _ap(**overrides):
    base = dict(
        pattern_kind="TECHNIQUE",
        title="Stored XSS through profile field",
        description=(
            "Free-text profile input reaches the HTML body on "
            "profile render."
        ),
        facts={
            "technique": "stored_xss_via_profile_field",
            "input_characteristics": ["free-text profile input"],
            "sink_characteristics": [
                "stored value rendered into html body"
            ],
        },
        provenance=_prov(),
        created_at=_CREATED,
    )
    base.update(overrides)
    return build_attack_pattern(**base)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = PatternStore(
            Path(self._tmp.name) / "patterns"
        )

    def tearDown(self):
        self._tmp.cleanup()

    def _record_file(self, pattern):
        return (
            self.store.records_dir / f"{pattern.idempotency_key}.json"
        )

    def _rewrite_record(self, pattern, mutate):
        path = self._record_file(pattern)
        envelope = json.loads(path.read_text(encoding="utf-8"))
        mutate(envelope)
        path.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


# ------------------------------------------------------------------
# Basic storage
# ------------------------------------------------------------------


class BasicStorageTests(StoreTestCase):
    def test_store_and_retrieve_vulnerability_pattern(self):
        pattern = _vp()
        result = self.store.put(pattern)
        self.assertTrue(result.created)
        fetched = self.store.get(pattern.pattern_id)
        self.assertIsNotNone(fetched)
        self.assertIsInstance(fetched, VulnerabilityPattern)
        self.assertEqual(
            fetched.model_dump(mode="json"),
            result.pattern.model_dump(mode="json"),
        )
        self.assertEqual(
            fetched.facts.products[0].product, "FooCMS"
        )

    def test_store_and_retrieve_attack_pattern(self):
        pattern = _ap()
        result = self.store.put(pattern)
        self.assertTrue(result.created)
        fetched = self.store.get(pattern.pattern_id)
        self.assertIsInstance(fetched, AttackPattern)
        self.assertEqual(
            fetched.facts.technique, "stored_xss_via_profile_field"
        )

    def test_unknown_id_returns_none(self):
        self.assertIsNone(self.store.get("vp-" + "0" * 16))
        self.assertIsNone(self.store.get("ap-" + "0" * 16))

    def test_malformed_id_rejected(self):
        for bad_id in (
            "",
            "../records/evil",
            "/abs/path",
            "vp-zzz",
            "vp-" + "g" * 16,
            "kb-" + "a" * 16,
            "vp-short",
            "vp-" + "a" * 16 + "/x",
            "vp-\x00" + "a" * 12,
        ):
            with self.assertRaises(
                PatternStoreError, msg=f"id={bad_id!r}"
            ):
                self.store.get(bad_id)

    def test_empty_store(self):
        self.assertIsNone(self.store.get(_vp().pattern_id))
        self.assertEqual(self.store.list(), [])
        self.assertEqual(
            self.store.get_by_semantic_key("a" * 64), []
        )

    def test_put_rejects_non_pattern(self):
        for bad in ("raw text", {"pattern_id": "vp-x"}, None, 42):
            with self.assertRaises(TypeError):
                self.store.put(bad)


# ------------------------------------------------------------------
# Identity
# ------------------------------------------------------------------


class IdentityTests(StoreTestCase):
    def test_same_pattern_twice_is_idempotent(self):
        pattern = _vp()
        first = self.store.put(pattern)
        second = self.store.put(pattern)
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(
            first.pattern.model_dump(mode="json"),
            second.pattern.model_dump(mode="json"),
        )
        self.assertEqual(len(self.store.list()), 1)

    def test_same_id_different_identity_is_conflict(self):
        pattern = _vp()
        self.store.put(pattern)
        index_text = self.store.index_path.read_text(
            encoding="utf-8"
        )
        index = json.loads(index_text)
        index["patterns"][pattern.pattern_id][
            "idempotency_key"
        ] = "0" * 64
        index["patterns"][pattern.pattern_id]["path"] = (
            "records/" + "0" * 64 + ".json"
        )
        self.store.index_path.write_text(
            json.dumps(index, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(PatternIdentityConflictError):
            self.store.put(pattern)

    def test_tampered_pattern_id_rejected(self):
        pattern = _vp()
        tampered = VulnerabilityPattern.model_construct(
            **{
                **pattern.model_dump(mode="json"),
                "pattern_id": "vp-" + "0" * 16,
            }
        )
        with self.assertRaises(PatternStoreError):
            self.store.put(tampered)
        self.assertEqual(self.store.list(), [])

    def test_tampered_semantic_key_rejected(self):
        pattern = _vp()
        tampered = VulnerabilityPattern.model_construct(
            **{
                **pattern.model_dump(mode="json"),
                "semantic_key": "1" * 64,
            }
        )
        with self.assertRaises(PatternStoreError):
            self.store.put(tampered)
        self.assertEqual(self.store.list(), [])

    def test_tampered_idempotency_key_rejected(self):
        pattern = _vp()
        tampered = VulnerabilityPattern.model_construct(
            **{
                **pattern.model_dump(mode="json"),
                "idempotency_key": "2" * 64,
            }
        )
        with self.assertRaises(PatternStoreError):
            self.store.put(tampered)
        self.assertEqual(self.store.list(), [])

    def test_idempotency_lookup(self):
        pattern = _ap()
        self.store.put(pattern)
        fetched = self.store.get_by_idempotency_key(
            pattern.idempotency_key
        )
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.pattern_id, pattern.pattern_id)
        self.assertIsNone(
            self.store.get_by_idempotency_key("0" * 64)
        )
        with self.assertRaises(PatternStoreError):
            self.store.get_by_idempotency_key("not-a-key")

    def test_semantic_lookup(self):
        pattern = _vp()
        self.store.put(pattern)
        matches = self.store.get_by_semantic_key(
            pattern.semantic_key
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pattern_id, pattern.pattern_id)
        with self.assertRaises(PatternStoreError):
            self.store.get_by_semantic_key("not-a-key")


# ------------------------------------------------------------------
# Semantic convergence
# ------------------------------------------------------------------


class SemanticConvergenceTests(StoreTestCase):
    def _two_variants(self):
        first = _vp(provenance=_prov(claim_ids=[_CLM1]))
        second = _vp(
            provenance=_prov(
                claim_ids=[_CLM2], research_hashes=[_HASH2]
            )
        )
        self.assertEqual(first.semantic_key, second.semantic_key)
        self.assertNotEqual(first.pattern_id, second.pattern_id)
        return first, second

    def test_same_semantic_groups_variants(self):
        first, second = self._two_variants()
        self.store.put(first)
        self.store.put(second)
        matches = self.store.get_by_semantic_key(first.semantic_key)
        self.assertEqual(len(matches), 2)
        self.assertEqual(
            [item.pattern_id for item in matches],
            sorted([first.pattern_id, second.pattern_id]),
        )

    def test_variant_provenance_preserved(self):
        first, second = self._two_variants()
        self.store.put(first)
        self.store.put(second)
        self.assertEqual(
            self.store.get(first.pattern_id).provenance.claim_ids,
            [_CLM1],
        )
        self.assertEqual(
            self.store.get(second.pattern_id).provenance.claim_ids,
            [_CLM2],
        )

    def test_variant_does_not_overwrite_sibling(self):
        first, second = self._two_variants()
        self.store.put(first)
        before = self.store.get(first.pattern_id).model_dump(
            mode="json"
        )
        self.store.put(second)
        after = self.store.get(first.pattern_id).model_dump(
            mode="json"
        )
        self.assertEqual(before, after)

    def test_semantic_lookup_ordering_deterministic(self):
        first, second = self._two_variants()
        self.store.put(second)
        self.store.put(first)
        matches = self.store.get_by_semantic_key(first.semantic_key)
        self.assertEqual(
            [item.pattern_id for item in matches],
            sorted([first.pattern_id, second.pattern_id]),
        )


# ------------------------------------------------------------------
# Lifecycle
# ------------------------------------------------------------------


class LifecycleTests(StoreTestCase):
    def test_initial_state_is_active(self):
        pattern = _vp()
        self.store.put(pattern)
        self.assertEqual(
            self.store.get(pattern.pattern_id).status, "ACTIVE"
        )

    def test_active_to_superseded(self):
        old = _vp()
        new = _vp(provenance=_prov(claim_ids=[_CLM2]))
        self.store.put(old)
        self.store.put(new)
        updated = self.store.transition(
            old.pattern_id,
            status="SUPERSEDED",
            supersedes=new.pattern_id,
        )
        self.assertEqual(updated.status, "SUPERSEDED")
        self.assertEqual(updated.supersedes, new.pattern_id)
        self.assertEqual(updated.idempotency_key, old.idempotency_key)
        self.assertEqual(updated.semantic_key, old.semantic_key)
        fetched = self.store.get(old.pattern_id)
        self.assertEqual(fetched.status, "SUPERSEDED")

    def test_active_to_retired(self):
        pattern = _vp()
        self.store.put(pattern)
        updated = self.store.transition(
            pattern.pattern_id,
            status="RETIRED",
            retirement_reason="Product line discontinued; "
            "research obsolete.",
        )
        self.assertEqual(updated.status, "RETIRED")
        # History preserved: facts and provenance untouched.
        self.assertEqual(updated.facts, pattern.facts)
        self.assertEqual(updated.provenance, pattern.provenance)

    def test_superseded_to_retired(self):
        old = _vp()
        new = _vp(provenance=_prov(claim_ids=[_CLM2]))
        self.store.put(old)
        self.store.put(new)
        self.store.transition(
            old.pattern_id,
            status="SUPERSEDED",
            supersedes=new.pattern_id,
        )
        updated = self.store.transition(
            old.pattern_id,
            status="RETIRED",
            retirement_reason="Superseding research withdrawn.",
        )
        self.assertEqual(updated.status, "RETIRED")

    def test_retired_is_terminal(self):
        pattern = _vp()
        self.store.put(pattern)
        self.store.transition(
            pattern.pattern_id,
            status="RETIRED",
            retirement_reason="Obsolete.",
        )
        for target in ("ACTIVE", "SUPERSEDED", "RETIRED"):
            kwargs = (
                {"supersedes": pattern.pattern_id}
                if target == "SUPERSEDED"
                else (
                    {"retirement_reason": "x"}
                    if target == "RETIRED"
                    else {}
                )
            )
            if target == "RETIRED":
                # Same-status no-op still succeeds.
                same = self.store.transition(
                    pattern.pattern_id,
                    status="RETIRED",
                    retirement_reason="Obsolete.",
                )
                self.assertEqual(same.status, "RETIRED")
                continue
            with self.assertRaises(InvalidPatternTransitionError):
                self.store.transition(
                    pattern.pattern_id, status=target, **kwargs
                )

    def test_invalid_status_rejected(self):
        pattern = _vp()
        self.store.put(pattern)
        for bad_status in (
            "CONFIRMED",
            "VERIFIED",
            "NOT_VULNERABLE",
            "EXPLOITED",
            "SAFE",
            "active",
            "",
        ):
            with self.assertRaises(
                InvalidPatternTransitionError,
                msg=f"status={bad_status!r}",
            ):
                self.store.transition(
                    pattern.pattern_id, status=bad_status
                )

    def test_supersedes_missing_target_rejected(self):
        pattern = _vp()
        self.store.put(pattern)
        with self.assertRaises(PatternNotFoundError):
            self.store.transition(
                pattern.pattern_id,
                status="SUPERSEDED",
                supersedes="vp-" + "0" * 16,
            )
        with self.assertRaises(InvalidPatternTransitionError):
            self.store.transition(
                pattern.pattern_id, status="SUPERSEDED"
            )

    def test_self_supersede_rejected(self):
        pattern = _vp()
        self.store.put(pattern)
        with self.assertRaises(InvalidPatternTransitionError):
            self.store.transition(
                pattern.pattern_id,
                status="SUPERSEDED",
                supersedes=pattern.pattern_id,
            )

    def test_circular_supersede_rejected(self):
        first = _vp()
        second = _vp(provenance=_prov(claim_ids=[_CLM2]))
        self.store.put(first)
        self.store.put(second)
        self.store.transition(
            first.pattern_id,
            status="SUPERSEDED",
            supersedes=second.pattern_id,
        )
        with self.assertRaises(InvalidPatternTransitionError):
            self.store.transition(
                second.pattern_id,
                status="SUPERSEDED",
                supersedes=first.pattern_id,
            )

    def test_cross_type_supersede_rejected(self):
        vuln = _vp()
        attack = _ap()
        self.store.put(vuln)
        self.store.put(attack)
        with self.assertRaises(InvalidPatternTransitionError):
            self.store.transition(
                vuln.pattern_id,
                status="SUPERSEDED",
                supersedes=attack.pattern_id,
            )

    def test_retirement_reason_enforced(self):
        pattern = _vp()
        self.store.put(pattern)
        for bad_reason in (None, "", "   "):
            with self.assertRaises(InvalidPatternTransitionError):
                self.store.transition(
                    pattern.pattern_id,
                    status="RETIRED",
                    retirement_reason=bad_reason,
                )

    def test_transition_unknown_id(self):
        with self.assertRaises(PatternNotFoundError):
            self.store.transition(
                "vp-" + "0" * 16, status="RETIRED",
                retirement_reason="x",
            )
        with self.assertRaises(PatternStoreError):
            self.store.transition("../evil", status="RETIRED",
                                  retirement_reason="x")

    def test_same_status_noop(self):
        pattern = _vp()
        self.store.put(pattern)
        same = self.store.transition(
            pattern.pattern_id, status="ACTIVE"
        )
        self.assertEqual(same.status, "ACTIVE")
        self.assertEqual(same.pattern_id, pattern.pattern_id)

    def test_list_filters(self):
        vuln = _vp()
        attack = _ap()
        self.store.put(vuln)
        self.store.put(attack)
        self.store.transition(
            vuln.pattern_id,
            status="RETIRED",
            retirement_reason="Obsolete.",
        )
        self.assertEqual(
            [item.pattern_id for item in self.store.list()],
            sorted([vuln.pattern_id, attack.pattern_id]),
        )
        self.assertEqual(
            [item.pattern_id for item in self.store.list(
                pattern_type="vulnerability")],
            [vuln.pattern_id],
        )
        self.assertEqual(
            [item.pattern_id for item in self.store.list(
                pattern_type="attack")],
            [attack.pattern_id],
        )
        self.assertEqual(
            [item.pattern_id for item in self.store.list(
                status="RETIRED")],
            [vuln.pattern_id],
        )
        self.assertEqual(
            [item.pattern_id for item in self.store.list(
                status="ACTIVE")],
            [attack.pattern_id],
        )
        self.assertEqual(
            [item.pattern_id for item in self.store.list(
                semantic_key=vuln.semantic_key)],
            [vuln.pattern_id],
        )
        with self.assertRaises(PatternStoreError):
            self.store.list(pattern_type="finding")
        with self.assertRaises(PatternStoreError):
            self.store.list(status="CONFIRMED")
        with self.assertRaises(PatternStoreError):
            self.store.list(semantic_key="nope")


# ------------------------------------------------------------------
# Corruption
# ------------------------------------------------------------------


class CorruptionTests(StoreTestCase):
    def test_malformed_json_rejected(self):
        pattern = _vp()
        self.store.put(pattern)
        self._record_file(pattern).write_text(
            "{not json", encoding="utf-8"
        )
        with self.assertRaises(PatternCorruptError):
            self.store.get(pattern.pattern_id)
        # Never silently repaired: still corrupt on re-read.
        with self.assertRaises(PatternCorruptError):
            self.store.get(pattern.pattern_id)

    def test_unknown_schema_version_rejected(self):
        pattern = _vp()
        self.store.put(pattern)

        def mutate(envelope):
            envelope["schema_version"] = "vulnerability_pattern/v99"

        self._rewrite_record(pattern, mutate)
        with self.assertRaises(PatternCorruptError):
            self.store.get(pattern.pattern_id)

    def test_invalid_pattern_type_rejected(self):
        pattern = _vp()
        self.store.put(pattern)

        def mutate(envelope):
            envelope["pattern_type"] = "exploit"

        self._rewrite_record(pattern, mutate)
        with self.assertRaises(PatternCorruptError):
            self.store.get(pattern.pattern_id)

    def test_type_masquerade_rejected(self):
        pattern = _vp()
        self.store.put(pattern)

        def mutate(envelope):
            envelope["pattern_type"] = "attack"

        self._rewrite_record(pattern, mutate)
        with self.assertRaises(PatternCorruptError):
            self.store.get(pattern.pattern_id)

    def test_tampered_fact_rejected(self):
        pattern = _vp()
        self.store.put(pattern)

        def mutate(envelope):
            envelope["pattern"]["facts"]["products"] = [
                {"product": "EvilCMS"}
            ]

        self._rewrite_record(pattern, mutate)
        with self.assertRaises(PatternCorruptError):
            self.store.get(pattern.pattern_id)

    def test_invalid_provenance_rejected(self):
        pattern = _vp()
        self.store.put(pattern)

        def mutate(envelope):
            envelope["pattern"]["provenance"]["claim_ids"] = []

        self._rewrite_record(pattern, mutate)
        with self.assertRaises(PatternCorruptError):
            self.store.get(pattern.pattern_id)

    def test_forbidden_extra_field_rejected(self):
        pattern = _vp()
        self.store.put(pattern)

        def mutate(envelope):
            envelope["pattern"]["scope_allowed"] = True
            envelope["pattern"]["command"] = "curl attacker.example"
            envelope["pattern"]["verdict"] = "CONFIRMED"

        self._rewrite_record(pattern, mutate)
        with self.assertRaises(PatternCorruptError):
            self.store.get(pattern.pattern_id)

    def test_missing_record_file_rejected(self):
        pattern = _vp()
        self.store.put(pattern)
        self._record_file(pattern).unlink()
        with self.assertRaises(PatternCorruptError):
            self.store.get(pattern.pattern_id)

    def test_corrupt_index_rejected(self):
        self.store.index_path.parent.mkdir(
            parents=True, exist_ok=True
        )
        self.store.index_path.write_text(
            "{broken", encoding="utf-8"
        )
        with self.assertRaises(PatternCorruptError):
            self.store.list()


# ------------------------------------------------------------------
# Persistence
# ------------------------------------------------------------------


class PersistenceTests(StoreTestCase):
    def test_store_survives_restart(self):
        vuln = _vp()
        attack = _ap()
        self.store.put(vuln)
        self.store.put(attack)
        reopened = PatternStore(self.store.root_dir)
        self.assertEqual(
            reopened.get(vuln.pattern_id).idempotency_key,
            vuln.idempotency_key,
        )
        self.assertEqual(
            reopened.get(attack.pattern_id).idempotency_key,
            attack.idempotency_key,
        )
        self.assertEqual(
            [item.pattern_id for item in reopened.list()],
            sorted([vuln.pattern_id, attack.pattern_id]),
        )

    def test_deterministic_serialization(self):
        first_dir = Path(self._tmp.name) / "a"
        second_dir = Path(self._tmp.name) / "b"
        PatternStore(first_dir).put(_vp())
        PatternStore(second_dir).put(_vp())
        first_files = sorted(
            (first_dir / "records").glob("*.json")
        )
        second_files = sorted(
            (second_dir / "records").glob("*.json")
        )
        self.assertEqual(len(first_files), 1)
        self.assertEqual(
            first_files[0].name, second_files[0].name
        )
        self.assertEqual(
            first_files[0].read_bytes(), second_files[0].read_bytes()
        )

    def test_records_are_plain_json_never_pickle(self):
        pattern = _vp()
        self.store.put(pattern)
        raw = self._record_file(pattern).read_bytes()
        self.assertFalse(raw.startswith(b"\x80"))
        parsed = json.loads(raw.decode("utf-8"))
        self.assertEqual(parsed["pattern_type"], "vulnerability")
        source = Path(store_module.__file__).read_text(
            encoding="utf-8"
        )
        for stmt in (
            "import pickle",
            "from pickle",
            "import marshal",
            "from marshal",
            "pickle.loads",
            "pickle.load(",
        ):
            self.assertNotIn(stmt, source)

    def test_no_temp_files_left_behind(self):
        vuln = _vp()
        attack = _ap()
        self.store.put(vuln)
        self.store.put(attack)
        self.store.transition(
            vuln.pattern_id,
            status="RETIRED",
            retirement_reason="Obsolete.",
        )
        leftovers = list(self.store.root_dir.rglob("*.tmp"))
        self.assertEqual(leftovers, [])

    def test_concurrent_identical_writes_converge(self):
        pattern = _vp()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(lambda _: self.store.put(pattern), range(8))
            )
        for result in results:
            self.assertEqual(
                result.pattern.pattern_id, pattern.pattern_id
            )
            self.assertEqual(
                result.pattern.idempotency_key,
                pattern.idempotency_key,
            )
        self.assertEqual(len(self.store.list()), 1)
        fetched = self.store.get(pattern.pattern_id)
        self.assertEqual(
            fetched.idempotency_key, pattern.idempotency_key
        )


# ------------------------------------------------------------------
# Security boundary
# ------------------------------------------------------------------


class SecurityBoundaryTests(StoreTestCase):
    def test_module_has_no_llm_network_or_execution_symbols(self):
        names = set(store_module.__dict__)
        for forbidden in (
            "LLMProvider",
            "openrouter",
            "avalai",
            "requests",
            "urllib",
            "httpx",
            "socket",
            "subprocess",
            "eval",
            "exec",
            "pickle",
            "NucleiRunner",
        ):
            self.assertNotIn(forbidden, names)

    def test_operations_run_with_network_disabled(self):
        import socket

        original = socket.socket

        def _blocked(*args, **kwargs):
            raise AssertionError("network access attempted")

        pattern = _vp()
        socket.socket = _blocked
        try:
            self.store.put(pattern)
            self.store.get(pattern.pattern_id)
            self.store.list()
            self.store.get_by_semantic_key(pattern.semantic_key)
        finally:
            socket.socket = original

    def test_traversal_ids_cannot_reach_filesystem(self):
        before = sorted(
            path.name for path in self.store.root_dir.rglob("*")
            if path.is_file()
        )
        for evil in (
            "../../evil",
            "/etc/passwd",
            "vp-../../../tmp/x",
            "..\\windows",
        ):
            with self.assertRaises(PatternStoreError):
                self.store.get(evil)
        after = sorted(
            path.name for path in self.store.root_dir.rglob("*")
            if path.is_file()
        )
        self.assertEqual(before, after)

    def test_pattern_fields_never_become_paths(self):
        pattern = _vp(
            title="../../evil",
            description="/abs/path",
            facts={"products": [{"product": "a/b\\c"}]},
        )
        self.store.put(pattern)
        names = sorted(
            path.name for path in self.store.records_dir.glob("*")
        )
        self.assertEqual(
            names, [f"{pattern.idempotency_key}.json"]
        )

    def test_malicious_record_never_persists(self):
        pattern = _vp()
        tampered = VulnerabilityPattern.model_construct(
            **{
                **pattern.model_dump(mode="json"),
                "scope_allowed": True,
                "target_affected": True,
                "confirmed": True,
                "verdict": "CONFIRMED",
                "command": "curl attacker.example",
                "shell": "sh",
            }
        )
        with self.assertRaises(PatternStoreError):
            self.store.put(tampered)
        self.assertEqual(self.store.list(), [])

    def test_stored_patterns_carry_no_foreign_authority(self):
        self.store.put(_vp())
        self.store.put(_ap())
        for stored in self.store.list():
            blob = stored.model_dump(mode="json")
            for forbidden in (
                "scope_allowed",
                "allow_scope",
                "target_affected",
                "match_score",
                "command",
                "subprocess",
                "shell",
                "tool_call",
                "callback",
                "verdict",
                "confirmed",
                "finding_status",
                "evidence",
            ):
                self.assertNotIn(forbidden, blob)
            self.assertIn(stored.status, ("ACTIVE",))


# ------------------------------------------------------------------
# Phase 2B → 2C integration
# ------------------------------------------------------------------


class ProjectorToStoreIntegrationTests(StoreTestCase):
    def test_grounded_claim_to_stored_pattern_round_trip(self):
        from ai.researcher.pattern_projector import (
            GroundedClaim,
            project_claim,
        )
        from ai.schemas.ingestion import ExtractedClaim

        claim = ExtractedClaim(
            evidence_class="EXPLICIT",
            rationale="directly stated in source",
            evidence_snippets=[
                {
                    "text": "FooCMS renders the profile bio field",
                    "section": "body",
                }
            ],
            title="FooCMS profile bio stored XSS",
            summary="FooCMS renders the profile bio field "
            "without encoding",
            technologies=["FooCMS"],
            techniques=["stored_xss_via_profile_field"],
            contexts=["html_body"],
            verification_patterns=[
                "stored marker executes on read"
            ],
            confidence=0.9,
        )
        grounded = GroundedClaim(
            claim=claim,
            claim_id=_CLM1,
            knowledge_id=_KB,
            source_id=_SRC,
            research_hash=_HASH1,
        )
        patterns = project_claim(grounded)
        self.assertGreaterEqual(len(patterns), 1)
        for pattern in patterns:
            result = self.store.put(pattern)
            self.assertTrue(result.created)
            fetched = self.store.get(pattern.pattern_id)
            self.assertIsNotNone(fetched)
            self.assertEqual(
                fetched.model_dump(mode="json"),
                pattern.model_dump(mode="json"),
            )
            self.assertEqual(
                fetched.semantic_key, pattern.semantic_key
            )
            self.assertEqual(
                fetched.idempotency_key, pattern.idempotency_key
            )


if __name__ == "__main__":
    unittest.main()
