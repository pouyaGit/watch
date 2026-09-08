"""Focused tests for Phase 4E retrieval & integrity audit.

Proves the read-only boundary::

    ArtifactStore
        +--> binding retrieval (read-only, id-ordered)
        +--> provenance audit (PASS / FAIL / INCONCLUSIVE)
        +--> integrity sweep (structured, never mutating)
        v
    read-only audit/query results

Strictly read-only: no generation, mutation, deletion,
execution, verification, findings, verdicts, LLM, network,
subprocess, or database. Covers the adversarial matrix A-AR.
"""

import ast
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ai.knowledge.artifact_store import (
    ArtifactCorruptError,
    ArtifactIdentityConflictError,
    ArtifactStore,
    ArtifactStoreError,
    StoredArtifact,
)
from ai.researcher.artifact_retrieval import (
    ArtifactRetrievalError,
    audit_provenance,
    get_by_binding,
    get_by_hypothesis_id,
    get_by_match_id,
    get_by_snapshot_hash,
    get_by_test_plan_id,
    verify_all,
)
from ai.test_artifact_store import (
    _benign,
    _bound_plan,
    _forge,
    _template_bytes,
    _valid_http,
    _valid_nuclei,
    _valid_xss,
    _vulnerable,
)

RETRIEVAL_PATH = "ai/researcher/artifact_retrieval.py"


def _hex(tag):
    return hashlib.sha256(tag.encode("utf-8")).hexdigest()


class RetrievalTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="artretr-")
        self.store = ArtifactStore(Path(self._tmp.name) / "store")

    def tearDown(self):
        self._tmp.cleanup()

    def _put_nuclei(self, plan, marker):
        content = _template_bytes(marker)
        from ai.researcher.artifact_validator import (
            build_validated_reference,
        )

        validated = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable(marker)],
        )
        assert validated.state == "VALID", validated.reasons
        return self.store.put(validated.reference, content).stored

    def _index(self):
        return json.loads(
            self.store.index_path.read_text(encoding="utf-8")
        )

    def _write_index(self, index):
        self.store.index_path.write_text(
            json.dumps(index, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


# ------------------------------------------------------------------
# A-F, N: binding retrieval
# ------------------------------------------------------------------


class BindingRetrievalTests(RetrievalTestCase):
    def test_retrieval_by_test_plan_id(self):
        plan_a = _bound_plan(sub="a.acme.com")
        plan_b = _bound_plan(sub="b.acme.com")
        ref_a, content_a = _valid_nuclei(plan_a)
        ref_ax, content_ax = _valid_xss(plan_a, b"payload-a-1")
        stored_b = self._put_nuclei(plan_b, "marker-plan-b-2222")
        ref_b, content_b = stored_b.reference, stored_b.content
        self.store.put(ref_a, content_a)
        self.store.put(ref_ax, content_ax)
        found = get_by_test_plan_id(self.store, plan_a.test_plan_id)
        self.assertEqual(len(found), 2)
        self.assertEqual(
            [item.reference.artifact_id for item in found],
            sorted(item.reference.artifact_id for item in found),
        )
        by_id = {item.reference.artifact_id: item for item in found}
        self.assertEqual(by_id[ref_a.artifact_id].content, content_a)
        self.assertEqual(by_id[ref_ax.artifact_id].content, content_ax)
        self.assertEqual(
            by_id[ref_a.artifact_id].reference, ref_a
        )
        # Unrelated artifact never appears.
        self.assertNotIn(
            ref_b.artifact_id, {item.reference.artifact_id for item in found}
        )

    def test_retrieval_by_hypothesis_id(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        found = get_by_hypothesis_id(self.store, plan.hypothesis_id)
        self.assertEqual(
            [item.reference.artifact_id for item in found],
            [ref.artifact_id],
        )

    def test_retrieval_by_match_id(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        assert plan.match_id is not None
        found = get_by_match_id(self.store, plan.match_id)
        self.assertEqual(
            [item.reference.artifact_id for item in found],
            [ref.artifact_id],
        )

    def test_retrieval_by_snapshot_hash(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        assert plan.snapshot_hash is not None
        found = get_by_snapshot_hash(self.store, plan.snapshot_hash)
        self.assertEqual(
            [item.reference.artifact_id for item in found],
            [ref.artifact_id],
        )

    def test_combined_binding_filters(self):
        plan = _bound_plan()
        ref_n, content_n = _valid_nuclei(plan)
        ref_x, content_x = _valid_xss(plan)
        self.store.put(ref_n, content_n)
        self.store.put(ref_x, content_x)
        found = get_by_binding(
            self.store,
            test_plan_id=plan.test_plan_id,
            artifact_type="xss_payload",
        )
        self.assertEqual(
            [item.reference.artifact_id for item in found],
            [ref_x.artifact_id],
        )
        both = get_by_binding(
            self.store,
            hypothesis_id=plan.hypothesis_id,
            match_id=plan.match_id,
            snapshot_hash=plan.snapshot_hash,
        )
        self.assertEqual(len(both), 2)

    def test_artifact_type_filtering(self):
        plan = _bound_plan()
        ref_n, content_n = _valid_nuclei(plan)
        ref_h, content_h = _valid_http(plan)
        self.store.put(ref_n, content_n)
        self.store.put(ref_h, content_h)
        nuclei = get_by_binding(self.store, artifact_type="nuclei_template")
        self.assertEqual(
            [item.reference.artifact_id for item in nuclei],
            [ref_n.artifact_id],
        )
        http = get_by_binding(
            self.store, artifact_type="http_request_spec"
        )
        self.assertEqual(
            [item.reference.artifact_id for item in http],
            [ref_h.artifact_id],
        )
        with self.assertRaises(ArtifactRetrievalError):
            get_by_binding(self.store, artifact_type="shell_script")

    def test_cross_program_identity_isolation(self):
        plan_p1 = _bound_plan(program="prog1", sub="a.prog1.com")
        plan_p2 = _bound_plan(program="prog2", sub="a.prog2.com")
        ref1, content1 = _valid_nuclei(plan_p1)
        stored2 = self._put_nuclei(plan_p2, "marker-prog2-4444")
        ref2 = stored2.reference
        self.store.put(ref1, content1)
        found1 = get_by_test_plan_id(self.store, plan_p1.test_plan_id)
        found2 = get_by_test_plan_id(self.store, plan_p2.test_plan_id)
        self.assertEqual(
            [item.reference.artifact_id for item in found1],
            [ref1.artifact_id],
        )
        self.assertEqual(
            [item.reference.artifact_id for item in found2],
            [ref2.artifact_id],
        )
        self.assertTrue(
            {item.reference.artifact_id for item in found1}.isdisjoint(
                {item.reference.artifact_id for item in found2}
            )
        )


# ------------------------------------------------------------------
# G-J: ordering, duplicates, missing, malformed
# ------------------------------------------------------------------


class RetrievalSemanticsTests(RetrievalTestCase):
    def _store_three(self):
        plans = [
            _bound_plan(sub=f"{letter}.acme.com")
            for letter in ("c", "a", "b")
        ]
        refs = []
        for plan, marker in zip(
            plans,
            ("marker-aaa-1111", "marker-bbb-2222", "marker-ccc-3333"),
        ):
            refs.append(self._put_nuclei(plan, marker))
        return plans, refs

    def test_deterministic_ordering(self):
        plans, refs = self._store_three()
        for plan in plans:
            first = get_by_test_plan_id(self.store, plan.test_plan_id)
            second = get_by_test_plan_id(self.store, plan.test_plan_id)
            self.assertEqual(first, second)
        all_found = get_by_binding(
            self.store, artifact_type="nuclei_template"
        )
        ids = [item.reference.artifact_id for item in all_found]
        self.assertEqual(ids, sorted(ids))

    def test_duplicate_free_results(self):
        plans, _ = self._store_three()
        for plan in plans:
            found = get_by_test_plan_id(self.store, plan.test_plan_id)
            ids = [item.reference.artifact_id for item in found]
            self.assertEqual(len(ids), len(set(ids)))

    def test_missing_binding_returns_empty(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        self.assertEqual(
            get_by_test_plan_id(self.store, "tp-" + "0" * 16), ()
        )
        self.assertEqual(
            get_by_hypothesis_id(self.store, "hyp-" + "0" * 16), ()
        )
        self.assertEqual(
            get_by_match_id(self.store, "tm-" + "0" * 16), ()
        )
        self.assertEqual(
            get_by_snapshot_hash(self.store, "0" * 64), ()
        )

    def test_malformed_binding_rejected(self):
        for call in (
            lambda: get_by_test_plan_id(self.store, "nope"),
            lambda: get_by_hypothesis_id(self.store, "hyp-xyz"),
            lambda: get_by_match_id(self.store, ""),
            lambda: get_by_snapshot_hash(self.store, "short"),
            lambda: get_by_binding(self.store, test_plan_id=123),
            lambda: get_by_binding(self.store),
        ):
            with self.assertRaises(
                (ArtifactRetrievalError, TypeError), msg=str(call)
            ):
                call()
        with self.assertRaises(TypeError):
            get_by_test_plan_id("tp-" + "0" * 16, "tp-" + "0" * 16)

    def test_filesystem_order_cannot_change_output(self):
        self._store_three()
        before = get_by_binding(
            self.store, artifact_type="nuclei_template"
        )
        sweep_one = verify_all(self.store)
        # Touch directory mtime only (read-only content otherwise).
        (self.store.records_dir / ".probe").write_text("x")
        try:
            after = get_by_binding(
                self.store, artifact_type="nuclei_template"
            )
            self.assertEqual(before, after)
        finally:
            (self.store.records_dir / ".probe").unlink()
        sweep_two = verify_all(self.store)
        self.assertEqual(sweep_one, sweep_two)


# ------------------------------------------------------------------
# K-L, AH-AO: corruption surfacing in retrieval
# ------------------------------------------------------------------


class RetrievalCorruptionTests(RetrievalTestCase):
    def test_corrupted_record_surfaced(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        record = self.store.records_dir / f"{ref.content_hash}.json"
        record.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ArtifactStoreError):
            get_by_test_plan_id(self.store, plan.test_plan_id)

    def test_corrupted_index_surfaced(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        self.store.index_path.write_text("{broken", encoding="utf-8")
        with self.assertRaises(ArtifactStoreError):
            get_by_test_plan_id(self.store, plan.test_plan_id)

    def test_index_record_disagreement_surfaced(self):
        plan_a = _bound_plan(sub="a.acme.com")
        plan_b = _bound_plan(sub="b.acme.com")
        ref_a, content_a = _valid_nuclei(plan_a)
        stored_b = self._put_nuclei(plan_b, "marker-disagree-3333")
        ref_b = stored_b.reference
        self.store.put(ref_a, content_a)
        index = self._index()
        index["artifacts"][ref_a.artifact_id]["content_hash"] = (
            ref_b.content_hash
        )
        index["artifacts"][ref_a.artifact_id]["path"] = (
            f"records/{ref_b.content_hash}.json"
        )
        self._write_index(index)
        with self.assertRaises(ArtifactStoreError):
            get_by_test_plan_id(self.store, plan_a.test_plan_id)

    def test_missing_record_surfaced(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        (self.store.records_dir / f"{ref.content_hash}.json").unlink()
        with self.assertRaises(ArtifactStoreError):
            get_by_test_plan_id(self.store, plan.test_plan_id)

    def test_unknown_type_entry_surfaced(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        index = self._index()
        index["artifacts"][ref.artifact_id]["artifact_type"] = (
            "shell_script"
        )
        self._write_index(index)
        with self.assertRaises(ArtifactStoreError):
            get_by_test_plan_id(self.store, plan.test_plan_id)

    def test_retrieval_returns_exact_stored_bytes(self):
        plan = _bound_plan()
        for ref, content in (
            _valid_nuclei(plan),
            _valid_xss(plan),
            _valid_http(plan),
        ):
            self.store.put(ref, content)
        for ref, content in (
            _valid_nuclei(plan),
            _valid_xss(plan),
            _valid_http(plan),
        ):
            found = get_by_binding(
                self.store, test_plan_id=plan.test_plan_id,
                artifact_type=ref.artifact_type,
            )
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].content, content)
            self.assertIsInstance(found[0].content, bytes)
            self.assertEqual(found[0].reference, ref)


# ------------------------------------------------------------------
# P-R: provenance audit
# ------------------------------------------------------------------


class ProvenanceAuditTests(RetrievalTestCase):
    def test_audit_pass(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        stored = self.store.put(ref, content).stored
        audit = audit_provenance(stored)
        self.assertEqual(audit.outcome, "PASS")
        self.assertEqual(audit.artifact_id, ref.artifact_id)
        self.assertTrue(audit.checks)
        self.assertTrue(
            all(check.outcome == "PASS" for check in audit.checks)
        )

    def test_audit_fail(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        stored = self.store.put(ref, content).stored
        tampered = StoredArtifact(
            reference=stored.reference, content=b"tampered-bytes"
        )
        audit = audit_provenance(tampered)
        self.assertEqual(audit.outcome, "FAIL")
        by_name = {check.name: check for check in audit.checks}
        self.assertEqual(by_name["content_hash"].outcome, "FAIL")

        forged_ref = _forge(ref, artifact_id="art-" + "f" * 16)
        forged = StoredArtifact(reference=forged_ref, content=content)
        forged_audit = audit_provenance(forged)
        self.assertEqual(forged_audit.outcome, "FAIL")

    def test_audit_never_emits_verdicts(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        stored = self.store.put(ref, content).stored
        for audit in (
            audit_provenance(stored),
            audit_provenance(
                StoredArtifact(
                    reference=stored.reference, content=b"other"
                )
            ),
        ):
            self.assertIn(audit.outcome, ("PASS", "FAIL", "INCONCLUSIVE"))
            text = (
                audit.outcome
                + " ".join(
                    check.name + check.outcome + check.detail
                    for check in audit.checks
                )
            ).upper()
            for banned in (
                "CONFIRMED", "VULNERABLE", "NOT_VULNERABLE", "SAFE",
                "EXPLOITED", "SEVERITY", "SCOPE_ALLOWED",
                "EXECUTION_ALLOWED",
            ):
                self.assertNotIn(banned, text)
        with self.assertRaises(TypeError):
            audit_provenance({"artifact_id": "art-" + "0" * 16})


# ------------------------------------------------------------------
# S-V, M, AH-AO, AP-AR: integrity sweep
# ------------------------------------------------------------------


class IntegritySweepTests(RetrievalTestCase):
    def _snapshot_files(self):
        snapshot = {}
        for item in self.store.root_dir.rglob("*"):
            if item.is_file():
                snapshot[str(item)] = (
                    item.stat().st_mtime_ns,
                    hashlib.sha256(item.read_bytes()).hexdigest(),
                )
        return snapshot

    def test_clean_sweep(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        report = verify_all(self.store)
        self.assertEqual(report.total_records, 1)
        self.assertEqual(report.valid_records, 1)
        self.assertEqual(report.corrupt_records, 0)
        self.assertEqual(report.orphan_records, 0)
        self.assertEqual(report.failures, ())

    def test_sweep_detects_all_corrupted_records(self):
        plan = _bound_plan()
        refs = []
        for marker in ("marker-one-1111", "marker-two-2222",
                       "marker-three-3333"):
            content = _template_bytes(marker)
            from ai.researcher.artifact_validator import (
                build_validated_reference,
            )

            validated = build_validated_reference(
                plan, content, "nuclei_template",
                fixtures=[_benign(), _vulnerable(marker)],
            )
            assert validated.state == "VALID"
            self.store.put(validated.reference, content)
            refs.append(validated.reference)
        # Corruption 1: malformed JSON record.
        (self.store.records_dir / f"{refs[0].content_hash}.json"
         ).write_text("{bad json", encoding="utf-8")
        # Corruption 2: content-hash mismatch (valid base64, wrong bytes).
        import base64 as _b64

        envelope = json.loads(
            (self.store.records_dir / f"{refs[1].content_hash}.json"
             ).read_text(encoding="utf-8")
        )
        envelope["content_b64"] = _b64.b64encode(b"wrong-bytes").decode()
        (self.store.records_dir / f"{refs[1].content_hash}.json"
         ).write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        # Corruption 3: missing record file.
        (self.store.records_dir / f"{refs[2].content_hash}.json").unlink()
        report = verify_all(self.store)
        self.assertEqual(report.valid_records, 0)
        self.assertGreaterEqual(report.corrupt_records, 3)
        subjects = [item.subject for item in report.failures]
        for ref in refs:
            self.assertIn(ref.artifact_id, subjects)

    def test_sweep_never_mutates_or_deletes(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        before = self._snapshot_files()
        verify_all(self.store)
        verify_all(self.store)
        after = self._snapshot_files()
        self.assertEqual(before, after)
        self.assertTrue(
            (self.store.records_dir / f"{ref.content_hash}.json").exists()
        )
        self.assertTrue(self.store.index_path.exists())

    def test_repeated_sweep_identical(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        self.assertEqual(verify_all(self.store), verify_all(self.store))

    def test_orphan_record_detected(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        index = self._index()
        del index["artifacts"][ref.artifact_id]
        self._write_index(index)
        report = verify_all(self.store)
        self.assertEqual(report.orphan_records, 1)
        kinds = [item.kind for item in report.failures]
        self.assertIn("orphan_record", kinds)
        # Not reattached, not deleted.
        self.assertIsNone(self.store.get(ref.artifact_id))
        self.assertTrue(
            (self.store.records_dir / f"{ref.content_hash}.json").exists()
        )

    def test_missing_record_surfaces(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        (self.store.records_dir / f"{ref.content_hash}.json").unlink()
        report = verify_all(self.store)
        self.assertEqual(report.corrupt_records, 1)
        self.assertIn(ref.artifact_id,
                      [item.subject for item in report.failures])

    def test_malformed_record_surfaces(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        (self.store.records_dir / f"{ref.content_hash}.json"
         ).write_text("not json at all", encoding="utf-8")
        report = verify_all(self.store)
        self.assertEqual(report.corrupt_records, 1)

    def test_unknown_artifact_type_surfaces(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        index = self._index()
        index["artifacts"][ref.artifact_id]["artifact_type"] = (
            "exec_blob"
        )
        self._write_index(index)
        report = verify_all(self.store)
        self.assertGreaterEqual(report.corrupt_records, 1)
        self.assertIn(ref.artifact_id,
                      [item.subject for item in report.failures])

    def test_schema_version_mismatch_surfaces(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        record = self.store.records_dir / f"{ref.content_hash}.json"
        envelope = json.loads(record.read_text(encoding="utf-8"))
        envelope["schema_version"] = "artifact_store/v9"
        record.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report = verify_all(self.store)
        self.assertEqual(report.corrupt_records, 1)

    def test_content_hash_mismatch_surfaces(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        import base64 as _b64

        record = self.store.records_dir / f"{ref.content_hash}.json"
        envelope = json.loads(record.read_text(encoding="utf-8"))
        envelope["content_b64"] = _b64.b64encode(b"aaa").decode()
        record.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report = verify_all(self.store)
        self.assertEqual(report.corrupt_records, 1)

    def test_artifact_id_mismatch_surfaces(self):
        plan = _bound_plan()
        ref, content = _valid_nuclei(plan)
        self.store.put(ref, content)
        record = self.store.records_dir / f"{ref.content_hash}.json"
        envelope = json.loads(record.read_text(encoding="utf-8"))
        envelope["reference"]["artifact_id"] = "art-" + "a" * 16
        record.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report = verify_all(self.store)
        self.assertEqual(report.corrupt_records, 1)

    def test_binding_mismatch_surfaces(self):
        plan_a = _bound_plan(sub="a.acme.com")
        plan_b = _bound_plan(sub="b.acme.com")
        ref, content = _valid_nuclei(plan_a)
        self.store.put(ref, content)
        from ai.schemas.artifact import artifact_id_for

        record = self.store.records_dir / f"{ref.content_hash}.json"
        envelope = json.loads(record.read_text(encoding="utf-8"))
        envelope["reference"]["test_plan_id"] = plan_b.test_plan_id
        envelope["reference"]["hypothesis_id"] = plan_b.hypothesis_id
        envelope["reference"]["match_id"] = plan_b.match_id
        envelope["reference"]["snapshot_hash"] = plan_b.snapshot_hash
        envelope["reference"]["artifact_id"] = artifact_id_for(
            artifact_type=envelope["reference"]["artifact_type"],
            test_plan_id=plan_b.test_plan_id,
            content_hash=envelope["reference"]["content_hash"],
            schema_version=envelope["reference"][
                "artifact_schema_version"
            ],
        )
        record.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report = verify_all(self.store)
        self.assertEqual(report.corrupt_records, 1)
        self.assertIn(ref.artifact_id,
                      [item.subject for item in report.failures])

    def test_snapshot_bound_artifacts_distinguishable(self):
        plan_old = _bound_plan(tech=("FooCMS:4.1.0",))
        plan_new = _bound_plan(tech=("FooCMS:4.2.0",))
        old = self._put_nuclei(plan_old, "marker-old-1111")
        new = self._put_nuclei(plan_new, "marker-new-2222")
        assert plan_old.snapshot_hash is not None
        assert plan_new.snapshot_hash is not None
        found_old = get_by_snapshot_hash(
            self.store, plan_old.snapshot_hash
        )
        found_new = get_by_snapshot_hash(
            self.store, plan_new.snapshot_hash
        )
        self.assertEqual(
            [item.reference.artifact_id for item in found_old],
            [old.reference.artifact_id],
        )
        self.assertEqual(
            [item.reference.artifact_id for item in found_new],
            [new.reference.artifact_id],
        )

    def test_multiple_artifacts_for_one_plan(self):
        plan = _bound_plan()
        ref_n, content_n = _valid_nuclei(plan)
        ref_x, content_x = _valid_xss(plan)
        ref_h, content_h = _valid_http(plan)
        self.store.put(ref_n, content_n)
        self.store.put(ref_x, content_x)
        self.store.put(ref_h, content_h)
        found = get_by_test_plan_id(self.store, plan.test_plan_id)
        self.assertEqual(len(found), 3)
        self.assertEqual(
            {item.reference.artifact_type for item in found},
            {"nuclei_template", "xss_payload", "http_request_spec"},
        )

    def test_same_content_bindings_follow_store_identity(self):
        plan_a = _bound_plan(sub="a.acme.com")
        plan_b = _bound_plan(sub="b.acme.com")
        ref_a, content = _valid_nuclei(plan_a)
        self.store.put(ref_a, content)
        # The store forbids re-binding identical bytes to another
        # plan; retrieval therefore surfaces exactly the one
        # stored identity.
        from ai.researcher.artifact_validator import (
            build_validated_reference,
        )

        validated_b = build_validated_reference(
            plan_b, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertEqual(validated_b.state, "VALID")
        with self.assertRaises(ArtifactIdentityConflictError):
            self.store.put(validated_b.reference, content)
        found_a = get_by_test_plan_id(self.store, plan_a.test_plan_id)
        found_b = get_by_test_plan_id(self.store, plan_b.test_plan_id)
        self.assertEqual(len(found_a), 1)
        self.assertEqual(found_b, ())
        self.assertEqual(found_a[0].content, content)


# ------------------------------------------------------------------
# X-AF: inertness, boundaries, no mutation API
# ------------------------------------------------------------------


class RetrievalBoundaryTests(unittest.TestCase):
    def test_retrieval_never_executes_content(self):
        text = Path(RETRIEVAL_PATH).read_text(encoding="utf-8")
        tree = ast.parse(text)
        called = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    called.add(func.attr)
                elif isinstance(func, ast.Name):
                    called.add(func.id)
        for banned in ("Popen", "check_output", "check_call",
                       "execve", "spawnl", "fork", "urlopen",
                       "system", "popen", "eval", "exec"):
            self.assertNotIn(banned, called, banned)
        self.assertNotIn("open(", text)

    def test_no_network_imports(self):
        names = _imports_of(RETRIEVAL_PATH)
        roots = {name.split(".")[0] for name in names}
        self.assertTrue(
            {"requests", "httpx", "urllib", "socket", "dns",
             "aiohttp", "urllib3"}.isdisjoint(roots),
            roots,
        )

    def test_no_subprocess_imports(self):
        names = _imports_of(RETRIEVAL_PATH)
        roots = {name.split(".")[0] for name in names}
        self.assertTrue(
            {"subprocess", "multiprocessing", "pty", "shlex"}.isdisjoint(
                roots
            ),
            roots,
        )

    def test_no_llm_imports(self):
        names = _imports_of(RETRIEVAL_PATH)
        joined = " ".join(names).casefold()
        for marker in ("llm", "openrouter", "avalai", "embedding",
                       "prompt"):
            self.assertNotIn(marker, joined)

    def test_no_database_imports(self):
        names = _imports_of(RETRIEVAL_PATH)
        joined = " ".join(names)
        for marker in ("mongoengine", "pymongo", "database"):
            self.assertNotIn(marker, joined)

    def test_no_verifier_executor_imports(self):
        names = _imports_of(RETRIEVAL_PATH)
        joined = " ".join(names)
        for marker in ("verifier", "oracle", "executor", "browser",
                       "playwright", "selenium", "nuclei_runner",
                       "nuclei_pipeline", "scheduler", "queue",
                       "Finding", "scope_policy"):
            self.assertNotIn(marker, joined)

    def test_no_scope_authority(self):
        text = Path(RETRIEVAL_PATH).read_text(encoding="utf-8")
        self.assertNotIn("scope_policy", text)
        tree = ast.parse(text)
        identifiers = {
            node.id for node in ast.walk(tree)
            if isinstance(node, ast.Name)
        }
        for banned in ("scope_allowed", "execution_allowed",
                       "authorize", "ooscope"):
            self.assertNotIn(banned, identifiers, banned)

    def test_no_finding_creation(self):
        text = Path(RETRIEVAL_PATH).read_text(encoding="utf-8")
        self.assertNotIn("Finding", text)
        tree = ast.parse(text)
        called = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(
            {"create_finding", "save_finding", "emit_finding"} & called
        )

    def test_no_mutation_api(self):
        import ai.researcher.artifact_retrieval as retrieval

        for banned in ("put", "delete", "remove", "update", "write",
                       "save", "store_artifact", "repair", "reattach",
                       "prune"):
            self.assertFalse(hasattr(retrieval, banned), banned)
        text = Path(RETRIEVAL_PATH).read_text(encoding="utf-8")
        for marker in ("mkdir", "unlink", "os.replace", "os.rename",
                       "write_text", ".put("):
            self.assertNotIn(marker, text, marker)


def _imports_of(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


if __name__ == "__main__":
    unittest.main()
