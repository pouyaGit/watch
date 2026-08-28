import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai.knowledge.store import (
    KnowledgeIdCollisionError,
    KnowledgeStore,
    KnowledgeStoreIntegrityError,
    content_hash,
    source_id,
)
from ai.schemas.knowledge import KnowledgeDocument
from ai.schemas.knowledge import KnowledgeProvenance


FIXTURE_DIR = (
    Path(__file__).parent
    / "tests"
    / "fixtures"
    / "knowledge"
)


def load_fixture(name: str) -> KnowledgeDocument:
    return KnowledgeDocument.model_validate(
        json.loads(
            (FIXTURE_DIR / name).read_text(
                encoding="utf-8"
            )
        )
    )


class KnowledgeStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = KnowledgeStore(
            Path(self.temp_dir.name) / "knowledge"
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_content_hash_and_id_are_stable(self):
        document = load_fixture("reflected_writeup.json")
        expected_hash = content_hash(document.content)

        stored, created = self.store.ingest(document)

        self.assertTrue(created)
        self.assertEqual(stored.content_hash, expected_hash)
        self.assertEqual(
            stored.knowledge_id,
            f"kb-{expected_hash[:16]}",
        )

    def test_duplicate_content_merges_distinct_provenance(self):
        first = load_fixture("reflected_writeup.json")
        mirror = load_fixture("reflected_writeup_mirror.json")

        stored_first, first_created = self.store.ingest(first)
        stored_mirror, mirror_created = self.store.ingest(mirror)
        stored_again, again_created = self.store.ingest(first)

        self.assertTrue(first_created)
        self.assertFalse(mirror_created)
        self.assertFalse(again_created)
        self.assertEqual(
            stored_first.knowledge_id,
            stored_mirror.knowledge_id,
        )
        self.assertEqual(len(stored_again.provenance), 2)
        self.assertEqual(
            [item.source_url for item in stored_again.provenance],
            [
                item.source_url
                for item in sorted(
                    [first, mirror],
                    key=lambda item: source_id(
                        item.source_type,
                        item.source_url,
                    ),
                )
            ],
        )

        document_files = list(
            (self.store.documents_dir).glob("*.json")
        )
        self.assertEqual(len(document_files), 1)

    def test_retrieval_normalizes_metadata_and_is_deterministic(self):
        reflected = load_fixture("reflected_writeup.json")
        second = reflected.model_copy(
            update={
                "content": "A second local fixture document.",
                "knowledge_id": "placeholder-two",
                "source_url": "https://research.example.test/second",
                "title": "Second fixture",
                "tags": ["fixture", "second"],
            }
        )

        first_stored, _ = self.store.ingest(reflected)
        second_stored, _ = self.store.ingest(second)

        matches = self.store.retrieve(
            technologies=["example-framework"],
            xss_types=["REFLECTED"],
            contexts=["HTML_attribute"],
            source_types=["WRITEUP"],
            evidence_quality=["high confidence"],
            tags=["reflected xss"],
        )

        self.assertEqual(
            [item.knowledge_id for item in matches],
            [first_stored.knowledge_id],
        )

        all_documents = self.store.retrieve(tags=["fixture"])
        self.assertEqual(
            [item.knowledge_id for item in all_documents],
            sorted(
                [
                    first_stored.knowledge_id,
                    second_stored.knowledge_id,
                ]
            ),
        )

    def test_persistence_reloads_by_id_and_hash(self):
        document = load_fixture("reflected_writeup.json")
        stored, _ = self.store.ingest(document)

        reloaded_store = KnowledgeStore(self.store.root_dir)

        self.assertEqual(
            reloaded_store.get_by_hash(stored.content_hash),
            stored,
        )
        self.assertEqual(
            reloaded_store.get_by_id(stored.knowledge_id),
            stored,
        )

    def test_short_id_collision_is_rejected(self):
        first = load_fixture("reflected_writeup.json")
        second = first.model_copy(
            update={
                "content": "A different fixture for collision testing.",
                "knowledge_id": "placeholder-two",
                "source_url": "https://research.example.test/collision",
            }
        )

        hashes = {
            first.content: "a" * 16 + "1" * 48,
            second.content: "a" * 16 + "2" * 48,
        }

        with patch(
            "ai.knowledge.store.content_hash",
            side_effect=lambda content: hashes[content],
        ):
            self.store.ingest(first)

            with self.assertRaises(KnowledgeIdCollisionError):
                self.store.ingest(second)

    def test_rejects_modified_content_with_stale_hash(self):
        document = load_fixture("reflected_writeup.json")
        stored, _ = self.store.ingest(document)
        path = self.store._document_path(stored.content_hash)
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["content"] = "Modified after persistence."
        path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaises(KnowledgeStoreIntegrityError):
            self.store.get_by_hash(stored.content_hash)

    def test_rejects_filename_hash_mismatch(self):
        document = load_fixture("reflected_writeup.json")
        stored, _ = self.store.ingest(document)
        original_path = self.store._document_path(stored.content_hash)
        mismatched_hash = "f" * 64
        mismatched_path = self.store._document_path(mismatched_hash)
        original_path.replace(mismatched_path)

        with self.assertRaises(KnowledgeStoreIntegrityError):
            self.store._load_document(mismatched_hash)

    def test_rejects_knowledge_id_hash_mismatch(self):
        document = load_fixture("reflected_writeup.json")
        stored, _ = self.store.ingest(document)
        path = self.store._document_path(stored.content_hash)
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["knowledge_id"] = "kb-0000000000000000"
        path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaises(KnowledgeStoreIntegrityError):
            self.store.get_by_hash(stored.content_hash)

    def test_rejects_index_document_mismatch(self):
        document = load_fixture("reflected_writeup.json")
        stored, _ = self.store.ingest(document)
        index = json.loads(
            self.store.index_path.read_text(encoding="utf-8")
        )
        index["documents"][stored.content_hash][
            "knowledge_id"
        ] = "kb-0000000000000000"
        self.store.index_path.write_text(
            json.dumps(index),
            encoding="utf-8",
        )

        with self.assertRaises(KnowledgeStoreIntegrityError):
            self.store.get_by_hash(stored.content_hash)

        with self.assertRaises(KnowledgeStoreIntegrityError):
            self.store.get_by_id("kb-0000000000000000")

        with self.assertRaises(KnowledgeStoreIntegrityError):
            self.store.retrieve()

    def test_source_aware_claims_preserve_attribution(self):
        first = load_fixture("reflected_writeup.json").model_copy(
            update={"indexed_at": "2026-08-01T00:00:00+00:00"}
        )
        mirror = load_fixture("reflected_writeup_mirror.json").model_copy(
            update={"indexed_at": "2026-08-02T00:00:00+00:00"}
        )

        stored, _ = self.store.ingest(first)
        stored, created = self.store.ingest(mirror)

        self.assertFalse(created)
        self.assertEqual(len(stored.provenance), 2)
        self.assertEqual(
            [item.value for item in stored.aggregate.xss_types],
            ["dom", "reflected"],
        )

        dom = next(
            item for item in stored.aggregate.xss_types
            if item.value == "dom"
        )
        reflected = next(
            item for item in stored.aggregate.xss_types
            if item.value == "reflected"
        )
        mirror_source_id = source_id(
            mirror.source_type,
            mirror.source_url,
        )
        first_source_id = source_id(
            first.source_type,
            first.source_url,
        )
        self.assertEqual(dom.source_ids, [mirror_source_id])
        self.assertEqual(reflected.source_ids, [first_source_id])

        self.assertEqual(
            [item.value for item in stored.aggregate.payload_patterns],
            ["marker-only"],
        )
        self.assertEqual(
            [item.source_ids for item in stored.aggregate.payload_patterns],
            [[first_source_id]],
        )
        self.assertEqual(
            [item.value for item in stored.aggregate.verification_patterns],
            ["browser execution"],
        )
        self.assertEqual(
            [item.evidence_quality for item in stored.aggregate.source_confidence],
            [
                item.evidence_quality
                for item in sorted(
                    [first, mirror],
                    key=lambda item: source_id(
                        item.source_type,
                        item.source_url,
                    ),
                )
            ],
        )
        self.assertFalse(hasattr(stored.aggregate, "confidence"))
        self.assertFalse(hasattr(stored.aggregate, "evidence_quality"))

    def test_reverse_source_ingestion_order_is_equivalent(self):
        first = load_fixture("reflected_writeup.json").model_copy(
            update={"indexed_at": "2026-08-01T00:00:00+00:00"}
        )
        mirror = load_fixture("reflected_writeup_mirror.json").model_copy(
            update={"indexed_at": "2026-08-02T00:00:00+00:00"}
        )

        left, _ = self.store.ingest(first)
        left, _ = self.store.ingest(mirror)

        with tempfile.TemporaryDirectory() as other_dir:
            other_store = KnowledgeStore(Path(other_dir) / "knowledge")
            right, _ = other_store.ingest(mirror)
            right, _ = other_store.ingest(first)

        self.assertEqual(
            left.model_dump(mode="json"),
            right.model_dump(mode="json"),
        )

    def test_same_source_claims_are_idempotent_and_changes_are_preserved(self):
        first = load_fixture("reflected_writeup.json").model_copy(
            update={"indexed_at": "2026-08-01T00:00:00+00:00"}
        )
        stored, _ = self.store.ingest(first)
        same, created = self.store.ingest(first)

        self.assertFalse(created)
        self.assertEqual(same.provenance, stored.provenance)

        changed = first.model_copy(
            update={
                "xss_types": ["dom"],
                "contexts": ["javascript string"],
                "evidence_quality": "SECONDARY",
                "confidence": 0.4,
            }
        )
        changed_stored, _ = self.store.ingest(changed)
        source = changed_stored.provenance[0]

        self.assertEqual(len(source.claims), 2)
        self.assertEqual(
            [item.value for item in changed_stored.aggregate.xss_types],
            ["dom", "reflected"],
        )
        self.assertEqual(
            len(changed_stored.aggregate.source_confidence),
            2,
        )

    def test_retrieval_uses_aggregate_with_source_attribution(self):
        first = load_fixture("reflected_writeup.json")
        mirror = load_fixture("reflected_writeup_mirror.json")
        self.store.ingest(first)
        stored, _ = self.store.ingest(mirror)

        dom_matches = self.store.retrieve(xss_types=["dom"])
        reflected_matches = self.store.retrieve(xss_types=["reflected"])

        self.assertEqual(dom_matches, [stored])
        self.assertEqual(reflected_matches, [stored])
        dom = next(
            item for item in dom_matches[0].aggregate.xss_types
            if item.value == "dom"
        )
        self.assertEqual(
            dom.source_ids,
            [source_id(mirror.source_type, mirror.source_url)],
        )

    def test_legacy_document_is_migrated_without_inventing_secondary_claims(self):
        legacy = load_fixture("reflected_writeup.json")
        legacy = legacy.model_copy(
            update={
                "provenance": [
                    KnowledgeProvenance(
                        source_url="https://mirror.example.test/legacy",
                        source_type="research",
                        title="Legacy mirror",
                    )
                ]
            }
        )

        stored, _ = self.store.ingest(legacy)
        primary = next(
            item for item in stored.provenance
            if item.source_id == source_id(legacy.source_type, legacy.source_url)
        )
        secondary = next(
            item for item in stored.provenance
            if item.source_id != primary.source_id
        )

        self.assertEqual(stored.schema_version, 2)
        self.assertEqual(len(primary.claims), 1)
        self.assertEqual(secondary.claims, [])
        self.assertNotIn(
            source_id(secondary.source_type, secondary.source_url),
            next(
                item for item in stored.aggregate.xss_types
                if item.value == "reflected"
            ).source_ids,
        )

    def test_canonical_hash_and_id_ignore_provenance_changes(self):
        first = load_fixture("reflected_writeup.json")
        changed_source = first.model_copy(
            update={
                "source_url": "https://mirror.example.test/same-content",
                "source_type": "research",
                "xss_types": ["dom"],
            }
        )

        stored, _ = self.store.ingest(first)
        updated, _ = self.store.ingest(changed_source)

        self.assertEqual(stored.content_hash, updated.content_hash)
        self.assertEqual(stored.knowledge_id, updated.knowledge_id)


if __name__ == "__main__":
    unittest.main()
