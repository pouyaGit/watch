"""Focused tests for the Phase 4D immutable Artifact Store.

Proves the storage boundary::

    VALID ArtifactReference + exact artifact bytes
                        |
                        v
    immutable, content-addressed, integrity-checked record

Storage only: no generation, no execution, no verification, no
findings, no verdicts, no LLM, no network, no subprocess, no
database. Covers the required adversarial matrix A-AZ plus a
pure filesystem-temp integration chain.
"""

import ast
import base64
import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path

from ai.knowledge.artifact_store import (
    ArtifactCorruptError,
    ArtifactIdentityConflictError,
    ArtifactStore,
    ArtifactStoreError,
    StoredArtifact,
)
from ai.researcher.artifact_validator import build_validated_reference
from ai.researcher.hypothesis_engine import build_hypothesis_from_match
from ai.researcher.nuclei_artifact_validator import NucleiFixture
from ai.researcher.pattern_projector import GroundedClaim, project_claim
from ai.researcher.target_intelligence import (
    EndpointRecord,
    HttpRecord,
    ParamRecord,
    ProgramRecord,
    SubdomainRecord,
    project_subdomain,
)
from ai.researcher.target_matcher import match_pattern_to_target
from ai.researcher.test_plan_builder import build_test_plan_from_hypothesis
from ai.schemas.artifact import (
    ArtifactReference,
    artifact_id_for,
    build_artifact_reference,
    content_hash_for_bytes,
)
from ai.schemas.knowledge import KnowledgeSourceClaims

MARKER = "cve-2024-0001-unique-detection-marker-9f3a7c"

STORE_PATH = "ai/knowledge/artifact_store.py"


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


def _hex(tag):
    return hashlib.sha256(tag.encode("utf-8")).hexdigest()


def _template_dict(marker=MARKER, **overrides):
    payload = {
        "template_id": "CVE-2024-0001",
        "method": "GET",
        "path": "/search",
        "headers": {},
        "query_params": {"q": "probe"},
        "body": None,
        "matchers": [
            {
                "matcher_type": "word",
                "values": [marker],
                "part": "body",
            }
        ],
    }
    payload.update(overrides)
    return payload


def _template_bytes(marker=MARKER, **overrides):
    return json.dumps(
        _template_dict(marker, **overrides),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _benign(body="Welcome to our homepage. All systems operational."):
    return NucleiFixture(
        fixture_kind="benign", status=200, headers={}, body=body
    )


def _vulnerable(marker=MARKER):
    return NucleiFixture(
        fixture_kind="vulnerable",
        status=200,
        headers={},
        body=f"results for {marker} version 1.2.3",
    )


def _target(program="acme", sub="app.acme.com", tech=("FooCMS:4.1.0",)):
    prog = ProgramRecord(
        program_name=program,
        scopes=[program + ".com"],
        ooscopes=[],
        record_id="prog-" + program,
    )
    subrec = SubdomainRecord(
        program_name=program,
        subdomain=sub,
        scope=program + ".com",
        record_id="sub-" + sub,
    )
    https = []
    if tech is not None:
        https.append(
            HttpRecord(
                program_name=program,
                subdomain=sub,
                tech=list(tech),
                record_id="http-" + sub,
            )
        )
    endpoints = [
        EndpointRecord(
            program_name=program,
            subdomain=sub,
            path="/search",
            example_url=f"https://{sub}/search",
            params=["q"],
            param_records=(
                ParamRecord(
                    name="q", method="GET", location="query",
                    source="crawl",
                ),
            ),
            record_id="ep-1",
        )
    ]
    return project_subdomain(
        prog, subrec, https=https, endpoints=endpoints
    ).intelligence


def _bound_plan(program="acme", sub="app.acme.com",
                tech=("FooCMS:4.1.0",)):
    from ai.schemas.hypothesis import ResearchProvenance
    from ai.schemas.research_pattern import build_vulnerability_pattern

    target = _target(program=program, sub=sub, tech=tech)
    tag = f"{program}/{sub}/{tech}"
    pattern = build_vulnerability_pattern(
        pattern_kind="PRODUCT_VULNERABILITY",
        title="Research pattern",
        description="Deterministic test pattern.",
        facts={
            "products": [{"product": "FooCMS"}],
            "attack_surface": [
                {
                    "surface_kind": "http_endpoint",
                    "path": "/search",
                    "method": "GET",
                    "parameter": "q",
                    "parameter_location": "query",
                }
            ],
            "observables": [
                {
                    "observation_kind": "response_contains",
                    "description": "marker reflected in response body",
                }
            ],
        },
        provenance=ResearchProvenance(
            claim_ids=["clm-" + _hex(tag)[:16]]
        ),
    )
    match = match_pattern_to_target(pattern, target)
    built = build_hypothesis_from_match(match, pattern, target)
    assert built.outcome == "CREATED", built.reason
    result = build_test_plan_from_hypothesis(
        built.hypothesis, match=match, pattern=pattern,
        target_intelligence=target,
    )
    assert result.outcome == "CREATED", result.reason
    return result.plan


def _valid_nuclei(plan, marker=MARKER):
    content = _template_bytes(marker)
    validated = build_validated_reference(
        plan, content, "nuclei_template",
        fixtures=[_benign(), _vulnerable(marker)],
    )
    assert validated.state == "VALID", validated.reasons
    return validated.reference, content


def _valid_xss(plan, payload=b"marker-probe-123"):
    validated = build_validated_reference(plan, payload, "xss_payload")
    assert validated.state == "VALID", validated.reasons
    return validated.reference, payload


def _valid_http(plan):
    content = json.dumps(
        {
            "method": "GET",
            "path": "/search",
            "query_params": {"q": "probe"},
            "headers": {},
            "body": None,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    validated = build_validated_reference(
        plan, content, "http_request_spec"
    )
    assert validated.state == "VALID", validated.reasons
    return validated.reference, content


def _forge(reference, **overrides):
    """Craft a schema-bypassing reference (corruption tests only)."""

    payload = reference.model_dump(mode="json")
    payload.update(overrides)
    return ArtifactReference.model_construct(**payload)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="artstore-")
        self.store = ArtifactStore(Path(self._tmp.name) / "store")

    def tearDown(self):
        self._tmp.cleanup()

    def _record_path(self, content_hash):
        return self.store.records_dir / f"{content_hash}.json"

    def _read_record(self, content_hash):
        return json.loads(
            self._record_path(content_hash).read_text(encoding="utf-8")
        )

    def _write_record(self, content_hash, envelope):
        self._record_path(content_hash).write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


# ------------------------------------------------------------------
# A-C: validation-state gate
# ------------------------------------------------------------------


class ValidationGateTests(StoreTestCase):
    def test_valid_artifact_accepted(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        result = self.store.put(reference, content)
        self.assertTrue(result.created)
        fetched = self.store.get(reference.artifact_id)
        self.assertIsNotNone(fetched)
        assert fetched is not None
        self.assertEqual(fetched.content, content)
        self.assertEqual(fetched.reference, reference)
        self.assertTrue(self.store.exists(reference.artifact_id))

    def test_unvalidated_artifact_rejected(self):
        plan = _bound_plan()
        reference = build_artifact_reference(
            artifact_type="xss_payload",
            content=b"plain-payload",
            test_plan_id=plan.test_plan_id,
            hypothesis_id=plan.hypothesis_id,
            match_id=plan.match_id,
            snapshot_hash=plan.snapshot_hash,
        )
        self.assertEqual(reference.validation_state, "UNVALIDATED")
        with self.assertRaises(ArtifactStoreError):
            self.store.put(reference, b"plain-payload")
        self.assertFalse(self.store.exists(reference.artifact_id))

    def test_rejected_artifact_rejected(self):
        plan = _bound_plan()
        bad = _template_bytes(
            matchers=[
                {"matcher_type": "word", "values": ["error"],
                 "part": "body"}
            ]
        )
        validated = build_validated_reference(
            plan, bad, "nuclei_template",
            fixtures=[_benign("a benign error page")],
        )
        self.assertEqual(validated.state, "REJECTED")
        with self.assertRaises(ArtifactStoreError):
            self.store.put(validated.reference, bad)

    def test_typed_put_inputs_only(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        with self.assertRaises(TypeError):
            self.store.put(reference.model_dump(mode="json"), content)
        with self.assertRaises(TypeError):
            self.store.put(reference, content.decode("utf-8"))
        with self.assertRaises(ArtifactStoreError):
            self.store.get("not-an-id")
        self.assertIsNone(
            self.store.get("art-" + "0" * 16)
        )
        self.assertFalse(
            self.store.exists("art-" + "0" * 16)
        )
        self.assertIsNone(
            self.store.get_by_content_hash("0" * 64)
        )
        with self.assertRaises(ArtifactStoreError):
            self.store.list(artifact_type="shell_script")


# ------------------------------------------------------------------
# D-F, Z-AY-AZ: content addressing
# ------------------------------------------------------------------


class ContentAddressingTests(StoreTestCase):
    def test_deterministic_content_addressed_path(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        expected = (
            self.store.records_dir / f"{reference.content_hash}.json"
        )
        self.assertTrue(expected.is_file())
        self.assertEqual(
            reference.content_hash, content_hash_for_bytes(content)
        )
        index = json.loads(
            self.store.index_path.read_text(encoding="utf-8")
        )
        entry = index["artifacts"][reference.artifact_id]
        self.assertEqual(entry["path"], f"records/{reference.content_hash}.json")

    def test_same_content_converges(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        first = self.store.put(reference, content)
        second = self.store.put(reference, content)
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(first.stored, second.stored)
        third = self.store.put(reference, content)
        self.assertFalse(third.created)

    def test_one_byte_content_differs(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        other = bytearray(content)
        other[-3] ^= 0x01
        marker = _template_dict()["matchers"][0]["values"][0]
        # One-byte flip breaks the marker -> rebuild VALID bytes
        # with a distinct marker instead (still VALID, new hash).
        alt_marker = marker[:-1] + ("0" if marker[-1] != "0" else "1")
        alt_content = _template_bytes(alt_marker)
        alt_validated = build_validated_reference(
            plan, alt_content, "nuclei_template",
            fixtures=[_benign(), _vulnerable(alt_marker)],
        )
        self.assertEqual(alt_validated.state, "VALID")
        result = self.store.put(alt_validated.reference, alt_content)
        self.assertTrue(result.created)
        self.assertNotEqual(
            alt_validated.reference.content_hash, reference.content_hash
        )
        self.assertNotEqual(
            alt_validated.reference.artifact_id, reference.artifact_id
        )
        self.assertEqual(len(self.store.list()), 2)

    def test_returned_bytes_exactly_equal(self):
        plan = _bound_plan()
        for reference, content in (
            _valid_nuclei(plan),
            _valid_xss(plan),
            _valid_http(plan),
        ):
            store = ArtifactStore(Path(self._tmp.name) / f"s-{reference.artifact_type}")
            store.put(reference, content)
            fetched = store.get(reference.artifact_id)
            assert fetched is not None
            self.assertEqual(fetched.content, content)
            by_hash = store.get_by_content_hash(reference.content_hash)
            assert by_hash is not None
            self.assertEqual(by_hash.content, content)

    def test_one_byte_corruption_detected(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        envelope = self._read_record(reference.content_hash)
        raw = base64.b64decode(envelope["content_b64"])
        tampered = bytearray(raw)
        tampered[20] ^= 0x01
        envelope["content_b64"] = base64.b64encode(bytes(tampered)).decode()
        self._write_record(reference.content_hash, envelope)
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)


# ------------------------------------------------------------------
# G-N, AA-AB: binding and conflict rejection
# ------------------------------------------------------------------


class BindingConflictTests(StoreTestCase):
    def test_wrong_content_hash_rejected(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        forged = _forge(reference, content_hash="0" * 64)
        with self.assertRaises(ArtifactStoreError):
            self.store.put(forged, content)

    def test_wrong_artifact_id_rejected(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        forged = _forge(reference, artifact_id="art-" + "0" * 16)
        with self.assertRaises(ArtifactStoreError):
            self.store.put(forged, content)

    def test_wrong_test_plan_binding_rejected(self):
        plan_a = _bound_plan(sub="a.acme.com")
        plan_b = _bound_plan(sub="b.acme.com")
        reference, content = _valid_nuclei(plan_a)
        forged = _forge(reference, test_plan_id=plan_b.test_plan_id)
        with self.assertRaises(ArtifactStoreError):
            self.store.put(forged, content)

    def test_wrong_hypothesis_binding_rejected(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        forged = _forge(reference, hypothesis_id="hyp-" + "1" * 16)
        with self.assertRaises(ArtifactIdentityConflictError):
            self.store.put(forged, content)

    def test_wrong_match_binding_rejected(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        forged = _forge(reference, match_id="tm-" + "2" * 16)
        with self.assertRaises(ArtifactIdentityConflictError):
            self.store.put(forged, content)

    def test_wrong_snapshot_binding_rejected(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        forged = _forge(reference, snapshot_hash="3" * 64)
        with self.assertRaises(ArtifactIdentityConflictError):
            self.store.put(forged, content)

    def test_wrong_artifact_type_rejected(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        forged = _forge(reference, artifact_type="xss_payload")
        with self.assertRaises(ArtifactStoreError):
            self.store.put(forged, content)

    def test_unknown_artifact_type_rejected(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        forged = _forge(reference, artifact_type="shell_script")
        with self.assertRaises(ArtifactStoreError):
            self.store.put(forged, content)

    def test_conflicting_duplicate_put_rejected(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        # Same identity, contradictory bindings: never merged.
        forged = _forge(reference, hypothesis_id="hyp-" + "4" * 16)
        with self.assertRaises(ArtifactIdentityConflictError):
            self.store.put(forged, content)
        # Stored record is untouched.
        fetched = self.store.get(reference.artifact_id)
        assert fetched is not None
        self.assertEqual(fetched.reference, reference)
        self.assertEqual(fetched.content, content)

    def test_same_content_different_plan_rejected(self):
        plan_a = _bound_plan(sub="a.acme.com")
        plan_b = _bound_plan(sub="b.acme.com")
        reference_a, content = _valid_nuclei(plan_a)
        self.store.put(reference_a, content)
        validated_b = build_validated_reference(
            plan_b, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertEqual(validated_b.state, "VALID")
        self.assertNotEqual(
            validated_b.reference.artifact_id, reference_a.artifact_id
        )
        with self.assertRaises(ArtifactIdentityConflictError):
            self.store.put(validated_b.reference, content)

    def test_immutable_content(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        self.assertFalse(hasattr(self.store, "update_content"))
        self.assertFalse(hasattr(self.store, "delete"))
        self.assertFalse(hasattr(self.store, "remove"))
        self.assertFalse(hasattr(self.store, "purge"))
        self.assertFalse(hasattr(self.store, "clear"))
        self.assertFalse(hasattr(self.store, "replace"))
        forged = _forge(reference, hypothesis_id="hyp-" + "5" * 16)
        with self.assertRaises(ArtifactStoreError):
            self.store.put(forged, content)


# ------------------------------------------------------------------
# O-U, AU: corruption handling
# ------------------------------------------------------------------


class CorruptionTests(StoreTestCase):
    def _stored_valid(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        return reference, content

    def test_malformed_record_rejected(self):
        reference, _ = self._stored_valid()
        self._record_path(reference.content_hash).write_text(
            "{not valid json", encoding="utf-8"
        )
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)

    def test_missing_content_rejected(self):
        reference, _ = self._stored_valid()
        self._record_path(reference.content_hash).unlink()
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)

    def test_content_hash_corruption_detected(self):
        reference, _ = self._stored_valid()
        envelope = self._read_record(reference.content_hash)
        envelope["content_hash"] = "0" * 64
        self._write_record(reference.content_hash, envelope)
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)

    def test_metadata_corruption_detected(self):
        reference, _ = self._stored_valid()
        envelope = self._read_record(reference.content_hash)
        envelope["reference"]["metadata"] = {"verdict": "confirmed"}
        self._write_record(reference.content_hash, envelope)
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)
        envelope = self._read_record(reference.content_hash)
        del envelope["reference"]["test_plan_id"]
        self._write_record(reference.content_hash, envelope)
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)

    def test_artifact_id_corruption_detected(self):
        reference, _ = self._stored_valid()
        envelope = self._read_record(reference.content_hash)
        envelope["reference"]["artifact_id"] = "art-" + "f" * 16
        self._write_record(reference.content_hash, envelope)
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)

    def test_schema_version_corruption_detected(self):
        reference, _ = self._stored_valid()
        envelope = self._read_record(reference.content_hash)
        envelope["schema_version"] = "artifact_store/v9"
        self._write_record(reference.content_hash, envelope)
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)
        envelope = self._read_record(reference.content_hash)
        envelope["schema_version"] = "artifact_store/v1"
        envelope["reference"]["artifact_schema_version"] = "artifact/v9"
        self._write_record(reference.content_hash, envelope)
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)

    def test_validation_state_corruption_detected(self):
        reference, _ = self._stored_valid()
        envelope = self._read_record(reference.content_hash)
        envelope["reference"]["validation_state"] = "REJECTED"
        self._write_record(reference.content_hash, envelope)
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)

    def test_plan_swap_in_record_detected_via_index(self):
        plan_a = _bound_plan(sub="a.acme.com")
        plan_b = _bound_plan(sub="b.acme.com")
        reference, content = _valid_nuclei(plan_a)
        self.store.put(reference, content)
        envelope = self._read_record(reference.content_hash)
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
        self._write_record(reference.content_hash, envelope)
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)

    def test_corrupted_index_fails_closed(self):
        reference, _ = self._stored_valid()
        self.store.index_path.write_text("{broken", encoding="utf-8")
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(reference.artifact_id)
        with self.assertRaises(ArtifactCorruptError):
            self.store.list()
        self.store.index_path.write_text(
            json.dumps({"artifacts": {"art-" + "0" * 16: {
                "artifact_type": "shell_script",
                "content_hash": "0" * 64,
                "test_plan_id": "tp-" + "0" * 16,
                "path": "records/" + "0" * 64 + ".json",
            }}, "version": 1}),
            encoding="utf-8",
        )
        with self.assertRaises(ArtifactCorruptError):
            self.store.get("art-" + "0" * 16)

    def test_duplicate_records_do_not_silently_merge(self):
        plan_a = _bound_plan(sub="a.acme.com")
        reference, content = _valid_nuclei(plan_a)
        self.store.put(reference, content)
        index = json.loads(
            self.store.index_path.read_text(encoding="utf-8")
        )
        rogue_id = "art-" + "e" * 16
        index["artifacts"][rogue_id] = {
            "artifact_type": reference.artifact_type,
            "content_hash": reference.content_hash,
            "path": f"records/{reference.content_hash}.json",
            "test_plan_id": reference.test_plan_id,
        }
        self.store.index_path.write_text(
            json.dumps(index, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        # The rogue entry fails closed instead of merging.
        with self.assertRaises(ArtifactCorruptError):
            self.store.get(rogue_id)
        # The genuine entry is unaffected.
        fetched = self.store.get(reference.artifact_id)
        assert fetched is not None
        self.assertEqual(fetched.reference, reference)


# ------------------------------------------------------------------
# V-X, AE: paths, temp files, ordering
# ------------------------------------------------------------------


class PathOrderingTests(StoreTestCase):
    def test_path_traversal_rejected(self):
        for bad in ("../evil", "..\\evil", "records/../../x",
                    "art-evil", "", "art-XYZ"):
            with self.assertRaises(ArtifactStoreError, msg=bad):
                self.store.get(bad)

    def test_absolute_path_rejected(self):
        for bad in ("/tmp/x", "/etc/passwd",
                    str(self.store.records_dir / "x")):
            with self.assertRaises(ArtifactStoreError, msg=bad):
                self.store.get(bad)
        with self.assertRaises(ArtifactStoreError):
            self.store.get_by_content_hash("/" + "0" * 64)

    def test_no_temp_files_remain(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        leftovers = [
            item for item in self.store.root_dir.rglob("*")
            if item.suffix == ".tmp" or ".tmp" in item.name
        ]
        self.assertEqual(leftovers, [])

    def test_atomic_record_is_complete(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        envelope = self._read_record(reference.content_hash)
        self.assertEqual(
            set(envelope.keys()),
            {"reference", "content_b64", "content_hash",
             "schema_version"},
        )
        self.assertEqual(
            base64.b64decode(envelope["content_b64"]), content
        )
        self.assertTrue(self.store.index_path.is_file())

    def test_deterministic_list_ordering(self):
        plans = [_bound_plan(sub=f"{letter}.acme.com")
                 for letter in ("c", "a", "b")]
        refs = []
        for plan, marker in zip(
            plans, ("marker-aaa-1111", "marker-bbb-2222",
                    "marker-ccc-3333")):
            content = _template_bytes(marker)
            validated = build_validated_reference(
                plan, content, "nuclei_template",
                fixtures=[_benign(), _vulnerable(marker)],
            )
            assert validated.state == "VALID", validated.reasons
            refs.append((validated.reference, content))
        for reference, content in reversed(refs):
            self.store.put(reference, content)
        first = [item.reference.artifact_id for item in self.store.list()]
        second = [item.reference.artifact_id for item in self.store.list()]
        self.assertEqual(first, sorted(first))
        self.assertEqual(first, second)
        nuclei_only = self.store.list(artifact_type="nuclei_template")
        self.assertEqual(len(nuclei_only), 3)
        xss_only = self.store.list(artifact_type="xss_payload")
        self.assertEqual(xss_only, [])


# ------------------------------------------------------------------
# AF-AI, AW-AX: handles, inertness, provenance
# ------------------------------------------------------------------


class HandleProvenanceTests(StoreTestCase):
    def test_no_executable_handles(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        stored = self.store.put(reference, content).stored
        self.assertIsInstance(stored, StoredArtifact)
        self.assertEqual(set(stored.__dataclass_fields__), {"reference", "content"})
        self.assertIsInstance(stored.content, bytes)
        for attr in ("path", "handle", "file", "executor",
                     "runner", "url", "command"):
            self.assertFalse(hasattr(stored, attr), attr)

    def test_xss_content_remains_inert_bytes(self):
        plan = _bound_plan()
        reference, content = _valid_xss(plan)
        self.store.put(reference, content)
        fetched = self.store.get(reference.artifact_id)
        assert fetched is not None
        self.assertEqual(fetched.content, content)
        self.assertEqual(fetched.reference.artifact_type, "xss_payload")

    def test_nuclei_content_never_executed(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        fetched = self.store.get(reference.artifact_id)
        assert fetched is not None
        self.assertEqual(fetched.content, content)
        text = Path(STORE_PATH).read_text(encoding="utf-8")
        for marker in ("NucleiTemplateGenerator", "nuclei_runner",
                       "nuclei_pipeline", "matchers-condition"):
            self.assertNotIn(marker, text, marker)

    def test_http_artifact_never_requested(self):
        plan = _bound_plan()
        reference, content = _valid_http(plan)
        self.store.put(reference, content)
        fetched = self.store.get(reference.artifact_id)
        assert fetched is not None
        self.assertEqual(fetched.content, content)

    def test_snapshot_bound_artifacts_distinguishable(self):
        plan_old = _bound_plan(tech=("FooCMS:4.1.0",))
        plan_new = _bound_plan(tech=("FooCMS:4.2.0",))
        self.assertNotEqual(
            plan_old.snapshot_hash, plan_new.snapshot_hash
        )
        ref_old, content_old = _valid_nuclei(plan_old, "marker-old-1111")
        ref_new, content_new = _valid_nuclei(plan_new, "marker-new-2222")
        self.assertNotEqual(ref_old.artifact_id, ref_new.artifact_id)
        self.store.put(ref_old, content_old)
        self.store.put(ref_new, content_new)
        fetched_old = self.store.get(ref_old.artifact_id)
        fetched_new = self.store.get(ref_new.artifact_id)
        assert fetched_old is not None and fetched_new is not None
        self.assertEqual(
            fetched_old.reference.snapshot_hash, plan_old.snapshot_hash
        )
        self.assertEqual(
            fetched_new.reference.snapshot_hash, plan_new.snapshot_hash
        )

    def test_provenance_intact_after_read(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        self.store.put(reference, content)
        fetched = self.store.get(reference.artifact_id)
        assert fetched is not None
        self.assertEqual(
            fetched.reference.test_plan_id, plan.test_plan_id
        )
        self.assertEqual(
            fetched.reference.hypothesis_id, plan.hypothesis_id
        )
        self.assertEqual(fetched.reference.match_id, plan.match_id)
        self.assertEqual(
            fetched.reference.snapshot_hash, plan.snapshot_hash
        )


# ------------------------------------------------------------------
# AS-AT: concurrency
# ------------------------------------------------------------------


class ConcurrencyTests(StoreTestCase):
    def test_concurrent_same_content_converges(self):
        plan = _bound_plan()
        reference, content = _valid_nuclei(plan)
        errors: list = []
        results: list = []

        def _work():
            try:
                results.append(self.store.put(reference, content))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_work) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        for result in results:
            self.assertEqual(result.stored.content, content)
            self.assertEqual(result.stored.reference, reference)
        records = list(self.store.records_dir.glob("*.json"))
        self.assertEqual(len(records), 1)
        leftovers = [
            item for item in self.store.root_dir.rglob("*")
            if ".tmp" in item.name
        ]
        self.assertEqual(leftovers, [])

    def test_concurrent_distinct_artifacts_isolated(self):
        errors: list = []
        payloads: list = []

        def _work(index):
            try:
                plan = _bound_plan(sub=f"w{index}.acme.com")
                marker = f"concurrent-marker-{index:04d}"
                content = _template_bytes(marker)
                validated = build_validated_reference(
                    plan, content, "nuclei_template",
                    fixtures=[_benign(), _vulnerable(marker)],
                )
                assert validated.state == "VALID", validated.reasons
                payloads.append((validated.reference, content))
                self.store.put(validated.reference, content)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=_work, args=(index,))
            for index in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(self.store.list()), 8)
        for reference, content in payloads:
            fetched = self.store.get(reference.artifact_id)
            assert fetched is not None
            self.assertEqual(fetched.content, content)


# ------------------------------------------------------------------
# AJ-AQ, AD: static boundaries
# ------------------------------------------------------------------


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


class StaticBoundaryTests(unittest.TestCase):
    def test_no_llm_imports(self):
        imports = _imports_of(STORE_PATH)
        self.assertTrue(
            all("llm" not in name and "openrouter" not in name
                and "avalai" not in name and "embedding" not in name
                for name in imports),
            imports,
        )

    def test_no_network_imports(self):
        imports = _imports_of(STORE_PATH)
        roots = {name.split(".")[0] for name in imports}
        self.assertTrue(
            {"requests", "httpx", "urllib", "socket", "dns",
             "aiohttp", "urllib3"}.isdisjoint(roots),
            roots,
        )

    def test_no_subprocess_imports(self):
        imports = _imports_of(STORE_PATH)
        roots = {name.split(".")[0] for name in imports}
        self.assertTrue(
            {"subprocess", "multiprocessing", "pty",
             "shlex"}.isdisjoint(roots),
            roots,
        )

    def test_no_database_imports(self):
        imports = _imports_of(STORE_PATH)
        joined = " ".join(imports)
        for marker in ("mongoengine", "pymongo", "database"):
            self.assertNotIn(marker, joined)

    def test_no_scope_policy_import(self):
        imports = _imports_of(STORE_PATH)
        self.assertNotIn("ai.correlator.scope_policy", imports)
        self.assertNotIn(
            "scope_policy",
            Path(STORE_PATH).read_text(encoding="utf-8"),
        )

    def test_no_verifier_runtime_imports(self):
        imports = _imports_of(STORE_PATH)
        joined = " ".join(imports)
        for marker in ("verifier", "oracle", "executor",
                       "browser", "nuclei_runner", "nuclei_pipeline",
                       "findings", "Finding"):
            self.assertNotIn(marker, joined)

    def test_no_finding_creation(self):
        text = Path(STORE_PATH).read_text(encoding="utf-8")
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

    def test_no_verdict_or_authorization_fields(self):
        # Identifier-level: docstring prose mentioning what is
        # excluded ("never deleted", "no verdicts") does not count
        # — only real code identifiers and exact string literals do.
        tree = ast.parse(Path(STORE_PATH).read_text(encoding="utf-8"))
        identifiers: set[str] = set()
        literals: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                identifiers.add(node.id)
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr)
            elif isinstance(node, ast.FunctionDef):
                identifiers.add(node.name)
            elif isinstance(node, ast.arg):
                identifiers.add(node.arg)
            elif isinstance(node, ast.Constant) and isinstance(
                node.value, str
            ):
                literals.add(node.value)
        for banned in ("scope_allowed", "execution_allowed",
                       "authorized", "finding", "verdict",
                       "confirmed", "exploited", "vulnerable"):
            self.assertNotIn(banned, identifiers, banned)
            self.assertNotIn(banned, literals, banned)

    def test_no_delete_api(self):
        store = ArtifactStore.__dict__
        for name in ("delete", "remove", "purge", "clear",
                     "update_content", "replace", "gc", "expire"):
            self.assertNotIn(name, store, name)


# ------------------------------------------------------------------
# Integration: full chain into the store and back
# ------------------------------------------------------------------


class IntegrationTests(StoreTestCase):
    def test_full_chain_put_get(self):
        claim_id = "clm-" + _hex("phase4d-claim")[:16]
        claim = KnowledgeSourceClaims(
            title="FooCMS search reflection report",
            summary="FooCMS exposes a search endpoint with a q parameter",
            technologies=["FooCMS"],
            evidence_quality="SECONDARY",
            confidence=0.7,
            tags=["xss"],
        )
        grounded = GroundedClaim(
            claim=claim,
            claim_id=claim_id,
            knowledge_id="kb-" + _hex("phase4d-kb")[:16],
            source_id="src-" + _hex("phase4d-src")[:16],
        )
        patterns = project_claim(grounded)
        self.assertTrue(patterns)
        pattern = next(
            item for item in patterns
            if type(item).__name__ == "VulnerabilityPattern"
        )

        target = _target()
        from ai.researcher.target_matcher import match_pattern_to_target

        match = match_pattern_to_target(pattern, target)
        self.assertIn(match.match_kind, ("MATCH", "PARTIAL_MATCH"))
        built = build_hypothesis_from_match(match, pattern, target)
        self.assertEqual(built.outcome, "CREATED")
        planned = build_test_plan_from_hypothesis(
            built.hypothesis, match=match, pattern=pattern,
            target_intelligence=target,
        )
        self.assertEqual(planned.outcome, "CREATED")
        plan = planned.plan
        assert plan is not None

        content = _template_bytes()
        validated = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertEqual(validated.state, "VALID", validated.reasons)

        put = self.store.put(validated.reference, content)
        self.assertTrue(put.created)
        fetched = self.store.get(validated.reference.artifact_id)
        assert fetched is not None
        self.assertEqual(fetched.content, content)
        self.assertEqual(fetched.reference, validated.reference)
        self.assertEqual(
            fetched.reference.test_plan_id, plan.test_plan_id
        )
        self.assertEqual(
            fetched.reference.snapshot_hash, plan.snapshot_hash
        )


if __name__ == "__main__":
    unittest.main()
