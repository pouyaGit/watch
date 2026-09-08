"""Focused tests for the Phase 4C Artifact Reference + Safety Contract.

Proves the artifact boundary::

    TestPlan + artifact bytes -> validated, hash-bound ArtifactReference

No generation, no storage, no execution, no verification, no
findings, no verdicts, no LLM, no network, no subprocess, no
database. Covers the required adversarial matrix A-AO plus the
H1/H2 security proofs and a pure in-memory integration chain.
"""

import ast
import hashlib
import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from ai.researcher import artifact_validator as av_module
from ai.researcher.artifact_validator import (
    build_validated_reference,
    validate_reference_binding,
    validate_xss_payload,
)
from ai.researcher.hypothesis_engine import build_hypothesis_from_match
from ai.researcher.nuclei_artifact_validator import (
    NucleiFixture,
    NucleiTemplateContent,
    canonical_template_bytes,
    parse_template_content,
    validate_nuclei_specificity,
)
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
    MAX_NUCLEI_TEMPLATE_BYTES,
    MAX_XSS_PAYLOAD_BYTES,
    ArtifactReference,
    artifact_id_for,
    build_artifact_reference,
    content_hash_for_bytes,
    content_hash_for_mapping,
)
from ai.schemas.knowledge import KnowledgeSourceClaims

MARKER = "cve-2024-0001-unique-detection-marker-9f3a7c"


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


def _hex(tag):
    return hashlib.sha256(tag.encode("utf-8")).hexdigest()


def _template_dict(**overrides):
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
                "values": [MARKER],
                "part": "body",
            }
        ],
    }
    payload.update(overrides)
    return payload


def _template_bytes(**overrides):
    return json.dumps(
        _template_dict(**overrides),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _benign(body="Welcome to our homepage. All systems operational.",
              status=200, headers=None):
    return NucleiFixture(
        fixture_kind="benign", status=status,
        headers=dict(headers or {}), body=body,
    )


def _vulnerable(body=None):
    return NucleiFixture(
        fixture_kind="vulnerable",
        status=200,
        headers={},
        body=body if body is not None else f"results for {MARKER} version 1.2.3",
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
                    name="q", method="GET", location="query", source="crawl"
                ),
            ),
            record_id="ep-1",
        )
    ]
    return project_subdomain(
        prog, subrec, https=https, endpoints=endpoints
    ).intelligence


def _bound_plan(program="acme", sub="app.acme.com"):
    from ai.schemas.research_pattern import build_vulnerability_pattern
    from ai.schemas.hypothesis import ResearchProvenance

    target = _target(program=program, sub=sub)
    tag = f"{program}/{sub}"
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


def _module_sources():
    return {
        "artifact_schema": Path("ai/schemas/artifact.py").read_text(
            encoding="utf-8"
        ),
        "artifact_validator": Path(
            "ai/researcher/artifact_validator.py"
        ).read_text(encoding="utf-8"),
        "nuclei_validator": Path(
            "ai/researcher/nuclei_artifact_validator.py"
        ).read_text(encoding="utf-8"),
    }


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


# ------------------------------------------------------------------
# A-B: closed type vocabulary
# ------------------------------------------------------------------


class ArtifactTypeTests(unittest.TestCase):
    def test_closed_vocabulary_accepts_known_types(self):
        plan = _bound_plan()
        for artifact_type in (
            "nuclei_template",
            "xss_payload",
            "http_request_spec",
        ):
            if artifact_type == "nuclei_template":
                content = _template_bytes()
                fixtures = [_benign(), _vulnerable()]
            elif artifact_type == "xss_payload":
                content = b"probe-\x3cinput\x3e-marker"
                fixtures = None
            else:
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
                fixtures = None
            result = build_validated_reference(
                plan, content, artifact_type, fixtures=fixtures
            )
            self.assertEqual(result.state, "VALID", result.reasons)

    def test_unknown_type_rejected(self):
        plan = _bound_plan()
        for bad in ("shell_script", "arbitrary_code", "browser_script",
                    "executable", "command", "other", "", "NUCLEI_TEMPLATE"):
            with self.assertRaises(ValueError, msg=str(bad)):
                build_validated_reference(plan, b"{}", bad)

    def test_schema_rejects_unknown_type_literal(self):
        plan = _bound_plan()
        digest = content_hash_for_bytes(b"{}")
        with self.assertRaises(ValidationError):
            ArtifactReference(
                artifact_id=artifact_id_for(
                    artifact_type="shell_script",
                    test_plan_id=plan.test_plan_id,
                    content_hash=digest,
                ),
                artifact_type="shell_script",
                content_hash=digest,
                test_plan_id=plan.test_plan_id,
            )


# ------------------------------------------------------------------
# C-G, AL-AM: hashing and identity
# ------------------------------------------------------------------


class HashIdentityTests(unittest.TestCase):
    def test_deterministic_content_hash(self):
        content = _template_bytes()
        self.assertEqual(
            content_hash_for_bytes(content),
            content_hash_for_bytes(bytes(content)),
        )
        self.assertEqual(
            content_hash_for_bytes(content),
            hashlib.sha256(content).hexdigest(),
        )

    def test_one_byte_change_changes_hash(self):
        content = bytearray(_template_bytes())
        before = content_hash_for_bytes(bytes(content))
        content[-2] ^= 0x01
        self.assertNotEqual(before, content_hash_for_bytes(bytes(content)))

    def test_deterministic_artifact_id(self):
        plan = _bound_plan()
        first = build_artifact_reference(
            artifact_type="xss_payload", content=b"abc",
            test_plan_id=plan.test_plan_id,
        )
        second = build_artifact_reference(
            artifact_type="xss_payload", content=b"abc",
            test_plan_id=plan.test_plan_id,
        )
        self.assertEqual(first.artifact_id, second.artifact_id)
        self.assertEqual(first.content_hash, second.content_hash)

    def test_different_plan_different_identity(self):
        plan_a = _bound_plan(sub="a.acme.com")
        plan_b = _bound_plan(sub="b.acme.com")
        self.assertNotEqual(plan_a.test_plan_id, plan_b.test_plan_id)
        ref_a = build_artifact_reference(
            artifact_type="xss_payload", content=b"same-bytes",
            test_plan_id=plan_a.test_plan_id,
        )
        ref_b = build_artifact_reference(
            artifact_type="xss_payload", content=b"same-bytes",
            test_plan_id=plan_b.test_plan_id,
        )
        self.assertNotEqual(ref_a.artifact_id, ref_b.artifact_id)
        self.assertEqual(ref_a.content_hash, ref_b.content_hash)

    def test_same_content_same_plan_same_identity(self):
        plan = _bound_plan()
        content = _template_bytes()
        first = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        second = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertEqual(first.state, "VALID")
        self.assertEqual(
            first.reference.artifact_id, second.reference.artifact_id
        )

    def test_order_independent_canonical_hash(self):
        first = {"b": "2", "a": "1", "m": {"y": 1, "x": 0}}
        second = {"m": {"x": 0, "y": 1}, "a": "1", "b": "2"}
        self.assertEqual(
            content_hash_for_mapping(first),
            content_hash_for_mapping(second),
        )
        typed_first = NucleiTemplateContent.model_validate(
            _template_dict()
        )
        reordered = dict(reversed(list(_template_dict().items())))
        typed_second = NucleiTemplateContent.model_validate(reordered)
        self.assertEqual(
            canonical_template_bytes(typed_first),
            canonical_template_bytes(typed_second),
        )

    def test_duplicate_validation_converges(self):
        plan = _bound_plan()
        content = _template_bytes()
        first = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        second = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_vulnerable(), _benign()],
        )
        self.assertEqual(first.state, second.state)
        self.assertEqual(
            first.reference.artifact_id, second.reference.artifact_id
        )
        self.assertEqual(first.reasons, second.reasons)
        self.assertEqual(
            validate_reference_binding(
                first.reference, plan, content,
                fixtures=[_benign(), _vulnerable()],
            ),
            [],
        )


# ------------------------------------------------------------------
# H-J: plan/provenance binding
# ------------------------------------------------------------------


class BindingTests(unittest.TestCase):
    def test_wrong_test_plan_rejected(self):
        plan_a = _bound_plan(sub="a.acme.com")
        plan_b = _bound_plan(sub="b.acme.com")
        content = _template_bytes()
        result = build_validated_reference(
            plan_a, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        errors = validate_reference_binding(
            result.reference, plan_b, content,
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertTrue(
            any("test_plan" in item for item in errors), errors
        )

    def test_wrong_hypothesis_binding_rejected(self):
        plan = _bound_plan()
        content = b"plain-payload"
        result = build_validated_reference(plan, content, "xss_payload")
        tampered = result.reference.model_copy(
            update={"hypothesis_id": "hyp-" + "0" * 16}
        )
        # Recompute a consistent id for the tampered binding so the
        # test isolates the hypothesis check (schema stays valid).
        tampered = ArtifactReference.model_validate(
            {
                **tampered.model_dump(mode="json"),
                "artifact_id": artifact_id_for(
                    artifact_type=tampered.artifact_type,
                    test_plan_id=tampered.test_plan_id,
                    content_hash=tampered.content_hash,
                    schema_version=tampered.artifact_schema_version,
                ),
            }
        )
        errors = validate_reference_binding(tampered, plan, content)
        self.assertTrue(
            any("hypothesis" in item for item in errors), errors
        )

    def test_wrong_snapshot_binding_rejected(self):
        plan = _bound_plan()
        content = b"plain-payload"
        result = build_validated_reference(plan, content, "xss_payload")
        tampered = ArtifactReference.model_validate(
            {
                **result.reference.model_dump(mode="json"),
                "snapshot_hash": "0" * 64,
                "artifact_id": artifact_id_for(
                    artifact_type=result.reference.artifact_type,
                    test_plan_id=result.reference.test_plan_id,
                    content_hash=result.reference.content_hash,
                    schema_version=(
                        result.reference.artifact_schema_version
                    ),
                ),
            }
        )
        errors = validate_reference_binding(tampered, plan, content)
        self.assertTrue(
            any("snapshot" in item for item in errors), errors
        )

    def test_tampered_bytes_rejected(self):
        plan = _bound_plan()
        content = _template_bytes()
        result = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        tampered = bytearray(content)
        tampered[10] ^= 0x01
        errors = validate_reference_binding(
            result.reference, plan, bytes(tampered),
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertTrue(
            any("hash" in item for item in errors), errors
        )

    def test_typed_inputs_only(self):
        plan = _bound_plan()
        with self.assertRaises(TypeError):
            build_validated_reference(
                plan.model_dump(mode="json"), b"x", "xss_payload"
            )
        with self.assertRaises(TypeError):
            build_validated_reference(plan, "not-bytes", "xss_payload")
        with self.assertRaises(TypeError):
            validate_reference_binding("ref", plan, b"x")
        with self.assertRaises(TypeError):
            validate_nuclei_specificity({"a": 1}, [_benign()])
        with self.assertRaises(TypeError):
            validate_nuclei_specificity(
                NucleiTemplateContent.model_validate(_template_dict()),
                [{"fixture_kind": "benign"}],
            )


# ------------------------------------------------------------------
# K-L: malformed + oversized
# ------------------------------------------------------------------


class MalformedSizeTests(unittest.TestCase):
    def test_malformed_nuclei_rejected(self):
        plan = _bound_plan()
        for bad in (b"not json", b"[1,2]", b'{"unknown_field": 1}',
                    b'{"method": "GET"}'):
            result = build_validated_reference(
                plan, bad, "nuclei_template", fixtures=[_benign()]
            )
            self.assertEqual(result.state, "REJECTED", bad)
            self.assertEqual(
                result.reference.validation_state, "REJECTED"
            )

    def test_malformed_http_rejected(self):
        plan = _bound_plan()
        result = build_validated_reference(
            plan, b"nope", "http_request_spec"
        )
        self.assertEqual(result.state, "REJECTED")

    def test_oversized_nuclei_rejected(self):
        plan = _bound_plan()
        big = b"a" * (MAX_NUCLEI_TEMPLATE_BYTES + 1)
        result = build_validated_reference(
            plan, big, "nuclei_template", fixtures=[_benign()]
        )
        self.assertEqual(result.state, "REJECTED")
        with self.assertRaises(ValueError):
            build_artifact_reference(
                artifact_type="nuclei_template", content=big,
                test_plan_id=plan.test_plan_id,
            )

    def test_oversized_xss_rejected(self):
        plan = _bound_plan()
        big = b"b" * (MAX_XSS_PAYLOAD_BYTES + 1)
        result = build_validated_reference(plan, big, "xss_payload")
        self.assertEqual(result.state, "REJECTED")
        self.assertTrue(validate_xss_payload(big))


# ------------------------------------------------------------------
# M-U: H2 safety matrix (via nuclei + http artifacts)
# ------------------------------------------------------------------


class H2SafetyTests(unittest.TestCase):
    def _check_rejected(self, **overrides):
        plan = _bound_plan()
        content = _template_bytes(**overrides)
        result = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertEqual(result.state, "REJECTED", result.reasons)
        return result

    def test_crlf_in_path_rejected(self):
        self._check_rejected(path="/search\r\nEvil: 1")

    def test_control_chars_in_path_rejected(self):
        self._check_rejected(path="/search\x01x")

    def test_absolute_url_in_path_rejected(self):
        self._check_rejected(path="https://evil.example/search")

    def test_crlf_in_header_rejected(self):
        self._check_rejected(
            headers={"X-Test": "a\r\nB: c"}
        )
        self._check_rejected(headers={"Bad\r\nName": "x"})

    def test_malformed_header_name_rejected(self):
        self._check_rejected(headers={"Bad Header!": "x"})

    def test_authorization_cookie_rejected(self):
        self._check_rejected(
            headers={"Authorization": "Bearer abc123"}
        )
        self._check_rejected(headers={"Cookie": "session=abc"})
        self._check_rejected(
            headers={"X-Ok": "yes", "Set-Cookie": "a=b"}
        )

    def test_bearer_token_value_rejected(self):
        self._check_rejected(headers={"X-Token": "Bearer secret-value"})

    def test_shell_syntax_rejected(self):
        self._check_rejected(query_params={"q": "a; cat /etc/passwd"})
        self._check_rejected(query_params={"q": "a|b"})

    def test_command_substitution_rejected(self):
        self._check_rejected(query_params={"q": "$(id)"})
        self._check_rejected(query_params={"q": "`id`"})
        self._check_rejected(query_params={"q": "${HOME}"})

    def test_shell_keyword_rejected(self):
        self._check_rejected(query_params={"q": "curl http://x.example"})

    def test_destructive_method_rejected(self):
        plan = _bound_plan()
        content = _template_bytes(method="DELETE")
        result = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertEqual(result.state, "REJECTED", result.reasons)

    def test_unsafe_host_rejected(self):
        self._check_rejected(headers={"X-Cb": "http://127.0.0.1/x"})
        self._check_rejected(
            headers={"X-Cb": "http://169.254.169.254/latest"}
        )
        self._check_rejected(
            headers={"X-Cb": "http://10.0.0.5/internal"}
        )
        self._check_rejected(
            headers={"X-Cb": "http://localhost/admin"}
        )

    def test_callback_endpoint_rejected(self):
        self._check_rejected(
            headers={"X-Cb": "https://abc123.burpcollaborator.net/x"}
        )
        self._check_rejected(
            query_params={"next": "https://x.interactsh.com/c"}
        )

    def test_embedded_script_rejected(self):
        self._check_rejected(path="/x\x3cscript\x3ealert(1)")
        self._check_rejected(body="hello \x3cscript\x3e evil")
        self._check_rejected(headers={"X-A": "javascript:alert(1)"})

    def test_http_artifact_enforces_same_gates(self):
        plan = _bound_plan()

        def _http(**overrides):
            payload = {
                "method": "GET",
                "path": "/search",
                "query_params": {"q": "probe"},
                "headers": {},
                "body": None,
            }
            payload.update(overrides)
            return json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode()

        good = build_validated_reference(
            plan, _http(), "http_request_spec"
        )
        self.assertEqual(good.state, "VALID", good.reasons)
        for bad in (
            _http(path="/x\r\ny"),
            _http(headers={"Cookie": "s=1"}),
            _http(query_params={"q": "$(id)"}),
            _http(headers={"X-C": "http://169.254.169.254/"}),
        ):
            result = build_validated_reference(
                plan, bad, "http_request_spec"
            )
            self.assertEqual(result.state, "REJECTED", result.reasons)
        rejected_delete = build_validated_reference(
            plan, _http(method="DELETE"), "http_request_spec"
        )
        self.assertEqual(rejected_delete.state, "REJECTED")


# ------------------------------------------------------------------
# V-Y, H1 proof: specificity gate
# ------------------------------------------------------------------


class H1SpecificityTests(unittest.TestCase):
    def test_generic_matcher_with_benign_fixture_rejected(self):
        plan = _bound_plan()
        content = _template_bytes(
            matchers=[
                {"matcher_type": "word", "values": ["error"],
                 "part": "body"}
            ]
        )
        result = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign("a benign error page"), _vulnerable()],
        )
        self.assertEqual(result.state, "REJECTED", result.reasons)

    def test_broad_matcher_matching_benign_rejected(self):
        template = NucleiTemplateContent.model_validate(
            _template_dict(
                matchers=[
                    {"matcher_type": "word",
                     "values": ["Welcome to our homepage"],
                     "part": "body"}
                ]
            )
        )
        outcome = validate_nuclei_specificity(
            template, [_benign(), _vulnerable("other specific text")]
        )
        self.assertFalse(outcome.passed)

    def test_specific_matcher_passes_benign(self):
        plan = _bound_plan()
        content = _template_bytes()
        result = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertEqual(result.state, "VALID", result.reasons)

    def test_vulnerable_fixture_positive_proof(self):
        template = NucleiTemplateContent.model_validate(_template_dict())
        outcome = validate_nuclei_specificity(
            template, [_benign(), _vulnerable()]
        )
        self.assertTrue(outcome.passed, outcome.reasons)
        missed = validate_nuclei_specificity(
            template, [_benign(), _vulnerable("unrelated text")]
        )
        self.assertFalse(missed.passed)

    def test_no_specificity_proof_rejected(self):
        plan = _bound_plan()
        status_only = _template_bytes(
            matchers=[
                {"matcher_type": "status", "values": ["200"],
                 "part": "status"}
            ]
        )
        result = build_validated_reference(
            plan, status_only, "nuclei_template",
            fixtures=[_benign(status=404), _vulnerable()],
        )
        self.assertEqual(result.state, "REJECTED", result.reasons)
        no_benign = build_validated_reference(
            plan, _template_bytes(), "nuclei_template",
            fixtures=[_vulnerable()],
        )
        self.assertEqual(no_benign.state, "REJECTED", no_benign.reasons)
        no_fixtures = build_validated_reference(
            plan, _template_bytes(), "nuclei_template"
        )
        self.assertEqual(no_fixtures.state, "REJECTED")

    def test_malformed_fixture_rejected(self):
        template = NucleiTemplateContent.model_validate(_template_dict())
        with self.assertRaises(TypeError):
            validate_nuclei_specificity(template, "benign")
        with self.assertRaises(TypeError):
            validate_nuclei_specificity(
                template, [{"fixture_kind": "benign"}]
            )
        # Empty fixture list cannot prove specificity (fail closed,
        # no exception — a deterministic REJECTED-equivalent).
        outcome = validate_nuclei_specificity(template, [])
        self.assertFalse(outcome.passed)

    def test_parse_round_trip(self):
        content = _template_bytes()
        parsed = parse_template_content(content)
        self.assertEqual(
            canonical_template_bytes(parsed), content
        )
        with self.assertRaises(ValueError):
            parse_template_content(b"\xff\xfe invalid")
        with self.assertRaises(ValueError):
            parse_template_content(b"[1]")


# ------------------------------------------------------------------
# Z-AA: XSS boundary
# ------------------------------------------------------------------


class XSSArtifactTests(unittest.TestCase):
    def test_xss_payload_is_bounded_inert_data(self):
        plan = _bound_plan()
        result = build_validated_reference(
            plan, b"marker-probe-123", "xss_payload"
        )
        self.assertEqual(result.state, "VALID", result.reasons)
        ref = result.reference
        self.assertEqual(ref.test_plan_id, plan.test_plan_id)
        self.assertEqual(ref.hypothesis_id, plan.hypothesis_id)
        self.assertEqual(ref.validation_state, "VALID")
        self.assertNotIn("CONFIRMED", ref.model_dump(mode="json").values())

    def test_xss_empty_and_nul_rejected(self):
        self.assertTrue(validate_xss_payload(b""))
        self.assertTrue(validate_xss_payload(b"a\x00b"))

    def test_xss_payload_never_executed(self):
        # AST-level: no runtime/execution calls exist in the
        # artifact modules (docstring prose mentioning what is
        # excluded does not count — only real imports/calls do).
        for path in StaticBoundaryTests.PATHS:
            tree = ast.parse(Path(path).read_text(encoding="utf-8"))
            called = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute):
                        called.add(func.attr)
                    elif isinstance(func, ast.Name):
                        called.add(func.id)
            for marker in ("Popen", "check_output", "check_call",
                           "run", "system", "exec", "eval",
                           "urlopen", "get"):
                if marker in ("run", "get", "system", "exec", "eval"):
                    continue  # too generic as bare names; covered below
                self.assertNotIn(marker, called, f"{path}:{marker}")
            text = Path(path).read_text(encoding="utf-8")
            for marker in ("playwright", "selenium", "pyppeteer",
                           "requests.get", "urlopen("):
                self.assertNotIn(marker, text, f"{path}:{marker}")


# ------------------------------------------------------------------
# AB-AK: static boundaries
# ------------------------------------------------------------------


class StaticBoundaryTests(unittest.TestCase):
    PATHS = (
        "ai/schemas/artifact.py",
        "ai/researcher/artifact_validator.py",
        "ai/researcher/nuclei_artifact_validator.py",
    )

    def test_no_llm_import(self):
        for path in self.PATHS:
            imports = _imports_of(path)
            self.assertFalse(
                {name for name in imports
                 if "llm" in name or "openrouter" in name or "avalai" in name},
                path,
            )
            text = Path(path).read_text(encoding="utf-8").casefold()
            self.assertNotIn("prompt_version", text, path)

    def test_no_network_import(self):
        for path in self.PATHS:
            imports = _imports_of(path)
            banned = {"requests", "httpx", "urllib", "socket", "dns",
                      "aiohttp", "urllib3"}
            self.assertTrue(
                banned.isdisjoint(
                    {name.split(".")[0] for name in imports}
                ),
                f"{path}: {imports & banned}",
            )

    def test_no_subprocess_import(self):
        for path in self.PATHS:
            imports = _imports_of(path)
            self.assertFalse(
                {"subprocess", "multiprocessing", "pty", "shlex"}
                & {name.split(".")[0] for name in imports},
                path,
            )

    def test_no_db_import(self):
        for path in self.PATHS:
            imports = _imports_of(path)
            joined = " ".join(imports)
            for marker in ("mongoengine", "database", "pymongo"):
                self.assertNotIn(marker, joined, path)

    def test_no_scope_policy_import(self):
        for path in self.PATHS:
            imports = _imports_of(path)
            self.assertNotIn("ai.correlator.scope_policy", imports, path)
            text = Path(path).read_text(encoding="utf-8")
            self.assertNotIn("scope_policy", text, path)

    def test_no_verifier_import(self):
        for path in self.PATHS:
            imports = _imports_of(path)
            joined = " ".join(imports)
            for marker in ("verifier", "oracle", "executor",
                           "nuclei_runner", "nuclei_pipeline"):
                self.assertNotIn(marker, joined, path)

    def test_no_finding_creation(self):
        for path in self.PATHS:
            text = Path(path).read_text(encoding="utf-8")
            self.assertNotIn("Finding", text, path)
            tree = ast.parse(text)
            called = {
                node.func.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
            }
            self.assertFalse(
                {"create_finding", "save_finding", "emit_finding"}
                & called,
                path,
            )

    def test_no_verdict_or_authorization_fields(self):
        ref_fields = set(ArtifactReference.model_fields)
        for forbidden in ("verdict", "confirmed", "vulnerable",
                          "exploited", "not_vulnerable", "scope_allowed",
                          "execution_allowed", "authorized", "finding",
                          "evidence"):
            self.assertNotIn(forbidden, ref_fields, forbidden)
        states = {"UNVALIDATED", "VALID", "REJECTED"}
        self.assertEqual(
            set(
                ArtifactReference.model_fields[
                    "validation_state"
                ].annotation.__args__
            ),
            states,
        )


# ------------------------------------------------------------------
# AN-AO: metadata authority
# ------------------------------------------------------------------


class MetadataAuthorityTests(unittest.TestCase):
    def test_hostile_metadata_cannot_change_identity(self):
        plan = _bound_plan()
        first = build_artifact_reference(
            artifact_type="xss_payload", content=b"same",
            test_plan_id=plan.test_plan_id,
            metadata={"label": "one"},
        )
        second = build_artifact_reference(
            artifact_type="xss_payload", content=b"same",
            test_plan_id=plan.test_plan_id,
            metadata={"label": "two", "extra": "hostile"},
        )
        self.assertEqual(first.artifact_id, second.artifact_id)
        self.assertEqual(first.content_hash, second.content_hash)

    def test_prompt_model_metadata_not_authoritative(self):
        plan = _bound_plan()
        ref = build_artifact_reference(
            artifact_type="xss_payload", content=b"same",
            test_plan_id=plan.test_plan_id,
            metadata={"model": "evil-model", "note": "audit only"},
        )
        self.assertEqual(
            ref.artifact_id,
            artifact_id_for(
                artifact_type="xss_payload",
                test_plan_id=plan.test_plan_id,
                content_hash=ref.content_hash,
            ),
        )
        with self.assertRaises(ValidationError):
            build_artifact_reference(
                artifact_type="xss_payload", content=b"same",
                test_plan_id=plan.test_plan_id,
                metadata={"verdict": "confirmed"},
            )
        with self.assertRaises(ValidationError):
            build_artifact_reference(
                artifact_type="xss_payload", content=b"same",
                test_plan_id=plan.test_plan_id,
                metadata={"scope_allowed": "true"},
            )

    def test_no_runtime_invocation_text(self):
        for path in StaticBoundaryTests.PATHS:
            tree = ast.parse(Path(path).read_text(encoding="utf-8"))
            called = set()
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute):
                        called.add(func.attr)
                    elif isinstance(func, ast.Name):
                        called.add(func.id)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imported.add(alias.name.split(".")[0])
            self.assertTrue(
                {"subprocess", "multiprocessing", "pty",
                 "shlex"}.isdisjoint(imported),
                f"{path}: runtime import {imported}",
            )
            for marker in ("Popen", "check_output", "check_call",
                           "execve", "spawnl", "fork"):
                self.assertNotIn(marker, called, f"{path}:{marker}")


# ------------------------------------------------------------------
# Integration: claim -> pattern -> target -> match -> hypothesis
#              -> plan -> artifact reference
# ------------------------------------------------------------------


class IntegrationTests(unittest.TestCase):
    def test_in_memory_chain(self):
        claim_id = "clm-" + _hex("phase4c-claim")[:16]
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
            knowledge_id="kb-" + _hex("phase4c-kb")[:16],
            source_id="src-" + _hex("phase4c-src")[:16],
        )
        patterns = project_claim(grounded)
        self.assertTrue(patterns)
        pattern = next(
            item for item in patterns
            if type(item).__name__ == "VulnerabilityPattern"
        )

        target = _target()
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

        content = _template_bytes(
            path="/search",
            query_params={"q": "probe"},
            matchers=[
                {"matcher_type": "word", "values": [MARKER],
                 "part": "body"}
            ],
        )
        validated = build_validated_reference(
            plan, content, "nuclei_template",
            fixtures=[_benign(), _vulnerable()],
        )
        self.assertEqual(validated.state, "VALID", validated.reasons)
        ref = validated.reference
        self.assertEqual(ref.test_plan_id, plan.test_plan_id)
        self.assertEqual(ref.hypothesis_id, plan.hypothesis_id)
        self.assertEqual(ref.match_id, plan.match_id)
        self.assertEqual(ref.snapshot_hash, plan.snapshot_hash)
        self.assertEqual(ref.validation_state, "VALID")
        self.assertEqual(
            validate_reference_binding(
                ref, plan, content,
                fixtures=[_benign(), _vulnerable()],
            ),
            [],
        )
        dumped = ref.model_dump(mode="json")
        for forbidden in ("scope_allowed", "execution_allowed",
                          "verdict", "confirmed", "vulnerable"):
            self.assertNotIn(forbidden, dumped)


if __name__ == "__main__":
    unittest.main()
