"""Research Pattern data contracts (Phase 2A).

A Research Pattern is normalized, auditable PRE-EXECUTION research
intelligence projected from GROUNDED claims. It is:

- NOT a finding and carries no verdict semantics (no CONFIRMED /
  VERIFIED / NOT_VULNERABLE can exist on this contract).
- NOT a target match: it describes research-side conditions only.
  Whether a Watch target is affected is decided later by the
  deterministic matcher (ai/correlator), never by a pattern.
- NOT execution authority: no command, shell, subprocess, eval,
  tool-call, callback, plugin, or executable-template field exists.
- NOT scope authority: no scope_allowed / allow_scope field exists.
  Target scope is resolved later by deterministic Watch policy.
- NOT evidence: observables describe what a future test SHOULD
  observe; they never assert that anything was observed.
- NOT verification: patterns cannot declare a target safe or unsafe.
  RETIRED status means the research became obsolete, NOT that a
  target was verified safe.

Trust separation is structural, not documentary only: grounded facts
live in ``facts`` (projected from grounded, provenance-cited claims),
model interpretation lives in ``interpretation`` (explicitly
non-authoritative), and deterministic metadata (identity, lifecycle,
schema version) lives at the top level. Model interpretation can
NEVER overwrite grounded facts because they occupy disjoint fields.

Identity follows the KnowledgeStore content-addressing convention
(AGENTS.md): ``idempotency_key`` is the full SHA-256 over the
canonical semantic basis, ``pattern_id`` is its short alias
(``vp-``/``ap-`` + first 16 hex chars), and ``semantic_key`` is the
SHA-256 over the same basis EXCLUDING provenance so the same
normalized pattern extracted from different sources (or by different
models) can later be recognized and merged. LLM metadata, reported
severity, timestamps, and status are audit metadata only and are
EXCLUDED from identity.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from ai.ingestion.grounding import contains_forbidden
from ai.schemas.hypothesis import (
    LLMMetadata,
    ResearchProvenance,
    _normalize_text,
)


SCHEMA_VERSION = "vulnerability_pattern/v1"
ATTACK_SCHEMA_VERSION = "attack_pattern/v1"

PatternStatus = Literal["ACTIVE", "SUPERSEDED", "RETIRED"]

# Shared closed pattern vocabulary. Smallest useful set for the
# current Watch architecture (CVE/Nuclei pipeline + XSS research
# stack). Unknown values fail closed. Each contract accepts only its
# semantically valid subset (enforced by model validators below).
ResearchPatternKind = Literal[
    "VULNERABILITY",
    "PRODUCT_VULNERABILITY",
    "TECHNIQUE",
    "ATTACK_SURFACE",
    "FRAMEWORK_BEHAVIOR",
]

_VULNERABILITY_KINDS = frozenset(
    {"VULNERABILITY", "PRODUCT_VULNERABILITY", "FRAMEWORK_BEHAVIOR"}
)
_ATTACK_KINDS = frozenset(
    {"TECHNIQUE", "ATTACK_SURFACE", "FRAMEWORK_BEHAVIOR"}
)

_VP_ID_RE = re.compile(r"^vp-[0-9a-f]{16}$")
_AP_ID_RE = re.compile(r"^ap-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VULN_ID_RE = re.compile(
    r"^(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CWE-\d{1,5})$"
)
_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.\-_+]{0,63}$")
_PARAMETER_RE = re.compile(r"^[A-Za-z0-9_.\-[\]]{1,128}$")
_CONTENT_TYPE_RE = re.compile(r"^[A-Za-z0-9.\-+]+/[A-Za-z0-9.\-+]+$")
_CVSS_VECTOR_RE = re.compile(
    r"^CVSS:[0-9.]+/[A-Za-z0-9:./\-]+$"
)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _require_grounded_labels(
    values: list[str], field_name: str
) -> list[str]:
    """Pattern label lists must be short, single-line, non-executable.

    Mirrors the ingestion policy (ai/ingestion/grounding) so pattern
    text can never smuggle executable constructs. Fail closed.
    """

    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"{field_name} entries must be non-empty strings"
            )
        if len(value) > 256:
            raise ValueError(
                f"{field_name} entry exceeds 256 characters"
            )
        if "\n" in value or "\r" in value:
            raise ValueError(
                f"{field_name} entries must not contain newlines"
            )
        if contains_forbidden(value):
            raise ValueError(
                f"{field_name} entry contains an executable payload "
                f"construct: {value!r}"
            )
    return values


class ProductIdentity(BaseModel):
    """Structured research-side product identity.

    Represents what research CLAIMS about a product. It does NOT
    decide whether any Watch target runs this product; that is the
    deterministic matcher's responsibility. Identity is kept
    sufficient for CVE → product → target matching (vendor, product,
    optional ecosystem/alias/CPE) and deliberately NOT a universal
    SBOM system.
    """

    model_config = ConfigDict(extra="forbid")

    vendor: str = ""
    product: str
    ecosystem: str = ""
    aliases: list[str] = Field(default_factory=list)
    cpe: str | None = None

    @field_validator("product")
    @classmethod
    def _product(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("product must be a non-empty string")
        if len(value) > 256:
            raise ValueError("product exceeds 256 characters")
        return value

    @field_validator("vendor", "ecosystem")
    @classmethod
    def _optional_label(cls, value: str) -> str:
        if len(value) > 256:
            raise ValueError("exceeds 256 characters")
        if "\n" in value or "\r" in value:
            raise ValueError("must not contain newlines")
        return value

    @field_validator("aliases")
    @classmethod
    def _aliases(cls, values: list[str]) -> list[str]:
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    "aliases must be non-empty strings"
                )
            if len(value) > 256:
                raise ValueError("alias exceeds 256 characters")
        return values

    @field_validator("cpe")
    @classmethod
    def _cpe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("cpe:2.3:"):
            raise ValueError(
                "cpe must be a CPE 2.3 string (cpe:2.3:...)"
            )
        if len(value) > 512:
            raise ValueError("cpe exceeds 512 characters")
        return value


class VersionConstraint(BaseModel):
    """Structured research-side version constraint. Representation only.

    This schema REPRESENTS what research claims about affected
    versions (exact versions, bounds with inclusive/exclusive
    semantics, ranges, fixed versions, and explicitly
    unknown/unparseable constraints). It performs NO comparison:
    deterministic version matching remains the responsibility of
    ``ai/correlator/version.py`` (extended by the matcher phase, not
    here). ``raw`` preserves the verbatim research sentence for audit
    but is NEVER authoritative for matching.
    """

    model_config = ConfigDict(extra="forbid")

    constraint_kind: Literal[
        "EXACT",
        "RANGE",
        "LOWER_BOUND",
        "UPPER_BOUND",
        "FIXED",
        "UNKNOWN",
    ]
    version: str | None = None
    upper_version: str | None = None
    lower_inclusive: bool = True
    upper_inclusive: bool = False
    raw: str | None = None

    @field_validator("version", "upper_version")
    @classmethod
    def _version_token(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _VERSION_RE.match(value):
            raise ValueError(
                f"malformed version token: {value!r}"
            )
        return value

    @field_validator("raw")
    @classmethod
    def _raw(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) > 256:
            raise ValueError("raw exceeds 256 characters")
        if "\n" in value or "\r" in value:
            raise ValueError("raw must not contain newlines")
        if contains_forbidden(value):
            raise ValueError(
                "raw contains an executable payload construct"
            )
        return value

    @model_validator(mode="after")
    def _shape_consistency(self) -> "VersionConstraint":
        kind = self.constraint_kind
        if kind == "EXACT":
            if not self.version or self.upper_version:
                raise ValueError(
                    "EXACT requires version and no upper_version"
                )
        elif kind == "RANGE":
            if not (self.version and self.upper_version):
                raise ValueError(
                    "RANGE requires version and upper_version"
                )
        elif kind == "LOWER_BOUND":
            if not self.version or self.upper_version:
                raise ValueError(
                    "LOWER_BOUND requires version and no upper_version"
                )
        elif kind == "UPPER_BOUND":
            if not self.version or self.upper_version:
                raise ValueError(
                    "UPPER_BOUND requires version (the upper bound) "
                    "and no upper_version"
                )
        elif kind == "FIXED":
            if not self.version or self.upper_version:
                raise ValueError(
                    "FIXED requires version (the fixed version) and "
                    "no upper_version"
                )
        elif kind == "UNKNOWN":
            if self.version or self.upper_version:
                raise ValueError(
                    "UNKNOWN must not carry parsed versions; use raw"
                )
        return self


class AttackSurfaceCharacteristic(BaseModel):
    """Non-executable description of one attack-surface property.

    Structured, constrained data only: no host, no URL, no request
    builder, no callback. A future test planner may use these fields
    to shape a test; the fields themselves cannot invoke anything.
    """

    model_config = ConfigDict(extra="forbid")

    surface_kind: Literal[
        "http_endpoint",
        "parameter",
        "file_upload",
        "url_fetch",
        "api_endpoint",
        "client_side",
        "auth_flow",
        "header",
        "cookie",
        "storage",
    ]
    path: str | None = None
    method: Literal[
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    ] | None = None
    parameter: str | None = None
    parameter_location: Literal[
        "query", "body", "header", "cookie", "path", "fragment",
        "postMessage", "storage",
    ] | None = None
    content_type: str | None = None
    authentication: Literal["none", "required", "unknown"] = "unknown"
    browser_involved: bool = False
    notes: list[str] = Field(default_factory=list)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("/"):
            raise ValueError("path must start with '/'")
        if "\n" in value or "\r" in value:
            raise ValueError("path must not contain newlines")
        if len(value) > 512:
            raise ValueError("path exceeds 512 characters")
        return value

    @field_validator("parameter")
    @classmethod
    def _parameter(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _PARAMETER_RE.match(value):
            raise ValueError(f"malformed parameter name: {value!r}")
        return value

    @field_validator("content_type")
    @classmethod
    def _content_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _CONTENT_TYPE_RE.match(value):
            raise ValueError(
                f"malformed content_type: {value!r}"
            )
        return value

    @field_validator("notes")
    @classmethod
    def _notes(cls, values: list[str]) -> list[str]:
        return _require_grounded_labels(values, "notes")


class ObservableCharacteristic(BaseModel):
    """What a future test SHOULD observe. Expectation, never evidence.

    These are TEST REQUIREMENTS (e.g. "parameter reflected in HTML
    body", "JavaScript sink executes with marker"). They never assert
    that anything was observed on any target; observations and
    evidence are produced later by executors and classified only by
    deterministic verifiers.
    """

    model_config = ConfigDict(extra="forbid")

    observation_kind: Literal[
        "response_contains",
        "parameter_reflected",
        "reaches_html_context",
        "javascript_executes",
        "status_code",
        "response_header",
        "behavior",
    ]
    description: str
    expected_value: str | None = None

    @field_validator("description")
    @classmethod
    def _description(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError(
                "description must be a non-empty string"
            )
        if len(value) > 256:
            raise ValueError("description exceeds 256 characters")
        if "\n" in value or "\r" in value:
            raise ValueError("description must not contain newlines")
        if contains_forbidden(value):
            raise ValueError(
                "description contains an executable payload construct"
            )
        return value

    @field_validator("expected_value")
    @classmethod
    def _expected_value(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) > 256:
            raise ValueError(
                "expected_value exceeds 256 characters"
            )
        if "\n" in value or "\r" in value:
            raise ValueError(
                "expected_value must not contain newlines"
            )
        return value


class ModelInterpretation(BaseModel):
    """Untrusted model interpretation. Explicitly non-authoritative.

    Everything here is model-derived prose or self-reported
    confidence. It is EXCLUDED from identity, MUST NEVER overwrite or
    amend grounded facts (disjoint fields), and MUST NEVER influence
    deterministic matching or verification.
    """

    model_config = ConfigDict(extra="forbid")

    classification_hints: list[str] = Field(default_factory=list)
    precondition_hints: list[str] = Field(default_factory=list)
    rationale: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    llm: LLMMetadata = Field(default_factory=LLMMetadata)

    @field_validator(
        "classification_hints", "precondition_hints"
    )
    @classmethod
    def _hints(cls, values: list[str]) -> list[str]:
        return _require_grounded_labels(values, "hints")

    @field_validator("rationale")
    @classmethod
    def _rationale(cls, value: str) -> str:
        if len(value) > 2048:
            raise ValueError("rationale exceeds 2048 characters")
        return value


class VulnerabilityFacts(BaseModel):
    """GROUNDED FACTS of a vulnerability pattern.

    Every field is projected from grounded, provenance-cited claims
    (see ``ResearchProvenance.claim_ids`` requirement on the pattern).
    These fields are the pattern's authoritative research-side
    content: they define identity and are the ONLY fields a future
    deterministic matcher may consult. Model interpretation cannot
    reach these fields.
    """

    model_config = ConfigDict(extra="forbid")

    vulnerability_ids: list[str] = Field(default_factory=list)
    products: list[ProductIdentity] = Field(default_factory=list)
    version_constraints: list[VersionConstraint] = Field(
        default_factory=list
    )
    attack_surface: list[AttackSurfaceCharacteristic] = Field(
        default_factory=list
    )
    observables: list[ObservableCharacteristic] = Field(
        default_factory=list
    )
    required_conditions: list[str] = Field(default_factory=list)

    @field_validator("vulnerability_ids")
    @classmethod
    def _vuln_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _VULN_ID_RE.match(value or ""):
                raise ValueError(
                    f"invalid vulnerability identifier: {value!r}"
                )
        return values

    @field_validator("required_conditions")
    @classmethod
    def _conditions(cls, values: list[str]) -> list[str]:
        return _require_grounded_labels(
            values, "required_conditions"
        )


class AttackFacts(BaseModel):
    """GROUNDED FACTS of an attack pattern.

    Same trust semantics as :class:`VulnerabilityFacts`: projected
    from grounded claims, authoritative for identity, and the only
    fields a future deterministic matcher may consult. Describes a
    reusable attack technique; contains NO exploit execution logic.
    """

    model_config = ConfigDict(extra="forbid")

    technique: str
    input_characteristics: list[str] = Field(default_factory=list)
    sink_characteristics: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    expected_observables: list[ObservableCharacteristic] = Field(
        default_factory=list
    )
    technology_context: list[str] = Field(default_factory=list)

    @field_validator("technique")
    @classmethod
    def _technique(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError(
                "technique must be a non-empty string"
            )
        if len(value) > 256:
            raise ValueError("technique exceeds 256 characters")
        return value

    @field_validator(
        "input_characteristics",
        "sink_characteristics",
        "preconditions",
        "technology_context",
    )
    @classmethod
    def _labels(cls, values: list[str]) -> list[str]:
        return _require_grounded_labels(values, "characteristics")


# ------------------------------------------------------------------
# Deterministic identity
# ------------------------------------------------------------------


def _canonical_products(
    products: list[ProductIdentity],
) -> list[dict]:
    canonical = []
    for product in products:
        canonical.append(
            {
                "aliases": sorted(
                    _normalize_text(alias) for alias in product.aliases
                ),
                "cpe": product.cpe,
                "ecosystem": _normalize_text(product.ecosystem),
                "product": _normalize_text(product.product),
                "vendor": _normalize_text(product.vendor),
            }
        )
    return sorted(canonical, key=lambda item: _canonical_json(item))


def _canonical_surface(
    surface: list[AttackSurfaceCharacteristic],
) -> list[dict]:
    canonical = []
    for item in surface:
        canonical.append(
            {
                "authentication": item.authentication,
                "browser_involved": item.browser_involved,
                "content_type": (
                    item.content_type.lower() if item.content_type else None
                ),
                "method": item.method,
                "parameter": item.parameter,
                "parameter_location": item.parameter_location,
                "path": item.path,
                "surface_kind": item.surface_kind,
            }
        )
    return sorted(canonical, key=lambda item: _canonical_json(item))


def _canonical_observables(
    observables: list[ObservableCharacteristic],
) -> list[dict]:
    canonical = []
    for item in observables:
        canonical.append(
            {
                "description": _normalize_text(item.description),
                "expected_value": item.expected_value,
                "observation_kind": item.observation_kind,
            }
        )
    return sorted(canonical, key=lambda item: _canonical_json(item))


def _canonical_version_constraints(
    constraints: list[VersionConstraint],
) -> list[dict]:
    canonical = []
    for item in constraints:
        canonical.append(
            {
                "constraint_kind": item.constraint_kind,
                "lower_inclusive": item.lower_inclusive,
                "raw": (
                    _normalize_text(item.raw) if item.raw else None
                ),
                "upper_inclusive": item.upper_inclusive,
                "upper_version": item.upper_version,
                "version": item.version,
            }
        )
    return sorted(canonical, key=lambda item: _canonical_json(item))


def _canonical_labels(values: list[str]) -> list[str]:
    return sorted(_normalize_text(value) for value in values)


def _canonical_provenance(
    provenance: ResearchProvenance,
) -> dict:
    return {
        "claim_ids": sorted(provenance.claim_ids),
        "knowledge_ids": sorted(provenance.knowledge_ids),
        "research_hashes": sorted(provenance.research_hashes),
        "source_ids": sorted(provenance.source_ids),
    }


def vulnerability_pattern_semantic_key(
    *,
    pattern_kind: str,
    facts: VulnerabilityFacts,
    schema_version: str = SCHEMA_VERSION,
) -> str:
    """Full SHA-256 over the provenance-free semantic basis.

    Binds schema version + kind + canonical grounded facts. Two
    models extracting the same normalized pattern from different
    research bases converge here; different product, version
    constraint, surface, observable, or identifier diverge.
    """

    canonical = {
        "facts": {
            "attack_surface": _canonical_surface(facts.attack_surface),
            "observables": _canonical_observables(facts.observables),
            "products": _canonical_products(facts.products),
            "required_conditions": _canonical_labels(
                facts.required_conditions
            ),
            "version_constraints": _canonical_version_constraints(
                facts.version_constraints
            ),
            "vulnerability_ids": sorted(facts.vulnerability_ids),
        },
        "pattern_kind": pattern_kind,
        "schema_version": schema_version,
    }
    return _sha256_hex(_canonical_json(canonical))


def attack_pattern_semantic_key(
    *,
    pattern_kind: str,
    facts: AttackFacts,
    schema_version: str = ATTACK_SCHEMA_VERSION,
) -> str:
    """Full SHA-256 over the provenance-free semantic basis.

    Binds schema version + kind + technique + canonical grounded
    facts. Different technique, input/sink characteristics,
    preconditions, technology context, or observables diverge.
    """

    canonical = {
        "facts": {
            "expected_observables": _canonical_observables(
                facts.expected_observables
            ),
            "input_characteristics": _canonical_labels(
                facts.input_characteristics
            ),
            "preconditions": _canonical_labels(facts.preconditions),
            "sink_characteristics": _canonical_labels(
                facts.sink_characteristics
            ),
            "technique": _normalize_text(facts.technique),
            "technology_context": _canonical_labels(
                facts.technology_context
            ),
        },
        "pattern_kind": pattern_kind,
        "schema_version": schema_version,
    }
    return _sha256_hex(_canonical_json(canonical))


def _idempotency_key_from_semantic(
    semantic_key: str,
    provenance: ResearchProvenance,
) -> str:
    """Full SHA-256 over semantic basis + sorted provenance basis.

    Same extraction from the same grounded claims is idempotent;
    the same pattern derived from a DIFFERENT provenance basis gets
    a distinct key (distinct research basis is semantically
    relevant). LLM metadata, severity, prose, timestamps, and
    status are excluded.
    """

    canonical = {
        "provenance": _canonical_provenance(provenance),
        "semantic_key": semantic_key,
    }
    return _sha256_hex(_canonical_json(canonical))


def vulnerability_pattern_id_from_key(key: str) -> str:
    return "vp-" + key[:16]


def attack_pattern_id_from_key(key: str) -> str:
    return "ap-" + key[:16]


# ------------------------------------------------------------------
# Contracts
# ------------------------------------------------------------------


class VulnerabilityPattern(BaseModel):
    """A normalized vulnerability pattern projected from grounded claims.

    Research-side intelligence only: it records what research claims
    (identifiers, affected products, version constraints, attack
    surface, required conditions, observable expectations) plus
    explicitly non-authoritative model interpretation. It does NOT
    decide target applicability (deterministic matcher later), does
    NOT grant scope or execution, and does NOT carry verdict or
    finding semantics. Lifecycle: ACTIVE → SUPERSEDED / RETIRED,
    where RETIRED means "research became obsolete", NEVER "a target
    was verified safe".
    """

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    idempotency_key: str
    semantic_key: str
    pattern_kind: ResearchPatternKind
    title: str
    description: str
    facts: VulnerabilityFacts
    provenance: ResearchProvenance
    interpretation: ModelInterpretation = Field(
        default_factory=ModelInterpretation
    )
    reported_severity: Literal[
        "UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    ] = "UNKNOWN"
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    status: PatternStatus = "ACTIVE"
    supersedes: str | None = None
    retirement_reason: str | None = None
    schema_version: Literal["vulnerability_pattern/v1"] = (
        "vulnerability_pattern/v1"
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    @field_validator("pattern_id")
    @classmethod
    def _vp_id(cls, value: str) -> str:
        if not _VP_ID_RE.match(value or ""):
            raise ValueError(f"invalid pattern_id: {value!r}")
        return value

    @field_validator("idempotency_key", "semantic_key")
    @classmethod
    def _keys(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid key: {value!r}")
        return value

    @field_validator("title", "description")
    @classmethod
    def _prose(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        if len(value) > 2048:
            raise ValueError("exceeds 2048 characters")
        return value

    @field_validator("cvss_vector")
    @classmethod
    def _vector(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _CVSS_VECTOR_RE.match(value):
            raise ValueError(
                f"malformed cvss_vector: {value!r}"
            )
        return value

    @field_validator("supersedes")
    @classmethod
    def _supersedes_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _VP_ID_RE.match(value):
            raise ValueError(f"invalid supersedes: {value!r}")
        return value

    @field_validator("retirement_reason")
    @classmethod
    def _retirement(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.strip():
            raise ValueError(
                "retirement_reason must be non-empty when present"
            )
        if len(value) > 512:
            raise ValueError(
                "retirement_reason exceeds 512 characters"
            )
        return value

    @model_validator(mode="after")
    def _consistency(self) -> "VulnerabilityPattern":
        if self.pattern_kind not in _VULNERABILITY_KINDS:
            raise ValueError(
                f"pattern_kind {self.pattern_kind!r} is not valid for "
                "VulnerabilityPattern"
            )
        if not (
            self.facts.vulnerability_ids or self.facts.products
        ):
            raise ValueError(
                "vulnerability pattern requires at least one "
                "vulnerability identifier or affected product"
            )
        if not self.provenance.claim_ids:
            raise ValueError(
                "patterns must be projected from grounded claims: "
                "provenance.claim_ids is required"
            )
        if self.status == "SUPERSEDED" and not self.supersedes:
            raise ValueError(
                "SUPERSEDED requires supersedes pattern_id"
            )
        if self.status == "RETIRED" and not (
            self.retirement_reason and self.retirement_reason.strip()
        ):
            raise ValueError(
                "RETIRED requires retirement_reason"
            )
        # Deterministic identity must be reproducible from the stored
        # basis (KnowledgeStore integrity convention): tampering with
        # keys without changing the basis fails closed.
        semantic = vulnerability_pattern_semantic_key(
            pattern_kind=self.pattern_kind,
            facts=self.facts,
            schema_version=self.schema_version,
        )
        if semantic != self.semantic_key:
            raise ValueError(
                "semantic_key does not match the pattern basis"
            )
        key = _idempotency_key_from_semantic(
            semantic, self.provenance
        )
        if key != self.idempotency_key:
            raise ValueError(
                "idempotency_key does not match the pattern basis"
            )
        if self.pattern_id != vulnerability_pattern_id_from_key(key):
            raise ValueError(
                "pattern_id must be the alias of idempotency_key"
            )
        return self


class AttackPattern(BaseModel):
    """A reusable attack technique pattern projected from grounded claims.

    Technique-level research intelligence independent of any single
    CVE: input/sink characteristics, preconditions, expected
    observables, and technology context, plus explicitly
    non-authoritative model interpretation. It contains NO exploit
    execution logic, NO verdict semantics, NO scope authority, and
    NO target-match authority. Lifecycle: ACTIVE → SUPERSEDED /
    RETIRED, where RETIRED means "the technique description became
    obsolete", NEVER "a target was verified safe".
    """

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    idempotency_key: str
    semantic_key: str
    pattern_kind: ResearchPatternKind
    title: str
    description: str
    facts: AttackFacts
    provenance: ResearchProvenance
    interpretation: ModelInterpretation = Field(
        default_factory=ModelInterpretation
    )
    status: PatternStatus = "ACTIVE"
    supersedes: str | None = None
    retirement_reason: str | None = None
    schema_version: Literal["attack_pattern/v1"] = "attack_pattern/v1"
    created_at: str = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    @field_validator("pattern_id")
    @classmethod
    def _ap_id(cls, value: str) -> str:
        if not _AP_ID_RE.match(value or ""):
            raise ValueError(f"invalid pattern_id: {value!r}")
        return value

    @field_validator("idempotency_key", "semantic_key")
    @classmethod
    def _keys(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid key: {value!r}")
        return value

    @field_validator("title", "description")
    @classmethod
    def _prose(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        if len(value) > 2048:
            raise ValueError("exceeds 2048 characters")
        return value

    @field_validator("supersedes")
    @classmethod
    def _supersedes_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _AP_ID_RE.match(value):
            raise ValueError(f"invalid supersedes: {value!r}")
        return value

    @field_validator("retirement_reason")
    @classmethod
    def _retirement(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.strip():
            raise ValueError(
                "retirement_reason must be non-empty when present"
            )
        if len(value) > 512:
            raise ValueError(
                "retirement_reason exceeds 512 characters"
            )
        return value

    @model_validator(mode="after")
    def _consistency(self) -> "AttackPattern":
        if self.pattern_kind not in _ATTACK_KINDS:
            raise ValueError(
                f"pattern_kind {self.pattern_kind!r} is not valid for "
                "AttackPattern"
            )
        if not (
            self.facts.sink_characteristics
            or self.facts.expected_observables
        ):
            raise ValueError(
                "attack pattern requires at least one sink "
                "characteristic or expected observable"
            )
        if not self.provenance.claim_ids:
            raise ValueError(
                "patterns must be projected from grounded claims: "
                "provenance.claim_ids is required"
            )
        if self.status == "SUPERSEDED" and not self.supersedes:
            raise ValueError(
                "SUPERSEDED requires supersedes pattern_id"
            )
        if self.status == "RETIRED" and not (
            self.retirement_reason and self.retirement_reason.strip()
        ):
            raise ValueError(
                "RETIRED requires retirement_reason"
            )
        semantic = attack_pattern_semantic_key(
            pattern_kind=self.pattern_kind,
            facts=self.facts,
            schema_version=self.schema_version,
        )
        if semantic != self.semantic_key:
            raise ValueError(
                "semantic_key does not match the pattern basis"
            )
        key = _idempotency_key_from_semantic(
            semantic, self.provenance
        )
        if key != self.idempotency_key:
            raise ValueError(
                "idempotency_key does not match the pattern basis"
            )
        if self.pattern_id != attack_pattern_id_from_key(key):
            raise ValueError(
                "pattern_id must be the alias of idempotency_key"
            )
        return self


# ------------------------------------------------------------------
# Deterministic factories
# ------------------------------------------------------------------


def build_vulnerability_pattern(
    *,
    pattern_kind: str,
    title: str,
    description: str,
    facts: VulnerabilityFacts | dict,
    provenance: ResearchProvenance,
    interpretation: ModelInterpretation | None = None,
    reported_severity: str = "UNKNOWN",
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
    created_at: str | None = None,
) -> VulnerabilityPattern:
    """Deterministic factory: same semantic basis + provenance → same id.

    Computes the semantic and idempotency keys from the canonical
    basis; LLM metadata and reported severity are recorded but never
    affect identity.
    """

    facts_obj = (
        VulnerabilityFacts.model_validate(facts)
        if isinstance(facts, dict)
        else facts
    )

    semantic = vulnerability_pattern_semantic_key(
        pattern_kind=pattern_kind,
        facts=facts_obj,
    )
    key = _idempotency_key_from_semantic(semantic, provenance)

    return VulnerabilityPattern(
        pattern_id=vulnerability_pattern_id_from_key(key),
        idempotency_key=key,
        semantic_key=semantic,
        pattern_kind=pattern_kind,  # type: ignore[arg-type]
        title=title,
        description=description,
        facts=facts_obj,
        provenance=provenance,
        interpretation=interpretation or ModelInterpretation(),
        reported_severity=reported_severity,  # type: ignore[arg-type]
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        **(
            {"created_at": created_at}
            if created_at is not None
            else {}
        ),
    )


def build_attack_pattern(
    *,
    pattern_kind: str,
    title: str,
    description: str,
    facts: AttackFacts | dict,
    provenance: ResearchProvenance,
    interpretation: ModelInterpretation | None = None,
    created_at: str | None = None,
) -> AttackPattern:
    """Deterministic factory: same semantic basis + provenance → same id."""

    facts_obj = (
        AttackFacts.model_validate(facts)
        if isinstance(facts, dict)
        else facts
    )

    semantic = attack_pattern_semantic_key(
        pattern_kind=pattern_kind,
        facts=facts_obj,
    )
    key = _idempotency_key_from_semantic(semantic, provenance)

    return AttackPattern(
        pattern_id=attack_pattern_id_from_key(key),
        idempotency_key=key,
        semantic_key=semantic,
        pattern_kind=pattern_kind,  # type: ignore[arg-type]
        title=title,
        description=description,
        facts=facts_obj,
        provenance=provenance,
        interpretation=interpretation or ModelInterpretation(),
        **(
            {"created_at": created_at}
            if created_at is not None
            else {}
        ),
    )


__all__ = [
    "ATTACK_SCHEMA_VERSION",
    "SCHEMA_VERSION",
    "AttackFacts",
    "AttackPattern",
    "AttackSurfaceCharacteristic",
    "ModelInterpretation",
    "ObservableCharacteristic",
    "PatternStatus",
    "ProductIdentity",
    "ResearchPatternKind",
    "VulnerabilityFacts",
    "VulnerabilityPattern",
    "VersionConstraint",
    "attack_pattern_id_from_key",
    "attack_pattern_semantic_key",
    "build_attack_pattern",
    "build_vulnerability_pattern",
    "vulnerability_pattern_id_from_key",
    "vulnerability_pattern_semantic_key",
]
