"""Observed asset inventory schema (Stage R30.2).

An :class:`ObservedAssetInventory` is a deterministic, read-only projection of
what Watch *already observed* for one program — technologies, products,
components, plugins, versions, parameters and paths — each item carrying
explicit provenance (``source`` + ``evidence_type``).

Hard boundaries encoded here:

- Every collection holds :class:`ObservedItem` values with provenance. Nothing
  is inferred; if a persisted source does not establish a value, the category is
  simply empty.
- ``evidence_type`` is a closed vocabulary (EXPLICIT_FIELD, STRUCTURED_ENDPOINT,
  STRUCTURED_PARAMETER, STRUCTURED_TECHNOLOGY, STRUCTURED_COMPONENT,
  INFERRED_COMPONENT, INFERRED_PLUGIN). Stage R31.2 adds the two INFERRED_*
  types for values produced by anchored, deterministic path rules
  (``ai/knowledge/component_inference.py``); GUESSED / LLM_DERIVED / bare
  INFERRED values are still never allowed.
- No raw target URL / IP / hostname field exists. ``paths`` are path-only
  (already normalized at write time). ``generated_from`` holds record counts.
- ``inventory_id`` is deterministic from rule_version + program.
- ``rule_version`` is fixed to ``r30-2``; ``research_only`` is forced ``True``;
  unknown fields are rejected (``extra="forbid"``).
- Stage R30.3 adds ``version_associations``: observed versions paired with the
  *explicit* owning technology family and (only when a structured source
  establishes it) the owning component/plugin. An association is never inferred
  from URLs, hostnames, parameters, keywords, CVE text or LLM output; the
  component stays empty (unavailable) when no structured source exists.
- Stage R31.5 adds ``component_provenance`` (canonical evidence path + owning
  scope for inferred components/plugins, path-only) and ``parameter_paths``
  (parameter -> path-only endpoint linkage). Both are additive and never
  replace or reinterpret explicit observations.

No I/O, no network, no LLM, no execution of any kind is represented here.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

OBSERVED_INVENTORY_RULE_VERSION = "r30-2"

# Stage R30.3 association layer (additive; the R30.2 inventory shape is
# unchanged). Association semantics are documented in
# ``ai/knowledge/version_component_association.py``.
VERSION_ASSOCIATION_RULE_VERSION = "r30-3"

# Stage R31.5 evidence-provenance layer (additive): inferred component/plugin
# observations keep their canonical evidence path and owning scope as
# structured, path-only data so the backend adapter can distinguish
# explicit vs inferred evidence and scope supporting paths/parameters.
EVIDENCE_PROVENANCE_RULE_VERSION = "r31-5"

# Closed evidence-type vocabulary. R31.2 permits only the two anchored,
# deterministic INFERRED_* rule types; guessed/LLM-derived values are never
# allowed.
EVIDENCE_TYPES: tuple[str, ...] = (
    "EXPLICIT_FIELD",
    "STRUCTURED_ENDPOINT",
    "STRUCTURED_PARAMETER",
    "STRUCTURED_TECHNOLOGY",
    "STRUCTURED_COMPONENT",
    "INFERRED_COMPONENT",
    "INFERRED_PLUGIN",
)

# Closed source vocabulary (existing Watch inventory sources only).
INVENTORY_SOURCES: tuple[str, ...] = (
    "ASSET_INVENTORY",
    "TECHNOLOGY_INVENTORY",
    "COMPONENT_INVENTORY",
    "PARAMETER_INVENTORY",
    "ENDPOINT_INVENTORY",
)

INVENTORY_ID_PREFIX = "inv-"
INVENTORY_ID_RE = re.compile(r"^inv-[0-9a-f]{16}$")
PROGRAM_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

MAX_ITEMS = 2000
MAX_VALUE_LEN = 512
MAX_EVIDENCE = 256


def inventory_id_for(
    program: str,
    rule_version: str = OBSERVED_INVENTORY_RULE_VERSION,
) -> str:
    """Deterministic inventory id from rule_version + program."""

    basis = "\n".join([str(rule_version or ""), str(program or "")])
    return INVENTORY_ID_PREFIX + hashlib.sha256(
        basis.encode("utf-8")
    ).hexdigest()[:16]


class ObservedItem(BaseModel):
    """One observed inventory value with explicit provenance."""

    model_config = ConfigDict(extra="forbid")

    value: str
    source: str
    evidence_type: str

    @field_validator("value")
    @classmethod
    def _valid_value(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("observed inventory value must be non-empty")
        return text[:MAX_VALUE_LEN]

    @field_validator("source")
    @classmethod
    def _valid_source(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in INVENTORY_SOURCES:
            raise ValueError(f"invalid inventory source: {value!r}")
        return text

    @field_validator("evidence_type")
    @classmethod
    def _valid_evidence_type(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in EVIDENCE_TYPES:
            raise ValueError(f"invalid evidence_type: {value!r}")
        return text


class ObservedVersionAssociation(BaseModel):
    """One observed version paired with its *explicit* owning identity.

    ``technology_family`` is the observed technology/product that owns the
    version (e.g. ``WordPress`` for the persisted ``WordPress:6.8.3``
    Http.tech label). ``component`` is the owning component/plugin and stays
    empty (unavailable) unless a structured source establishes it. Neither
    value is ever inferred from URLs, hostnames, parameter names, keywords,
    CVE description text or LLM output.

    The schema is additive to Stage R30.2 (``ObservedItem`` is unchanged).
    """

    model_config = ConfigDict(extra="forbid")

    version: str
    technology_family: str = ""
    component: str = ""
    source: str = "TECHNOLOGY_INVENTORY"
    evidence_type: str = "STRUCTURED_TECHNOLOGY"

    @field_validator("version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("observed version must be non-empty")
        return text[:MAX_VALUE_LEN]

    @field_validator("technology_family", "component")
    @classmethod
    def _bounded_owner(cls, value: str) -> str:
        text = str(value or "").strip()
        return text[:MAX_VALUE_LEN]

    @field_validator("source")
    @classmethod
    def _valid_source(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in INVENTORY_SOURCES:
            raise ValueError(f"invalid inventory source: {value!r}")
        return text

    @field_validator("evidence_type")
    @classmethod
    def _valid_evidence_type(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in EVIDENCE_TYPES:
            raise ValueError(f"invalid evidence_type: {value!r}")
        return text


def _path_only(value: object) -> str:
    """Deterministic path-only sanitizer (no scheme/host/query/fragment)."""

    text = str(value if value is not None else "")
    text = re.sub(r"[\r\n]+", " ", text).strip()
    if not text:
        return ""
    if "://" in text or text.startswith("//"):
        try:
            text = urlsplit(text).path or ""
        except ValueError:
            return ""
    text = text.split("?", 1)[0].split("#", 1)[0].strip()
    if not text:
        return ""
    if not text.startswith("/"):
        text = "/" + text
    return text[:MAX_VALUE_LEN]


class ObservedProvenance(BaseModel):
    """Structured provenance for one *inferred* component/plugin value.

    Records the canonical evidence path and the owning directory scope as
    path-only strings (no scheme, host, query, fragment or target identifier).
    Explicit observations do not need this structure: their provenance is the
    item's ``source``/``evidence_type``. Inferred path retention is additive to
    Stage R30.2/R31.2 and never replaces an explicit observation.
    """

    model_config = ConfigDict(extra="forbid")

    value: str
    category: str
    evidence_type: str
    evidence_path: str
    scope_path: str = ""
    rule_id: str = ""
    source: str = "COMPONENT_INVENTORY"

    @field_validator("value")
    @classmethod
    def _valid_value(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("provenance value must be non-empty")
        return text[:MAX_VALUE_LEN]

    @field_validator("category")
    @classmethod
    def _valid_category(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in ("COMPONENT", "PLUGIN"):
            raise ValueError(f"invalid provenance category: {value!r}")
        return text

    @field_validator("evidence_type")
    @classmethod
    def _valid_evidence_type(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in ("INFERRED_COMPONENT", "INFERRED_PLUGIN"):
            raise ValueError(f"invalid inferred evidence_type: {value!r}")
        return text

    @field_validator("evidence_path")
    @classmethod
    def _valid_evidence_path(cls, value: str) -> str:
        text = _path_only(value)
        if not text:
            raise ValueError("provenance evidence_path must be non-empty")
        return text

    @field_validator("scope_path")
    @classmethod
    def _valid_scope_path(cls, value: str) -> str:
        return _path_only(value)

    @field_validator("rule_id")
    @classmethod
    def _bounded_rule_id(cls, value: str) -> str:
        return str(value or "").strip()[:MAX_VALUE_LEN]

    @field_validator("source")
    @classmethod
    def _valid_source(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in INVENTORY_SOURCES:
            raise ValueError(f"invalid inventory source: {value!r}")
        return text


class ObservedParameterPath(BaseModel):
    """One observed parameter and the path-only endpoint that carries it.

    Additive R31.5 linkage used to decide whether a parameter is inside an
    inferred component's owning scope. ``path`` is path-only.
    """

    model_config = ConfigDict(extra="forbid")

    parameter: str
    path: str
    source: str = "PARAMETER_INVENTORY"

    @field_validator("parameter")
    @classmethod
    def _valid_parameter(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("parameter-path parameter must be non-empty")
        return text[:MAX_VALUE_LEN]

    @field_validator("path")
    @classmethod
    def _valid_path(cls, value: str) -> str:
        text = _path_only(value)
        if not text:
            raise ValueError("parameter-path path must be non-empty")
        return text

    @field_validator("source")
    @classmethod
    def _valid_source(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        if text not in INVENTORY_SOURCES:
            raise ValueError(f"invalid inventory source: {value!r}")
        return text


def _bounded_items(value: list) -> list[ObservedItem]:
    out: list[ObservedItem] = []
    seen: set[tuple[str, str, str]] = set()
    for item in value or ():
        if not isinstance(item, ObservedItem):
            item = ObservedItem(**item)
        key = (item.value, item.source, item.evidence_type)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_ITEMS:
            break
    return out


def _bounded_associations(value: list) -> list[ObservedVersionAssociation]:
    out: list[ObservedVersionAssociation] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for item in value or ():
        if not isinstance(item, ObservedVersionAssociation):
            item = ObservedVersionAssociation(**item)
        key = (
            item.version,
            item.technology_family,
            item.component,
            item.source,
            item.evidence_type,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_ITEMS:
            break
    return out


def _bounded_provenance(value: list) -> list[ObservedProvenance]:
    out: list[ObservedProvenance] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for item in value or ():
        if not isinstance(item, ObservedProvenance):
            item = ObservedProvenance(**item)
        key = (
            item.category,
            item.value,
            item.evidence_type,
            item.evidence_path,
            item.scope_path,
            item.rule_id,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_ITEMS:
            break
    return out


def _bounded_parameter_paths(value: list) -> list[ObservedParameterPath]:
    out: list[ObservedParameterPath] = []
    seen: set[tuple[str, str]] = set()
    for item in value or ():
        if not isinstance(item, ObservedParameterPath):
            item = ObservedParameterPath(**item)
        key = (item.parameter, item.path)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_ITEMS:
            break
    return out


class ObservedAssetInventory(BaseModel):
    """Read-only observed inventory for one program (research-only)."""

    model_config = ConfigDict(extra="forbid")

    inventory_id: str
    program: str

    technologies: list[ObservedItem] = Field(default_factory=list)
    products: list[ObservedItem] = Field(default_factory=list)
    components: list[ObservedItem] = Field(default_factory=list)
    plugins: list[ObservedItem] = Field(default_factory=list)
    versions: list[ObservedItem] = Field(default_factory=list)
    parameters: list[ObservedItem] = Field(default_factory=list)
    paths: list[ObservedItem] = Field(default_factory=list)

    # Stage R30.3 additive: observed version -> owning family/component pairs.
    # Defaults to empty (unassociated) when no structured owner exists.
    version_associations: list[ObservedVersionAssociation] = Field(
        default_factory=list
    )

    # Stage R31.5 additive: structured provenance for inferred
    # components/plugins (canonical evidence path + owning scope), and the
    # parameter -> path-only endpoint linkage used for component-scoped
    # support decisions.
    component_provenance: list[ObservedProvenance] = Field(
        default_factory=list
    )
    parameter_paths: list[ObservedParameterPath] = Field(
        default_factory=list
    )

    sources: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    generated_from: dict = Field(default_factory=dict)

    rule_version: str = OBSERVED_INVENTORY_RULE_VERSION
    research_only: bool = True

    @field_validator("inventory_id")
    @classmethod
    def _valid_inventory_id(cls, value: str) -> str:
        text = str(value or "").strip()
        if not INVENTORY_ID_RE.match(text):
            raise ValueError(f"malformed inventory_id: {value!r}")
        return text

    @field_validator("program")
    @classmethod
    def _valid_program(cls, value: str) -> str:
        text = str(value or "").strip()
        if not PROGRAM_RE.match(text):
            raise ValueError(f"malformed program: {value!r}")
        return text

    @field_validator(
        "technologies", "products", "components", "plugins", "versions",
        "parameters", "paths", mode="before",
    )
    @classmethod
    def _valid_collections(cls, value: list) -> list[ObservedItem]:
        return _bounded_items(value)

    @field_validator("version_associations", mode="before")
    @classmethod
    def _valid_version_associations(
        cls, value: list
    ) -> list[ObservedVersionAssociation]:
        return _bounded_associations(value)

    @field_validator("component_provenance", mode="before")
    @classmethod
    def _valid_component_provenance(
        cls, value: list
    ) -> list[ObservedProvenance]:
        return _bounded_provenance(value)

    @field_validator("parameter_paths", mode="before")
    @classmethod
    def _valid_parameter_paths(
        cls, value: list
    ) -> list[ObservedParameterPath]:
        return _bounded_parameter_paths(value)

    @field_validator("sources")
    @classmethod
    def _valid_sources(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = str(item or "").strip().upper()
            if text in INVENTORY_SOURCES and text not in out:
                out.append(text)
        return sorted(out)

    @field_validator("evidence")
    @classmethod
    def _bounded_evidence(cls, value: list) -> list[str]:
        out: list[str] = []
        for item in value or ():
            text = str(item or "").strip()[:MAX_VALUE_LEN]
            if text and text not in out:
                out.append(text)
            if len(out) >= MAX_EVIDENCE:
                break
        return out

    @field_validator("rule_version")
    @classmethod
    def _fixed_rule(cls, value: str) -> str:
        return OBSERVED_INVENTORY_RULE_VERSION

    @field_validator("research_only")
    @classmethod
    def _research_only(cls, value: bool) -> bool:
        if not value:
            raise ValueError("observed inventory is research-only")
        return True


def observed_item_values(items: object) -> list[str]:
    """Deterministic value list for one inventory category.

    Accepts :class:`ObservedItem` models or serialized dicts.
    """

    values: list[str] = []
    for item in items or ():
        if isinstance(item, ObservedItem):
            value = item.value
        elif isinstance(item, dict):
            value = str(item.get("value") or "")
        else:
            value = str(getattr(item, "value", "") or "")
        if value and value not in values:
            values.append(value)
    return values


def inventory_projection(value: ObservedAssetInventory) -> dict:
    """Serialize one observed inventory deterministically."""

    return value.model_dump(mode="json")
