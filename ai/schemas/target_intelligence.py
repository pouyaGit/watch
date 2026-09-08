"""Target Intelligence data contracts (Phase 3A).

A TargetIntelligence object is a normalized, read-only snapshot of
what Watch already knows about one target (program + subdomain)
from its existing reconnaissance inventory. It is:

- NOT a security verdict and carries no CONFIRMED / VERIFIED /
  NOT_VULNERABLE / EXPLOITED semantics (no such value can exist on
  this contract).
- NOT a target match: it records observed inventory only. Whether
  a target is affected by a research pattern is decided later by
  the deterministic matcher, never here.
- NOT scope authority: ``scope_snapshot`` preserves scope strings
  exactly as stored in the recon inventory (observed data), and
  NEVER means "authorized for execution". No ``execution_allowed``
  / ``scope_allowed`` / ``authorized_target`` field exists.
  Execution must re-resolve scope through the canonical Watch
  scope policy (``ai/correlator/scope_policy.py``).
- NOT execution authority: no command, shell, subprocess, HTTP
  fetcher, browser, Nuclei, DNS, or tool-call field exists. A URL
  stored in the inventory is DATA and is never fetched.
- NOT evidence: observations describe what recon recorded; they
  never assert attacker-visible proof of anything.

Observation vs ground truth: every observation below is OBSERVED
INVENTORY, not ground truth about the remote target. If an HTTP
banner says ``nginx/1.24.0``, the projection preserves
``technology = nginx, observed_version = 1.24.0, source =
http_tech`` — this does NOT prove the deployed version. Version
comparison, affected/unaffected decisions, and pattern matching
are explicitly out of scope (future deterministic matcher).

Identity follows the Watch content-addressing convention: the
stable ``intelligence_id`` (``ti-`` + 16 hex) identifies the
target slot (program + subdomain + projection version) and does
NOT move when inventory changes; ``snapshot_hash`` (full SHA-256
over the canonical observations) identifies one observation state
so future consumers can detect staleness. Timestamps are audit
metadata only and are EXCLUDED from identity.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

PROJECTION_VERSION = "target_intelligence/v1"

_TI_ID_RE = re.compile(r"^ti-[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Same token shape as the Phase 2A VersionConstraint contract, so an
# observed version stays directly consumable by the future matcher.
# It is an OBSERVATION filter here, never a comparison input.
_VERSION_TOKEN_RE = re.compile(r"^[0-9][0-9A-Za-z.\-_+]{0,63}$")


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def target_key_for(program_name: str, subdomain: str) -> str:
    """Semantic target identity: program + canonical subdomain."""

    return _sha256_hex(f"{program_name}\n{subdomain}")


def intelligence_id_for(
    program_name: str,
    subdomain: str,
    projection_version: str = PROJECTION_VERSION,
) -> str:
    """Stable slot identity: same target always maps here."""

    return "ti-" + _sha256_hex(
        f"{projection_version}\n{program_name}\n{subdomain}"
    )[:16]


def snapshot_hash_for(canonical_observations: dict) -> str:
    """Snapshot identity over canonical (sorted) observations."""

    return _sha256_hex(_canonical_json(canonical_observations))


def _single_line(value: str, field_name: str, limit: int) -> str:
    if not value or not value.strip():
        raise ValueError(f"{field_name} must be non-empty")
    if len(value) > limit:
        raise ValueError(f"{field_name} exceeds {limit} characters")
    if "\n" in value or "\r" in value:
        raise ValueError(f"{field_name} must not contain newlines")
    return value


def _optional_line(value: str, field_name: str, limit: int) -> str:
    if not value:
        return value
    if len(value) > limit:
        raise ValueError(f"{field_name} exceeds {limit} characters")
    if "\n" in value or "\r" in value:
        raise ValueError(f"{field_name} must not contain newlines")
    return value


def _label_list(
    values: list[str], field_name: str, limit: int
) -> list[str]:
    for value in values:
        if not isinstance(value, str):
            raise ValueError(
                f"{field_name} entries must be strings"
            )
        if len(value) > limit:
            raise ValueError(
                f"{field_name} entry exceeds {limit} characters"
            )
        if "\n" in value or "\r" in value:
            raise ValueError(
                f"{field_name} entries must not contain newlines"
            )
    return values


class ScopeSnapshot(BaseModel):
    """Scope strings exactly as stored in recon inventory.

    OBSERVED DATA ONLY. These strings describe how inventory rows
    were labelled at write time (registrable-domain scope labels
    and program scope lists). They grant nothing and permit
    nothing; the executor-side scope policy remains the sole
    execution authority.
    """

    model_config = ConfigDict(extra="forbid")

    program_scopes: list[str] = Field(default_factory=list)
    program_ooscopes: list[str] = Field(default_factory=list)
    subdomain_scope: str = ""

    @field_validator("program_scopes", "program_ooscopes")
    @classmethod
    def _scope_lists(cls, values: list[str]) -> list[str]:
        return _label_list(values, "scope", 256)

    @field_validator("subdomain_scope")
    @classmethod
    def _scope(cls, value: str) -> str:
        return _optional_line(value, "scope", 256)


class TechnologyObservation(BaseModel):
    """One observed technology label from HTTP inventory.

    ``raw_label`` is the verbatim inventory string (e.g.
    ``nginx:1.24.0`` as reported by httpx tech-detect).
    ``observed_version`` is the version token parsed from that
    label when one is present, else None. Parsing is
    observation-preserving (same suffix shape the existing
    ``ai/correlator/technology.py`` normalizer documents), never
    inference: no version is guessed, compared, or judged.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    observed_version: str | None = None
    raw_label: str
    source: Literal["http_tech"] = "http_tech"
    record_ref: str

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return _single_line(value, "name", 256)

    @field_validator("raw_label")
    @classmethod
    def _raw(cls, value: str) -> str:
        return _single_line(value, "raw_label", 512)

    @field_validator("observed_version")
    @classmethod
    def _version(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _VERSION_TOKEN_RE.match(value):
            raise ValueError(
                f"malformed observed version token: {value!r}"
            )
        return value

    @field_validator("record_ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        return _single_line(value, "record_ref", 128)


class HttpObservation(BaseModel):
    """One HTTP inventory row, projected read-only.

    Header *names* only (sorted): header values can be large and
    are reachable through ``record_ref`` when an audit needs them.
    """

    model_config = ConfigDict(extra="forbid")

    record_ref: str
    url: str = ""
    final_url: str = ""
    status_code: int | None = None
    title: str = ""
    ips: list[str] = Field(default_factory=list)
    header_names: list[str] = Field(default_factory=list)

    @field_validator("record_ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        return _single_line(value, "record_ref", 128)

    @field_validator("url", "final_url")
    @classmethod
    def _urls(cls, value: str) -> str:
        return _optional_line(value, "url", 2048)

    @field_validator("title")
    @classmethod
    def _title(cls, value: str) -> str:
        return _optional_line(value, "title", 512)

    @field_validator("ips", "header_names")
    @classmethod
    def _labels(cls, values: list[str]) -> list[str]:
        return _label_list(values, "http label", 256)


class UrlObservation(BaseModel):
    """One crawled-URL inventory row: metadata only, never fetched."""

    model_config = ConfigDict(extra="forbid")

    record_ref: str
    url: str
    scheme: str
    host: str
    path: str
    params: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    status_code: int | None = None

    @field_validator("record_ref", "scheme", "host")
    @classmethod
    def _required(cls, value: str) -> str:
        return _single_line(value, "field", 256)

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return _single_line(value, "url", 2048)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return _single_line(value, "path", 2048)

    @field_validator("params", "sources")
    @classmethod
    def _labels(cls, values: list[str]) -> list[str]:
        return _label_list(values, "url label", 256)


class ParamDetail(BaseModel):
    """One parameter provenance record from endpoint inventory.

    Vocabulary mirrors the canonical ``param_records`` convention
    established at write time (``crawl/watch_param_discovery.py``:
    method ∈ {GET, POST, PUT, PATCH}, location ∈ {query, body},
    source ∈ {crawl, x8}). Unknown values fail closed at the
    projector boundary and never reach this contract.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    method: Literal["GET", "POST", "PUT", "PATCH"]
    location: Literal["query", "body"]
    source: Literal["crawl", "x8"]

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return _single_line(value, "name", 128)


class EndpointObservation(BaseModel):
    """One endpoint inventory row (path-level, already normalized
    at write time by ``database.normalize_path`` — the projector
    never re-normalizes paths). ``example_url`` is stored DATA for
    audit context; it is never fetched, resolved, or executed.
    """

    model_config = ConfigDict(extra="forbid")

    record_ref: str
    path: str
    example_url: str = ""
    params: list[str] = Field(default_factory=list)
    param_details: list[ParamDetail] = Field(default_factory=list)
    hit_count: int | None = None
    x8_checked: bool = False

    @field_validator("record_ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        return _single_line(value, "record_ref", 128)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return _single_line(value, "path", 2048)

    @field_validator("example_url")
    @classmethod
    def _example(cls, value: str) -> str:
        if not value:
            return value
        return _single_line(value, "example_url", 2048)

    @field_validator("params")
    @classmethod
    def _params(cls, values: list[str]) -> list[str]:
        return _label_list(values, "param", 128)


class SourceRefs(BaseModel):
    """Stable references back to the recon rows projected here."""

    model_config = ConfigDict(extra="forbid")

    program_record_id: str = ""
    subdomain_record_id: str = ""
    http_record_ids: list[str] = Field(default_factory=list)
    url_record_ids: list[str] = Field(default_factory=list)
    endpoint_record_ids: list[str] = Field(default_factory=list)

    @field_validator(
        "program_record_id", "subdomain_record_id"
    )
    @classmethod
    def _ids(cls, value: str) -> str:
        return _optional_line(value, "record id", 128)

    @field_validator(
        "http_record_ids", "url_record_ids", "endpoint_record_ids"
    )
    @classmethod
    def _ref_lists(cls, values: list[str]) -> list[str]:
        return _label_list(values, "record id", 128)


class TargetIntelligence(BaseModel):
    """Read-only intelligence for one program + subdomain target."""

    model_config = ConfigDict(extra="forbid")

    intelligence_id: str
    target_key: str
    program_name: str
    subdomain: str
    scope_snapshot: ScopeSnapshot = Field(
        default_factory=ScopeSnapshot
    )
    technologies: list[TechnologyObservation] = Field(
        default_factory=list
    )
    http_observations: list[HttpObservation] = Field(
        default_factory=list
    )
    url_observations: list[UrlObservation] = Field(
        default_factory=list
    )
    endpoint_observations: list[EndpointObservation] = Field(
        default_factory=list
    )
    source_refs: SourceRefs = Field(default_factory=SourceRefs)
    observed_at: str | None = None
    snapshot_hash: str
    projection_version: Literal["target_intelligence/v1"] = (
        "target_intelligence/v1"
    )

    @field_validator("intelligence_id")
    @classmethod
    def _ti_id(cls, value: str) -> str:
        if not _TI_ID_RE.match(value or ""):
            raise ValueError(f"invalid intelligence_id: {value!r}")
        return value

    @field_validator("target_key", "snapshot_hash")
    @classmethod
    def _keys(cls, value: str) -> str:
        if not _SHA256_RE.match(value or ""):
            raise ValueError(f"invalid key: {value!r}")
        return value

    @field_validator("program_name", "subdomain")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        if "\n" in value or "\r" in value:
            raise ValueError("must not contain newlines")
        return value


__all__ = [
    "PROJECTION_VERSION",
    "EndpointObservation",
    "HttpObservation",
    "ParamDetail",
    "ScopeSnapshot",
    "SourceRefs",
    "TargetIntelligence",
    "TechnologyObservation",
    "UrlObservation",
    "intelligence_id_for",
    "snapshot_hash_for",
    "target_key_for",
]
