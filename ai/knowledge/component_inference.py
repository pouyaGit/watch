"""Stage R31.2 deterministic component/plugin inference (pure engine).

Infers component/plugin observations from *already-persisted* URL and endpoint
paths using an isolated, versioned rule table. This is the only inference the
observed inventory allows: every rule is anchored to a well-known technology
path convention (e.g. ``/wp-content/plugins/<slug>/``) and produces an existing
schema :class:`~ai.schemas.observed_inventory.ObservedItem` with an explicit
``INFERRED_COMPONENT`` / ``INFERRED_PLUGIN`` evidence type.

Hard boundaries encoded here:

- Pure and offline: no I/O, no network, no DNS, no LLM, no subprocess, no
  browser, no Nuclei, no target interaction, no persistence, no execution.
- Only the *path* portion of an input record is used. Schemes, hostnames,
  query strings, parameter names and page keywords are never evidence and
  never appear in output values.
- No fuzzy/guess matching: a value is either a fixed canonical name or a
  single path segment validated against a strict slug shape and captured by an
  anchored rule. Arbitrary strings, ``..``, percent-encoding and whitespace
  are rejected.
- Rules live only in :data:`RULES` and are individually identified by
  ``rule_id``; new rules can be added without touching the inventory loader or
  the observed inventory builders.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ai.correlator.technology import normalize as normalize_technology
from ai.schemas.observed_inventory import (
    ObservedAssetInventory,
    ObservedItem,
)

RULE_VERSION = "r31-2"

CATEGORY_COMPONENT = "component"
CATEGORY_PLUGIN = "plugin"

EVIDENCE_COMPONENT = "INFERRED_COMPONENT"
EVIDENCE_PLUGIN = "INFERRED_PLUGIN"

SOURCE_COMPONENT = "COMPONENT_INVENTORY"

MAX_ITEMS = 2000
MAX_EVIDENCE = 256
MAX_PATH_LEN = 2048
MAX_PATHS = 20000

_SINGLE_LINE_RE = re.compile(r"[\r\n]+")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")


@dataclass(frozen=True)
class InferenceRule:
    """One anchored path -> component/plugin rule.

    ``fixed_value`` rules emit a canonical component name (CKEditor); rules
    without it must capture a ``value`` group that is validated as a path
    segment before it can become an observation.
    """

    rule_id: str
    category: str
    evidence_type: str
    pattern: re.Pattern
    fixed_value: str = ""


# Isolated, ordered, extendable rule table. Patterns are anchored to known
# technology path layouts (case-insensitive) and match path boundaries only.
RULES: tuple[InferenceRule, ...] = (
    InferenceRule(
        "wordpress-plugin",
        CATEGORY_PLUGIN,
        EVIDENCE_PLUGIN,
        re.compile(
            r"(?:^|/)wp-content/plugins/(?P<value>[^/]+)(?:/|$)", re.I
        ),
    ),
    InferenceRule(
        "wordpress-mu-plugin",
        CATEGORY_PLUGIN,
        EVIDENCE_PLUGIN,
        re.compile(
            r"(?:^|/)wp-content/mu-plugins/(?P<value>[^/]+)(?:/|$)", re.I
        ),
    ),
    InferenceRule(
        "wordpress-theme",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(
            r"(?:^|/)wp-content/themes/(?P<value>[^/]+)(?:/|$)", re.I
        ),
    ),
    InferenceRule(
        "ckeditor",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(r"(?:^|/)ckeditor(?:/|$)", re.I),
        fixed_value="CKEditor",
    ),
    InferenceRule(
        "fckeditor",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(r"(?:^|/)fckeditor(?:/|$)", re.I),
        fixed_value="FCKeditor",
    ),
    InferenceRule(
        "ckfinder",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(r"(?:^|/)ckfinder(?:/|$)", re.I),
        fixed_value="CKFinder",
    ),
    InferenceRule(
        "tinymce",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(r"(?:^|/)tinymce(?:/|$)", re.I),
        fixed_value="TinyMCE",
    ),
    InferenceRule(
        "drupal-module-sites",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(
            r"(?:^|/)sites/(?:all|default)/modules/(?P<value>[^/]+)"
            r"(?:/|$)",
            re.I,
        ),
    ),
    InferenceRule(
        "drupal-module-contrib",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(r"(?:^|/)modules/contrib/(?P<value>[^/]+)(?:/|$)", re.I),
    ),
    InferenceRule(
        "joomla-component",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(r"(?:^|/)components/(?P<value>com_[A-Za-z0-9_\-]+)(?:/|$)",
                   re.I),
    ),
    InferenceRule(
        "joomla-module",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(r"(?:^|/)modules/(?P<value>mod_[A-Za-z0-9_\-]+)(?:/|$)",
                   re.I),
    ),
    InferenceRule(
        "jquery-asset",
        CATEGORY_COMPONENT,
        EVIDENCE_COMPONENT,
        re.compile(
            r"(?:^|/)jquery(?:[-.][0-9][A-Za-z0-9.\-]*)?(?:\.min)?\.js$",
            re.I,
        ),
        fixed_value="jQuery",
    ),
)


# ---------------------------------------------------------------------------
# Path extraction (path only; host/scheme/query are never used)
# ---------------------------------------------------------------------------


def _clean_path(value: object) -> str:
    text = str(value if value is not None else "")
    text = _SINGLE_LINE_RE.sub(" ", text).strip()
    if not text:
        return ""
    if "://" in text or text.startswith("//"):
        try:
            parsed = urlsplit(text)
        except ValueError:
            return ""
        text = parsed.path or ""
    text = text.split("?", 1)[0].split("#", 1)[0].strip()
    if not text:
        return ""
    if not text.startswith("/"):
        text = "/" + text
    return text[:MAX_PATH_LEN]


def _record_value(record: object, key: str) -> object:
    if isinstance(record, dict):
        return record.get(key)
    return getattr(record, key, None)


def _path_from_record(record: object) -> str:
    """Best-effort path from a URL/endpoint/HTTP record (fail-soft)."""

    if record is None:
        return ""
    for key in ("path", "example_url", "url", "final_url"):
        text = _clean_path(_record_value(record, key))
        if text:
            return text
    return ""


def _collect_paths(records: object) -> list[str]:
    paths: set[str] = set()
    for record in records or ():
        path = _path_from_record(record)
        if path:
            paths.add(path)
    return sorted(paths)


# ---------------------------------------------------------------------------
# Rule application
# ---------------------------------------------------------------------------


def _valid_segment(value: str) -> bool:
    if not value or value in (".", ".."):
        return False
    if "%" in value or " " in value:
        return False
    return bool(_SEGMENT_RE.match(value))


def _observed_item(value: str, evidence_type: str) -> ObservedItem | None:
    try:
        return ObservedItem(
            value=value,
            source=SOURCE_COMPONENT,
            evidence_type=evidence_type,
        )
    except ValueError:
        return None


def _matched_value(rule: InferenceRule, match: re.Match) -> str:
    if rule.fixed_value:
        return rule.fixed_value
    return str(match.group("value") or "").strip()


def infer_inventory_items(
    *,
    url_records: object = (),
    endpoint_records: object = (),
    http_records: object = (),
) -> dict:
    """Infer components/plugins from persisted paths (pure, deterministic).

    Returns ``{"components": [ObservedItem, ...], "plugins": [...],
    "evidence": [str, ...]}``. Every emitted item carries
    ``source=COMPONENT_INVENTORY`` and an ``INFERRED_COMPONENT`` /
    ``INFERRED_PLUGIN`` evidence type. Input order never affects the output.
    """

    paths = sorted(
        set(_collect_paths(endpoint_records))
        | set(_collect_paths(url_records))
        | set(_collect_paths(http_records))
    )[:MAX_PATHS]

    values: dict[str, dict[str, str]] = {
        CATEGORY_COMPONENT: {},
        CATEGORY_PLUGIN: {},
    }
    evidence: list[str] = []
    for path in paths:
        for rule in RULES:
            match = rule.pattern.search(path)
            if match is None:
                continue
            value = _matched_value(rule, match)
            if not value:
                continue
            if not rule.fixed_value and not _valid_segment(value):
                continue
            key = normalize_technology(value)
            if not key:
                continue
            bucket = values[rule.category]
            if key in bucket:
                continue
            bucket[key] = value
            evidence.append(
                f"{rule.category} {value!r} inferred from path {path!r} "
                f"(rule {rule.rule_id})"
            )

    def _build(category: str, evidence_type: str) -> list[ObservedItem]:
        out: list[ObservedItem] = []
        for key in sorted(values[category]):
            item = _observed_item(values[category][key], evidence_type)
            if item is not None:
                out.append(item)
            if len(out) >= MAX_ITEMS:
                break
        return out

    components = _build(CATEGORY_COMPONENT, EVIDENCE_COMPONENT)
    plugins = _build(CATEGORY_PLUGIN, EVIDENCE_PLUGIN)

    return {
        "components": components,
        "plugins": plugins,
        "evidence": sorted({line for line in evidence if line})[
            :MAX_EVIDENCE
        ],
    }


# ---------------------------------------------------------------------------
# Inventory merge (additive; existing categories are preserved verbatim)
# ---------------------------------------------------------------------------


def apply_inferred_items(
    inventory: ObservedAssetInventory,
    inferred: object,
) -> ObservedAssetInventory:
    """Merge inferred components/plugins into an observed inventory.

    Explicit items always win: an inferred value whose normalized key already
    exists in the category is dropped. Technologies, products, versions,
    version associations, parameters and paths are copied unchanged. Returns
    the same object when nothing new is inferred.
    """

    data = inferred if isinstance(inferred, dict) else {}
    inferred_components = list(data.get("components") or ())
    inferred_plugins = list(data.get("plugins") or ())
    if not inferred_components and not inferred_plugins:
        return inventory

    existing_components = {
        normalize_technology(item.value) for item in inventory.components
    }
    existing_plugins = {
        normalize_technology(item.value) for item in inventory.plugins
    }
    new_components = [
        item
        for item in inferred_components
        if normalize_technology(item.value) not in existing_components
    ]
    new_plugins = [
        item
        for item in inferred_plugins
        if normalize_technology(item.value) not in existing_plugins
    ]
    if not new_components and not new_plugins:
        return inventory

    evidence = list(inventory.evidence)
    for line in data.get("evidence") or ():
        text = str(line or "").strip()
        if text and text not in evidence:
            evidence.append(text)

    sources = sorted(
        set(inventory.sources) | {SOURCE_COMPONENT}
    )
    generated_from = dict(inventory.generated_from)
    generated_from["component_inference_rule_version"] = RULE_VERSION
    generated_from["inferred_components"] = len(new_components)
    generated_from["inferred_plugins"] = len(new_plugins)

    return ObservedAssetInventory(
        inventory_id=inventory.inventory_id,
        program=inventory.program,
        technologies=inventory.technologies,
        products=inventory.products,
        components=list(inventory.components) + new_components,
        plugins=list(inventory.plugins) + new_plugins,
        versions=inventory.versions,
        version_associations=inventory.version_associations,
        parameters=inventory.parameters,
        paths=inventory.paths,
        sources=sources,
        evidence=evidence,
        generated_from=generated_from,
    )


__all__ = [
    "RULE_VERSION",
    "CATEGORY_COMPONENT",
    "CATEGORY_PLUGIN",
    "EVIDENCE_COMPONENT",
    "EVIDENCE_PLUGIN",
    "SOURCE_COMPONENT",
    "InferenceRule",
    "RULES",
    "infer_inventory_items",
    "apply_inferred_items",
]
