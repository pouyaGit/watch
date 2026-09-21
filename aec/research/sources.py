"""Read-only Watch-domain adapter (EPIC 6 Part 1+7).

Consumes existing Watch data shapes as plain mappings — backend code is
never imported. Normalization is verbatim-or-lowercase only: hosts are
lowercased, technology labels are lowercased/deduplicated/sorted, and
everything else passes through untouched. No category, severity,
technology, or version is ever inferred from names, paths, or text.

Classification (REAL_WATCH_DATA vs OFFLINE_FIXTURE) comes ONLY from the
caller's explicit origin argument: "watch" or "fixture". Anything else
is refused.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from aec.research.models import NormalizedRecord

ORIGIN_MODES = {
    "watch": "REAL_WATCH_DATA",
    "fixture": "OFFLINE_FIXTURE",
}


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _text_list(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def normalize_record(entry: Mapping[str, Any], origin: str) -> NormalizedRecord:
    """Normalize one record. Raises ValueError on bad input or origin."""
    if origin not in ORIGIN_MODES:
        raise ValueError(f"unknown origin: {origin!r}")
    if not isinstance(entry, Mapping):
        raise ValueError("record must be a mapping")
    host = _text(entry.get("subdomain") or entry.get("host")).strip().lower()
    if "endpoint" in entry:
        endpoint = _text(entry.get("endpoint")).strip()
    else:
        endpoint = _text(entry.get("url")).strip()
    if not host:
        raise ValueError("record missing host")
    if not endpoint:
        raise ValueError("record missing endpoint")
    technologies = tuple(sorted(
        {item.strip().lower() for item in _text_list(entry.get("technology"))
         if item.strip()}))
    versions = tuple(
        item for item in _text_list(entry.get("versions")) if item)
    observed = entry.get("last_update") or entry.get("observed_at")
    observed_at = observed if isinstance(observed, str) and observed \
        else "unstated"
    source = _text(entry.get("source")) or "unknown"
    source_id = (
        _text(entry.get("id"))
        or _text(entry.get("source_id"))
        or f"{host}{endpoint}"
    )
    mode = ORIGIN_MODES[origin]
    provenance = {
        "source": source,
        "source_id": source_id,
        "observed_at": observed_at,
        "normalization": "normalized",
        "classification": mode,
    }
    return NormalizedRecord(
        host=host,
        url=_text(entry.get("url")),
        endpoint=endpoint,
        parameter=_text(entry.get("parameter")),
        method=_text(entry.get("method")) or "GET",
        technologies=technologies,
        versions=versions,
        source_mode=mode,
        provenance=provenance,
    )


def normalize_batch(
    entries: Sequence[Mapping[str, Any]],
    origin: str,
    collect_refused: bool = False,
) -> Any:
    """Normalize many records. Refusals are raised, or collected."""
    if isinstance(entries, (str, bytes)) or not isinstance(entries, Sequence):
        raise ValueError("entries must be a sequence of mappings")
    if origin not in ORIGIN_MODES:
        raise ValueError(f"unknown origin: {origin!r}")
    records: list[NormalizedRecord] = []
    refused: list[dict[str, str]] = []
    for index, entry in enumerate(entries):
        try:
            records.append(normalize_record(entry, origin=origin))
        except ValueError as error:
            if not collect_refused:
                raise
            refused.append({"index": str(index), "reason": str(error)})
    if collect_refused:
        return records, refused
    return records


__all__ = ["ORIGIN_MODES", "normalize_batch", "normalize_record"]
