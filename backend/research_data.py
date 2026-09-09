"""
backend/research_data.py — Read-only data access for the research track.

Single place for all research-artifact filesystem logic. Backs the
read-only router ``backend/routers/research.py`` with small, capped,
metadata-first loaders over:

- ``ai_data/research/<CVE>.cli.json``
- ``ai_data/knowledge/`` (via the existing KnowledgeStore readback)
- ``ai_data/research/xss/xss-*.json``
- ``ai_data/reports/<CVE>.md``
- ``ai_data/nuclei/{generated,results,findings}`` (counts only)

READ-ONLY: no writes, no Mongo writes, no network, no subprocess, no
LLM, no Nuclei execution, no production verifier. Deterministic
ordering everywhere; missing values are omitted, never invented.
Path security: ids validated against fixed regexes and every
constructed path is resolved under its fixed base directory.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_DIR = PROJECT_ROOT / "ai_data" / "research"
REPORTS_DIR = PROJECT_ROOT / "ai_data" / "reports"
XSS_DIR = PROJECT_ROOT / "ai_data" / "research" / "xss"
XSS_LLM_DIR = XSS_DIR / "llm"
NUCLEI_DIRS = {
    "generated": PROJECT_ROOT / "ai_data" / "nuclei" / "generated",
    "results": PROJECT_ROOT / "ai_data" / "nuclei" / "results",
    "findings": PROJECT_ROOT / "ai_data" / "nuclei" / "findings",
}

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
XSS_ID_RE = re.compile(r"^xss-[0-9a-f]{16}$")
KB_ID_RE = re.compile(r"^kb-[0-9a-f]{16}$")

DEFAULT_LIMIT = 50
MAX_LIMIT = 100


class ResearchDataError(ValueError):
    """Client-fixable input problem (router maps to 400/404)."""


class NotFoundError(ResearchDataError):
    """Requested artifact does not exist (router maps to 404)."""


def clamp_limit(limit: int) -> int:
    """Clamp a user-supplied limit to [1, MAX_LIMIT] (never unbounded)."""
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_LIMIT
    return min(max(limit, 1), MAX_LIMIT)


def normalize_cve(cve: str) -> str:
    """Validate a CVE id; raise ResearchDataError on malformed input."""
    text = (cve or "").strip()
    if not CVE_RE.match(text):
        raise ResearchDataError(f"malformed CVE id: {cve!r}")
    return text


def normalize_xss_id(candidate_id: str) -> str:
    """Validate an XSS candidate id (prevents path traversal)."""
    text = (candidate_id or "").strip()
    if not XSS_ID_RE.match(text):
        raise ResearchDataError(f"malformed candidate id: {candidate_id!r}")
    return text


def normalize_kb_id(knowledge_id: str) -> str:
    """Validate a KB short id (prevents path traversal)."""
    text = (knowledge_id or "").strip()
    if not KB_ID_RE.match(text):
        raise ResearchDataError(f"malformed knowledge id: {knowledge_id!r}")
    return text


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise NotFoundError(str(path.name)) from None
    except (OSError, ValueError) as exc:
        raise ResearchDataError(f"unreadable artifact {path.name}") from exc


def _resolved_under(path: Path, base: Path) -> Path:
    resolved = path.resolve()
    if not str(resolved).startswith(str(base.resolve()) + "/"):
        raise ResearchDataError("path escaped its base directory")
    return resolved


def _confined(base: Path, *parts: str) -> Path:
    return _resolved_under(base / Path(*parts), base)


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def severity_bucket(value: Any) -> str:
    """Whitelisted severity token from a persisted severity string.

    Returns one of critical/high/medium/low/unknown — never invented:
    the classification is a substring match over the persisted text.
    """
    text = str(value or "").strip().lower()
    if not text:
        return "unknown"
    for bucket in ("critical", "high", "medium", "moderate", "low"):
        if bucket in text:
            return "moderate" if bucket == "moderate" else bucket
    return "unknown"


# ---------------------------------------------------------------------------
# Research (CVE cli.json)
# ---------------------------------------------------------------------------

_RESEARCH_STRIP_FIELDS = (
    "evidence",
    "detection_ideas",
    "attack_requirements",
    "impact",
)


def _extract_cwe(vulnerability_type: Any) -> str | None:
    match = re.search(r"CWE-\d+", str(vulnerability_type or ""))
    return match.group(0) if match else None


def _extract_paths(research: dict) -> list[str]:
    corpus = "\n".join(
        [
            str(research.get("title") or ""),
            str(research.get("summary") or ""),
            str(research.get("root_cause") or ""),
            *(_as_list(research.get("attack_requirements"))),
            *(_as_list(research.get("detection_ideas"))),
            *(_as_list(research.get("evidence"))),
        ]
    )
    paths = sorted(
        {
            m.group(0)
            for m in re.finditer(
                r"/[\w.\-]+(?:/[\w.\-]+)+(?:\.php)?|/[\w.\-]+\.\w{2,5}", corpus
            )
            if len(m.group(0)) > 2
        }
    )
    return paths[:20]


def _research_payload(cve: str) -> tuple[dict, Path]:
    path = _confined(RESEARCH_DIR, f"{cve}.cli.json")
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ResearchDataError(f"invalid research artifact {path.name}")
    return payload, path


def research_record_from(payload: dict, cve: str) -> dict:
    """Compact list-record for one research payload (explicit fields only)."""
    cve_block = payload.get("cve", {}) if isinstance(payload.get("cve"), dict) else {}
    metadata = (
        payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
    )
    research = (
        payload.get("research", {}) if isinstance(payload.get("research"), dict) else {}
    )
    endpoints = _extract_paths(research)
    record = {
        "cve": cve,
        "title": _first_text(research.get("title")),
        "generated_at": _first_text(payload.get("generated_at")),
        "research_version": _first_text(payload.get("research_version")),
        "cvss_score": cve_block.get("cvss_score"),
        "cvss_vector": cve_block.get("cvss_vector"),
        "severity": _first_text(research.get("severity")),
        "cwe": _extract_cwe(research.get("vulnerability_type")),
        "products": _as_list(research.get("affected_products"))
        or _as_list(cve_block.get("products")),
        "versions": _as_list(research.get("affected_versions")),
        "vulnerability_type": _first_text(research.get("vulnerability_type")),
        "endpoint": endpoints[0] if endpoints else None,
        "endpoints": endpoints,
        "parameters": sorted(
            {
                m.group(1)
                for m in re.finditer(
                    r"""['\"]([A-Za-z_][\w-]*)['\"]\s+parameter""",
                    "\n".join(
                        [
                            str(research.get("summary") or ""),
                            str(research.get("root_cause") or ""),
                            *(_as_list(research.get("evidence"))),
                        ]
                    ),
                )
            }
        ),
        "authentication": _first_text(
            *[
                item
                for item in research.get("attack_requirements") or []
                if "auth" in str(item).lower()
            ]
        ),
        "public_exploit": research.get("public_exploit"),
        "research_status": payload.get("research_status"),
        "llm_status": payload.get("llm_status"),
        "authoritative": payload.get("authoritative"),
        "nuclei_decision": research.get("nuclei_decision"),
        "nuclei_candidate": research.get("nuclei_candidate"),
        "assets": _as_list(metadata.get("assets")),
        "programs": _as_list(metadata.get("programs")),
        "technologies": _as_list(metadata.get("technologies")),
    }
    return record


def list_research(
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    q: str | None = None,
    cve: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    sort: str = "cve",
    direction: str = "asc",
) -> dict:
    """Capped, deterministic research list (no evidence bodies)."""
    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    needle = (q or "").strip().lower()
    cve_filter = (cve or "").strip().lower()
    sev_f = (severity or "").strip().lower()
    status_f = (status or "").strip().lower()
    entries = []
    if RESEARCH_DIR.exists():
        paths = sorted(
            p
            for p in RESEARCH_DIR.glob("*.cli.json")
            if CVE_RE.match(p.name[:-9])
        )
        for path in paths:
            cve_id = path.name[:-9]
            if cve_filter and cve_filter not in cve_id.lower():
                continue
            try:
                payload, _ = _research_payload(cve_id)
            except (ResearchDataError, NotFoundError):
                continue
            record = research_record_from(payload, cve_id)
            if needle and not any(
                needle in str(record.get(k) or "").lower()
                for k in ("cve", "title")
            ) and not any(
                needle in str(p).lower()
                for p in (record.get("products") or [])
            ):
                continue
            if sev_f:
                bucket = severity_bucket(record.get("severity"))
                if sev_f in ("unknown", "none", "n/a", "-"):
                    if bucket != "unknown":
                        continue
                elif bucket != sev_f:
                    continue
            if status_f and status_f not in str(
                record.get("research_status") or ""
            ).lower():
                continue
            entries.append(record)
    desc = str(direction).lower() in ("desc", "descending", "-1")

    def _cve_key(r):
        return r["cve"]

    def _title_key(r):
        return str(r.get("title") or "").lower(), r["cve"]

    if sort == "cvss":
        present = [r for r in entries if isinstance(r.get("cvss_score"), (int, float))]
        missing = [r for r in entries if not isinstance(r.get("cvss_score"), (int, float))]
        # asc = lowest score first; missing values always sort last.
        present.sort(key=lambda r: (r["cvss_score"], r["cve"]), reverse=desc)
        entries = present + missing
    elif sort == "title":
        present = [r for r in entries if str(r.get("title") or "").strip()]
        missing = [r for r in entries if not str(r.get("title") or "").strip()]
        present.sort(key=_title_key, reverse=desc)
        entries = present + missing
    elif sort == "updated":
        # persisted generated_at is ISO-8601: lexicographic order == time order
        present = [r for r in entries if str(r.get("generated_at") or "").strip()]
        missing = [r for r in entries if not str(r.get("generated_at") or "").strip()]
        present.sort(key=lambda r: (str(r["generated_at"]), r["cve"]), reverse=desc)
        entries = present + missing
    else:  # cve (default)
        entries.sort(key=_cve_key, reverse=desc)
    total = len(entries)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": entries[offset : offset + limit],
    }


def research_stats() -> dict:
    """Aggregate severity/status/nuclei-candidate counts over all research
    artifacts. Cached for 10s (same TTL as get_overview) so a research-list
    render does not re-parse the whole corpus on every request."""
    now = _time.monotonic()
    hit = _OVERVIEW_CACHE.get("research_stats")
    if hit and (now - hit[0]) < _OVERVIEW_TTL:
        return hit[1]
    by_sev: dict[str, int] = {}
    by_status: dict[str, int] = {}
    total = 0
    nuclei_candidates = 0
    public_exploits = 0
    if RESEARCH_DIR.exists():
        for path in sorted(RESEARCH_DIR.glob("*.cli.json")):
            cve_id = path.name[:-9]
            if not CVE_RE.match(cve_id):
                continue
            try:
                payload, _ = _research_payload(cve_id)
            except (ResearchDataError, NotFoundError):
                continue
            record = research_record_from(payload, cve_id)
            total += 1
            sev = severity_bucket(record.get("severity"))
            by_sev[sev] = by_sev.get(sev, 0) + 1
            st = str(record.get("research_status") or "unknown").lower()
            by_status[st] = by_status.get(st, 0) + 1
            if record.get("nuclei_candidate") is True:
                nuclei_candidates += 1
            if record.get("public_exploit") is True:
                public_exploits += 1
    value = {
        "total": total,
        "severity": dict(sorted(by_sev.items())),
        "status": dict(sorted(by_status.items())),
        "nuclei_candidates": nuclei_candidates,
        "public_exploits": public_exploits,
    }
    _OVERVIEW_CACHE["research_stats"] = (now, value)
    return value


def get_research(cve: str) -> dict:
    """Full useful persisted research structure (no execution, no fetch)."""
    cve = normalize_cve(cve)
    payload, path = _research_payload(cve)
    record = research_record_from(payload, cve)
    research = (
        payload.get("research", {}) if isinstance(payload.get("research"), dict) else {}
    )
    detail = dict(record)
    metadata = (
        payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
    )
    detail["summary"] = _first_text(research.get("summary"))
    detail["root_cause"] = _first_text(research.get("root_cause"))
    detail["impact"] = _as_list(research.get("impact"))
    detail["attack_requirements"] = _as_list(research.get("attack_requirements"))
    detail["evidence"] = _as_list(research.get("evidence"))
    detail["detection_ideas"] = _as_list(research.get("detection_ideas"))
    detail["nuclei_reason"] = _first_text(research.get("nuclei_reason"))
    detail["bug_bounty_relevance"] = research.get("bug_bounty_relevance")
    detail["references"] = _as_list(research.get("references"))
    detail["assessment_count"] = metadata.get("assessment_count")
    detail["discovered_source_count"] = metadata.get("discovered_source_count")
    detail["fetched_source_count"] = metadata.get("fetched_source_count")
    detail["artifact"] = path.name
    return detail


# ---------------------------------------------------------------------------
# Knowledge Base (read-only KnowledgeStore access, metadata-first)
# ---------------------------------------------------------------------------

_KB_ROOT = PROJECT_ROOT / "ai_data" / "knowledge"


def _kb_store(root=None):
    from ai.knowledge.store import KnowledgeStore

    return KnowledgeStore(root_dir=str(root) if root is not None else str(_KB_ROOT))


def _kb_meta(doc) -> dict:
    values = lambda items: [i.value for i in (items or [])]
    get = lambda name, default=None: getattr(doc, name, default)
    return {
        "knowledge_id": get("knowledge_id"),
        "title": get("title"),
        "source_url": get("source_url"),
        "source_type": get("source_type"),
        "summary": get("summary"),
        "tags": list(get("tags") or []),
        "technologies": values(get("aggregate").technologies) if get("aggregate") else list(get("technologies") or []),
        "xss_types": values(get("aggregate").xss_types) if get("aggregate") else list(get("xss_types") or []),
        "contexts": values(get("aggregate").contexts) if get("aggregate") else list(get("contexts") or []),
        "confidence": get("confidence"),
        "evidence_quality": get("evidence_quality"),
        "indexed_at": str(get("indexed_at")) if get("indexed_at") else None,
        "published_at": str(get("published_at")) if get("published_at") else None,
    }


def list_kb(
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    q: str | None = None,
    cve: str | None = None,
    tag: str | None = None,
) -> dict:
    """Capped, deterministic KB metadata list (no content bodies)."""
    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    needle = (q or "").strip().lower()
    cve_filter = (cve or "").strip().lower()
    tag_filter = (tag or "").strip().lower()
    try:
        docs = _kb_store().retrieve()
    except (OSError, ValueError):
        raise ResearchDataError("knowledge store unavailable")
    entries = []
    for doc in docs:
        meta = _kb_meta(doc)
        haystack = " ".join(
            [
                str(meta.get("title") or ""),
                str(meta.get("summary") or ""),
                str(meta.get("source_url") or ""),
                " ".join(meta.get("tags") or []),
            ]
        ).lower()
        if needle and needle not in haystack:
            continue
        if tag_filter and not any(tag_filter in str(t).lower() for t in (meta.get("tags") or [])):
            continue
        if cve_filter and cve_filter not in haystack:
            continue
        entries.append(meta)
    entries.sort(key=lambda r: str(r.get("knowledge_id") or ""))
    total = len(entries)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": entries[offset : offset + limit],
    }


def get_kb(knowledge_id: str) -> dict:
    """KB document metadata + content + provenance (read-only)."""
    knowledge_id = normalize_kb_id(knowledge_id)
    try:
        doc = _kb_store().get_by_id(knowledge_id)
    except (OSError, ValueError) as exc:
        raise ResearchDataError("knowledge store unavailable") from exc
    if doc is None:
        raise NotFoundError(knowledge_id)
    meta = _kb_meta(doc)
    meta["content"] = getattr(doc, "content", "")
    try:
        provenance = [p.model_dump(mode="json") for p in (getattr(doc, "provenance", None) or [])]
    except Exception:
        provenance = []
    meta["provenance"] = provenance
    return meta


# ---------------------------------------------------------------------------
# XSS candidates (persisted ai_data/research/xss/xss-*.json only)
# ---------------------------------------------------------------------------

_XSS_KIND = "research_candidate"
_XSS_DISCLAIMER = (
    "Research candidates only — NOT production findings. "
    "No live testing was performed and no target was contacted. "
    "Test ideas were never executed."
)


def _xss_payload(candidate_id: str) -> tuple[dict, Path]:
    path = _confined(XSS_DIR, f"{candidate_id}.json")
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ResearchDataError(f"invalid XSS artifact {path.name}")
    return payload, path


def _xss_top_evidence(payload: dict) -> str | None:
    evidence = payload.get("source_evidence")
    if not isinstance(evidence, list):
        return None
    best = None
    for item in evidence:
        if not isinstance(item, dict):
            continue
        title = _first_text(item.get("title"))
        if not title:
            continue
        score = item.get("score")
        rank = score if isinstance(score, (int, float)) else 0
        if best is None or rank > best[0]:
            best = (rank, title)
    return best[1] if best else None


def _xss_compact(payload: dict) -> dict:
    return {
        "candidate_id": payload.get("candidate_id"),
        "kind": _XSS_KIND,
        "status": payload.get("status"),
        "xss_type": payload.get("xss_type"),
        "context": payload.get("context", payload.get("injection_context")),
        "injection_context": payload.get("injection_context", payload.get("context")),
        "confidence": payload.get("confidence"),
        "query": payload.get("query"),
        "vulnerability_pattern": payload.get("vulnerability_pattern"),
        "top_evidence": _xss_top_evidence(payload),
        "technologies": _as_list(payload.get("technologies")),
        "disclaimer": payload.get("disclaimer", _XSS_DISCLAIMER),
    }


def list_xss(
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    status: str | None = None,
    xss_type: str | None = None,
    context: str | None = None,
    q: str | None = None,
) -> dict:
    """Capped, deterministic XSS candidate list (compact records)."""
    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    status_f = (status or "").strip().lower()
    type_f = (xss_type or "").strip().lower()
    ctx_f = (context or "").strip().lower()
    needle = (q or "").strip().lower()
    entries = []
    if XSS_DIR.exists():
        for path in sorted(XSS_DIR.glob("xss-*.json")):
            stem = path.stem
            if not XSS_ID_RE.match(stem):
                continue
            try:
                payload, _ = _xss_payload(stem)
            except (ResearchDataError, NotFoundError):
                continue
            record = _xss_compact(payload)
            if status_f and status_f != str(record.get("status") or "").lower():
                continue
            if type_f and type_f != str(record.get("xss_type") or "").lower():
                continue
            ctx_val = str(record.get("context") or record.get("injection_context") or "").lower()
            if ctx_f and ctx_f != ctx_val:
                continue
            if needle and needle not in " ".join(
                [
                    str(record.get("candidate_id") or ""),
                    str(record.get("query") or ""),
                    str(record.get("vulnerability_pattern") or ""),
                ]
            ).lower():
                continue
            entries.append(record)
    entries.sort(key=lambda r: str(r.get("candidate_id") or ""))
    total = len(entries)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": entries[offset : offset + limit],
    }


def get_xss(candidate_id: str) -> dict:
    """Full XSS candidate: evidence/reasons/sinks/test idea/KB refs/disclaimer."""
    candidate_id = normalize_xss_id(candidate_id)
    payload, path = _xss_payload(candidate_id)
    detail = dict(payload)
    detail["kind"] = _XSS_KIND
    detail["is_finding"] = False
    if not detail.get("disclaimer"):
        detail["disclaimer"] = _XSS_DISCLAIMER
    detail["artifact"] = path.name
    return detail


# ---------------------------------------------------------------------------
# XSS LLM research (persisted ai_data/research/xss/llm/<candidate_id>.json)
# ---------------------------------------------------------------------------
#
# Stage R7 persists one optional LLM research record per deterministic
# candidate under ``XSS_LLM_DIR``. This layer is strictly read-only:
# no writes, no provider calls, no subprocess, no network. The record is
# returned verbatim (plus kind/disclaimer markers); the deterministic
# candidate remains authoritative for status/confidence.


def _xss_llm_payload(candidate_id: str) -> tuple[dict, Path]:
    path = _confined(XSS_LLM_DIR, f"{candidate_id}.json")
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ResearchDataError(f"invalid XSS LLM research artifact {path.name}")
    return payload, path


def has_xss_llm_research(candidate_id: str) -> bool:
    """Cheap existence check for the confined LLM research artifact."""
    try:
        candidate_id = normalize_xss_id(candidate_id)
        return _confined(XSS_LLM_DIR, f"{candidate_id}.json").exists()
    except ResearchDataError:
        return False


def get_xss_llm_research(candidate_id: str) -> dict:
    """Return the persisted R7 LLM research record for one candidate.

    Raises NotFoundError when no LLM research was generated for this
    candidate, ResearchDataError on malformed ids/artifacts. Never
    invokes a provider and never writes.
    """
    candidate_id = normalize_xss_id(candidate_id)
    payload, path = _xss_llm_payload(candidate_id)
    if payload.get("candidate_id") not in (None, candidate_id):
        raise ResearchDataError(
            f"candidate id mismatch in LLM research artifact {path.name}"
        )
    detail = dict(payload)
    detail["kind"] = "llm_research"
    detail["is_finding"] = False
    detail["verified"] = False
    detail["artifact"] = path.name
    return detail


# ---------------------------------------------------------------------------
# Reports (ai_data/reports/<CVE>.md, raw Markdown only)
# ---------------------------------------------------------------------------


def list_reports(
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    q: str | None = None,
    cve: str | None = None,
) -> dict:
    """Capped, deterministic report list (metadata only, never bodies)."""
    limit = clamp_limit(limit)
    offset = max(int(offset or 0), 0)
    needle = (q or cve or "").strip().lower()
    entries = []
    if REPORTS_DIR.exists():
        for path in sorted(REPORTS_DIR.glob("*.md")):
            stem = path.stem
            if not CVE_RE.match(stem):
                continue
            if needle and needle not in stem.lower():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            entries.append({"cve": stem, "artifact": path.name, "size_bytes": size})
    entries.sort(key=lambda r: r["cve"])
    total = len(entries)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": entries[offset : offset + limit],
    }


def get_report(cve: str) -> dict:
    """Return CVE + raw Markdown (no HTML rendering, no |safe)."""
    cve = normalize_cve(cve)
    path = _confined(REPORTS_DIR, f"{cve}.md")
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise NotFoundError(cve) from None
    except OSError as exc:
        raise ResearchDataError(f"unreadable report {path.name}") from exc
    return {"cve": cve, "artifact": path.name, "markdown": text, "size_bytes": len(text.encode("utf-8"))}


def has_report(cve: str) -> bool:
    """Cheap existence check for the confined report artifact."""
    try:
        cve = normalize_cve(cve)
        return _confined(REPORTS_DIR, f"{cve}.md").exists()
    except ResearchDataError:
        return False


# ---------------------------------------------------------------------------
# Nuclei artifact summaries (read-only persisted files; nothing executed)
# ---------------------------------------------------------------------------

_TEMPLATE_ID_RE = re.compile(r"^id:\s*(.+?)\s*$", re.M)
_TEMPLATE_SEV_RE = re.compile(r"^\s*severity:\s*(.+?)\s*$", re.M)


def nuclei_summary(cve: str) -> dict:
    """Deterministic read-only summary of persisted Nuclei artifacts for one
    CVE (template metadata + validation decision). Never executes anything."""
    cve = normalize_cve(cve)
    out: dict[str, Any] = {
        "cve": cve,
        "template": None,
        "results": None,
        "findings": None,
    }
    gen = NUCLEI_DIRS["generated"]
    try:
        template_path = _confined(gen, f"{cve}.yaml")
    except ResearchDataError:
        template_path = None
    if template_path is not None and template_path.exists():
        try:
            text = template_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        info: dict[str, Any] = {"name": template_path.name}
        m = _TEMPLATE_ID_RE.search(text)
        if m:
            info["id"] = m.group(1).strip().strip("'\"")
        m = _TEMPLATE_SEV_RE.search(text)
        if m:
            info["severity"] = m.group(1).strip().strip("'\"")
        out["template"] = info
    res_dir = NUCLEI_DIRS["results"]
    try:
        results_path = _confined(res_dir, f"{cve}.json")
    except ResearchDataError:
        results_path = None
    if results_path is not None and results_path.exists():
        payload = _read_json(results_path)
        if isinstance(payload, dict):
            summary = {"name": results_path.name}
            for key in ("decision", "semantic_valid", "nuclei_valid"):
                if key in payload:
                    summary[key] = payload.get(key)
            runs = payload.get("run_results")
            if isinstance(runs, list):
                summary["run_result_count"] = len(runs)
            findings = payload.get("findings")
            if isinstance(findings, list):
                summary["finding_count"] = len(findings)
            out["results"] = summary
    fin_dir = NUCLEI_DIRS["findings"]
    try:
        findings_path = _confined(fin_dir, f"{cve}.json")
    except ResearchDataError:
        findings_path = None
    if findings_path is not None and findings_path.exists():
        payload = _read_json(findings_path)
        count = len(payload) if isinstance(payload, list) else None
        out["findings"] = {"name": findings_path.name, "record_count": count}
    return out


# ---------------------------------------------------------------------------
# Overview (cheap counts, 10s cache like dashboard.py)
# ---------------------------------------------------------------------------

import time as _time

_OVERVIEW_TTL = 10.0
_OVERVIEW_CACHE: dict = {}


def _count_files(directory: Path, pattern: str) -> int:
    try:
        if not directory.exists():
            return 0
        return sum(1 for _ in directory.glob(pattern))
    except OSError:
        return 0


def get_overview() -> dict:
    """Deterministic cheap counts across research/KB/XSS/reports/nuclei."""
    now = _time.monotonic()
    hit = _OVERVIEW_CACHE.get("overview")
    if hit and (now - hit[0]) < _OVERVIEW_TTL:
        return hit[1]
    # KB count from the index (cheap, no document reads).
    kb_count = 0
    try:
        index_path = _KB_ROOT / "index.json"
        if index_path.exists():
            docs = json.loads(index_path.read_text(encoding="utf-8")).get("documents", {})
            kb_count = len(docs) if isinstance(docs, dict) else 0
    except (OSError, ValueError):
        kb_count = 0
    xss_by_status: dict[str, int] = {}
    xss_total = 0
    if XSS_DIR.exists():
        for path in sorted(XSS_DIR.glob("xss-*.json")):
            if not XSS_ID_RE.match(path.stem):
                continue
            xss_total += 1
            try:
                status = str(json.loads(path.read_text(encoding="utf-8")).get("status", "UNKNOWN"))
            except (OSError, ValueError):
                status = "UNKNOWN"
            xss_by_status[status] = xss_by_status.get(status, 0) + 1
    reports_count = _count_files(REPORTS_DIR, "*.md")
    # Reuse the cached research-stats pass for the persisted candidate flags
    # (nuclei_candidate / public_exploit are real fields of the cli.json).
    stats = research_stats()
    value = {
        "research_cves": stats["total"],
        "kb_documents": kb_count,
        "xss_candidates": xss_total,
        "xss_by_status": dict(sorted(xss_by_status.items())),
        "reports": reports_count,
        "nuclei_candidates": stats.get("nuclei_candidates", 0),
        "public_exploit_cves": stats.get("public_exploits", 0),
        "nuclei": {
            name: _count_files(path, "*")
            for name, path in sorted(NUCLEI_DIRS.items())
        },
    }
    _OVERVIEW_CACHE["overview"] = (now, value)
    return value
