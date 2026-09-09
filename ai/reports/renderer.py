"""Deterministic read-only Markdown research report renderer (Stage R2).

Consumes ONLY already-persisted local artifacts:

- ``ai_data/research/<CVE>.cli.json``
- ``ai_data/research/<CVE>.references.json`` (optional)
- existing KnowledgeStore contents (read-only ``retrieve()``)
- existing Nuclei generated/results/findings artifacts (optional)

Produces:

- ``ai_data/reports/<CVE>.md``

Safety properties (enforced by construction):

- No network calls (no sockets, no ``urllib``/``requests``, no subprocess).
- No LLM calls (no ``ai.llm`` / provider imports).
- No Nuclei execution (never invokes a runner, never spawns processes).
- No production verification/materialization (no 5B-5J imports, no Mongo,
  no finding creation, no alerts).
- No timestamps generated at render time; stable ordering everywhere;
  same persisted inputs produce byte-identical Markdown.

This module is import-light on purpose: only the standard library plus
``ai.knowledge.store.KnowledgeStore`` (local JSON readback, imported lazily
inside :func:`build_report_for_cve` so static import scans stay clean).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


class ReportError(ValueError):
    """Raised when a report cannot be rendered deterministically."""


# ---------------------------------------------------------------------------
# Centralized deterministic filesystem paths (cwd-relative, like the CLI).
# ---------------------------------------------------------------------------

RESEARCH_DIR = Path("ai_data/research")
REPORTS_DIR = Path("ai_data/reports")
NUCLEI_GENERATED_DIR = Path("ai_data/nuclei/generated")
NUCLEI_RESULTS_DIR = Path("ai_data/nuclei/results")
NUCLEI_FINDINGS_DIR = Path("ai_data/nuclei/findings")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

UNKNOWN = "Unknown"

# Cap on KB matches rendered (deterministic truncation with a note).
KB_MATCH_LIMIT = 20


# ---------------------------------------------------------------------------
# Markdown sanitization for untrusted persisted text.
#
# Persisted reference titles/URLs and research strings are untrusted input.
# They must never alter the report structure (headings, tables, links,
# code fences). Strategy:
#
# - single-line fields: collapse newlines/CRs to spaces (this alone
#   neutralizes heading/list/block injections, which all require a line
#   break), strip control chars, escape the remaining structural
#   metacharacters (code spans, emphasis, links, tables, HTML);
# - URLs: only http(s) schemes are rendered, always inside code spans;
#   anything else renders as an "invalid URL" literal;
# - fenced code blocks are never emitted around untrusted text, so no
#   fence can be broken out of.
# ---------------------------------------------------------------------------

_MD_ESCAPE_RE = re.compile(r"([\\`*_\[\]|<>])")


def esc_inline(value: Any) -> str:
    """Escape untrusted text for safe inline Markdown rendering."""
    text = "" if value is None else str(value)
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = text.strip()
    if not text:
        return UNKNOWN
    return _MD_ESCAPE_RE.sub(r"\\\1", text)


def esc_cell(value: Any) -> str:
    """Escape untrusted text for a Markdown table cell (no pipes/newlines)."""
    text = esc_inline(value)
    return text.replace("|", "\\|")


def esc_url(value: Any) -> str:
    """Render an untrusted URL as a code span; reject non-http(s) schemes."""
    text = "" if value is None else str(value).strip()
    text = re.sub(r"[\x00-\x20\x7f]", "", text)
    if re.match(r"^https?://[^\s`<>]+$", text):
        return f"`{text}`"
    if not text:
        return UNKNOWN
    return f"invalid URL: `{esc_inline(text)}`"


# ---------------------------------------------------------------------------
# Loading helpers (read-only, fail-soft for optional artifacts).
# ---------------------------------------------------------------------------


def _validate_cve_id(cve_id: str) -> str:
    normalized = (cve_id or "").strip()
    if not CVE_RE.match(normalized):
        raise ReportError(f"invalid CVE id: {cve_id!r}")
    return normalized


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise ReportError(f"invalid JSON artifact: {path}: {exc}") from exc


def _load_research(cve_id: str, research_dir: Path) -> dict:
    path = research_dir / f"{cve_id}.cli.json"
    if not path.exists():
        raise ReportError(
            f"missing CVE research JSON: {path} "
            "(run `research --cve` first; report rendering is read-only "
            "and never fetches data)"
        )
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ReportError(f"invalid CVE research JSON (not an object): {path}")
    return payload


def _load_references(
    cve_id: str, research_dir: Path
) -> tuple[list[dict] | None, str | None]:
    """Return (records, note). ``None`` records means the archive is absent."""
    path = research_dir / f"{cve_id}.references.json"
    if not path.exists():
        return None, path.as_posix()
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ReportError(f"invalid references archive (not an object): {path}")
    records = payload.get("records", [])
    if not isinstance(records, list):
        raise ReportError(f"invalid references archive (records not a list): {path}")
    cleaned = [r for r in records if isinstance(r, dict)]
    # Stable order: by source_url.
    cleaned.sort(key=lambda r: str(r.get("source_url") or ""))
    return cleaned, None


def _load_kb_documents(store: Any) -> list[Any]:
    try:
        documents = store.retrieve()
    except ValueError as exc:
        raise ReportError(f"knowledge-store readback failed: {exc}") from exc
    return sorted(
        list(documents or []), key=lambda d: str(getattr(d, "knowledge_id", ""))
    )


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Field extraction helpers (persisted data only, no inference beyond
# quoting/keywording what the artifacts already state).
# ---------------------------------------------------------------------------


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _extract_cwe(vulnerability_type: Any) -> str | None:
    match = re.search(r"CWE-\d+", str(vulnerability_type or ""))
    return match.group(0) if match else None


def _auth_requirement(research: dict) -> str | None:
    """Quote the persisted stance on authentication, or None if unstated."""
    haystacks = _as_list(research.get("attack_requirements"))
    haystacks += _as_list(research.get("evidence"))
    root = _first_text(research.get("root_cause"))
    if root:
        haystacks.append(root)
    unauth = any(
        re.search(
            r"un-authenticated|unauthenticated|no authentication|"
            r"without authentication|PR:N",
            h,
            re.I,
        )
        for h in haystacks
    )
    auth = any(
        re.search(
            r"\bauthenticated\b|requires authentication|low-privilege|"
            r"PR:L|privileges required",
            h,
            re.I,
        )
        for h in haystacks
    )
    if unauth and not auth:
        return "Unauthenticated (as stated in persisted research)"
    if auth and not unauth:
        return "Authenticated (as stated in persisted research)"
    if unauth and auth:
        return "Mixed statements in persisted research (see evidence)"
    return None


def _extract_paths_and_params(research: dict) -> tuple[list[str], list[str]]:
    """Collect endpoint paths / parameter names mentioned in persisted text."""
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
    # Only multi-segment paths (/a/b) or file-like paths (/a.ext) count;
    # bare single words after "/" (e.g. "/Nuclei" in prose) are noise.
    paths = sorted(
        {
            m.group(0)
            for m in re.finditer(
                r"/[\w.\-]+(?:/[\w.\-]+)+(?:\.php)?|/[\w.\-]+\.\w{2,5}", corpus
            )
            if len(m.group(0)) > 2
        }
    )
    params: set[str] = set()
    for m in re.finditer(r"""['"]([A-Za-z_][\w\-]*)['"]\s+parameter""", corpus):
        params.add(m.group(1))
    for m in re.finditer(r"""parameter\s+['"]([A-Za-z_][\w\-]*)['"]""", corpus):
        params.add(m.group(1))
    for m in re.finditer(r"[?&]([A-Za-z_][\w\-]*)=", corpus):
        params.add(m.group(1))
    return paths[:20], sorted(params)[:20]


def _kb_keywords(research: dict, cve: dict) -> set[str]:
    tokens: set[str] = set()

    def add(text: Any) -> None:
        for word in re.findall(r"[A-Za-z0-9]{4,}", str(text or "")):
            tokens.add(word.lower())

    add(cve.get("id"))
    for key in ("vendor", "products"):
        for item in _as_list(cve.get(key)):
            add(item)
    for key in ("title", "summary", "vulnerability_type", "root_cause"):
        add(research.get(key))
    for item in _as_list(research.get("affected_products")):
        add(item)
    return tokens


def _kb_match(doc: Any, keywords: set[str], cve_id: str) -> set[str]:
    haystack = " ".join(
        [
            str(getattr(doc, "title", "") or ""),
            str(getattr(doc, "summary", "") or ""),
            str(getattr(doc, "content", "") or ""),
            " ".join(str(t) for t in (getattr(doc, "tags", None) or [])),
            " ".join(str(t) for t in (getattr(doc, "technologies", None) or [])),
        ]
    ).lower()
    if cve_id.lower() in haystack:
        return {cve_id.lower()}
    words = set(re.findall(r"[a-z0-9]{4,}", haystack))
    return keywords.intersection(words)


def _template_identity(template_text: str | None) -> str | None:
    if not template_text:
        return None
    match = re.search(r"^id:\s*(.+?)\s*$", template_text, re.M)
    return match.group(1).strip().strip("'\"") if match else None


def _template_severity(template_text: str | None) -> str | None:
    if not template_text:
        return None
    match = re.search(r"^\s*severity:\s*(.+?)\s*$", template_text, re.M)
    return match.group(1).strip().strip("'\"") if match else None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fmt_bool(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return UNKNOWN


def _summarize_statuses(items: list[dict], key: str) -> str:
    counts: dict[str, int] = {}
    for item in items:
        if isinstance(item, dict):
            key_value = str(item.get(key, "UNKNOWN"))
            counts[key_value] = counts.get(key_value, 0) + 1
    if not counts:
        return UNKNOWN
    return "; ".join(f"{k}={v}" for k, v in sorted(counts.items()))


# ---------------------------------------------------------------------------
# Section renderers. Each returns Markdown text; missing data renders as
# explicit "Not available"/"Unknown" states, never as invented content.
# ---------------------------------------------------------------------------


def _render_summary(cve_id: str, payload: dict) -> str:
    cve = payload.get("cve", {}) if isinstance(payload.get("cve"), dict) else {}
    research = (
        payload.get("research", {}) if isinstance(payload.get("research"), dict) else {}
    )
    lines = ["## 1. CVE / Research Summary", ""]
    cwe = _extract_cwe(research.get("vulnerability_type"))
    cvss_score = cve.get("cvss_score")
    cvss_vector = cve.get("cvss_vector")
    if cvss_score is None and cvss_vector is None:
        cvss = UNKNOWN
    else:
        cvss = f"{cvss_score if cvss_score is not None else UNKNOWN}"
        if cvss_vector:
            cvss += f" ({cvss_vector})"
    if "public_exploit" in research:
        exploit = _fmt_bool(research.get("public_exploit"))
        if research.get("actively_exploited") is not None:
            exploit += f" / actively exploited: {_fmt_bool(research.get('actively_exploited'))}"
    else:
        exploit = UNKNOWN
    status_parts = [
        part
        for part in [
            f"research_status={payload.get('research_status')}"
            if payload.get("research_status")
            else None,
            f"llm_status={payload.get('llm_status')}"
            if payload.get("llm_status")
            else None,
            f"authoritative={payload.get('authoritative')}"
            if "authoritative" in payload
            else None,
        ]
        if part
    ]
    rows = [
        ("CVE", esc_cell(cve_id)),
        ("Title", esc_cell(_first_text(research.get("title")) or UNKNOWN)),
        (
            "CVSS / severity",
            esc_cell(f"{cvss} — {_first_text(research.get('severity')) or UNKNOWN}"),
        ),
        ("CWE", esc_cell(cwe or UNKNOWN)),
        (
            "Affected product/plugin",
            esc_cell(
                "; ".join(
                    _as_list(research.get("affected_products"))
                    or _as_list(cve.get("products"))
                )
                or UNKNOWN
            ),
        ),
        (
            "Affected versions",
            esc_cell("; ".join(_as_list(research.get("affected_versions"))) or UNKNOWN),
        ),
        ("Authentication", esc_cell(_auth_requirement(research) or UNKNOWN)),
        ("Public exploit", esc_cell(exploit)),
        ("Research status", esc_cell("; ".join(status_parts) or UNKNOWN)),
    ]
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    for field, value in rows:
        lines.append(f"| {field} | {value} |")
    lines.append("")
    return "\n".join(lines)


def _render_vulnerability(payload: dict) -> str:
    research = (
        payload.get("research", {}) if isinstance(payload.get("research"), dict) else {}
    )
    lines = ["## 2. Vulnerability", ""]
    vuln_type = _first_text(research.get("vulnerability_type"))
    lines.append(
        f"- Vulnerability type: {esc_inline(vuln_type) if vuln_type else UNKNOWN}"
    )
    paths, params = _extract_paths_and_params(research)
    if paths:
        lines.append("- Affected endpoint/path (as stated in persisted research):")
        for path in paths:
            lines.append(f"  - `{esc_inline(path)}`")
    else:
        lines.append("- Affected endpoint/path: Unknown")
    if params:
        lines.append(
            f"- Parameter(s): {', '.join(f'`{esc_inline(p)}`' for p in params)}"
        )
    else:
        lines.append("- Parameter(s): Unknown")
    summary = _first_text(research.get("summary"))
    root_cause = _first_text(research.get("root_cause"))
    lines.append(f"- Description: {esc_inline(summary) if summary else UNKNOWN}")
    lines.append(f"- Root cause: {esc_inline(root_cause) if root_cause else UNKNOWN}")
    evidence = _as_list(research.get("evidence"))
    if evidence:
        lines.append("- Persisted evidence:")
        for item in sorted(set(evidence)):
            lines.append(f"  - {esc_inline(item)}")
    else:
        lines.append("- Persisted evidence: Not available")
    lines.append("")
    return "\n".join(lines)


def _render_references(
    records: list[dict] | None, missing_note: str | None
) -> str:
    lines = [
        "## 3. References",
        "",
        "_Persisted archive only. References were NOT fetched at render time._",
        "",
    ]
    if records is None:
        # missing_note is a trusted local path (fixed dir + validated CVE
        # id), rendered as a code span without escaping.
        lines.append(
            f"- References archive: Not available (`{missing_note}` not found)"
        )
        lines.append("")
        return "\n".join(lines)
    if not records:
        lines.append("- References archive: present but contains no records.")
        lines.append("")
        return "\n".join(lines)
    lines.append(f"- Persisted references: {len(records)}")
    lines.append("")
    for i, record in enumerate(records, 1):
        title = record.get("title")
        url = record.get("source_url")
        source_type = record.get("source_type")
        chunks = record.get("context_chunks")
        exact = record.get("exact_record")
        content_hash = record.get("content_hash")
        if isinstance(chunks, list) and chunks:
            context_state = f"persisted context available ({len(chunks)} chunk(s))"
        else:
            context_state = "no persisted context"
        exact_state = "exact record available" if exact else "no exact record"
        lines.append(
            f"### 3.{i} {esc_inline(title) if title else 'Untitled reference'}"
        )
        lines.append("")
        lines.append(f"- URL: {esc_url(url)}")
        lines.append(
            f"- Source/type: {esc_cell(source_type) if source_type else UNKNOWN}"
        )
        lines.append(
            f"- Context: {esc_inline(context_state)}; {esc_inline(exact_state)}"
        )
        lines.append(
            f"- Content hash: `{esc_inline(content_hash)}`"
            if content_hash
            else "- Content hash: Not available"
        )
        lines.append("")
    return "\n".join(lines)


def _render_kb(documents: list[Any], keywords: set[str], cve_id: str) -> str:
    lines = [
        "## 4. Knowledge Base",
        "",
        "_Read-only KnowledgeStore readback (`retrieve()`, deterministic order). "
        "Relevance below is token overlap computed at render time for "
        "presentation only; it is NOT a KnowledgeStore relationship._",
        "",
    ]
    if not documents:
        lines.append("- Matching KB documents: none (knowledge store is empty).")
        lines.append("")
        return "\n".join(lines)
    scored: list[tuple[int, str, Any, set[str]]] = []
    for doc in documents:
        matched = _kb_match(doc, keywords, cve_id)
        if matched:
            scored.append(
                (
                    len(matched),
                    str(getattr(doc, "knowledge_id", "")),
                    doc,
                    matched,
                )
            )
    # Deterministic: most overlap first, then knowledge_id.
    scored.sort(key=lambda item: (-item[0], item[1]))
    lines.append(f"- KB documents checked: {len(documents)}; matches: {len(scored)}")
    lines.append("")
    if not scored:
        lines.append(
            "- No KB document shares persisted-research keywords or the CVE id."
        )
        lines.append("")
        return "\n".join(lines)
    omitted = scored[KB_MATCH_LIMIT:]
    for _overlap, _kid, doc, matched in scored[:KB_MATCH_LIMIT]:
        kid = getattr(doc, "knowledge_id", UNKNOWN)
        title = getattr(doc, "title", UNKNOWN)
        source_type = getattr(doc, "source_type", None)
        source_url = getattr(doc, "source_url", None)
        quality = getattr(doc, "evidence_quality", None)
        lines.append(f"### {esc_inline(kid)} — {esc_inline(title)}")
        lines.append("")
        lines.append(
            f"- Source/type: {esc_cell(source_type) if source_type else UNKNOWN}"
        )
        lines.append(f"- Source URL: {esc_url(source_url) if source_url else UNKNOWN}")
        lines.append(
            f"- Evidence quality: {esc_cell(quality) if quality else UNKNOWN}"
        )
        lines.append(
            f"- Matched terms: {', '.join(f'`{esc_inline(t)}`' for t in sorted(matched))}"
        )
        lines.append("")
    if omitted:
        lines.append(
            f"- ... and {len(omitted)} further match(es) omitted "
            f"(limit {KB_MATCH_LIMIT})."
        )
        lines.append("")
    return "\n".join(lines)


def _render_nuclei(
    cve_id: str,
    template_text: str | None,
    results: Any,
    generated_dir: Path,
    results_dir: Path,
    findings_dir: Path,
) -> str:
    lines = [
        "## 5. Nuclei",
        "",
        "_Research evidence only. A research candidate or Nuclei artifact is "
        "NOT a Watch finding. Nothing was executed to produce this section._",
        "",
    ]
    template_path = (generated_dir / f"{cve_id}.yaml").as_posix()
    results_path = (results_dir / f"{cve_id}.json").as_posix()
    findings_path = (findings_dir / f"{cve_id}.json").as_posix()
    if template_text is None:
        lines.append(
            f"- Generated template: Not available (`{template_path}` not found)"
        )
    else:
        digest = _sha256_hex(template_text.encode("utf-8"))
        identity = _template_identity(template_text)
        severity = _template_severity(template_text)
        lines.append(f"- Generated template: `{template_path}`")
        lines.append(
            f"- Template identity: {esc_cell(identity) if identity else UNKNOWN}"
        )
        lines.append(
            f"- Template severity: {esc_cell(severity) if severity else UNKNOWN}"
        )
        lines.append(f"- Template digest: `sha256:{digest[:16]}`")
    if not isinstance(results, dict):
        lines.append(
            f"- Results artifact: Not available (`{results_path}` not found)"
        )
        lines.append(
            f"- Findings artifact: Not available (`{findings_path}` not found)"
        )
    else:
        sem = results.get("semantic_valid")
        nvalid = results.get("nuclei_valid")
        lines.append(
            "- Semantic validation: "
            f"{'valid' if sem is True else 'invalid' if sem is False else UNKNOWN}"
            + (
                "; template validation: "
                f"{'valid' if nvalid is True else 'invalid' if nvalid is False else UNKNOWN}"
                if nvalid is not None
                else ""
            )
        )
        decision = results.get("decision")
        reason = results.get("decision_reason") or results.get("nuclei_reason")
        lines.append(f"- Decision: {esc_cell(decision) if decision else UNKNOWN}")
        if reason:
            lines.append(f"- Decision reason: {esc_inline(reason)}")
        run_results = (
            results.get("run_results")
            if isinstance(results.get("run_results"), list)
            else []
        )
        if run_results:
            lines.append(
                f"- Result summary: {len(run_results)} target result(s); "
                f"status counts: {_summarize_statuses(run_results, 'status')}"
            )
        else:
            lines.append("- Result summary: no per-target results persisted")
        findings = (
            results.get("findings")
            if isinstance(results.get("findings"), list)
            else None
        )
        if findings is None:
            standalone = results.get("_standalone_findings")
            if isinstance(standalone, list):
                findings = standalone
        if findings is None:
            lines.append(
                f"- Findings artifact: Not available (`{findings_path}` not found)"
            )
        else:
            matched = sum(
                1 for f in findings if isinstance(f, dict) and f.get("matched") is True
            )
            lines.append(
                f"- Finding summary: {len(findings)} persisted finding record(s); "
                f"matched={matched}; unmatched={len(findings) - matched}"
            )
            if findings and matched == 0:
                lines.append(
                    "- Verdict: no confirmed match in persisted Nuclei evidence "
                    "(dry-run only)."
                )
            lines.append(f"- Findings artifact: `{findings_path}` (or embedded)")
    lines.append("")
    lines.append(
        "> Trust boundary: candidate/research evidence describes what *might* "
        "be true; Nuclei evidence describes offline template validation and "
        "dry-run outcomes; only production Watch findings (which this report "
        "never creates) describe what *is* true about a target."
    )
    lines.append("")
    return "\n".join(lines)


def _render_watch_relevance(payload: dict) -> str:
    metadata = (
        payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
    )
    research = (
        payload.get("research", {}) if isinstance(payload.get("research"), dict) else {}
    )
    lines = [
        "## 6. Watch Relevance",
        "",
        "_Only fields explicitly present in persisted research artifacts are "
        "shown. Where applicability is unknown, it is stated as unknown._",
        "",
    ]
    programs = _as_list(metadata.get("programs"))
    assets = _as_list(metadata.get("assets"))
    technologies = _as_list(metadata.get("technologies"))
    lines.append(
        "- Correlated programs: "
        f"{esc_inline('; '.join(sorted(set(programs)))) if programs else UNKNOWN}"
    )
    lines.append(
        "- Correlated assets: "
        f"{esc_inline('; '.join(sorted(set(assets)))) if assets else UNKNOWN}"
    )
    lines.append(
        "- Correlated technologies: "
        f"{esc_inline('; '.join(sorted(set(technologies)))) if technologies else UNKNOWN}"
    )
    count = metadata.get("assessment_count")
    lines.append(
        f"- Assessment count: {esc_inline(count) if count is not None else UNKNOWN}"
    )
    relevance = research.get("bug_bounty_relevance")
    lines.append(
        "- Bug-bounty relevance (persisted): "
        f"{esc_inline(relevance) if relevance is not None else UNKNOWN}"
    )
    lines.append(
        "- Watch-specific applicability: Unknown — persisted artifacts do not "
        "confirm the vulnerable product/version on any specific Watch target."
    )
    lines.append(
        "- Exploitability against Watch targets: Unknown — no live validation "
        "was performed and none is inferred from absence of data."
    )
    lines.append("")
    return "\n".join(lines)


def _render_limitations(
    payload: dict,
    references: list[dict] | None,
    kb_documents: list[Any],
    template_text: str | None,
    results: Any,
) -> str:
    research = (
        payload.get("research", {}) if isinstance(payload.get("research"), dict) else {}
    )
    metadata = (
        payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
    )
    missing: list[str] = []
    if references is None:
        missing.append("reference bodies: references archive not persisted")
    else:
        without_context = sum(
            1
            for r in references
            if not (isinstance(r.get("context_chunks"), list) and r["context_chunks"])
        )
        if without_context:
            missing.append(
                f"reference bodies: {without_context} reference(s) "
                "without persisted context"
            )
        if not references:
            missing.append("reference bodies: archive contains no records")
    versions = " ".join(_as_list(research.get("affected_versions"))).lower()
    if "fix" not in versions and "patch" not in versions:
        missing.append("fixed version: unknown from persisted inputs")
    if not metadata.get("assets") or metadata.get("assessment_count", 0) == 0:
        missing.append(
            "target evidence: no correlated Watch assets in persisted metadata"
        )
    missing.append("live validation: not performed (read-only report, no network)")
    if template_text is None:
        missing.append("template evidence: no persisted Nuclei template")
    if not isinstance(results, dict):
        missing.append("template evidence: no persisted Nuclei results artifact")
    if not kb_documents:
        missing.append("knowledge base: knowledge store is empty")
    lines = ["## 7. Limitations", ""]
    for item in missing:
        lines.append(f"- {esc_inline(item)}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def render_report(
    cve_id: str,
    payload: dict,
    references: list[dict] | None,
    references_note: str | None,
    kb_documents: list[Any],
    template_text: str | None,
    results: Any,
    *,
    generated_dir: Path = NUCLEI_GENERATED_DIR,
    results_dir: Path = NUCLEI_RESULTS_DIR,
    findings_dir: Path = NUCLEI_FINDINGS_DIR,
) -> str:
    """Render deterministic Markdown from already-loaded artifacts (pure)."""
    cve = _validate_cve_id(cve_id)
    research = (
        payload.get("research", {}) if isinstance(payload.get("research"), dict) else {}
    )
    cve_block = payload.get("cve", {}) if isinstance(payload.get("cve"), dict) else {}
    keywords = _kb_keywords(research, cve_block)
    parts = [
        f"# Research Report — {cve}",
        "",
        "_Deterministic read-only render from persisted local artifacts. "
        "No network, no LLM, no Nuclei execution, no production access._",
        "",
        _render_summary(cve, payload),
        _render_vulnerability(payload),
        _render_references(references, references_note),
        _render_kb(kb_documents, keywords, cve),
        _render_nuclei(
            cve, template_text, results, generated_dir, results_dir, findings_dir
        ),
        _render_watch_relevance(payload),
        _render_limitations(payload, references, kb_documents, template_text, results),
    ]
    return "\n".join(parts)


def build_report_for_cve(
    cve_id: str,
    output_path: str | Path | None = None,
    output: str | Path | None = None,
    *,
    research_dir: str | Path = RESEARCH_DIR,
    reports_dir: str | Path = REPORTS_DIR,
    nuclei_generated_dir: str | Path = NUCLEI_GENERATED_DIR,
    nuclei_results_dir: str | Path = NUCLEI_RESULTS_DIR,
    nuclei_findings_dir: str | Path = NUCLEI_FINDINGS_DIR,
    kb_root: str | Path | None = None,
    store: Any | None = None,
) -> Path:
    """Build the Markdown report for ``cve_id`` from persisted artifacts.

    Read-only: loads ``<CVE>.cli.json``, the optional
    ``<CVE>.references.json`` archive, read-only KnowledgeStore contents, and
    optional Nuclei artifacts. Writes ``ai_data/reports/<CVE>.md`` (or
    ``output``/``output_path`` when given) atomically with stable formatting.

    Raises :class:`ReportError` when the required research JSON is missing
    or any present artifact is corrupt. Missing *optional* artifacts render
    as explicit "Not available"/"Unknown" states instead of failing.
    """
    cve = _validate_cve_id(cve_id)
    research_dir_p = Path(research_dir)
    reports_dir_p = Path(reports_dir)
    gen_dir_p = Path(nuclei_generated_dir)
    res_dir_p = Path(nuclei_results_dir)
    fin_dir_p = Path(nuclei_findings_dir)

    payload = _load_research(cve, research_dir_p)
    references, references_note = _load_references(cve, research_dir_p)

    if store is None:
        from ai.knowledge.store import KnowledgeStore

        store = (
            KnowledgeStore(root_dir=kb_root) if kb_root is not None else KnowledgeStore()
        )
    kb_documents = _load_kb_documents(store)

    template_text = _read_text(gen_dir_p / f"{cve}.yaml")

    results: Any = None
    results_path = res_dir_p / f"{cve}.json"
    if results_path.exists():
        results = _read_json(results_path)
        if isinstance(results, dict):
            standalone_path = fin_dir_p / f"{cve}.json"
            if standalone_path.exists():
                standalone = _read_json(standalone_path)
                if isinstance(standalone, list):
                    results = dict(results)
                    embedded = results.get("findings")
                    if not isinstance(embedded, list) or not embedded:
                        results["_standalone_findings"] = standalone
    else:
        standalone_path = fin_dir_p / f"{cve}.json"
        if standalone_path.exists():
            standalone = _read_json(standalone_path)
            if isinstance(standalone, list):
                results = {"findings": standalone}

    markdown = render_report(
        cve,
        payload,
        references,
        references_note,
        kb_documents,
        template_text,
        results,
        generated_dir=gen_dir_p,
        results_dir=res_dir_p,
        findings_dir=fin_dir_p,
    )

    chosen = output if output is not None else output_path
    dest = Path(chosen) if chosen is not None else (reports_dir_p / f"{cve}.md")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_text(markdown, encoding="utf-8")
    tmp.replace(dest)
    return dest
