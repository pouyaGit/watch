"""Deterministic, atomic, idempotent persistence for R23 research results.

Layout (under ``ai_data/research/agent/`` by default):

    <plan_id>.<rule_version>.json     one completed research result per plan+rule
    <plan_id>.<rule_version>.md       deterministic Markdown report
    runs/<run_id>.json                one scheduler run record

Properties:

- atomic writes (temp file + ``os.replace``)
- idempotent: an existing completed result is never overwritten
- no secrets, no raw API keys, no arbitrary target responses
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

__all__ = [
    "DEFAULT_AGENT_DIR",
    "result_path",
    "report_path",
    "store_result",
    "load_result",
    "list_results",
    "results_summary",
    "write_report",
    "store_run",
    "list_runs",
    "latest_run",
]

DEFAULT_AGENT_DIR = Path("ai_data/research/agent")

_SAFE_PLAN_RE = re.compile(r"^r22-[0-9a-f]{16}$")
_SAFE_RUN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _base_dir(base: str | Path | None = None) -> Path:
    return Path(base) if base is not None else DEFAULT_AGENT_DIR


def _safe(plan_id: str) -> str:
    text = str(plan_id or "")
    if not _SAFE_PLAN_RE.match(text):
        raise ValueError(f"invalid plan id: {plan_id!r}")
    return text


def _safe_run(run_id: str) -> str:
    text = str(run_id or "")
    if not _SAFE_RUN_RE.match(text):
        raise ValueError(f"invalid run id: {run_id!r}")
    return text


def result_path(plan_id: str, rule_version: str, base: str | Path | None = None) -> Path:
    return _base_dir(base) / f"{_safe(plan_id)}.{rule_version}.json"


def report_path(plan_id: str, rule_version: str, base: str | Path | None = None) -> Path:
    return _base_dir(base) / f"{_safe(plan_id)}.{rule_version}.md"


def _atomic_write_text(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, dest)


def store_result(
    result: Any,
    *,
    base: str | Path | None = None,
    overwrite: bool = False,
) -> tuple[Path, bool]:
    """Persist one result; return ``(path, written)``.

    Idempotent by default: if the deterministic result file already exists it
    is left untouched (``written=False``). ``overwrite=True`` is the explicit,
    versioned opt-in for replacing a completed result.
    """
    payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
    plan_id = payload.get("plan_id")
    rule_version = payload.get("rule_version")
    dest = result_path(plan_id, rule_version, base)
    if dest.exists() and not overwrite:
        return dest, False
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    _atomic_write_text(dest, text)
    return dest, True


def load_result(
    plan_id: str, rule_version: str, base: str | Path | None = None
) -> dict | None:
    dest = result_path(plan_id, rule_version, base)
    try:
        return json.loads(dest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_results(base: str | Path | None = None) -> list[dict]:
    directory = _base_dir(base)
    if not directory.is_dir():
        return []
    out: list[dict] = []
    for path in sorted(directory.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("plan_id"):
            out.append(payload)
    out.sort(key=lambda r: (str(r.get("plan_id")), str(r.get("rule_version"))))
    return out


def results_summary(base: str | Path | None = None) -> dict:
    results = list_results(base)
    by_status: dict[str, int] = {}
    for result in results:
        status = str(result.get("status") or "UNKNOWN")
        by_status[status] = by_status.get(status, 0) + 1
    return {"total": len(results), "by_status": by_status}


def render_result_markdown(result: dict) -> str:
    cve = result.get("cve_id") or ""
    program = result.get("program") or ""
    lines: list[str] = [
        f"# Research Agent Result — {cve} → {program}",
        "",
        "**RESEARCH ONLY — NOT TARGET VALIDATION — NOT A PRODUCTION FINDING**",
        "",
        "_Deterministic research-only render. No target interaction, no active "
        "validation, no Nuclei execution, no production finding._",
        "",
        f"- result_id: {result.get('result_id')}",
        f"- run_id: {result.get('run_id')}",
        f"- plan_id: {result.get('plan_id')}",
        f"- lead_id: {result.get('lead_id') or '—'}",
        f"- status: {result.get('status')}",
        f"- rule_version: {result.get('rule_version')}",
        "",
        "## Recommended next step",
        "",
        str(result.get("recommended_next_step") or "—"),
        "",
        "## Exploitability summary",
        "",
        str(result.get("exploitability_summary") or "—"),
        "",
        "## Sources",
        "",
    ]
    sources = result.get("sources") or []
    if sources:
        for source in sources:
            lines.append(
                f"- [{source.get('source_type')}] {source.get('url')} "
                f"({source.get('status')})"
            )
    else:
        lines.append("- none")
    lines += ["", "## Evidence", ""]
    evidence = result.get("evidence") or []
    if evidence:
        for item in evidence:
            lines.append(
                f"- ({item.get('confidence')}) {item.get('claim')} "
                f"— {item.get('source_url')}"
            )
    else:
        lines.append("- none (no grounded evidence available)")
    lines += ["", "## Inferences", ""]
    inferences = result.get("inferences") or []
    if inferences:
        for item in inferences:
            label = "model" if item.get("model_generated") else "deterministic"
            lines.append(f"- [{label}] {item.get('statement')}")
    else:
        lines.append("- none")
    lines += ["", "## Unknowns", ""]
    for unknown in result.get("unknowns") or []:
        lines.append(f"- {unknown}")
    lines += ["", "## Affected versions", ""]
    for version in result.get("affected_versions") or []:
        lines.append(f"- {version}")
    lines += ["", "## Affected components", ""]
    for component in result.get("affected_components") or []:
        lines.append(f"- {component}")
    lines += ["", "## Affected parameters", ""]
    for parameter in result.get("affected_parameters") or []:
        lines.append(f"- {parameter}")
    lines += ["", "## Nuclei research candidates", ""]
    candidates = result.get("nuclei_candidates") or []
    if candidates:
        for candidate in candidates:
            lines.append(
                f"- {candidate.get('product') or '—'} "
                f"(executed={candidate.get('executed')})"
            )
    else:
        lines.append("- none")
    lines += [
        "",
        "## Limitations",
        "",
        "- Research planning only. A result is never a confirmed vulnerability, "
        "exploit, or production finding.",
        "- The target/program was never contacted, scanned, or validated.",
    ]
    return "\n".join(lines) + "\n"


def write_report(
    result: Any,
    *,
    base: str | Path | None = None,
    overwrite: bool = False,
) -> tuple[Path, bool]:
    payload = result.model_dump(mode="json") if hasattr(result, "model_dump") else dict(result)
    dest = report_path(payload.get("plan_id"), payload.get("rule_version"), base)
    if dest.exists() and not overwrite:
        return dest, False
    _atomic_write_text(dest, render_result_markdown(payload))
    return dest, True


def store_run(record: dict, *, base: str | Path | None = None) -> Path:
    run_id = _safe_run(record.get("run_id"))
    dest = _base_dir(base) / "runs" / f"{run_id}.json"
    _atomic_write_text(
        dest, json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True)
    )
    return dest


def list_runs(base: str | Path | None = None) -> list[dict]:
    directory = _base_dir(base) / "runs"
    if not directory.is_dir():
        return []
    out: list[dict] = []
    for path in sorted(directory.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get("run_id"):
            out.append(payload)
    out.sort(key=lambda r: str(r.get("started_at") or ""))
    return out


def latest_run(base: str | Path | None = None) -> dict | None:
    runs = list_runs(base)
    return runs[-1] if runs else None
