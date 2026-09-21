#!/usr/bin/env python3
"""diff_guard.py — change risk analyzer for the Watch delivery layer.

Autonomous Delivery Pipeline v1 (Epic 0).

Reads a change set (``git diff --name-status`` or ``git status --porcelain``)
plus, optionally, the unified diff text, and returns **PASS** or **BLOCK** with
every finding spelled out. It detects:

- production / authority-chain files touched  (FORBIDDEN_PATH)
- secrets and credential material             (SECRET_FILE, SECRET_CONTENT)
- environment / credential configuration      (ENV_CHANGE)
- systemd and OS-level units                  (SYSTEM_FILE)
- dangerous modifications                     (GUARD_DELETED, LIVE_GATE_FLIP,
                                               PATH_TRAVERSAL, MODE_CHANGE,
                                               BINARY_FILE, LARGE_DIFF)
- anything outside the allowlist              (UNKNOWN_PATH, warning only)

It is read-only: it never writes a file, never runs a subprocess, never touches
the network or Git. Fail-closed: unparseable input is a BLOCK, never a pass.

CLI::

    git diff --name-status main...HEAD | diff_guard.py
    diff_guard.py --name-status /tmp/ns.txt --diff /tmp/d.diff --json

Exit codes: 0 = PASS, 1 = BLOCK, 2 = invalid input (also reported as BLOCK).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.dont_write_bytecode = True  # keep the delivery directory free of __pycache__

_DELIVERY_DIR = Path(__file__).resolve().parent
if str(_DELIVERY_DIR) not in sys.path:
    sys.path.insert(0, str(_DELIVERY_DIR))

import policy  # noqa: E402  (loaded from the delivery directory)

VERDICT_PASS = "PASS"
VERDICT_BLOCK = "BLOCK"

EXIT_PASS = 0
EXIT_BLOCK = 1
EXIT_INVALID = 2

_STATUS_TOKEN = re.compile(r"^(?:[ACDMRTUXB][0-9]*|\?\?|!!)$")
_PORCELAIN_FIELDS = {"M", "A", "D", "R", "C", "U", "T", "?", "!", "??", "!!"}
_GIT_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_MODE_LINE = re.compile(r"^(?:old|new) mode ([0-7]{6})$")
_BINARY_LINE = re.compile(r"^Binary files .* differ$")

#: Added-line patterns. Each pattern is written so that this module's own source
#: cannot match it (asserted by the test suite).
_LIVE_GATE = re.compile(
    r"\b(?:LIVE_[A-Z0-9_]+|WATCH_AI_LIVE[A-Z0-9_]*)\s*[:=]\s*(?:True|true|1)\b"
)
_SECRET_CONTENT = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"mongodb(?:\+srv)?://[^:@\s/]+:[^@\s]+@"),
    re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    re.compile(
        r"(?i)(?:secret|api[_-]?key|access[_-]?key|auth[_-]?token)"
        r"\s*[:=]\s*['\"][A-Za-z0-9/+=_-]{16,}['\"]"
    ),
)

LARGE_DIFF_THRESHOLD = 5000


class ParseError(ValueError):
    """Raised when a change record cannot be understood."""


def _finding(kind: str, path: str, detail: str) -> dict[str, str]:
    return {
        "kind": kind,
        "path": path or "<change-set>",
        "severity": policy.severity_for(kind),
        "detail": detail,
    }


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def parse_changes(text: object) -> tuple[dict[str, str], ...]:
    """Parse ``git diff --name-status`` or ``git status --porcelain`` output."""
    if text is None:
        raise ParseError("no change set supplied")
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    changes: list[dict[str, str]] = []
    for raw in str(text).splitlines():
        if not raw.strip():
            continue
        if "\t" in raw:
            parts = [part.strip() for part in raw.split("\t")]
            status = parts[0]
            if not _STATUS_TOKEN.match(status) or len(parts) < 2:
                raise ParseError(f"unrecognised change record: {raw!r}")
            if status[0] in "RC" and len(parts) >= 3:
                old_path, path = parts[1], parts[2]
            else:
                old_path, path = "", parts[1]
        else:
            line = raw.rstrip()
            field = line[:2]
            rest = line[2:].strip()
            if field.strip() not in _PORCELAIN_FIELDS or not rest:
                raise ParseError(f"unrecognised change record: {raw!r}")
            status = field.strip() or "M"
            if " -> " in rest:
                old_path, path = [part.strip() for part in rest.split(" -> ", 1)]
            else:
                old_path, path = "", rest
        if not path:
            raise ParseError(f"change record without a path: {raw!r}")
        changes.append({"status": status, "path": path, "old_path": old_path})
    return tuple(changes)


def _blocked(kind: str, detail: str, files_checked: int = 0) -> dict[str, Any]:
    finding = _finding(kind, "<change-set>", detail)
    payload = _result([finding], files_checked)
    return payload


def _result(findings: Sequence[Mapping[str, str]], files_checked: int) -> dict[str, Any]:
    ordered = sorted(
        (dict(item) for item in findings),
        key=lambda item: (
            0 if item["severity"] == "BLOCK" else 1,
            item["kind"],
            item["path"],
            item["detail"],
        ),
    )
    blocking = [item for item in ordered if item["severity"] == "BLOCK"]
    warnings = [item for item in ordered if item["severity"] != "BLOCK"]
    return {
        "verdict": VERDICT_BLOCK if blocking else VERDICT_PASS,
        "blocked": bool(blocking),
        "findings": ordered,
        "blocking": blocking,
        "warnings": warnings,
        "files_checked": files_checked,
        "policy_version": policy.POLICY_VERSION,
        "policy_fingerprint": policy.policy_fingerprint(),
    }


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------


def analyse_path(path: str, status: str, origin: str = "") -> list[dict[str, str]]:
    """Findings for one changed path (path kinds, guard deletion, traversal)."""
    findings: list[dict[str, str]] = []
    prefix = f"{origin} " if origin else ""
    kinds = policy.classify_path_kinds(path)
    if "PATH_TRAVERSAL" in kinds:
        findings.append(
            _finding("PATH_TRAVERSAL", path, prefix + "path escapes the repository root")
        )
    if "FORBIDDEN" in kinds:
        findings.append(
            _finding(
                "FORBIDDEN_PATH",
                path,
                prefix + "authority chain, production entry point or protected directory",
            )
        )
    if "SECRET" in kinds:
        findings.append(
            _finding("SECRET_FILE", path, prefix + "credential material must never be committed")
        )
    if "ENV" in kinds:
        findings.append(
            _finding("ENV_CHANGE", path, prefix + "environment / credential configuration")
        )
    if "SYSTEM" in kinds:
        findings.append(
            _finding("SYSTEM_FILE", path, prefix + "systemd or OS-level unit")
        )
    if policy.classify_path(path) == "UNKNOWN":
        findings.append(
            _finding("UNKNOWN_PATH", path, prefix + "outside the delivery policy allowlist")
        )
    if status.upper().startswith("D") and policy.is_guard_path(path):
        findings.append(
            _finding("GUARD_DELETED", path, prefix + "deleting a delivery guard file removes a gate")
        )
    return findings


def analyse_diff_text(diff_text: object) -> list[dict[str, str]]:
    """Findings from the unified diff text (added lines only)."""
    if not diff_text:
        return []
    if isinstance(diff_text, bytes):
        diff_text = diff_text.decode("utf-8", "replace")
    findings: list[dict[str, str]] = []
    current = "<diff>"
    added = 0
    for line in str(diff_text).splitlines():
        header = _GIT_HEADER.match(line)
        if header:
            current = header.group(2).strip() or current
            continue
        if _MODE_LINE.match(line):
            findings.append(
                _finding("MODE_CHANGE", current, "file mode changed (review executable bits)")
            )
            continue
        if _BINARY_LINE.match(line):
            findings.append(_finding("BINARY_FILE", current, "binary content changed"))
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added += 1
        content = line[1:]
        if _LIVE_GATE.search(content):
            findings.append(
                _finding(
                    "LIVE_GATE_FLIP",
                    current,
                    "change enables a live-capability flag (live traffic / live validation)",
                )
            )
        for pattern in _SECRET_CONTENT:
            if pattern.search(content):
                findings.append(
                    _finding(
                        "SECRET_CONTENT",
                        current,
                        "added line looks like credential material or a secret",
                    )
                )
                break
    if added > LARGE_DIFF_THRESHOLD:
        findings.append(
            _finding(
                "LARGE_DIFF",
                "<diff>",
                f"{added} added lines is above the review threshold "
                f"({LARGE_DIFF_THRESHOLD})",
            )
        )
    return findings


def evaluate(changes: object, diff_text: object = "") -> dict[str, Any]:
    """Full change-set evaluation. Always returns a result; never raises."""
    if isinstance(changes, str) or isinstance(changes, bytes):
        try:
            changes = parse_changes(changes)
        except ParseError as error:
            return _blocked("UNPARSEABLE_INPUT", str(error))

    findings: list[dict[str, str]] = []
    records: list[Mapping[str, Any]] = []
    malformed = False
    if changes is None:
        changes = ()
    try:
        iterator = list(changes)
    except TypeError:
        return _blocked("UNPARSEABLE_INPUT", "change set is not a sequence")
    for item in iterator:
        if not isinstance(item, Mapping):
            malformed = True
            continue
        path = str(item.get("path") or "").strip()
        if not path:
            malformed = True
            continue
        records.append(item)
    if malformed:
        findings.append(
            _finding("UNPARSEABLE_INPUT", "<change-set>", "malformed change record in the change set")
        )
    if not records and not malformed:
        findings.append(_finding("NO_CHANGES", "<change-set>", "no changed files to promote"))

    for item in records:
        status = str(item.get("status") or "M")
        path = str(item.get("path") or "")
        old_path = str(item.get("old_path") or "")
        findings.extend(analyse_path(path, status))
        if old_path and old_path != path:
            findings.extend(analyse_path(old_path, status, origin="(renamed from)"))

    findings.extend(analyse_diff_text(diff_text))
    return _result(findings, len(records))


def evaluate_text(name_status_text: object, diff_text: object = "") -> dict[str, Any]:
    """Parse + evaluate raw text; unparseable text becomes a BLOCK."""
    try:
        changes = parse_changes(name_status_text)
    except ParseError as error:
        return _blocked("UNPARSEABLE_INPUT", str(error))
    return evaluate(changes, diff_text=diff_text)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _print_human(result: Mapping[str, Any]) -> None:
    print(f"DIFF GUARD: {result['verdict']}")
    print(f"  files checked : {result['files_checked']}")
    print(f"  policy        : {result['policy_version']}  {result['policy_fingerprint'][:16]}")
    for item in result["findings"]:
        print(f"  {item['severity']:<5} {item['kind']:<17} {item['path']}  — {item['detail']}")
    if not result["findings"]:
        print("  no findings: every changed path is inside the delivery policy allowlist")


def main(argv: Sequence[str] | None = None) -> int:
    args = [str(item) for item in (argv if argv is not None else sys.argv[1:])]
    name_status_path = None
    diff_path = None
    as_json = False
    index = 0
    while index < len(args):
        token = args[index]
        if token in ("--name-status", "--diff"):
            if index + 1 >= len(args):
                print(f"BLOCK\n  reason: {token} needs a value")
                return EXIT_INVALID
            if token == "--name-status":
                name_status_path = args[index + 1]
            else:
                diff_path = args[index + 1]
            index += 2
            continue
        if token == "--json":
            as_json = True
            index += 1
            continue
        if token in ("--help", "-h"):
            print(__doc__)
            return EXIT_PASS
        print(f"BLOCK\n  reason: unknown argument {token!r}")
        return EXIT_INVALID

    diff_text = ""
    if diff_path is not None:
        try:
            diff_text = _read(diff_path)
        except OSError as error:
            print(f"BLOCK\n  reason: cannot read diff file: {error}")
            return EXIT_INVALID

    try:
        if name_status_path is not None:
            text = _read(name_status_path)
        else:
            text = sys.stdin.read()
    except OSError as error:
        print(f"BLOCK\n  reason: cannot read change set: {error}")
        return EXIT_INVALID

    result = evaluate_text(text, diff_text=diff_text)
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _print_human(result)
    if any(item["kind"] == "UNPARSEABLE_INPUT" for item in result["blocking"]):
        return EXIT_INVALID
    if result["verdict"] == VERDICT_BLOCK:
        return EXIT_BLOCK
    if not result["files_checked"]:
        return EXIT_INVALID
    return EXIT_PASS


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
