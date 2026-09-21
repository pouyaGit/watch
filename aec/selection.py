"""aec/selection.py — deterministic offline pilot case selection (AEC-1, task T1).

Turns the existing research cases into a **pilot selection**: which cases the
bounded read-only observation pilot may look at, which it may not, why, and
what evidence each selected case still needs.

Guarantees of this module:

- **Offline.** No socket, no name resolution, no transport, no subprocess, no
  live validation and no target interaction. Imports are stdlib + ``aec`` only.
- **Deterministic.** Input order never changes the outcome; two runs over the
  same inputs produce byte-identical JSON.
- **Fail-closed.** Unknown programs and ambiguous scope deny by default; every
  case gets exactly one outcome; the exclusion vocabulary is closed.
- **Write-scoped.** The only function that touches the filesystem for writing
  is :func:`write_outputs`, and only under ``ai_data/aec/`` and
  ``agent-reports/`` (path escapes raise :class:`SelectionError`).

The live leg (``aec/live_deps.py``, ``aec/observation_lane.py``) is Track B and
deliberately does not exist in this phase.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from aec import (
    ALLOWED_OUTPUT_ROOTS,
    APPROVAL_SHEET_DIR,
    APPROVAL_SHEET_FILENAME,
    APPROVAL_SHEET_VERSION,
    FAMILY_CAPS,
    FAMILY_DESCRIPTIONS,
    FAMILY_ORDER,
    NOT_CONFIRMED_NOTE,
    PILOT_BUDGET,
    PILOT_HOST_RANGE,
    SELECTION_DIR,
    SELECTION_FILENAME,
    SELECTION_RULE_VERSION,
    PilotBudgetLimits,
)
from aec.errors import (
    REASON_DESCRIPTIONS,
    SELECTED,
    SelectionError,
)
from aec.models import (
    CaseRef,
    SelectionDecision,
    SelectionResult,
)

#: Documented invariant: the 5E live traffic gate in
#: ``ai/execution/http_executor.py`` must remain ``False``. AEC-1 T1 never
#: enables, wraps or bypasses it; this constant exists so a test can assert the
#: expectation explicitly rather than by accident.
LIVE_TRAFFIC_ENABLED_EXPECTED = False

# --------------------------------------------------------------------------
# Endpoint / parameter classification (deterministic, documented heuristics)
# --------------------------------------------------------------------------

#: Whole-path-segment tokens that mark an authentication / identity surface.
_LOGIN_TOKENS = frozenset(
    {
        "account",
        "accounts",
        "auth",
        "authorisation",
        "authorization",
        "authorize",
        "changepassword",
        "logon",
        "login",
        "logout",
        "mfa",
        "oauth",
        "oauth2",
        "openid-connect",
        "passwd",
        "password",
        "realms",
        "reset",
        "reset-credentials",
        "resetpassword",
        "saml",
        "session",
        "sessions",
        "sign-in",
        "sign-up",
        "signin",
        "signup",
        "sso",
    }
)

#: Substrings that are unambiguous even when embedded in a longer segment.
_LOGIN_MARKERS = (
    "changepassword",
    "crosssite-login",
    "crosssite-logout",
    "googleonetap",
    "login-actions",
    "openid-connect",
    "redirectsso",
    "requestaccess",
    "reset-credentials",
    "resetpassword",
    "wp-login",
)

#: Parameters consistent with a session / credential / identity context.
_AUTH_PARAMS = frozenset(
    {
        "auth",
        "authorization",
        "code",
        "csrf",
        "csrf_token",
        "csrfmiddlewaretoken",
        "id_token",
        "jsessionid",
        "jwt",
        "m",
        "phpsessid",
        "refresh_token",
        "session",
        "session_id",
        "sessionid",
        "sid",
        "src",
        "t",
        "token",
    }
)

_AUTH_PARAM_MARKERS = (
    "access_token",
    "bearer",
    "cookie",
    "csrf",
    "jwt",
    "password",
    "passwd",
    "secret",
    "session",
    "token",
)

#: Parameters that make a case non-comparable (no safe second value).
_PLACEHOLDER_PARAMS = frozenset({"{id}", "{slug}", "{}", "none", "null"})

#: Reflected-input parameter signals (mirrors the project's XSS classifier).
_REFLECTED_PARAMS = frozenset(
    {
        "input",
        "message",
        "name",
        "next",
        "q",
        "query",
        "redirect",
        "return",
        "s",
        "search",
    }
)

#: id-like object-reference parameters for the wp-json resource family.
_ID_PARAMS = frozenset({"id", "object_id", "objectid", "uid", "user_id", "userid"})

#: url-like parameters for the oEmbed proxy family.
_URL_PARAMS = frozenset({"uri", "url"})

_WP_JSON_RESOURCE = "/wp-json/wp/v2/"
_WP_JSON_OEMBED = "/wp-json/oembed/"

_CONFIDENCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def path_segments(endpoint: object) -> tuple[str, ...]:
    """Path segments of an endpoint, query string removed, lower-cased."""
    path = str(endpoint or "").split("?", 1)[0]
    return tuple(segment for segment in path.split("/") if segment)


def _stem(segment: str) -> str:
    """Segment without a file extension (``RequestAccess.aspx`` -> ``requestaccess``)."""
    return segment.split(".", 1)[0].lower()


def is_login_endpoint(endpoint: object) -> bool:
    """True for login / account / SSO / authorization surfaces."""
    path = str(endpoint or "").split("?", 1)[0].lower()
    if any(marker in path for marker in _LOGIN_MARKERS):
        return True
    return any(_stem(segment) in _LOGIN_TOKENS for segment in path_segments(path))


def is_challenge_parameter(parameter: object) -> bool:
    """True for bot-management / challenge tokens (never contacted by the pilot)."""
    text = str(parameter or "").strip().lower()
    if not text:
        return False
    if text.startswith("__"):
        return True
    return any(
        marker in text for marker in ("challenge", "cf_clearance", "cf_chl", "captcha")
    )


def is_auth_parameter(parameter: object) -> bool:
    """True when the parameter carries session / credential / identity semantics."""
    text = str(parameter or "").strip().lower()
    if not text:
        return False
    if text in _AUTH_PARAMS:
        return True
    return any(marker in text for marker in _AUTH_PARAM_MARKERS)


def is_comparable_parameter(parameter: object) -> bool:
    """True when a safe second value could exist for this parameter."""
    text = str(parameter or "").strip().lower()
    if not text or text in _PLACEHOLDER_PARAMS:
        return False
    return not (text.startswith("{") and text.endswith("}"))


def family_for(case: CaseRef) -> str:
    """Pilot family of a case, or ``""`` when it is outside every family."""
    endpoint = case.endpoint.lower()
    parameter = case.parameter.strip().lower()

    if case.category == "idor" and _WP_JSON_RESOURCE in endpoint:
        if parameter in _ID_PARAMS:
            return "IDOR_JSON_RESOURCE"
    if case.category == "ssrf" and _WP_JSON_OEMBED in endpoint:
        if parameter in _URL_PARAMS:
            return "SSRF_OEMBED"
    if case.category == "xss" and parameter in _REFLECTED_PARAMS:
        return "XSS_REFLECTED"
    return ""


def _body_required(case: CaseRef) -> bool:
    return "body" in {location.lower() for location in case.locations}


def _host_matches(host: str, suffix: str) -> bool:
    host = host.lower().strip(".")
    suffix = suffix.lower().strip(".")
    if not host or not suffix:
        return False
    return host == suffix or host.endswith("." + suffix)


def normalise_scope(scope: Mapping[str, Any] | None) -> dict[str, dict[str, tuple[str, ...]]]:
    """Normalise a scope mapping to ``{program: {"scopes": ..., "ooscopes": ...}}``."""
    normalised: dict[str, dict[str, tuple[str, ...]]] = {}
    if not isinstance(scope, Mapping):
        return normalised
    for program, entry in scope.items():
        name = str(program or "").strip().lower()
        if not name or not isinstance(entry, Mapping):
            continue
        normalised[name] = {
            "scopes": tuple(
                str(item).strip() for item in (entry.get("scopes") or ()) if str(item).strip()
            ),
            "ooscopes": tuple(
                str(item).strip() for item in (entry.get("ooscopes") or ()) if str(item).strip()
            ),
        }
    return normalised


def host_in_scope(
    program: object,
    host: object,
    scope: Mapping[str, Mapping[str, Sequence[str]]],
) -> bool:
    """Deny-by-default scope check for one host in one program."""
    entry = scope.get(str(program or "").strip().lower())
    if not entry:
        return False
    host_text = str(host or "").strip()
    if not host_text:
        return False
    if any(_host_matches(host_text, suffix) for suffix in entry.get("ooscopes", ())):
        return False
    return any(_host_matches(host_text, suffix) for suffix in entry.get("scopes", ()))


def preclassify(case: CaseRef, scope: Mapping[str, Mapping[str, Sequence[str]]]) -> str:
    """First-match-wins pre-classification. Returns ``""`` when selectable."""
    if is_challenge_parameter(case.parameter):
        return "CHALLENGE_TOKEN"
    if is_login_endpoint(case.endpoint):
        return "LOGIN_ENDPOINT"
    if is_auth_parameter(case.parameter):
        return "AUTH_REQUIRED"
    if _body_required(case):
        return "BODY_REQUIRED"
    if case.method not in {"GET", "HEAD"}:
        return "NON_GET_METHOD"
    if case.category == "file_upload":
        return "UPLOAD_CATEGORY"
    if not host_in_scope(case.program, case.host, scope):
        return "OUT_OF_SCOPE_HOST"
    if not is_comparable_parameter(case.parameter):
        return "NOT_COMPARABLE"
    if not family_for(case):
        return "CATEGORY_OUT_OF_PILOT"
    return ""


def priority_key(case: CaseRef) -> tuple:
    """Deterministic selection priority: family, confidence, host, endpoint, id."""
    family = family_for(case)
    family_rank = FAMILY_ORDER.index(family) if family in FAMILY_ORDER else len(FAMILY_ORDER)
    return (
        family_rank,
        _CONFIDENCE_RANK.get(case.confidence, 9),
        case.host.lower(),
        case.endpoint,
        case.parameter.lower(),
        case.case_id,
    )


def _exclusion_key(decision: SelectionDecision) -> tuple:
    return (
        decision.reason,
        decision.host.lower(),
        decision.endpoint,
        decision.parameter.lower(),
        decision.case_id,
    )


# --------------------------------------------------------------------------
# The selector
# --------------------------------------------------------------------------


def select(
    cases: Iterable[Any],
    scope: Mapping[str, Any] | None = None,
    *,
    budget: PilotBudgetLimits | None = None,
    family_caps: Mapping[str, int] | None = None,
    host_range: Sequence[int] | None = None,
) -> SelectionResult:
    """Select the pilot case set deterministically. Performs no I/O."""
    limits = budget or PILOT_BUDGET
    caps = dict(FAMILY_CAPS)
    if family_caps:
        caps.update({str(k): int(v) for k, v in family_caps.items()})
    host_window = tuple(host_range or PILOT_HOST_RANGE)
    max_hosts = int(host_window[1])
    scope_norm = normalise_scope(scope)

    refs: list[CaseRef] = [
        case if isinstance(case, CaseRef) else CaseRef.from_report(case) for case in cases
    ]
    refs.sort(key=priority_key)

    selected: list[SelectionDecision] = []
    excluded: list[SelectionDecision] = []
    host_counts: dict[str, dict[str, int]] = {}
    family_counts: dict[str, dict[str, int]] = {}
    seen_endpoints: set[tuple[str, str, str]] = set()
    hosts_used: list[str] = []
    order = 0

    for ref in refs:
        family = family_for(ref)
        reason = preclassify(ref, scope_norm)
        if reason:
            excluded.append(
                SelectionDecision(
                    case=ref,
                    decision=reason,
                    family=family,
                    note=REASON_DESCRIPTIONS.get(reason, ""),
                )
            )
            continue

        if ref.endpoint_key in seen_endpoints:
            excluded.append(
                SelectionDecision(
                    case=ref, decision="DUPLICATE_ENDPOINT", family=family,
                    note=REASON_DESCRIPTIONS["DUPLICATE_ENDPOINT"],
                )
            )
            continue

        if family_counts.get(family, {}).get("selected", 0) >= caps.get(family, 0):
            excluded.append(
                SelectionDecision(
                    case=ref, decision="FAMILY_CAP_FULL", family=family,
                    note=REASON_DESCRIPTIONS["FAMILY_CAP_FULL"],
                )
            )
            continue

        if host_counts.get(ref.host, {}).get("selected", 0) >= limits.max_requests_per_host:
            excluded.append(
                SelectionDecision(
                    case=ref, decision="HOST_BUDGET_FULL", family=family,
                    note=REASON_DESCRIPTIONS["HOST_BUDGET_FULL"],
                )
            )
            continue

        if ref.host not in hosts_used and len(hosts_used) >= max_hosts:
            excluded.append(
                SelectionDecision(
                    case=ref, decision="HOST_SET_FULL", family=family,
                    note=REASON_DESCRIPTIONS["HOST_SET_FULL"],
                )
            )
            continue

        if len(selected) >= limits.max_cases:
            excluded.append(
                SelectionDecision(
                    case=ref, decision="PILOT_CAP_FULL", family=family,
                    note=REASON_DESCRIPTIONS["PILOT_CAP_FULL"],
                )
            )
            continue

        order += 1
        selected.append(
            SelectionDecision(
                case=ref,
                decision=SELECTED,
                family=family,
                order=order,
                note=(
                    "Selected for a bounded, authorized, read-only comparison "
                    "during the AEC-1 pilot (no contact without a grant)."
                ),
            )
        )
        seen_endpoints.add(ref.endpoint_key)
        if ref.host not in hosts_used:
            hosts_used.append(ref.host)
        bucket = host_counts.setdefault(
            ref.host, {"selected": 0, "cap": limits.max_requests_per_host}
        )
        bucket["selected"] += 1
        family_bucket = family_counts.setdefault(
            family, {"selected": 0, "cap": caps.get(family, 0)}
        )
        family_bucket["selected"] += 1

    excluded.sort(key=_exclusion_key)

    result = SelectionResult(
        selected=selected,
        excluded=excluded,
        family_counts=family_counts,
        host_counts=host_counts,
        limits={
            "max_cases": limits.max_cases,
            "max_requests": limits.max_requests,
            "max_requests_per_case": limits.max_requests_per_case,
            "max_requests_per_host": limits.max_requests_per_host,
            "min_seconds_between_requests": limits.min_seconds_between_requests,
            "max_concurrency": limits.max_concurrency,
            "max_wall_seconds_per_run": limits.max_wall_seconds_per_run,
            "host_range": list(host_window),
            "family_caps": dict(caps),
        },
        rule_version=SELECTION_RULE_VERSION,
        generated_from={"cases_considered": len(refs)},
    )
    return result


# --------------------------------------------------------------------------
# Rendering + the only writing path
# --------------------------------------------------------------------------


def render_approval_sheet(result: SelectionResult, *, now: str | None = None) -> str:
    """Human approval sheet (P1 artifact) for the pilot selection."""
    counts = result.counts
    reason_counts: dict[str, int] = {}
    for decision in result.excluded:
        reason_counts[decision.reason] = reason_counts.get(decision.reason, 0) + 1

    lines: list[str] = []
    lines.append("# AEC-1 Pilot Selection — Approval Sheet")
    lines.append("")
    lines.append(f"- Rule version: `{result.rule_version}`")
    lines.append(f"- Approval sheet version: `{APPROVAL_SHEET_VERSION}`")
    if now:
        lines.append(f"- Generated (UTC): {now}")
    lines.append(f"- Cases considered: {counts['total']}")
    lines.append(f"- Selected: {counts['selected']}")
    lines.append(f"- Excluded: {counts['excluded']}")
    lines.append("")
    lines.append(f"> {NOT_CONFIRMED_NOTE}")
    lines.append("")

    lines.append("## 1. Approval request")
    lines.append("")
    lines.append(
        "Approval of this selection authorizes **nothing on its own**. It is the "
        "P1 input to the AEC-1 gate chain: the operator still has to grant a "
        "per-host authorization (P2), approve the per-case observation plans "
        "(P3) and start the run (P4)."
    )
    lines.append("")
    lines.append("Requested by: AEC-1 pilot selector (automated, offline).")
    lines.append("Decision required from: operator (Authorization Officer).")
    lines.append("")
    lines.append("Proposed distinct hosts:")
    lines.append("")
    for host in result.hosts:
        counts_for_host = result.host_counts.get(host, {})
        lines.append(f"- `{host}` — {counts_for_host.get('selected', 0)} case(s)")
    lines.append("")

    lines.append("## 2. Selected cases")
    lines.append("")
    if not result.selected:
        lines.append("No case satisfied the pilot families and limits.")
    for decision in result.selected:
        gap = decision.evidence_gap
        lines.append(f"### {decision.order}. `{decision.case_id}` — {decision.family}")
        lines.append("")
        lines.append(f"- Host / endpoint / parameter: `{decision.host}` `{decision.endpoint}` `{decision.parameter}`")
        lines.append(f"- Method / category / confidence: `{decision.method}` / `{decision.category}` / `{decision.confidence}`")
        lines.append(f"- Risk category: `{decision.risk_category}`")
        lines.append(f"- Evidence ladder: `{gap.level_current}` → `{gap.level_target}`")
        lines.append(f"- Evidence required: {', '.join(gap.required) or '—'}")
        lines.append(
            f"- Evidence stated missing (the gap this pilot would close): "
            f"{', '.join(gap.missing) or '—'}"
        )
        lines.append(
            f"- Stored artifacts collected: {', '.join(gap.artifacts_collected) or '—'}"
        )
        lines.append(
            f"- Stored artifacts still missing: {', '.join(gap.artifacts_missing) or '—'}"
        )
        if gap.not_listed_missing:
            lines.append(
                "- Required evidence not listed as missing (no claim that an "
                f"artifact exists): {', '.join(gap.not_listed_missing)}"
            )
        lines.append(f"- What the pilot would attempt: {_attempt_description(decision.family)}")
        lines.append("")

    lines.append("## 3. Excluded cases and reasons")
    lines.append("")
    lines.append("Every considered case receives exactly one outcome.")
    lines.append("")
    lines.append("| Reason | Cases | Meaning |")
    lines.append("|---|---:|---|")
    for reason in sorted(reason_counts):
        lines.append(
            f"| `{reason}` | {reason_counts[reason]} | {REASON_DESCRIPTIONS.get(reason, '')} |"
        )
    lines.append("")
    lines.append("Excluded case ids by reason:")
    lines.append("")
    for reason in sorted(reason_counts):
        ids = [d.case_id for d in result.excluded if d.reason == reason]
        shown = ", ".join(f"`{case_id}`" for case_id in ids[:25])
        more = "" if len(ids) <= 25 else f" … (+{len(ids) - 25} more)"
        lines.append(f"- **{reason}** ({len(ids)}): {shown}{more}")
    lines.append("")

    lines.append("## 4. Limits and budget")
    lines.append("")
    limits = result.limits
    lines.append(f"- Max cases: {limits.get('max_cases')}")
    lines.append(f"- Max authorized requests (whole pilot): {limits.get('max_requests')}")
    lines.append(f"- Max requests per case: {limits.get('max_requests_per_case')}")
    lines.append(f"- Max requests per host: {limits.get('max_requests_per_host')}")
    lines.append(f"- Distinct-host window: {limits.get('host_range')}")
    lines.append(f"- Min seconds between requests: {limits.get('min_seconds_between_requests')}")
    lines.append(f"- Max concurrency: {limits.get('max_concurrency')}")
    lines.append(f"- Max wall seconds per run: {limits.get('max_wall_seconds_per_run')}")
    lines.append("")
    lines.append("Per-family usage (selected / cap):")
    lines.append("")
    for family in FAMILY_ORDER:
        bucket = result.family_counts.get(family, {"selected": 0, "cap": limits.get("family_caps", {}).get(family, 0)})
        lines.append(f"- `{family}`: {bucket.get('selected', 0)} / {bucket.get('cap', 0)}")
    lines.append("")
    estimated = sum(limits.get("max_requests_per_case", 0) for _ in result.selected)
    lines.append(
        f"Estimated worst-case request count for this selection: "
        f"{len(result.selected)} × {limits.get('max_requests_per_case')} = {estimated} "
        f"(hard cap {limits.get('max_requests')})."
    )
    lines.append("")

    lines.append("## 5. What this pilot will NOT do")
    lines.append("")
    lines.append("- No contact with any target before a granted authorization exists.")
    lines.append("- No payloads, no injection, no fuzzing, no browsers, no Nuclei, no uploads.")
    lines.append("- No POST/PUT/PATCH/DELETE, no request bodies, no redirect following.")
    lines.append("- No authentication, no session or identity acquisition.")
    lines.append("- No severity assignment, no submission, no confirmed finding of any kind.")
    lines.append("- No writes outside `ai_data/aec/` and `agent-reports/`.")
    lines.append("")
    lines.append("Family descriptions:")
    lines.append("")
    for family in FAMILY_ORDER:
        lines.append(f"- `{family}`: {FAMILY_DESCRIPTIONS.get(family, '')}")
    lines.append("")
    return "\n".join(lines)


def _attempt_description(family: str) -> str:
    if family == "IDOR_JSON_RESOURCE":
        return (
            "read two distinct publicly listed object references and compare "
            "bounded response metadata (status, length, digest) → response difference"
        )
    if family == "SSRF_OEMBED":
        return (
            "read the endpoint once as a baseline and once with one safe, "
            "non-forbidden url-shaped value, comparing bounded metadata → "
            "parameter behaviour + response difference"
        )
    if family == "XSS_REFLECTED":
        return (
            "read the parameter raw and encoded, comparing bounded metadata → "
            "encoding context"
        )
    return "no automated attempt defined for this family"


def _resolve_output_path(root: Path, relative_dir: str, filename: str) -> Path:
    """Resolve an output path and refuse anything outside the allowed area."""
    candidate = Path(relative_dir)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise SelectionError(f"refusing unsafe output directory: {relative_dir!r}")
    target = (root / candidate / filename).resolve()
    root_resolved = Path(root).resolve()
    if not str(target).startswith(str(root_resolved) + "/"):
        raise SelectionError(f"refusing output outside the project root: {target}")
    allowed = {
        str((root_resolved / Path(item)).resolve()) for item in ALLOWED_OUTPUT_ROOTS
    }
    if str(target.parent) not in allowed:
        raise SelectionError(
            f"refusing output outside the allowed area {ALLOWED_OUTPUT_ROOTS}: {target}"
        )
    return target


def write_outputs(
    result: SelectionResult,
    *,
    root: Path | str | None = None,
    selection_dir: str = SELECTION_DIR,
    approval_dir: str = APPROVAL_SHEET_DIR,
    now: str | None = None,
) -> list[Path]:
    """Write the selection JSON and the approval sheet. Returns the paths.

    This is the only function in ``aec/`` that writes to disk, and it can only
    write under ``ai_data/aec/`` and ``agent-reports/``.
    """
    root_path = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    selection_path = _resolve_output_path(root_path, selection_dir, SELECTION_FILENAME)
    approval_path = _resolve_output_path(root_path, approval_dir, APPROVAL_SHEET_FILENAME)

    payload = result.to_dict()
    if now is not None:
        payload["generated_at_utc"] = now

    selection_path.parent.mkdir(parents=True, exist_ok=True)
    selection_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    approval_path.parent.mkdir(parents=True, exist_ok=True)
    approval_path.write_text(render_approval_sheet(result, now=now), encoding="utf-8")
    return [selection_path, approval_path]


# --------------------------------------------------------------------------
# Input loading (read-only)
# --------------------------------------------------------------------------


def load_reports(reports_dir: Path | str) -> list[dict[str, Any]]:
    """Load investigation report JSON documents (read-only, deterministic order)."""
    directory = Path(reports_dir)
    reports: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:  # fail-soft, never silent
            raise SelectionError(f"unreadable report {path.name}: {error}") from error
        if isinstance(document, Mapping):
            reports.append(dict(document))
    return reports


def load_scope(path: Path | str) -> dict[str, dict[str, list[str]]]:
    """Load a scope snapshot (operator-provided, read-only)."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(document, Mapping) and "programs" in document:
        document = document["programs"]
    if not isinstance(document, Mapping):
        raise SelectionError("scope snapshot must be a mapping of program -> scopes")
    scope: dict[str, dict[str, list[str]]] = {}
    for program, entry in document.items():
        if not isinstance(entry, Mapping):
            raise SelectionError(f"scope entry for {program!r} must be a mapping")
        scope[str(program)] = {
            "scopes": [str(item) for item in (entry.get("scopes") or ())],
            "ooscopes": [str(item) for item in (entry.get("ooscopes") or ())],
        }
    return scope


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _parse_args(argv: Sequence[str] | None) -> dict[str, Any]:
    args = list(argv if argv is not None else [])
    options: dict[str, Any] = {
        "reports_dir": "ai_data/investigations/reports",
        "scope_json": "ai_data/aec/scope-snapshot.json",
        "root": None,
        "now": None,
        "write": True,
    }
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"--reports-dir", "--scope-json", "--root", "--now"}:
            if index + 1 >= len(args):
                raise SelectionError(f"{token} requires a value")
            options[token.lstrip("-").replace("-", "_")] = args[index + 1]
            index += 2
            continue
        if token == "--no-write":
            options["write"] = False
            index += 1
            continue
        raise SelectionError(f"unknown argument: {token}")
    return options


def main(argv: Sequence[str] | None = None) -> int:
    """CLI: build the selection and (unless ``--no-write``) write its artifacts."""
    options = _parse_args(argv)
    reports = load_reports(options["reports_dir"])
    scope: dict[str, Any] = {}
    scope_path = Path(options["scope_json"])
    if scope_path.exists():
        scope = load_scope(scope_path)
    result = select(reports, scope)

    counts = result.counts
    print(f"AEC-1 pilot selection ({result.rule_version})")
    print(f"  cases considered : {counts['total']}")
    print(f"  selected         : {counts['selected']}")
    print(f"  excluded         : {counts['excluded']}")
    print(f"  hosts            : {len(result.hosts)} -> {', '.join(result.hosts)}")
    if counts["selected"] > result.limits.get("max_cases", 0):
        raise SelectionError("selection exceeds the pilot case cap")

    if options["write"]:
        paths = write_outputs(result, root=options["root"], now=options["now"])
        for path in paths:
            print(f"  wrote            : {path}")
    return 0


__all__ = [
    "LIVE_TRAFFIC_ENABLED_EXPECTED",
    "family_for",
    "host_in_scope",
    "is_auth_parameter",
    "is_challenge_parameter",
    "is_comparable_parameter",
    "is_login_endpoint",
    "load_reports",
    "load_scope",
    "main",
    "normalise_scope",
    "path_segments",
    "preclassify",
    "priority_key",
    "render_approval_sheet",
    "select",
    "write_outputs",
]


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
