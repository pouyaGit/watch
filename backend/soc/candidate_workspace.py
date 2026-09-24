"""backend/soc/candidate_workspace.py — ONE authoritative current-state
projection for the candidate/finding detail analyst workspace.

Contract (UX/data-contract correction):

* ``workspace.states`` is the ONLY current-state source the page header
  may use: candidate lifecycle + verification + finding case + Evidence
  Gate decision, all read from persisted rows.  LLM advisory text never
  feeds it — advisory renders only inside ``llm`` and is always labelled
  historical/advisory.
* Missing values render ``not_recorded`` / ``unavailable`` / ``unknown``.
  Nothing is inferred from unrelated text: no parameter, exploitability,
  severity, payload, CVE or affected-behaviour inference.
* Evidence is grouped for PRESENTATION only.  The persisted event list is
  never altered, deleted or CSS-hidden-away: every group reports its
  event count and the full event list stays available in ``raw``.
* Links are built only for routes that exist; external links never carry
  an ``api_key`` (page links append nothing — auth propagation stays on
  the app-wide ``api_key_qs`` convention handled by the templates).
* Every Mongo-backed read goes through ONE combined, fail-closed call so
  a dead Mongo renders ``unavailable`` instead of hanging the page.

This module is a read-model: it never mutates state, never decides a
verdict, and never invents evidence.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from typing import Any, Callable

SCHEMA = "watch-candidate-workspace-v1"

NOT_RECORDED = "not_recorded"
UNAVAILABLE = "unavailable"
UNKNOWN = "unknown"

#: bounded presentation caps (never affect stored data)
OBSERVATION_GROUP_CAP = 40
EVENT_ROWS_CAP = 40
RELATED_CAP = 20
TIMELINE_CAP = 40

#: authoritative lifecycle vocabulary (longest token first so
#: VERIFICATION_PENDING never degrades to a bare VERIFICATION match)
_STATE_TOKENS: tuple[str, ...] = (
    "VERIFICATION_PLANNED", "VERIFICATION_PENDING", "VERIFICATION",
    "NEEDS_EVIDENCE", "VERIFYING", "VERIFIED", "TRIAGED", "DETECTED",
    "REJECTED", "BLOCKED", "DUPLICATE", "INCONCLUSIVE", "EXPIRED",
    "PENDING", "READY", "AUTHORIZED",
)

#: persisted transition reason -> analyst timeline label
_TRANSITION_LABELS: dict[str, str] = {
    "candidate_detected": "Candidate detected",
    "triage:verify_via_hunt_planner": "Triaged",
    "triage_recommends_verification": "Verification planned",
    "authorization_granted": "Authorization granted",
    "verification_started": "Verification started",
    "evidence_rules_met": "Candidate VERIFIED",
}

#: persisted lineage stage -> analyst timeline label (milestones only;
#: engineering-stage rows stay available in the raw section)
_LINEAGE_LABELS: dict[str, str] = {
    "verification:AUTHORIZED": "Authorization granted",
    "verification:VERIFIED": "Verification completed",
    "case:READY_FOR_REVIEW": "Case READY_FOR_REVIEW",
    "case:HANDED_OFF": "Case HANDED_OFF",
    "case:REJECTED": "Case REJECTED",
    "case:BLOCKED": "Case BLOCKED",
    "case:DUPLICATE": "Case DUPLICATE",
    "case:INCONCLUSIVE": "Case INCONCLUSIVE",
}

#: timeline ordering rank (ties keep the example order)
_PHASE_RANK: dict[str, int] = {
    "Candidate detected": 10,
    "Triaged": 20,
    "Verification planned": 30,
    "Authorization granted": 40,
    "Verification started": 50,
    "Verification completed": 60,
    "Candidate VERIFIED": 70,
    "Case READY_FOR_REVIEW": 80,
}


def _safe(name: str, fn: Callable[[], Any]) -> dict[str, Any]:
    """Fail-closed source envelope (same shape as prod_intel.sources)."""
    try:
        return {"state": "ok", "data": fn(), "reason": ""}
    except Exception as exc:                     # noqa: BLE001
        return {"state": UNAVAILABLE, "data": None,
                "reason": f"{name}: {type(exc).__name__}: "
                          f"{str(exc)[:160]}"}


# ---------------------------------------------------------------- mongo
# One combined lookup so the page performs at most ONE Mongo connection
# attempt per render.  A short negative cache keeps a dead Mongo from
# stacking timeouts across repeated renders.
_MONGO_CACHE: dict[str, Any] = {"at": 0.0, "payload": None}
_MONGO_CACHE_TTL = 10.0


def mongo_records(*, obs_refs: list[str], affected_url: str,
                  program: str, path: str) -> dict[str, Any]:
    """URL / endpoint / program source records in one fail-closed read.

    Returns ``{"state": "ok"|"unavailable", "url_records": {ref: {...}},
    "affected_url": {...}|None, "endpoint": {...}|None,
    "program_exists": bool|None, "reason": ""}``.
    """
    key = repr((sorted(set(obs_refs)), affected_url, program, path))
    cached = _MONGO_CACHE
    if cached["payload"] is not None and cached.get("key") == key:
        if time.time() - float(cached["at"]) < _MONGO_CACHE_TTL:
            return dict(cached["payload"])
    try:
        from database.db import Endpoints, Programs, Urls

        payload: dict[str, Any] = {
            "state": "ok", "url_records": {}, "affected_url": None,
            "endpoint": None, "program_exists": None, "reason": "",
        }
        # observation refs of the form "urls:<objectid>"
        ids = [r.split(":", 1)[1] for r in dict.fromkeys(obs_refs)
               if isinstance(r, str) and r.startswith("urls:")
               and len(r) > 5]
        if ids:
            for doc in Urls.objects(id__in=ids):
                payload["url_records"][f"urls:{doc.id}"] = _url_row(doc)
        if affected_url:
            doc = Urls.objects(url=affected_url).first()
            payload["affected_url"] = _url_row(doc) if doc else None
        if program and path:
            doc = Endpoints.objects(program_name=program,
                                    path=path).first()
            payload["endpoint"] = _endpoint_row(doc) if doc else None
        if program:
            payload["program_exists"] = bool(
                Programs.objects(program_name=program).first())
        cached.update(at=time.time(), payload=payload, key=key)
        return dict(payload)
    except Exception as exc:                     # noqa: BLE001
        payload = {"state": UNAVAILABLE, "url_records": {},
                   "affected_url": None, "endpoint": None,
                   "program_exists": None,
                   "reason": f"{type(exc).__name__}: {str(exc)[:160]}"}
        cached.update(at=time.time(), payload=payload, key=key)
        return dict(payload)


def _url_row(doc: Any) -> dict[str, Any]:
    return {"record_id": str(doc.id), "url": str(doc.url or ""),
            "path": str(doc.path or ""), "params": [str(p) for p in
                                                    (doc.params or [])],
            "program_name": str(doc.program_name or ""),
            "sources": [str(s) for s in (doc.sources or [])]}


def _endpoint_row(doc: Any) -> dict[str, Any]:
    return {"record_id": str(doc.id),
            "program_name": str(doc.program_name or ""),
            "path": str(doc.path or ""),
            "example_url": str(getattr(doc, "example_url", "") or ""),
            "params": [str(p) for p in (doc.params or [])]}


def reset_mongo_cache() -> None:
    """Test hook: drop the negative cache (never called by the page)."""
    _MONGO_CACHE.update(at=0.0, payload=None, key=None)


# ---------------------------------------------------------------- helpers
def _text(value: Any, limit: int = 200) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return ""
    out = str(value).strip()
    return out[:limit]


def _confidence_value(raw: Any) -> str:
    if isinstance(raw, dict):
        return _text(raw.get("value")) or UNKNOWN
    return _text(raw) or NOT_RECORDED


def _endpoint_parts(endpoint: Any) -> dict[str, str]:
    if isinstance(endpoint, dict):
        return {"url": _text(endpoint.get("url")),
                "method": _text(endpoint.get("method")),
                "parameter": _text(endpoint.get("parameter"))}
    url = _text(endpoint)
    return {"url": url, "method": "", "parameter": ""}


def _scope_program(scope_ref: str) -> str:
    """Program name from a persisted scope (watch:scope:<p>/<target>)."""
    if not scope_ref.startswith("watch:scope:"):
        return ""
    head = scope_ref.split("/", 1)[0]
    return head.split(":")[-1] if ":" in head else ""


def _split_url(url: str) -> dict[str, str]:
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:                            # noqa: BLE001
        return {"scheme": "", "host": "", "path": "",
                "query": ""}
    return {"scheme": parts.scheme, "host": parts.netloc,
            "path": parts.path or "", "query": parts.query or ""}


def _extract_state(text: str) -> str:
    """State token literally present in advisory TEXT (never a state
    field — the advisory record persists no state column)."""
    for token in _STATE_TOKENS:
        if re.search(r"\b" + token + r"\b", text or ""):
            return token
    return ""


def _human(stage: str) -> str:
    """Fallback timeline label from a persisted stage/reason token."""
    raw = _text(stage)
    if not raw:
        return ""
    return raw.replace("_", " ").replace(":", " ").strip().capitalize()


# ---------------------------------------------------------------- build
def verification_outcome(cand_state: str, ver_state: str = "",
                         ver_decision: str = "") -> str:
    """EPIC10 §10: the five-way verification outcome, distinct from raw
    lifecycle states.

    VERIFIED            only from an authoritative VERIFIED candidate
                        (the Evidence Gate recorded rules-met — an LLM
                        suggestion or a URL/parameter can never yield
                        this outcome)
    DUPLICATE           correlation/dedup resolved the candidate away
    REJECTED            verification or candidate rejected
    BLOCKED             verification blocked (authorization or gate)
    INSUFFICIENT_EVIDENCE  not yet verified: waiting for evidence,
                        inconclusive, or still in progress
    """
    cand = str(cand_state or "").upper()
    ver = str(ver_state or "").upper()
    decision = str(ver_decision or "").upper()
    if cand == "VERIFIED" or decision == "VERIFIED":
        return "VERIFIED"
    if cand == "DUPLICATE":
        return "DUPLICATE"
    if cand == "REJECTED" or decision == "REJECTED":
        return "REJECTED"
    if cand == "BLOCKED" or ver in ("BLOCKED", "AUTHORIZATION_REQUIRED"):
        return "BLOCKED"
    return "INSUFFICIENT_EVIDENCE"


def build_workspace(detail: dict[str, Any],
                    fs: Any = None) -> dict[str, Any]:
    """Assemble the analyst workspace from ONE finding_detail payload."""
    cand = detail.get("candidate") if isinstance(
        detail.get("candidate"), dict) else {}
    cand = cand or {}
    ver = detail.get("verification") if isinstance(
        detail.get("verification"), dict) else None
    case = detail.get("case") if isinstance(
        detail.get("case"), dict) else None
    gate = detail.get("gate") if isinstance(detail.get("gate"), dict) \
        else {}
    package = detail.get("package") if isinstance(
        detail.get("package"), dict) else {}
    handoff = detail.get("handoff") if isinstance(
        detail.get("handoff"), dict) else {}
    advisor = detail.get("advisor") if isinstance(
        detail.get("advisor"), dict) else {}
    evidence = detail.get("evidence") if isinstance(
        detail.get("evidence"), list) else []

    candidate_id = _text(detail.get("candidate_id"))
    state = _text(detail.get("state")) or NOT_RECORDED
    ver_state = _text((ver or {}).get("state")) or NOT_RECORDED
    case_state = _text((case or {}).get("state")) or NOT_RECORDED
    gate_decision = _text(gate.get("decision")) or NOT_RECORDED
    gate_reason = _text(gate.get("gate_reason")) or NOT_RECORDED

    endpoint = _endpoint_parts(cand.get("endpoint"))
    affected_url = endpoint["url"]
    parts = _split_url(affected_url)
    target = _text(cand.get("target")) or (parts["host"] or NOT_RECORDED)
    scope_ref = _text(cand.get("scope_ref"))

    # ---------------- source records (one Mongo read, fail-closed) ----
    obs_refs = [e.get("observation_ref", "") for e in evidence
                if isinstance(e, dict)]
    obs_refs = [r for r in dict.fromkeys(obs_refs) if r]
    program = _scope_program(scope_ref)
    try:
        rec = mongo_records(obs_refs=obs_refs,
                            affected_url=affected_url,
                            program=program, path=parts["path"])
    except Exception as exc:              # noqa: BLE001 - fail closed
        rec = {"state": UNAVAILABLE,
               "reason": f"{type(exc).__name__}: source lookup failed"}
    rec_state = _text(rec.get("state")) or UNAVAILABLE
    affected_rec = rec.get("affected_url") or {}
    if isinstance(affected_rec, dict) and affected_rec.get(
            "program_name") and not program:
        program = affected_rec["program_name"]
    elif isinstance(affected_rec, dict) and not affected_rec:
        pass
    url_records: dict[str, Any] = rec.get("url_records") or {}
    endpoint_rec = rec.get("endpoint") or {}

    # ---------------- parameter resolution (linked records only) ------
    linked_params: list[str] = []
    param_source = NOT_RECORDED
    if _text(cand.get("parameter")):
        linked_params = [cand["parameter"]] if isinstance(
            cand.get("parameter"), str) else list(
            cand.get("parameter") or [])
        param_source = "candidate.parameter"
    elif endpoint_rec.get("params"):
        linked_params = list(endpoint_rec["params"])
        param_source = "endpoint_record"
    elif affected_rec.get("params"):
        linked_params = list(affected_rec["params"])
        param_source = "url_record"

    observed_params: list[str] = []
    for row in url_records.values():
        for p in (row or {}).get("params") or []:
            if p not in observed_params:
                observed_params.append(p)

    # ---------------- states (the ONE authoritative projection) -------
    states = {
        "candidate": state,
        "verification": ver_state,
        "case": case_state,
        # EPIC10 §10 five-way outcome (presentation projection of the
        # authoritative states above — never a new source of truth)
        "outcome": verification_outcome(
            state, ver_state, _text((ver or {}).get("decision"))),
        "gate_decision": gate_decision,
        "gate_reason": gate_reason,
        "source": ("candidate + verification + finding case "
                   "(persisted rows only; LLM advisory excluded)"),
    }

    # ---------------- header / summary --------------------------------
    severity = _text(detail.get("severity")) or NOT_RECORDED
    severity_prov = _text(detail.get("severity_provenance")) or \
        NOT_RECORDED
    confidence = _confidence_value(cand.get("confidence"))
    confidence_prov = _text(detail.get("confidence_provenance")) or \
        NOT_RECORDED
    summary = {
        "title": f"{_text(cand.get('vulnerability_class')) or UNKNOWN} "
                 f"Candidate",
        "vulnerability_class": _text(
            cand.get("vulnerability_class")) or NOT_RECORDED,
        "candidate_id": candidate_id,
        "candidate_state": state,
        "verification_state": ver_state,
        "case_state": case_state,
        "target": target,
        "affected_url": affected_url or NOT_RECORDED,
        "specialist": _text(cand.get("specialist")) or NOT_RECORDED,
        "created_at": _text(cand.get("created_at")) or NOT_RECORDED,
        "updated_at": _text(cand.get("updated_at")) or NOT_RECORDED,
        "confidence": confidence,
        "confidence_provenance": confidence_prov,
        "severity": severity,
        "severity_provenance": severity_prov,
        "notice_kind": _notice_kind(state),
        "notice": _notice(state, gate_reason, case_state),
    }

    # ---------------- why this candidate exists -----------------------
    signals = [_text(s) for s in (cand.get("supporting_signals")
                                  or []) if _text(s)]
    observed_bullets: list[dict[str, str]] = [
        {"text": s, "source": "candidate.supporting_signals"}
        for s in signals
    ]
    obs = _group_observations(evidence, url_records, rec_state)
    observed_bullets.append({
        "text": f"{obs['unique_count']} unique observation(s) across "
                f"{obs['event_count']} persisted evidence event(s)",
        "source": "runtime evidence rows",
    })
    if affected_url:
        observed_bullets.append({
            "text": f"Affected endpoint recorded: {affected_url}",
            "source": "candidate.endpoint",
        })
    if observed_params:
        observed_bullets.append({
            "text": "XSS parameter inventory from linked URL records: "
                    + ", ".join(observed_params[:12])
                    + (" …" if len(observed_params) > 12 else ""),
            "source": "url records (parameter inventory)",
        })
    elif rec_state == "ok":
        observed_bullets.append({
            "text": "Linked URL records contain no parameter names",
            "source": "url records (parameter inventory)",
        })
    missing = detail.get("missing_evidence") if isinstance(
        detail.get("missing_evidence"), list) else []
    why = {
        "observed": observed_bullets[:12],
        "reason": _text(detail.get("hypothesis")) or NOT_RECORDED,
        "creation_reason": _text(
            (detail.get("transitions") or [{}])[0].get("reason")
        ) or NOT_RECORDED,
        "confidence": confidence,
        "confidence_provenance": confidence_prov,
        "parameter": linked_params[0] if linked_params else NOT_RECORDED,
        "parameter_display": linked_params[0] if linked_params
        else "Not recorded in candidate context",
        "parameter_source": param_source,
        "parameters_all": linked_params[:12],
        "parameter_sources_checked": [
            "candidate.parameter",
            f"endpoint record ({rec_state})",
            f"url record ({rec_state})",
        ],
        "missing_evidence": missing[:12],
        "missing_evidence_count": len(missing),
        "scope_note": "This describes the observed signal. It is not "
                      "proof of exploitability unless the authoritative "
                      "verification/evidence state supports that "
                      "conclusion.",
    }

    # ---------------- affected resource --------------------------------
    affected = {
        "target": target,
        "host": parts["host"] or target,
        "url": affected_url or NOT_RECORDED,
        "url_is_link": bool(affected_url and parts["scheme"]),
        "path": parts["path"] or (UNKNOWN if affected_url else
                                  NOT_RECORDED),
        "method": endpoint["method"] or NOT_RECORDED,
        "parameters": linked_params[:12],
        "parameters_display": ", ".join(linked_params[:12])
        if linked_params else "Not recorded in candidate context",
        "program": program or NOT_RECORDED,
        "scope_ref": scope_ref or NOT_RECORDED,
        "records": {
            "url_record": affected_rec or None,
            "endpoint_record": endpoint_rec or None,
            "lookup_state": rec_state,
            "lookup_reason": _text(rec.get("reason")),
        },
        "source_label": ("Open Watch URL record"
                         if affected_rec else
                         f"URL record lookup: "
                         f"{'no match' if rec_state == 'ok' else rec_state}"),
    }

    # ---------------- verification -------------------------------------
    auth_ids = [str(a) for a in (detail.get("authorization_ids") or [])]
    verification = {
        "status": ver_state,
        "rule": gate_reason,
        "rule_version": _text((ver or {}).get("rule_version")) or
        NOT_RECORDED,
        "verification_id": _text((ver or {}).get("verification_id")) or
        NOT_RECORDED,
        "gate_case_id": _text(gate.get("case_id")) or NOT_RECORDED,
        "finding_case_id": _text((case or {}).get("case_id"))
        or _text(gate.get("finding_case_id")) or NOT_RECORDED,
        "decided_at": _text(gate.get("decided_at")) or NOT_RECORDED,
        "attempts": (ver or {}).get("attempts", NOT_RECORDED),
        "authorization_ids": auth_ids,
        "required_evidence": [str(r) for r in
                              ((ver or {}).get("required_evidence")
                               or [])][:12],
        "required_evidence_count": len(
            (ver or {}).get("required_evidence") or []),
        "current_evidence_count": len(
            (ver or {}).get("current_evidence") or []),
        "decided": bool(gate),
        "reason": _text(gate.get("reason")) or NOT_RECORDED,
    }

    # ---------------- what was / was NOT verified ----------------------
    ev_used = ((package.get("authoritative_verification") or {})
               .get("evidence_used") or [])
    verified_items: list[dict[str, str]] = []
    if gate and gate_decision in ("VERIFIED", "REJECTED", "INCONCLUSIVE",
                                  "BLOCKED"):
        verified_items.append({
            "text": f"Evidence Gate requirements were satisfied "
                    f"({gate_reason}).",
            "basis": "evidence gate decision",
        })
        n_pkg = len(package.get("evidence_ids") or [])
        n_used = len(ev_used)
        n_events = len(evidence)
        if n_used and n_pkg and n_used != n_pkg:
            vtext = (f"{n_used} of {n_pkg} persisted evidence events in "
                     f"the package were used in the Evidence Gate's "
                     f"verification set.")
        elif n_used or n_pkg or n_events:
            n_show = n_used or n_pkg or n_events
            vtext = (f"{n_show} persisted evidence events support the "
                     f"verification package.")
        else:
            vtext = ""
        if vtext:
            verified_items.append({
                "text": vtext,
                "basis": "package evidence ids + runtime evidence rows",
            })
        if auth_ids:
            verified_items.append({
                "text": "Verification completed within the authorized "
                        "scope (authorization ids recorded).",
                "basis": "verification.authorization_ids",
            })
    else:
        verified_items.append({
            "text": "No completed Evidence Gate decision is recorded "
                    "yet — nothing has been verified.",
            "basis": "verification record",
        })

    payload_value = _text((package.get("payload")
                           or (handoff.get("payload") or "")))
    payload_recorded = bool(payload_value) and payload_value not in (
        "", "unavailable", NOT_RECORDED)
    cve_value = _first_cve(cand, ver or {}, case or {})
    not_verified: list[dict[str, str]] = [
        {"text": "No exploit or payload execution is recorded (payload "
                 "detail is not stored in an authorized field).",
         "basis": "case package payload field: "
                  + (payload_value or NOT_RECORDED)},
        {"text": "Exploitability was not established through payload "
                 "execution.",
         "basis": "no payload execution record exists"
         if not payload_recorded else "see recorded payload field"},
        {"text": f"Severity remains {severity} because "
                 + ("no authoritative severity rule exists"
                    if "no_authoritative" in severity_prov
                    else f"provenance is {severity_prov}"),
         "basis": "candidate.severity_provenance"},
        {"text": "CVE applicability is not established — "
                 + (f"recorded CVE reference: {cve_value}"
                    if cve_value else "no authoritative CVE evidence "
                                      "is recorded"),
         "basis": "candidate/verification/case CVE fields"},
    ]
    distinctions = [
        {"dimension": "Evidence Gate verification",
         "state": f"{gate_decision} ({gate_reason})" if gate else
         NOT_RECORDED,
         "meaning": "the persisted evidence rules the Gate evaluated"},
        {"dimension": "Exploitability confirmation",
         "state": "not established (no payload execution recorded)"
         if not payload_recorded else "payload field recorded",
         "meaning": "requires execution this runtime does not perform"},
        {"dimension": "Severity assessment",
         "state": f"{severity} ({severity_prov})",
         "meaning": "severity only changes via an authoritative rule"},
        {"dimension": "External-report readiness",
         "state": case_state if case else NOT_RECORDED,
         "meaning": "analyst review state of the finding case"},
    ]

    # ---------------- LLM advisory (historical only) -------------------
    llm = _llm_block(advisor, state, verification)

    # ---------------- case package + next step -------------------------
    pkg_evidence = [str(x) for x in (package.get("evidence_ids") or [])]
    pkg_timeline = [x for x in (package.get("evidence_timeline") or [])]
    limitations: list[str] = []
    for _src in ((case or {}).get("limitations"),
                 handoff.get("limitations"),
                 package.get("limitations"),
                 detail.get("limitations")):
        for _item in (_src or []):
            _txt = str(_item)
            if _txt and _txt not in limitations:
                limitations.append(_txt)
    next_text = (_text((case or {}).get("recommended_next_step"))
                 or _text(package.get("recommended_analyst_next_step"))
                 or _text(handoff.get("recommended_next_step")))
    next_source = ("case.recommended_next_step"
                   if _text((case or {}).get("recommended_next_step"))
                   else "package.recommended_analyst_next_step"
                   if _text(package.get(
                       "recommended_analyst_next_step"))
                   else "handoff.recommended_next_step"
                   if _text(handoff.get("recommended_next_step"))
                   else NOT_RECORDED)
    case_package = {
        "case_id": _text((case or {}).get("case_id")) or NOT_RECORDED,
        "exists": bool(case),
        "status": case_state,
        "evidence_count": len(pkg_evidence),
        "timeline_count": len(pkg_timeline),
        "limitations_count": len(limitations),
        "handoff_state": case_state if case else NOT_RECORDED,
        "handoff_read_only": bool(handoff.get("read_only")),
        "gate_result": _text((case or {}).get("gate_result"))
        or gate_reason,
        "evidence_ids": pkg_evidence[:EVENT_ROWS_CAP],
        "timeline": [
            {"at": _text(t.get("at") if isinstance(t, dict) else ""),
             "event": _text(t.get("event") if isinstance(t, dict)
                            else t),
             "state": _text(t.get("state") if isinstance(t, dict)
                            else ""),
             "reason": _text(t.get("reason") if isinstance(t, dict)
                             else "")}
            for t in pkg_timeline[:TIMELINE_CAP]
        ],
        "limitations": limitations[:12],
    }
    next_step = {
        "text": next_text or NOT_RECORDED,
        "display": next_text or "No persisted analyst next step is "
                                "recorded for this candidate yet.",
        "source": next_source,
        "scope_note": "Reproduce only within the authorized scope "
                      "before any external report. Never generate "
                      "instructions for unauthorized exploitation.",
    }

    # ---------------- claim / evidence integrity (EPIC11) --------------
    integrity = _integrity_section(detail)

    # ---------------- related candidates (deduplicated) ----------------
    related = _related_rows(detail, fs=fs)

    # ---------------- timeline -----------------------------------------
    timeline = _timeline(detail, gate=gate, case=case)

    # ---------------- navigation ---------------------------------------
    links = _links(program=program, affected_url=affected_url,
                   path=parts["path"], program_exists=rec.get(
                       "program_exists"),
                   lookup_state=rec_state,
                   detail=detail, verification=verification,
                   case_package=case_package, params=linked_params)

    # ---------------- raw / engineering --------------------------------
    research = detail.get("research_history") if isinstance(
        detail.get("research_history"), dict) else {}
    hunt = detail.get("hunt") if isinstance(detail.get("hunt"), dict) \
        else {}
    raw = {
        "scope_ref": scope_ref or NOT_RECORDED,
        "source_job": _text(research.get("source_job")) or NOT_RECORDED,
        "verification_job": _text(research.get("verification_job"))
        or NOT_RECORDED,
        "campaign_id": _text(research.get("campaign_id")) or
        NOT_RECORDED,
        "objective_id": _text(research.get("objective_id")) or
        NOT_RECORDED,
        "hunt_objective_id": _text(hunt.get("objective_id")) or
        NOT_RECORDED,
        "hunt_objective_state": _text(hunt.get("state")) or NOT_RECORDED,
        "plan_ids": [str(x) for x in (detail.get("plan_ids") or [])],
        "authorization_ids": auth_ids,
        "observation_ids": [str(x) for x in
                            (detail.get("observation_ids") or [])],
        "verification_ids": [str(x) for x in
                             (cand.get("verification_ids") or [])],
        "revision": cand.get("revision", NOT_RECORDED),
        "provenance": detail.get("provenance") if isinstance(
            detail.get("provenance"), dict) else {},
        "transitions": detail.get("transitions") or [],
        "lineage": detail.get("lineage") or [],
        "evidence_event_ids": [e.get("id", "") for e in evidence
                               if isinstance(e, dict)],
        "duplicate_of": _text(detail.get("duplicate_of")),
        "linked_duplicates": [str(x) for x in
                              (detail.get("linked_duplicates") or [])],
        "lookup_state": rec_state,
    }

    return {
        "schema": SCHEMA,
        "available": True,
        "summary": summary,
        "states": states,
        "why": why,
        "affected": affected,
        "observations": obs,
        "verification": verification,
        # NB: key is `points`, never `items` — Jinja resolves dict
        # attribute access first, so `.items` would yield the builtin
        # dict.items method instead of the list.
        "verified": {"points": verified_items},
        "not_verified": {"points": not_verified,
                         "distinctions": distinctions},
        "llm": llm,
        "integrity": integrity,
        "case_package": case_package,
        "next_step": next_step,
        "related": related,
        "timeline": timeline,
        "links": links,
        "raw": raw,
    }


# ------------------------------------------------------------- sections
def _integrity_section(detail: dict[str, Any]) -> dict[str, Any]:
    """EPIC11 §21: what is supported, what is missing, what was NOT shown.

    Renders the persisted claim/evidence contract for an analyst: the
    claim/evidence matrix, the evidence BASIS of a confirmed finding, the
    exact missing evidence for a pending/blocked one, the report
    validation outcome, and the historical advisory kept separate from
    the authoritative state.
    """
    raw = detail.get("integrity") if isinstance(detail.get("integrity"),
                                                dict) else {}
    # §21: only a RECORDED contract may present an authoritative state.
    # A synthesized or legacy block (no contract row persisted) is not a
    # verdict: it is reported with its historical states and the
    # assessment re-projected from the persisted evidence.  The explicit
    # ``recorded`` flag wins; a block that never carried the flag is
    # judged by whether it actually carries contract content.
    if "recorded" in raw:
        recorded = bool(raw.get("recorded"))
    else:
        # contract CONTENT is what counts: a bare state label (or a bare
        # ``confirmed`` flag) is exactly the unsupported verdict this
        # section must not present
        recorded = bool(raw.get("claim_evidence_matrix")
                        or raw.get("gate_reason")
                        or raw.get("confirmation_status")
                        or raw.get("evidence_basis")
                        or raw.get("stage_reached"))
    if not raw or not recorded:
        return {
            "available": False,
            "recorded": False,
            "note": ("No claim/evidence contract is recorded for this "
                     "candidate (pre-EPIC11 record). No verdict is implied "
                     "by its absence."),
            "persisted_state": (raw.get("persisted_state")
                                if isinstance(raw.get("persisted_state"),
                                              dict) else {}),
            "projected": (raw.get("projected")
                          if isinstance(raw.get("projected"), dict) else {}),
            "source": _text(raw.get("source")),
        }
    matrix = []
    for row in (raw.get("claim_evidence_matrix") or []):
        if not isinstance(row, dict):
            continue
        matrix.append({
            "claim": _text(row.get("claim_type")) or UNKNOWN,
            "statement": _text(row.get("statement"), 200),
            "status": (_text(row.get("status")) or "MISSING").upper(),
            "verified": (_text(row.get("status")) or "").upper()
            == "SUPPORTED",
            "missing": (_text(row.get("status")) or "").upper()
            in ("", "MISSING", "UNSUPPORTED"),
            "contradicted": (_text(row.get("status")) or "").upper()
            == "CONTRADICTED",
            "evidence": ", ".join(str(x) for x in
                                  (row.get("evidence_ids") or []))[:120],
            "evidence_count": len(row.get("evidence_ids") or []),
        })
    basis = raw.get("evidence_basis") if isinstance(
        raw.get("evidence_basis"), dict) else {}
    validation = raw.get("report_validation") if isinstance(
        raw.get("report_validation"), dict) else {}
    advisory = raw.get("advisory") if isinstance(raw.get("advisory"),
                                                dict) else {}
    return {
        "available": True,
        "recorded": True,
        "authoritative_state": _text(raw.get("authoritative_state"))
        or NOT_RECORDED,
        "confirmed": bool(raw.get("confirmed")),
        "confirmation_status": _text(raw.get("confirmation_status"))
        or NOT_RECORDED,
        "gate_reason": _text(raw.get("gate_reason")) or NOT_RECORDED,
        "stage_reached": raw.get("stage_reached"),
        "stage_label": _text(raw.get("stage_label")) or NOT_RECORDED,
        "missing_evidence_types": [str(x) for x in
                                   (raw.get("missing_evidence_types")
                                    or [])][:12],
        "missing_evidence_reasons": [str(x) for x in
                                     (raw.get("missing_evidence_reasons")
                                      or [])][:8],
        "malformed_evidence": [str(x) for x in
                               (raw.get("malformed_evidence") or [])][:6],
        "matrix": matrix[:20],
        "matrix_counts": {
            "supported": len([m for m in matrix if m["verified"]]),
            "missing": len([m for m in matrix if m["missing"]]),
            "contradicted": len([m for m in matrix if m["contradicted"]]),
        },
        "evidence_basis": {
            "evidence_ids": [str(x) for x in
                             (basis.get("evidence_ids") or [])][:12],
            "unique_observations": basis.get("unique_observations"),
            "duplicate_events": basis.get("duplicate_events"),
        },
        "report_validation": {
            "status": _text(validation.get("status")) or NOT_RECORDED,
            "blockers": [b.get("code") if isinstance(b, dict) else str(b)
                         for b in (validation.get("blockers") or [])][:8],
            "unsupported_claims": [str(x) for x in
                                   (validation.get("unsupported_claims")
                                    or [])][:8],
        },
        "advisory": {
            "label": _text(advisory.get("label"))
            or "Historical / Advisory Only",
            "state": _text(advisory.get("state")) or NOT_RECORDED,
            "authoritative": False,
            "conflicts_with_current_state": bool(
                advisory.get("conflicts_with_current_state")),
        },
        "source": _text(raw.get("source")) or
        "persisted claim-integrity record",
    }


def _notice_kind(state: str) -> str:
    if state == "VERIFIED":
        return "verified"
    if state in ("REJECTED", "BLOCKED", "DUPLICATE", "INCONCLUSIVE",
                 "EXPIRED"):
        return "decided"
    return "pending"


def _notice(state: str, gate_reason: str, case_state: str) -> str:
    kind = _notice_kind(state)
    if kind == "verified":
        if gate_reason in (NOT_RECORDED, UNAVAILABLE, UNKNOWN, ""):
            return (f"Candidate state {state} is persisted; Evidence "
                    f"Gate decision detail {gate_reason}; finding case "
                    f"{case_state}.")
        return ("Authoritative Evidence Gate decision recorded "
                f"({gate_reason}); finding case {case_state}.")
    if kind == "decided":
        return (f"Verification concluded: {state}. No confirmed-"
                "vulnerability claim is made by this page.")
    return ("This is a candidate under review — exploitability, "
            "severity and CVE applicability are not established until "
            "the Evidence Gate decides.")


def _first_cve(cand: dict, ver: dict, case: dict) -> str:
    """CVE reference ONLY from an explicit persisted field (never from
    free text)."""
    for source in (cand, ver, case):
        for key, value in (source or {}).items():
            if "cve" in str(key).lower() and isinstance(value, str) \
                    and value.strip():
                return value.strip()
    pkg = (case or {}).get("package") if isinstance(case, dict) else {}
    if isinstance(pkg, dict):
        for key, value in pkg.items():
            if "cve" in str(key).lower() and isinstance(value, str) \
                    and value.strip():
                return value.strip()
    return ""


def _llm_block(advisor: dict, current_state: str,
               verification: dict) -> dict[str, Any]:
    used = bool(advisor.get("used"))
    text = _text(advisor.get("candidate_interpretation"), 600)
    claimed = _extract_state(text)
    stale = bool(claimed and current_state != NOT_RECORDED
                 and claimed != current_state)
    return {
        "present": bool(advisor),
        "used": used,
        "heading": "Historical LLM Advisory" if used else
        "LLM Advisory",
        "sublabel": ("Generated before final verification — advisory "
                     "context, not current state"
                     if used and stale else
                     "Advisory context only — not current state"
                     if used else NOT_RECORDED),
        "historical": used,
        "stale": stale,
        "current_authoritative_state": current_state,
        "state_at_generation": NOT_RECORDED,
        "state_in_advisory_text": claimed or NOT_RECORDED,
        "state_in_advisory_text_source":
        "extracted from advisory text (the advisory record persists no "
        "state column)" if claimed else NOT_RECORDED,
        "generated_at": NOT_RECORDED,
        "recorded_on": verification.get("verification_id",
                                        NOT_RECORDED),
        "text": text or NOT_RECORDED,
        "model": _text(advisor.get("model_resolved"))
        or _text(advisor.get("model_requested")) or NOT_RECORDED,
        "role": "ADVISORY ONLY",
        "authority": "Evidence Gate",
        "confidence": _text(advisor.get("confidence")) or NOT_RECORDED,
        "missing_evidence": [str(x) for x in
                             (advisor.get("missing_evidence") or [])][:8],
        "recommendations": [str(x) for x in (advisor.get(
            "verification_recommendations") or [])][:8],
        "blockers": [str(x) for x in
                     (advisor.get("blockers") or [])][:8],
        "error": _text(advisor.get("error")),
        "prompt_version": _text(advisor.get("prompt_version")) or
        NOT_RECORDED,
        "note": ("LLM advisory output. Not authoritative — the "
                 "Evidence Gate decided this candidate's state."),
    }


def _group_observations(evidence: list, url_records: dict,
                        lookup_state: str) -> dict[str, Any]:
    """Deterministic presentation grouping by persisted observation
    identity.  Nothing is removed from storage: every group carries its
    full event list (bounded for display only)."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    total = 0
    for row in evidence:
        if not isinstance(row, dict):
            continue
        total += 1
        obs_ref = _text(row.get("observation_ref"))
        signal = _text(row.get("signal")) or _text(row.get("type"))
        key = (obs_ref or _text(row.get("id")) or UNKNOWN, signal)
        grp = groups.get(key)
        created = _text(row.get("created_at"))
        if grp is None:
            rec = url_records.get(obs_ref) or {}
            grp = {
                "observation_id": key[0],
                "type": _text(row.get("type")) or NOT_RECORDED,
                "signal": signal or NOT_RECORDED,
                "signal_quality": {
                    "reliability": _text(row.get("reliability")) or
                    UNKNOWN,
                    "directness": _text(row.get("directness")) or
                    UNKNOWN,
                    "stance": _text(row.get("stance")) or UNKNOWN,
                },
                "role": _text(row.get("verification_relevance")) or
                UNKNOWN,
                "first_observed": created or NOT_RECORDED,
                "last_observed": created or NOT_RECORDED,
                "event_count": 0,
                "jobs": [],
                "affected_resource": _text(row.get("detail"), 160)
                or NOT_RECORDED,
                "observed_url": _text((rec or {}).get("url")),
                "observed_path": _text((rec or {}).get("path")),
                "observed_program": _text(
                    (rec or {}).get("program_name")),
                "parameters": list((rec or {}).get("params") or []),
                "source_record": (rec or {}).get("record_id")
                if rec else None,
                "source_record_state": ("ok" if rec else
                                        lookup_state),
                "events": [],
                "id_is_evidence": not bool(obs_ref),
            }
            groups[key] = grp
        grp["event_count"] += 1
        if created:
            if grp["first_observed"] in ("", NOT_RECORDED) or (
                    created < grp["first_observed"]):
                grp["first_observed"] = created
            if created > grp["last_observed"]:
                grp["last_observed"] = created
        job = _text(row.get("job_id"))
        if job and job not in grp["jobs"]:
            grp["jobs"].append(job)
        if len(grp["events"]) < EVENT_ROWS_CAP:
            grp["events"].append({
                "id": _text(row.get("id")),
                "job_id": job or NOT_RECORDED,
                "created_at": created or NOT_RECORDED,
                "label": _text(row.get("label")) or _text(
                    row.get("signal")) or _text(row.get("detail"), 80),
                "reliability": _text(row.get("reliability")) or UNKNOWN,
            })
    ordered = sorted(groups.values(),
                     key=lambda g: (g["first_observed"],
                                    g["observation_id"]))
    unique_signals = sorted({g["signal"] for g in ordered})
    return {
        "unique_count": len(ordered),
        "event_count": total,
        "unique_signals": unique_signals,
        "groups": ordered[:OBSERVATION_GROUP_CAP],
        "truncated_groups": max(0, len(ordered) -
                                OBSERVATION_GROUP_CAP),
    }


def _related_rows(detail: dict, fs: Any = None) -> dict[str, Any]:
    """Deduplicate related-candidate presentation BY CANDIDATE ID.

    Correlation rows repeat the same pair (one row per rule run); this
    merges them into one row per candidate with the union of reasons and
    that candidate's CURRENT authoritative state.
    """
    our_id = _text(detail.get("candidate_id")) or _text(
        (detail.get("candidate") or {}).get("candidate_id"))
    correlations = detail.get("related") if isinstance(
        detail.get("related"), list) else []
    merged: dict[str, dict[str, Any]] = {}
    canonical_of: list[str] = []
    canonical_for_us = ""
    for corr in correlations:
        if not isinstance(corr, dict):
            continue
        other = _text(corr.get("other_candidate_id"))
        if not other or other == our_id:
            continue
        relation = _text(corr.get("relation")) or NOT_RECORDED
        reasons = [str(r) for r in (corr.get("reasons") or [])]
        canonical = _text(corr.get("canonical_id"))
        row = merged.get(other)
        if row is None:
            row = {"candidate_id": other, "relations": [],
                   "reasons": [], "state": NOT_RECORDED,
                   "state_source": "not looked up",
                   "link": f"/ui/soc/findings/{other}",
                   "canonical_id": ""}
            merged[other] = row
        if relation not in row["relations"]:
            row["relations"].append(relation)
        for r in reasons:
            if r not in row["reasons"]:
                row["reasons"].append(r)
        if canonical and our_id and canonical == our_id:
            if other not in canonical_of:
                canonical_of.append(other)
            row["canonical_id"] = our_id
        elif canonical:
            canonical_for_us = canonical
            row["canonical_id"] = canonical
    # current state of each related candidate (persisted lookup)
    if fs is not None:
        for row in merged.values():
            try:
                other = fs.get_candidate(row["candidate_id"])
            except Exception:                    # noqa: BLE001
                other = None
            if other is None:
                row["state"] = "not_found"
                row["state_source"] = "finding store lookup"
            else:
                row["state"] = _text(other.lifecycle_state) or \
                    NOT_RECORDED
                row["state_source"] = "finding store (persisted)"
    rows = sorted(merged.values(), key=lambda r: r["candidate_id"])
    duplicate_of = _text(detail.get("duplicate_of"))
    return {
        "count": len(rows),
        "lookup_state": "ok" if fs is not None else UNAVAILABLE,
        "rows": rows[:RELATED_CAP],
        "canonical_candidate": duplicate_of or canonical_for_us
        or our_id if (canonical_of or duplicate_of or
                      canonical_for_us) else NOT_RECORDED,
        "canonical_is_self": bool(canonical_of) and not duplicate_of,
        "preserved_evidence_from": sorted(canonical_of),
        "duplicate_of": duplicate_of,
        "note": ("This candidate is canonical; evidence from the "
                 "listed candidates is preserved."
                 if canonical_of and not duplicate_of else
                 f"Duplicate of {duplicate_of}; evidence preserved."
                 if duplicate_of else
                 "No canonical relationship recorded."
                 if not rows else
                 "Related candidates — deduplicated by candidate id."),
    }


def _timeline(detail: dict, gate: dict, case: dict) -> dict[str, Any]:
    """Analyst research timeline from persisted transitions + lineage.

    Raw event names stay available in the raw section; this is the
    labelled, ordered milestone view.
    """
    entries: dict[tuple[str, str], dict[str, Any]] = {}

    def _put(at: str, label: str, kind: str, source: str,
             link: str = "") -> None:
        if not at or not label:
            return
        key = (label, at)
        if key in entries:
            if link and not entries[key].get("link"):
                entries[key]["link"] = link
            return
        entries[key] = {"at": at, "label": label, "kind": kind,
                        "source": source, "link": link}

    for row in (detail.get("transitions") or []):
        if not isinstance(row, dict):
            continue
        reason = _text(row.get("reason"))
        to_state = _text(row.get("to_state"))
        mapped = _TRANSITION_LABELS.get(reason)
        label = mapped or (f"Candidate {to_state}" if to_state else "")
        if not label:
            continue
        _put(_text(row.get("created_at")), label, "candidate",
             f"candidate transition ({reason or 'state change'})",
             "#raw-details")
    for row in (detail.get("lineage") or []):
        if not isinstance(row, dict):
            continue
        stage = _text(row.get("stage"))
        label = _LINEAGE_LABELS.get(stage)
        if not label:
            continue
        kind = "verification" if stage.startswith("verification:") \
            else "case"
        if kind == "verification":
            link = "#verification-section"
        else:
            link = "#case-package"
        _put(_text(row.get("created_at")), label, kind,
             f"persisted lineage ({stage})", link)
    ordered = sorted(entries.values(),
                     key=lambda e: (e["at"],
                                    _PHASE_RANK.get(e["label"], 900),
                                    e["label"]))
    return {"count": len(ordered),
            "entries": ordered[:TIMELINE_CAP]}


def _links(*, program: str, affected_url: str, path: str,
           program_exists: Any, lookup_state: str, detail: dict,
           verification: dict, case_package: dict,
           params: list[str]) -> dict[str, Any]:
    """Navigation paths — only for routes that exist (§15).

    Internal links rely on the application's existing authenticated
    navigation (``api_key_qs`` propagation handled by base.html);
    EXTERNAL links never receive a key.
    """
    links: dict[str, Any] = {}

    def _ui(label: str, href: str, note: str = "") -> None:
        links[label] = {"label": label, "href": href, "kind": "ui",
                        "note": note}

    _ui("programs", "/ui/programs")
    if program:
        if program_exists is True:
            _ui("program", f"/ui/program/{program}",
                "program record exists")
        else:
            links["program"] = {
                "label": "program", "href": "",
                "kind": "none",
                "note": ("program record lookup: "
                         + ("no match" if lookup_state == "ok"
                            else lookup_state))}
    if affected_url and affected_url != NOT_RECORDED:
        links["affected_url"] = {"label": "affected url",
                                 "href": affected_url,
                                 "kind": "external",
                                 "note": "external target — never "
                                         "receives an api_key"}
        q = urllib.parse.urlencode({"q": affected_url,
                                    "program": program} if program
                                   else {"q": affected_url})
        _ui("url_record", f"/ui/urls?{q}",
            "watch URL records filtered to this url")
    if path and path not in ("", UNKNOWN) and program:
        q = urllib.parse.urlencode({"q": path, "program": program})
        _ui("endpoint_record", f"/ui/endpoints?{q}",
            "watch endpoint records filtered to this path")
    if params:
        q = urllib.parse.urlencode({"q": params[0]})
        _ui("parameter_record", f"/ui/parameters?{q}",
            "parameter inventory filtered to this parameter")
    else:
        _ui("parameter_inventory", "/ui/parameters",
            "no parameter recorded for this candidate")
    research = detail.get("research_history") if isinstance(
        detail.get("research_history"), dict) else {}
    for label, key in (("source_job", "source_job"),
                       ("verification_job", "verification_job")):
        job = _text(research.get(key))
        if job:
            _ui(label, f"/ui/soc/handoff/{job}",
                "job handoff / report record")
    campaign = _text(research.get("campaign_id"))
    if campaign:
        _ui("campaign", f"/ui/soc/campaigns/{campaign}")
    gate_case = verification.get("gate_case_id", "")
    if gate_case and gate_case != NOT_RECORDED:
        _ui("gate_case", f"/ui/soc/cases/{gate_case}",
            "evidence-gate runtime case")
    finding_case = case_package.get("case_id", "")
    if case_package.get("exists"):
        _ui("finding_case", f"/ui/soc/cases/{finding_case}",
            "finding case record (same authoritative package)")
        _ui("evidence_timeline",
            f"/ui/soc/cases/{finding_case}",
            "case page carries the persisted evidence timeline")
        links["case_package_json"] = {
            "label": "case package json",
            "href": f"/api/intel/cases/{finding_case}",
            "kind": "api", "note": "secondary machine-readable copy"}
    _ui("cases_index", "/ui/soc/cases")
    _ui("handoff_index", "/ui/soc/handoff")
    _ui("findings_index", "/ui/soc/findings")
    return links
