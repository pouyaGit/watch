---
name: bb-verify
description: "bb-verify — Candidate Triage & Evidence Discipline. Companion to verifier + bypass-researcher roles."
---

# bb-verify — Candidate Triage & Evidence Discipline

Companion to verifier + bypass-researcher roles.

## Evidence manifest (what a finding needs)
```
evidence/<finding_id>/
  req.txt        exact request (headers + body)
  res.txt        exact response (status + headers + body)
  timing.txt     timing deltas (for blind SQLi/CMDi)
  payload.txt    the exact payload that triggered
  screen.png     browser screenshot (XSS/clickjacking/UI)
  notes.md       human annotations
```

## Confidence rubric
- 0.9+: reproduced cross-account/cross-tenant, evidence complete, no FP pattern matches.
- 0.7: reproduced once, evidence complete, single-account.
- 0.5: plausible signal, evidence incomplete.
- 0.3: reflection-only / single quirk — do NOT confirm.

## Duplicate detection
- Compare (title-normalized, asset, endpoint, signals[]). If a prior row covers the same
  root cause + asset, mark duplicate with a link. Root-cause duplication counts even if
  the path differs.

## Refute discipline
- Refute when: evidence gate fails, FP pattern matches, or a benign explanation exists
  (e.g. error text from a library, not an injection).
- On refute, record the context pattern so the Router stops re-dispatching that check
  (playbook `notes.false_positives`).

## WAF-bypass iteration loop
```
blocked (403/400) -> bypass-researcher -> bypass.found -> re-run analyzer -> confirm
```
- Bypass research runs on the SAME evidence gates — a bypassed payload still needs the
  full manifest before it can be confirmed.

## Rules
- Confirmed = evidence manifest + reproduction + no FP match. Nothing else.
- Intrusive/RCE outcomes never auto-confirmed → handoff to the human.
