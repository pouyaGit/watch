# AEC-1 EPIC 4 — Watch Security Research Intelligence Layer v1 (offline)

## Architecture

```
Watch recon (plain data, never imported)
  AttackSurfaceRecord / AttackSurfaceCandidate shapes
        │
        ▼
aec/surface/adapter ──► ResearchCandidateDraft (content-hash id)
        │                    asset · endpoint · parameters · technology
        │                    research_category · first-observation gap
        │                    source_reference · classification notes
        ▼
aec/memory/connect ◄── case memories ── duplicate? related patterns?
  RelatedContext ──► history_summary {researched, related_patterns}
        │                          │
        ▼                          ▼
aec/assignment/rules      aec/intelligence/scoring
  surface → role            5 dimensions × 0–20 → 0–100
  authorization/input/      bands LOW/MEDIUM/HIGH
  server/general            (research priority, never severity)
        │                          │
        └──────────┬───────────────┘
                   ▼
      to_case_kwargs ──► CaseRef ──► orchestrator intake ──► queue
                   ▼
      backend/routers/aec: /api/aec/candidates, /api/aec/research-status
      (+ existing /cases /queue /status)
```

New: `aec/surface/` (models, adapter), `aec/intelligence/` (models,
scoring), `aec/assignment/` (models, rules), `aec/memory/connect.py`.
Extended: `backend/routers/aec.py` (+2 builders, +2 routes).

## Data flow

A record adapts to exactly one draft; the connector reads supplied
memories without mutating them; the scorer and assigner are pure
functions of draft + history; the draft projects onto CaseRef kwargs
(case_id = candidate_id, no URL invented) and enters the EPIC 3
lifecycle at intake. Router handlers project the merged fields.

## Boundaries

- **No backend imports in aec.** Recon shapes are consumed as plain
  mappings (test-enforced per module); `attack_surface` /
  `observed_inventory` never appear in aec source.
- **Priority ≠ severity.** Bands LOW/MEDIUM/HIGH name effort ordering
  only. Source scans ban SEVERITY/CVSS/CRITICAL/VULNERABLE/EXPLOIT/
  CONFIRMED/FINDING/VERDICT; the required band names are the only
  grade-like vocabulary and are pinned as non-severity by test.
- **Memory hygiene.** Scrub-on-write (EPIC 3) plus connector reads that
  never mutate; pattern context reuses stored scrubbed text.
- **Read-only API.** Two new GET builders follow the EPIC 3 allowlist
  pattern; unknown bands drop, unknown roles default to generalist,
  bad counts refuse. Router still inert until mounted; `api.py`
  untouched.
- **Denial-suite layering (as EPIC 3).** The four pure-aec modules run
  under socket denial; router + flow render tests run normally with AST
  import guards (backend touches sockets at import).

## Design decisions

- **Draft ids are content hashes** (`rc-` + sha256 of source|asset|
  endpoint|parameter|category): the same source always yields the same
  draft, across runs and machines.
- **Fresh candidates need one observation.** The gap is
  `{required: [initial-observation], missing: [initial-observation]}` —
  the only gap claim the adapter can honestly make without observing.
- **Unknown categories refuse at the adapter** (closed 5-code
  vocabulary) but **fall back to generalist at assignment**: the adapter
  guards the pipeline mouth; the assigner never silently drops a
  candidate for novelty.
- **Duplicate = same endpoint key observed under another case.**
  Candidate ids become case ids by construction, so same-id memories
  are the same case, not a duplicate.
- **Rubric weights are pinned constants** with one-line rationales;
  changing a weight changes scores, so the weight table is contract.

## Future execution path

Track B (`live_deps.py`, `observation_lane.py`) still uncreated. When
it lands, queue heads + HIGH-band candidates + ALLOW decisions are its
input; nothing here grants authority or touches the network, so the
gate stands unchanged.

## Verification

202 new tests (67 surface, 55 intelligence, 23 assignment, 26
connector, 17 flow, 14 router additions), RED first (20 errors,
packages absent), GREEN after implementation with test-side corrections
only (namespace scoping, scrubber shapes, import paths, denial
boundary, two rubric pins). Full AEC: 666/666. `git diff --check`
clean, read-only VERIFIED, frozen files identical.

## Delivery

Commit `feat(aec): add research intelligence layer`; auto-push;
promotion request; await APPROVE. No main merge without it.
