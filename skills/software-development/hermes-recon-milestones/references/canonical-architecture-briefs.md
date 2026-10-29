# Canonical architecture briefs (Stage-series milestones)

Use when a brief opens with a CANONICAL ARCHITECTURE — MUST READ FIRST section
naming `/home/ubuntu/HERMES_AI_RESEARCH_JEV_ARCHITECTURE.md`.

## Rules that cost time when missed

- The canonical file lives at `/home/ubuntu/HERMES_AI_RESEARCH_JEV_ARCHITECTURE.md`
  and is NEWER than the in-tree copy
  `/root/hermes-recon/HERMES_AI_RESEARCH_JEV_ARCHITECTURE.md`. Always read the
  /home/ubuntu one; note the staleness of the in-tree copy in the report but
  never update the copy yourself unless the brief says so.
- Read it FIRST and hold the intent for the whole milestone: LLM = read/reason,
  Jev = classify/gate/route/score (shadow -> advisory -> gated, never an
  authority), Hermes = enforce/persist/audit, Human = verify/submit; M1–M24 keep
  their authority; no Knowledge Graph / Vector DB / RAG / new scanner / new
  crawler; scheduler singleton with persistent state; additive persistence only.
- The report must carry an ARCHITECTURE ALIGNMENT block with the exact fields:
  CANONICAL ARCHITECTURE READ: YES · TARGET ARCHITECTURE UNDERSTOOD: YES/NO ·
  CURRENT MILESTONE ALIGNMENT: PASS/PARTIAL/FAIL · ARCHITECTURE CONFLICTS:
  <none/list> · FUTURE ARCHITECTURE IMPACT: <short>. Add it even when the
  milestone was delivered before the requirement arrived (append it to the
  already-written report).
- Map alignment to section numbers (§22 resource budget, §23 scheduler
  singleton, §24 additive persistence, §28 run-specific Telegram, §39 'we
  deliberately do not build', §42 target three-column RECON/RESEARCH/
  INTELLIGENCE) — section citations are the proof, not prose agreement.
- Never silently resolve a conflict between the brief and the canonical doc:
  implement within the milestone scope, and record the conflict in
  ARCHITECTURE CONFLICTS with the precedence you applied (the stage brief wins
  for its own scope, e.g. Persian pulse text vs the English sample in §28).
- Stage-series briefs name later stages explicitly as out of scope (e.g.
  resource balancing, DNS brute force). Deliver exactly the current stage and
  mark the untouched later-stage items by name in the FINAL REPORT fields
  (e.g. RESOURCE_BALANCING_IMPLEMENTED: NO) rather than leaving them implicit.
