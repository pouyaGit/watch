# Adaptive Outcome Loop Layer (M23 reference model)

How to build a milestone whose job is to close a loop between existing authorities —
measure what became of a routed decision and derive a bounded next step — without becoming
a second prioritizer, a second learning engine or a second orchestrator.

## 1. When such a layer is justified

Build it only when ALL of these are measurably true:

1. An upstream milestone produces a routed decision, and **nothing records what became of it**.
2. The outcome facts **already exist** in other milestones' tables — you are adding a READ and
   an ATTRIBUTION, not a new capability.
3. No existing milestone owns "the cross-milestone observation of a routed decision". (Each
   owner records its own outcome; nobody reads them back together.)

If (2) is false — if nothing records outcomes at all — the right milestone is an outcome
recorder, not an adaptive loop. Building the loop first produces a layer that permanently
reports `INSUFFICIENT_DATA`.

## 2. Phase 0: audit the OUTCOME stage before designing anything

The design input is the **terminal** surface, not the input surface. Measure it:

```
per surface: rows, and the DISTRIBUTION over the status vocabulary
terminal = how many objects actually reached a resolved/closed state?
```

A real measurement from HERMES production at M23 time:

| Surface | State | Terminal |
|---|---|---|
| M13 `hunt_outcomes` | 25 NOT_EXECUTED, 25 EXPIRED, 1 PARTIALLY_USEFUL | **0 USEFUL** |
| M16 case threads | 30 total | **0 RESOLVED** |
| M15 `research_loops` | 10 CANCELLED, 15 ROUTED | **0 RESOLVED** |
| M18 `orchestration_routes` | 20 total | **0 non-WAITING** |
| M21 `recon_changes` | 124 baselines | **0 material changes** |

Conclusion: measuring only "did a USEFUL outcome arrive" would never measure anything.
**Correlate every surface that already records an outcome**, and give silence its own state.

## 3. The pipeline

```
COLLECT -> NORMALIZE -> CORRELATE -> MEASURE -> CLASSIFY -> ADAPT -> BOUND -> ROUTE -> PERSIST
```

- **COLLECT** — only objects the upstream actually routed (`routed_to` non-empty). Never invent
  a subject; a layer that can create its own work cannot be bounded or falsified.
- **NORMALIZE** — canonicalize every identity field once. Bind closed vocabularies to the
  OWNING milestone's constants by import, never by re-typing them: a second hand-written copy
  silently stops recognizing values the owner adds.
- **CORRELATE** — read each surface through its owner's public accessor. Recompute nothing.
- **MEASURE** — outcome state + a content-addressed evidence fingerprint over SEMANTIC facts
  only (never a row id, never a clock, never a run id).
- **CLASSIFY / ADAPT** — closed vocabularies; the condition table IS the policy and its ORDER
  IS the precedence.
- **BOUND** — one funnel; see §6.
- **ROUTE** — advisory, through existing public APIs; see §7.
- **PERSIST** — append-only observation/decision/route/history.

## 4. The outcome vocabulary

Closed, small, and each value must be REACHABLE by some rule:

| State | Meaning |
|---|---|
| `TERMINAL` | reached a stable end state; do not act again |
| `POSITIVE_PROGRESS` | something genuinely moved |
| `PARTIAL_PROGRESS` | evidence changed but did not resolve the thread |
| `NO_PROGRESS` | response rows exist and none moved |
| `BLOCKED` | an explicit statement by an owning authority, or a gate, is the blocker |
| `CONTRADICTORY` | authority answers disagree |
| `INSUFFICIENT_DATA` | not enough history to judge |

An unknown value is **rejected**, never coerced into a decision.

## 5. Precedence — the part that is always wrong first

Correct order, and the reason for each boundary:

1. **TERMINAL** — the strongest statement; nothing should outrank it.
2. **POSITIVE / PARTIAL / CONTRADICTORY** — measured movement or measured disagreement.
3. **NO_PROGRESS** — measured absence of movement. **Must outrank an in-flight inaction.**
4. **INSUFFICIENT_DATA** (the measurement floor) — everything evidence-bearing sits ABOVE it.
5. **bare in-flight fallback** (`BLOCKED` from an all-`WAITING` route) — the weakest evidence.

Three defects this ordering fixes, each of which shipped green under a wrong order:

- An in-flight `WAITING` route checked early **masked** a measured `NO_PROGRESS`, making that
  state unreachable for any object with a live route.
- A measurement floor checked early **buried explicit authority statements** — a case in
  `WAITING_HUMAN` reported as "wait longer". A statement by the owner is a measurement, not
  silence.
- A **neutral** value (`ACTIVE`) must not clear the floor on its own: existence is not outcome,
  or a brand-new thread is declared productive/unproductive before anything was observed.

## 6. Bounds

Every ceiling must be:

- **enforced** — a place that REFUSES, not merely a constant that appears in a summary;
- **tested by seeding past it** — otherwise it is fiction;
- **observable under the documented name** — record the ceiling constant, not the internal
  budget key (`routes` means nothing to an operator or a test);
- **un-raisable by environment** — accept an override only when `0 <= v <= default`.

The trap: a constant used as a read `LIMIT` everywhere and as a ceiling in the summary looks
bound-checked and is not. Grep each ceiling for its refusal site.

## 7. Routing and refusals

- Route only where the destination's **existing** public API supports the operation.
- A refusal is **recorded verbatim** (`route_state=REFUSED` + error text) and never worked
  around.
- Add **no** policy, weight, dimension or threshold to another milestone. If the audit does not
  justify a change, adding one anyway is how a second prioritizer is born.
- An alert gate must be **reachable**: a gate nothing calls is dead code, and the escalation is
  recorded while the analyst is never told. Assert reachability by firing the real path and
  requiring the downstream row to appear.

## 8. Identity rules

| Object | Identity basis | Never include |
|---|---|---|
| thread / observation | content-addressed (semantic fields) | clock, row id, run id |
| observation | the SEMANTIC measurement (state + evidence) | incidental `before_state`, prose |
| history row | the transition; for an adaptation, state + adaptation | incidental `before_state` |
| run | clock (a run IS an event) **+ collision discriminator** | — |

A clock-only run id silently REPLACES a run when two passes land in the same second.

## 9. Test design: the failure modes that produce false greens

- **Vacuous predicates.** `cond or count >= 0` is true for every input. Assert non-vacuity
  explicitly: the check must be able to FAIL.
- **Digesting `repr(sqlite3.Row)`** compares MEMORY ADDRESSES. Convert to `dict(row)`.
- **Truthy-string verdicts.** `check()[0] == "OUT_OF_SCOPE"` is truthy; compare to the enum.
- **Scanning prose for capabilities.** Strip string constants via AST, then scan; self-test the
  scanner on a known-bad snippet.
- **Fixtures that do not vary what the engine reads.** Read the fingerprint's inputs from the
  code, then vary those — or content-addressed dedup correctly refuses and ceilings look
  unreachable.
- **Reading the live DB twice.** Attribute the running daemon's writes to your milestone. Use
  copy-pre vs copy-post.
- **Wrong constant/table/return types.** Verify names against the live schema and the real
  signatures before asserting; a wrong assertion makes a working feature look broken.
- **Stray edits during a certifying run.** Stop it, freeze hashes, run once, re-verify hashes.

## 10. Certification checklist

- [ ] Phase-0 audit written and its decisive finding stated as measured numbers
- [ ] architecture justified against "no second prioritizer/learner/orchestrator/planner"
- [ ] closed vocabularies, owner-bound, unknown values rejected
- [ ] every measurement rule and every adaptation reachable (prove with a no-write simulate)
- [ ] every ceiling enforced, seeded past, named, env-tighten-only
- [ ] idempotency: same input twice → no duplicate observation/decision/history
- [ ] restart recovery: batch close + a fresh interpreter against the same state
- [ ] zero network / subprocess / socket / DNS, refusal-tested
- [ ] live empty path honest: reports its reason, fabricates nothing, still records its run
- [ ] isolated populated path proven through the REAL executor dispatch
- [ ] snapshot: ZERO DELETIONS (milestone) + (all actors), protected state non-decreasing
- [ ] live schema == fresh-DB schema (count AND set) after a daemon restart
- [ ] full regression run once against frozen hashes, every failure classified
- [ ] hashes re-verified after the run
