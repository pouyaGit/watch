---
name: hermes-recon-model-routing
description: "Use for HERMES research model routing."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [HERMES, recon, ai-research, routing, budgets, fallbacks]
    related_skills: [hermes-recon-hardening, hermes-recon-milestones, test-driven-development, read-only-codebase-audit]
---

# HERMES AI Research model routing

Use this skill for changes that select, fall back from, or account for an AI Research language model. It covers provider resolution, native-free fallback, fail-closed behavior, and the shared request budget.

## Standing gates

- Work on the live install only when the brief permits it. Do not use repository-management commands, GitHub, manual scheduler triggers, artificial research runs, target traffic, exploitation, fuzzing, or synthetic production findings.
- Preserve M1–M24 semantics, M17/M18/M24, Finding Routing, M6/Nuclei, research safety gates, and Jev's shadow-only role unless the brief explicitly changes that boundary.
- Do not print API keys, bearer values, tokens, or `.env` contents. Record variable names and `PRESENT — VALUE REDACTED` only.
- Do not claim a live model is available from a catalog entry, environment variable name, historical usage row, or successful unrelated job. Availability requires a usable resolved runtime or a real validation run.
- Do not claim PASS while any required regression, protected-state comparison, post-edit search, or report artifact is missing. Use `INCOMPLETE` and list the unverified surfaces.
- Do not restart a live daemon as an implicit verification step. A long-running process may still hold old code; report runtime loading as unverified unless restart was authorized and verified.

## Procedure

1. **Discover before editing.** Trace the actual entrypoint and interpreter, then provider selection → provider request → parser/safety pipeline → request accounting. Inspect active Hermes config, fallback config, service units, scheduler metadata, and environment names without exposing values. Capture pre-edit hashes and protected database row/ID digests when the brief bans repository history.
2. **Resolve the primary from Hermes.** Read the installed Hermes configuration/runtime resolver and preserve its actual model/provider identifiers. Do not infer names, scan arbitrary YAML blocks, or let a legacy research-specific endpoint/model override silently replace the resolved default. A provider is a route only when its endpoint and credential/token source are usable.
3. **Discover free candidates from the installed catalog.** Query Hermes' current free-model catalog and runtime resolver. Record the exact returned identifiers and whether a runtime is usable. Keep candidate discovery deterministic and bounded; never invent a provider, endpoint, model, or key.
4. **Define the contract in tests first.** Specify primary success, primary transport failure → free, both unavailable → fail closed, malformed/content failure → no provider switch, explicit fixture mode, redaction, deterministic repeatability, and the exact budget boundary. Run the new tests RED before production code.
5. **Implement the smallest adapter.** Keep automatic production mode separate from explicit mock/fixture mode. Advance only on transport/provider-unavailable outcomes. Once a response reaches the parser, keep bounded retries on that route and apply the existing schema/grounding/safety pipeline unchanged. Return provider-unavailable with resumable work when routes are exhausted; never substitute a mock in automatic mode.
6. **Make the request budget authoritative.** Pass `remaining = cap - already_sent` into each analysis call. Count every physical request, including fallback and retry, in one shared bucket. Test 21, 1, and 0 remaining; a pre-call `can_llm()` check alone is not enough.
7. **Run focused and mandated regressions.** Use an offline scripted matrix with HTTP primitives poisoned, temporary state, and no real completion request. Then run the existing parser, source, and agent suites plus the brief's M17/M18/M24, Finding-Routing, routing, budget, and Telegram checks. Record exact test names and counts; classify pre-existing/environmental failures separately.
8. **Audit and report.** Re-hash protected files, compare protected row counts and ID sets, search again for paid-route references, and distinguish the isolated research path from protected complex paths. If no natural run exercises a real route, report `PENDING_NATURAL_RUN`, not PASS. Write the mandated report verbatim and stop.

## Scheduled consumer remediation

When a scheduled job is the only proven consumer of a paid route and no existing non-paid backend preserves its behavior, use the scheduler's native `pause` as the minimal reversible remedy; do not remap `model` or `provider`. Trace reverse control edges first: pause a budget/admission guard too if it can resume the target jobs, and verify that it cannot reopen the path. Preserve prompts, model, provider, schedule, and rollback metadata. Report a paused route as dormant-but-routable, not removed; any manual resume reopens the paid path.

For a scheduler pause/remove remediation, capture a read-only boundary timestamp and verify after it: target `enabled/state`, no in-flight execution, no new target execution rows, no new target usage rows, and no router/provider evidence of the paid route. Do not use `run`, `resnap`, or a restart merely to prove the fix. Scope `no active path` to the paused execution path; separately disclose dormant definitions and any alias that remains available in the router.

## Evidence closure and final-report discipline

- **Separate implementation closure from evidence closure.** If the brief says the implementation is already verified, do not edit `lib/`, scripts, configuration, scheduler files, or tests while repairing evidence. Record implementation hashes before report generation and re-hash them after the last report/evidence write.
- **Preserve the requested schema count.** Run the authoritative SQLite enumeration twice on the same read-only connection and retain both raw results. If the brief expects the raw count, do not silently substitute an application-only count after excluding `sqlite_%` tables; record the raw count, excluded names, and any filtered count separately. A required-count mismatch keeps the result `INCOMPLETE` until reconciled.
- **Make the report and JSON prove each other.** Every terminal field must be present in both artifacts and derived from the same captured snapshot. Treat a test-fixture edit as a file change even when production implementation is untouched; never claim “no files changed” from an implementation-only scope.
- **Separate Jev code presence from Jev configuration.** The existence of `lib/jev.py`, an import, or a sanitizer call is not Jev configuration. Report config/environment presence separately from pre-existing code, and never expose values.
- **Verify the terminal block mechanically.** Parse the JSON, assert required report sections and terminal keys, assert repeated schema enumeration equality and `quick_check`, compare report values with the JSON snapshot, and choose `PASS` only after all assertions pass. Any mismatch is `INCOMPLETE`, not a cosmetic correction.

## General pitfalls

- **Do not confuse subsystem hits with the request path.** A paid route in a complex cron job, budget ledger, or Finding-Routing module may be unrelated to AI Research; report the boundary and leave protected code unchanged.
- **Do not make route selection and request accounting separate authorities.** Route adapters can emit metadata, but the runner's single remaining-budget value must cap every physical request.
- **Do not let content failures switch providers.** A malformed response is not evidence that the next route is better; switching can bypass the safety contract and double-request a single article.
- **Do not call a static catalog “available.”** Catalog discovery proves candidacy; resolved credentials and an actual response prove usability.
- **Do not use a focused 12-case matrix as the only regression.** It catches the new contract but cannot certify untouched M1–M24, scheduler, database, or notification behavior.
- **Do not hide incomplete verification in a confident status block.** Every unknown test, runtime load state, post-edit integrity comparison, or evidence/report mismatch remains explicit in the final report.
- **Valid primary must short-circuit fallback:** When primary Jev returns a valid, bounded decision, short-circuit immediately. Do not make an LLM fallback call or burn token budget when primary evaluation succeeded (`VALID JEV -> ZERO LLM CALLS`).
- **Isolate test harnesses from live model latency:** In offline or frozen test runs (e.g. `MODE_FROZEN_COPY` or `/tmp/` databases), do not make live external HTTP calls to Jev or LLM providers unless explicitly instructed via environment variables. Inject deterministic test providers/mocks to prevent test runner timeouts.
- **Mock function signature completeness:** When stubbing capacity policies or subsystem metrics in test harnesses (such as `capacity_policy()`), accept `**kwargs` rather than zero arguments. Real consumers (like `execplane.allowed_for()`) pass parameters (e.g. `max_recon=...`), causing `TypeError` on strict zero-argument mocks.

See `references/routing-validation.md` for the discovery checklist, test matrix, budget boundary recipe, and evidence fields.
