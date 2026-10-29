# Routing cleanup and restoration: reusable protocol

Use this reference when a milestone corrects a provisional provider/routing change in a live system, especially when the requested outcome is to restore an existing configured default rather than add discovery, fallback, or rotation.

## Corrective-scope sequence

1. **Read the corrective brief literally.** A named accidental scope drift is a signal to audit the prior implementation and remove only the named additions. Do not preserve provisional behavior merely because its tests passed.
2. **Map the execution path before editing:** scheduler/daemon → wrapper/runner → adapter → configured runtime → transport. Inspect unit files, environment-variable sources, and cron commands for provider/model overrides.
3. **Classify every provider reference by role:** Research execution, separate scheduled complex jobs, Finding Routing, historical accounting, test fixture, documentation, and dead/unused configuration. Record both location and execution effect. Do not claim global removal when unrelated references remain.
4. **Define the single route contract:** configured default model/provider → existing provider runtime → fail closed. No catalog lookup, free candidate, fallback, provider rotation, or silent fixture substitution is part of this contract.
5. **Preserve explicit test fixtures.** `mock` and `unavailable` may remain selectable only when passed explicitly by tests; automatic production mode must return the unavailable provider when the configured route cannot be resolved.

## Evidence and regression gates

- Capture a read-only baseline: protected SHA-256 hashes, DB `quick_check`, table count, relevant row counts and ID digests, current model/provider, scheduler gate values, and process/service state. Re-check all of them after the final edit.
- Use isolated fixtures for tests: temporary DB/state/skills, file notification sink, poisoned network primitives where applicable, and no research-runner or scheduler trigger. Assert configured-default selection, provider resolution, no DeepSeek/Jev/free route, fail-closed behavior, JSON contract, budget constant, retry semantics, and protected-surface hashes.
- Keep legacy fallback tests out of the authoritative suite. If an old test entry point must remain, turn it into a compatibility shim that runs the current contract rather than preserving obsolete expectations.
- A malformed copied WAL/database fixture is not a product regression. Re-run that suite once in a clean isolated environment and verify production `quick_check`; classify it `ENVIRONMENTAL` only with that evidence.
- A running daemon can change findings/alert counts while the milestone runs. Compare append-only IDs/row counts and timestamps; unchanged Research-specific counts and intact protected IDs are stronger evidence than absolute live counts. Never call live churn destructive without a deletion/id-shrink proof.

## Report closure

The report is a deliverable, not an afterthought. After the last source edit and final test run:

1. Recompute final hashes and DB evidence.
2. Run the daemon load/health check without triggering Research.
3. Write the report.
4. Programmatically verify every required section and the exact terminal status block.
5. If any cosmetic or evidence edit follows, invalidate the previous report/evidence and regenerate them; otherwise `INCOMPLETE` is the honest result.

Never write `READY FOR PRODUCTION: YES` when a required test, execution audit, integrity check, or report format remains unverified.
