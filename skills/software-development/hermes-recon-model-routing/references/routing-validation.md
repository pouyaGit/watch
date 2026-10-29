# Routing validation reference

## Discovery checklist

- Identify the real entrypoint and interpreter. Check whether the daemon, scheduler, or fixture path is responsible.
- Read the active Hermes default/provider and fallback metadata with read-only CLI/config APIs. Record exact model/provider identifiers only.
- Trace `get_provider` (or equivalent) through `analyze_artifact`, provider transport, parser, validation, and persistence.
- Search source, service units, scheduler metadata, and environment names for the paid route. Classify each hit as isolated task path, protected complex path, configuration-only, or historical data.
- Before editing, hash protected source/config files and record row counts plus ID-set digests for protected tables.

## Deterministic fallback matrix

Use temporary state and scripted providers. Poison all provider HTTP constructors/entry points so a real request fails immediately.

1. Primary succeeds: exactly one request; no free call; primary metadata persists.
2. Primary is locally unavailable: no request for that route; free candidate is tried if usable.
3. Primary times out or returns a transport/HTTP failure: one primary request, then deterministic free transition; count both.
4. Primary returns malformed or schema-invalid content: no switch to free; allow only the existing same-route bounded retry, then fail closed.
5. Free is unavailable or fails: no third route, no mock rescue, work remains resumable.
6. Both routes are unavailable: zero requests and an explicit provider-unavailable result.
7. Legacy paid research override: it cannot enter automatic route metadata.
8. Provider error includes a secret: the secret is absent from result metadata.
9. Repeat the matrix: route order, counts, outcome, and failure class are identical.

## Budget boundary recipe

Keep the existing cap declaration and test the shared token bucket:

- With 21 remaining, primary failure plus free success consumes two physical requests.
- With 1 remaining, primary failure consumes the final slot and no free request is sent.
- With 0 remaining, there are zero provider calls and no parser-side substitute.
- A response that was received and then failed validation never changes route; any allowed retry remains on the same route and is counted.

Pass the remaining budget into each article call. Do not rely only on a pre-call `can_llm()` predicate.

## Evidence fields

Record, without secrets:

- discovered primary provider/model and source of truth;
- each discovered free candidate and whether a usable runtime was resolved;
- route attempt order, route kind, provider, model, sent flag, and failure class;
- actual request count and remaining budget after each case;
- target/request/network calls made by the milestone (expected zero for offline validation);
- pre/post protected hashes and database row/ID digests;
- exact focused and regression test commands and counts;
- pre-existing versus introduced failures;
- natural-run validation state (`PASS`, `PENDING_NATURAL_RUN`, or `FAILED`).

## Status rule

A new offline matrix is necessary but insufficient. If any mandated regression, protected-state comparison, post-edit search, runtime-load check, or report artifact is incomplete, the milestone is `INCOMPLETE`; do not issue a production-readiness verdict.
