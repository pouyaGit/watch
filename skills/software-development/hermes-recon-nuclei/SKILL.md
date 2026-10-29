---
name: hermes-recon-nuclei
description: "Use when running Nuclei from HERMES recon safely."
---

# HERMES recon — controlled external scanner execution (Nuclei)

`lib/nuclei.py` is the engine: capability audit, template trust classifier, local
inventory, method policy, profiles, argv builder, bounded executor, JSONL parser,
result validator, dedup and canonical mapping. `scripts/cycle.py:nuclei_scan_executor`
is the job body; `lib/store.py` holds `nuclei_executions` / `nuclei_templates` /
`nuclei_results`. Registration is three places: `JOB_CLASS`, the `budgets` dict, and
`planner.CEIL`.

The engine is a detection engine, **never an unrestricted command runner**. Every
gate below fails closed.

## Order of refusal (stop at the first that fires)

1. **Capability** — no usable binary ⇒ `NUCLEI_UNAVAILABLE`, zero results, zero
   findings. Never fabricate a result and never widen a safety ceiling so the
   feature looks capable; report the missing dependency as the blocker.
2. **Scope** — validate every target BEFORE launch; out-of-scope ⇒ `BLOCKED_SCOPE`
   with an empty argv (nothing starts).
3. **Template trust** — only `TRUSTED` templates survive ⇒ else `BLOCKED_TEMPLATE`.
4. **Result validity** — re-validate every result's host independently, so a
   redirect that left scope is rejected even if the binary ignored the flag.

## Template trust model

Classify by **inspecting content, never the filename**; three outcomes:

- `TRUSTED` — no dangerous capability, conservative tag, GET/HEAD only.
- `REVIEW_REQUIRED` — ambiguous: unknown tags, NO tags at all, oversized file
  (content not fully inspected), non-HTTP protocol, auth/fuzz/OOB/intrusive hints.
- `BLOCKED` — shell/command execution, file write/delete, reverse shell, credential
  theft, brute force, DoS, exploit payloads, OOB callbacks, raw requests with write
  verbs, scope-escape logic, traversal paths.

Rules that matter:

- `verify_template()` must raise unless `TRUSTED`, and every execution path goes
  through it. No bypass switch, not even behind a flag.
- **Untagged is not safe.** A template declaring no tags has demonstrated nothing;
  send it to `REVIEW_REQUIRED`, do not default it to `TRUSTED`.
- Ambiguity always resolves toward the stricter class.
- Blocked detection is heuristic — a novel dangerous template that avoids every
  pattern can classify TRUSTED. Treat the profile allowlist plus human review as the
  real control, and say so in the report.

## Method policy and template parsing

- Allowed: `GET`, `HEAD`. Block `POST/PUT/PATCH/DELETE/OPTIONS/TRACE/CONNECT`.
- **Match the loose YAML form `^\s*(?:-\s+)?method\s*:`.** Nuclei writes
  `  - method: POST`; anchoring on `^\s*method:` misses it, so the template parses
  as having NO declared method and is classified `TRUSTED`. That is a fail-open bug —
  a declared write method must make the template `BLOCKED`, and "no write method
  reached argv" is the thing to assert in tests.

## Subprocess and argument safety

- `subprocess.run(argv, shell=False)` only. argv is an explicit LIST built from
  validated values; never `shell=True`, never a concatenated string, never
  `eval`/`exec`. No user-controlled value may become shell syntax.
- **Probe the binary's own `-h` for supported flags and pass only those.** A flag the
  installed version does not advertise must not be assumed to have been applied.
- **The flag probe must parse single-character flags.** Parse each help line with
  `-{1,2}([A-Za-z][A-Za-z0-9-]{0,30})` so the `-o, -output string` list form yields
  `o` as well as `output`; a long-flag-only regex silently drops `-o` and the scan
  writes its JSONL nowhere.
- Validate targets as bare in-scope hostnames (no scheme, port, userinfo, spaces or
  metacharacters) and template paths as existing `.yaml/.yml` regular files inside an
  approved directory, size-bounded. Reject; do not sanitise.
- With no shell interpretation, `;`, `&&`, `$( )`, backticks, `|`, newlines and
  `../` in a target are refused at validation and again at `build_argv()`.

## Bounds, budgets and rate composition

- Hard ceilings live in CODE (`HARD_*`); env/config may only LOWER them. Clamp
  rather than trust configuration.
- The execution budget must stay under the scheduler's per-job cap so a worker is
  never wedged; keep scheduler timeout and HTTP timeout separate concepts.
- **Rate limiting is composition, not in-process enforcement.** An external scanner
  is a separate process: the Hermes limiter cannot observe its requests. Contain it
  with a low `-rate-limit` (at or below the configured per-target rate), process
  concurrency of 1, HTTP timeouts and a request budget — then DOCUMENT the residual
  gap instead of implying tight coupling.
- Bound output bytes, findings per execution, targets per job and templates per
  execution. Record truncation explicitly.

## Results into the canonical finding model

- Parse machine-readable output (JSONL). **Reject malformed records with a stated
  reason**; never guess at a partial object, never fabricate missing fields.
- Reject results whose host is out of scope and results from blocked templates.
- Dedup identity = target + template id + matched-at. Distinct endpoints stay
  distinct; do not collapse them.
- Carry an `engine` field plus template context (id, name, severity, type,
  matched_at, extracted_results, execution_id) onto the canonical finding.
- **Do not force an XSS source→sink model onto a non-XSS result** — leave
  `source`/`sink`/`source_to_sink_chain` NULL.
- Also confirm the shared scope helper is not merely called but actually applied:
  passing a raw truthy verdict object into a boolean check is the same fail-open
  class of bug as parsing policy out of text.
- **Template severity is not Hermes confidence.** Detection alone never proves
  exploitability: map high/critical → `medium` confidence, medium/low/info → `low`,
  carry severity through unchanged, and state the basis in the evidence
  (`exploitability NOT demonstrated`).
- Evidence must stand alone for human triage; if it does not, mark the result as
  requiring verification.

## Testing: deterministic fixtures, no production load

`scripts/m6_fixtures.py` builds a stub binary that mimics the real CLI surface
(`-version`, `-h`, `-jsonl`, `-o`, `-rate-limit`, `-concurrency`, `-timeout`,
`-retries`, `-disable-redirects`) plus a template corpus covering TRUSTED /
REVIEW_REQUIRED / BLOCKED and a local HTTP server. That exercises argv construction,
subprocess isolation, JSONL parsing, timeouts and budgets for real without
contacting a target.

- Expose a `dry_run=True` path that builds argv and executes nothing — that is how
  argv safety is asserted deterministically.
- Point the approved-template lookup at the fixture corpus with an env override
  (e.g. `HERMES_NUCLEI_TEMPLATE_DIR`); it only ever narrows the approved set, and
  every template still has to pass the classifier.
- Fixture the failure modes too: `hang` (timeout + forced kill), `crash` (non-zero
  exit), `malformed` (garbage JSONL), `outofscope` (redirect leak), `many`
  (output/finding budget).
- Run the executor through the real `execute_job()` against an isolated `HERMES_DB`
  to prove wiring, dedup on the second run, and `BLOCKED_SCOPE` for a planted
  out-of-scope host — in a scratch DB, never production.
- **A local fixture server on `127.0.0.1` must still be REFUSED**: scope outranks
  local reachability. That is a good end-to-end assertion.

## Cross-cutting gate trap

`scope_guard.check(host)` returns `(verdict, target_dir)` where `verdict` is the
STRING `IN_SCOPE` / `OUT_OF_SCOPE` / `UNKNOWN`. Both members are truthy, so
`ok, label = check(h)` then `if not ok` accepts EVERY host — including
`attacker.example.com` — and out-of-scope scanning proceeds silently. Write an
explicit helper that compares `verdict == "IN_SCOPE"` and treats `UNKNOWN` as
refusal, and use it at every call site. A gate that parses its own policy out of
  text fails open the same way: always assert the REAL invariant (no execution
  primitives, no write method in argv) rather than the absence of a token.

## Runtime bootstrap — installing the binary without Git

When `capability_audit()` reports the dependency missing, that is a fixable setup
state, not a permanent blocker. Install the **official release binary**; never a
repository clone.

1. Read the latest release metadata (`api.github.com/repos/projectdiscovery/nuclei/releases/latest`)
   and pick the `linux_amd64.zip` asset plus its `*_checksums.txt`.
2. Download BOTH with `curl -fL`. **Never `curl … | sh` or `wget … | bash`** — no
   script is ever piped to a shell.
3. **Verify SHA-256 against the official checksums file and refuse to install on
   mismatch.** An unverified binary is an untrusted engine in a security tool.
4. List the archive before extracting, then extract with Python `zipfile`
   (`unzip` may be absent). Extract only the binary, not the bundled README copies.
5. `install -m 0755` into a directory already in the engine's `SEARCH_PATHS`
   (`/usr/local/bin/nuclei`), then confirm exactly ONE binary exists across all
   candidate paths — a duplicate shadowing on `PATH` is a silent divergence.
6. Re-run `capability_audit()` and record version, path, source and permissions from
   it. Do NOT re-implement discovery for the install check; the audit is the check.
7. Do not install a language toolchain to build from source when a release binary
   exists. Do not touch scope, rate or safety configuration to accommodate the
   binary.

**Templates: author a minimal reviewed set by hand** under the approved directory;
never import a third-party corpus. Start with one or two deterministic, read-only
detection templates (single GET/HEAD, header or body matcher, no parameters, no
auth). The profile allowlist plus human review is the real control.

Full commands, the real-binary safety matrix and the evidence-capture recipe:
`references/real-binary-bootstrap.md`.

## Live verification with the real binary

- **Prove the process really ran with an INDEPENDENT observation**, not the
  executor's own report: run a watcher thread that samples `ps -eo pid,ppid,etime,rss,args`
  while the scan is in flight and record PID, argv and RSS growth. A self-reported
  `exit_code` proves nothing about whether a child existed.
- **Each out-of-scope case must be proven to spawn NO process** (sample `ps` during
  the attempt), not merely to return `BLOCKED_SCOPE`. "No process started" is the
  assertion that matters; an exception-free return is not.
- **Zero results is a valid outcome.** When the engine genuinely matches nothing,
  say so and stop — never manufacture a finding to demonstrate the pipeline.
- Prove the JSONL → validator → canonical finding → persistence → dedup path against
  a **copy** of the production DB, then keep production clean. Assert the second run
  creates 0 new findings while the identity's `seen_count` increments.
- Re-verify the fatal safety cases (`localhost`, private IP, metadata endpoint,
  attacker domain, POST template, malformed result) with the REAL binary after
  installing it; the fixture suite does not cover a real engine's behaviour.
- Sweep for orphaned child processes afterwards (`pgrep` must find none). A real
  scanner that times out can outlive its worker if termination is not forced.

## Status honesty

Template updates/downloads are a separate, explicitly reviewed action — never
automatic, per cycle, or triggered by a scan. If the runtime dependency is absent,
deliver the layer, the fixtures and the capability audit, then set the ready-status
to NO with the dependency named as the exact blocker — a layer never exercised
against the real binary is not "ready". Then remove that blocker: bootstrap the
binary (above) and re-verify, rather than leaving a re-issued milestone parked on a
setup state you can actually fix.

**Never encode an environment fact as a test assertion.** A suite that asserts
`available is False` passes only while the dependency is missing and goes red the
moment it is installed — a stale assertion, not a regression. Assert the INVARIANT
instead: when available, the audit reports a real path and a version; when not, it
reports an explicit reason and no path. Then force the unavailable branch explicitly
(temporarily stub the binary finder) so that path stays covered. Fix the assertion in
place; never relax a safety check to make a suite green, and say plainly in the report
which assertions you changed and why.
