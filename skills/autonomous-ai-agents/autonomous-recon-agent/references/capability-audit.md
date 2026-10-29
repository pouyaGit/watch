# Capability audit of a deployed recon agent

For "what can this system actually do?" — audit only, read-only probes, no installs, no schedule or scope
changes, no payloads. The deliverable is a capability map, not a code review.

## 1. Establish invocation, not existence

Four states per capability, and the report must say which one holds:

- **NOT INSTALLED** — no binary, no reference in the tree.
- **AVAILABLE BUT UNUSED** — the binary/module exists and nothing calls it (or only a helper supports a
  path nobody requests).
- **INVOKED** — a real call site exists; cite file:line.
- **PRODUCING PERSISTED RESULTS** — a table/file shows rows attributable to it.

Where to look:

- Call sites: search `subprocess\.(run|Popen|check_output)|os\.system|shutil\.which` over `lib/` and the
  executor script; ignore scratch `tmp_*.py` and audit `verify_*.py` helpers when counting production use.
- Executor branches: search `if jtype ==|elif jtype ==` in the cycle script — that list is the authoritative
  job-type set; each branch shows the command, its persistence call and its coverage mark. Compare it with
  the planner's job-type ceilings: a planned type with no branch is unrunnable.
- Model/agent invocations are NOT in the tree: they live in the host scheduler (cron job pins plus
  `monitor_script` / `no_agent` flags), so audit `jobs.json` for those, not the repo.

## 2. Runtime evidence per capability

- Per-module work counts: `SELECT module,COUNT(*) FROM activity_events WHERE timestamp > <now-24h> GROUP BY module`.
- Job accounting: `SELECT status,COUNT(*) FROM jobs GROUP BY status` plus `MAX(finished_at)`.
- Artifact counts: `assets`, `http_samples`, `js_samples`, `js_assets`, `urls` grouped by `source`
  (provenance is the honest story of where URLs/parameters came from), `xss_candidates`, `findings`,
  `correlation_groups`, `finding_reviews`; plus per-target files under `targets/<name>/`.
- Scheduler truth: `jobs.json` fields `last_run_at`, `last_status`, `state` (paused/scheduled), `paused_at`,
  `monitor_state` (null together with `repeat.completed = 0` means the agent has never run),
  and the host's cron `executions.db` / `deliveries.db` for execution and delivery outcomes.
- Passive-source health: the module's `source_status()` / `active_sources()` show which sources are live
  versus auto-disabled and until when.

## 3. Safe probes

- **Serialisation / refusal**: hold the worker's single-instance lock from a helper process (`fcntl.flock`
  on the cycle lock file), invoke the worker, and capture the exit code WITHOUT a pipe
  (`cmd > /tmp/out 2>&1; echo $?`). The skip code plus the log line is the proof and no request is made.
- **Pre-dispatch gate**: run the monitor digest path twice and compare output byte-for-byte; check the
  reservation store is empty and a DEFERRED record exists.
- **Planner/queue behaviour**: run the existing selftest against a COPY of the live DB (`HERMES_DB=<tmp>`).
- **Limit claims**: read the enforcement code and grep each constant for a read site before repeating it.
- **Tool identity**: check the shebang or `--version` — a same-named binary in a language venv is often a
  different product than the upstream scanner it resembles.

## 4. Distinctions the report must keep

- Probing vs crawling: fetching the root page (or stored URLs) is not crawling; a crawler needs a frontier and
  a visited set that reaches depth >= 2.
- Crawling vs endpoint extraction: regex over downloaded JS/HTML is extraction, not crawling.
- Parameter presence vs discovery: parameters already in collected URLs are collection; discovery means new
  names plus a probe that shows the name is honoured — and a synthetic blank-value GET is not brute force.
- Detection vs parsing: a regex that flags a file type (source map, OpenAPI, GraphQL) is not parsing it.
- Static analysis vs dynamic confirmation: static source/sink reasoning never confirms exploitability.
- "An LLM could write X" vs a pipeline: only stores + validates + runs + links to a finding counts.

## 5. Report skeleton

1. Executive summary: one paragraph on what the system is, plus the tool count actually invoked.
2. Tool inventory split ACTUALLY INVOKED / AVAILABLE BUT UNUSED / NOT INSTALLED (with command, executor,
   input, output, persistence, trigger, scope, rate).
3. Pipeline walk per stage with executor and persistence.
4. Per-capability sections, each with an explicit NOT IMPLEMENTED where that is the answer, and a
   supported/tool/depth/scope/persisted/production-used breakdown.
5. Capability matrix: `Capability | Status | Tool | Executor | Production used | Main gap`.
6. Top gaps grouped by area (discovery, crawling, parameters, JS, research, automation, finding quality,
   operations) — grouped, not ranked by an invented score.
7. Roadmap per item: WHY / CURRENT GAP / IMPLEMENTATION LOCATION / DEPENDENCIES / RESOURCE COST /
   SAFETY IMPACT / EXPECTED OUTPUT.
8. Explicit answers to every question asked, in the language it was asked in.
