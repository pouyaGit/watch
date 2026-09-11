# Stage R23.1 — Controlled Real Research Validation

## 0. What this was

A controlled **public-research-only** validation of the R23 autonomous research
worker over the persisted CVE-2026-1557 reference corpus. No target was
contacted. No active validation, no Nuclei execution, no PoCs, no browser
automation, no 5B–5J, no production findings, no alerts, no Git operations.

During the validation two safety gaps were found and minimally remediated (see
section 11). The remediations are disclosed here; all checks below were run on
the remediated code.

## 1. Exact commands

Environment (process-local; **defaults unchanged**):

```
WATCH_RESEARCH_ENABLED=true
WATCH_RESEARCH_NETWORK=true
WATCH_RESEARCH_LLM=true
WATCH_RESEARCH_LOCK=/opt/watch/ai_data/research/agent/.watch-research.lock
```

`WATCH_RESEARCH_LOCK` was overridden only because the default
`/run/watch-research.lock` is not writable by this user outside the systemd
`RuntimeDirectory=watch-research`; the default lock path and policy were not
modified.

Plan 1:

```
python3 -m ai.research_cli agent run --plan r22-38d26f10681e9a0f --network --json
```

Plan 2:

```
python3 -m ai.research_cli agent run --plan r22-fda96966ea7af4ae --network --json
```

`--force` was **not** used.

## 2. Scheduler / window result

- `WATCH_RESEARCH_ENABLED` default is `false`; it was set to `true` for this
  controlled run only. The default scheduler policy was not modified.
- Window: `18:00-00:00 Asia/Tehran`. Run times were 20:19–20:57 Tehran, so
  `in_window=true`. The window policy was therefore honored; `--force` was not
  needed and not used.
- Run record fields: `enabled=true`, `in_window=true`, `network=true`,
  `llm=true`, `skipped=null`, `failures=[]`.

## 3. Source results (network scope)

Only the 6 persisted CVE reference URLs already present in
`ai_data/research/CVE-2026-1557.cli.json` were considered. No new URLs were
discovered; no program/target URL was fetched. 6 sources per plan:

| # | Source | Type | Result | Reason |
|---|---|---|---|---|
| 1 | plugins.trac.wordpress.org/browser/.../image_handler.php#L28 | vendor | FAILED | HTTP 403 (bot protection) |
| 2 | plugins.trac.wordpress.org/browser/.../SBOutputFile.php#L33 | vendor | FAILED | HTTP 403 |
| 3 | plugins.trac.wordpress.org/browser/.../WPResponsiveImages.php#L265 | vendor | FAILED | HTTP 403 |
| 4 | wordfence.com/threat-intel/vulnerabilities/id/22c6f81b-... | wordfence | FAILED | HTTP 202, empty body |
| 5 | github.com/projectdiscovery/nuclei-templates/pull/15592 | github | AVAILABLE | body extracted (6000-char cap) |
| 6 | github.com/crowdsecurity/hub/pull/1749 | github | AVAILABLE | body extracted (6000-char cap) |

Successful: 2/6 per plan. Failed: 4/6 per plan (recorded, non-fatal;
`RESEARCH_PARTIAL`). Failure reasons were confirmed with an independent
read-only probe of the same persisted URLs (403 / empty body).

## 4. Result status and artifacts

Both plans: `status = RESEARCH_PARTIAL`, `production_finding = false`,
`rule_version = r23-1`.

Plan 1 (`r22-38d26f10681e9a0f`, dell, `rl-af7ecfba1a86fc83`):

- run: `run-20260910T165753Z`
- result: `ra-ad5962a468434a5d`
- sources 6 (2 available / 4 failed), evidence 7, inferences 6, unknowns 17,
  nuclei candidates 2

Plan 2 (`r22-fda96966ea7af4ae`, indeed, `rl-d1d66e2ee9d8467c`):

- run: `run-20260910T165508Z`
- result: `ra-7651e519f46b47e3`
- sources 6 (2 available / 4 failed), evidence 6, inferences 5, unknowns 17,
  nuclei candidates 2

Generated files:

```
ai_data/research/agent/r22-38d26f10681e9a0f.r23-1.json
ai_data/research/agent/r22-38d26f10681e9a0f.r23-1.md
ai_data/research/agent/r22-fda96966ea7af4ae.r23-1.json
ai_data/research/agent/r22-fda96966ea7af4ae.r23-1.md
ai_data/research/agent/runs/run-20260910T165753Z.json
ai_data/research/agent/runs/run-20260910T165508Z.json
(+ earlier intermediate run records)
```

Field checks: `plan_id`, `lead_id`, `cve_id=CVE-2026-1557` and `program`
correct; `production_finding=false`; status in the allowed set; `affected_versions=['<=1.0']`,
`affected_parameters=['src']`, components include `image_handler.php` and the
plugin.

Atomicity/idempotency: re-invoking `store_result`/`write_report` on the final
results returned `written=False` and the JSON/Markdown SHA-256 prefixes were
unchanged for both plans. (An earlier same-plan re-run also produced an
unchanged result file.)

## 5. Evidence provenance verification

For every evidence item in both results:

- `source_url` ∈ the supplied persisted references — TRUE (all)
- `source_url` is not a program/target URL — TRUE (all)
- `content_hash` non-empty — TRUE (all)
- `content_hash` == the source-layer hash for that source — TRUE (all)
- model-provided hash ignored — the schema/hash always comes from the source
  layer (verified by test + inspection)
- claim has provenance (source URL + hash) — TRUE (all)
- no forbidden verdict vocabulary in claim/quote — TRUE (all)

Evidence summary (plan 1): Nuclei-template PR facts (merged 2026-03-18, uses an
absolute-path payload not traversal, accepts HTTP 403, lacks CWE-22) and the
CrowdSec vpatch facts, each grounded to the GitHub PR that was actually fetched.
This is **research evidence only**, not verified-vulnerability evidence.

## 6. Research report wording

Both generated Markdown reports begin with:

```
**RESEARCH ONLY — NOT TARGET VALIDATION — NOT A PRODUCTION FINDING**
```

They explicitly state no target interaction / no active validation / no Nuclei
execution / no production finding, and the limitations say the target/program
was never contacted, scanned, or validated. A line scan found no
VULNERABLE/VERIFIED/EXPLOITED/FINDING occurrence outside an explicitly safe
negative ("never …", "not …") statement.

## 7. Target isolation verification

- No source URL fetched or recorded contains `dell.com` or `indeed.com`
  (`program_host_in_sources == []` for both plans).
- `dell.com` occurrences in each result JSON: **0**; `indeed.com`: **0**.
- The program name appears only as research context (`program: dell` /
  `program: indeed`).
- No network request was made to any program/target host. The only outbound
  requests were to the 6 persisted CVE reference URLs above plus the configured
  LLM provider.
- Redirect isolation: the followed redirect chains for the fetched references
  ended on `plugins.trac.wordpress.org`, `www.wordfence.com`, and `github.com`
  only — no program/localhost/RFC1918/link-local/metadata/internal host
  appeared in any chain.

## 8. LLM result

- Existing OpenRouter abstraction only; no new provider, no hard-coded model.
  `WATCH_LLM_PROVIDER` / `WATCH_LLM_MODEL` were unset, so the existing
  `OPENROUTER_MODEL` / `OPENROUTER_API_KEY` configuration was authoritative.
- Credentials/model were available; the final runs succeeded and produced the
  evidence above.
- One intermediate plan-1 attempt hit a transient provider error and
  fail-softed to `RESEARCH_PARTIAL` with no evidence; after the remediation the
  result records the exact sanitized reason (`LLM provider error:
  OpenRouterProviderError: …`). No API key or secret was printed.

## 9. Dashboard verification

- `/ui/research/agent` → 200; shows Research Agent, current window, last run,
  last status (`RESEARCH_PARTIAL`), plans processed, research results, and the
  research-only banner; wording includes "never contacts … the target/program".
- `/ui/research/agent/<run_id>` → 200 for the final run ids; shows run status,
  plans processed, per-result rows and the banner.
- `GET /api/research/agent/status` → 200; `GET /api/research/agent/runs` → 200.
- No `?api_key=.../<path>` query-string concatenation; all links use `build_url`.

## 10. Tests

- `python3 -m unittest tests.test_research_agent` → **Ran 92 tests … OK**
  (offline, no network/LLM/Mongo).
- Relevant research/dashboard suites (navigation, intelligence UI, workflow,
  API, leads, execution, dashboard navigation) → **Ran 192 tests … OK**.
- `git diff --check` → clean.
- `database/db.py` untouched.

## 11. Remediations applied (found during this validation)

The validation surfaced two gaps. Minimal, targeted fixes were applied and
re-validated:

1. `ai/research_agent/agent.py` — model-generated **unknowns** were not scrubbed
   for forbidden verdict language (an unknown question contained "vulnerable").
   Model unknowns are now dropped and replaced with a neutral note when they
   carry a forbidden verdict term; the model `exploitability_summary` falls back
   to the deterministic summary in the same case.
2. `ai/research_agent/agent.py` — the exact LLM provider failure reason was
   discarded; it is now surfaced (bounded, key-free).
3. `ai/research_agent/storage.py` — the deterministic Markdown report now emits
   the explicit `RESEARCH ONLY — NOT TARGET VALIDATION — NOT A PRODUCTION
   FINDING` banner.
4. `tests/test_research_agent.py` — 3 focused tests added (unknown scrub,
   summary scrub, provider-reason surfacing); 89 → 92 tests.

No scheduler default, systemd unit, or unrelated test was modified.

## 12. Security review

- Network stayed within the persisted CVE reference set; SSRF guard remained
  authoritative (no localhost/RFC1918/link-local/metadata/program hosts).
- No target interaction, no active validation, no Nuclei execution, no browser,
  no PoC, no 5B–5J, no production finding, no alert.
- LLM output is non-authoritative: evidence requires a supplied source + trusted
  hash; uncited/forbidden claims are dropped to unknowns.
- Nuclei candidates forced `executed=False`, `target_url=None`, `status=RESEARCH_CANDIDATE`.
- No secrets printed; runs stored no credentials or raw target responses.
- systemd units were not enabled or started and were not modified.

## 13. Limitations

- Only 2 of 6 persisted references were fetchable from this environment
  (`plugins.trac.wordpress.org` returned HTTP 403, Wordfence returned an empty
  202); this is a source-side/environment condition, not an agent fault. The
  agent recorded the failures and continued (fail-soft → `RESEARCH_PARTIAL`).
- Evidence grounding is attributional (source URL + trusted hash), not semantic
  verification of each quote.
- Redirect handling: the source layer validates the initial URL before fetching;
  the existing `ReferenceCollector` follows redirects and does not re-validate
  each redirect hop at runtime. Observed chains in this validation stayed on
  allowed public hosts, but a future hardening step should re-validate the final
  host (and each hop) against the SSRF guard.
- Model free-text (e.g. `recommended_next_step`) is advisory and may mention
  human research steps; the agent itself never acts on them. Recommendation
  vocabulary is not yet constrained to the R22 code set.
- A transient LLM provider error occurred once; it failed soft and was reported.
- Results are stored under the gitignored `ai_data/research/agent/`; the
  pre-fix plan-1 artifacts were archived to `/tmp/opencode/r23_prefix_artifacts/`
  for traceability.

## 14. Explicit confirmations

- NO target interaction
- NO active validation
- NO Nuclei execution
- NO production findings
- NO alerts
- NO 5B–5J
- NO systemd timer activation (`systemctl enable/start` not run; units unmodified)
- NO Git operations (no commit, no push)
- `database/db.py` not modified

## Agent / Model

- Model: opencode-go/deepseek-flash
- Stage: R23.1
- Role: Controlled Real Research Validation
