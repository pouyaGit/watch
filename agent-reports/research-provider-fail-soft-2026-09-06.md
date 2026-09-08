# Research Provider Fail-Soft / Degraded Mode — Implementation Report

Date: 2026-09-06
Mode: research-only, dry-run. No live execution. No commit. No push.

## 1. Current failure behavior (before this stage)

- `ai/research_cli.py::_research_single_cve` called
  `SecurityResearcher.research()` with no error handling: any LLM
  provider exception (HTTP 402/429/5xx, timeout, network, or a plain
  programming bug) propagated to the caller.
- `ai/researcher/cve_batch.py::research_one_cve` caught every
  exception identically and recorded `research_status = "failed"`.
- `run_cve_batch` counted `processed = (status == "completed")` and
  `failed = (status != "completed")`, so a transient provider outage
  dropped every affected CVE from the batch (`failed += 1` each).
- Net effect: `LLM provider failure -> research_status = failed ->
  CVE loses the research result`, exactly the behavior this stage
  removes for transient provider errors.

## 2. Provider error classification

New module: `ai/researcher/provider_errors.py`

- `TRANSIENT_HTTP_STATUSES = {402, 429, 500, 502, 503, 504}`.
- Status extraction is best-effort across exception attributes
  (`status_code`/`status`/`response.status_code`), the `__cause__`
  chain, and message text (`HTTP 429`, `status_code: 503`).
- Known timeout/network exception names
  (`APIConnectionError`, `APITimeoutError`, `ConnectError`,
  `ReadTimeout`, `WriteTimeout`, `RemoteProtocolError`, …) and
  provider-wrapped transport text (`OpenRouterProviderError:
  ... connection error ...`) classify as transient.
- Programming-error type names (`TypeError`, `AttributeError`,
  `KeyError`, `IndexError`, `AssertionError`, `ImportError`, …)
  are NEVER transient, even when wrapped.
- Any other explicit HTTP status (e.g. 400/401/403/404) is
  non-transient. `ValueError` (LLM JSON parse failures), generic
  `RuntimeError`, and unknown exceptions are non-transient.
- Public messages are truncated to 500 chars, single-line, and never
  carry credentials (the classifier only reformats the exception
  text; the provider layer already strips API keys).
- No retry loop: classification is synchronous and the caller
  degrades immediately (402 is never retried indefinitely).

## 3. Fallback architecture

New module: `ai/researcher/degraded.py`

- `build_degraded_research(...)` — minimal deterministic
  `ResearchResult` from caller-supplied NVD/reference material only.
- `build_degraded_research_from_document(document, llm_error)` —
  grounded variant used by the real CLI flow (NVD description,
  vendor/products, affected versions, references).
- `degraded_payload_fields(...)` — CLI-payload wrapper helpers.

Wiring (reuse, no duplication):

- `ai/research_cli.py::_research_single_cve` wraps ONLY the
  `researcher.research(...)` call. On a classified-transient
  exception it builds the document-grounded degraded result and
  returns a normal payload with
  `research_status = "completed_degraded"`,
  `llm_status = "unavailable"`, `llm_error = <classified message>`,
  `authoritative = False`, `research_only = True`, plus a
  `provenance = {deterministic: [nvd, reference], llm: unavailable}`.
  Non-transient exceptions re-raise unchanged. Success path now
  records `research_status = "completed"`, `llm_status = "ok"`.
  `--skip-llm` path unchanged in behavior
  (`research_status = "completed"`, `llm_status = "skipped"`).
- `ai/researcher/cve_batch.py::research_one_cve`:
  - Payload with `research_status == "completed_degraded"` (or
    `llm_status == "unavailable"`) → per-CVE
    `research_status = "completed_degraded"`, Nuclei lane runs
    normally on the grounded material, `error` records the
    `degraded: …` notice so operators see the outage.
  - `research_fn` raising a classified-transient error (e.g.
    injected fakes in tests, or a future caller without
    payload-level handling) → minimal CVE-id-only degraded result,
    conservative Nuclei stage, `completed_degraded`.
  - Any other exception → `failed`, exactly as before.
- Nuclei path untouched: `run_nuclei_offline_stage` still uses only
  `NucleiPipeline.prepare_offline` / `DetectionSpecExtractor` /
  `NucleiDecisionEngine`. Grounded-only material with no HTTP
  method/path yields `NOT_APPLICABLE`; no template is generated
  merely because a CVE exists. `nuclei_candidate` is forced False
  in every degraded result.

## 4. Data provenance rules

Degraded `ResearchResult` guarantees (asserted by tests):

- Deterministic/NVD/reference facts only: NVD description in
  `summary`, NVD vendor/products in `affected_products`, NVD
  versions in `affected_versions`, NVD URLs in `references`,
  `CONFIRMED:` (metadata only) / `SECONDARY:` evidence items.
- LLM-derived research absent: `root_cause = None`,
  `detection_ideas = []`, `attack_requirements = []`,
  `impact = []`, `vulnerability_type = None`, `severity = None`.
- Unavailable LLM analysis explicit: `summary` and `nuclei_reason`
  state the LLM did not complete; `NOT OBSERVED: LLM analysis
  unavailable (…)` evidence; payload-level `llm_status =
  "unavailable"` + `llm_error` (outside the `ResearchResult`
  schema, so `ResearchResult(**payload["research"])` still
  validates — extra keys are ignored).
- Never invented: `public_exploit = None`,
  `actively_exploited = None`, no HTTP signatures, no Nuclei
  payloads, no versions beyond source material,
  `bug_bounty_relevance = 0`, `nuclei_candidate = False`.
- Never authoritative: payload `authoritative = False`,
  `research_only = True`; no SealedFinding/5J/CONFIRMED anywhere.

## 5. Batch status semantics

Per-CVE `research_status` is now tri-state:

| status | meaning |
| --- | --- |
| `completed` | normal LLM research succeeded |
| `completed_degraded` | provider unavailable but deterministic research completed; CVE preserved |
| `failed` | actual unrecoverable pipeline failure (bad CVE format, programming error, non-transient LLM error, NVD failure) |

Aggregate (`run_cve_batch`) is backward compatible and additive:

- `processed = completed + completed_degraded`
- `failed = (status == "failed")` only
- new keys `completed` and `completed_degraded` added alongside
  the existing `processed` / `failed`
- markdown report keeps the `processed=X failed=Y` line and adds a
  `completed=… completed_degraded=…` line
- CLI exit code still `0` iff `failed == 0`, so degraded batches
  exit 0; per-CVE `RESULT_KEYS` tuple is unchanged
- `research --cve`, `batch --cves`, `batch --file`, legacy
  `batch --days/--limit` surfaces and signatures unchanged

## 6. Exact files changed

- NEW `ai/researcher/provider_errors.py` — transient vs
  programming-error classification (`classify_provider_failure`,
  `is_transient_provider_failure`, `ProviderFailureInfo`).
- NEW `ai/researcher/degraded.py` — deterministic degraded
  `ResearchResult` builders + payload helpers.
- MOD `ai/research_cli.py` — fail-soft wrap of the LLM call in
  `_research_single_cve`; status/provenance fields on all paths.
- NEW `ai/test_provider_fail_soft.py` — 17 focused unittests
  (unittest style, offline).
- MOD `ai/researcher/cve_batch.py` — `research_one_cve`
  degraded handling + tri-state aggregate counts + markdown line.
  (`RESULT_KEYS` unchanged.)

No changes to `ns/`, `crawl/`, `database/`, Nuclei/CVE
functionality, providers, or credentials.

## 7. Tests and exact counts

New suite `ai.test_provider_fail_soft`: **17 tests, all pass**.

- `ClassifyTests` (6): 402→transient, 429→transient,
  500/502/503/504→transient, 401→not transient, connection-error→
  transient, programmer errors (TypeError/AttributeError/KeyError/
  ValueError-JSON/generic RuntimeError)→not transient.
- `DegradedResultTests` (2): never claims LLM completion; never
  authoritative/CONFIRMED.
- `BatchFailSoftTests` (7): 402→completed_degraded,
  429→completed_degraded, 5xx→completed_degraded,
  unexpected→failed, batch continues (mixed
  degraded/failed/completed in one batch with
  completed=1/completed_degraded=1/failed=1/processed=2),
  degraded→conservative `NOT_APPLICABLE` Nuclei decision with zero
  network/subprocess, successful-LLM path unchanged
  (status completed, error None).
- `ResearchCliFailSoftTests` (2): single-CVE transient→
  `completed_degraded` + `llm_status=unavailable` +
  `research_only=True`; TypeError re-raises (failed, not hidden).

Regression runs (all offline, `python -m unittest`):

- `ai.test_provider_fail_soft ai.test_cve_batch
  ai.test_research_cli ai.test_openrouter`: **64 tests, OK**.
- Full focused research/Nuclei set
  (`test_provider_fail_soft`, `test_cve_batch`,
  `test_research_cli`, `test_openrouter`, `test_knowledge_store`,
  `test_xss_researcher`, `test_xss_llm_researcher`):
  **127 tests, OK**.
- Nuclei/correlator lane (`test_nuclei_offline_prepare`,
  `test_nuclei_ready`, `test_nuclei_cve_2026_1557_dryrun`,
  `test_correlation`, `test_research_pattern`, `test_llm`): **OK**.
- `git diff --check` on all touched files: clean (remaining
  `--check` warnings elsewhere are pre-existing CRLF/whitespace in
  untouched files).

## 8. Safety verification

- Offline tests patch `socket`/`subprocess`; degraded batch
  completes under full socket/DNS + subprocess blocks.
- No target-side requests: batch Nuclei lane uses
  `prepare_offline` only (`prepare_for_watch` never referenced —
  existing AST test still passes); degraded path forces empty
  offline selection semantics via the same lane.
- No Nuclei execution, no browser, no DNS probing, no 5J, no
  SealedFinding, no CONFIRMED, no `LIVE_HTTP`/`LIVE_NUCLEI`.
- No provider keys/secrets added; aggregate/per-CVE artifacts
  carry only research text (existing canary/secret scan test
  passes).
- Degraded results explicitly disclaim LLM completion and claim no
  candidacy, so no downstream consumer can mistake them for
  analyzed/confirmed findings.

## 9. Limitations

- Minimal (CVE-id-only) degraded fallback, used when `research_fn`
  raises before returning a payload, carries NVD description only
  implicitly via the CVE id — full grounding requires the
  document-level path in `_research_single_cve` (the real flow).
- `llm_error` text is provider-exception-derived and truncated; it
  is an operator notice, not a stable error taxonomy for alerting.
- No retry/backoff was added by design (degrade quickly); a
  flapping provider produces one degraded result per CVE per run
  rather than a retried success.
- Second paid provider explicitly out of scope for this stage.

## 10. Recommended next step

Add provider-health telemetry without changing semantics: emit a
per-batch `provider_outages: {http_402, http_429, http_5xx,
network}` histogram (counts only, no payloads/secrets) into the
aggregate JSON so the NEXT stage (standby/paid provider or bounded
retry budget) can trigger on measured outage classes while the
fail-soft contract (`completed_degraded` preserves the CVE) stays
exactly as implemented here.
