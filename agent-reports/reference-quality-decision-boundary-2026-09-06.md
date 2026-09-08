# Reference Quality → Research Decision Boundary — Verification Report

Date: 2026-09-06
Stage: Reference Context Quality → Research Decision Boundary
Mode: research-only, offline, non-authoritative, verification-only

## 1. Exact files changed

1. `ai/test_reference_quality_decision_boundary.py` (NEW, 20 tests)
   — the ONLY file touched by this stage.

## 2. Whether production code changed

No. Production code was inspected and proven correct; no boundary bug
was demonstrated, so per the file boundary no production file was
modified. Specifically untouched: `ai/research_cli.py`,
`ai/researcher/cve_batch.py`, `ai/researcher/reference_quality.py`,
`ai/researcher/researcher.py`, `ai/correlator/nuclei_decision.py`,
`ai/correlator/detection.py`, `ai/researcher/degraded.py`. No Nuclei
DecisionEngine semantic change (no bug found). No fix was required, so
no regression fix + test cycle beyond the verification suite itself.

## 3. Boundary verified

Structural facts asserted in tests (test 8, test 9):

- `SecurityResearcher.research` signature is exactly
  `(document, programs, assets, technologies, reference_contexts,
  discovered_sources)` — there is NO telemetry/quality channel, so
  `checked`/`rejected` cannot be passed as evidence even by accident.
- `NucleiDecisionEngine.decide` takes `(cve, research, detection,
  exploit)` — no quality input.
- Source-text scan: `ai.researcher.researcher`,
  `ai.correlator.nuclei_decision`, `ai.correlator.detection`, and
  `ai.researcher.degraded` contain zero mentions of
  `reference_quality` / `gate_reference` — the downstream layer cannot
  read telemetry it never references.
- Gate output dicts reaching the researcher are the identical objects
  (`is`-check), in identical order — filter-only, no mutation, no
  reorder, no fabrication, no claims, no confidence, no Nuclei
  decision, no authoritative state.

## 4. Empty / partial context behavior

- A (test 1): valid references reach the researcher unchanged.
- B (tests 2, 14): foreign reference rejected; survivor only, research
  completes, quality `{checked: 1, rejected: 1}`, no candidacy.
- C (test 4): all rejected → researcher receives `[]`; research still
  completes from deterministic CVE/NVD facts.
- D (test 5): no references → `[]`, completed, quality `{1, 0}`,
  `nuclei_candidate False`.
- E (test 6): duplicates → exactly one surviving context.
- F (test 7): mixed valid/invalid/duplicate → `[URL_A, URL_C]` only.
- Degraded results (test 16) assert the conservative content:
  `nuclei_candidate False`, `public_exploit None`,
  `actively_exploited None`, `severity None`, `bug_bounty_relevance 0`.

## 5. Decision safety

- Empty evidence through the existing offline extractor + decision
  yields `NOT_APPLICABLE`, `http_detectable False` (tests 10, 20).
- Batch-lane rule (`nuclei_candidate and decision == GOOD_CANDIDATE`)
  stays `False` even for a hostile stub claiming candidacy with empty
  evidence (test 11) — removing references can never strengthen a
  candidate, and telemetry never acts as Nuclei evidence.
- Rejected URLs and foreign-CVE text are absent from researcher input
  (tests 12, 13).

## 6. LLM boundary

Test 8 proves gate output exactly equals researcher input
(field-by-field, order-preserving); test 9 proves researcher kwargs
contain no `checked`/`rejected`/`reference_quality` keys. Flow is
gate → filtered ReferenceContext → researcher, never gate →
fabricated evidence → researcher. Only structured ResearchResult fields
and supplied contexts inspected.

## 7. Nuclei boundary

No Nuclei executed (socket/subprocess guards armed throughout). Only
the pure offline `DetectionSpecExtractor.extract` +
`NucleiDecisionEngine.decide` path was used for deterministic
assertions. Proven: empty/poor references yield NOT_APPLICABLE (no
candidate); prior-art/prompt requirements untouched; no Watch asset
selection; no fingerprinting.

## 8. Fail-soft / retry behavior

- 429 → one retry; both researcher calls receive the identical gated
  contexts with no telemetry leakage (test 15).
- Retry exhaustion → `completed_degraded`, quality preserved (test 16).
- 503 / network → existing degraded path, quality preserved,
  `nuclei_candidate False` (tests 17, 18). No new provider calls
  (scripted call counts asserted: 2/2/1/1).
- Programming errors → hard failure (covered by prior suites, unchanged).
- skip-LLM: researcher never instantiated, `skipped True`, quality
  `{1, 0}`, no fabricated candidacy (test 19).

## 9. Safety verification

Socket (`create_connection`/`socket`/`getaddrinfo`) and subprocess
(`run`/`Popen`) blocked in every test; fake discovery/fetch/LLM; no
Mongo, HTTP, DNS, Nuclei execution, browser, or target requests.
Payload scans: no SealedFinding/CONFIRMED/LIVE_HTTP/LIVE_NUCLEI/
READY_FOR_SCAN; `authoritative False`, `research_only True`.

## 10. Exact test counts / results

New suite: `ai.test_reference_quality_decision_boundary` — 20/20 OK.

Full regression (all OK):

```
python -m unittest ai.test_reference_quality_gate \
  ai.test_single_cve_quality_parity ai.test_batch_reference_quality_parity \
  ai.test_provider_fail_soft ai.test_provider_telemetry ai.test_provider_retry \
  ai.test_provider_cache ai.test_reference_cache \
  ai.test_reference_url_canonicalization ai.test_cve_batch ai.test_research_cli \
  ai.test_openrouter ai.test_reference_quality_decision_boundary
Ran 283 tests — OK

python -m unittest ai.test_researcher ai.test_nuclei_offline_prepare \
  ai.test_nuclei_ready
Ran 5 tests — OK
```

## 11. Diff-check

```
git diff --check -- ai/test_reference_quality_decision_boundary.py
exit=0 (clean)
```

Scoped to the single touched file per instructions.

## 12. Limitations

- Verification is stub-LLM based (by design — no live LLM): it proves
  the deterministic handoff and decision-lane conservatism, not the
  behavior of any particular live model output.
- Confidence comparisons are expressed through the deterministic
  decision lane (`NOT_APPLICABLE` vs candidate rules), since
  `ResearchResult` carries no confidence scalar.
- Degraded `references` are NVD-sourced URLs by architecture (not
  gate-filtered); the suite asserts they carry no exploit/candidacy
  claims rather than asserting their absence.

## 13. Git operations

Explicit statement: no Git operations were performed — no commit, no
push, no branch, no tag, no stash, no checkout, no push to VPS/VM.
Only the new test file and this report were written to the working tree.
