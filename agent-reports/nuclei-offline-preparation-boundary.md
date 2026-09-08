# Offline Nuclei Preparation Boundary + CVE-2026-1557 Payload Provenance

Date: 2026-09-06. Mode: research-only, dry-run. No commits, no pushes,
no VPS/SSH changes, no live gates touched, no live execution.

## 1. Objective

(A) Close the architectural boundary found in the CVE-2026-1557
dry-run validation: `NucleiPipeline.prepare_for_watch()` can reach
`WatchAssetSelector.select()` -> `HTTPFingerprintRunner.check()` ->
live `httpx.get()`, giving research-only preparation an implicit
network side effect. Provide a guaranteed network-free preparation
lane via explicit target input, without redesigning the pipeline.

(B) Investigate the `src=/wp-config.php` (stored template) vs
`src=../../../../wp-config.php` (research/upstream description)
payload discrepancy using only local material; change nothing without
evidence.

## 2. Root cause of implicit network boundary

`prepare_for_watch()` is a single monolithic flow: parse -> decision ->
generate -> semantic validation -> `nuclei -validate` (subprocess) ->
`self.target_selector.select()` -> dry-run -> findings. For
ecosystem-level matches (exactly this CVE's case: WordPress ecosystem,
plugin presence unverified), `WatchAssetSelector.select()` calls
`_fingerprint_wordpress_plugin()` -> `HTTPFingerprintRunner.check()`
-> `httpx.get()` against real Watch assets. There is no parameter,
flag, or seam to run the offline stages without also arming the live
fingerprint stage; safety rested only on operator discipline plus the
downstream `scope_status`/`execute` gates. `nuclei -validate` adds a
second implicit side effect (subprocess, and the binary itself attempts
a template auto-update over the network, as seen in the prior run log).

## 3. Architecture before/after

Before: one lane (`prepare_for_watch`), offline stages inseparable
from subprocess + live selection.

After: two lanes on the same class, same components, same schemas.

- `prepare_for_watch` — UNCHANGED, byte-for-byte behavior preserved
  (full preparation incl. `nuclei -validate` and live selection).
- `prepare_offline(cve, research, source_template, selection, ...)` —
  NEW. Reuses the same `parser / decision_engine / generator /
  validator / runner` instances: parse -> decision -> generate+write ->
  semantic validation -> `runner.dry_run(selection)` -> `to_findings`
  -> `save_findings`. It never references `self.target_selector`,
  never calls `_validate_with_nuclei`, never spawns subprocesses.
  Result carries explicit markers: `mode: research-only-offline`,
  `offline: true`, `fingerprint_performed: false`,
  `nuclei_binary_validated: false`, plus warnings stating validation
  was skipped (no subprocesses) and fingerprinting was not performed
  (no network; scope states are the caller's). Fail-closed on missing
  source (`FileNotFoundError`) and selection/CVE mismatch
  (`ValueError`). Findings remain informational (`matched=false`,
  non-authoritative `NucleiFinding`).
- Live fingerprinting stays exactly where it was
  (`WatchAssetSelector.select` / `HTTPFingerprintRunner`), now
  explicitly separate from the offline lane by construction.

## 4. Exact files changed

- `ai/researcher/nuclei_pipeline.py` — added `WatchTargetSelection`
  import, lane docstring, and `prepare_offline()` (~150 lines).
  `prepare_for_watch()` and everything else untouched.
- `ai/test_nuclei_offline_prepare.py` — NEW focused unittest (5 tests).
- `ai/test_nuclei_cve_2026_1557_dryrun.py` — test-only fixes from this
  stage (temp-file lifetime, AST-based separation assertion); no
  production code touched by that.
- Template, research artifact, `ai_data/`, 5B-5J chain, VPS/SSH:
  unchanged.

## 5. Offline behavior

`prepare_offline` for CVE-2026-1557 over a synthetic selection returns
`GOOD_CANDIDATE` (0.95), regenerates the stored template byte-identical,
semantic-valid, dry-run `DRY_RUN_ONLY`/`EXCLUDED` with empty output,
4 findings all `matched=false`. Proven by tests that patch
`socket.socket`, `socket.create_connection`, `subprocess.run`, and
`HTTPFingerprintRunner.check` to raise: the lane completes without
tripping any of them. An AST structural test further asserts the method
body contains no reference to `target_selector`,
`_validate_with_nuclei`, `HTTPFingerprintRunner`, `fingerprint_runner`,
`subprocess`, `httpx`, or `socket`.

## 6. Payload provenance investigation — PROVENANCE_UNRESOLVED

Searched locally only (no fetches): full-repo grep for `wp-config`,
`wp-responsive-images`, traversal/`../` payloads, `15592`,
`nuclei-templates`; `nuclei/` templates; git history.

- For `../../../../wp-config.php`: exactly one local source — the
  research artifact's `nuclei_reason` prose (LLM summary of upstream
  PR #15592) plus detection-idea text mentioning `../` monitoring.
- For `/wp-config.php`: the stored generated template, present with
  that value since the single checkpoint commit (`a7375c6`); the
  generator faithfully reproduces its source spec (round-trip proven),
  so the value predates generation and is not a generator artifact.
- No vendored copy of upstream PR #15592, no cached template, no
  earlier git history exists locally to arbitrate.

Missing evidence: the actual merged upstream `CVE-2026-1557.yaml`
content. WITHOUT IT, NEITHER VALUE CAN BE CONFIRMED INTENDED.
Template left unchanged; no payload invented. Note: the artifact's own
detection idea (alert on `../` in `src`) suggests the traversal form
is the exploit-realistic one, but that is corroboration of the
vulnerability shape, not of the template's exact `src` value.

## 7. Tests and exact counts

- NEW `ai.test_nuclei_offline_prepare`: 5/5 pass (network/subprocess
  freedom, stored-template reproduction, mismatch rejection, missing
  source, live-path separation).
- `ai.test_nuclei_cve_2026_1557_dryrun`: 5/5 pass (prior lane intact).
- `ai.test_research_cli`: 6/6 pass.
- Combined: `python3 -m unittest ai.test_nuclei_offline_prepare
  ai.test_nuclei_cve_2026_1557_dryrun ai.test_research_cli` — 16/16 OK.
- Not run (per scope): live Nuclei/HTTP, browser, crawl, DNS brute
  force, heavy Watch pipeline.

## 8. Safety verification

- No `LIVE_*` env vars; live gates unmodified; 5B-5J chain, VPS, SSH
  untouched.
- Tests use `.invalid` fixtures plus artifact-local asset names; all
  network/subprocess surfaces patched to fail loudly; `ai_data/`
  untouched (tmp dirs).
- `grep` re-confirms no `SealedFinding`/`5J`/`CONFIRMED` in the Nuclei
  lane; offline results contain none; `NucleiFinding` remains
  non-authoritative.
- The `wp-config.php` request was not executed at any point.

## 9. Remaining limitations

1. `prepare_for_watch` still bundles live selection; callers must
   choose `prepare_offline` explicitly — the safe lane is opt-in, not
   default.
2. Offline lane skips `nuclei -validate` (no binary here); schema
   assurance rests on semantic validation + YAML round-trip.
3. Payload provenance unresolved (section 6).
4. Pure-prose `DetectionSpecExtractor` still yields no reliable
   signature for this artifact; candidacy depends on existing-template
   prior art.

## 10. Recommended next step

Obtain the merged upstream PR #15592 template through an authorized,
auditable channel (vendored copy with hash), diff against the stored
template to settle `src`, and only then consider making the offline
lane the default for research-only callers.
