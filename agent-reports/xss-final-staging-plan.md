# XSS Oracle Confirmation State Machine — Final Staging Plan

**Task:** Stage ONLY the XSS Oracle Confirmation State Machine implementation.
**Mode:** READ-ONLY plan. Nothing was staged, modified, committed, or pushed while producing this report.
**Working tree:** `/opt/watch` · Branch `main` (HEAD `a3ad8c1`)
**Index state at plan time:** empty (0 files staged; `git diff --cached --stat` clean).
**Based on:** current working-tree diffs + `agent-reports/xss-confirmation-state-machine-final-review.md` §2 file attribution.

---

## 1. Executive Answer

**Yes — the XSS task can be staged safely, but not with plain `git add` alone.**

| Target file | Ownership | Safe method |
|---|---|---|
| `ai/schemas/xss_finding.py` | 100% this task | plain `git add` |
| `ai/schemas/xss_verification.py` | MIXED (4 hunks; only `oracle_identity` block belongs) | `git add -p` with **manual hunk edit** (`e`) — plain y/n is NOT enough |
| `ai/verification/verifier.py` | 100% this task | plain `git add` |
| `ai/verification/xss_pipeline.py` | 100% this task | plain `git add` |
| `watch_xss_verify.py` | 100% this task | plain `git add` |
| `ai/test_xss_verification.py` | 100% this task | plain `git add` |
| `ai/test_xss_pipeline.py` | 100% this task | plain `git add` |
| `ai/test_xss_oracle.py` | UNTRACKED & MIXED (only `OracleAttemptFactoryTests` belongs) | **temp-file partial staging** (deterministic); NOT feasible with plain `git add -p` |
| `ai/test_browser_executor.py` | MIXED (4 hunks; only hunk 4 belongs) | `git add -p` with plain y/n |

Excluded (pre-existing / other tasks, must NOT be staged):
`ai/verification/oracle.py` (untracked), `ai/verification/browser_executor.py`,
`ai/verification/http_executor.py`, `ai/test_http_executor.py`,
`ai/test_watch_param_discovery.py`, `ai/test_xss_case_builder.py`,
`AGENTS.md`, `README-watch-updated.md` (D), `crawl/`, `database/`,
`tests/`, `wordlists/`, `agent-reports/`.

---

## 2. Exact Files to Stage (whole-file, plain `git add`)

All six files' working-tree diffs are 100% attributable to this task:

| File | numstat | Content |
|---|---|---|
| `ai/schemas/xss_finding.py` | +10/−0 | `confirmation_state`, `oracle_channels` fields on `XSSFinding` |
| `ai/verification/verifier.py` | +516/−97 | `_classify_oracle`, `_oracle_execution_proof`, `build_oracle_verification_attempt`, `ORACLE_ATTEMPT_PHASE`, run_salt plumbing, browser CONFIRMED→POTENTIAL demotion, `_STATUS_TO_CONFIDENCE` unchanged |
| `ai/verification/xss_pipeline.py` | +10/−1 | `build_default_verifier(..., *, run_salt=None)` passthrough |
| `watch_xss_verify.py` | +7/−0 | `import secrets` + `run_salt=secrets.token_hex(32)` per pipeline build |
| `ai/test_xss_verification.py` | +1089/−128 | Oracle fixtures, demotion rewrites, `XSSVerifierOraclePlanTests`, reflected/DOM matrix, security matrix |
| `ai/test_xss_pipeline.py` | +27/−0 | `test_run_salt_default_is_none_and_forwarded` |

---

## 3. Mixed File 1 — `ai/schemas/xss_verification.py` (+100/−0, 4 hunks)

### 3.1 Hunk decision table

| # | Header | Content | This task? | Action |
|---|---|---|---|---|
| 1 | `@@ -82,6 +82,65 @@` | `DialogEvent`, `NetworkOracleEvent`, `EvalInvocation` classes | NO (pre-existing oracle infra) | `n` |
| 2 | `@@ -420,6 +479,27 @@` | `VerificationAttempt` oracle-field block | **MIXED inside the hunk** | `e` (edit) — see 3.2 |
| 3 | `@@ -637,6 +717,23 @@` | `VerificationEvidence`: `dialog_events`, `oracle_network_events`, `eval_invocations`, `intended_request_url`, `actual_request_url` | NO (pre-existing oracle infra) | `n` |
| 4 | `@@ -693,6 +790,9 @@` | `__all__` += DialogEvent/EvalInvocation/NetworkOracleEvent | NO (pre-existing oracle infra) | `n` |

### 3.2 Why hunk 2 CANNOT be split with `s`

Hunk 2 adds 21 contiguous lines with zero context lines between them:

```
+    # Execution-oracle infrastructure (xss-oracle-design.md).
+    # Populated only for oracle attempts created by the trusted
+    # planner; ``None`` keeps every existing attempt unchanged
+    # (backward compatible). The seed S MAY travel inside the
+    # payload; the derived oracle value D MUST NEVER appear on
+    # the wire (enforced independently by
+    # ``ai.verification.oracle.anti_harvest_violations``).
+    oracle_seed: str | None = None
+    oracle_value: str | None = None
+    oracle_version: int | None = None        ← lines 1–10: PRE-EXISTING infra
+    # Deterministic pre-oracle candidate identity the oracle seed was
+    # minted against (the paired plain-browser attempt's ``attempt_id``).
+    # Required because the oracle attempt's own ``attempt_id`` includes
+    # the seed-bearing payload, which would make seed derivation
+    # circular. The verifier re-derives run freshness from
+    # ``oracle_seed(run_salt, oracle_identity, phase)`` and rejects any
+    # attempt whose ``oracle_identity`` does not map to the same
+    # ``logical_pair_id`` candidate. Only oracle attempts carry it;
+    # ``None`` keeps every existing attempt unchanged.
+    oracle_identity: str | None = None       ← lines 11–21: THIS TASK
+                                             (trailing blank)
```

git cannot auto-split contiguous additions → **must use `e` (edit)**.

### 3.3 Exact content of the EDITED hunk (what to leave in the `e` editor)

Delete added lines 1–10 (the infra comment block + `oracle_seed` /
`oracle_value` / `oracle_version`), keep lines 11–21, and fix the header
new-side count `27` → `17` (6 context + 11 added). The `-420,6` side stays
untouched; leave `+479` as-is.

```diff
@@ -420,6 +479,17 @@ class VerificationAttempt(BaseModel):
     # observed correlation token, NOT via phase.
     phase: str = "primary"
 
+    # Deterministic pre-oracle candidate identity the oracle seed was
+    # minted against (the paired plain-browser attempt's ``attempt_id``).
+    # Required because the oracle attempt's own ``attempt_id`` includes
+    # the seed-bearing payload, which would make seed derivation
+    # circular. The verifier re-derives run freshness from
+    # ``oracle_seed(run_salt, oracle_identity, phase)`` and rejects any
+    # attempt whose ``oracle_identity`` does not map to the same
+    # ``logical_pair_id`` candidate. Only oracle attempts carry it;
+    # ``None`` keeps every existing attempt unchanged.
+    oracle_identity: str | None = None
+
     @field_validator(
         "attempt_id", "logical_pair_id", "correlation_token"
     )
```

**Result:** staged file contains ONLY the `oracle_identity` field.
Staged numstat for this file: `11 insertions, 0 deletions`.

---

## 4. Mixed File 2 — `ai/test_browser_executor.py` (+188/−4, 4 hunks)

### 4.1 Hunk decision table

| # | Header | Content | This task? | Action |
|---|---|---|---|---|
| 1 | `@@ -28,6 +28,7 @@` | `from ai.verification.oracle import evaluate_e2_network` (needed by infra boundary tests) | NO | `n` |
| 2 | `@@ -321,14 +322,17 @@` | `FakePage.Req.__init__` fix (supports infra oracle-boundary tests) | NO | `n` |
| 3 | `@@ -832,6 +836,176 @@` | `BrowserEvidenceExecutorOracleBoundaryTests` (oracle evidence-boundary fix tests) | NO | `n` |
| 4 | `@@ -2652,9 +2826,19 @@` | `BrowserEvidenceExecutorVerifierIntegrationTests` — **MANDATED DEMOTION** assertion (browser CONFIRMED → POTENTIAL/SINK_REACHED) | **YES** | `y` |

No manual editing required here — hunk 4 is cleanly separable with y/n.
**Staged numstat:** `10 insertions, 2 deletions`.

Staged hunk 4 verbatim:

```diff
@@ -2652,9 +2826,19 @@ class BrowserEvidenceExecutorVerifierIntegrationTests(unittest.TestCase):
         confirmed = [
             f for f in result.findings if f.status == "CONFIRMED"
         ]
-        self.assertEqual(len(confirmed), 1)
+        # MANDATED DEMOTION: browser chain/token evidence without an
+        # oracle execution proof is POTENTIAL (SINK_REACHED), never
+        # CONFIRMED. The browser attempt's finding is POTENTIAL.
+        self.assertEqual(len(confirmed), 0)
+        browser_findings = [
+            f
+            for f in result.findings
+            if f.verification_mode == "browser_execution"
+        ]
+        self.assertEqual(len(browser_findings), 1)
+        self.assertEqual(browser_findings[0].status, "POTENTIAL")
         self.assertEqual(
-            confirmed[0].verification_mode, "browser_execution"
+            browser_findings[0].confirmation_state, "SINK_REACHED"
         )
 
     def test_browser_evidence_without_chain_inconclusive(self):
```

---

## 5. Untracked Mixed File — `ai/test_xss_oracle.py` (1081 lines)

### 5.1 Ownership map (inspected line by line — do NOT assume whole file)

| Lines | Content | Ownership |
|---|---|---|
| 1–10 | Module docstring ("…this task implements oracle infrastructure only…") | PRE-EXISTING infra task |
| 12 | `from __future__ import annotations` | shared (keep in staged slice) |
| 14–17 | `json`, `shutil`, `subprocess`, `tempfile` | infra (node/equiv + tmpdir tests) |
| 18 | `import unittest` | shared (keep) |
| 20–25 | `DialogEvent`/`EvalInvocation`/`NetworkOracleEvent`/`VerificationAttempt` import | infra |
| 26–43 | `from ai.verification.oracle import …` | shared (factory tests use 6 of these names) |
| 44–46 | `from ai.verification.verifier import build_oracle_verification_attempt` | **THIS TASK** (used ONLY by `OracleAttemptFactoryTests`; verified by grep — no other user in the file) |
| 48 | `_HAS_NODE = shutil.which("node") is not None` | infra — **must be EXCLUDED** (references `shutil`, which the slice does not import) |
| 49 | `_ENDPOINT = "https://target.example.com/path"` | shared (used by factory `setUp`) |
| 51–86 | `_planner()`, `_plan()`, `_attempt()` helpers | infra |
| 89–918 | 12 infra test classes: `FnV1A32Tests`, `OracleValueTests`, `SeedGenerationTests`, `JavaScriptEquivalenceTests`, `OraclePlannerTests`, `E1DialogPredicateTests`, `E2NetworkPredicateTests`, `E3EvalPredicateTests`, `BenignSpoofRegressionTests`, `EvidenceBoundaryTests`, `EvidenceBoundaryAPITests`, `RunSaltReplayTests` | PRE-EXISTING infra task |
| **920–1077** | **`class OracleAttemptFactoryTests(unittest.TestCase)`** — 7 tests: `test_seed_binds_to_candidate_identity`, `test_attempt_identity_distinct_from_candidate`, `test_deterministic`, `test_run_salt_changes_oracle`, `test_payload_contains_seed_once_never_value`, `test_unsupported_context_yields_no_oracle_attempt`, `test_anti_harvest_holds_on_oracle_attempt` | **THIS TASK** |
| 1078 | blank | shared |
| 1079–1081 | `if __name__ == "__main__": unittest.main()` | shared trailer (keep) |

### 5.2 Why plain `git add -p` is NOT feasible here

The file is **untracked**. Even after `git add -N` (intent-to-add), the whole
file presents as a single all-addition hunk with no context lines, so `s`
(split) cannot divide it and `e` (edit) would require hand-editing a ~1081-line
hunk. **Use the deterministic temp-file method instead** (§6, Step 4).

### 5.3 Staged slice spec (task-owned content only)

The index entry for `ai/test_xss_oracle.py` must be assembled from exact
line ranges of the current working file:

- line 12 (`from __future__ import annotations`)
- line 18 (`import unittest`)
- lines 26–46 (oracle + verifier imports — verbatim; contains the six oracle
  names and `build_oracle_verification_attempt` the class needs; extra unused
  oracle imports are harmless and keep the slice byte-faithful)
- line 49 (`_ENDPOINT`)
- two blank separator lines
- lines 920–1081 (`OracleAttemptFactoryTests` + blank + `__main__` guard)

**Excluded from the staged slice:** docstring (1–10), json/shutil/subprocess/
tempfile (14–17), schema import block (20–25), `_HAS_NODE` (48), helpers
(51–86), all 12 infra test classes (89–918).

---

## 6. Exact Git Commands (run in this order, from `/opt/watch`)

> ⚠️ NEVER use `git add .`, `git add -A`, or `git commit -a` in this tree —
> it would sweep in oracle.py, browser/http executors, crawl, database, etc.

```bash
# ── Step 0: sanity — index must be empty ──────────────────────────────
git diff --cached --stat          # expect: (no output)

# ── Step 1: whole-file task files ────────────────────────────────────
git add ai/schemas/xss_finding.py \
        ai/verification/verifier.py \
        ai/verification/xss_pipeline.py \
        watch_xss_verify.py \
        ai/test_xss_verification.py \
        ai/test_xss_pipeline.py

# ── Step 2: mixed file — ai/test_browser_executor.py (hunk 4 only) ───
git add -p ai/test_browser_executor.py
#   hunk 1  @@ -28,6    +28,7     (oracle import)            -> n
#   hunk 2  @@ -321,14  +322,17   (FakePage.Req fix)         -> n
#   hunk 3  @@ -832,6   +836,176  (OracleBoundaryTests)      -> n
#   hunk 4  @@ -2652,9 +2826,19  (MANDATED DEMOTION test)   -> y

# ── Step 3: mixed file — ai/schemas/xss_verification.py ──────────────
git add -p ai/schemas/xss_verification.py
#   hunk 1  @@ -82,6    +82,65   (Dialog/Network/Eval classes) -> n
#   hunk 2  @@ -420,6  +479,27   (oracle fields block)         -> e
#            In the editor: DELETE the 10 infra lines
#            ("# Execution-oracle infrastructure..." through
#             "oracle_version: int | None = None"),
#            KEEP the oracle_identity comment block + field +
#            trailing blank, and change the header count 27 -> 17:
#            @@ -420,6 +479,17 @@
#   hunk 3  @@ -637,6  +717,23   (VerificationEvidence fields) -> n
#   hunk 4  @@ -693,6  +790,9    (__all__ additions)           -> n

# ── Step 4: untracked mixed file — ai/test_xss_oracle.py ─────────────
# Deterministic partial staging (index-only; working tree restored
# byte-identical afterwards):
mkdir -p /tmp/opencode
cp ai/test_xss_oracle.py /tmp/opencode/test_xss_oracle.py.full
{
  sed -n '12p'      /tmp/opencode/test_xss_oracle.py.full
  sed -n '18p'      /tmp/opencode/test_xss_oracle.py.full
  sed -n '26,46p'   /tmp/opencode/test_xss_oracle.py.full
  sed -n '49p'      /tmp/opencode/test_xss_oracle.py.full
  printf '\n\n'
  sed -n '920,1081p' /tmp/opencode/test_xss_oracle.py.full
} > ai/test_xss_oracle.py
git add ai/test_xss_oracle.py
cp /tmp/opencode/test_xss_oracle.py.full ai/test_xss_oracle.py   # restore full tree
```

### 6.1 Optional deterministic alternative for Step 3 (no interactive editor)

If the `e`-mode edit in Step 3 is undesirable, stage the exact blob with
plumbing (index-only; working tree untouched):

```bash
python3 - <<'PY'
from pathlib import Path
text = Path("ai/schemas/xss_verification.py").read_text()
infra_block = (
    '    # Execution-oracle infrastructure (xss-oracle-design.md).\n'
    '    # Populated only for oracle attempts created by the trusted\n'
    '    # planner; ``None`` keeps every existing attempt unchanged\n'
    '    # (backward compatible). The seed S MAY travel inside the\n'
    '    # payload; the derived oracle value D MUST NEVER appear on\n'
    '    # the wire (enforced independently by\n'
    '    # ``ai.verification.oracle.anti_harvest_violations``).\n'
    '    oracle_seed: str | None = None\n'
    '    oracle_value: str | None = None\n'
    '    oracle_version: int | None = None\n'
)
assert text.count(infra_block) == 1, "infra block not found exactly once"
Path("/tmp/opencode/xss_verification.task-staged.py").write_text(
    text.replace(infra_block, "")
)
PY
blob=$(git hash-object -w /tmp/opencode/xss_verification.task-staged.py)
git update-index --cacheinfo 100644,"$blob",ai/schemas/xss_verification.py
```

(If this alternative is used, skip Step 3 entirely; do not run both.)

---

## 7. Post-Staging Verification Commands

```bash
git status --short
git diff --cached --stat
git diff --cached --check
git diff --cached
```

### 7.1 Expected `git status --short`

```
 M AGENTS.md
 D README-watch-updated.md
M  ai/schemas/xss_finding.py
MM ai/schemas/xss_verification.py
 M ai/test_http_executor.py
 M ai/test_watch_param_discovery.py
 M ai/test_xss_case_builder.py
M  ai/test_xss_pipeline.py
M  ai/test_xss_verification.py
MM ai/test_browser_executor.py
AM ai/test_xss_oracle.py
 M ai/verification/browser_executor.py
 M ai/verification/http_executor.py
M  ai/verification/verifier.py
M  ai/verification/xss_pipeline.py
 M crawl/watch_param_discovery.py
 M database/change_events.py
 M database/db.py
M  watch_xss_verify.py
?? agent-reports/
?? ai/verification/oracle.py
?? tests/
?? wordlists/
```

Legend: `M ` = fully staged (whole-file task files); `MM` = partially staged
(mixed files — remaining unstaged portion belongs to other tasks); `AM` =
task slice staged, full infra content still unstaged in the working tree
(this is the intended end state for `ai/test_xss_oracle.py`).

### 7.2 Expected `git diff --cached --stat`

```
 ai/schemas/xss_finding.py       |  10 ++
 ai/schemas/xss_verification.py  |  11 ++
 ai/test_browser_executor.py     |  12 +-
 ai/test_xss_oracle.py           | 188 +
 ai/test_xss_pipeline.py         |  27 ++
 ai/test_xss_verification.py     | 1217 ++++++++++++++++++++++...
 ai/verification/verifier.py     |  613 ++++++++++...
 ai/verification/xss_pipeline.py |  11 +-
 watch_xss_verify.py             |   7 ++
 9 files changed, ~2116 insertions(+), ~100 deletions(-)
```

### 7.3 `git diff --cached --check`

Must output **nothing** (no whitespace errors) and exit 0.

### 7.4 `git diff --cached` — spot-check assertions

- `ai/schemas/xss_verification.py`: shows ONLY the `oracle_identity` hunk
  (`@@ -420,6 +420,17 @@`-ish; the +side start will be recomputed since infra
  hunks are NOT staged). `oracle_seed` / `oracle_value` / `oracle_version`
  must be ABSENT from the staged diff.
- `ai/test_browser_executor.py`: shows ONLY hunk 4 (demotion). No
  `evaluate_e2_network` import, no `OracleBoundaryTests`.
- `ai/test_xss_oracle.py`: staged file starts with
  `from __future__ import annotations`, imports, `_ENDPOINT`, then
  `class OracleAttemptFactoryTests`, then `__main__` guard. No
  `FnV1A32Tests`/`OraclePlannerTests`/`EvidenceBoundary*`/`RunSaltReplayTests`.
- `ai/verification/verifier.py`: full oracle state machine present
  (`_classify_oracle`, `_oracle_execution_proof`, `build_oracle_verification_attempt`).
- No `ai/verification/oracle.py`, no `browser_executor.py`, no `http_executor.py`
  in the staged diff.

Additional sanity (optional but recommended):

```bash
git diff --cached --name-only          # exactly the 9 target paths
git diff -- ai/test_xss_oracle.py | head -40        # infra remainder stays unstaged
git diff -- ai/schemas/xss_verification.py | grep -c oracle_seed   # 2 (still unstaged)
python3 -m unittest ai.test_xss_oracle.OracleAttemptFactoryTests -v
python3 -m unittest ai.test_xss_verification ai.test_xss_pipeline -v
python3 -m unittest ai.test_browser_executor.BrowserEvidenceExecutorVerifierIntegrationTests -v
```

---

## 8. Cross-Task Dependency / Sequencing Caveats

1. **The staged set is NOT self-contained.** `ai/verification/verifier.py`
   (staged) imports `ai.verification.oracle` (untracked, NOT staged) and
   reads `attempt.oracle_seed/oracle_value/oracle_version` plus the
   `VerificationEvidence` oracle-channel fields and `DialogEvent`/
   `NetworkOracleEvent`/`EvalInvocation` — all of which live in the
   **excluded pre-existing oracle-infrastructure work**. This commit must
   therefore land AFTER (or be reviewed together with) the oracle-infra
   commit. Staging itself is safe (index operations don't validate imports;
   tests run against the full working tree), but a standalone checkout of
   only this commit would not import.
2. **Staged `xss_verification.py` contains `oracle_identity` but not
   `oracle_seed/value/version`.** `verifier.py`'s
   `build_oracle_verification_attempt` does `model_copy(update={...})` with
   those names. This is coherent only once the infra commit supplies the
   missing fields (see item 1).
3. **`ai/test_xss_oracle.py` ordering.** The staged slice is a valid
   standalone module, but the 12 infra test classes remain unstaged and
   belong to the infra task's own commit. If the infra commit lands first
   and includes the file WITHOUT `OracleAttemptFactoryTests`, the factory
   tests become a clean tracked-file append (hunks at lines 44–46 and
   920–1081) and this plan's Step 4 reduces to a normal `git add` of the
   delta. With both tasks sharing one tree, the AM state is the correct
   intermediate.
4. **Never commit `agent-reports/`** with this task; it stays untracked
   documentation.

---

## 9. Do-NOT List (hard guardrails)

- Do NOT `git add ai/verification/oracle.py`, `ai/verification/browser_executor.py`,
  `ai/verification/http_executor.py`, `ai/test_http_executor.py`,
  `ai/test_watch_param_discovery.py`, `ai/test_xss_case_builder.py`,
  `AGENTS.md`, `README-watch-updated.md`, `crawl/`, `database/`, `tests/`,
  `wordlists/`, or `agent-reports/`.
- Do NOT accept hunk 1/3/4 of `ai/schemas/xss_verification.py` or hunks 1–3
  of `ai/test_browser_executor.py`.
- Do NOT stage the whole of `ai/test_xss_oracle.py` (its docstring and 12
  infra test classes belong to the pre-existing infrastructure task).
- Do NOT use `git add .` / `git add -A` / `git commit -a`.
- Do NOT commit or push as part of this step.

---

*Report generated as a read-only staging plan. No file outside
`agent-reports/` was created, modified, staged, committed, or pushed.*
