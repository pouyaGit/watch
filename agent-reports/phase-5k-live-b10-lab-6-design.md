# Phase 5K Live — B10-LAB.6: LAB-scoped Verification Boundary (Design-Only)

Date: 2026-09-08
Task: Design, but DO NOT IMPLEMENT, the smallest LAB-only verification boundary that lets the
isolated CVE-2026-1557 lab produce a genuine `Nuclei MATCH -> VERIFIED MATCH` without weakening,
relaxing, or modifying any existing production safety guard.
Final status: **DESIGN_READY**

---

## 1. Executive Summary

B10-LAB.5 proved, empirically and by code, that the expected "Nuclei MATCH → VERIFIED MATCH"
cannot be produced through the **unmodified production verifier**: the production argv builder pins
`-restrict-local-network-access` (`nuclei_executor.py:934`), which makes Nuclei silently refuse the
RFC1918 destination, while any argv that does reach the lab necessarily differs from the digest the
verifier recomputes, so it fails `argv_digest_mismatch` (`nuclei.py:94-95`).

This design breaks that deadlock **without touching a single line of production code, schema,
literal, env switch, or pinned constant**, by moving the lab to a self-contained, closed verification
arc inside `ai/lab/`:

- a **LAB-only evidence contract** with its own closed execution-class literal and schema version
  (`evidence-lab/v1`) — production `EvidenceRecord` (which `extra="forbid"`s) and production
  closed Literals cannot represent it, and vice-versa (type-level bidirectional isolation);
- a **LAB argv spec** that is the production argv minus exactly one flag and minus the production
  scratch root, rebuilt by a closed builder from pinned constants only → deterministic digest;
- a **LAB verifier entry point** that mirrors the production gate logic (same order, same fail-closed
  philosophy) but recomputes the digest from the LAB argv spec and pins the lab target/template, the
  artifact hash, and the provenance chain; it emits a `LAB_VERIFIED_MATCH` verdict **in a lab namespace
  only** — never a production `CONFIRMED`/`POTENTIAL`.

Everything that is not (re)built here is reused as a pure, unmodified production function
(`build_target_string`, `argv_digest_for`, `assert_frozen_argv_supported`, `run_bounded_process`,
`EgressRule`/`NetnsRuleSet`, `probe_netns_capabilities`). Production verifier, argv builder, gates,
literals, `PINNED_TEMPLATE_DIGEST`, `LIVE_NUCLEI`, `LIVE_LAUNCH_ENABLED` remain **byte-for-byte
unchanged and unimported-for-verdicts**.

Decision on §F: **implement the LAB-scoped verification** (choice 1), with the understanding that the
achieved verdict is a lab-only, provenance-bound `LAB_VERIFIED_MATCH`, not the production
`/VERIFIED` gate outcome and not `CONFIRMED` (the architecture's `Nuclei => CONFIRMED` ceiling of
`nuclei.py:19-22` is deliberately not lifted). Advisory-only (choice 2) stays as the zero-cost
fallback; re-targeting the lab (choice 3) is rejected because it conflicts with constraints (fixed
RFC1918 target `http://172.31.209.10:80` and no weakening of private-IP restrictions).

---

## 2. Current Verifier Contract (section A)

### 2.1 The analytic gate: `verify_nuclei_observation` (`ai/verification/deterministic/nuclei.py:71-104`)

Executed per rule `nuclei-advisory` from `_decide_nuclei` (`classifier.py:242-253`), only after the
integrity/provenance gate (`verify_handoff_evidence`, `gate.py`) has already `VERIFIED` the handoff.
It is a *binding-first* analytic gate. For each condition, whether the field is **recomputed** or
**bound by equality**:

| # | Check (`nuclei.py`) | Kind | Field(s) involved |
|---|---|---|---|
| 1 | `record.nuclei` present | bound | `NucleiObservation` (`evidence.py:386-418`) |
| 2 | `record.template_binding` present | bound | `TemplateBinding` (`evidence.py:274-300`) |
| 3 | `observation.template_id == binding.template_id` and `observation.template_hash == binding.template_hash` | bound | → `template_binding_mismatch` |
| 4 | `record.execution_class == "nuclei_scan"` | bound (closed literal) | `EvidenceExecutionClass` (`evidence.py:60-65`); `SUPPORTED_EXECUTION_CLASSES` (`gate.py:70-72`) |
| 5 | `record.derivation_binding is None` | bound | → `derivation_binding_unexpected` |
| 6 | `observation.argv_digest == _recompute_argv_digest(record)` | **recomputed** | see 2.2 → `argv_digest_mismatch` |
| 7 | `not timed_out and not killed` | bound | → `nuclei_output_truncated` |
| 8 | `exit_code is not None` | bound | → `nuclei_exit_unknown` |
| 9 | `finding_like_text_present` | bound (text-shape signal) | → `nuclei_advisory_weak` (POTENTIAL) else `nuclei_no_advisory_signal` |

The module docstring (`nuclei.py:19-22`) makes `Nuclei => CONFIRMED` structurally unreachable;
the ceiling is `OUTCOME_POTENTIAL` ("nuclei_advisory_weak", `classifier.py:244-253`).

### 2.2 What the verifier recomputes vs. what is immutable

**Recomputed locally, from record fields only — no caller input** (`_recompute_argv_digest`,
`nuclei.py:49-68`):

```
target_string  = build_target_string(scheme,     host,   effective_port)   # from record.target
scratch_dir    = scratch_dir_for(execution_id)                             # = /srv/watch/scratch/nuclei/{ex_id}
template_path  = f"{scratch_dir}/{template_hash[:16]}.json"                 # hash: template_binding.template_hash
argv           = build_nuclei_argv(template_path=..., target_string=...)    # fatal: see 2.3
expected       = argv_digest_for(argv)                                      # SHA-256(json(list))
```

`build_nuclei_argv` (`nuclei_executor.py:879-936`) is a **closed, frozen 23-token argv**:
`SERVER_CONTROLLED_NUCLEI_BINARY`, `-t <path>`, `-u <target>`, `-disable-update-check`,
`-disable-redirects`, `-no-interactsh`, `-silent`, `-no-color`, `-stats-interval 0`, `-jsonl`,
`-bulk-size 1`, `-concurrency 1`, `-timeout 5`, `-retries 0`,
`-restrict-local-network-access`, `-nc`. It **rejects** any `template_path` not starting with
`/srv/watch/scratch/nuclei/` (`nuclei_executor.py:902-907`) and pins the guard at `:934`.
`argv_digest_for` (`nuclei_executor.py:998-1008`) is SHA-256 over `json.dumps(list(argv))`
— deterministic, position-sensitive, path-and-value sensitive. `build_target_string`
(`nuclei_executor.py:861-876`) elides the port when it equals the scheme default, so
the canonical lab target string `http://172.31.209.10` (port 80 elided).

**Immutable / bound (not recomputed; must equal the sealed record, handoff, authorization):**
the `EvidenceRecord` (`evidence.py:479-511`) frozen triple
`bindings_hash`/`observations_hash`/`content_hash`, laid down by
`canonical_envelope_bytes` (`ai/evidence/store.py:129`) and re-verified by
`TRIPLE_HASH_MISMATCH` (`gate.py:275-292`); plus gates 1-13 of `verify_handoff_evidence`
(`gate.py:115-435`): schema version + id formats, handoff binding (program/target/artifact/
execution ids, gates 7/9/11), authorization provenance via `verify_provenance_for_handoff`
(`ai/evidence/handoff.py:256`), lifecycle `SEALED+complete`, per-class required
observation channels, artifact-class consistency, stage pairing, closed
`SUPPORTED_EXECUTION_CLASSES` (gate 12), forbidden lifecycle states.

The **only callable/executable surface** in production is the frozen argv builder; none of the
verifier's bindings can be influenced by evidence bytes (they are equality checks against
constants, pins, and the authorization/handoff), and none can influence the argv.

### 2.3 Fatal coupling (why no lab argv can pass)

`_recompute_argv_digest` calls `build_nuclei_argv` **unconditionally**. That single call encodes
both the guard flag and the production scratch root into the expected digest. The verifier never
sees the executed argv — only its hash — so digest equality *is* the proof of the exact argv
tuple. Since `argv_digest_for` is a collision-resistant hash over the full token list, digest
equality implies **byte-identical argv**, including `-restrict-local-network-access`.

---

## 3. Exact Structural Conflict (section B)

Proof from code, both branches with a deterministic outcome:

### Branch 1 — production argv (guard present)

- `verify_nuclei_observation` recomputes `expected_digest` over an argv that contains
  `-restrict-local-network-access` (`nuclei_executor.py:934`).
- Inside the child, Nuclei v3 interprets that flag as *deny any local/private destination*.
  B10-LAB.5 empirical scan: executable with the guard against
  `http://172.31.209.10:80` → **exit 0, zero JSONL, no matcher signal**.
- Result: the digest *matches* (the record's observed digest equals the recompute) but there is no
  nuclei signal → `nuclei_no_advisory_signal` (`nuclei.py:104`). **Not a MATCH.**

### Branch 2 — lab argv (guard absent)

- Reachable: B10-LAB.5 empirical scan of the same argv minus the one flag produced a genuine JSONL
  finding with `"matcher-status":true` → real Nuclei MATCH. The argv the observation actually
  carried is `affbc093195022a28e2a1e2b68ff8484313627daaa773bf9cf8237f20684e174`.
- `_recompute_argv_digest` necessarily rebuilds the argv **with** the guard and with the production
  scratch path `/srv/watch/scratch/nuclei/{ex_id}/{hash[:16]}.json`, producing
  `3217ca9b9a1c7ba32e2b5eb892d8954283a9c48c164a89382850a5970789bbbb`
  (B10-LAB.5 recorded digest).
- The two argv tuples differ by at least the guard token → SHA-256 differs →
  `observation.argv_digest != expected_digest` (`nuclei.py:94`) → `argv_digest_mismatch`
  (`nuclei.py:95`). **Rejected before the match datum is even examined.**

### Collision

There is exactly one argv tuple that equates to the recomputed digest — the frozen production
argv, which is uncallable against an RFC1918 lab (Branch 1). Every argv tuple that can genuinely
match the lab recomputes to a different digest (Branch 2). No intermediate argv exists that is both
digest-equal and lab-callable, because digest equality requires byte-equality of the full token
list and the two surviving candidates differ in at least one mandatory token.

**Therefore `VERIFIED MATCH` through the unmodified production verifier is impossible for this
reviewed RFC1918 lab target. This is a structural property of the const-call graph, not a defect
in the lab adapter (B10-LAB.5 §7, F2).**

---

## 4. Option Comparison (section C)

### Option 1 — LAB-specific argv digest recomputation
Add a lab argv builder + lab recompute so LAB records verify their digest against the LAB argv.

| Axis | Assessment |
|---|---|
| Files that would change | `ai/lab/argv.py` (new), `ai/lab/verifier.py` (new). Production: none. |
| Production behavior changes | None (only new callers of pure helpers). |
| Production schemas change | None. |
| Production findings → LAB path | No: lab verifier class/target/template/artifact pins reject all production-class records. |
| LAB artifacts → production | No: production closed literal + `extra="forbid"` reject the lab contract at parse. |
| Attack surface | The lab recompute + constant argv (deterministic; no caller inputs). |
| Test requirements | Lab digest determinism, gate-order, cross-path (in both directions), forged digest. |
| Migration complexity | Low. |
| Recommendation | **Adopt as component of the preferred design** (the digest basis for lab records). |

### Option 2 — LAB-specific verifier entry point
A distinct `verify_lab_observation` in `ai/lab/` (analytic mirror of §2 but pinned to lab).

| Axis | Assessment |
|---|---|
| Files that would change | `ai/lab/verifier.py` (new). Production: none. |
| Production behavior changes | None. |
| Production schemas change | None. |
| Production findings → LAB path | No. |
| LAB artifacts → production | No (production verifier never called by lab; lab class not in production `SUPPORTED_EXECUTION_CLASSES`). |
| Attack surface | Second verifier to maintain; all state constant-bound. |
| Test requirements | Full analytic-gate suite for the lab variant; parity checks vs production logic. |
| Migration complexity | Low-Medium (a parallel analytic gate). |
| Recommendation | **Adopt** (with Option 1 + Option 4). This is the only route where a lab argv digest can equate to the executed argv. |

### Option 3 — Verifier policy object / verifier profile
Add a profile/mode parameter so a caller picks the digest basis.

| Axis | Assessment |
|---|---|
| Files that would change | Would require touching `ai/verification/deterministic/nuclei.py` (forbidden), plus new policy plumbing. |
| Production behavior changes | **Yes** — every caller now passes a policy; risk of accidental lab-mode dispatch. |
| Production schemas change | None necessarily. |
| Production findings → LAB path | **Yes** if the profile is ever defaulted or derived from caller/env. |
| LAB artifacts → production | **Yes** — the profile is the attack/confusion vector. |
| Attack surface | High: a single caller-supplied or env-derived flag decides security posture — precisely the "generic disable-security-flag switch" and "caller-controlled verifier mode" the constraints forbid. |
| Test requirements | Huge (every profile × every gate). |
| Migration complexity | High (contract change across the verifier API). |
| Recommendation | **REJECT** (violates constraints: forbidden file, caller-controlled mode, env switch). |

### Option 4 — LAB-specific Evidence/Observation contract
New `ai/lab/schemas.py` with `LabEvidenceRecord`/`LabNucleiObservation` and a **lab-local** closed
literal `lab_nuclei_scan` + schema version `evidence-lab/v1`.

| Axis | Assessment |
|---|---|
| Files that would change | `ai/lab/schemas.py` (new). Production schemas: none (production literal files untouched; the new literal lives in a new module). |
| Production behavior changes | None. |
| Production schemas change | None (type-level isolation is *added*, not mutated). |
| Production findings → LAB path | No: production `EvidenceRecord` validates with `extra="forbid"` and would fail to parse lab-schema bytes; a genuine production record is rejected by the lab contract (class literal mismatch) and by lab pins. |
| LAB artifacts → production | No: production parser rejects `evidence-lab/v1` + `lab_nuclei_scan`; production `PINNED_TEMPLATE_DIGEST` resolver never selects the lab digest (B10-LAB.5 §1.1/1.2). |
| Attack surface | Schema must remain closed (`extra="forbid"`, bounded samples, hash-sized fields). |
| Test requirements | Schema validation, closed-literal, forbidden-field, cross-parse rejection both ways; content-addressed seal. |
| Migration complexity | Low. |
| Recommendation | **Adopt** (structural isolation foundation). |

### Option 5 — Separate LAB lane that consumes production verifier after a LAB pre-verification
"Run the production verifier, but only after a LAB-specific deterministic pre-verification step."

| Axis | Assessment |
|---|---|
| Files that would change | `ai/lab/*` (new); production: none. |
| Production behavior changes | None. |
| Production schemas change | None. |
| Production findings → LAB path | No. |
| LAB artifacts → production | No. |
| Attack surface | None added to production, but **incapable of the goal**: the production verifier *always* recomputes the production argv digest (`nuclei.py:49-68`), so even after a correct lab pre-verification the final gate returns `argv_digest_mismatch`. A pre-step cannot retrofit the digest without either (a) forging the observation digest (threat-model: forged argv digest — unacceptable) or (b) running the uncallable production argv (Branch 1 — no signal). |
| Test requirements | Would only document the dead-end (already done in B10-LAB.5). |
| Migration complexity | N/A. |
| Recommendation | **REJECT in literal form.** Its *isolation intent* is adopted: the lab runs a separate, deterministic analytic gate — that is Option 2, not "consume the production verifier." The production verifier is reused only as pure helper *functions* (digest, target-string, flag assertions), never as the verdict-decision function for lab records. |

### Comparative summary

| Option | Diff volume | Prod behavior | Prod schemas | Prod→Lab leak | Lab→Prod leak | Attack surface | Verdict |
|---|---|---|---|---|---|---|---|
| 1 (lab digest recompute) | small | unchanged | unchanged | none | none | low | adopt |
| 2 (lab verifier entry) | small/med | unchanged | unchanged | none | none | low-med | adopt |
| 3 (verifier profile) | critical (forbidden file) | **changed** | none | **yes** | **yes** | high | **reject** |
| 4 (lab contract) | small | unchanged | unchanged | none | none | low | adopt |
| 5 (pre-verify + prod verifier) | small | unchanged | unchanged | none | none | none (inert) | reject (can't reach MATCH) |

---

## 5. Recommended Design (section D) — "Closed LAB Verification Arc" (`ai/lab`)

One coherent design folding Options 1 + 2 + 4 into the existing B10-LAB.5 `ai/lab` lane. No
production file is changed, no production function becomes a verdict-decider, no env var is added.

### 5.1 New files (all under `ai/lab/`, none production)

**`ai/lab/schemas.py`** — the LAB evidence contract (Option 4):
- `LabExecutionClass = Literal["lab_nuclei_scan"]` — a **lab-local** closed literal in a new module;
  the production `ExecutionClass` (`execution_authorization.py:77`) and `EvidenceExecutionClass`
  (`evidence.py:60`) files are untouched.
- `LAB_SCHEMA_VERSION = "evidence-lab/v1"` (vs production `"evidence/v1"`).
- `LabEvidenceRecord`: minimal mirror of `EvidenceRecord` (`evidence.py:479-511`) with
  `execution_class: LabExecutionClass`, lab id namespaces (e.g. `lab-ev-*`/`lab-ex-*`) reusing the
  existing id regexes, `target: TargetIdentity` **reused from production** `ai.schemas.evidence`
  (pure, unmodified, `scheme: Literal["http","https"]`), `template_binding:
  LabTemplateBinding`, `nuclei: LabNucleiObservation`, lifecycle `LAB_BUILDING`/`LAB_SEALED`,
  and the frozen seal triple `bindings_hash`/`observations_hash`/`content_hash` recomputed over a
  canonical lab envelope (5.2). `extra="forbid"` everywhere.
- `LabNucleiObservation`: mirror of `NucleiObservation` (`evidence.py:386-418`) —
  `template_id`, `template_hash`, `argv_digest`, `exit_code`, `timed_out`, `killed`,
  `stdout_hash`, `stderr_hash`, bounded samples, `finding_like_text_present`.

**`ai/lab/argv.py`** — the LAB argv spec (Option 1):
- `LAB_SCRATCH_ROOT = "/srv/watch/scratch/lab/nuclei"` (carried from B10-LAB.5 `config.py`).
- `LAB_TARGET_STRING = "http://172.31.209.10"` (port-80-elided canonical form; asserted equal to
  `build_target_string("http","172.31.209.10",80)` in tests).
- `build_lab_nuclei_argv(*, template_path, target_string) -> tuple[str, ...]`: closed builder.
  It mirrors production `build_nuclei_argv` (`nuclei_executor.py:879-936`) **flag-for-flag** with
  exactly two differences: (a) template path asserted under `LAB_SCRATCH_ROOT/` (not production
  root), (b) the single token `-restrict-local-network-access` is semantically required **absent**
  — the builder returns the frozen lab tuple with every other token byte-identical, including
  `-disable-redirects`, `-no-interactsh`, `-bulk-size 1`, `-concurrency 1`, `-timeout 5`,
  `-retries 0`, `-nc`.
- `assert_lab_argv(argv)`: reuse production `assert_frozen_argv_supported`
  (`nuclei_executor.py:939-995`) for the shared flag contract, then require **exact tuple equality**
  against the frozen lab constant (an attacker/tamper cannot inject any flag).
- `lab_argv_digest(template_hash, execution_id)` = `argv_digest_for(build_lab_nuclei_argv(...))`
  — deterministic, artifact-independent except for the pinned template hash prefix, recomputable by
  the verifier.

**`ai/lab/verifier.py`** — the LAB verifier entry point (Option 2):
`verify_lab_observation(record: LabEvidenceRecord) -> LabAdvisory`, mirroring the production gate
**order and fail-closed spirit** of `verify_nuclei_observation` (`nuclei.py:71-104`) with LAB pins:

| G | Condition | Reject reason (closed) |
|---|---|---|
| 1 | `record.nuclei` and `record.template_binding` present | `lab_observation_missing` / `lab_template_binding_missing` |
| 2 | `template_id == "cve-2026-1557-lab"`; `template_hash == 1b806a7c...` (both vs binding **and** vs pin) | `lab_template_binding_mismatch` / `lab_template_not_pinned` |
| 3 | `execution_class == "lab_nuclei_scan"` **and** `evidence_schema_version == "evidence-lab/v1"` | `lab_class_mismatch` |
| 4 | `record.target == ("…", "172.31.209.10", "http", 80, "")` — exact tuple, literal dotted-quad, **no DNS**; hostname/IP/port/scheme deviation rejected | `lab_target_mismatch` |
| 5 | `record.artifact_content_hash == 1b806a7c...` and artifact in lab namespace | `lab_artifact_mismatch` |
| 6 | recompute `expected = lab_argv_digest(...)` from `LAB_TARGET_STRING` + lab scratch; `observation.argv_digest == expected` | `lab_argv_digest_mismatch` |
| 7 | `derivation_binding is None`; `not timed_out and not killed`; `exit_code == 0` (stricter than production's `is not None` — a MATCH requires a clean run) | `lab_derivation_unexpected` / `lab_output_truncated` / `lab_exit_nonzero` |
| 8 | recompute the lab seal triple over the canonical lab envelope == record triple | `lab_seal_hash_mismatch` |
| 9 | provenance: read + single-use-consume the lab authorization from the lab store; verify program/target/artifact binding and expiry ("provenance, never permission" mirroring `verify_provenance_for_handoff`) | `lab_provenance_missing` / `lab_provenance_invalid` / `lab_authorization_replayed` / `lab_authorization_expired` |
| 10 | if `finding_like_text_present` → `LabAdvisory(match=True, "lab_matcher_signal")`; else `LabAdvisory(False, "lab_no_signal")`; any gate fail → `match=False` with closed reason | — |

`LabAdvisory`/`LabVerificationResult` (in `ai/lab/verdict.py`) is a distinct namespace:
`status ∈ {LAB_VERIFIED_MATCH, LAB_UNKNOWN, LAB_REJECTED}` with closed reasons, deterministically
hashed. It is **explicitly labeled lab-only** and is never a production finding; the production
classifier's `Nuclei => POTENTIAL ceiling` is untouched.

**`ai/lab/evidence_store.py`** — lab evidence persistence isolated from production: separate
collection (e.g. `watch.evidence_lab`) or lab-namespaced documents carrying
`evidence_schema_version="evidence-lab/v1"`, so even co-located bytes are unparseable as production
records; in-memory store for tests. (B10-LAB.5 already isolates authz via lab program/lab binding.)

### 5.2 Lane integration (delta over B10-LAB.5 `lane.py`)

Existing gate order is retained and cheap: `TARGET → TEMPLATE → EGRESS → SANDBOX → AUTHZ →
EXECUTE → COLLECT → SEAL(lab contract, lab store) → VERIFY(lab verifier) → CONSUME`.

The one change: the lane's verification step calls `verify_lab_observation` (lab verifier) instead
of routing the lab record into production `verify_nuclei_observation`. `verifier_boundary.py`
(B10-LAB.5) keeps its role as the instrumentation that *documents* why the production verifier
cannot verify lab traffic (recorded for the record, not used for the verdict). The proof-of-tie for
the lane becomes gates G6 (argv) + G8 (seal).

### 5.3 Satisfies every §D requirement

| Requirement | Satisfied by |
|---|---|
| Production verifier byte-for-byte unchanged | `nuclei.py`/`gate.py`/`classifier.py` untouched; not imported for verdicts |
| Production argv builder unchanged | `nuclei_executor.py` untouched; lab builder is a **new** closed function |
| LAB uses its own explicitly pinned argv | `ai/lab/argv.py` frozen constant; exact-tuple assertion |
| LAB argv digest deterministic | `argv_digest_for` (shared) over the closed lab tuple; recomputed by verifier G6 |
| LAB artifact identity isolated | digest pin (G2/G5), lab artifact-id namespace, `PINNED_TEMPLATE_DIGEST` untouched |
| LAB target identity isolated | exact dotted-quad tuple (G4) + `LAB_TARGET_STRING` in argv digest |
| LAB verification rejects arbitrary RFC1918 | G4 pins exactly `172.31.209.10:80`; anything else → reject; no DNS |
| LAB verification rejects arbitrary templates | G2 pins id + SHA (`1b806a7c…`); production digest `f5ba287d…` rejected |
| LAB verification cannot be invoked for production artifacts | contract isolation (class literal/schema version) + artifact pin |
| Production cannot consume LAB evidence | production parser rejects lab schema bytes (`extra="forbid"`, closed literal, schema version); separate collection |
| No generic disable-security switch | the lab argv is a closed constant; there is no parameter/flag plumbed anywhere |
| No caller-controlled verifier mode | lab verifier is a distinct callable with no dispatch; production verifier has no mode param |
| No env var can switch production into LAB mode | no new env var anywhere; production env reads frozen; lab env allowlist (B10-LAB.5) |
| Fail closed on any ambiguity | every gate → `LAB_REJECTED`/`LAB_UNKNOWN` with closed reason; match only with all 10 passing |

### 5.4 Trust boundaries

```
                          untrusted external
                                  │
                                  ▼
        ┌───────────────────────────────────────────────┐
        │  netns sandbox  (default-deny, single EGRESS  │
        │  tuple (172.31.209.10,80,tcp); no DNS/UDP/NAT;│
        │  no default route)                            │   ← production NetnsRuleSet reuse
        └───────────────────────────────────────────────┘
                                  │ only lab argv (closed constant, single -u, single -t)
                                  ▼
        ┌───────────────────────────────────────────────┐
        │  /usr/bin/nuclei pinned v3.11.1, bounded      │
        │  process (60s, 4MiB caps, rlimits)            │   ← run_bounded_process reuse
        └───────────────────────────────────────────────┘
                                  │ stdout/stderr (untrusted, hashed, bounded samples)
                                  ▼
        ┌─────────── LAB SEAL (content-addressed) ───────┐
        │  LabEvidenceRecord, evidence-lab/v1,           │
        │  lab store (watch.evidence_lab)                │
        └────────────────────────────────────────────────┘
                                  │
                                  ▼
        ┌─────────── LAB VERIFIER (closed, ai/lab) ──────┐
        │  G1-G9 pins (target/template/artifact/argv/    │
        │  seal/provenance) → G10 matcher signal         │
        └────────────────────────────────────────────────┘
                                  │
                                  ▼
                 LAB_VERIFIED_MATCH  (lab namespace only)
                 (never production CONFIRMED/POTENTIAL)
```

Boundary invariants: the disposable lab VM can only ever receive requests shaped by the closed lab
argv, over one authorized TCP tuple, inside a default-deny namespace; Nuclei's output is untrusted
data and enters the verdict only through the shape flag `finding_like_text_present` after every
binding has been re-pinned; the verdict namespace never intersects production's.

---

## 6. Threat Model (section E)

All items below are addressed by gates G1-G10 (§5.1), arg-checking in `argv.py`, the closed
contract in `schemas.py`, and the sandbox/egress/runner reuse from B10-LAB.5:

| # | Attack | Defence | Fail state |
|---|---|---|---|
| 1 | production template → LAB verifier | G2 pins `cve-2026-1557-lab` + `1b806a7c…`; production digest `f5ba287d…` differs | `lab_template_not_pinned` |
| 2 | LAB template → production verifier | production closed literal + schema version reject `lab_nuclei_scan`/`evidence-lab/v1`; resolver `PINNED_TEMPLATE_DIGEST` excludes lab digest | parse/`SUPPORTED_EXECUTION_CLASSES` rejection |
| 3 | wrong LAB template | G2 template-id/hash pin | `lab_template_binding_mismatch` |
| 4 | wrong SHA | G2/G5 hash pins (load-time + seal-time) | `lab_template_not_pinned`/`lab_artifact_mismatch` |
| 5 | wrong target | G4 exact tuple equality | `lab_target_mismatch` |
| 6 | hostname instead of `172.31.209.10` | G4 requires exact dotted-quad; no DNS anywhere in scope | `lab_target_mismatch` |
| 7 | wrong port | G4 `effective_port == 80` + `LAB_TARGET_STRING` in argv digest | `lab_target_mismatch` / digest |
| 8 | wrong scheme | G4 `scheme == "http"` (TargetIdentity literal) | `lab_target_mismatch` |
| 9 | changed argv | G6 digest recompute over closed constant; `assert_lab_argv` exact tuple | `lab_argv_digest_mismatch` |
| 10 | changed Nuclei binary | argv `argv[0]` == `SERVER_CONTROLLED_NUCLEI_BINARY` (shared), runner binary checks (B10-LAB.5) | runner refuses |
| 11 | changed Nuclei version | `require_pinned_nuclei_version` (shared; v3.11.1) at launch | runner refuses |
| 12 | target changed after authorization | G4 + G9: record.target vs authorization target binding; provenance read at verify time | `lab_target_mismatch`/`lab_provenance_invalid` |
| 13 | template changed after authorization | G2/G5 + G9 artifact/template binding in authorization | `lab_provenance_invalid` |
| 14 | replayed authorization | single-use consume + provenance re-check (G9); second consume raises (B10-LAB.5) | `lab_authorization_replayed` |
| 15 | expired authorization | `expires_at` enforcement in lab consume path | `lab_authorization_expired` |
| 16 | cross-lane authorization | distinct program/target/artifact namespace; lab authz binds only lab pins | `lab_provenance_invalid` |
| 17 | forged LAB evidence | G8 rehash of canonical lab envelope (content-addressed triple) | `lab_seal_hash_mismatch` |
| 18 | forged matcher status | G7 (clean run, exit 0, bounded); `finding_like_text_present` must survive rehash (G8) — altering it changes observations_hash | `lab_seal_hash_mismatch` |
| 19 | forged argv digest | G6 recompute over constant; stored value must equal recompute | `lab_argv_digest_mismatch` |
| 20 | caller-controlled verifier profile | no profile/mode exists (Option 3 rejected); lab verifier is a closed callable | n/a |
| 21 | environment-based bypass | no env var drives production or lab mode; lab env allowlist; `LIVE_NUCLEI`/`LIVE_LAUNCH_ENABLED` frozen False and untouched | runner refuses |
| 22 | proxy injection | env allowlist rejects proxy-shaped vars; argv has no `-proxy`; sandbox single tuple | `lab_argv_digest_mismatch`/sandbox (B10-LAB.5 `require_clean_launch_environment`) |
| 23 | DNS resolution | `dns_unavailable=True`, literal-IP target, no resolver in ruleset | sandbox default-deny |
| 24 | UDP egress | explicit `DROP OUTPUT udp *` in lab rule set (B10-LAB.5) | dropped |
| 25 | NAT | no NAT rules; no CAP_SYS_ADMIN on host; `require_no_default_route` | unavailable |
| 26 | unrestricted route | `require_no_default_route` + default-drop in/out (B10-LAB.5) | refused |

Note on #18: nuclei's own JSONL `"matcher-status":true` bit is *untrusted process output*; the lab
verdict is keyed to the deterministic shape flag `finding_like_text_present` derived from the same
output and content-addressed by G8. The verifier never re-parses output text and never trusts a
"matcher" string beyond that flag — mirroring the production text-shape policy (`nuclei.py:100-101`).

---

## 7. Required Tests (design — to be implemented in a later, coded task)

- **Contract**: closed literals (lab-only `lab_nuclei_scan`; production set unchanged); `extra="forbid"` on every lab model; id/hash/port validators; bounded samples.
- **Cross-path (both directions)**: production-typed record → lab parser fails; lab-typed record → production parser fails; production findings can never render `LAB_VERIFIED_MATCH`; lab verdicts never render production `POTENTIAL`/`CONFIRMED`.
- **Argv**: `build_lab_nuclei_argv` deterministic; exact-constant byte equality; `assert_lab_argv` rejects any injected flag; digest stable across calls; wrong target/port/scheme/template-hash produce distinct digests.
- **Verifier gates**: each of G1-G10 fail-closed reason; MATCH only when all pass; strict exit-0 rule; seal-triple tamper on any field.
- **Provenance**: single-use; replay; expiry; cross-lane; target/template swapped after issuance.
- **Sandbox/egress regression** (B10-LAB.5 suite): single ACCEPT tuple, default-deny, no DNS/UDP/NAT/route.
- **Offline discipline**: whole suite runs without host/network/Mongo (in-memory lab store + fake popen); real run gated by explicit operator flag, as in B10-LAB.5.
- **Regression set** (at minimum, per AGENTS.md): `ai.test_knowledge_store`, `ai.test_xss_researcher`, `ai.test_xss_llm_researcher`, `ai.test_openrouter`, `ai.test_live_validation`, `ai.test_nuclei_ready`, `ai.test_nuclei_executor`, `ai.test_lab_adapter`, plus the new lab verifier/schema/argv suites. `git diff --check` clean.

---

## 8. Rollout / Activation Gates

1. **GATE-A — code-only (offline)**: new files under `ai/lab/` only; `git diff --stat` empty
   (no tracked production file changed); `git diff --check` clean; full offline unit + regression
   suite green. Review: peer review of `schemas/argv/verifier` for closed-contract and pin fidelity;
   explicit confirmation that no production verifier/argv file is imported for verdicts.
2. **GATE-B — operator-supervised single run** on a netns-capable host (CAP_SYS_ADMIN): one
   authoritative lab run, all stages recorded; the sealed `LabEvidenceRecord` hash chain printed;
   operator confirms the raw nuclei JSONL showed the seeded fixture marker.
3. **GATE-C — decision review**: compare the run's sealed record + `LAB_VERIFIED_MATCH` verdict
   against the manual nuclei run (same argv) for digests and matcher flag; confirm no evidence
   written to production collections (only `watch.evidence_lab`).
4. **GATE-D — freeze**: lock the lab argv constant, lab target/template pins, and verdict schema
   version; any future change requires a new lab schema/argv version, never a mutation.
5. **Persistent invariants**: `LIVE_NUCLEI`, `LIVE_LAUNCH_ENABLED`, `PINNED_TEMPLATE_DIGEST`,
   production literals, and all forbidden files must remain byte-identical (enforced by test
   snapshots / diff discipline), forever.

---

## 9. Explicit GO / NO-GO Recommendation (section F)

Comparison of the three asked alternatives:

1. **Implement LAB-scoped verification (this design)** — achieves a genuine, provenance-bound,
   deterministic `LAB_VERIFIED_MATCH` for the lab namespace. Cost: a small parallel contract,
   argv spec, and analytic gate to maintain (~5 new modules, all under `ai/lab/`); production is
   untouched. Benefit: proves the seeded matcher, template, pinned binary, sandbox, authorization,
   evidence, and verification machinery end-to-end — the exact purpose of the lab lane. It does
   **not** lift the production `Nuclei => POTENTIAL` ceiling.
2. **Keep LAB advisory-only** — zero additional code; the B10-LAB.5 lane already yields an honest
   `argv_digest_mismatch` advisory and a fully exercised pipeline. Every safety property holds today.
   Cost: the pipeline never demonstrates a genuine verified match for a private lab target, leaving
   the "does a MATCH actually flow end-to-end" question answered only by manual scans.
3. **Redesign the lab target so the production argv works unchanged** — rejected: conflicts with the
   hard constraint that the lab target remain `http://172.31.209.10:80`, and would either require a
   public-IP lab (weakens private-IP protections) or removing the guard (weakens the SSRF boundary).

**Recommendation: GO with choice 1** — implement the Closed LAB Verification Arc under `ai/lab/`,
with the activation gates above. It is the smallest path that yields the requested genuine MATCH
while keeping production byte-for-byte behaviorally unchanged, schemas untouched, and every
production safety guard intact. Adopt choice 2 (advisory-only) if the cost of maintaining a
second analytic gate is refused; do not implement choice 3.

Verdict framing, stated explicitly: this design produces a **`LAB_VERIFIED_MATCH`** in a lab-only
verdict namespace. It is not the production verifier's `VERIFIED` gate status and never a production
`CONFIRMED`/`POTENTIAL`; the task's "Do not claim VERIFIED MATCH" is honored — the achievable,
lab-namespaced verdict is precisely what is recommended for implementation.

**Final status: DESIGN_READY** (design only; no code, tests, or execution performed).