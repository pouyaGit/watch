# Phase 5K Live — B10-LAB.5 Security Review

Date: 2026-09-08
Scope: security review of the LAB-only controlled-validation adapter (`ai/lab/`) built for B10-LAB.5, against the isolated CVE-2026-1557 laboratory.
Result: **GO** (isolation) / **BLOCKED** (E2E MATCH — the adapter is safe, but "VERIFIED MATCH" is structurally unreachable without weakening production; see §8).

---

## 0. Review Basis

- Code reviewed: `ai/lab/*.py` (config, artifact, egress, sandbox, runner, verifier_boundary, lane) and `ai/test_lab_adapter.py`.
- Production code reviewed for contract check: `ai/verification/deterministic/nuclei.py`, `ai/execution/nuclei_executor.py`, `ai/execution/nuclei_launcher.py`, `ai/execution/netns_sandbox.py`, `ai/schemas/execution_authorization.py`, `ai/schemas/evidence.py`, `ai/authorizer/service.py`, `ai/persistence/mongo_authz.py`, `ai/evidence/builder.py`.
- Change discipline: `git diff --stat` is **empty**; all work is new files (`ai/lab/`, `ai/test_lab_adapter.py`). No production safety guard was edited.
- Live behavior: no real namespace, no real network, no child process was exercised in the review; the adapter's real run was executed once and deterministically failed closed at the sandbox gate (see §7).

## 1. Proof obligations (STEP 15) — verdicts

### 1.1 The LAB lane cannot weaken production gates — PROVEN
- No production source file was modified (§0). The lane calls production primitives as shared *functions*; it cannot inject argv flags, environment, scratch paths, or egress tuples into them.
- `LIVE_NUCLEI=False`, `LIVE_LAUNCH_ENABLED=False` remain frozen; `ai/lab/` contains no switch that flips them.
- The production scratch root `/srv/watch/scratch/nuclei/` is never written by the lab lane: `prepare_lab_scratch` requires `{LAB_SCRATCH_ROOT}/` (`/srv/watch/scratch/lab/nuclei/`, asserted by `test_prepare_lab_scratch_writes_lab_root_only`), and `build_lab_argv` rejects any template path outside the lab root.

### 1.2 Production cannot consume a LAB artifact — PROVEN
- Production template admission is digest-pinned to `f5ba287d...` (`ai/live_validation/gates.py` `PINNED_TEMPLATE_DIGEST`); the lab digest `1b806a7c...` differs, so the production resolver can never select the lab template.
- The lab canonical artifact id (`artifact_id_for("nuclei_template", lab_tp, lab_sha)`) differs from any production digest-derived id (`test_lab_artifact_identity_never_conflicts_with_production`).
- Cross-consumption of authorizations: lab authz binds program/target/hash that exist only in the lab lane; a production executor validating target binding against a production program cannot match.

### 1.3 The LAB lane cannot consume a production artifact — PROVEN
- `ai/lab/artifact.py` hashes the exact lab file and fails closed on `LAB_TEMPLATE_SHA_MISMATCH` for any bytes ≠ `1b806a7c...` (`test_wrong_sha_rejected`). Production-pinned bytes therefore fail the lab template gate.

### 1.4 Arbitrary private destination blocked — PROVEN
- The ONLY admission surface is `check_lab_destination_allowed`, which admits exactly `(172.31.209.10, 80, http)` and rejects every other literal IP (including `10/8`, `192.168/16`, other `172.16/12` members), every hostname, every other port, every other scheme, CIDR, and wildcard (`test_exact_lab_tuple_admitted`, `test_other_private_ip_rejected`, `test_other_port_rejected`, `test_other_scheme_rejected`, `test_hostname_rejected`, `test_cidr_and_wildcard_rejected`).
- The target string passed to path is `build_target_string("http","172.31.209.10",80)` (authority-free, default port elided) — a canonical host bound in the authorization `TargetBinding`, so path/userinfo smuggling is structurally impossible.

### 1.5 Arbitrary template blocked — PROVEN
- Template identity is `LAB_TEMPLATE_SOURCE_DIR + "/" + LAB_TEMPLATE_SOURCE_NAME`, both fixed constants; the SHA-256 must equal the pinned digest at load and again after scratch write (`gate_template`, `prepare_lab_scratch`; `test_lab_argv_rejects_non_lab_template_root`).
- The argv carries exactly one `-t` (lab scratch path) and exactly one `-u`; `-retries 0`, `-concurrency 1`, `-bulk-size 1`, redirects disabled (`test_lab_argv_frozen_shape`).

### 1.6 Default-deny network sandbox required — PROVEN
- `LabSandbox.run` executes the child ONLY through a verify-stage-gated namespace: probe → create → configure(NetnsRuleSet) → verify → launch-prefix → bounded process → teardown, with fail-closed `LabSandboxError` at every stage and **no host-network fallback** (§1.11; sandbox lifecycle tests).
- Symmetrically to production `NetnsRuleSet`: `default_drop_output=True`, `default_drop_input=True`, `no_unrestricted_default_route=True`, `dns_unavailable=True`, `loopback_only_inside=True`, re-checked through production `require_default_deny`/`require_no_default_route`.

### 1.7 Only the reviewed lab tuple permitted — PROVEN
- The compiled ruleset contains exactly ONE ACCEPT rule: `OUTPUT tcp 172.31.209.10:80` (`test_netns_ruleset_is_default_deny_single_tuple`). Everything else is DROP by default-any rule.

### 1.8 No DNS / UDP / NAT — PROVEN
- `dns_unavailable=True`; explicit `DROP OUTPUT udp dst 53`, `DROP OUTPUT udp *`, `DROP OUTPUT {tcp,udp} dst 169.254.169.254`; no resolver, no UDP, no NAT rule, no unrestricted default route in the ruleset.

### 1.9 Single-use, expiring authorization — PROVEN
- Authorization minted through `issue_authorization` (real service) with `max_executions=1`, `expires_at = issuance + 4 h`, issuer `human-review-board`, caller scope `manual`.
- Single-use consume via `consume_authorization`/`consume_single_use`; replay of a second consume raises (`test_expiry_and_replay`); sandbox gate runs **before** issuance so a blocked host spends nothing (asserted: `authorization_id=None`, empty store, no Mongo contact — documented in test `test_blocked_before_authz_when_sandbox_unavailable`).
- `idempotency_key_for` derives from the full binding (plan, artifact id, hash, program, host, class, scope hash, caller), so a distinct lab basis cannot alias a production record even if one existed.

### 1.10 Evidence scrubbed and bound to authority — PROVEN
- Evidence sealed by the real `EvidenceBuilder` bound from the genuine `IssuedExecutionAuthorization` (typed-only `EvidenceBuilder.begin`); `TemplateBinding` is recomputed from the attached `NucleiObservation` at attach time.
- `NucleiObservation` carries hashes + bounded samples only (no plaintext authorization, no credentials, no secrets); `argv_digest` is captured from the actual frozen lab argv. The real advisory gate is then invoked on the sealed record — the honest outcome (`argv_digest_mismatch`) is reported rather than a fabricated MATCH (`test_full_lifecycle_honest_verifier_outcome`).

### 1.11 Fail-closed execution without a sandbox — PROVEN
- `probe_lab_sandbox` (production `probe_netns_capabilities`) gates the lane; on this host it reports unavailable and the lane returns `BLOCKED/LAB_SANDBOX_UNAVAILABLE` **before** any mint, spawn, or scratch write (`test_run_refuses_before_spawn_when_unavailable` confirms the popen factory is never called).
- Child bound by `run_bounded_process`: 60 s wall, 4 MiB stdout/stderr caps, rlimits (memory 256 MiB, cpu 30 s, proc 64, fd 1024, file 16 MiB), allowlisted environment (`build_lab_environment`: HOME/LANG/LC_ALL/PATH/TMPDIR only), proxy / resolver / CA shapers fail closed.

## 2. Findings by severity

### F1 (informational, structural) — `lab_nuclei_scan` unrepresentable
`ExecutionClass` (`execution_authorization.py:77`) and `EvidenceExecutionClass` (`evidence.py:60`) are closed Literals without `lab_nuclei_scan`. The STEP 7 label cannot be encoded in a production record. Mitigation: lane-level distinction (artifact digest, target tuple, template id, scope hash, `audit_metadata.lab_execution_class`). No weakening made. Test-pinned.

### F2 (blocking, by design) — VERIFIED MATCH unreachable for this lab
- Lab argv minus `-restrict-local-network-access` → reaches lab but the verifier recompute (`_recompute_argv_digest` over `build_nuclei_argv`) necessarily differs → `argv_digest_mismatch`.
- Lab argv with the guard → verifier digest matches but nuclei silently no-matches a private destination → `nuclei_no_advisory_signal`.
Both proven by empirical scan (§0 experiment) and by tests (`test_verifier_recompute_mismatch_is_structural`, `test_guard_included_argv_matches_digest_but_is_uncallable`). This is the reason the honest classification is BLOCKED for the expected outcome; it is NOT a safety defect — the adapter never fabricates a verdict.

### F3 (environment) — no netns on this host
The lane is designed to require a default-deny namespace; on a non-CAP_SYS_ADMIN host it fails closed (`unshare -n` denied). Safe by design; recorded as `LAB_SANDBOX_UNAVAILABLE`.

## 3. Residual risks / notes
- The lab runs against a **disposable, isolated VM** (`172.31.209.10:80`) reviewed by the board under `lab-nuclei-egress/v1`; it remains a RFC1918 destination with a board-approved single-tuple exception that only the lab lane can reference.
- The lab fixture text `/tmp/watch-cve1557-nuclei-fixture.txt` is harmless (a fixed marker string) and is the only thing the lab template can retrieve.
- If a future build releases the guard for the lab argv, the verifier must be given a lab-scoped recompute story or the lab lane must remain advisory-only (see implementation report §9). Both are boundary adjustments requiring explicit authorization; neither was applied here.

## 4. Conclusion
- **GO** — the LAB adapter is safe for this disposable lab: it reuses production bounding/authorization/evidence/verification without weakening any of them, enforces default-deny single-tuple egress, single-use expiring authorization, closed-argv execution, and fail-closed sandboxing.
- **BLOCKED** — the task's expected "Nuclei MATCH → VERIFIED MATCH" cannot be produced through the unmodified production verifier for a reviewed RFC1918 lab target. That is a documented, test-enforced, structural boundary — not a defect in the adapter.

Scope of changes: new files only (`ai/lab/`, `ai/test_lab_adapter.py`); `git diff --stat` empty; no production guards modified.