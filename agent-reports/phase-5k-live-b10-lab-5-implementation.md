# Phase 5K Live — B10-LAB.5 Implementation Report

Date: 2026-09-08
Task: B10-LAB.5 — Safe, isolated, LAB-only controlled-validation adapter for the disposable CVE-2026-1557 laboratory.
Status: **BLOCKED** (implementation) — READY_FOR_LAB_E2E is structurally unreachable without modifying production safety guards, which this task forbids.

---

## 1. Objective

Build a LAB-ONLY controlled-validation execution adapter that drives the **existing Watch controlled-validation architecture end-to-end** against the isolated CVE-2026-1557 laboratory:

- Target: `http://172.31.209.10:80` (disposable lab VM)
- Lab template: `/opt/watch-lab/cve-2026-1557/CVE-2026-1557-lab.yaml`, SHA-256 `1b806a7cefc88b82fbf10848d70f02752f6aa75695ff66389e8802572f6c2de9` (distinct from the production pinned digest `f5ba287d518652b8b222a8c030931360c2f9398de8204a60de2c4c4c1f0b1b8d`)
- Expected (per task): a seeded Nuclei MATCH produced through a fail-closed, default-deny, bounded execution boundary.

The task explicitly forbids weakening any hardened production primitive ("DON'T weaken 5A"). This report documents what was implemented, what was proven, and exactly where a production boundary structurally prevents the expected outcome.

## 2. Environment Facts (re-verified this phase)

| Fact | Value | Evidence |
|---|---|---|
| Runtime user | uid 1001 (unprivileged) | `id` |
| Network sandbox capability | **unavailable** — `unshare -n true` → `Operation not permitted` (no CAP_SYS_ADMIN) | `probe_netns_capabilities()` |
| Nuclei binary | `/usr/bin/nuclei` → `Nuclei Engine Version: v3.11.1` (= `PINNED_NUCLEI_VERSION`) | `nuclei -version` |
| Lab reachability | TCP 172.31.209.10:80 open; HTTP 200 | `/dev/tcp` + curl |
| Lab fixture | recreated in `cve1557-lab-wp` at `/tmp/watch-cve1557-nuclei-fixture.txt` = `WATCH_CVE1557_NUCLEI_LAB_MARKER_2883fc88` | LAB.3 precedent + re-verification |
| Live execution flags | `LIVE_NUCLEI=False`, `LIVE_LAUNCH_ENABLED=False` | code, frozen, untouched |

## 3. What Was Built

New, LAB-only package `ai/lab/` (no production file was modified — see §6):

| File | Purpose | Reused production machinery (unmodified) |
|---|---|---|
| `ai/lab/config.py` | Closed `LAB_*` constants; target tuple, template digest, scratch root, authz policy | — |
| `ai/lab/artifact.py` | Typed `LabArtifact` identity, SHA-pinned template loader | — |
| `ai/lab/egress.py` | Exact-tuple admission gate + default-deny lab rule construction | `EgressRule`, `NetnsRuleSet`, `require_default_deny`, `require_no_default_route` |
| `ai/lab/sandbox.py` | Fail-closed lab namespace lifecycle (CREATE→CONFIGURE→VERIFY→EXECUTE→COLLECT→TEARDOWN) | `probe_netns_capabilities`, `run_bounded_process` |
| `ai/lab/runner.py` | Frozen lab argv (single documented divergence), closed env allowlist, scratch materialization under lab root | `assert_frozen_argv_supported`, `require_clean_launch_environment`, `check_nuclei_binary`, `read_nuclei_version_output`, `require_pinned_nuclei_version`, `argv_digest_for` |
| `ai/lab/verifier_boundary.py` | Structural no-match proof instrumented against the REAL verifier/argv builders | `build_nuclei_argv`, `argv_digest_for`, `verify_nuclei_observation` |
| `ai/lab/lane.py` | Single-use orchestrator `LabValidationLane.run()` + typed `LabLaneResult`/`LabLaneBlocked` | `issue_authorization`, `consume_authorization`, `AuthorizationRequest`/`TargetBinding`/`ArtifactBinding`, `EvidenceBuilder`, `build_target_string` |
| `ai/test_lab_adapter.py` | 38 adversarial unit tests (offline; no host contact) | `InMemoryAuthorizationStore` |

## 4. Lane Design (fail-closed, cheapest gates first)

```
TARGET -> TEMPLATE -> EGRESS -> SANDBOX -> AUTHZ -> EXECUTE -> EVIDENCE -> VERIFY -> CONSUME
```

Decision: the sandbox gate runs **before** any authorization is minted, so a host that cannot provision the default-deny namespace spends nothing (no Mongo write, no scratch, no child process).

Reuse map (all production, unmodified):

- authority: `ai.authorizer.service.{issue,consume}_authorization` over `MongoAuthorizationStore` (real store default; `InMemoryAuthorizationStore` in tests)
- evidence: `ai.evidence.builder.EvidenceBuilder` (BUILDING→attach_nuclei→SEALED), `NucleiObservation`/`TemplateBinding` schemas
- verification: `ai.verification.deterministic.nuclei.verify_nuclei_observation` (the REAL gate — nothing synthetic)
- bounding: `run_bounded_process` (wall 60 s; stdout/stderr 4 MiB caps; rlimits memory/cpu/proc/fd/file), `require_clean_launch_environment`, pinned-binary + pinned-version checks
- egress shape: production `EgressRule`/`NetnsRuleSet` shapes + `require_default_deny` / `require_no_default_route` guards, exactly **one** ACCEPT tuple `(172.31.209.10, 80, tcp)`, explicit DROP for metadata service (tcp+udp), DNS (udp/53), and all UDP, `dns_unavailable=True`, `no_unrestricted_default_route=True`

The lab lane supplies ONLY lab wiring: the exact target tuple, the single lab digest, the lab scratch root (`/srv/watch/scratch/lab/nuclei/`, never production scratch), the lab argv, and the sandbox gate wiring.

## 5. Schema Note (critical structural fact)

`ai/schemas/execution_authorization.py:77-82`:

```python
ExecutionClass = Literal[
    "http_probe",
    "nuclei_scan",
    "http_verification",
    "browser_verification",
]
```

`ai/schemas/evidence.py:60-65` (`EvidenceExecutionClass`) is the same closed set. **`lab_nuclei_scan` is not representable** in either literal. The STEP 7 instruction "execution_class = `lab_nuclei_scan`" is therefore unrepresentable through the production schema without modifying a production type contract. Resolution taken: the LAB distinction is carried at the **lane level** (distinct artifact digest, distinct target tuple, distinct template id, distinct scope hash, `audit_metadata.lab_execution_class=lab_nuclei_scan`), while issuance/evidence carry the schema-mandated `nuclei_scan`. Test-proven in `test_execution_class_schema_literal_is_closed` / `test_evidence_execution_class_literal_is_closed`.

## 6. Real E2E Attempt — Deterministic Fail-Closed Result

Run exactly one lab validation on this host:

```
status:          BLOCKED
lane_version:    b10-lab-lane/v1
target:          http://172.31.209.10:80
gates_passed:    ('target', 'template', 'egress')
blocked.code:    LAB_SANDBOX_UNAVAILABLE
blocked.detail:  lab execution refused: unshare -n failed (no CAP_SYS_ADMIN)
boundary.reason: argv_digest_mismatch
lab_argv_digest:              affbc093195022a28e2a1e2b68ff8484313627daaa773bf9cf8237f20684e174
production_recomputed_digest: 3217ca9b9a1c7ba32e2b5eb892d8954283a9c48c164a89382850a5970789bbbb
authorization_id: None   (nothing minted — sandbox gate runs first)
```

This is the **correct, safe** outcome on this host: the default-deny namespace cannot be provisioned (no CAP_SYS_ADMIN), so the lane fails closed before authorization, scratch, or child execution. The isolated execution boundary is engageable and refuses cleanly.

## 7. Primary Blocker — VERIFIED MATCH is Structurally Impossible

Empirical proof (re-verified this phase against `http://172.31.209.10:80`):

| argv | Result |
|---|---|
| `... -restrict-local-network-access ...` (production frozen argv) | exit 0, **zero JSONL**, NO MATCH — nuclei silently refuses the RFC1918 destination |
| same argv minus the one guard flag | JSONL finding, `"matcher-status":true`, `matched-at` present → a genuine nuclei MATCH |

Code-level proof of why a VERIFIED MATCH cannot pass the unmodified verifier:

1. `ai/verification/deterministic/nuclei.py:49-68` — `_recompute_argv_digest` recomputes the digest from **`build_nuclei_argv`**, which pins:
   - `-restrict-local-network-access` (`ai/execution/nuclei_executor.py:934`)
   - template path `/srv/watch/scratch/nuclei/{ex_id}/{hash[:16]}.json` (production scratch; `scratch_dir_for`)
2. `ai/verification/deterministic/nuclei.py:86-95` — the gate requires `execution_class == "nuclei_scan"` and `observation.argv_digest == expected_digest`, else `execution_class_mismatch` / `argv_digest_mismatch`.

Collision of requirements:
- To reach the lab (RFC1918) the argv **must omit** `-restrict-local-network-access` → argv digest necessarily differs from the verifier's recompute → `argv_digest_mismatch`.
- An argv matched to the recomputed digest carries the guard → nuclei silently produces no signal → `nuclei_no_advisory_signal`.

Both branches are asserted in tests (`test_verifier_recompute_mismatch_is_structural`, `test_guard_included_argv_matches_digest_but_is_uncallable`) and mirrored by the lane's own `_boundary_proof`. The full-lab-lifecycle test also seals a real `EvidenceRecord` and calls the REAL `verify_nuclei_observation` — the advisory honestly reports `argv_digest_mismatch`, never a fabricated MATCH.

## 8. Adversarial Test Coverage (STEP 14 list)

All 38 tests in `ai/test_lab_adapter.py` pass offline (no host contact):

| STEP 14 adversarial item | Test |
|---|---|
| wrong template SHA / path | `test_wrong_sha_rejected`, `test_unreadable_template_rejected`, `test_prepare_lab_scratch_sha_gate`, `test_prepare_lab_scratch_writes_lab_root_only` |
| wrong target IP / port / scheme / hostname | `test_exact_lab_tuple_admitted`, `test_other_private_ip_rejected`, `test_other_port_rejected`, `test_other_scheme_rejected`, `test_hostname_rejected`, `test_blocked_on_target_admission` |
| CIDR / wildcard / empty / untyped | `test_cidr_and_wildcard_rejected`, `test_empty_and_typed_rejected` |
| wrong / closed execution class | `test_execution_class_schema_literal_is_closed`, `test_evidence_execution_class_literal_is_closed` |
| cross-lane artifact confusion | `test_lab_artifact_identity_never_conflicts_with_production`, `test_lab_artifact_for_happy_path` |
| DNS / UDP / NAT / metadata shapes | `test_netns_ruleset_is_default_deny_single_tuple` (single exact ACCEPT tuple, explicit DROP udp/53, DROP all-udp, DROP metadata, default-deny in+out, no default route) |
| missing capability / binary / version | `test_probe_fail_closed_when_capability_missing`, `test_run_refuses_before_spawn_when_unavailable`, `test_version_pin_rejects_other_release`, `test_clean_environment_rejects_proxy_shaped_env` |
| retries / concurrency / multi-target | `test_lab_argv_frozen_shape` (`-retries 0`, `-concurrency 1`, `-bulk-size 1`, exactly one `-t`/`-u`), `test_lab_argv_rejects_non_lab_template_root` |
| expiry / replay / single-use | `test_expiry_and_replay`, `test_prepare_lab_scratch_rejects_replay` |
| sandbox lifecycle fail-closed | `test_create_failure_fails_closed`, `test_verify_failure_fails_closed`, `test_teardown_failure_fails_closed`, `test_run_happy_path_applies_prefix_and_teardown` |

Regression results: `test_live_validation` + `test_nuclei_ready` + `test_nuclei_executor` (175 OK); `test_openrouter` + `test_knowledge_store` + `test_xss_researcher` + `test_xss_llm_researcher` (89 OK); lab adapter (38 OK). Total 302.

## 9. Boundary Adjustments Required to Unblock

Each item would weaken a production safety guard and is therefore flagged, not applied:

1. **Sandbox capability**: this host cannot create netns (no CAP_SYS_ADMIN). A provisionable host (root/CAP_SYS_ADMIN) is required. The lane already handles it (falls through to AUTHZ → EXECUTE).
2. **Executable lab target**: release `-restrict-local-network-access` for the LAB-only argv (exactly one flag) — this is the historical reason nuclei cannot reach a reviewed RFC1918 lab.
3. **Verifier recompute**: either (a) a lab-scope argv digest recompute (e.g. lab-scoped argv builder recognized by a *heretofore-absent* lab branch in the gate), or (b) accepting that the lab advisory stays `argv_digest_mismatch` — i.e. the lab is a *probe* of the machinery, not a CONFIRMED finding source, and the expected "VERIFIED MATCH" is intentionally dropped for the lab lane.
4. **Execution-class literal**: adding `lab_nuclei_scan` to `ExecutionClass`/`EvidenceExecutionClass` would change shared production type contracts; currently the lab distinction is lane-level only.

## 10. Honest Classification

- **Implementation**: BLOCKED for the literal "expected VERIFIED MATCH" outcome. The adapter is fully implemented, isolated, and fail-closed; every gate that can be proven on this host is proven; the real run terminates deterministically and safely at the sandbox gate.
- The adapter is UI-ready for an operator on a netns-capable host; even then it would produce a *honest* advisory (`argv_digest_mismatch` or `nuclei_no_advisory_signal`), never a fabricated MATCH.
- No production safety guard was modified; `git diff --stat` is empty (all work is new files under `ai/lab/` and `ai/test_lab_adapter.py`).