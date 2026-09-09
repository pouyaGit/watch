# Phase B10-LAB.4 — Watch End-to-End Controlled Lab Validation

**Date:** 2026-09-08
**Status:** **BLOCKED**
**Classification:** BLOCKED — six independent structural blockers prevent the lab template from flowing through the production lane without new infrastructure.

## Summary

After tracing the complete production controlled-validation path against the Watch codebase, this phase concludes that **no safe seam exists** to supply the LAB-ONLY template (`CVE-2026-1557-lab.yaml`, SHA `1b806a7c...`) through the existing `ControlledLiveValidationLane` without bypassing production safety architecture.

The architecture is **correct and intentional**: the same guards that block the lab target are what make the production lane safe. Weakening or bypassing any guard would violate the safety design.

## STEP 1 — Complete Production Path Trace

```
AuthorizationRequest                        [ai/live_validation/lane.py:507-531]
  ├─ artifact.artifact_id = artifact_id_for( [ai/live_validation/gates.py:510-517]
  │    content_hash=PINNED_TEMPLATE_DIGEST)  ← PRODUCTION template SHA only
  ├─ target.host = 172.31.209.10             [lane.py:519-525]
  └─ expires_at = EXPIRES_FAR_FUTURE

issue_authorization(MongoAuthzStore, req)    [ai/persistence/mongo_authz.py:209-217]
  ↓
get_issued_authorization(store, id)          [mongo_authz.py:299-310]
  ↓
_resolve_addresses(host)                     [lane.py:602-631]
  ↓
_build_resolution()                          [lane.py:633-698]
  ↓
ScopeEvaluator.evaluate() → ALLOWED         [lane.py:573-579]
  ↓
check_destination_allowed("172.31.209.10")   [b3_boundary.py:317-325]
  ↓ → is_forbidden_destination returns True (RFC1918 private)
  ↓ → B6 egress gate: block("egress", "EGRESS_FORBIDDEN")

[If somehow past egress:]
build_nuclei_argv(template_path=...)         [nuclei_executor.py:879-936]
  ↓ → template_path must start with "/srv/watch/scratch/nuclei/"
  ↓ → LAB template at /opt/watch-lab/... REJECTED

launch_nuclei_bounded()                      [nuclei_launcher.py:506-576]
  ↓ → require_production_sandbox() → SANDBOX_UNAVAILABLE (no CAP_SYS_ADMIN)
  ↓ → LIVE_LAUNCH_ENABLED=False → LAUNCHER_DISABLED

execute_nuclei(runner=FakeNucleiRunner)      [nuclei_executor.py:1865-1915]
  ↓ → LiveNucleiRunner → NUCLEI_EXECUTION_BLOCKED
  ↓ → FakeNucleiRunner → scripted (no real Nuclei)
```

## STEP 2-10 — Six Independent Structural Blockers

### Blocker 1: Template Artifact Identity (gates.py:34-60, 95-112)

`resolve_pinned_candidate("CVE-2026-1557")` returns only `PinnedCveCandidate` with:
- `template = PINNED_TEMPLATE` (production: `wp-config.php` traversal)
- `digest = PINNED_TEMPLATE_DIGEST = "f5ba287d...b8d"` (production template SHA)
- `canonical_bytes = PINNED_TEMPLATE_BYTES` (production template canonical bytes)

**No code path accepts an alternative template or digest.** The authorization is bound to `PINNED_TEMPLATE_DIGEST` at `lane.py:514`. The LAB template's digest (`1b806a7c...`) is a different artifact identity.

**Required for lab path:** A new `PinnedCveCandidate` variant or a `lab_template` parameter that creates a distinct `AuthorizationRequest` bound to the LAB template's SHA. This requires new code; no existing seam supports it.

### Blocker 2: Template Path Guard (nuclei_executor.py:902-906)

```python
if not template_path.startswith(_SCRATCH_ROOT + "/"):
    raise ExecutorError("TARGET_EXPANSION_DENIED", "template path outside scratch")
```

Where `_SCRATCH_ROOT = "/srv/watch/scratch/nuclei"`. The LAB template is at `/opt/watch-lab/cve-2026-1557/CVE-2026-1557-lab.yaml`.

**The argv builder rejects any template path not in the production scratch directory.** The template path is derived from `report.template_hash[:16].json` where `report` comes from the pinned template's safety validation. There is no injection point for an arbitrary path.

**Required for lab path:** Either a separate scratch root for lab templates, or a new code path that skips the path guard for a lab-specific execution class. Both require new code.

### Blocker 3: RFC1918 Egress Guard (b3_boundary.py:288-314, lane.py:343-357)

The B6 egress gate in `lane.py:343-357`:
```python
for addr in resolution.resolved_addresses:
    if is_forbidden_destination(addr):
        return block("egress", f"EGRESS_FORBIDDEN: {addr}")
```

`172.31.209.10` is RFC1918 private → `classify_address` raises → `is_forbidden_destination` returns `True` → gate blocks with `EGRESS_FORBIDDEN`.

**This is correct and desirable.** It proves the production lane physically refuses to contact private/lab networks. The production lane's safety relies on this guard.

**Required for lab path:** A separate lane or a lab-specific egress policy that explicitly allows the lab target. This requires new infrastructure (e.g., `LabLiveValidationLane` with a lab-specific egress allowlist).

### Blocker 4: Sandbox Gate (nuclei_launcher.py:450-503)

```python
caps = materializer.capabilities()
if not caps.can_create_netns:
    raise LauncherError("SANDBOX_UNAVAILABLE", "production sandbox not provisionable")
```

`SystemNetnsBackend.capabilities()` → `can_create_netns = False` (no `CAP_SYS_ADMIN`).

**This is correct.** Without network namespace capability, the production sandbox cannot be provisioned. This gate correctly refuses live execution when isolation cannot be guaranteed.

**Required for lab path:** A lab-specific backend that provides a different isolation model (e.g., Docker container network isolation, or a simplified sandbox that trusts the lab's internal bridge). This requires new code.

### Blocker 5: Master Launch Switch (nuclei_launcher.py:85, 574)

```python
LIVE_LAUNCH_ENABLED = False  # frozen constant
```

Even if every other gate passed, the frozen `False` constant blocks execution. No code path can set it to `True`.

**This is correct.** The master switch is the final defense-in-depth. It ensures no accidental or unauthorized execution occurs.

**Required for lab path:** A lab-specific runner that bypasses `launch_nuclei_bounded` entirely (e.g., a `LabNucleiRunner` that directly spawns nuclei without the launcher's gate chain). This requires new code and security review.

### Blocker 6: Watch AI Live Validation Env Gate (config.py:21-36)

```python
if mode == "live":
    try:
        require_live_validation_enabled()
    except LiveValidationDisabled:
        return block("config", "LIVE_VALIDATION_DISABLED")
```

`WATCH_AI_LIVE_VALIDATION` is currently unset. Even if set to `true`, Blockers 1-5 remain.

**Required for lab path:** Setting the env var is necessary but insufficient. All other blockers remain.

## Architectural Assessment

**No safe seam exists today.** The production lane (`ControlledLiveValidationLane`) is a tightly integrated gate chain where:

1. The template identity is cryptographically pinned to the production template
2. The template path is locked to a production-only scratch directory
3. The egress guard rejects private addresses (by design)
4. The sandbox gate fails closed without kernel capabilities
5. The master switches are frozen `False` constants
6. The environment gate is a necessary but insufficient precondition

Every one of these guards is **correct and intentional**. They are the safety architecture that makes the production lane trustworthy. Weakening or bypassing any guard for lab purposes would compromise the production lane's safety guarantees.

## What Would Be Required for a Lab E2E Path

To run the Watch lane end-to-end against the lab target, the following new infrastructure would be needed:

1. **LabTemplateCandidate**: A new `PinnedCveCandidate` variant or factory that accepts the LAB template's SHA and bytes, creating a distinct artifact identity.

2. **LabScratchRoot**: A separate template scratch directory (e.g., `/srv/watch/scratch/lab/nuclei/`) that the LAB template can be written to and the argv builder can accept.

3. **LabEgressPolicy**: A lab-specific egress allowlist that explicitly permits `172.31.209.10:80` (or the lab target), with a distinct policy version (e.g., `lab-nuclei-egress/v1`).

4. **LabSandboxBackend**: A `NetnsBackend` variant that provides lab-appropriate isolation (e.g., Docker container network, or a "trusted lab" mode that skips namespace creation when the target is known-safe).

5. **LabNucleiRunner**: A `NucleiRunner` implementation that actually spawns the pinned Nuclei binary with the frozen argv, inside the lab sandbox. This replaces `FakeNucleiRunner` (offline) and `LiveNucleiRunner` (blocked).

6. **LabLiveValidationLane**: A variant of `ControlledLiveValidationLane` that wires these lab-specific components through the existing gate chain, preserving all other safety checks (auth verification, scope evaluation, evidence sealing, deterministic verification).

Each of these requires:
- New code
- New unit tests
- Security review
- Integration verification

This is a substantial but well-scoped engineering task. The existing architecture provides clean injection points for all of these (the lane accepts injected `runner_factory`, `resolver`, `policy_store`, `authz_store`). The key insight is that the existing abstractions are designed for exactly this kind of extension — they just haven't been extended to a lab variant yet.

## Existing Lane Injection Points (Relevant for Future Extension)

The `ControlledLiveValidationLane.__init__()` accepts:
- `runner_factory: Callable[[], Any]` → can return a `LabNucleiRunner`
- `resolver: Any` → can return lab target addresses
- `policy_store: InMemoryPolicyStore` → can include lab target in scope
- `authz_store: AuthorizationStore` → can use `MongoAuthorizationStore` (already proven)
- `now / monotonic` → time injection

The lane's `run()` method:
- Gate 1 (config): can be satisfied with `WATCH_AI_LIVE_VALIDATION=true`
- Gate 2 (target): accepts any target string
- Gate 3 (candidate): hardcoded to `CVE-2026-1557` — would need a lab variant
- Gate 4 (template): hardcoded to `PINNED_TEMPLATE` — would need a lab variant
- Gate 5 (authorization): uses `candidate.digest` — would need a lab variant
- Gate 6 (scope): uses `ScopeEvaluator` with injected policy — lab policy can allow lab target
- Gate 6b (egress): checks every resolved address — lab policy must explicitly allow lab addresses
- Gate 7 (execution): uses `runner_factory()` — lab runner can spawn real Nuclei
- Gate 8 (verification): deterministic — works with any evidence

The abstractions are clean. What's missing is the lab-specific wiring.

## Remaining Evidence from Prior Phases

The lab environment and template remain as proven test evidence:
- Lab: `http://172.31.209.10:80` (Docker bridge, isolated, healthy)
- Template: `/opt/watch-lab/cve-2026-1557/CVE-2026-1557-lab.yaml` (SHA `1b806a7c...`)
- Prior manual Nuclei run: MATCH confirmed (LAB.3)
- Prior curl traversal: marker confirmed (LAB.2)

These remain valid and reproducible for manual validation or for a future lab-aware Watch lane.

## Cleanup

No synthetic records were created. No lab authorization was issued. No Nuclei was executed through the Watch lane. The lab remains running. The production pinned template and digest are byte-unchanged.

## Safety Checks

- [x] No external network destinations contacted
- [x] No DNS requests made
- [x] No public port exposure
- [x] No production Mongo records modified
- [x] No credentials accessed
- [x] No wp-config.php accessed
- [x] No Nuclei process remains
- [x] Lab remains healthy
- [x] Production pinned template unchanged
- [x] LIVE_NUCLEI and LIVE_LAUNCH_ENABLED remain False
- [x] WATCH_AI_LIVE_VALIDATION not set (and lane not invoked)
- [x] No git operations

## Final Classification

**BLOCKED**

The existing Watch production lane cannot safely execute the LAB-ONLY template because:
1. Template identity is pinned to the production template digest
2. Template path guard rejects non-production scratch paths
3. Egress guard rejects RFC1918 addresses (by design)
4. Sandbox gate fails closed without kernel capabilities
5. Master launch switches are frozen False
6. No lab-specific code path exists

A safe lab E2E path requires new infrastructure (lab template candidate, lab scratch root, lab egress policy, lab sandbox backend, lab Nuclei runner). The existing abstractions are well-designed for this extension; no existing safety guards need to be weakened.

Report generated:
`agent-reports/phase-5k-live-b10-lab-4-watch-e2e-validation.md`
