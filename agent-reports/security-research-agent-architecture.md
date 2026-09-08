# AI Security Research Agent — System Architecture

## 1. Executive Summary

Watch already owns, in working code, roughly 70% of an AI-assisted
autonomous security research system: an NVD CVE collector
(`ai/collectors/cve.py`), a deterministic correlator
(`ai/correlator/`: technology/version matching, CVE assessment, shortlist,
scope policy, Nuclei decision/generation/semantic-validation),
a grounded ingestion agent with prompt-injection quarantine
(`ai/ingestion/agent.py`, `grounding.py`), a content-addressed,
source-attributed knowledge store (`ai/knowledge/store.py`), two LLM
providers behind a minimal interface (`ai/llm/`), an XSS research stack
with a hard AI/verdict separation (`ai/researcher/xss_orchestrator.py`,
`xss_researcher.py`, `xss_llm_researcher.py`), an end-to-end Nuclei
preparation pipeline (`ai/researcher/nuclei_pipeline.py`), and
deterministic execution + verification layers (`ai/verification/`:
HTTP/browser executors, XSS verifier with execution oracle, stored-XSS
rounds). MongoDB models (`Programs`, `Subdomains`, `Http`, `Urls`,
`Endpoints`, `XssFindings`) provide recon inventory and finding
persistence.

What is missing is not capability but **architecture**: there is no common
research lifecycle, no first-class Hypothesis/TestPlan/Artifact schemas, no
target-intelligence projection, no prompt registry, no model strategy, no
scheduler with cost control, no artifact sandbox, and no feedback loop from
verdicts back into intelligence. The pieces were built per-task and do not
compose into the vision flow
Sources → Collection → Understanding → Intelligence → Patterns → Relevance
→ Hypothesis → Test → Executor → Evidence → Verifier → Finding.

This document designs that composition **without redesigning anything that
works**: every existing component is classified REUSE, EXTEND, WRAP,
ISOLATE, or NEW (§19). The load-bearing invariants are preserved end to
end: AI is untrusted (never emits CONFIRMED), Research ≠ Finding, every
transition is auditable to its sources, external text and LLM output are
untrusted input, and all verdicts remain with deterministic verifiers.
The recommended first step (§21) is deliberately tiny: formalize the
Hypothesis + TestPlan schemas and route one existing flow (CVE →
shortlist → Nuclei decision) through them with no behavior change.

## 2. Current Watch Architecture

### 2.1 What exists today (verified in source)

**Recon / inventory (untouched by this design).** `ns/`, `crawl/`,
`enum/`, `http/` feed MongoDB (`database/db.py`): `Programs`
(scopes/ooscopes), `Subdomains`, `LiveSubdomains`, `Http`, `Urls`,
`Endpoints` (with `param_records`, `x8_checked`), `XssFindings`
(`case_id`-unique, serialized `XSSFinding` payloads + verification audit).
Scope safety mirrors `get_domain_name` semantics. Per AGENTS.md these
subsystems are scope-protected; the research agent consumes them
read-only through a Target Intelligence boundary (§10).

**Research collection.** `ai/collectors/`: `cve.py` (NVD API with
rate-limit, retry/backoff, `NVD_API_KEY` from env),
`exploit_discovery.py`, `reference.py`/`reference_ranker.py`,
`discovery.py`/`discovery_fetch.py`, `http.py`,
`nuclei_template.py` (parser), `exploit_evidence.py`. Output shape:
`ai/schemas/source.py::ResearchDocument` (+ `AffectedVersion`).

**Deterministic correlator.** `ai/correlator/`: `technology.py`
(alias/explicit-match lists, generic-technology blocklist),
`version.py` (extraction/normalization/comparison),
`cve_matcher.py` (technology match, explicitly NO version matching),
`assessment.py` (`CVEAssessment` per asset), `candidates.py`,
`shortlist.py` (`ResearchCandidate` + priority score, limit 10),
`watch_targets.py` (asset selection), `scope_policy.py`
(`ScopeDecision`: ALLOW/EXCLUDE with reason),
`http_fingerprint.py`, `plugin_presence.py`, `detection.py`,
`nuclei_decision.py` (notably: **no reliable HTTP signature → no Nuclei**),
`nuclei_generator.py` (YAML only, never executes; requires
method+path+matchers), `nuclei_validator.py` (semantic validation of
generated YAML against the `DetectionSpec`), `index.py`.

**Ingestion (AI boundary with grounding).** `ai/ingestion/agent.py`
(`IngestionReport`: persisted id, accepted/rejected/quarantined counts —
quarantine already exists) + `grounding.py` (NFKC/casefold normalization,
deterministic substring grounding, `contains_forbidden`, base64-blob guard,
confidence bands per evidence class). Schemas: `SourceDocument`,
`EvidenceSnippet`, `ExtractedClaim` (mirrors `KnowledgeSourceClaims`),
`ExtractionResult`, `IngestionError`. This is the project's existing
answer to prompt injection: extract-then-ground-then-quarantine.

**Knowledge.** `ai/knowledge/store.py`: content-addressed (full SHA-256
canonical identity; `kb-…` short alias), source-attributed
(`KnowledgeProvenance` per source, per-source claims, no synthesized global
confidence — AGENTS.md forbids it), integrity errors, deterministic
retrieval projections (`KnowledgeAggregate`). File-backed under `ai_data/`.
Schemas in `ai/schemas/knowledge.py`.

**XSS research stack (the reference pattern).**
`XSSResearcher` (deterministic retrieval, side-effect-free, no LLM, no
network) → `XSSLLMResearcher` (prompt + JSON parse + attribution
cross-validation; evidence prefixes `CONFIRMED:/UNKNOWN:/NOT
OBSERVED:/SECONDARY:/MODEL_GENERATED:`; LLM status suggestions restricted
to pre-confirmation states) → `XSSOrchestrator` (provider-agnostic,
injected collaborators only; audit object; forbidden stages
VERIFYING/CONFIRMED/NOT_VULNERABLE). Then `XSSVerificationPipeline`
(orchestrator.analyze → verifier.verify, exceptions propagate, never
converted to verdicts) and `XSSVerifier` (sole classifier; oracle E1/E2/E3;
run_salt; round binding). `watch_xss_verify.py` composes production.
**This exact shape — deterministic retrieval, validated LLM layer,
orchestrator audit, executor/verifier verdict ownership — is the template
for every new agent in this design.**

**Nuclei preparation.** `ai/researcher/nuclei_pipeline.py`
(`NucleiPipeline`): ResearchResult → DetectionSpec → Decision → Generate →
semantic validation → `nuclei -validate` (subprocess, fail-closed) →
target selection → scope policy → dry-run → finding normalization. Live
scanning explicitly out of scope of the class; `nuclei_runner.py` handles
execution with scope gating. `ai_data/nuclei/{generated,results,findings}`.

**LLM layer.** `ai/llm/base.py` (`LLMProvider.generate/complete`,
`LLMResult` with model/request metadata); `openrouter.py`, `avalai.py`
(env credentials via `ai/config.py`: `AI_PROVIDER`, `*_API_KEY`,
`*_MODEL`). Provider construction is already DI-friendly.

**Tests.** ~30 AI test modules including grounding/schema/ingestion
contracts, oracle matrix, stored rounds, pipeline composition, and a
localhost real-browser E2E. Any new component must follow the existing
pattern: unit-test the contract, never weaken fail-closed behavior.

### 2.2 Reuse map (summary; detail in §19)

- REUSE as-is: KnowledgeStore + schemas, grounding/validation primitives,
  LLM provider interface, XSS verifier/executors, Nuclei validator +
  `nuclei -validate` gate, scope policy, MongoDB inventory models.
- EXTEND: correlator (version-range matching is currently partial —
  matcher explicitly skips versions), ingestion (add writeup/blog source
  types on the same claim pipeline), orchestrator pattern (generalize to
  non-XSS flows).
- WRAP: collectors behind a common `ResearchCollector` interface;
  NucleiRunner behind an execution-sandbox boundary.
- ISOLATE: prompt texts into a versioned registry (today inline in
  researcher modules); model selection into a policy (today env default).
- NEW: Hypothesis/TestPlan/Artifact schemas + stores, Target Intelligence
  projection, Research lifecycle state machine, scheduler/queues,
  feedback-loop updater, template execution sandbox rules.

## 3. Proposed Architecture

```
                        ┌─────────────────────┐
                        │   RESEARCH SOURCES  │  NVD/CVE, GHSA, vendor
                        │  (untrusted input)  │  advisories, blogs,
                        └─────────┬───────────┘  writeups, HN reports
                                  │ fetch only (SSRF-guarded)
                    ┌─────────────▼──────────────┐
                    │  COLLECTORS (deterministic)│  CVECollector… (WRAP)
                    │  fetch · normalize · hash  │  → RawResearchItem
                    └─────────────▲──────────────┘
                                  │ dedupe by content-hash BEFORE llm
                    ┌─────────────▼──────────────┐
                    │  RESEARCH STORE            │  content-addressed,
                    │  RAW→NORMALIZED→DEDUPED    │  source-attributed (REUSE
                    │                            │  KnowledgeStore pattern)
                    └─────────────▲──────────────┘
                                  │
              ┌───────────────────▼────────────────────┐
              │  RESEARCH ANALYZER (AI, untrusted)     │  cheap→strong
              │  classify · summarize · extract claims │  escalation;
              │  grounding + quarantine gates (REUSE)  │  prompts versioned
              └─────────────▲──────────────────────────┘
                            │ claims (grounded) only
              ┌─────────────▼──────────────┐   ┌──────────────────────┐
              │  PATTERN STORE             │◄──│ TARGET INTELLIGENCE  │◄── read-only
              │  VulnPattern/AttackPattern │   │ projection over recon│    recon/DNS/
              │  +TechFingerprint (NEW,    │   │ DB: tech, versions,  │    crawl/params
              │  file-backed like KS)      │   │ endpoints, flows     │    (never redesign)
              └─────────────▲──────────────┘   └──────────────────────┘
                            │ deterministic match first
              ┌─────────────▼──────────────┐
              │  TARGET MATCHER (determin.)│  technology→version→
              │  relevance scoring         │  presence→scope (EXTEND
              └─────────────▲──────────────┘  correlator)
                            │ scored (target, pattern) pairs
              ┌─────────────▼──────────────┐
              │  HYPOTHESIS ENGINE (AI)    │  hypothesis only;
              │  pattern × target → claim  │  never a verdict (NEW)
              └─────────────▲──────────────┘
                            │
              ┌─────────────▼──────────────┐
              │  TEST PLANNER (AI+rules)   │  TestPlan + artifact
              │  plan → generate artifact  │  (Nuclei YAML / XSS case);
              └─────────────▲──────────────┘  deterministic validators
                            │        gate every artifact
              ┌─────────────▼──────────────┐
              │  EXECUTION LAYER (sandbox) │  NucleiRunner (WRAP),
              │  scope-gated, bounded      │  XSS pipeline (REUSE)
              └─────────────▲──────────────┘
                            │ evidence only
              ┌─────────────▼──────────────┐
              │  VERIFICATION LAYER        │  SOLE verdict authority
              │  XSSVerifier / Nuclei      │  (REUSE untouched)
              │  evidence matcher          │
              └─────────────▲──────────────┘
                            │ CONFIRMED/POTENTIAL/INCONCLUSIVE
              ┌─────────────▼──────────────┐
              │  FINDING LAYER + FEEDBACK  │  persist; intelligence
              │  audit chain → sources     │  updater (bounded, NEW)
              └────────────────────────────┘
```

Trust summary: everything above Execution is hypothesis-generation
(untrusted); Execution produces evidence (untrusted input to verifiers);
only Verification classifies; Finding persists verdict + full audit chain.

## 4. Component Responsibilities

**ResearchCollector** (WRAP existing collectors). Responsibility: fetch +
normalize + hash one source type. Inputs: source config (URL allowlist,
rate limits, credentials from env). Outputs: `RawResearchItem`
(bytes + normalized text + source URL + fetched_at). Trust: untrusted
output (fetched bytes), trusted transport behavior (timeouts, SSRF guard:
no cloud-metadata IPs, no intranet literals unless allowlisted, redirect
cap, size cap — the NVD collector's interval/retry pattern becomes the
shared base). Dependencies: network only.

**ResearchStore** (REUSE KnowledgeStore pattern; may share the store
implementation with a separate namespace). Responsibility: canonical
identity (SHA-256), dedup, lifecycle states RAW→NORMALIZED→DEDUPED.
Inputs: raw items. Outputs: stable ids. Trust: trusted (deterministic).
Dedup happens BEFORE any LLM call (cost rule).

**ResearchAnalyzer** (NEW orchestrator reusing ingestion agent). 
...[truncated 20887 chars]