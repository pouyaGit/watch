# AI Security Research Agent — Adversarial Review

## 1. Verdict

**ARCHITECTURE SOUND WITH HARDENING REQUIRED**

No realistic path was found from untrusted input to false CONFIRMED,
arbitrary execution, scope bypass, evidence contamination, or secret
leakage that the architecture leaves completely unguarded. The core
property holds: every CONFIRMED still requires a deterministic verifier,
and the XSS oracle path is unreachable from research-agent outputs except
as candidate inputs. However, two HIGH findings (H1: Nuclei matcher
specificity has no gate; H2: generator interpolates attacker-influenced
fields into raw requests without safety normalization) must be fixed
before generated or third-party templates can produce findings or be
executed. Nothing here blocks Phase 1 (data contracts).

## 2. Executive Summary

I attacked the proposed architecture assuming a fully hostile
environment: malicious writeups with prompt injection, hallucinated CVEs,
poisoned templates, compromised model output, SSRF-redirecting sources,
concurrent agents, and a poisoned feedback loop. Method: trace every
untrusted byte from source to verdict against actual current code
(verifier, oracle, executors, correlator, generator, validator, runner,
ingestion grounding, LLM layer), distinguishing PROVEN BY CURRENT CODE
from DESIGN ASSUMPTION from RECOMMENDATION.

Result: 0 CRITICAL, 2 HIGH, 6 MEDIUM, 4 LOW/INFO findings. The
strongest results: (a) the XSS confirmation path is genuinely
unreachable — research output enters only as candidate patterns and the
planner-owned oracle payload cannot be steered (PROVEN); (b) the Nuclei
path has a real integrity gap — finding quality equals template-matcher
quality and no specificity gate exists (H1); (c) grounding defeats
exfiltration-style injection but cannot defeat instruction-style injection
whose payload *is* claim-shaped, so priority/scheduling influence is the
realistic blast radius, not verdicts (M1); (d) all SSRF, secrecy, replay,
and concurrency risks reduce to missing-but-well-understood primitives
listed in §9, most already named as blocking in the architecture report.

## 3. Threat Model

Adversary controls: arbitrary research documents (writeups, CVE text,
templates, references, redirect targets), LLM output content (compromised
or careless provider), timing/concurrency of agent runs, and stale or
false public data. Adversary goals: false CONFIRMED, out-of-scope
testing, SSRF/command execution, secret exfiltration, evidence
contamination across targets, resource exhaustion, feedback poisoning.
Out of scope: compromise of Watch infrastructure itself, malicious
commits by maintainers, LLM provider infrastructure breach beyond output
content. Fail-closed is required at every automated gate; human review is
an acceptable gate only where explicitly designated.

## 4. Trust Boundary Map

```
UNTRUSTED zone: research bytes, fetched pages, LLM output, generated YAML,
  relevance scores, priorities, summaries, hypotheses, test plans
  ── crosses into SEMI-TRUSTED only through deterministic validators ──
SEMI-TRUSTED zone: grounded claims, DetectionSpec (deterministic build),
  validated templates, scope decisions, executor evidence
  ── crosses into VERDICT only through sole-authority classifiers ──
TRUSTED zone: XSSVerifier/oracle, scope policy code, KnowledgeStore
  integrity rules, run_salt/round binding, finding persistence
```

Crossings audited: (1) source→claims: grounding+quarantine (PROVEN);
(2) claims→patterns: schema restriction (DESIGN ASSUMPTION — schema
exists for claims, pattern schema is Phase-1 NEW); (3) pattern→hypothesis:
deterministic match first, LLM only配对 (DESIGN ASSUMPTION); (4)
hypothesis→artifact: DetectionSpec validators + `nuclei -validate`
(PROVEN for syntax, ASSUMED for future AI-YAML path); (5)
artifact→execution: scope gate + dry-run default (PROVEN); (6)
evidence→verdict: sole-authority verifiers (PROVEN for XSS; PARTIAL for
Nuclei — see H1).

## 5. Attack Matrix

| # | Attack | Expected | Actual | Result |
|---|---|---|---|---|
| 1 | Malicious writeup w/ injection → unintended actions | contained | contained: collectors fetch-only; no tool calls exist; claims schema-restricted | HOLD |
| 2 | "Mark confirmed" instruction in research | no verdict effect | no status field crosses into any verifier; XSS statuses forbidden by orchestrator/LLM validators (PROVEN) | HOLD |
| 3 | Hallucinated CVE-2026-99999 → pattern→test→template→finding | blocked at ≥1 gate | blocked at matcher (no asset tech match) AND decision (no signature → no Nuclei); IF tech matches, template still needs matchers+validation; Nuclei finding possible only via H1 gap | HOLD* (*H1) |
| 4 | Wrong version (FooCMS 4.5.0 vs ≤4.2.1) tested anyway | version gate | `assessment.py` AFFECTED/UNKNOWN split (PROVEN); UNKNOWN tested at 0.5 (fail-open to *testing*, verdict still needs evidence) | HOLD |
| 5 | Wrong tech via generic strings | no match | generic-technology blocklist + explicit aliases (PROVEN); residual alias risk acknowledged upstream | HOLD |
| 6 | Scope bypass (ooscope/sibling/redirect/pivot/callback) | blocked w/o LLM | scope policy + runner eligibility + executor same-origin + verifier origins (PROVEN); template-embedded absolute URLs NOT constrained (H2) | HOLD* (*H2) |
| 7 | Malicious/malformed template (exec/file/SSRF/scope/destructive/DoS) | neutralized | destructive-flag refusal + HTTP-only + required fields + `nuclei -validate` (PROVEN); header/path injection + destructive-flag provenance weak (H2) | HOLD* (*H2) |
| 8 | XSS: malicious payload/fake sink/reused/stale/cross-target oracle material → CONFIRMED | impossible w/o execution | planner-owned O, run-salted S/D, round binding, exact E1/E2/E3, anti-harvest (PROVEN by oracle matrix + stored rounds) | HOLD |
| 9 | Cross-target mix (A-evidence→B) | rejected | attempt/round/run binding per target execution (PROVEN for XSS); Nuclei findings keyed by (cve,target,template) (PROVEN structurally) | HOLD |
| 10 | 2-year-fixed vuln → current finding | blocked/fresh | NO freshness TTL exists (M4); version gate mitigates when versions known; UNKNOWN-version + H1 = residual false-finding path | WEAK |
| 11 | Replay old item/hypothesis/plan/artifact/evidence | stale rejected | XSS: salt/round binding (PROVEN); research re-test is legitimate re-execution, not replay; evidence has no cross-run validity except via re-execution | HOLD |
| 12 | Concurrent same-CVE agents → dupes/races | idempotent | XSS findings: unique case_id (PROVEN); Nuclei file outputs + finding lists: no demonstrated idempotency key (M5) | WEAK |
| 13 | FP → feedback poisons intel/patterns/scores/prompts | bounded | statistics-only currently toothless AND unguarded (M6); prompt mutation has no gate in code today | WEAK |
| 14 | Provider returns malformed/huge/malicious/adversarial output | rejected/capped | JSON validators → reject/quarantine (PROVEN); max_tokens+timeout caps (PROVEN); truncation→parse-fail→reject (fail-closed) | HOLD |
| 15 | Collector redirect → localhost/RFC1918/metadata/ports | blocked | NVD fixed-host today (PROVEN narrow); general fetcher guard is DESIGN ASSUMPTION (M2) | WEAK* |
| 16 | Secrets into prompts/artifacts/reports | prevented | env-only credentials (PROVEN); NO prompt-construction hygiene rule in code (M3) | WEAK |
| 17 | Huge/recursive/duplicated inputs, escalation bombs, retry loops, target-matrix blowup | bounded | hash-dedupe + body caps + shortlist-10 + dry-run default (PROVEN partial); budgets/queues/output caps are ASSUMPTION | WEAK |

## 6. State Machine Attack

Per transition (who / trusted inputs / validation / replay / skip /
backwards / LLM-force / attacker-force / idempotent):

- RAW→NORMALIZED: collector code; transport bytes (untrusted) + allowlist
  config (trusted); SSRF/size/redirect validation (ASSUMED for new
  sources); replay safe (re-fetch → same hash); cannot skip (constructor
  of item); backwards N/A; LLM cannot force; attacker can only supply
  bytes; idempotent by content hash. VERDICT: sound if B3 implemented.
- NORMALIZED→DEDUPED: store code; hashes (trusted); equality check;
  replay N/A; skip impossible (same function); backwards N/A; idempotent.
  VERDICT: sound (PROVEN pattern).
- DEDUPED→ANALYZED: analyzer; item text (untrusted) + versioned prompt
  (trusted); grounding+quarantine (PROVEN); replay creates new versioned
  pass (bounded by budget — ASSUMED); skip impossible (gated call order);
  backwards allowed as re-analysis with version++ (must be monotonic —
  RECOMMENDATION); LLM cannot force acceptance (validators raise);
  attacker forces only cost (bounded by M-budgets); idempotent per
  (item-hash, prompt-version). VERDICT: sound with budgets (B6-adjacent).
- ANALYZED→PATTERN_EXTRACTED: deterministic projector over accepted
  claims; claim values (semi-trusted) + closed vocabularies (trusted);
  unknown-enum rejection; replay safe; skip impossible; backwards allowed
  (re-project); LLM cannot force (no LLM in projector — REQUIRED, currently
  true by construction); attacker shapes only claim content within schema.
  VERDICT: sound.
- PATTERN_EXTRACTED→MATCHED: matcher code; pattern + inventory snapshot
  (trusted read); alias/version logic; replay safe; skip impossible;
  backwards N/A; no LLM (REQUIRED); attacker cannot force (no input
  channel except published research → matched only on genuine tech
  overlap). VERDICT: sound; over-match risk is M1-priority only.
- MATCHED→HYPOTHESIS_CREATED: hypothesis engine (AI) + deterministic
  match record; LLM proposes, code commits with hypothesis-id; replay
  creates duplicate unless idempotency key (RECOMMENDATION §9);
  skip impossible (engine is the only writer); backwards allowed
  (supersede chain); LLM cannot force verdict fields (schema has none —
  REQUIRED); attacker influences ranking only. VERDICT: sound with
  idempotency keys.
- HYPOTHESIS_CREATED→TEST_PLANNED: planner (AI+rules); TestPlan schema
  validation; replay safe with keys; skip blocked (executor requires plan
  id); backwards allowed; LLM cannot set scope/target outside matched set
  (code re-resolves targets — REQUIRED); attacker: ranking only. VERDICT:
  sound with target re-resolution rule.
- TEST_PLANNED→TESTED: executors; plan+scope token (RECOMMENDATION);
  scope gate + dry-run default (PROVEN); replay = legitimate re-test with
  fresh evidence; skip impossible; backwards N/A; LLM absent at runtime;
  attacker cannot redirect (target re-resolved + scope-checked at exec
  time — REQUIRED, runner does this today for scope). VERDICT: sound.
- TESTED→VERIFIED: sole-authority verifiers; evidence (untrusted) +
  identities (trusted); exact predicates (PROVEN XSS; H1 for Nuclei);
  replay of evidence across runs invalid (salt/round; Nuclei evidence is
  per-run output); skip impossible; backwards N/A; LLM absent;
  attacker shapes evidence bytes only. VERDICT: sound for XSS; Nuclei
  needs H1 fix.
- VERIFIED→FINDING: persistence with audit chain; unique keys (XSS
  case_id PROVEN; Nuclei finding key ASSUMED — M5); replay safe;
  skip impossible; backwards N/A (findings immutable; supersede only).
  VERDICT: sound with finding keys.

No transition that must be deterministic is AI-controlled, PROVIDED the
projector (ANALYZED→PATTERN) and target re-resolution (→TESTED) rules are
implemented as code without LLM calls — both are RECOMMENDATIONS made
blocking in §10.

## 7. AI vs Deterministic Boundary Audit

| Operation | AI Allowed? | Deterministic Gate | Security Consequence if gate missing |
|---|---|---|---|
| summarization | yes | none needed (display only) | priority confusion at most |
| extraction | yes (proposal) | grounding + quarantine + confidence bands | poisoned claims enter store |
| classification | yes (proposal) | closed-enum validator | uncontrolled routing/cost |
| vulnerability identification | yes (proposal) | DetectionSpec validators + decision engine | untestable tests generated |
| version matching | NO | `version.py` compare (PROVEN) | wrong-version testing (fail-open) |
| target matching | NO | alias/version/scope code (PROVEN) | false hypotheses, wasted tests |
| hypothesis generation | yes | schema + match-record binding + idempotency key | untraceable/duplicate hypotheses |
| test planning | yes | TestPlan validator + target re-resolution | scope/target confusion |
| payload generation (XSS) | yes (pattern only) | planner-owned oracle payload (PROVEN) | none (verifier decides) |
| Nuclei generation | yes (proposal) | required-fields + semantic + `nuclei -validate` + NEW specificity gate (H1) + output constraints (H2) | false findings / unsafe requests |
| template validation | NO | validator code (PROVEN) | self-graded homework |
| scope decision | NO | scope policy + runner eligibility (PROVEN) | out-of-scope testing |
| execution | NO | dry-run default + scope re-check (PROVEN) | unintended live traffic |
| evidence collection | NO | executor-owned channels (PROVEN) | forged evidence |
| verification | NO | sole-authority verifiers (PROVEN XSS) | false CONFIRMED |
| verdict | NO | verifier status mapping (PROVEN) | direct AI→CONFIRMED |
| finding persistence | NO | unique keys + audit chain (PROVEN XSS; ASSUMED Nuclei) | duplicates, lost provenance |
| feedback | statistics only | human gate for prompt/model changes (REQUIRED) | self-poisoning loop |

## 8. Findings

**H1 — HIGH — Nuclei matcher specificity has no gate.**
Attack: publish/plant a template (or future AI-generated YAML) whose
matchers match benign content (e.g. status+generic string); it passes
`nuclei -validate` (syntax) and semantic validation (structural
correspondence), matches the target, yields `matched: true` → finding.
Preconditions: template reaches the runner (extracted from third-party
source or AI-generated without review). Exploit path:
`collectors/nuclei_template.py` parse → `NucleiDecisionEngine` (checks
signature presence, not specificity) → generate → validate → dry-run
(match is fine) → finding. Existing mitigation: required-fields,
destructive refusal, scope gating — none test discriminative power.
Missing: negative-control gate (template MUST NOT match a benign fixture
of the same tech; SHOULD match a vulnerable fixture where available).
Fix: fixture-based specificity gate before any generated/untrusted-source
template can produce findings; human review until then. Blocks: YES for
auto-findings from generated templates (not for Phase 1 contracts).

**H2 — HIGH — generator interpolates attacker-influenced fields without
safety normalization.**
Attack: crafted `path` (absolute URL), `query_parameter_values`, or
`headers` (CRLF/newline) from a poisoned template/CVE text flows via
`DetectionSpec` into raw request lines (`f"{header}: {value}"`,
`quote(value, safe="/:@-._~!$'()*+,;=")` preserves `:`/`@`).
Preconditions: untrusted-source template parsed or future AI-written
DetectionSpec fields. Impact: malformed/smuggled requests to in-scope
targets; `destructive` flag provenance is parser/keyword-based — must
never become LLM-settable. Existing mitigation: `nuclei -validate`,
HTTP-only check, scope-bounded targets. Missing: relative-path
enforcement, header name/value allowlist + CRLF rejection, value allowlist
for query construction, `destructive` default-true on uncertainty.
Fix: deterministic output-constraints module in the generator path.
Blocks: YES before executing untrusted-source templates live.

**M1 — MEDIUM — grounding cannot stop instruction-shaped claims; blast
radius is priority/scheduling.**
Attack: "CRITICAL RCE, exploit in the wild, test immediately" inside a
writeup → grounded (it IS in the source) → priority/crowding of the
top-10 shortlist, genuine CVEs displaced, compute diverted. Cannot reach
verdicts (schemas carry no verdict fields; verifiers don't read claims).
Fix: priority inputs restricted to deterministic fields (CVSS, asset
count, exploit-confirmed flag); claim text sentiment excluded from
scoring. Blocks: NO (scheduling integrity, not verdict integrity).

**M2 — MEDIUM — research-fetch SSRF guard does not exist yet.**
Current collectors hit fixed hosts (NVD) — narrowly safe today; the
general fetcher (blogs/GHSA/writeups) is pure design. Missing:
host allowlist, IP-literal/metadata-range blocks, redirect caps,
credential stripping, DNS-rebinding note. Blocks: YES before any general
URL fetching (already listed as blocking in the architecture).

**M3 — MEDIUM — no prompt secret-hygiene rule.**
Credentials live in env (PROVEN), but nothing constrains what target/
infra data enters prompts (URLs with userinfo, internal hostnames to
external providers). Missing: URL sanitizer + prompt-field allowlist +
audit test asserting no secret patterns in rendered prompts. Blocks: YES
before new target-data prompts (XSS flow grandfathered — restrict to same
rule at next touch).

**M4 — MEDIUM — no research freshness TTL; UNKNOWN-version fail-open.**
Stale research + unknown versions get tested (acceptable — verdict needs
evidence) but combined with H1 could yield stale false findings. Missing:
research TTL + `version_required` enforcement + patched-version exclusion
list. Blocks: NO (hardening).

**M5 — MEDIUM — concurrency idempotency incomplete.**
XSS findings: unique `case_id` (PROVEN). Nuclei file outputs/finding lists
and hypothesis/plan creation: no demonstrated idempotency keys; concurrent
same-CVE runs can duplicate. Missing: content-hash idempotency keys +
finding dedup keys. Blocks: NO for Phase 1 (include keys in contracts now).

**M6 — MEDIUM — feedback loop has no gates in code.**
Statistics-only still shifts future priorities; prompt/model mutation path
is design prose. Missing: append-only metrics, human approval for prompt
changes, no automatic retraining/reweighting. Blocks: YES for any prompt
mutation or auto-reweighting (not for read-only metrics).

**L1 — LOW — provider-output abuse handled.**
Malformed JSON → ValidationError→reject/quarantine; huge output →
max_tokens+timeout caps; truncation → parse-fail→reject. PROVEN. No action.
**L2 — LOW — state-transition authorization implicit.**
Call-order gating works but is not an explicit allowlist; recommend
transition table + monotonic versions (non-blocking).
**L3 — INFO — inherited oracle/A4/E3 residuals** unchanged.
**L4 — INFO — duplicate identical deterministic rounds → duplicate
findings** (pre-existing pattern, benign).

Counts: CRITICAL 0, HIGH 2, MEDIUM 6, LOW 2, INFO 2.

## 9. Missing Security Primitives

(Each justified by the attack that needs it.)
1. Template specificity gate (benign/vulnerable fixtures) — H1.
2. Generator output constraints (relative-path, header allowlist, CRLF
   rejection, destructive-default-true) — H2.
3. Fetch SSRF guard (allowlist, IP/metadata blocks, redirect/size caps,
   credential strip, rebinding note) — M2/attack 15.
4. Priority-input restriction (deterministic fields only) — M1.
5. Prompt secret-hygiene + audit test — M3/attack 16.
6. Research TTL + patched-version exclusion — M4/attack 10.
7. Idempotency keys (content-hash) + finding dedup keys — M5/attack 12.
8. State-transition allowlist + monotonic versions + scope tokens
   (plan→exec binding) — attacks 12/state machine.
9. Feedback append-only metrics + human gate for prompt changes — M6/attack 13.
10. Artifact content-hash binding (plan→artifact→evidence→finding chain) —
    attacks 9/11 provenance.

## 10. Blocking Requirements

B1: Specificity gate (primitive 1) before generated/untrusted templates
can produce findings; human review until then.
B2: Generator output constraints (primitive 2) before live execution of
untrusted-source templates.
B3: Fetch SSRF guard (primitive 3) before general research URL fetching.
B4: Priority-input restriction (primitive 4) before scheduler uses scores.
B5: Prompt hygiene rule + audit test (primitive 5) before new target-data
prompts.
B6: Transition allowlist + idempotency keys (primitives 7/8) before the
scheduler/matcher/hypothesis engine is built.
B7: No-LLM-in-projector and target re-resolution as code invariants
(§6); any violation is architecture-noncompliant.
B8: Feedback human gate (primitive 9) before any prompt/model mutation.

## 11. Non-Blocking Hardening

Research TTL/patched-exclusion (M4), Nuclei finding dedup keys (M5),
budget/queue tuning, benign-fixture library growth, S5b-style
registrable-domain documentation, duplicate-finding dedup, transition
table documentation (L2).

## 12. Phase 1 Safety Assessment

**Yes — Phase 1 (Hypothesis + TestPlan contracts) is safe to begin now.**
Contracts are pure data schemas with zero execution authority: they
cannot fetch, execute, or classify; validators reject unknown fields
fail-closed; no verdict field exists in either schema; the scheduler,
fetcher, and executors do not exist yet, so there is nothing to misuse.
The only Phase-1 obligations: include `hypothesis_id`/idempotency key,
provenance chain, and explicit "no verdict semantics" documentation in the
schemas themselves, plus contract tests asserting unknown-field rejection.

## 13. Final Recommendation

Approve the architecture with hardening required: implement Phase 1
contracts immediately (safe), then satisfy B1–B8 in phase order before the
components they gate. Do not allow generated or third-party templates to
produce findings or run live until B1+B2 are proven by fixture tests; do
not build general research fetching until B3 is proven by SSRF tests.
Re-review at the scheduler milestone — that is where the remaining
assumptions (budgets, queues, transition authorization) become code.

## 14. Test Cases We Should Add Later

1. Specificity fixtures: generic-matcher template MUST NOT match benign
   app fixture; MUST match vulnerable fixture (B1 proof).
2. Generator adversarial inputs: absolute-URL path, CRLF header,
   destructive-flag uncertainty → rejection or safe normalization (B2).
3. SSRF suite: metadata IP, RFC1918, odd ports, redirect chains,
   credentialed URLs, DNS-rebinding-shaped responses (B3).
4. Priority-crowding: injected "CRITICAL test now" writeup must not
   displace scored CVEs (B4).
5. Prompt hygiene: rendered prompts asserted free of secret patterns and
   userinfo URLs (B5).
6. Concurrency: parallel same-CVE runs → single hypothesis/plan/artifact
   set, single finding (idempotency).
7. Replay: old evidence/artifact against new run → rejected or re-executed
   fresh, never inherited.
8. Feedback: injected FP statistics must not alter prompts without human
   approval.
9. Hallucinated-CVE end-to-end: invented CVE with real tech → blocked at
   matcher/decision, never a finding.
10. E2E negative: full pipeline on benign target → zero CONFIRMED across
    XSS and Nuclei paths.

---

Method: READ-ONLY challenge; no source, architecture, or component
modified; no git operations. Only created:
`agent-reports/security-research-agent-adversarial-review.md` (this file,
written from scratch). Distinction key: XSS/oracle/executor/scope-policy
claims are PROVEN BY CURRENT CODE; fetcher guards, scheduler, contracts,
and gates are DESIGN ASSUMPTION unless noted with existing code paths;
all fixes are RECOMMENDATION.
