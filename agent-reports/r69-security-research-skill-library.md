# R69 — Security Research Skill Library

Date: 2026-09-15
Base commit: `1c66dbed5db789ae130fc66bf6dd8199ec9abeb4` (R68)
Rule version: `r69-1`

## 1. Objective

Improve the actual quality of Watch's LLM research output by giving the model
bounded, Watch-native methodology for only the categories relevant to the
current context, without prompt bloat, without weakening the R65/R66 safety
boundary, and without introducing authorization or execution semantics.

## 2. Claude-Red methodology sources inspected

External reference (methodology only; no text copied):

- `https://github.com/SnailSploit/Claude-Red` — README (78 skills, 23
  categories, skill index, trigger-based loading model).
- `LICENSE` — MIT, Copyright (c) 2024-2025 SnailSploit / Kai Aizen.
- `Skills/web/offensive-idor/SKILL.md` — SKILL.md structure: metadata,
  description, trigger phrases, ordered methodology, mechanisms, hunt
  guidance, false-positive/bypass considerations, remediation.
- Also inspected existing Watch-native knowledge engines
  (`ai/knowledge/specialist_eligibility.py`,
  `ai/knowledge/idor_bola_hypothesis_planner.py`) and the R64–R68 pipeline to
  keep the new layer additive and consistent with existing abstractions.

What was NOT copied: payloads, bypass dumps, tooling instructions, target
steps. Only methodology concepts (object-reference scope, authorization
boundaries, evidence discipline, false-positive control) were rewritten as
original Watch-native text.

## 3. Skills extracted

11 Watch-native skills (bounded; no payload dictionaries):

1. `idor-bola` — IDOR/BOLA object-level authorization
2. `ssrf` — server-side request influence
3. `xss` — reflection and execution context
4. `sqli` — SQL injection evidence discipline
5. `jwt` — JWT artifact and validation evidence
6. `oauth` — OAuth/OIDC flow artifact discipline
7. `api-security` — API surface structural discipline (RECON)
8. `business-logic` — workflow/state discipline (RECON)
9. `open-redirect` — server-side redirect behavior (RECON)
10. `graphql` — GraphQL surface evidence (RECON)
11. `cve-research` — technology/version CVE discipline

## 4. Watch-native skill structure

`ai/knowledge/security_skills/`:

- `skills.py` — structured, immutable-by-convention skill records with
  `skill_id`, `category`, `title`, `applicability`, `trigger_conditions`,
  `required_evidence`, `useful_evidence_types`, `methodology`,
  `hypothesis_patterns`, `false_positives`, `confidence_constraints`,
  `priority_constraints`, `rejection_cases`, `safe_next_actions`,
  `watch_signals`.
- `library.py` — deterministic selection, bounding and compact rendering.
- `__init__.py` — public API (`select_skills`, `render_skills`,
  `all_skills`, `skill_by_id`, constants).

Categories align with the existing canonical specialist order (XSS, SSRF,
SQLI, IDOR, JWT, OAUTH, RECON, CVE_RESEARCH).

## 5. Integration point

`tests/local_e2e/r64_research.py` (R61 -> R62 -> R68 evidence -> **R69 skills**
-> OpenRouter -> R65 grounding -> R66 per-hypothesis validation):

- `build_research_prompt` selects and renders skills for the bounded context
  and adds a `research_skills` list to the same untrusted-data payload.
- `_instructions` adds a short `RESEARCH SKILLS` note (only when skills are
  present) stating that skills are methodology, not evidence, not
  authorization, and never proof of a vulnerability.
- Rule version `r69-1`; CLI banner prints the selected skill ids.
- No change to evidence resolution, category rules, strength caps, rejection
  logic, safety block, provider, Mongo behavior or persistence schema.

## 6. Selection behavior

`select_skills(signals, evidence, limit=3)`:

- **category/signal-aware**: IDOR/SSRF/XSS/SQLI/JWT/OAUTH/CVE_RESEARCH watch
  signals select their skill; a RECON signal selects the relevant
  RECON-family skill (GraphQL path -> `graphql`, redirect-shaped parameter ->
  `open-redirect`, logic-shaped parameter -> `business-logic`, else
  `api-security`).
- **evidence-aware** (deterministic structural patterns, not behavior
  claims): object-reference routes -> `idor-bola`; URL/host-shaped parameters
  -> `ssrf`; redirect-shaped parameters -> `open-redirect`; token-shaped
  parameters -> `jwt`; OAuth/OIDC-shaped parameters -> `oauth`;
  business-value parameters -> `business-logic`; GraphQL paths -> `graphql`;
  observed technology **and** version -> `cve-research`.
- **bounded**: at most 3 skills; rendered block capped at 2,100 chars; if the
  prompt payload would exceed the existing `MAX_PROMPT_CONTEXT_CHARS`, skills
  are dropped deterministically from the end until it fits (the existing
  fail-closed size check is unchanged).
- **deterministic**: ordering is `(canonical category order, skill_id)`;
  repeated calls and reversed inputs produce identical selections.

Observed selections: fixture context -> `idor-bola, open-redirect,
cve-research`; real Indeed Mongo context -> `idor-bola, oauth, api-security`.

## 7. Evidence interaction

Skills describe evidence *requirements* only. The model still receives the
R68 evidence catalog (`E1`, `E2`, ...) and still returns `evidence_refs`;
Watch resolves ids to canonical evidence and validates with the unchanged
R65/R66 gates. Skills never introduce raw URLs, IPs, Mongo ids, credentials or
new evidence kinds, and never change evidence identity.

## 8. False-positive controls

Every skill carries explicit `false_positives` and `rejection_cases`,
including the R64 failure classes:

- `{id}` placeholder alone is not IDOR; REST shape is not an authorization
  failure;
- URL-like parameter name is not SSRF; open redirect alone is not SSRF;
- parameter name is not XSS; `id/q/sort` names are not injection evidence;
- `sid`/`token`/`session` names are not JWTs; `code`/`state` alone are not
  OAuth;
- endpoint names do not prove purpose; versioned paths are not
  vulnerabilities;
- `continue`/`next`/`return`/`url` names are not open redirects;
- a version string is not an exploitable CVE; unassociated versions are not
  component versions.

Agent-test assertions verify these phrases survive in the library.

## 9. Tests run

- `ai/test_security_skills.py` — **12 passed, 27 subtests** (discovery,
  category matching, RECON-family selection, evidence-aware selection,
  boundedness/limit validation, determinism, relevance-only, unknown category
  handling, bounded/safe rendering, false-positive guidance, rule version).
- `tests/local_e2e/test_r64_research.py` — **102 passed, 37 subtests**
  (includes R65 grounding, R66 partial acceptance, R68 selection, R69 prompt
  integration: bounded skills, determinism, empty-context no-skills,
  validation-not-bypassed).
- `pytest tests/local_e2e -q` — **244 passed, 63 subtests**.
- Adjacent suites (`ai/test_security_skills.py`, `ai/test_openrouter.py`,
  `ai/test_llm.py`, `tests/test_research_priority.py`,
  `tests/test_evidence_confidence_aggregator.py`) — **174 passed, 27
  subtests**.

## 10. Real fixture run

- Provider/model: `openrouter` / `nvidia/nemotron-3-ultra-550b-a55b:free`
- Skills sent: `idor-bola, open-redirect, cve-research`
- Status: **`COMPLETED_WITH_REJECTIONS`** — 3 accepted, 1 rejected
  (`MODEL_OUTPUT_UNGROUNDED`: "redirect hypotheses require observed redirect
  evidence")
- Artifact: `ai_data/research/r69/r64-indeed-2ea29240244dcf5b.json`
- Accepted: IDOR M/M (canonical path + IDOR signal); REST API structure
  L-M/M (structural only); technology/version CVE L/L ("without mapping, CVE
  correlation is not possible").

## 11. Real Mongo / Indeed run

- Executed: yes; program `indeed`; read-only; R61 caps unchanged
  (subdomains 500, live_subdomains 500, http 300, urls 1000, endpoints 1000);
  evidence items 81; skills sent `idor-bola, oauth, api-security`.
- Provider/model: `openrouter` / `nvidia/nemotron-3-ultra-550b-a55b:free`
  (runtime-only 900 s timeout wrapper; Mongo server-selection 5 s in the /tmp
  wrapper; repository timeout configuration unchanged).
- Status: **`COMPLETED_WITH_REJECTIONS`** — 2 accepted, 3 rejected.
- Artifact: `ai_data/research/r69/r64-indeed-ddd4831a4ecf7077.json`
- Accepted:
  1. "Internal API endpoint exposure" — RECON, priority LOW / confidence
     MEDIUM; observation `path:/api/internal/brand/theme/style-sheet`;
     conditional wording, missing method/auth/response evidence.
  2. "Cloudflare Bot Management with challenge parameters" — RECON, LOW /
     MEDIUM; observations `technology:Cloudflare`, `technology:Cloudflare Bot
     Management`, three `%5Cu0026__cf_chl_*` parameters; missing challenge
     behavior evidence.
- Rejected: REST API structure (only derived signals, no grounded
  observation), account management authentication surface (session wording
  without observed session evidence), path-based object references (derived
  IDOR signal only).
- Honest quality: both accepted hypotheses are **WEAK / LOW-VALUE
  STRUCTURAL LEADS**. No behavior, no vulnerability, no confirmation. The
  "internal" API hypothesis is still name-adjacent but is explicitly
  conditional at MEDIUM with missing authorization evidence.

## 12. Comparison with R68

| Run | R68 | R69 |
| --- | --- | --- |
| Fixture status | COMPLETED_WITH_REJECTIONS (4 accepted / 1 rejected) | COMPLETED_WITH_REJECTIONS (3 accepted / 1 rejected) |
| Fixture accepted | IDOR M/M; nginx CVE M/M; jQuery CVE M/M; `/weird` RECON L/L | IDOR M/M; REST structure L-M/M; version/CVE L/L (no mapping) |
| Mongo status | COMPLETED_WITH_REJECTIONS (2 accepted / 4 rejected) | COMPLETED_WITH_REJECTIONS (2 accepted / 3 rejected) |
| Mongo accepted | `assertion` RECON L/L; `attach/attachment` RECON L/L | internal API path RECON L/M; Cloudflare challenge RECON L/M |

Qualitative changes observed:

- **Fewer, more disciplined hypotheses**: R69 produced no `/weird` name-based
  hypothesis and no separate nginx/jQuery CVE hypotheses without an observed
  technology-version mapping.
- **Name-based over-inference reduced**: the parameter-name OAuth/attachment
  leads accepted in R68 did not appear; instead the model explicitly rejected
  session inference from login/logout paths and derived-signal-only IDOR
  (R68 rejected the same session pattern for a different reason).
- **Better absence framing**: R69 summaries explicitly state that no response
  bodies, authorization behavior, redirect chains or token evidence are
  present — matching the skill requirement to name missing evidence.
- **Still weak real leads**: both versions produce only structural / weak
  leads from bounded recon; R69 is somewhat better grounded but is not a
  transformation in finding quality. Reported honestly.

## 13. Safety verification

- Mongo writes: **0** (read-only snapshot; collection counts identical before
  and after the run).
- Target activity: **0** (only OpenRouter completion calls).
- `execution_performed=false`, `vulnerability_confirmed=false`,
  `exploit_authorized=false`, `confirmation_state=NOT_CONFIRMED`,
  `human_authority_required=true`, `advisory=true`, `research_only=true`.
- Artifacts: no raw URLs, IPs, Mongo identifiers or credentials; input
  hygiene all false; rejected hypothesis bodies absent (only safe
  code/reason/title metadata).
- Skills contain no payloads, execution instructions or authorization
  semantics; rendering is scanned by tests for forbidden content.

## 14. Files changed

- `ai/knowledge/security_skills/__init__.py` (new)
- `ai/knowledge/security_skills/skills.py` (new)
- `ai/knowledge/security_skills/library.py` (new)
- `ai/test_security_skills.py` (new)
- `tests/local_e2e/r64_research.py` (skill integration, rule version `r69-1`)
- `tests/local_e2e/test_r64_research.py` (integration + version updates)
- `agent-reports/r69-security-research-skill-library.md` (this report)

## 15. Commit

One local commit: `feat(ai): add security research skill library`
(hash reported in the final task response). No push.
