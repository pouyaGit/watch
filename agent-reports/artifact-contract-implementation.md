# Phase 4C — Artifact Reference + Safety Contract: Implementation Report

## 1. Verdict

**IMPLEMENTED.** Phase 4C establishes the deterministic artifact contract
boundary exactly as specified:

```
TestPlan + artifact bytes → validated, hash-bound ArtifactReference
```

No artifacts are generated, stored, executed, or verified. No findings,
verdicts, scope decisions, LLM calls, network access, subprocess
execution, or database writes were introduced. All new tests pass
(56/56) and all regression suites pass with zero new failures.

## 2. Actual repository findings

Inspected before writing any code (no prior report was trusted):

- `ai/schemas/test_plan.py` — `TestPlan` carries `test_plan_id`
  (`tp-` + 16 hex alias of the SHA-256 idempotency key),
  `hypothesis_id`, optional Phase-4B `match_id` (`tm-…`) and
  `snapshot_hash`, plus an existing `ArtifactRef` that binds
  **content hash only** (`artifact_id = "art-" + content_hash[:16]`)
  with a permissive `"generic"` type. It is **not** TestPlan-bound,
  carries no validation state, and allows an `"other"`-style
  `generic` type — insufficient for Phase 4C, so a first-class
  contract was created **alongside** it. `test_plan.py` itself was
  **not modified** (no additive field proved necessary).
- `ai/schemas/hypothesis.py`, `target_match.py`,
  `research_pattern.py`, `target_intelligence.py` — deterministic
  SHA-256 identity conventions (`hyp-`/`tm-`/`vp-`/`ap-`/`ti-`
  aliases, canonical sorted-keys JSON, `extra="forbid"`, no
  verdict/authority fields) were reused verbatim for the new
  contract. Nothing in these files was modified.
- `ai/researcher/{test_plan_builder,hypothesis_engine,
  target_matcher,pattern_projector,target_intelligence}.py` —
  pure deterministic builders; imports reused only as typed inputs
  in tests. None modified.
- `ai/ingestion/grounding.py` (`contains_forbidden`,
  `claim_fingerprint`), `ai/knowledge/pattern_store.py`
  (content-addressed identity discipline), `ai/correlator/version.py`
  and `technology.py` (deterministic matching authorities) — noted
  as conventions; none duplicated, none modified.
- Existing Nuclei code: `ai/correlator/nuclei_generator.py`
  (emits relative-path `METHOD <path> HTTP/1.1` raw requests;
  refuses destructive templates), `ai/collectors/nuclei_template.py`
  (read-only parser; marks `DELETE` destructive), and
  `ai/correlator/nuclei_validator.py` (semantic DetectionSpec
  diffing). None performs specificity gating or attacker-field
  normalization — that gap is exactly H1/H2, closed by the new
  gate modules without touching the existing files.
- Existing XSS code (`ai/schemas/xss*.py`, verification/oracle
  contracts) — case/research/finding layers only; no payload
  artifact contract existed. Nothing modified.
- No existing validator could be reused safely for H1/H2 (the
  semantic validator diffs against a DetectionSpec and never
  evaluates matcher-vs-fixture specificity), so dedicated gate
  modules were created. No code was duplicated.

## 3. Exact artifact contract

New file `ai/schemas/artifact.py` (`SCHEMA_VERSION = "artifact/v1"`):

```python
class ArtifactReference(BaseModel):  # extra="forbid"
    artifact_id: str            # art- + 16 hex, deterministic alias
    artifact_type: ArtifactType # closed literal (see §4)
    content_hash: str           # full SHA-256 of exact artifact bytes
    test_plan_id: str           # tp-…; exactly one bound plan
    hypothesis_id: str | None   # descriptive provenance, never authority
    match_id: str | None        # descriptive provenance, never authority
    snapshot_hash: str | None   # descriptive provenance, never authority
    artifact_schema_version: Literal["artifact/v1"]
    validation_state: ValidationState  # UNVALIDATED | VALID | REJECTED
    metadata: dict[str, str]    # audit-only; excluded from identity;
                                # verdict/authorization keys rejected
```

Identity is enforced by a post-init model validator: `artifact_id`
must equal `artifact_id_for(type, test_plan_id, content_hash,
version)` or construction fails. `build_artifact_reference()`
is the deterministic factory (same inputs → same id; oversized
bytes raise `ValueError`).

## 4. Artifact type vocabulary (closed)

```python
ArtifactType = Literal["nuclei_template", "xss_payload", "http_request_spec"]
```

Only types with a concrete future use in Watch. No `shell_script`,
`arbitrary_code`, `browser_script`, `executable`, `command`, and no
`"other"`/`"generic"` escape hatch. Unknown types fail closed
(`ValueError` from the factory and the validator entry point;
`ValidationError` at the schema literal).

## 5. Hash / canonicalization rules

- `content_hash = SHA256(canonical artifact bytes)` using the
  project's existing SHA-256 convention.
- For raw bytes: the digest is over the **exact bytes**. Timestamps,
  filesystem paths, random IDs, model metadata, prompt text, and
  environment variables never enter the digest.
- For mappings: canonical form is sorted-keys, compact-separator
  JSON (`sort_keys=True, separators=(",",":")`, UTF-8), so
  validation is independent of dictionary/input order (proven by
  test AL).
- Nuclei/HTTP artifacts are canonical JSON objects; `parse_*`
  rejects non-UTF-8, non-JSON, non-object, and unknown-field
  payloads fail-closed. No fuzzy hashes exist.
- Same bytes → same hash; one-byte change → different hash (tests
  C/D). Two semantically identical artifacts with different bytes
  have different hashes (documented; no canonical-representation
  normalization is claimed beyond sorted-keys JSON).

## 6. TestPlan binding

- `build_validated_reference()` copies `test_plan_id`,
  `hypothesis_id`, `match_id`, `snapshot_hash` from the supplied
  `TestPlan`; bindings are never manufactured.
- `validate_reference_binding()` re-checks all four bindings with
  exact equality: an artifact built for one plan can never attach
  to another (tests H/I/J). `test_plan_id` inequality,
  hypothesis/match/snapshot inequality, content-hash inequality,
  and `artifact_id` basis mismatch are each reported as errors.
- Re-validation of `VALID` references re-runs type validation
  (safety + specificity), so duplicate validation converges (AM).

## 7. Provenance binding

`hypothesis_id`/`match_id`/`snapshot_hash` travel as descriptive
audit pointers copied from the bound `TestPlan`. Artifact content
never replaces provenance; hostile `metadata` never enters
identity (AN) and verdict/authorization metadata keys
(`verdict`, `scope_allowed`, …) are rejected at the schema level
(AO).

## 8. Validation-state semantics (closed)

`ValidationState = Literal["UNVALIDATED", "VALID", "REJECTED"]`.
`VALID` means only **"the artifact passed deterministic
contract/safety validation"** — never "the target is vulnerable",
never scope/execution authorization. No `CONFIRMED`, `EXPLOITED`,
or `VULNERABLE` state exists; the type system rejects them.

## 9. H1 specificity gate — IMPLEMENTED ✅

`ai/researcher/nuclei_artifact_validator.py` →
`validate_nuclei_specificity(template, fixtures)`:

1. Typed inputs only (`NucleiTemplateContent`, list of
   `NucleiFixture`); raw dicts raise `TypeError`.
2. Static pre-gate rejects matchers that cannot prove
   specificity: values shorter than 4 chars, generic tokens
   (`error`, `success`, `html`, `200`, …), and status-only
   matchers.
3. A `benign` fixture is **required**; missing/empty fixtures →
   `passed=False` (deterministic unsupported).
4. If **any** matcher matches the benign fixture → `passed=False`
   (fail closed). Local evaluation only: `word` = substring,
   `regex` = bounded `re.search`, `dsl` = quoted-literal/status
   matching, `status` = status-set membership. Unparseable DSL
   never matches (fail closed toward "no positive proof").
5. Where vulnerable fixtures exist, **every** vulnerable fixture
   must be matched by at least one matcher, else `passed=False`.
6. The gate never mentions real targets and never emits verdicts.

**H1 proof (tests V–Y + dedicated):** a template whose matcher is
broad enough to match the benign fixture (`word: "error"` vs a
benign body containing "error"; `"Welcome to our homepage"` vs
the default benign body) is `REJECTED` and can never be `VALID`;
the same harness with the unique marker scores `VALID`.

## 10. H2 safety gate — IMPLEMENTED ✅

`validate_nuclei_safety()` (+ `validate_http_safety()` reusing the
same field validators for `http_request_spec`):

- **PATH:** relative only (`/`-anchored), no absolute URL, no
  CR/LF/NUL/control chars, no command substitution (``$(``,
  backtick, `${`), no `;`/`|` shell syntax, no shell/command
  keywords (`curl`, `/bin/`, `cat /etc/passwd`, …), no embedded
  script (`<script`, `javascript:`, event handlers), unsafe-host
  and callback checks.
- **HEADERS:** strict name regex, CR/LF/control rejection,
  `Authorization`/`Cookie`/`Set-Cookie`/`Proxy-Authorization`/
  `Proxy-Authenticate` rejected entirely, `Bearer`/`Basic`
  credential values rejected, shell/script/callback/unsafe-host
  checks per value.
- **QUERY/PARAMS:** CRLF/control rejection, shell-construct and
  `;`/`|` rejection, command-like interpolation rejection,
  embedded-script rejection, per-value unsafe-host/callback
  checks.
- **BODY:** bounded plain data only; NUL/CR-LF/C0 controls, shell
  constructs/syntax/keywords, embedded scripts, and unsafe
  targeting all rejected. (If safe handling cannot be
  established, the gate rejects — no body allowlist is claimed.)
- **Destructive/unsafe:** `DELETE` rejected (no existing Watch
  contract requires destructive artifact methods); localhost,
  loopback, private, link-local, `169.254.169.254`, `localhost`,
  `metadata.google*` targeting rejected via stdlib `ipaddress`
  parsing (no resolution, no requests); collaborator/callback
  domains (`burpcollaborator`, `interactsh`, `ngrok`,
  `webhook.site`, …) rejected; embedded scripts rejected. Scope
  is intentionally **not** broadened into a generic SSRF
  subsystem — only artifact-level rules are enforced.

**H2 proof (tests M–U):** CRLF path/headers, credential headers,
shell syntax, `$(…)`/backtick/`${…}` substitution, `DELETE`,
private/metadata hosts, callback endpoints, and embedded
`<script>`/`javascript:` content are each proven `REJECTED`;
a clean template is proven `VALID`.

## 11. XSS artifact boundary

`validate_xss_payload()`: non-empty, ≤ 4096 bytes, UTF-8, no NUL,
no CR/LF/C0 controls. The payload is **inert data**: hashed,
plan-bound, size-bounded — never executed, never sent, never
loaded in a browser, never resolved against callbacks, never
classified as "working" (tests Z/AA; AST tests prove no browser,
executor, or network calls exist in the new modules).

## 12. Size limits

```python
MAX_NUCLEI_TEMPLATE_BYTES = 32768  # raw request + matchers fit; else reject
MAX_XSS_PAYLOAD_BYTES     = 4096   # inert payload data cap
MAX_HTTP_ARTIFACT_BYTES   = 16384  # request-spec cap
```

Explicit constants in `ai/schemas/artifact.py`, enforced in both
the factory (`ValueError`) and the validator (`REJECTED`
reference that stays hash-bound so re-validation converges).
Oversized content is proven rejected (test L). Limits are
conservative against existing Watch contracts (labels ≤512,
prose ≤2048, explanations ≤4096).

## 13. Security boundaries (all statically tested)

New modules import only `hashlib/json/re/ipaddress`, `pydantic`,
and the sibling contract/validator modules. AST tests prove the
absence of: LLM/model/prompt/embedding imports (AB/AO), network
imports `requests/httpx/urllib/socket/dns` (AC), subprocess
imports/calls (AD/AH), DB imports `mongoengine/database/pymongo`
(AE), `scope_policy` imports (AF), verifier/oracle/executor/Nuclei
runtime imports (AG), finding creation (AI), verdict fields (AJ),
and authorization fields (AK). No files were written outside
test-memory fixtures; `compileall` passes.

## 14. Adversarial test coverage (A–AO)

`ai/test_artifact.py` — 56 tests, all passing. Mapping:

| ID | Coverage | Result |
|----|----------|--------|
| A | closed type vocabulary accepted | ✅ |
| B | unknown type → reject | ✅ |
| C | deterministic content hash | ✅ |
| D | one-byte change → different hash | ✅ |
| E | deterministic artifact_id | ✅ |
| F | different TestPlan → different identity | ✅ |
| G | same content + plan → same identity | ✅ |
| H | wrong test_plan_id → reject | ✅ |
| I | wrong hypothesis binding → reject | ✅ |
| J | wrong snapshot binding → reject | ✅ |
| K | malformed content → reject | ✅ |
| L | oversized content → reject | ✅ |
| M | CRLF in path → reject | ✅ |
| N | CRLF in header → reject | ✅ |
| O | Authorization/Cookie/bearer → reject | ✅ |
| P | shell-like content → reject | ✅ |
| Q | command substitution → reject | ✅ |
| R | destructive method → reject | ✅ |
| S | localhost/private/metadata → reject | ✅ |
| T | callback endpoint → reject | ✅ |
| U | embedded script → reject | ✅ |
| V | generic matcher + benign → reject | ✅ |
| W | specific matcher + benign → pass | ✅ |
| X | specific + vulnerable → positive proof | ✅ |
| Y | no specificity proof → reject | ✅ |
| Z | XSS bounded inert data | ✅ |
| AA | XSS never executed | ✅ |
| AB–AG | import boundaries | ✅ |
| AH | no runtime invocation | ✅ |
| AI | no finding creation | ✅ |
| AJ | no verdict fields | ✅ |
| AK | no authorization fields | ✅ |
| AL | order-independent validation | ✅ |
| AM | duplicate validation converges | ✅ |
| AN | hostile metadata ≠ identity | ✅ |
| AO | prompt/model metadata not authoritative | ✅ |

## 15. Integration test

`IntegrationTests.test_in_memory_chain` runs fully in memory with
no network/DB/LLM/subprocess:

```
KnowledgeSourceClaims(SECONDARY)
→ GroundedClaim → project_claim → VulnerabilityPattern
→ project_subdomain → TargetIntelligence
→ match_pattern_to_target → MATCH/PARTIAL_MATCH
→ build_hypothesis_from_match → CREATED
→ build_test_plan_from_hypothesis → CREATED (PROPOSED)
→ build_validated_reference → VALID ArtifactReference
→ validate_reference_binding → [] (clean)
```

The final reference is hash-bound, plan-bound (plan +
hypothesis + match + snapshot), deterministic,
validation-state-bound (`VALID`), non-executable, and
non-authoritative (no scope/verdict/finding keys in the dump).

## 16. Exact test results

- `python3 -m unittest ai.test_artifact` → **56 tests, OK**
- `ai.test_hypothesis_testplan ai.test_research_pattern
  ai.test_pattern_projector ai.test_pattern_store
  ai.test_target_intelligence ai.test_target_matcher
  ai.test_hypothesis_engine ai.test_test_plan_builder` →
  **467 tests, OK**
- `ai.test_ingestion_schema ai.test_ingestion_grounding
  ai.test_knowledge_store ai.test_knowledge_ingestion` →
  **132 tests, OK**
- `ai.test_openrouter ai.test_xss_researcher
  ai.test_xss_llm_researcher ai.test_xss_verification
  ai.test_xss_oracle` → **265 tests, OK**
- `python3 -m compileall -q ai` → **OK**

## 17. Limitations

1. The Nuclei artifact model is canonical JSON, not YAML: a
   future generator must serialize through `NucleiTemplateContent`
   (or produce byte-identical canonical JSON) — raw YAML
   templates are out of scope for this phase.
2. DSL matcher evaluation is conservative (quoted literals +
   `status_code==NNN`); exotic DSL that is locally unparseable
   yields "no positive proof" rather than a match — fail closed
   by design, but a future phase may extend the local DSL reader.
3. `;`/`|` are rejected in paths/query values/bodies even though
   rare legitimate values could contain them — intentional
   fail-closed tradeoff, documented in code.
4. No artifact store exists (in-memory references only); no
   generator, executor, or verifier integration exists — all
   explicitly deferred.
5. `http_request_spec` has no fixture/specificity gate (no
   matcher semantics); it enforces the H2-equivalent safety gate
   only.

## 18. Explicit Git no-op confirmation

**No Git command was executed in this phase.** No `git status`,
`diff`, `add`, `commit`, `checkout`, `switch`, `restore`,
`reset`, `merge`, `branch`, `stash`, or any other Git operation
was run. No unrelated working-tree files were inspected, staged,
modified, or cleaned. Three new files were created; zero existing
files were modified.

## 19. Recommended next safe phase

A **read-only Artifact Store** phase: content-addressed,
plan-bound persistence of already-`VALID` references (record
files keyed by full content hash, atomic writes, integrity
re-validation on read — mirroring `PatternStore` conventions),
still with no generation, no execution, no verification, and no
LLM involvement. Generation (deterministic first, LLM later)
must remain a separate phase after storage semantics are fixed.
