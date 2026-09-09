# Stage R9.2 — LLM content_hash Mismatch Diagnosis

## Scope / constraints observed

- No code modified. No schemas changed. No prompts changed. No validator patched.
- No LLM/provider request made in this stage (no `complete()` call, no network).
- No API keys or provider metadata printed in this report.
- Evidence is the R7 implementation as read from the working tree plus
  read-only local recomputation against the persisted candidate.

Sources read:

- `agent-reports/stage-r7-llm-xss-research.md`
- `agent-reports/stage-r9-first-real-llm-run.md`
- `agent-reports/stage-r9.1-provider-error-fix.md`
- `ai/researcher/xss_llm_assistant.py` (R7 implementation)
- `ai/schemas/xss.py` (`XSSLLMResearchAssistantResult`)
- `ai/research_cli.py` (`run_xss_llm_research`)
- `ai/test_xss_llm_assistant.py` (why mocks pass but a real model cannot)
- `ai_data/research/xss/xss-488f639165085224.json` (persisted candidate)

## 1. How the deterministic candidate content_hash is calculated

`ai/researcher/xss_llm_assistant.py::_candidate_content_hash` (lines 409–419):

```python
payload = {k: v for k, v in candidate.items() if k != "content_hash"}
serialized = json.dumps(
    payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
)
return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
```

Properties:

- SHA-256 over the canonical JSON serialization of the **candidate dict
  as loaded**, with `sort_keys=True`, `separators=(",", ":")`,
  `ensure_ascii=False`.
- The `content_hash` key itself is **excluded**, so the hash is stable
  regardless of when it was attached.
- It is **not** the file-bytes hash of
  `ai_data/research/xss/<id>.json` (which depends on indentation/key
  order/whitespace). It is a hash of the re-serialized payload.
- Computed in `XSSLLMResearchAssistant.research()` at line 381–382
  (`if content_hash is None: content_hash = _candidate_content_hash(candidate)`),
  then attached as `candidate["content_hash"]` (line 384) for the
  downstream `build_research_assistant_result(candidate, ...)` comparison.
- The CLI (`run_xss_llm_research`) never passes `content_hash`; it calls
  `assistant.research(candidate, store)` (line 1253), so the `None` branch
  above always applies on the real path.

## 2. What exact value is supplied to the LLM prompt, if any

**No hash value is supplied to the LLM. None.**

Chain of proof (all verified by direct read + local prompt build, no
provider call):

1. `research()` sets `candidate["content_hash"]` and then calls
   `_build_prompt(candidate, evidence)` (line 386).
2. `_build_prompt` does **not** embed the candidate dict. It embeds
   `_candidate_projection(candidate)` (line 157).
3. `_candidate_projection` (lines 80–116) projects exactly these keys:
   `candidate_id, status, query, xss_type, context, injection_context,
   confidence, vulnerability_pattern, sinks, sources, preconditions,
   unknowns, source_evidence, references`.
   It has **no `content_hash` key**. Verified programmatically:
   `projection has content_hash key: False`.
4. A locally built prompt for `xss-488f639165085224` (offline string
   build only) confirms: `prompt contains hash value: False`. The only
   occurrence of the token `content_hash` in the entire prompt is the
   schema-instruction line (1 occurrence):
   `"content_hash": "string (exactly as given)"` (prompt line ~106).
5. The candidate projection dumped into the `DETERMINISTIC CANDIDATE
   (authoritative)` section therefore contains `candidate_id`, `status`,
   `confidence`, etc., but no hash the model could copy.

So the prompt says "exactly as given" for a value that was never given.

## 3. Whether the LLM is expected to generate the content_hash itself

Yes — structurally, that is what the code demands, even though the prompt
never gives it the value:

- The output schema (`XSSLLMResearchAssistantResult.content_hash: str`,
  required, no default) forces every response to contain a `content_hash`
  string, or pydantic raises `ValidationError` (missing field).
- `build_research_assistant_result` (lines 346–353) seeds a deterministic
  payload and then **overwrites it with the model's data**:

  ```python
  payload = {
      "candidate_id": candidate.get("candidate_id"),
      "status": candidate.get("status"),
      "confidence": candidate.get("confidence"),
      "content_hash": candidate.get("content_hash"),
  }
  payload.update(llm_data)   # model-supplied content_hash wins
  result = XSSLLMResearchAssistantResult.model_validate(payload)
  _check_authority(result, candidate)
  ```

- `_check_authority` (lines 258–260) then requires
  `result.content_hash == candidate["content_hash"]`, else
  `XSSLLMResearchError("LLM returned a mismatched content_hash")`.

Net effect: the model **must emit** the 64-hex-char hash, and it must
match exactly. Since it was never shown the value, the only way to pass
is to guess 256 bits correctly (probability ~2^-256) or to echo a value
leaked by some other channel (there is none — secrets/redaction tests
confirm no hash is injected anywhere else).

## 4. Whether content_hash is supposed to be model-generated or verifier-derived

Per the R7 design intent, it is **verifier-derived, not model-generated**:

- R7 report §"Schema / output structure": "`content_hash` is the
  deterministic SHA-256 of the deterministic candidate payload … so a
  re-read can prove the research was generated against a specific
  candidate version."
- Schema docstring (`ai/schemas/xss.py`, `XSSLLMResearchAssistantResult`):
  "`content_hash` is the SHA-256 of the deterministic candidate the
  research is based on, so a later re-read can confirm it was not
  regenerated against a different candidate."
- `model` / `raw_response_id` are explicitly "always overwritten from the
  provider result (never from model self-reporting)" — the codebase
  already knows the pattern for verifier-derived fields, but
  `content_hash` was not given the same treatment.
- The R7 "Remaining limitations" framing ("`content_hash` ties research
  to a candidate snapshot") describes a **binding/version stamp**, i.e. a
  verifier assertion, not model knowledge.

The implementation contradicts that intent by routing the binding through
the model's output and then treating a mismatch as a model fault.

## 5. Why a valid LLM response can realistically produce a mismatched content_hash

Because **every** real model response is in the failure set, no matter how
"valid" its research content is:

- A well-behaved model that follows the schema must invent 64 hex chars
  (or copy a wrong/placeholder hash, omit-and-fail, or truncate). Any of
  these fails `_check_authority`. The observed
  `ERROR: XSSLLMResearchError: LLM returned a mismatched content_hash`
  is therefore the **expected outcome of a successful provider call**,
  not evidence of a bad model or bad research content.
- The `nvidia/nemotron-3-ultra-550b-a55b:free` run reaching the model
  successfully and then failing validation is exactly this: transport OK,
  research fields plausibly well-formed, hash echo impossible.
- Contributing model-side behaviors that make specific wrong values
  likely (all normal, none adversarial):
  - emitting a plausible-looking but random 64-hex string;
  - echoing a hash-like string from the KB evidence (e.g. a KB
    `content_hash` such as `609f38e9…`, which is a *document* hash, not
    the *candidate* hash);
  - returning `""`, `null`, or omitting the field (then schema validation
    fails instead, same fail-closed result);
  - normalizing case/truncation of a hash (any single-char deviation fails
    the exact-equality check).
- None of these indicate the model's research (`explanation`,
  `supporting_reasoning`, evidence attribution, etc.) was wrong. The
  validator rejects before those fields are even evaluated for quality.

Why the test suite did not catch this: `_valid_llm_body` in
`ai/test_xss_llm_assistant.py` (lines 75–80) builds the mock body as
`"content_hash": candidate.get("content_hash", "")`, where the test
`setUpClass` pre-attached the correct hash (line 143). The mock is
handed the answer key out-of-band; a real LLM never gets it. All 20/21
mock tests therefore pass while the real path is deterministically
broken. This is a test-blind-spot, not model misbehavior.

## 6. Classification

- **A) Expected model behavior — NO.** The model is not misbehaving. A
  stochastic text generator asked to reproduce an unseen 256-bit value
  cannot succeed by construction. Blaming the model (or retrying models)
  cannot fix this.
- **B) Implementation/design defect — YES (primary).**
  `build_research_assistant_result` does `payload.update(llm_data)` so
  model output overwrites the deterministic binding, then
  `_check_authority` punishes the model for not knowing it. A
  verifier-derived binding must never transit through untrusted model
  output. `model`/`raw_response_id` already follow the correct
  overwrite-from-verifier pattern; `content_hash` should have too.
- **C) Prompt construction defect — YES (contributing).**
  `_candidate_projection` strips `content_hash` while the schema
  instruction says `"content_hash": "string (exactly as given)"`. Either
  the value must be supplied (bad idea — see below) or the instruction
  must not ask for it. As written the instruction is unsatisfiable.
- **D) Invalid validation expectation — YES (same root cause as B).**
  Requiring `result.content_hash == det_hash` where `result.content_hash`
  comes from `llm_data` is checking the model's ability to guess, not
  the research's binding to a candidate version. The check is correct
  *only if* the compared value is verifier-stamped, not model-echoed.

In short: **B + C + D, not A.** One root cause expressed in three places:
design routes a deterministic binding through the model (B), the prompt
withholds it while demanding it (C), and the validator treats the
inevitable mismatch as a model fault (D).

## Independent hash recomputation from the persisted candidate

Method (read-only, no provider call):

```python
import json, hashlib, pathlib
cand = json.loads(pathlib.Path(
    "ai_data/research/xss/xss-488f639165085224.json").read_text())
payload = {k: v for k, v in cand.items() if k != "content_hash"}
h = hashlib.sha256(json.dumps(
    payload, ensure_ascii=False, sort_keys=True,
    separators=(",", ":")).encode()).hexdigest()
```

Results:

| Quantity | Value |
| --- | --- |
| Expected `content_hash` (canonical payload hash) | `bbdc0d5f7d26d497acb9397d76c8909485f602acb5f865c1c6b75bac1418f7b6` |
| Candidate file-bytes SHA-256 (encoding/whitespace-dependent, NOT the binding) | `599c14f39402f8baf4e10172c7355e77423d4520f60d07f652407a09a4fa056f` |

The recomputed `bbdc0d5f…` matches the R9 report's recorded
`content_hash (R7)` exactly, confirming the hash function understanding
and that the persisted candidate is the version the R9 retry bound
against. (Do not confuse the two hashes: `599c14f3…` proves file
byte-integrity; `bbdc0d5f…` is the authority binding the validator
compares.)

## Rejected model response inspection (no new provider call)

Attempted without any provider call:

- `ai_data/research/xss/llm/` **does not exist** (verified `ls`); no
  partial output is persisted by design — `persist_research` is never
  reached when `build_research_assistant_result` raises.
- Fail-closed therefore destroys the evidence: the rejected JSON body
  (including whatever hash string the model invented) exists only in the
  stderr of the R9 retry process, which is not recorded anywhere in the
  repository. There is **no persisted artifact to inspect**.
- What can be stated without the body: *any* value other than exactly
  `bbdc0d5f7d26d497acb9397d76c8909485f602acb5f865c1c6b75bac1418f7b6`
  triggers the identical error message (`_check_authority` emits a
  fixed string with no expected/got detail), so the error line alone
  cannot distinguish "model emitted garbage" from "model did perfect
  research but guessed the hash". The validator logs neither the
  expected nor the received hash.
- Recommendation for any future run (not done here): log expected vs.
  received hash shape (length/hex) at debug level, or better, stop
  requiring the echo at all (next section). No secret material is
  involved in doing so.

## Answer to the mandated question

**Should the system derive `content_hash` deterministically after the LLM
response instead of asking the LLM to provide it?**

**Yes — unambiguously.**

- `content_hash` is a binding/version stamp, not research content. The
  verifier already computes it (`_candidate_content_hash`) before the
  call. It should stamp it onto the validated result after parsing
  (exactly as `model`/`raw_response_id` are stamped via
  `result.model_copy(update={...})`), and the schema instruction asking
  the model for `content_hash` should be removed (or the field dropped
  from the model-visible schema entirely).
- Supplying the hash *into* the prompt so the model can echo it back
  would make validation pass but buys nothing: echo-checks prove
  copy-ability, not binding, and they keep a deterministic invariant
  hostage to stochastic output (any future truncation/rephrase breaks
  it again). Post-hoc verifier derivation is strictly stronger: the
  persisted record is bound to the exact candidate bytes by construction,
  with zero model cooperation needed.
- This preserves every R7 guarantee (authority, attribution, URL
  allow-list, fail-closed persistence, one-record-per-candidate) while
  removing the only check that fails on correct outputs. Status /
  confidence echo-checks can remain model-echoed (they *are* present in
  the prompt projection, so echoing them is satisfiable); the hash
  cannot remain in that category because it is deliberately absent from
  the projection.

Minimal shape of the correct fix (diagnosis only, **not applied**):

1. Remove `"content_hash"` from the model-visible JSON schema in
   `_build_prompt`.
2. In `build_research_assistant_result`, pop any model-supplied
   `content_hash` from `llm_data` (never trust it) and stamp the
   deterministic value after validation.
3. Keep/extend `_check_authority` for genuinely model-echoable fields
   (`candidate_id`, `status`, `confidence`); assert the stamped hash
   instead of comparing a model string.
4. Add a regression test with a mock body that **omits** `content_hash`
   (or supplies a wrong one) and asserts success with the verifier hash
   stamped — the test that would have caught this pre-R9.

## No-change confirmation

- No files under `ai/`, `ai_data/`, schemas, prompts, or validators were
  modified in this stage. The only filesystem write is this report.
- No provider/LLM call was made. No secrets read or printed.
- Pre-existing working-tree modifications (e.g. `ai/research_cli.py`,
  `ai/schemas/xss.py` from earlier stages) were left untouched and are
  not attributed to this diagnosis.

## Agent / Model

- Model: muse-spark-1.3-contributor (opencode/muse-spark-1.3-contributor)
- Stage: R9.2
- Role: Diagnosis
