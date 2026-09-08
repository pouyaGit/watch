# ResearchResult `affected_products` LLM-Output Robustness Fix

## Summary

Fixed the `ValidationError` that failed CVE-2026-1557 during the real
3-CVE batch. The LLM emitted an object inside `affected_products`:

```json
{"name": "WP Responsive Images", "type": "WordPress Plugin"}
```

while the canonical schema requires `list[str]`. A small deterministic
normalization step now runs at the LLM-output boundary (pydantic
`mode="before"` validation), so the failure shape is normalized instead
of raising. The public schema is unchanged.

## Root Cause

- `ResearchResult.affected_products` is declared `list[str]`
  (`ai/schemas/research.py`), with no `mode="before"` normalizer —
  unlike `evidence` and `affected_versions`, which already tolerate
  LLM-emitted objects via `stringify_evidence` /
  `stringify_affected_version`.
- The `SecurityResearcher` prompt (`ai/researcher/researcher.py`) only
  forbade objects inside `evidence` and `affected_versions`; it said
  nothing about `affected_products`, so the model emitted
  `{"name": ..., "type": ...}` there.
- Pydantic therefore rejected the whole `ResearchResult` for
  CVE-2026-1557 with
  `affected_products.0: Input should be a valid string`.

## Changes (minimal, localized)

1. `ai/schemas/research.py`
   - Added `stringify_affected_product(value) -> str | None`.
   - Added `ResearchResult.normalize_products`, a
     `@field_validator("affected_products", mode="before")` that maps
     each item through the normalizer and drops `None` results.
   - `affected_products` annotation is unchanged: strictly `list[str]`.
2. `ai/researcher/researcher.py`
   - Prompt `IMPORTANT OUTPUT FORMAT RULES` now explicitly require
     `affected_products` to be an array of strings, forbid objects
     there, and show the required vs. forbidden shape.
3. `ai/test_research_affected_products.py` (new)
   - 14 focused offline regression tests (see below).

No other research code was refactored. Normalization applies ONLY to
`affected_products`; unrelated fields are untouched.

## Exact Normalization Behavior

| Input item | Output |
|---|---|
| `"Some Product"` (string) | unchanged, verbatim |
| `{"name": "WP Responsive Images"}` | `"WP Responsive Images"` |
| `{"name": "WP Responsive Images", "type": "WordPress Plugin"}` | `"WP Responsive Images (WordPress Plugin)"` |
| `{}` / `{"type": "X"}` / `{"name": "  "}` / `{"foo": "bar"}` (malformed, no usable `name`) | dropped (no product invented) |
| `None` | dropped |
| nested list/tuple/set | dropped |
| other scalars (e.g. int) | `str(value)`; dropped if blank |
| `None` field / missing field | `[]` |
| non-list field value | wrapped to single-item list, then normalized as above |

Strings keep existing behavior verbatim (no stripping, no filtering),
so valid `list[str]` payloads validate exactly as before.

## Tests Run / Results

New focused suite — all pass:

```bash
python3 -m unittest ai.test_research_affected_products -v
# Ran 14 tests — OK
```

Coverage: normal `list[str]`; dict `{name}`; dict `{name, type}`
(using the exact CVE-2026-1557 payload shape); mixed strings+objects;
malformed object dropped conservatively; canonical annotation still
`list[str]`; nested containers dropped; missing field defaults to `[]`;
unrelated field (`impact`) with an object still raises
`ValidationError` (no silent cross-field normalization).

Existing regression suites — all pass, no regressions:

```bash
python3 -m unittest ai.test_knowledge_store ai.test_xss_researcher \
  ai.test_xss_llm_researcher ai.test_openrouter
# Ran 89 tests — OK

python3 -m unittest ai.test_cve_batch ai.test_nuclei_cve_2026_1557_dryrun \
  ai.test_nuclei_offline_prepare ai.test_reference_quality_decision_boundary
# Ran 45 tests — OK
```

Total: 148 tests, all green.

Additionally verified directly that the exact failing payload now
validates:

```python
ResearchResult.model_validate({
    "title": "CVE-2026-1557",
    "summary": "s",
    "affected_products": [
        {"name": "WP Responsive Images", "type": "WordPress Plugin"}
    ],
})
# affected_products == ["WP Responsive Images (WordPress Plugin)"]
```

## Confirmation: No Live Execution

- No LLM calls (all LLM interactions use offline fixtures/mocks in the
  suites above; the fix itself is pure deterministic parsing).
- No Mongo writes (no Mongo client instantiated in any test run).
- No Nuclei execution (Nuclei-related suites run offline/dry-run paths
  only).
- No commits, pushes, or other git write operations performed.

## Note on `git diff --check`

`git diff --check` flags trailing-whitespace warnings on added lines,
but inspection shows the repository files use CRLF line endings
throughout (every line ends with CR), so every added line is flagged —
a pre-existing repo condition also affecting untouched files
(`ai/config.py`, `ai/correlator/version.py`, `ai/researcher/batch.py`,
etc.). The new code itself contains zero trailing-space lines
(verified by direct scan); the single flagged content line in
`ai/researcher/researcher.py` (line 267, two spaces) is pre-existing.

---

## Follow-up: Prompt f-string Regression (fixed)

### Root cause

The `affected_products` prompt instruction added above contained a
literal JSON example with single braces:

```text
NEVER like [{"name": "WP Responsive Images", "type": "WordPress Plugin"}].
```

`SecurityResearcher.research` (`ai/researcher/researcher.py`) builds
the whole prompt as one f-string, so Python interpreted `{...}` as a
format expression and prompt construction raised:

```text
ValueError: Invalid format specifier ' "WP Responsive Images", ...'
```

before any CVE was processed — all 3 CVEs in the real batch failed
(`processed=0 failed=3`).

### Exact fix

One line in `ai/researcher/researcher.py` (line 195): escaped the
literal JSON braces as `{{` / `}}`, matching the existing convention
already used by the JSON-schema block in the same f-string:

```text
NEVER like [{{"name": "WP Responsive Images", "type": "WordPress Plugin"}}].
```

The rendered prompt is byte-identical to the intended instruction
(single braces). The `ResearchResult` schema and normalization behavior
are untouched; no other code was refactored.

### Tests

Added `ResearchPromptRenderingTests` to
`ai/test_research_affected_products.py`: drives
`SecurityResearcher.research` with a fake LLM (captures the prompt,
returns minimal valid JSON) and asserts:

- prompt construction does not raise `ValueError`;
- the rendered prompt contains the intended literal shape
  `NEVER like [{"name": "WP Responsive Images", "type": "WordPress Plugin"}]`;
- no `{{` / `}}` escape residue leaks into the rendered prompt.

Results — all green:

```bash
python3 -m unittest ai.test_research_affected_products -v
# Ran 15 tests — OK (14 prior + 1 new prompt-render test)

python3 -m unittest ai.test_research_cli ai.test_research_pattern \
  ai.test_reference_quality_decision_boundary ai.test_single_cve_quality_parity
# Ran 101 tests — OK

python3 -m unittest ai.test_cve_batch ai.test_nuclei_cve_2026_1557_dryrun \
  ai.test_nuclei_offline_prepare ai.test_batch_reference_quality_parity
# Ran 46 tests — OK
```

Total: 162 tests, all passing.

### Confirmation: no live execution

- The new test uses a fake in-process LLM; no network, no provider
  credentials, no model calls.
- No Mongo writes (no Mongo client instantiated in any test run).
- No Nuclei execution (Nuclei-related suites use offline/dry-run paths
  only).
- No git operations performed (read-only inspection only).
