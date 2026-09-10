# Stage R14 — Deterministic Parameter & Component Intelligence

## 1. Objective

Extract deterministic, evidence-backed **vulnerable parameter** and
**vulnerable component / file / endpoint** intelligence from
already-extracted reference bodies (Stage R13 output), closing the R13
limitation where CVE-2024-5376's body explicitly named the `id`
parameter and `view_each_faculty.php` but the conservative R12 parser
left `parameters=[]`. Output remains research/intelligence only.

## 2. Files changed

- `ai/knowledge/intelligence.py` — R14 rules: labeled/bare/forward
  parameter rules, component/file/endpoint rules, validators
  (`_validate_component_value`, `_component_from_labeled_candidate`),
  vuln-context gating, exploit-tooling rejection, `components` field on
  `ExtractedIntelligence`. Rule version bumped `r12-2` → `r14-1`.
- `ai/schemas/knowledge.py` — additive `components` field on
  `KnowledgeSourceClaims`, `KnowledgeAggregate`, `KnowledgeDocument`
  (default `[]`, no renames, schema_version unchanged).
- `ai/knowledge/store.py` — writes/merges `components` into claims,
  aggregate, and compatibility projection.
- `ai/knowledge/ingestion.py` — projects `intelligence.components`
  into document fields, aggregate, and provenance claims.
- `ai/test_parameter_component_intelligence.py` — new, 32 tests.
- `ai/test_research_ingestion.py` — one assertion updated (see §10).

## 3. Parameter extraction rules

All rules are case-insensitive regex, bounded at
`MAX_INTELLIGENCE_TEXT_CHARS`, and gated by `_Attributor` (nearest-CVE /
structural / product-term logic unchanged from R12).

| Rule id | Form | Example |
|---|---|---|
| `parameter-vulnerable-labeled` | `vulnerable parameter[:=] NAME` | `vulnerable parameter: id` |
| `parameter-name-labeled` | `parameter name = NAME` | `parameter name: search` |
| `parameter-name-bare` | `NAME parameter(s?)` | `id parameter of view_each_faculty.php`, `the id parameter`, `'search' parameter` |
| `parameter-name-forward` | `parameter NAME` (singular only) | `parameter id`, `GET parameter id`, `parameter "id"` |

Normalization: quote/backtick stripping, trailing `=:,;.` trim, lowercase,
identifier regex `[A-Za-z_][A-Za-z0-9_.\-]{0,63}`, blocklist of sentence
words (of/the/is/was/name/…) and HTTP-method/marker words (`get`, `post`,
`query`, `url`, …) so "GET parameter id" yields `id` not `get`. Bare and
forward forms additionally reject generic abstraction nouns adjacent to
the keyword (`input`, `request`, `response`, `value`, `data`, `content`,
`text`, `string`, `code`). Generic words (`user`, `page`, …) are extracted
only when explicitly parameter-worded — never inferred from arbitrary nouns.

## 4. Component / file / endpoint extraction rules

- `component-vulnerable-labeled`: `vulnerable|affected|insecure
  file|component|endpoint|script|page|url|path|plugin [:|=|is] PATH` —
  no further context required (the label is the vulnerability context).
- `component-endpoint-named`: `endpoint|url|uri|route|path|script|page|
  file|component [is|:|=] /PATH` — vuln-context word required in the
  bounded window.
- `component-file-context`: source-file candidates
  (`*.php|jsp|asp|aspx|py|rb|js|ts|java|sh|sql|conf|…`) — extracted only
  when a vulnerability-oriented word (`vulnerab*`, `affected`, `injection`,
  `xss`, `sql injection`, `traversal`, `endpoint`, `parameter`, `exploit*`,
  `security issue`, `insecure`, `unauthorized`, `disclosure`) occurs in
  the bounded window. Plain project listings and unrelated code blocks
  yield nothing.

Validation (`_validate_component_value`): strips query/fragment, rejects
whitespace/HTML/protocol-relative/proxy URLs, bounded `[A-Za-z0-9_\-./]{1,150}`,
requires either a source-file extension or a leading `/` (endpoint),
normalizes to lowercase and strips leading slashes for dedup. Exploit
tooling shipped with PoC repos (`poc.sh`, `exploit.py`, `payload.*` —
stem pattern `poc|exploit|payload`) is rejected on the bare-file path:
a PoC script describes the exploit, not the vulnerable component.

## 5. Provenance behavior

Every claim is an `IntelligenceEvidence` record (field, value,
`source_artifact`, `source_url`, `source_type`, verbatim bounded
`evidence` snippet, `rule_id`, `rule_version="r14-1"`), reusing the R12
structure and `_record` path unchanged. No URLs or provenance are
fabricated; `research.*` text carries `source_url=None` /
`source_type="research"` exactly as before. Legacy R12 claim IDs and the
R12 evidence-merge in `store._merged_intelligence_evidence` are
untouched — R14 evidence records merge alongside them.

## 6. Normalization / deduplication behavior

Values are lowercased and quote-stripped (`id`, `"id"`, backtick-`id` →
`id`); components strip leading slashes so `/view_each_faculty.php` and
`view_each_faculty.php` converge, while deeper path distinctions
(`wp-content/plugins/foo/bar.php`, `/api/users` vs `/api`) are preserved.
`_ordered_unique` applied per field with first-seen ordering; evidence
dedup is the existing `(field, value, rule_id, source_url, evidence)`
tuple set on merge.

## 7. CVE-2024-5376 real-data result

From the persisted R13 reference body (GitHub PDF,
"XSS injection vulnerability exists in id parameter of
view_each_faculty.php file …"), no seeding, no special-casing:

- `vulnerability_types = ['xss']`
- `parameters = ['id']` — rule `parameter-name-bare`
- `components  = ['view_each_faculty.php']` — rule `component-file-context`
- Provenance points to the actual reference body URL (`github.com/E1CHO/
  cve_hub/.../College Management System - vuln 10.pdf`) with the verbatim
  snippet "XSS injection vulnerability exists in id parameter of
  view_each_faculty.php file of …", `rule_version = r14-1`.
- Persisted KB document after `kb ingest`: top-level `components` /
  `parameters`, aggregate attributed values, provenance claims, and
  `intelligence_evidence` all carry the two claims.

## 8. Five-CVE corpus regression result

| CVE | vulnerability_types | parameters | components |
|---|---|---|---|
| CVE-2024-27956 | sql_injection, code_injection | [] | [] |
| CVE-2024-42327 | sql_injection | [] | [] |
| CVE-2025-3102 | [] | [] | [] |
| CVE-2025-4893 | [] | [] | [] |
| CVE-2024-5376 | xss | ['id'] | ['view_each_faculty.php'] |

No new claims on unrelated CVEs; CVE-2024-27956's `poc.sh` mention is
correctly rejected by the exploit-tooling guard.

## 9. Focused test result

`ai.test_parameter_component_intelligence`: **32 tests, all OK**
(parameter forms, component forms, provenance/attribution, normalization,
dedup/stability, adversarial suite).

## 10. Regression test result

- Intelligence/knowledge/reference suites (19 modules incl. R12
  `test_intelligence`, `test_knowledge_store`, `test_knowledge_ingestion`,
  `test_research_ingestion`, `test_research_kb_xss_e2e`, R13
  `test_body_extraction`, quality-gate/canonicalization/ranker suites,
  mandatory XSS/LLM suites): **465 tests, all OK**.
- Full `ai` discovery: 2679 tests, 16 non-loader failures/errors. Stash
  baseline confirms **all are pre-existing environment/subsystem issues**
  (missing `tldextract`, unset Mongo URI, executor redaction, Nuclei
  template fixtures) — identical with R14 changes reverted.
- One updated assertion: `test_non_xss_content_never_gains_xss_dimensions`
  expected `parameters == []` only because the old parser could not
  recognize the fixture's explicit "Unsanitized src parameter." claim.
  The test's intent (no XSS dimensions for path-traversal content) is
  unchanged and still asserted; `parameters == ["src"]` is now the
  correct deterministic result.
- `git diff --check`: clean.

## 11. Idempotency result

All five CVEs re-ingested twice through `kb ingest`: 24 KB documents,
**zero byte-level file changes** between passes (SHA-256 per document),
document count stable, `created` empty on second pass.

## 12. False-positive / adversarial test result

All 16 mandated scenarios covered and passing, including: unrelated
filename mention → no claim; generic "input" without parameter wording →
no claim; URL with query string → not a parameter; HTML attributes →
no extraction; unrelated code-block filenames → no claim (no vuln
context); duplicate parameter/component mentions → single deterministic
claim; multiple parameters/components → stable first-seen ordering;
multi-CVE reference → nearest-CVE attribution only; CVE-silent product
reference → R12 behavior preserved; empty/garbage → no claim; oversized
text (200 KB) → bounded (50 KB scan cap) in ~30 ms.

## 13. Security / performance notes

Pure offline regex/dataclass engine — no LLM, no network, no subprocess,
no code execution. All regexes use bounded character classes and single
quantifiers (no nested quantifiers, no catastrophic backtracking);
scan capped at `MAX_INTELLIGENCE_TEXT_CHARS` (50 KB), evidence windows at
±90 chars / 240-char snippets. Per-document extraction is near-linear in
text size (fixed rule set). 200 KB adversarial input processes in ~30 ms.

## 14. Known limitations

- `parameter-name-bare`/`forward` rely on a fixed sentence-word blocklist;
  unusual prose shapes may miss or (rarely) admit a non-parameter token.
- Component extraction requires an explicit vulnerability-oriented word
  in the bounded window; vulnerabilities described only by filename
  implication are not captured.
- Bare endpoints without a source extension and without explicit
  endpoint labeling are rejected (conservative).
- `components` is additive; KB documents ingested before R14 keep empty
  `components` until rebuilt.

## 15. Explicit statement

- **No LLM used.**
- **No network used** (no fetches; verification used only persisted data).
- **No active validation** and no exploitation or Nuclei execution.
- **No production authority changed** (controlled-validation/live chain,
  B10 lab, DNS/crawl/systemd untouched; extraction is research-only).
- **No Git operations performed** (no commit, no push).

## Agent / Model
- Model: GLM (via Cline)
- Stage: R14
- Role: Deterministic Parameter & Component Intelligence
