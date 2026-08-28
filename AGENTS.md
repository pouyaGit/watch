# Watch Project Agent Rules

## General

- Read this file before modifying the repository.
- Do not commit or push unless explicitly requested.
- Keep changes minimal and scoped to the requested task.
- Do not rewrite working code unnecessarily.
- Run relevant tests after modifications.
- Run `git diff --check` before reporting completion.
- Never expose secrets, API keys, tokens, credentials, or `.env` values.

## Scope Protection

The repository contains multiple active subsystems.

Do not modify unrelated subsystems.

### NS / DNS
The NS/DNS subsystem is actively maintained separately.
Do not modify `ns/` unless explicitly requested.

### Crawl / Parameter Discovery
The crawl and parameter-discovery subsystem is actively maintained separately.
Do not modify `crawl/` unless explicitly requested.

### Database
Do not modify `database/` unless the task explicitly requires a database change.

### Nuclei / CVE
Do not modify Nuclei or CVE functionality unless explicitly requested.

## AI Subsystem

AI-related work belongs primarily under:

- `ai/schemas/`
- `ai/knowledge/`
- `ai/researcher/`
- `ai/llm/`
- `ai/collectors/`
- `ai/correlator/`
- `ai_data/`

Prefer existing project abstractions over introducing duplicates.

### Knowledge Base

KnowledgeStore is deterministic and source-aware.

- Full SHA-256 content hashes are canonical document identity.
- `knowledge_id` is only a short stable alias.
- Never invent knowledge attribution.
- Preserve source attribution.
- Do not synthesize global security confidence from source claims.
- Do not silently discard source-specific metadata.
- Do not bypass integrity validation.

### XSS Research

XSS has separate concepts:

- `XSSCase` = investigation hypothesis/state
- `XSSResearchContext` = retrieved research context
- `XSSResearchLLMResult` = model research output
- `XSSFinding` = evidence-backed finding

Do not treat model suggestions as confirmed vulnerabilities.

The LLM must not independently retrieve from KnowledgeStore.

Knowledge retrieval happens before LLM reasoning.

Model-generated suggestions must remain explicitly marked
`model_generated`.

Knowledge-derived suggestions must retain valid `knowledge_ids`
and `source_ids`.

## LLM Safety

LLM providers must:

- use environment-based credentials
- never hard-code API keys
- never log credentials
- use dependency injection where practical
- have mocked/unit-tested network interactions
- avoid target-side network requests

LLM output must be parsed and validated before being consumed.

Never allow the LLM to directly:

- execute payloads
- scan targets
- run browsers
- confirm vulnerabilities
- modify production data

## Testing

Prefer `unittest` consistent with the existing AI test suite.

For AI changes, run the smallest relevant tests plus regression tests.

At minimum, when modifying the XSS/knowledge layer:

- `ai.test_knowledge_store`
- `ai.test_xss_researcher`
- `ai.test_xss_llm_researcher`
- `ai.test_openrouter`

Before completion:

```bash
git diff --check