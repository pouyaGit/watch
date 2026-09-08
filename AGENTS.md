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
```

## Agent Reports

Every task that requires a report, audit, review, implementation report,
design review, investigation report, or similar deliverable MUST follow
this mandatory workflow:

1. Create the report inside `agent-reports/`.
2. Never create task reports in the project root.
3. If `agent-reports/` does not exist, create it.
4. Report filenames must be descriptive and task-specific.

   Examples:

   - `agent-reports/xss-oracle-implementation-report.md`
   - `agent-reports/xss-oracle-review-report.md`
   - `agent-reports/xss-confirmation-state-machine-review.md`

5. Before creating a report, if a report with the exact same filename
   already exists, delete it and create the new report FROM SCRATCH.
6. Never append to an old report when the task explicitly requires a fresh
   report.
7. The report must contain only the results of the current task/review
   unless the task explicitly asks for historical information.
8. At the end of every task that produces a report, tell the user the exact
   relative path of the generated report.

   Example:

   ```
   Report:
   agent-reports/xss-oracle-review-report.md
   ```

9. The user will retrieve/upload that report to the supervising ChatGPT
   instance for review. Therefore, do NOT merely summarize the report in
   the final response when the report itself is requested.
10. Verify that the report exists before finishing.

    Example:

    ```bash
    ls -la agent-reports/<report-name>.md
    wc -l agent-reports/<report-name>.md
    ```

11. Keep the project root clean. Temporary reports, audit reports,
    implementation reports, design reviews, investigation reports, and
    similar agent-generated documentation belong under `agent-reports/`
    unless the task explicitly requires another location.
12. Do not move existing canonical project documentation into
    `agent-reports/`. Files such as README.md, architecture documentation,
    or other project documentation remain where the project architecture
    requires them.
13. When a task prompt explicitly specifies a report path outside
    `agent-reports/`, follow the latest explicit user instruction for that
    task, but otherwise `agent-reports/` is mandatory.

### Report Naming

Prefer the form:

```
<area>-<task>-<type>.md
```

Examples:

- `xss-oracle-implementation-report.md`
- `xss-oracle-review-report.md`
- `xss-confirmation-design-review.md`
- `cve-pipeline-audit-report.md`

Avoid generic names such as:

- `report.md`
- `final.md`
- `notes.md`
- `output.md`

The filename should make the report's purpose obvious without opening it.

### Final Response

Whenever a report is generated, the final response must include:

```
Report generated:
agent-reports/<exact-filename>.md
```

If relevant, also include the line count.