# Repository State Cleanup v1

Date (UTC): 2026-09-20
Branch: `agent/daily-development`
Workspace: `/opt/watch/.worktrees/watch-agent` (agent worktree)
Production checkout (inspected read-only): `/opt/watch` (`main`)

## 1. TASK

Make the Watch repository clean for autonomous development:

1. Inspect the current dirty/untracked files.
2. Classify everything under `ai_data/knowledge/*`, `wordlists/*` and
   `agent-reports/*`.
3. Improve `.gitignore` safely, ignoring only generated/runtime files and
   never hiding source, tests, documentation, or deterministic research
   reports.
4. Produce this report.
5. Run `git status` (and tests if needed) and commit the changes.

Constraints observed: never push, never delete files, never edit the
production checkout `/opt/watch`.

## 2. Workspace finding (important)

The agent worktree (`agent/daily-development`) was **already clean**. Every
dirty/untracked file referenced by the task lives in the **production
checkout `/opt/watch`** on `main`:

```
 M ai_data/knowledge/index.json
 M wordlists/dell_params.txt
 M wordlists/indeed_params.txt
 D utils.zip
?? agent-reports/REAL-OPERATION-*.md                (13 files)
?? agent-reports/VM-CODE-RECONCILIATION-R100.md
?? agent-reports/dell-watchlist-inventory-reuse-report.md
?? agent-reports/git-history-reconciliation-a0a0349.md
?? agent-reports/reconciled-inventory-reuse-report.md
?? ai_data/knowledge/documents/<sha256>.json        (6 files)
```

`docs/AUTONOMOUS_DEVELOPMENT_WORKFLOW.md` defines a hard rule: the agent must
never edit files under `/opt/watch`; all development happens in the worktree.
The production changes were therefore analysed **read-only** for
classification, and were **not** touched, adopted, or committed.

## 3. Classification

### A) Source / project artifacts (tracked; must NOT be ignored)

These are deterministic, content-addressed or source inputs. They are project
artifacts by design and belong in Git.

| Path | State | Rationale |
|------|-------|-----------|
| `ai_data/knowledge/index.json` | modified | Canonical KnowledgeStore index. Deterministic catalog derived from content-addressed documents (`ai/knowledge/store.py`). |
| `ai_data/knowledge/documents/<sha256>.json` (6 new) | untracked | KnowledgeStore documents. The full SHA-256 content hash is the canonical identity (`AGENTS.md`). Deterministic, source-attributed research output. |
| `ai_data/knowledge/documents/<sha256>.json` (24 existing) | tracked | Same class; already part of the repository baseline. |
| `ai_data/reports/*.md` | tracked | Deterministic CVE research reports. |
| `ai_data/nuclei/generated|results|findings/*` | tracked | Generated templates and their results/findings, kept as deterministic evidence. |
| `wordlists/dell_params.txt`, `wordlists/indeed_params.txt` | modified | Source wordlists consumed by parameter discovery. Additive content, not discardable runtime state. |
| `agent-reports/*.md` (327 tracked + 17 untracked) | untracked/modified | Project convention: `agent-reports/` is a permanent artifact directory. The untracked files are substantive `REAL-OPERATION-*`, reconciliation and inventory reports — deterministic research documentation. |

### B) Generated runtime artifacts (ignored or newly ignored)

None of the tracked/untracked files in section A are runtime garbage. The
runtime artifacts produced by the pipeline were either already ignored or are
newly covered by this change:

| Pattern / path | Status | Source |
|----------------|--------|--------|
| `ai_data/research/`, `ai_data/raw/`, `ai_data/cve/` | already ignored | runtime research data |
| `crawl/output/`, `dns-bruteforce/work/` | already ignored | crawler / DNS runtime workspaces |
| `programs/*` (except two negations) | already ignored | runtime program sync data |
| `__pycache__/`, `*.py[cod]`, `venv/`, `.env`, `*.db`, `*.log` | already ignored | Python / secrets / DB / logs |
| `*.lock` | **newly ignored** | `.tasks.lock`, `.sessions.lock`, `.outcomes.lock` written by `ai/knowledge/*` stores at runtime |
| `logs/` | **newly ignored** | per-run task logs under `logs/tasks/`; `api.py` notes log contents can include sensitive recon data (`*.log` only partly covered this) |
| `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.coverage`, `.coverage.*`, `coverage.xml`, `htmlcov/` | **newly ignored** | Python testing/tooling caches |
| `.env.*` (with `!.env.example`) | **newly ignored** | local credential overrides; example kept tracked |

### C) Temporary files

| Pattern | Status | Source |
|---------|--------|--------|
| `*.tmp` | already ignored | KnowledgeStore atomic writes: `index.json.tmp`, `<hash>.json.tmp` (`ai/knowledge/store.py`) |
| `*.bak`, `*.orig`, `*.rej` | **newly ignored** | editor / merge temporaries |
| `*.swp`, `*.swo`, `*~` | already ignored | editor temporaries |

### Out of scope / ambiguous

- `utils.zip` is **deleted** in the production working tree. It is a tracked
  archive, not a generated runtime artifact. Per the "never delete" rule the
  agent did not restore or confirm the deletion; it is left exactly as found
  in `/opt/watch`.

## 4. Decisions

1. **Do not ignore deterministic artifacts.** `ai_data/knowledge/`,
   `ai_data/reports/`, `ai_data/nuclei/`, `agent-reports/`, and `wordlists/`
   remain tracked. An explicit comment block was added to `.gitignore`
   documenting this so future changes do not "clean" them away.
2. **Ignore only genuine runtime/generated files.** Added lock files, the
   runtime log directory, Python tooling caches, local `.env.*` overrides, and
   editor/merge temporaries. No source, test, documentation, or deterministic
   report path matches any new rule.
3. **Respect the production boundary.** `/opt/watch` was inspected read-only.
   No production file was edited, deleted, adopted, or committed.
4. **Never push, never delete.** No deletion or remote operation was
   performed.
5. **Scope kept minimal.** Only `.gitignore` and this report are changed.
6. **Production artifacts remain uncommitted.** The section-A files in
   `/opt/watch` still need a human/operator decision to commit them (or an
   explicit follow-up task authorising their adoption into the agent branch).
   They are deliberate deterministic artifacts and must not be silently
   ignored or discarded.

## 5. Verification

- Tracked files that would become ignored by the new rules (must be empty):
  `git ls-files -ci --exclude-standard` → empty.
- Negative checks (deterministic artifacts must not be ignored):
  `git check-ignore -v` on `ai_data/knowledge/index.json`,
  `ai_data/knowledge/documents/*.json`, `ai_data/reports/*.md`,
  `ai_data/nuclei/*`, `agent-reports/*.md`, `wordlists/*.txt`,
  `tests/*` → no matches.
- Positive checks (runtime files must be ignored): `*.lock`, `logs/`,
  `.env.*`, `.pytest_cache/` → matched.
- `git diff --check` → no whitespace errors.
- Tests: not required — the change is `.gitignore` plus documentation only,
  no executable code was modified. No application tests were run.

## 6. Files changed

| File | Change |
|------|--------|
| `.gitignore` | Added `.env.*` (`!.env.example`), Python tooling caches, `*.lock`, `logs/`, `*.bak`/`*.orig`/`*.rej`, and a comment block documenting the deterministic artifacts that must stay tracked. |
| `agent-reports/repository-state-cleanup-v1.md` | This report (new). |

## 7. Summary

TASK: Classify dirty/untracked files (`ai_data/knowledge/*`, `wordlists/*`,
`agent-reports/*`), harden `.gitignore` against generated/runtime files only,
report, and commit.

SUMMARY: The agent worktree was clean; all dirty files were found in the
production checkout and classified as deterministic project artifacts
(category A) that must not be ignored. `.gitignore` was hardened for genuine
runtime artifacts (locks, runtime logs, tooling caches, local env overrides,
merge temporaries). No file was deleted and the production checkout was not
modified.

FILES CHANGED:
- `.gitignore`
- `agent-reports/repository-state-cleanup-v1.md`

TESTS: Not required (`.gitignore` + documentation only). Verification done via
`git ls-files -ci --exclude-standard`, `git check-ignore`, and
`git diff --check`.

COMMIT STATUS: committed on `agent/daily-development`.
PUSH STATUS: not pushed.
READY TO PUSH: YES
