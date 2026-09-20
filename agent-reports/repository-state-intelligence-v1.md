# Repository State Intelligence v1 — Implementation Report

## Scope

Extend the Watch Command Center so it can **explain** repository state instead of
only showing a raw dirty flag. A new read-only backend module classifies the
running checkout's uncommitted work, and the Command Center renders a
"Repository Intelligence" section with state, risk and per-category counts.

Explicit constraints observed:

- No git command is executed anywhere — neither by the implementation nor
  during verification. The module reads Git's own on-disk metadata read-only
  (`.git` / `HEAD` and the binary index) plus the working tree.
- `/opt/watch` (production checkout) was not modified. Only the agent
  workspace `/opt/watch/.worktrees/watch-agent` was changed.
- **Nothing was committed or pushed** (per task instructions).

## Deliverables

1. `backend/repository_intelligence.py` — deterministic, read-only classifier.
2. Command Center integration: `repository` payload slice, the new
   `GET /api/command/repository` endpoint, and a "Repository Intelligence"
   UI section.
3. `tests/test_repository_intelligence.py` — focused tests.
4. This report.

## How it works

Change detection (no git invocation):

- The Git directory is resolved from `.git` (a directory for a normal
  checkout, a `gitdir:` pointer file for a linked worktree).
- The binary index is parsed (v2/v3) into `path -> {mtime_s, mtime_ns, size,
  sha, mode}`. Index v4 (path compression) is rejected and the module degrades
  to an untracked-only scan.
- Each indexed path is stat-checked: missing -> `deleted_files`; a size or
  mtime difference is a modification candidate and is confirmed by computing
  the Git blob SHA-1 and comparing it to the staged digest (bounded by a
  64 MB hash budget). A same-size/same-mtime file is assumed unchanged,
  matching Git's stat-cache behavior.
- Untracked files are found by a bounded deterministic walk (`MAX_FILES_VISITED
  = 20000`) that prunes caches, vendor dirs and runtime output roots. Pruned
  runtime/ignored directories are reported as single bounded markers.

Deterministic classification (path based), matching the requested categories:

| Category | Meaning |
|----------|---------|
| `source_changes` | source/tests/docs/config files (tracked-modified or untracked) |
| `generated_knowledge` | `ai_data/knowledge/` SHA-256 content store + `index.json` |
| `agent_reports` | `agent-reports/` task/review reports |
| `runtime_artifacts` | runtime output/locks/temp files and runtime-dir markers |
| `ignored_artifacts` | ignored vendor/env/IDE/cache paths |
| `deleted_files` | tracked paths missing from the working tree |
| `unknown_changes` | anything not covered above |

Deterministic summary:

- `state`: `clean` when there are zero changes, else `dirty`.
- `risk`: `none` (clean) / `high` (source or deleted) / `medium` (unknown
  changes) / `low` (only reports, knowledge, runtime or ignored artifacts).
- `counts`: true per-category totals; each listed category is capped at
  `DISPLAY_LIMIT = 60` with `truncated_categories` recorded, so the payload is
  always bounded.

Example shape:

```json
{
  "summary": {"state": "dirty", "risk": "low",
              "counts": {"generated_knowledge": 1, "agent_reports": 2}},
  "categories": {
    "source_changes": [],
    "generated_knowledge": ["ai_data/knowledge/index.json"],
    "agent_reports": ["agent-reports/a.md", "agent-reports/b.md"],
    "runtime_artifacts": [],
    "ignored_artifacts": [],
    "deleted_files": [],
    "unknown_changes": []
  }
}
```

## Files changed

New:

- `backend/repository_intelligence.py`
- `tests/test_repository_intelligence.py`
- `agent-reports/repository-state-intelligence-v1.md` (this report)

Modified:

- `backend/routers/command_center.py` — imports the module, adds the
  `repository` payload slice, adds `GET /api/command/repository` and updates
  the module docstring.
- `web/templates/command_center.html` — adds the "Repository Intelligence"
  section (state / risk / branch / counts + categorized change lists).
- `web/static/css/custom.css` — additive `.cc-repo-*` styles.

Unchanged: `backend/command_intelligence.py`, `backend/agent_operations.py`,
`backend/operations_status.py`, `backend/watchlist_data.py`,
`backend/system_stats.py`, `api.py`. No `ai/`, `ns/`, `crawl/`, `database/`,
Nuclei/CVE or schema file was modified.

## Verification

Tests (project convention is `unittest`; `pytest` is not installed):

```bash
python3 -m unittest tests.test_repository_intelligence
# -> 16 tests, OK

python3 -m unittest tests.test_command_center tests.test_command_center_intelligence tests.test_command_center_operations
# -> 44 tests, OK

python3 -m unittest tests.test_ui_redesign tests.test_dashboard_logic tests.test_routers_fixes
# -> 51 tests, OK

python3 -m unittest tests.test_research_api
# -> 29 tests, OK

python3 -m unittest ai.test_knowledge_store ai.test_xss_researcher ai.test_xss_llm_researcher ai.test_openrouter
# -> 96 tests, OK
```

`tests.test_repository_intelligence` covers exactly the requested cases:
generated knowledge detection, agent report detection, source code
modification detection, unknown file detection, plus deleted files,
runtime/ignored markers, deterministic summary/risk, Git index v2 parsing and
v4 rejection, and the Command Center routes/panel.

Compile and real-data check (read-only):

```bash
python3 -m py_compile backend/repository_intelligence.py \
  backend/routers/command_center.py tests/test_repository_intelligence.py

# real render against the production watchlist dir (read-only)
# TestClient(api.app).get("/ui/command")               -> HTTP 200
#   contains "Repository Intelligence", "Repository state",
#            "Source changes", "Generated knowledge",
#            "Agent reports pending", "Runtime artifacts"
#   forbidden words absent
# TestClient(api.app).get("/api/command/repository")   -> HTTP 200
#   branch agent/daily-development, index_available True,
#   correctly detected the current uncommitted work as source_changes
#   (repository_intelligence.py, command_center.py, tests, template, css)
#   and runtime markers (logs/, programs/).
```

Whitespace/EOF hygiene was checked with a read-only Python scan over all
changed files (no git command used), since the task forbids git commands and
therefore `git diff --check` could not be run.

The module was also exercised against the real worktree index
(1439 entries, index v2) and returned in ~0.06 s with no git invocation.

## Notes / limitations

- Detection is stat-cache based and confirmed by content hash for same-size
  candidates, bounded by a 64 MB hash budget; beyond the budget a candidate is
  reported modified from stat data alone.
- Sanctioned subdirectories (e.g. `ai_data/research/`, `logs/`, `programs/`)
  are pruned from the walk and reported as single markers rather than
  enumerating their (potentially large) contents. Tracked files inside pruned
  trees are still checked via the index.
- `pytest` is not installed in this environment; `unittest` (the repository
  convention per `AGENTS.md`) was used. The tests are standard `unittest` and
  run under `pytest` unchanged if it is installed.

## READY TO PUSH

READY TO PUSH: YES

The implementation is complete, all related and regression tests pass, the
change is read-only and production-safe, and no blocker remains. Per the task
instructions no commit was created; the operator should commit and push
manually.
