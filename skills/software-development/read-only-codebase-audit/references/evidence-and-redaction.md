# Evidence and redaction recipes

Concrete commands for the read-only audit workflow. All are non-mutating.

## Map the tree first

```bash
find . -path ./.git -prune -o -type f -print | sort
```

Note which top-level layers exist (`lib/`, `scripts/`, `bin/`, config dirs,
`systemd/`, `state/`). A missing config or `.env` is itself an answer.

## Exhaustive capability grep

One case-insensitive alternation covering every plausible spelling and vendor
name, sweeping ALL file types (not just source). Vendor keyword lists are
examples — substitute the capability and its known providers.

```bash
grep -rIniE "deepseek|openai|anthropic|groq|openrouter|litellm|ollama|chat/completions|gpt-|claude|gemini|llm|inference|prompt" . \
  --exclude-dir=.git
```

For a source-only pass with file counts, to see which modules are even in play:

```bash
grep -rIl "<kw1>|<kw2>" --include="*.py" . | grep -v venv
```

Then classify every hit by file role. Typical false positives:

- asset/subdomain lists and the log lines that admitted them
- fixture and eval directories
- docstrings that merely use the word ("no payloads, no `prompt`")
- the words `usage:` in CLI help text and `Token-bucket` in a rate limiter

## Dependency boundary per tree

Which packages does the tree actually import (stdlib vs third-party)?

```bash
grep -rhn "^import \|^from \|^    import \|^        import " --include="*.py" lib/ scripts/ bin/ \
  | sed -E 's/^[0-9]+://' | sed -E 's/^[[:space:]]+//' | sort -u
```

If everything resolves to stdlib plus the tree's own modules, the project is
stdlib-only — a first-class finding that constrains future work.

Package versions without a working `pip list` (read the directory names):

```bash
cd <venv>/lib/python3.*/site-packages && ls -d openai-* httpx-* requests-* anthropic-* 2>/dev/null
```

## Attribute dirty files with mtimes

`git status --short` shows tree state, not authorship. On a host with a running
service, runtime state writes dominate.

```bash
cd <repo>
git status --short
git diff --stat
stat -c '%y  %n' <each modified path>
date '+%Y-%m-%d %H:%M:%S'          # compare against session start
systemctl --user is-active <unit>  # is something still writing?
```

Report form: list each dirty path with its mtime relative to session start, and
state whether a running process accounts for it. Separate pre-existing
uncommitted source edits (visible in `git diff --stat` on a source file) from
runtime churn (locks, logs, JSONL evidence, heartbeats).

Take the reading twice — before inspecting and again before reporting — and diff
`HEAD` too:

```bash
git log --oneline -5 --date=iso --pretty="%h %ad %s"
git reflog --date=iso -8
```

A `HEAD` that moved between the two readings means a concurrent writer committed,
reverted, or added files during your session. Attribute it by commit time against
your own window, state that you did not author it, and timestamp the evidence.

## Configuration inventory without leaking values

Env file — print names only, every value replaced:

```bash
sed -E 's/=.*/=<REDACTED>/' /path/to/.env
```

Use in the report as: `<VAR_NAME>` — **PRESENT — VALUE REDACTED**, or omit
entirely if irrelevant to the audit.

YAML — redact by key name before display:

```bash
sed -E 's/(key|token|secret|password)[: ]+.*/\1: <REDACTED>/I' config.yaml
```

Never echo a key, token, or password even when a page or log shows one, and
never ask the user to paste one.

## Locating where a capability actually lives

When the premise points at one tree but the integration is elsewhere:

```bash
which <tool>
file $(which <tool>)
head -20 $(which <tool>)          # wrapper scripts reveal the real interpreter
                                 # and package root
```

Follow wrapper → interpreter → package directory, then audit inside that root.
Also check the tool's own config/state dir for provider settings, and look for
the coupling between trees — commonly a `subprocess` call to a CLI (transport),
not a library import (inference).

## Read live runtime state without mutating it

Source shows what the code *can* emit; the live store shows what it *did*. Query
the running database read-only — no lock, no write, no backup:

```bash
python3 - <<'EOF'
import sqlite3
c = sqlite3.connect("file:/abs/path/state.db?mode=ro", uri=True)   # uri=True required
c.row_factory = sqlite3.Row

def q(sql, a=()):
    try:                   return [dict(r) for r in c.execute(sql, a).fetchall()]
    except Exception as e: return [{"ERR": str(e)}]                # missing table = finding

print(q("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"))
print(q("PRAGMA integrity_check"))
EOF
```

Read the schema (`PRAGMA table_info(<t>)`) before naming columns; `PRAGMA
journal_mode`, `page_size` and the file size tell you what a second writer would
contend with.

**Separate code-defined from actually-emitted.** For each category the user asks
about, put the live row count next to the code that produces it, and name the
unreachable producer branches (labels defined but never assigned, emitting
functions never called). "The code can emit N types; the store holds M of them"
is itself the finding.

**Sample rows, don't only count them.** Two or three real records often carry
the argument: a data-flow chain that attributes library internals to target
input, a detection whose own evidence string is an artefact of matching inside a
minified bundle. Quote the row, then say why it weakens or strengthens the case —
redacting secrets exactly as the config section describes.
