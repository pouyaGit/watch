---
name: read-only-codebase-audit
description: "Read-only audit or design step: map what exists first."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [audit, read-only, codebase, capability-map, integration]
    related_skills: [autonomous-recon-agent, codebase-inspection]
---

# Read-only Codebase Audit

For asks shaped like "audit how <capability> is integrated", "map the current
implementation before we add <layer>", "inspect the repo and tell me what
exists" — normally carrying an explicit do-not-modify / do-not-install /
do-not-restart constraint.

The same skill governs the *design* step that usually follows such an audit
("design the smallest safe architecture that can eventually use <capability>")
under the identical prohibitions. Read `references/evidence-and-redaction.md`
before the first command.

**The deliverable is a verified map of what exists — and, in a design step, a
contract that cites that map.** Absence of the capability is a valid finding and
frequently the correct one.

## When to Use

- A capability audit before a planned integration (router, budget layer, cache,
  provider fallback, status surface)
- "What is currently implemented?" questions where a wrong answer becomes the
  foundation of later work
- Any inspection request that forbids modifying the system under audit

## Non-negotiables

- Do not write files, install packages, restart services, or edit units — not
  even to "verify" a fix. Inspection is enough.
- Do not call the external service under audit. Reading a config that names a
  provider is not the same as invoking it.
- Every claim in the report carries a `path:line` from this session's own reads.
  Nothing is described from expectation or from general knowledge of the tool.

## Order of operations

1. **Map the tree before grepping.** Enumerate files first so you know which
   layers exist at all. Whether a config file, `.env`, or a `providers/`-style
   directory is present often answers the question before any search runs.
2. **Establish presence/absence with ONE exhaustive grep across ALL file types** —
   not just `*.py`. Case-insensitive, all plausible vendor spellings, and sweep
   config, logs, and data files as well as source. See
   `references/evidence-and-redaction.md` for the patterns.
3. **Separate code hits from data hits.** The usual false positives are target
   names, log lines, and fixture strings that merely contain the keyword (an
   asset hostname containing the vendor word, and the log line that admitted
   it). Judge by file role and quote `file:line`.
4. **Confirm which tree actually owns the integration.** A stated premise may be
   true of a *different* codebase than the one you were pointed at: a framework
   the tool shells out to, a service it talks to, a globally installed package.
   Resolve the real owner via entrypoint → interpreter → package root, and
   report that path. Two trees with one subprocess coupling between them is a
   common shape — identify the coupling point (often a CLI call for transport,
   not inference).
5. **Establish each dependency per tree, not globally.** Determine whether the
   target imports only stdlib (grep every `import`/`from` line and `sort -u`),
   because that constrains what any future change may use. Note where each
   third-party dep actually belongs when several trees share a host.
6. **Report item-by-item, marking state honestly.** For every requested item use
   one of: confirmed present (`path:line` + snippet), confirmed absent, or
   "absent here / present elsewhere" with the other location. Never leave an
   item blank and never fill it with a plausible description.

## Do not confabulate

A checklist-shaped request ("report the client, the model, the base URL, the
retries, ...") invites inventing an implementation to fill the slots —
especially when the user asserts the capability exists. Resist it:

- **Treat the request's checklist as describing the intended end state, not
  current reality.** These lists are usually written from the plan, so most
  items may legitimately not exist yet. Audit against the code, not the list.
- State plainly that the capability is absent from the named target, and where
  it does live.
- Describe only what you read; never narrate behavior you did not open.
- When the premise conflicts with the code, the code wins — and the conflict is
  itself a reportable finding, not something to smooth over.
- Do not upgrade a finding to satisfy a checklist: "no cost tracking" is false if
  tracking exists in another tree, and "unbounded retries" is false if the SDK
  retries are disabled and a bounded backoff owns them. Mark such items
  "absent here / present elsewhere" and say what you actually found.

## Design steps (audit → contract)

The map still comes first: every statement about existing behaviour the design
builds on carries a `path:line` from this session's own reads.

- **Mark every slot with no producer as unreachable today.** A requested field,
  enum, priority tier, or table is a shape, not evidence that anything emits it.
  Name the values actually reachable now versus those reserved for a future
  producer. A design implying coverage it does not have is the same fabrication
  as a false finding.
- **Name the one behaviour change, or state that there is none.** When a
  recommendation alters existing behaviour (storage mode, schema migration, a new
  writer), isolate it and say explicitly that it is the only one, so the operator
  can gate it separately. A reviewer approves one change, not a diff.
- **Say why each required field is required.** The justification is the
  contract's value; the field list alone is not.
- **Reuse the host's conventions — after auditing them for single-writer
  assumptions.** Mirroring an existing id scheme, status machine, retry/backoff
  list, and locking primitive keeps the design legible, but a `COUNT(*)`-based id
  allocator or a check-then-write path is racy the moment the design adds a
  second process. Adopt the atomic `UPDATE ... WHERE status='<expected>'` plus
  affected-rows check and an `flock`, cite the original as prior art, and say why
  the original does not transfer.
- **Ground resource and cost claims in the tree's own numbers.** Take prices,
  caps, and limits from a dated snapshot inside the audited code, never from
  memory, and compute with a tool. Express headroom in the unit the reader acts
  on (tasks/day, hosts/cycle) and price the bad design at the volume the user
  worries about — that arithmetic is the recommendation's whole argument.
- **End with the operator's decisions.** Close on the two or three choices that
  are theirs (budget ownership, egress destination, the one gated change), not on
  a restatement of your own text.

## Proving the audit changed nothing

`git status --short` alone is NOT proof. On a host running a live service the
tree is routinely dirty from runtime state writes (lock files, logs, evidence
files, heartbeats), so files you never touched appear modified.

Attribute them with timestamps instead of asserting — compare each modified
file's `mtime` against the session start time and check whether a process is
running that accounts for it. Keep two explanations distinct: pre-existing
uncommitted source edits versus runtime state churn. Recipe in
`references/evidence-and-redaction.md`.

When the brief BANS repository commands outright (the common HERMES shape:
"NO Git"), hash instead: before editing anything, record SHA-256 of every file
you must NOT change into a `*_preedit_hashes.json` evidence file, re-hash at
the end and assert equality, and pair it with before/after row-count AND
id-set snapshots of the protected DB tables. Growth on append-only tables is
expected runtime churn (attribute it by timestamp); an id-set SHRINKAGE is a
real deletion and must be explained or reported as a failure. That hash file
is the both-ends reading the `HEAD` comparison would have given you.

**Take the reading at both ends and compare `HEAD`.** Another agent, session, or
the user can commit, revert, or add files while you read. If `HEAD` moved, or a
delta you saw at the start is gone at the end, attribute it via `git log` /
`git reflog` dates, say plainly that you did not author it, and timestamp the
clean-tree evidence — it is valid only as of the moment you took it. Never let a
moved `HEAD` pass as "no changes from this step" unattributed, and never present
someone else's change as your own work.

## Configuration and secrets

Report configuration as **variable names only**. List env var names without
values, and mark each relevant secret `PRESENT — VALUE REDACTED`. Never echo a
key, token, or password, even if a page, log, or config displays one. Redaction
recipes are in `references/evidence-and-redaction.md`.

## Reporting shape

Mirror the section order the user asked for; if none was given, use: current
architecture → the integration under audit → task/call inventory → configuration
→ dependencies → execution flow → existing observability → recommended insertion
point → risks/gaps → change-control status (git + why any dirty files are
accounted for).

Such prompts usually carry TWO structures: a numbered requirement list for the
work and a separate named outline for the final report. Answer the outline, and
put a one-line coverage map at the top (`§n → section letter`) so the reader can
confirm nothing was skipped without re-reading the request. End with the exact
status marker the user asked for, verbatim; any caveats belong above it.

For "recommended insertion point", justify against the system's real invariants:
name which guards sit above the proposed seam (scope, rate, budget, locking) and
why inserting below them cannot violate them. State the latent trap in numbers
when you can — a per-job call inside an N-iteration loop is N ungoverned calls
per run, and that arithmetic is the recommendation's whole argument.

## Pitfalls

- **A generic keyword grep will match unrelated data.** Restrict interpretation
  by file role, and never count a `targets/`, `logs/`, or fixture hit as an
  implementation.
- **Do not assume the named repo holds the integration.** Resolve the entrypoint
  even when the request lists specific paths.
- **Package versions: read `site-packages/*.dist-info` names when `pip list` in a
  venv is unavailable or errors.** The `dist-info` directory name carries the
  version.
- **Distinguish "vendored/installed on this host" from "declared by this
  project".** A globally installed SDK is not a dependency of a stdlib-only tree.
- **When a risk checklist item is genuinely not present, say so explicitly.**
  Listing it as a risk because it was on the list is fabrication.
- **Do not stop at the first tree you were pointed at.** If the premise and the
  code disagree, the search is not finished.
- **Importing the module under audit can WRITE.** An import chain that reaches a
  DB connection, schema/migration bootstrap, cache warmer, or client singleton
  performs its side effect against whatever target is configured — violating the
  do-not-write mandate from the inside while the terminal reports success. Read
  the source instead, or rebind the data path to a throwaway copy BEFORE the
  import; when you must execute logic to measure it, replicate the pure function
  standalone and re-read its data files from disk.
- **A zero-row query is not proof of emptiness until the other key space has
  been tried.** A schema can hold two naming conventions for one entity (a label
  vs a directory key, a display name vs an id), and the wrong one returns an
  empty result rather than an error — so "the pipeline produced nothing" and
  "you filtered on the wrong column value" are indistinguishable in the output.
  Enumerate the distinct values of both candidate key columns, re-run with each,
  and only then report emptiness.

## Reference

- `references/evidence-and-redaction.md` — exhaustive grep patterns, mtime and
  `HEAD` attribution recipes, read-only SQLite/live-state queries, secret-safe
  config inventory commands.
