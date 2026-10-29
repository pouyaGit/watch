# Finding data contract (canonical representation + milestone-stage edits)

Rules for extending the persisted finding model of a recon tree that stores two
finding tables (`findings` for analyzer findings, `xss_candidates` for JS flows).
Applies to any stage that adds fields: classification, evidence, correlation,
vulnerability context.

## 1. Reuse a column, never add an alias

Resolve every requested canonical name against what already exists before adding
anything; the same concept is often spelled differently per table.

| canonical field | `findings` | `xss_candidates` |
|---|---|---|
| source / sink | `source`, `sink` | `source`, `sink` |
| source_to_sink_chain | `source_to_sink_chain` | `data_flow` |
| sanitization / transform | `sanitization` | `sanitization` |
| js_file / js_line | `js_file`, `js_line` | `js_file`, `line` |
| evidence excerpt | `evidence_excerpt` (fallback: head of `evidence`) | same |
| evidence ref | `evidence_ref` | `evidence_ref` |
| correlation | `correlation_id` | `correlation_id` |

`canonical_view()` does the per-table aliasing (`data_flow` -> chain, `line` ->
`js_line`). Before adding a column, grep the whole tree for the concept's other
spellings — a second column for one concept is the failure this table prevents.

## 2. Absent means NULL, never a default

Optional fields stay `NULL`/`None` when the analysis produced nothing. Do not
backfill a placeholder severity, confidence, classification or reason to make a
field look populated, and never migrate old rows into invented classifications.
Derive only from what was actually observed:

- excerpt: bounded head of the real evidence text (~400 chars) — no JS dumps.
- chain: `SOURCE -> SINK`, or `SOURCE -> TRANSFORM -> SINK` when a transform was
  actually recorded; return `None` when source or sink is missing ("chain
  unavailable" must be stated, not fabricated). A transform string meaning
  "not identified"/"unknown" collapses to the two-node form.

## 3. Persistence pattern

- Keep the entry point backward compatible: `add_finding(..., **extra)` with the
  optional names whitelisted in a module-level tuple, inserted dynamically;
  unknown kwargs are dropped silently. Existing call sites keep working unchanged.
- Drop `None` and `''` when collecting optionals, or an omitted field overwrites
  a stored value.
- On the UPDATE path use `COALESCE(?, col)` so re-observing a finding never blanks
  a value already persisted.
- Keep the dedup fingerprint inputs unchanged; adding fields must not change
  finding identity.
- Field discovery for a table's real shape: `PRAGMA table_info(<table>)` via the
  `sqlite3` module in `python3 -c` (the CLI is often absent) — reading the `SCHEMA`
  string alone misses columns added by migrations.

## 4. Migration pattern

`store.conn()` runs `CREATE TABLE IF NOT EXISTS` from the module `SCHEMA` string and
then a per-table `ALTER TABLE ... ADD COLUMN` loop guarded by `PRAGMA table_info`.
Every new column belongs in BOTH places — the `SCHEMA` string for fresh databases
and the migration tuple for existing ones. Existing rows stay untouched.

## 5. Classification stays where it is computed

Exposing a classification is not recalibrating it. The deterministic gate and the
`apply_classification()` writer (which also appends an audit row) remain the only
producers of severity/confidence/classification/`downgraded_from`; the canonical
layer only reads them. Verify consistency as analysis == persisted row ==
canonical view rather than re-deriving a verdict in the view.

## 6. Version / CVE context from a local KB only

A version-correlation candidate is a CANDIDATE. `affected_range` comes from the KB
entry's upper bound (`"< " + entry.lt`) and `cve_context` from its note plus the
standing "exploitability NOT established" qualifier; no exact product/CVE entry
means `(None, None)`. Never add an external CVE feed in a persistence stage, never
convert a version match into a confirmed vulnerability.

## 7. Correlation / dedup context is read-only

- Build a `member_id -> [groups]` index from the correlation groups table in ONE
  query. A member can belong to several stored groups; a dict keyed by member keeps
  only the last one and silently misreports the strongest relationship.
- Map dedup state from the stored group `kind` only: duplicate -> `DUPLICATE`,
  related -> `RELATED`, root-cause group -> `ROOT_CAUSE_GROUP`, no group ->
  `INDEPENDENT`. When one member sits in several groups, pick a primary by
  strength (DUPLICATE > ROOT_CAUSE > RELATED) for the label — ordering only, never
  a new category.
- The group writer stamps exactly ONE correlation id onto the row. The canonical
  `correlation_group` must mirror that stored id (a different "primary" makes the
  view contradict its own row); report the full membership in a separate
  `group_ids` field.
- `root_cause` is the root-cause group's stored detail; `duplicate_of` a real
  duplicate-group peer; `related_findings` the union of actual peers. No stored
  relationship means `None` — never synthesise one.
- Accept a preloaded index as an optional parameter on the view functions so a
  batch of rows costs one query, keeping the default call signature compatible.

## 8. Anchor-guarded bulk edits (quote-heavy source)

Single find/replace tool calls fail on Python source carrying escaped quotes:
the escaping survives into the pattern, the match misses, and the result is a
"patch FAILED / escape-drift" report rather than a silent no-op. For any multi-site
edit of a quote-heavy module:

1. Write a one-shot script (`scripts/_<stage>_fix.py`, deleted after use) that
   reads the RAW file text (`open(path).read()` — never line-numbered output).
2. List `(label, old, new)` triples in one `EDITS` list.
3. First pass: `src.count(old)` for EVERY triple; require exactly `1`. Report all
   offenders and exit WITHOUT writing if any anchor fails — never partially apply.
4. Second pass: apply all replacements, write the file, and print the count applied.
5. Immediately `python3 -c "import ast; ast.parse(open(p).read())"` and grep the
   changed lines back out of the file to confirm what actually landed.
6. Delete the helper script once the tests pass.

Watch for ambiguous anchors: a short fragment such as a bare `("sink", "TEXT")`
can appear in both a schema string and a migration list, so anchor on the
surrounding unique lines instead of the one-liner.

## 9. Focused-test shape per stage

`scripts/test_m<N>_<topic>.py` that sets `HERMES_DB` to a `tempfile` path BEFORE
importing the store module, then covers: full-field save/reload round trip;
a minimal legacy row still loading; absent optionals not crashing; the analysis
verdict == persisted row == canonical view; no fabricated relationship for an
independent row. Build correlation fixtures by running the REAL correlator against
the throwaway database rather than hand-inserting groups. Print one PASS/FAIL line
per check plus a final `N passed, M failed` and exit non-zero on any failure, so the
stage report can quote exact results.

## 10. Report and safety accounting

Record production row counts (`findings`, `xss_candidates`, correlation groups,
linked members) before and after the work and assert equality — read-only
verification on real rows only, never mutating a real finding into a test fixture.
Confirm the daemon is still running and the finding store still readable at the end;
do not restart it just to pick up library changes during a read/verify stage.
