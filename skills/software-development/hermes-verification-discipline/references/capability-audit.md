# Read-only capability / data-inventory audit

Procedure for auditing what a system *actually has and runs*, as opposed to what
its code implies. Assumes a SQLite production DB you may open `mode=ro`.

## Order of work

1. **Read the canonical architecture first.** It tells you the intended topology,
   so a discovered absence is a finding rather than a misunderstanding.
2. **Enumerate namespaces before counting anything.** Names collide across
   subsystems. List every place the noun can live, label each, and only then
   produce counts.
3. **Execute the code path against production.** Reading a query proves the
   query text exists. Calling the function proves the table exists.
4. **Measure effectiveness from production rows**, not from the module that
   would consume them. Check whether the linking column even exists.
5. **Rank gaps against current data.** A gap is only worth naming if the evidence
   to close it already exists in the system.
6. **Score the report against the brief's literal field list** before writing the
   verdict.

## Read-only discipline

```python
con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
con.execute("PRAGMA query_only=ON")
```

`query_only` is belt-and-braces: `mode=ro` rejects writes at the connection
level, `query_only` rejects them at the statement level. Use both in an audit
whose whole value proposition is that it changed nothing. Re-check
`PRAGMA quick_check` and the table count at the end as proof.

## Distinguishing live from theoretical

| question | command that answers it |
|---|---|
| does the table exist? | `SELECT name FROM sqlite_master WHERE type='table'` |
| does the function work here? | call it with a production connection, record the exception |
| does the guard disable it? | evaluate the guard in production and report the disabled branch |
| is it ever populated? | `COUNT(*)` on the rows it would write |
| is it attributed in output? | `PRAGMA table_info` — is there a linking column at all |

A chain is live per-hop. Report the exact hop where it ends.

## Writing counts that will not be disputed

- Read every table name and row count in one pass and emit them all, so a reader
  can see the whole shape rather than only the interesting numbers.
- Take column names from `PRAGMA table_info`, never from memory. Guessed names
  fail loudly (`no such column`) or, worse, silently fingerprint the wrong
  thing when the guess happens to exist.
- State the timestamp basis: counts from a live DB under active writers drift.

## Absence is a finding, not a failure of the audit

Report `0` plainly, name the missing schema, and say what the consequence is
(`the call raises OperationalError`, `the guard passes None`). Do not create
instances to make the audit look productive, and do not propose implementation —
an audit that ends in a patch is a milestone wearing an audit's clothes.

## Verdict discipline

- `PASS` describes the audit, not the subject. An audit can pass while
  documenting that a whole subsystem is dead.
- List the searches that failed to substantiate a brief's premise, and report
  `UNKNOWN` rather than inferring.
- State limits as their own section, including anything that could not be
  verified and anything whose classification came from reading code rather than
  tracing a runtime path.
