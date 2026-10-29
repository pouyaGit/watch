# Building a read-only layer over live state

Depth for the "Building a read-only layer" rules in SKILL.md. Applies when a
milestone adds a query module, report page, HTTP API, or UI over the production
SQLite state. The governing hazard: **a large, populated table that renders as
"0 rows, no data" reads as a real finding and is not one.**

## The silent-empty-result class

Several independent bugs in one layer all produced "empty", none of them an empty
table. The shared enabler was a helper that did:

```python
try:
    return [dict(r) for r in conn().execute(sql, args).fetchall()]
except sqlite3.Error as exc:
    _record_error(exc)
    return []          # <- indistinguishable from "no data"
```

Fix shape: count the error, keep the message, let the caller see it.

```python
STATS = {"queries": 0, "errors": 0, "last_error": None}

def _record_error(exc):
    STATS["errors"] += 1
    STATS["last_error"] = str(exc)[:300]
```

Then a test asserts `STATS["errors"] == 0` after exercising every screen. That one
line converts the whole class from invisible to loud.

**A `LIMIT` collision is the same class.** A helper that appends `LIMIT ?` to a
statement whose SQL already ends in its own `LIMIT 10` produces
`near "LIMIT": syntax error` — swallowed, page empty. Guard before appending, or
have every caller own its own limit. Prefer the former so pagination stays in one
place.

## Verify columns before writing SQL

`PRAGMA table_info(<table>)` is cheap and read-only. Run it before the query, not
after the failure. Columns that are routinely not what the domain name implies:

| Table | Looks like | Actually |
|---|---|---|
| `hunt_intelligence` | has `target` | keyed by `subject` — a TOPIC (`cisa_kev`, `xss\|low`, `nvd_api`), never a target name |
| `hunt_decisions` | joins to cases by `case_id` | no `case_id`; keyed by `target`/`host` |
| `evidence_actions` | has `host` | host is on `evidence_items` (which may itself be empty) |
| `hunt_cases` | — | has `target`, but guard for NULL before using it in a join |

A `WHERE <col>=?` returning 0 rows against a table you believe is populated is
evidence of a wrong column, not of absent data. Confirm by pulling a sample row and
reading one real value.

**When a relationship genuinely does not exist, say so rather than inventing a
join.** `hunt_intelligence.subject` is a topic; joining it to a case by target can
never match. The honest rendering is a clearly-labelled global topic feed plus the
case's own persisted structured fields — not a per-case list that is silently always
empty, and not a fabricated association.

## Query shape and wall time

Repeated per-row work over large tables is the second silent failure — it does not
return empty, it returns *late*, and a timeout may be swallowed as empty.

- Per-row correlated `MAX()` over a ~30k-row table → `GROUP BY`, or
  `ROW_NUMBER() OVER (PARTITION BY k ORDER BY ts DESC)`.
- Per-row subquery joining a 44k-row table to a 13k-row table → one pre-aggregated
  subquery `LEFT JOIN`ed once.

Budget: a list page over tens of thousands of rows should answer in well under a
second. A page that takes >1 s is a query-shape problem. Record the measured time
per page in the real-data validation so a regression in shape stays visible.

## Arity contracts

Every route/page function returns one shape. Decide it once, write it down, keep it:

```
(title, body_html, action, active_nav, subtitle, query)   # 6 values
```

A helper that returned 5 while callers expected 6 did not raise — it unpacked so
that `content` became the whole tuple, and every miss rendered a blank page with
HTTP 200. When a page is unexpectedly empty, print `len(result)` and the element
types before touching SQL. Related: the status code must match the content (miss →
404, fault → 500) or a monitor and any future cache read a miss as data.

## Test-probe defects that fake results

These produce false alarms and false passes, and cost more time than the bugs they
were written to find.

- **Shape-blind counting.** `r.get("total")` or `len(r.get("rows") or [])` returns
  0 for a domain dict with different keys. Walk the actual returned value: sum
  list/tuple lengths plus truthy scalars. One run reported 19 false "returned 0 but
  data exists" alarms this way.
- **First-row selection picks fixtures.** `ORDER BY article_id LIMIT 1` returned a
  fixture (`title='T'`, `url=None`) rather than a real article, hiding a genuine
  "no clickable original URL" defect. Select the row that carries real data:
  `WHERE title IS NOT NULL AND COALESCE(NULLIF(canonical_url,''), url) IS NOT NULL`.
- **Stale/reused probe locals.** A probe referencing `c["target"]` after `c` was
  reassigned raises `KeyError` that looks like a UI bug. Use distinct per-probe
  names and pass explicit arguments.
- **Shared error counters.** A check reading a module-global error counter reports an
  *earlier* probe's failure as its own. Reset the counter immediately before
  exercising, then assert.
- **Greps that match prose.** `assert "llm_call" not in src` fires on a *column
  name* the UI legitimately displays (`research_runs.llm_calls`) and on docstrings
  that state the prohibition. Match call forms (`llm_call(`, `llm.invoke(`) and
  scope to non-comment lines, or use the AST.

## When the audit's best deliverable is NO code change

A read-only audit often ends with a root cause identified and a fix deliberately
NOT applied, because the brief's scope forbids touching the component that would
have to change. That is a legitimate result, not a failed milestone — and it must
not drift into a half-applied fix.

- The audit IS the artifact. Quantify the defect against production data — rows
  affected, the per-record values, the resolution path each record entered — so the
  finding stands with no code change behind it.
- Prove non-interference after declining the fix: call the unchanged function on
  the real input and show it still behaves as before. An audit that cannot show it
  changed nothing has not shown its scope held.
- Separate measured results from the recommendation. Put the proposed change in its
  own report section with rationale and blast radius, state plainly that it is not
  implemented and needs its own gate, and never let it sit in the same section as
  measured values where it reads as already done.
- When the fix would change what a downstream consumer sees, name the new view
  explicitly (e.g. rows moving from a verdict that is right for the wrong reason to
  an honest unknown). Value the correction by its accuracy, not by how many rows it
  newly admits — the second number is a warning sign, not a win.
- The `PRODUCTION_MUTATION: 0` / `SCHEMA_CHANGES: 0` fields still need the full
  controlled-window evidence even when you changed nothing; an audit that skips it
  because "there was nothing to change" is unverified.

## Proving read-only

Three independent lines of evidence, strongest last.

1. **Source inspection** — no mutating verb in any code line (skip comments and
   docstrings, which name the verbs in prose).
2. **Connection-level** — the handle the UI actually uses. Open `mode=ro` plus
   `PRAGMA query_only=ON`, then attempt real statements against a real table:
   `INSERT`/`UPDATE`/`DELETE`/`REPLACE`/`CREATE TABLE`/`ALTER TABLE`/`DROP TABLE`.
   All must raise *attempt to write a readonly database*.
3. **Controlled window** — stop the writer (the daemon), exercise every route hard,
   then compare full row counts, schema objects, and per-table checksums.

Distinguish a **refused** write from a **no-op**: `DROP TABLE IF EXISTS <missing>` is
accepted, because nothing exists to drop and nothing is written. That is correct
SQLite behaviour, not a hole. Assert the refusals on statements that would write, and
assert the no-op separately by showing the schema is unchanged afterwards.

A `before`/`after` row-count comparison taken while the daemon is live measures the
daemon, not the change. If that comparison reports drift, redo it under quiescence
rather than explaining the delta away.

## Transport checklist (stdlib `http.server`)

- Default host is loopback; a routable bind is an explicit opt-in argument.
- GET only. Alias every other verb to one `_reject` returning 405 — including
  `TRACE` and `CONNECT`, which `BaseHTTPRequestHandler` dispatches before your
  `do_TRACE` could run, so they answer 501 unless explicitly overridden.
- Status matches content: 200 / 404 / 500.
- Headers: `nosniff`, `no-referrer`, `no-store`, plus a CSP with `default-src 'none'`.
  No `Server` version banner, no framework fingerprint header.
- Never serve a filesystem path from a route parameter. No eval, no subprocess, no
  shell, no SQL passthrough, no URL-fetch proxy (SSRF), no generic RPC.
- Stored URLs are data: a link is rendered only for a stored `http(s)` URL, and the
  click is browser navigation. A row with no stored URL renders a dash and is not
  clickable. Never synthesise a URL from host+path.
- Bind order: the HTML `shell()` must not use `%`-formatting on a template containing
  CSS (`@media (max-width:...)` carries a literal `%`) or the page raises. Use
  placeholder `.replace()`, and coerce optional fields through the escaper before
  substitution — a `None` reaching `.replace()` renders an empty page.

## Pagination

Default 25, maximum 100, enforced in one helper that both clamps and reports the
effective size. Verify by calling with an oversized value and asserting the
*returned* size is `<= 100` — a helper that clamps to the real row count (4 rows)
returns 4, which is correct and must not be reported as a bound violation.

## Whole-file hashing cannot certify "no mutation"

A shared regression battery typically ends with a `before`/`after` snapshot and a
single `INTEGRITY_RC`. When that RC is nonzero, **classify it before reporting
it** — a nonzero integrity code is not by itself evidence of mutation, and
publishing it as one is as false as hiding it.

Distinguish two failure shapes:

| Signal | Reading |
|---|---|
| `sha256` and `mtime_ns` differ; `size`, `tables`, `row_counts_unchanged`, `quick_check`, `integrity_check`, `foreign_key_check` all agree | SQLite checkpointed the WAL and rewrote the file with **identical content**. The byte layout changed; the data did not. |
| Any row count, schema object count, or per-table checksum differs | a real write occurred |

The cause is that whole-file `sha256` is content-blind to rewrite-without-change.
The content-aware measurement is per-table `COUNT(*)` plus a per-table row
checksum, taken under a controlled window with the writer stopped.

Report this as an **artifact of the battery's comparison method**, in its own
named subsection, with the table of agreeing/disagreeing signals — do not
suppress it and do not let it read as UI-caused mutation. A content-aware
battery check is the real fix, but the battery is shared infrastructure; do not
edit it inside a milestone that did not own it. Note it as a limitation instead.

## Accessibility is structural, not per-call-site

A responsive design that hides `thead` at narrow widths **destroys the column
header for every stacked card** unless each cell carries its own label. The
mechanism: the card view relies on the cell to name itself, and a bare `<td>`
has nothing to fall back on.

Emit the label inside the shared table helper so no call site can forget:

```python
labels = [str(x) for x in headers]
cells.append('<td data-label="%s">%s</td>' % (esc(labels[i]), content))
```

The same helper should guarantee the other structural properties, because they
are cheap to add centrally and easy to omit across ~30 call sites:

- `<caption>` derived from the column headers when no explicit name is passed —
  a table with neither `<caption>` nor `aria-label` is announced as an unnamed grid.
- `scope="col"` on every `<th>`.
- `aria-current="page"` on the active nav item (both the rail and the mobile bar).
- A skip-to-content link as the first focusable element, visually hidden until
  focused (`position:absolute;left:-9999px` + `:focus{left:8px}`), with
  `id="main"` and `tabindex="-1"` on `<main>`.
- `aria-hidden="true"` on decorative glyph spans so emoji are not read as content.

Verify these against the **rendered HTML of the real pages**, not by grepping
for class names you expect. A check that asserts `.bottom-nav` exists fails
against a correct implementation that uses a collapsing rail; a check that
asserts `overflow-x:auto` fails against a *stronger* implementation that stacks
cards so scrolling is never needed. Read the actual CSS first, then assert the
property it implements.

## Never let a false failure stand, and never manufacture one to fix it

Verification suites drift in both directions, and both errors corrupt the gate.

- **False failure** — a check guessing an identifier the implementation never
  used. Symptom: several failures in one group that all point at naming.
  Response: read the real source, then assert the property it actually
  implements. A check must fail for a real defect, not for a renamed class.
- **False pass** — a check that passes for the wrong reason. The classic is a
  write-refusal assertion whose statement has a bad column name: SQLite raises
  during *preparation*, before the read-only guard is ever consulted, so the
  test "proves" refusal that never happened. When a check passes, confirm the
  error it observed is the error it meant to provoke (`attempt to write a
  readonly database`, not `no such column`).
- **Assert against the source of truth, not a hand-written guess.** If the nav
  destinations are defined in a `NAV` tuple, assert every `href` in that tuple
  appears — not a list of paths reconstructed from memory. A guessed path that
  is not a real route returns 404 and fails three downstream checks at once.
- **Fixture selection hides real defects** — see the shape-blind and
  first-row rules above; the same applies to a11y probes that fetch a
  non-existent route and then blame the heading structure.

## Test-group layout that maps to a brief

Group the suite by the brief's own numbered requirement groups, and keep a distinct
group for API security (injection, traversal, file read, command execution, SSRF,
write methods, header hygiene, secrets, bind scope, immutability). Route tests and
focused/unit tests are separate files; each prints a per-group pass/fail list and a
final `X passed, Y failed`, exiting nonzero on any failure.

## Real-data validation against a spec's quoted figures

When a design spec quotes production counts, the validation compares live against
quoted and shows BOTH — never hardcodes the spec number into the UI, never silently
reconciles a mismatch.

- Expect drift on anything time-varying: url/case/outcome counts grow between the
  spec and the build. Report live as authoritative, note the delta.
- Expect a genuine regression on anything curated: if the spec says N patterns and
  the table now holds fewer, that is a finding, not noise — report it plainly.
- When a query unions a second source, the table count and the query count differ and
  BOTH are real. Print both with the reason; do not pick one.
- Screen for legitimately-empty domains and whitelist them by name (0 skills because
  the factory has never run; 0 human-confirmed; hunters with no live invocations), so
  a real empty is not re-flagged on every run.
