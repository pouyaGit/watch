# Verdict write mechanics — Watch `Finding` (MongoEngine)

Details that cost re-runs when triaging `/opt/watch` findings.

## Writing a verdict

- Unknown fields are **rejected**: `Finding.objects(...).update(set__note="…")`
  raises `LookUpError: Cannot resolve field "note"`. The model's fields are
  `program_name, scope, target, source, name, severity, matched, extra, first_seen,
  last_seen, status`.
- Put the reasoning into the existing `extra` dict and save per document:

```python
for f in Finding.objects(source="takeover", status="open"):
    ex = f.extra if isinstance(f.extra, dict) else {}
    ex["verified"] = "asuid TXT present — binding still owned; not claimable"
    f.extra, f.status = ex, "false_positive"
    f.save()
```

- `status`: `open | triaged | false_positive | fixed`. Mark, never delete.

## The collection moves under you

Two things change the row set while you are still working:

1. **The nuclei lane keeps running.** `upsert_finding()` writes `status` only under
   `$setOnInsert`, so a host scanned *after* your pass finished lands as a fresh
   `status="open"` row. Re-query `status="open"` immediately before writing
   coverage numbers; a list taken at the start will be stale.
2. **The operator prunes noisy info rows on purpose.** Don't reconstruct them and
   don't report the absence as a pipeline fault — rebuild what you need from
   `Urls` / `Endpoints` instead:

```python
q = {"params__in": sorted(wordlist_names)}
for u in Urls.objects(**q).only("program_name", "url", "path", "params"):
    ...  # dedupe on (program, netloc+path, tuple(params))
```

That rebuild is also the honest way to keep an analysis reproducible after the
findings table has changed.

## Scope check before any request

`/opt/watch/programs/<prog>.json` holds `scopes` and `ooscopes`; a host must match
`scopes` and match **none** of `ooscopes`. The ooscopes are real excluded subdomains
(e.g. a partner portal, internal consoles) — not decorative.
