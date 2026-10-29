# Defining "fresh" and reading a recon store

Depth for the collector step: what a recon store holds, how to bound the window, and the traps that
turn a query into a confident zero.

## Shape of a recon data store

Observed collections in one MongoDB-backed recon store, as a template for what to expect:

```
subdomains        subdomain · providers[] · scope · program_name
live_subdomains   subdomain · ips[] · cdn · scope · program_name
http              url · final_url · status_code · title · tech[] · headers · ips[] · favicon
endpoints         path · params[] · param_records[] · example_url · hit_count · subdomain
                  · x8_checked · created_date
urls              url · path · params[] · sources[] · subdomain · program_name
change_event      event_type · subdomain · old_value · new_value · created_date
finding           name · severity · matched · target · source · status · first_seen · last_seen
```

Read the real field names with a one-document probe (`find_one()` and print `sorted(keys)`) before
writing any query. Derive the program/scope list from the store's own program collection plus the
scope file; a `scope` field on the endpoint rows may be effectively empty and is not the authority.

## Bounding the window

State the window from the previous run's recorded completion time, not from a fixed lookback:

- Persist `last_run` after each successful pass and read it at the start of the next.
- Apply a **floor** (e.g. 7 days) so a long outage does not resurrect history as if it were new.
- Provide a `--hours` override plus a `--force-hours` flag, so a manual run is reproducible and a
  scheduled run keeps its continuity. Without the override you cannot re-measure yesterday's window.
- Record `window_start` and `window_end` inside the output artifact, not only in the log: a reader
  must be able to tell which window a shortlist describes.

## The traps that produce a confident zero

- **A date stored as a STRING makes a range query return 0 silently.**
  `{"created_date": {"$gte": "2026-09-01"}}` compares inside BSON type order and matches nothing,
  while `{"created_date": {"$gte": <datetime>}}` matches the whole population. The failure is
  invisible: the query succeeds, the count is 0, and "no new records" looks like a finding. Probe
  one document, print `repr()` of the field, and pass the value with the type the data actually has.
  Measured: the same filter returned **0** with a string cutoff and **461** with a datetime cutoff.
- **A collection's document count is often a rolling window, not a property of the collection.**
  The same count read 252,677 and then 200,026 hours apart, spanning 27 distinct days with thin
  edges and a heavy middle. Quote a corpus count with the time it was taken or not at all.
- **A change/event collection keyed by an event type is not a freshness filter.** Measure the
  distribution first: one event type accounted for a large majority of all rows, so "new event" was
  true of nearly everything and separated nothing. Use the record's own creation timestamp.
- **"New" is not cheap.** A 24h window can hold tens of thousands of endpoints and hundreds of
  thousands of URLs. The collector's job is to shortlist, never to enumerate; the probe step must
  operate on the capped shortlist.

## Collector design

One script, no probing, invoked with the project's own interpreter (the store client is a project
dependency, so a bare `python3` will not have it):

1. Resolve the window (previous run, or the override, floored).
2. Pull each fresh class with a cap: new live subdomains, new endpoints, new parameters, changed
   title / status / technology, hosts answering for the first time.
3. Rank the endpoint class and keep the top N. Drop nothing silently - carry a count of the rows a
   noise filter removed.
4. Write one JSON artifact with the window, every class, and a `counts` block; print a compact brief.
5. Persist `last_run` and the artifact path.

Ranking that works, in order of how much it discriminates:

- parameters whose NAME names a destination, a file or a command (`url`, `redirect`, `next`,
  `return`, `goto`, `dest`, `target`, `callback`, `file`, `path`, `template`, `proxy`, `fetch`,
  `cmd`, `exec`) - these are the ones that carry SSRF, open redirect and traversal;
- membership of a curated interesting-name set, counted as a set intersection;
- path SEGMENTS equal to a structural token (`api`, `admin`, `graphql`, `oauth`, `upload`) -
  compared as whole segments, never as substrings of the path;
- a small bonus for endpoints no prior pass has touched.

Every cap and every filter belongs in the artifact's `counts` block, so a later reader can tell a
narrow window from a quiet one.
