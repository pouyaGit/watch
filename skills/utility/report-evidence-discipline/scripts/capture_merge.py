#!/usr/bin/env python3
"""Merge evidence captures instead of overwriting them.

A hunt writes its measurements to a JSON capture.  Hours later the
script is re-run, the endpoint is rate limited, and the new file has
fewer rows than the old one - while the report still cites the bigger
table.

This is the reusable form of the rule:

  * merge by case key, never truncate
  * a rate limit (or any "the request never got there" status) means
    NOT MEASURED, so it must not replace a previously measured result
  * a case the new run did not touch keeps its previous result
  * a case the new run actually measured replaces it

Use it from a writer script:

    from capture_merge import write_capture

    rows = [...]                                  # this run's measurements
    write_capture("/root/hunt/evidence.json", rows, key="label")

``write_capture`` loads the file already on disk, merges, and writes the
union.  It never truncates.

Self-test (offline, no network, no target traffic):

    python3 capture_merge.py --self-test
"""

import json
import os
import sys

# Statuses that mean the request never reached the layer under test.
# A record with one of these was NOT measured.
NOT_MEASURED = (429, 503, 0, None)


def is_measured(rec, status_key="status"):
    """True when the record represents a request that actually ran.

    A rate limit, a service-unavailable and a transport failure all
    mean "not measured", so they must never overwrite a result that was
    measured.  A record with no status field at all is trusted.
    """
    if not isinstance(rec, dict):
        return False
    if status_key not in rec:
        return True
    return rec.get(status_key) not in NOT_MEASURED


def merge_captures(prev, new, key="label", status_key="status"):
    """Return the union of ``prev`` and ``new``, keyed by ``key``.

    A case in ``new`` replaces the previous one only when it was
    actually measured; an unmeasured (rate limited) result is dropped
    and the previous result for that case is kept.
    """
    merged = {}
    order = []
    for rec in prev or []:
        if not isinstance(rec, dict) or key not in rec:
            continue
        if rec[key] not in merged:
            order.append(rec[key])
        merged[rec[key]] = rec
    for rec in new or []:
        if not isinstance(rec, dict) or key not in rec:
            continue
        k = rec[key]
        if k not in merged:
            order.append(k)
        if not is_measured(rec, status_key):
            continue
        merged[k] = rec
    return [merged[k] for k in order]


def load_rows(path):
    """Load the rows of a capture, whether it is a list or a wrapper."""
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (ValueError, OSError):
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return data["results"]
        for value in data.values():
            if isinstance(value, list):
                return value
    return []


def write_capture(path, rows, key="label", status_key="status"):
    """Merge ``rows`` into the capture at ``path`` and write the union."""
    merged = merge_captures(load_rows(path), rows, key, status_key)
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(merged, fh, indent=1)
    os.replace(tmp, path)
    return merged


def self_test():
    """Four scenarios, offline.  No network, no target traffic."""
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))

    prev = [
        {"label": "a", "status": 200, "value": "old-a"},
        {"label": "b", "status": 200, "value": "old-b"},
        {"label": "c", "status": 200, "value": "old-c"},
    ]

    # 1. a re-run that measured nothing
    new = [dict(r, status=429) for r in prev]
    out = merge_captures(prev, new)
    check("a re-run that measured nothing keeps every case",
          len(out) == 3, "got %d" % len(out))
    check("a re-run that measured nothing keeps every value",
          all(str(r.get("value", "")).startswith("old") for r in out))

    # 2. a partial re-run
    new = [{"label": "a", "status": 200, "value": "new-a"},
           {"label": "b", "status": 429, "value": "new-b"}]
    out = merge_captures(prev, new)
    by = {r["label"]: r for r in out}
    check("a partial re-run keeps every case", len(out) == 3, "got %d" % len(out))
    check("a measured case is updated", by["a"]["value"] == "new-a")
    check("a rate limited case keeps its previous value",
          by["b"]["value"] == "old-b", by["b"]["value"])

    # 3. a brand new case
    new = [{"label": "d", "status": 200, "value": "new-d"}]
    out = merge_captures(prev, new)
    check("a new case is added", len(out) == 4, "got %d" % len(out))
    check("the new case is present",
          any(r["label"] == "d" for r in out))

    # 4. a fresh measurement with a different result
    new = [{"label": "a", "status": 200, "value": "fresh-a"}]
    out = merge_captures(prev, new)
    by = {r["label"]: r for r in out}
    check("a fresh measurement replaces the previous one",
          by["a"]["value"] == "fresh-a", by["a"]["value"])
    check("untouched cases survive a fresh measurement",
          by["b"]["value"] == "old-b" and by["c"]["value"] == "old-c")

    # 5. the file level writer
    path = "/tmp/capture_merge_selftest.json"
    if os.path.exists(path):
        os.remove(path)
    write_capture(path, prev)
    check("the writer creates the capture", os.path.exists(path))
    write_capture(path, [{"label": "a", "status": 429, "value": "x"}])
    rows = load_rows(path)
    by = {r["label"]: r for r in rows}
    check("the writer does not truncate on a rate limited re-run",
          len(rows) == 3, "got %d" % len(rows))
    check("the writer keeps the measured value",
          by["a"]["value"] == "old-a", by["a"]["value"])
    if os.path.exists(path):
        os.remove(path)

    npass = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    for name, ok, detail in results:
        print("  %-4s %s%s" % ("PASS" if ok else "FAIL", name,
                              "" if ok else "  <- %s" % detail))
    print("\n=== %d/%d merge checks passed ===" % (npass, total))
    return 0 if npass == total else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    print(__doc__)
    print("usage: python3 capture_merge.py --self-test")
    sys.exit(2)
