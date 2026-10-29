#!/usr/bin/env python3
"""Print the HERMES human-review backlog, grouped by underlying signal.

READ-ONLY: opens the DB through lib/store's conn() and issues only SELECTs.
Presents a decision list rather than a row dump, because N waiting rows are
routinely a handful of distinct fingerprints.

  python3 scripts/human_review_digest.py
  python3 scripts/human_review_digest.py --json

Pair with SKILL.md section 30 before acting on a bulk disposition request: the
output separates infrastructure-shaped entries (reason names a provider outage)
from genuine judgement calls, and shows the evidence-quality flags that make a
blind approve meaningless.
"""
import argparse
import json
import os
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, os.path.join(ROOT, "lib"))
from store import conn  # noqa: E402

CAPPED = "MAX_SUPPORTING_EVENTS"


def ago(ts, now):
    if not ts:
        return "?"
    d = now - float(ts)
    return f"{d/3600:.1f}h" if d < 86400 else f"{d/86400:.1f}d"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    now = time.time()
    c = conn()
    out = {"cases": [], "closures": [], "unacknowledged": 0}

    # Queue 1: unacknowledged high/medium findings across BOTH finding tables.
    try:
        import findings_state as fs
        out["unacknowledged"] = len(fs.find_unread())
    except Exception:                                          # noqa: BLE001
        pass

    # Queue 2: cases parked on a human judgement state, grouped by reason.
    for r in c.execute("SELECT case_id,case_type,case_reason,host,target,severity_context,"
                       "confidence_state,updated_at FROM hunt_cases "
                       "WHERE status='WAITING_HUMAN' ORDER BY updated_at DESC"):
        d = dict(r)
        d["age"] = ago(d["updated_at"], now)
        d["infrastructure"] = "unavailable" in (d["case_reason"] or "").lower()
        out["cases"].append(d)

    # Queue 3: closures awaiting judgement, grouped by target.
    for r in c.execute("SELECT closure_id,target,host,claim_type,evidence_state,reason_code,"
                       "rule_term,basis_summary,unresolved_json,conflict_count,"
                       "supporting_count,authority_sources,decided_at FROM decision_closures "
                       "WHERE decision_state='HUMAN_REVIEW_REQUIRED' ORDER BY decided_at DESC"):
        d = dict(r)
        d["age"] = ago(d["decided_at"], now)
        try:
            d["conflict_count"] = int(d["conflict_count"] or 0)
        except (TypeError, ValueError):
            d["conflict_count"] = 0
        d["basis_truncated"] = CAPPED in (d["unresolved_json"] or "")
        out["closures"].append(d)

    c.close()
    out["counts"] = {"unacknowledged": out["unacknowledged"],
                     "cases": len(out["cases"]),
                     "closures": len(out["closures"])}
    if a.json:
        print(json.dumps(out, indent=1, default=str))
        return 0

    n = out["counts"]
    print(f"HUMAN REVIEW DIGEST — {n['unacknowledged']} unacknowledged finding(s), "
          f"{n['cases']} case(s), {n['closures']} closure(s)")
    print("=" * 68)

    infra = [d for d in out["cases"] if d["infrastructure"]]
    judgement = [d for d in out["cases"] if not d["infrastructure"]]
    for label, group in (("INFRASTRUCTURE-SHAPED (reason names a provider outage)", infra),
                         ("GENUINE JUDGEMENT CALLS", judgement)):
        if not group:
            continue
        print(f"\n## CASES — {label} ({len(group)})")
        by_reason = defaultdict(list)
        for d in group:
            by_reason[d["case_reason"] or "?"].append(d)
        for reason, rows in by_reason.items():
            hosts = sorted({r["host"] for r in rows if r["host"]})
            ages = sorted(r["age"] for r in rows)
            print(f"\n  x{len(rows)}  {reason[:100]}")
            print(f"       hosts: {', '.join(hosts[:4])}{' …' if len(hosts) > 4 else ''}")
            print(f"       age:   {ages[0]} .. {ages[-1]}")

    if out["closures"]:
        print(f"\n## CLOSURES ({len(out['closures'])}) — grouped by target")
        by_target = defaultdict(list)
        for d in out["closures"]:
            by_target[d["target"]].append(d)
        for target, rows in sorted(by_target.items(), key=lambda x: -len(x[1])):
            conflict = sum(1 for r in rows if r["conflict_count"] > 0)
            capped = sum(1 for r in rows if r["basis_truncated"])
            ages = sorted(r["age"] for r in rows)
            print(f"\n  {target} — {len(rows)} closure(s), conflict>0: {conflict}, "
                  f"basis truncated: {capped}, age {ages[0]}..{ages[-1]}")
            print(f"       {rows[0]['claim_type']} / {rows[0]['evidence_state']} "
                  f"/ {rows[0]['reason_code']}")

        print("\n  Basis quality across the queue (read before any bulk approve):")
        print(f"    truncated bases : {sum(1 for d in out['closures'] if d['basis_truncated'])}"
              f" of {len(out['closures'])}  — the recorded basis is NOT the full evidence")
        print(f"    contradictory   : {sum(1 for d in out['closures'] if d['conflict_count'] > 0)}"
              f"  — conflict>0 means evidence disagrees, not that it is merely thin")

    print("\nRead-only. No state was changed. Confirming is a human judgement: "
          "do not bulk-confirm these.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
