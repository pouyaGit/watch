#!/usr/bin/env python3
"""
watch_maintenance.py -- keeps the high-volume collections bounded (watch-maintenance timer).

Prunes Urls not seen for URLS_RETENTION_MONTHS and trims ChangeEvent to the newest
CHANGE_EVENTS_MAX rows. Dry-run by default: nothing is deleted without --apply.
Deletes run in batches so the database is never locked for long.

Usage:
  python3 scripts/watch_maintenance.py                    # report what would be pruned
  python3 scripts/watch_maintenance.py --apply            # prune
  python3 scripts/watch_maintenance.py --apply --ensure-indexes

Env knobs:
  URLS_RETENTION_MONTHS  drop Urls with last_update older than this (default 12)
  CHANGE_EVENTS_MAX      keep at most this many ChangeEvent rows (default 200000)
  MAINTENANCE_BATCH      ids per delete batch (default 5000)
"""
import argparse
import os
import sys
from datetime import datetime, timedelta

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(ROOT)

from database.change_events import ChangeEvent  # noqa: E402
from database.db import Endpoints, Finding, Http, LiveSubdomains, Subdomains, Urls  # noqa: E402
from utils.recon import env_int, log  # noqa: E402

INDEXED_MODELS = (Subdomains, LiveSubdomains, Http, Urls, Endpoints, Finding, ChangeEvent)


def _delete_ids(coll, ids):
    coll.delete_many({"_id": {"$in": ids}})


def prune_urls(cutoff, batch, apply):
    coll = Urls._get_collection()
    query = {"last_update": {"$lt": cutoff}}
    stale = coll.count_documents(query)
    log(f"urls older than {cutoff:%Y-%m-%d}: {stale}")
    if not apply or not stale:
        return stale
    removed = 0
    while True:
        ids = [d["_id"] for d in coll.find(query, {"_id": 1}).limit(batch)]
        if not ids:
            break
        _delete_ids(coll, ids)
        removed += len(ids)
    log(f"urls pruned: {removed}")
    return removed


def trim_change_events(max_rows, batch, apply):
    coll = ChangeEvent._get_collection()
    total = coll.estimated_document_count()
    excess = total - max_rows
    log(f"change_events: {total} rows, cap {max_rows}, excess {max(excess, 0)}")
    if excess <= 0 or not apply:
        return max(excess, 0)
    removed = 0
    while removed < excess:
        take = min(batch, excess - removed)
        ids = [d["_id"] for d in coll.find({}, {"_id": 1}).sort("created_date", 1).limit(take)]
        if not ids:
            break
        _delete_ids(coll, ids)
        removed += len(ids)
    log(f"change_events trimmed: {removed}")
    return removed


def ensure_indexes():
    for model in INDEXED_MODELS:
        model.ensure_indexes()
    log("indexes ensured")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="actually delete (default is dry-run)")
    parser.add_argument("--ensure-indexes", action="store_true", help="create missing indexes first")
    args = parser.parse_args()

    batch = env_int("MAINTENANCE_BATCH", 5000)
    retention_months = env_int("URLS_RETENTION_MONTHS", 12)
    max_events = env_int("CHANGE_EVENTS_MAX", 200000)
    cutoff = datetime.now() - timedelta(days=30 * retention_months)

    mode = "APPLY" if args.apply else "DRY-RUN"
    log(f"=== maintenance {mode} ===")
    if args.ensure_indexes:
        ensure_indexes()
    prune_urls(cutoff, batch, args.apply)
    trim_change_events(max_events, batch, args.apply)
    log("=== maintenance done ===")


if __name__ == "__main__":
    main()
