#!/usr/bin/env python3
"""promotion/audit.py — append-only local audit log for the promotion operator.

Autonomous Promotion Operator v1 (Epic 0.1).

One JSON object per line: ``seq``, ``event``, ``timestamp``, ``request``,
``commit``, ``actor``, ``detail``. The log is append-only: this program can add
a line or read lines, never rewrite or delete. ``verify`` checks the chain
(monotonic seq from 1, known events, valid JSON).

Closed event vocabulary: PROMOTION_REQUESTED, PROMOTION_APPROVED,
PROMOTION_BLOCKED, PROMOTION_COMPLETED. No secrets are ever recorded — callers
pass identifiers (request filename, commit sha, operator name) only.

Usage:
  audit.py --log FILE record --event E [--request R] [--commit C]
           [--actor A] [--detail D] [--now T]
  audit.py --log FILE list [--json]
  audit.py --log FILE verify
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

EVENTS = (
    "PROMOTION_REQUESTED",
    "PROMOTION_APPROVED",
    "PROMOTION_BLOCKED",
    "PROMOTION_COMPLETED",
)


def _read_entries(log_path: Path) -> list[dict]:
    if not log_path.is_file():
        return []
    entries = []
    for lineno, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except ValueError as error:
            raise ValueError(f"{log_path}:{lineno}: invalid JSON: {error}") from error
    return entries


def cmd_record(args: argparse.Namespace) -> int:
    if args.event not in EVENTS:
        print(f"FAIL: unknown audit event: {args.event}", file=sys.stderr)
        print(f"  expected one of: {', '.join(EVENTS)}", file=sys.stderr)
        return 1
    log_path = Path(args.log)
    entries = _read_entries(log_path)
    entry = {
        "seq": len(entries) + 1,
        "event": args.event,
        "timestamp": args.now or "",
        "request": args.request or "",
        "commit": args.commit or "",
        "actor": args.actor or "",
        "detail": args.detail or "",
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    print(f"recorded {args.event} seq={entry['seq']}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    entries = _read_entries(Path(args.log))
    if args.json:
        for entry in entries:
            print(json.dumps(entry, sort_keys=True))
    else:
        for entry in entries:
            print(
                f"  {entry.get('seq')} {entry.get('timestamp')} "
                f"{entry.get('event')} {entry.get('request')} "
                f"{entry.get('commit')} {entry.get('actor')}"
            )
            if entry.get("detail"):
                print(f"    detail: {entry.get('detail')}")
        if not entries:
            print("  (no audit events)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        entries = _read_entries(Path(args.log))
    except ValueError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    for index, entry in enumerate(entries, 1):
        if entry.get("seq") != index:
            print(
                f"FAIL: broken sequence at entry {index}: seq={entry.get('seq')!r}",
                file=sys.stderr,
            )
            return 1
        if entry.get("event") not in EVENTS:
            print(
                f"FAIL: unknown event at entry {index}: {entry.get('event')!r}",
                file=sys.stderr,
            )
            return 1
    print(f"audit log verified: {len(entries)} event(s), sequence intact")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Promotion operator audit log")
    parser.add_argument("--log", required=True, help="audit log file")
    sub = parser.add_subparsers(dest="command", required=True)

    record = sub.add_parser("record", help="append one audit event")
    record.add_argument("--event", required=True, help="|".join(EVENTS))
    record.add_argument("--request", default="")
    record.add_argument("--commit", default="")
    record.add_argument("--actor", default="")
    record.add_argument("--detail", default="")
    record.add_argument("--now", default="")

    listed = sub.add_parser("list", help="print audit events")
    listed.add_argument("--json", action="store_true")

    sub.add_parser("verify", help="verify the audit chain")

    args = parser.parse_args(argv)
    if args.command == "record":
        return cmd_record(args)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "verify":
        return cmd_verify(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
