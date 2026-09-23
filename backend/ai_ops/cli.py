"""EPIC9 operations CLI — one bounded tick or a read-only status.

    python -m backend.ai_ops.cli tick        run one bounded tick
    python -m backend.ai_ops.cli status      read-only projection now
    python -m backend.ai_ops.cli status --at ISO
                                             read-only what-if for a
                                             timestamp (never executes,
                                             never writes)

``tick`` is what the hourly scheduling service reaches indirectly via
``ai.research_cli agent run`` (which calls
``backend.ai_ops.dispatcher.maybe_run_from_scheduler``); the direct
subcommand exists for validation and operator use. The window gate
always runs; no flag can bypass it.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from backend.ai_ops.config import DispatcherConfig
from backend.ai_ops.dispatcher import run_tick, status_payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.ai_ops.cli",
        description="Bounded AI Operations dispatcher (EPIC9).")
    sub = parser.add_subparsers(dest="command")
    tick = sub.add_parser("tick", help="run one bounded AI operations "
                                       "tick (window-enforced)")
    tick.add_argument("--json", action="store_true",
                      help="emit the tick record as JSON")
    status = sub.add_parser("status", help="read-only operations status")
    status.add_argument("--at", default="",
                        help="ISO timestamp for a what-if evaluation "
                             "(no execution, no writes)")
    status.add_argument("--json", action="store_true",
                        default=True, help="JSON output (default)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = getattr(args, "command", None)

    if command == "status":
        at = None
        if getattr(args, "at", ""):
            try:
                at = datetime.fromisoformat(args.at)
            except ValueError:
                print(json.dumps({"ok": False, "error":
                                  "invalid --at ISO timestamp"}))
                return 2
        payload = status_payload(at=at,
                                 config=DispatcherConfig.from_env())
        print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
        return 0

    if command == "tick":
        record = run_tick(config=DispatcherConfig.from_env())
        if getattr(args, "json", False):
            print(json.dumps(record, ensure_ascii=True, sort_keys=True,
                             default=str))
        else:
            print(f"TICK: {record.get('tick_id', '')}")
            print(f"OUTCOME: {record.get('outcome', '')}")
            counts = record.get("discovered") or {}
            print(f"DISCOVERED: total={counts.get('discovered', 0)} "
                  f"executable={counts.get('executable', 0)} "
                  f"waiting={counts.get('waiting', 0)} "
                  f"blocked={counts.get('blocked', 0)}")
            print(f"EXECUTED: {len(record.get('executed', []))}")
            if record.get("stop_reason"):
                print(f"STOP: {record['stop_reason']}")
            for error in (record.get("errors") or [])[:5]:
                print(f"  error: {error}")
        # a tick is an operational report, not a process exit signal:
        # only a genuine tick failure is non-zero (honest, visible).
        return 0 if record.get("outcome") not in ("FAILED",) else 1

    build_parser().print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
