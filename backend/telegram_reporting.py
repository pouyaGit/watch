"""backend/telegram_reporting.py — Stage R84 Telegram AI activity reporting.

Consumes the existing R83 activity collector directly (no localhost HTTP, no
duplicated activity calculation), formats bounded reports through the pure
R84 formatter and sends them over the existing Telegram transport
(``database.telegram.send_message``; config via ``config()`` ->
``TELEGRAM_BOT_TOKEN`` / ``TELEGRAM_CHAT_ID``).

Design:

- R83 ``collect_activity`` is the single source of runtime truth; the daily
  report and the event reports both render that snapshot.
- Deduplication uses a tiny bounded JSON state file with deterministic keys
  (``daily:<window_start>``, ``event:<type>:<run_id>``,
  ``event:<type>:<case_id>:<case_modified_at>``). Keys are recorded only
  after a successful send, so a failed send can be retried on the next
  invocation (one attempt per invocation, no retry storm). The first
  observation of a state stores a silent baseline, so stale events are never
  replayed just because the reporter ran for the first time.
- Fail-safe: missing Telegram configuration or transport failure returns a
  bounded result, never raises (the public entry point is a totality wrapper),
  never touches research state and never breaks the AI pipeline.
- No secrets are logged or stored: only boolean configuration flags, report
  keys and the sanitized transition snapshot are persisted.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from typing import Callable, Mapping

from ai.knowledge.ai_activity_report import (
    RULE_VERSION,
    build_daily_report,
    event_reports,
    snapshot_of,
)
from backend import research_activity

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE_PATH = (
    PROJECT_ROOT / "ai_data" / "research" / "ai_reports" / "telegram_state.json"
)
MAX_KEYS = 24

MODE_AUTO = "auto"
MODE_DAILY = "daily"
MODE_EVENTS = "events"
MODE_BOTH = "both"
MODES: tuple[str, ...] = (MODE_AUTO, MODE_DAILY, MODE_EVENTS, MODE_BOTH)


def _text(value: object, limit: int = 200) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _block(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def state_path() -> Path:
    override = _text(os.environ.get("WATCH_TELEGRAM_REPORT_STATE"), 512)
    if override:
        candidate = Path(override)
        return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
    return DEFAULT_STATE_PATH


def telegram_config_status() -> dict:
    """Boolean configuration state only; values are never read out."""

    try:
        from config import config

        values = config()
        token = _text(values.get("TELEGRAM_BOT_TOKEN"), 4096)
        chat = _text(values.get("TELEGRAM_CHAT_ID"), 64)
    except Exception:
        token, chat = "", ""
    return {
        "token_configured": bool(token),
        "chat_configured": bool(chat),
        "configured": bool(token and chat),
    }


def load_state(path: object = None) -> dict:
    target = Path(path) if path is not None else state_path()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        payload = {}
    keys = [
        _text(key, 200)
        for key in (payload.get("keys") or ())
        if _text(key, 200)
    ]
    snapshot = payload.get("snapshot")
    return {
        "keys": keys[-MAX_KEYS:],
        "snapshot": dict(snapshot) if isinstance(snapshot, Mapping) else {},
        "updated_at": _text(payload.get("updated_at"), 64),
    }


def save_state(state: Mapping, path: object = None) -> Path:
    target = Path(path) if path is not None else state_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "rule_version": RULE_VERSION,
        "keys": [
            _text(key, 200)
            for key in (state.get("keys") or ())
            if _text(key, 200)
        ][-MAX_KEYS:],
        "snapshot": dict(state.get("snapshot") or {}),
        "updated_at": _text(state.get("updated_at"), 64),
    }
    tmp = target.with_name(target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True))
    os.replace(tmp, target)
    return target


def _default_sender(message: str) -> bool:
    """Existing Telegram transport (used only when no sender is injected)."""

    from database.telegram import send_message

    return bool(send_message(message))


def _select_reports(
    activity: Mapping, state: Mapping, mode: str
) -> list[dict]:
    reports: list[dict] = []
    in_window = bool(_block(activity.get("window")).get("in_window"))
    if mode in (MODE_DAILY, MODE_BOTH) or (mode == MODE_AUTO and not in_window):
        reports.append(build_daily_report(activity))
    if mode in (MODE_EVENTS, MODE_BOTH) or mode == MODE_AUTO:
        known = set(state.get("keys") or ())
        previous = state.get("snapshot") or {}
        for report in event_reports(activity, previous):
            if report.get("dedup_key") in known:
                continue
            reports.append(report)
    return reports


def send_activity_reports(
    *,
    activity: Mapping | None = None,
    now: object = None,
    mode: str = MODE_AUTO,
    sender: Callable[[str], bool] | None = None,
    state_path_override: object = None,
    dry_run: bool = False,
) -> dict:
    """Totality wrapper: reporting must never raise into the caller."""

    try:
        return _send_activity_reports(
            activity=activity,
            now=now,
            mode=mode,
            sender=sender,
            state_path_override=state_path_override,
            dry_run=dry_run,
        )
    except Exception as exc:  # noqa: BLE001 - fail-soft by contract
        config = telegram_config_status()
        return {
            "rule_version": RULE_VERSION,
            "mode": mode if mode in MODES else MODE_AUTO,
            "configured": config["configured"],
            "token_configured": config["token_configured"],
            "chat_configured": config["chat_configured"],
            "sent": 0,
            "failed": 0,
            "skipped": 0,
            "activity_status": "",
            "reasons": [f"unexpected_{type(exc).__name__}"],
        }


def _send_activity_reports(
    *,
    activity: Mapping | None = None,
    now: object = None,
    mode: str = MODE_AUTO,
    sender: Callable[[str], bool] | None = None,
    state_path_override: object = None,
    dry_run: bool = False,
) -> dict:
    """Collect R83 activity, build bounded reports and send them (fail-soft)."""

    resolved_mode = mode if mode in MODES else MODE_AUTO
    config = telegram_config_status()
    result: dict = {
        "rule_version": RULE_VERSION,
        "mode": resolved_mode,
        "configured": config["configured"],
        "token_configured": config["token_configured"],
        "chat_configured": config["chat_configured"],
        "sent": 0,
        "failed": 0,
        "skipped": 0,
        "reasons": [],
    }

    try:
        if activity is None:
            activity = research_activity.collect_activity(now=now)
    except Exception as exc:
        result["reasons"].append(f"activity_unavailable_{type(exc).__name__}")
        return result

    activity = _block(activity)
    result["activity_status"] = _text(activity.get("status"), 40)

    if not config["configured"] and not dry_run:
        result["reasons"].append("telegram_not_configured")
        return result

    state = load_state(state_path_override)
    known = list(state.get("keys") or ())
    try:
        reports = _select_reports(activity, state, resolved_mode)
    except Exception as exc:
        result["reasons"].append(f"report_build_failed_{type(exc).__name__}")
        return result

    transport = sender or _default_sender
    state_changed = False
    stop_sending = False
    for report in reports:
        key = _text(report.get("dedup_key"), 200)
        if key and key in known:
            result["skipped"] += 1
            continue
        if dry_run:
            result["skipped"] += 1
            report_label = _text(
                report.get("event_type") or report.get("report_type"), 40
            )
            result["reasons"].append(f"dry_run:{report_label}")
            continue
        if stop_sending:
            result["skipped"] += 1
            continue
        message = report.get("message")
        if not isinstance(message, str):
            message = str(message or "")
        try:
            # The formatter already bounds the message; the slice is a second
            # safety bound. Never collapse whitespace here: Telegram output is
            # multi-line by design.
            delivered = bool(transport(message[:4096]))
        except Exception as exc:
            delivered = False
            result["reasons"].append(f"transport_error_{type(exc).__name__}")
        if delivered:
            result["sent"] += 1
            if key and key not in known:
                known.append(key)
                state_changed = True
        else:
            result["failed"] += 1
            result["reasons"].append("send_failed")
            # One attempt per invocation; no retry storm.
            stop_sending = True

    if resolved_mode in (MODE_EVENTS, MODE_BOTH, MODE_AUTO) and not stop_sending:
        new_snapshot = snapshot_of(activity)
        if new_snapshot != state.get("snapshot"):
            state["snapshot"] = new_snapshot
            state_changed = True
    if state_changed and not dry_run:
        state["keys"] = known[-MAX_KEYS:]
        state["updated_at"] = datetime.now(ZoneInfo("Asia/Tehran")).isoformat()
        try:
            save_state(state, state_path_override)
        except OSError:
            result["reasons"].append("state_write_failed")

    result["reasons"] = result["reasons"][:12]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m backend.telegram_reporting",
        description=(
            "R84 Telegram AI activity reporting (read-only R83 source, "
            "bounded reports, deterministic deduplication)"
        ),
    )
    parser.add_argument("--mode", choices=MODES, default=MODE_AUTO)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = send_activity_reports(mode=args.mode, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True))
    else:
        print(
            "TELEGRAM AI ACTIVITY REPORT: "
            f"mode={result['mode']} configured={result['configured']} "
            f"sent={result['sent']} failed={result['failed']} "
            f"skipped={result['skipped']}"
        )
        if result.get("reasons"):
            print("notes: " + ", ".join(result["reasons"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
