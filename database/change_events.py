"""
database/change_events.py — Minimal change-history collection for the dashboard.

The crawlers already DETECT changes (title/status in upsert_http, ip/cdn in
upsert_lives, new endpoints/params in bulk_store_crawl_results) but only
fired Telegram notifications; nothing was persisted. This module adds a
tiny, bounded event log so the UI can answer "what changed since the last
recon?" without a complicated event system.

``record_change`` / ``record_changes`` are deliberately best-effort and
never raise -- change tracking must never break the crawler that is doing
the real work.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Iterable

from mongoengine import DateTimeField, Document, StringField

_log = logging.getLogger("watch.change_events")

# event_type vocabulary (used by the UI to group/colour events)
EVENT_TYPES = {
    "title_changed",
    "status_changed",
    "ip_changed",
    "cdn_changed",
    "technology_changed",
    "new_domain",
    "new_live",
    "new_http",
    "new_endpoint",
    "new_parameter",
}

# Human-readable label + icon for each event type (UI badge text).
EVENT_LABELS = {
    "title_changed":      ("Title", "🔄"),
    "status_changed":     ("HTTP status", "⚠️"),
    "ip_changed":         ("IP", "🔀"),
    "cdn_changed":        ("CDN", "🛰"),
    "technology_changed": ("Technology", "🧩"),
    "new_domain":         ("New domain", "🟢"),
    "new_live":           ("New live host", "🟢"),
    "new_http":           ("New HTTP", "🌐"),
    "new_endpoint":       ("New endpoint", "🆕"),
    "new_parameter":      ("New parameter", "🆕"),
}


class ChangeEvent(Document):
    program_name = StringField(required=True)
    subdomain    = StringField()
    event_type   = StringField(required=True)
    old_value    = StringField(default="")
    new_value    = StringField(default="")
    created_date = DateTimeField(default=datetime.now)

    meta = {
        "indexes": [
            {"fields": ["program_name", "-created_date"]},
            {"fields": ["event_type"]},
            {"fields": ["-created_date"]},
        ]
    }

    def as_dict(self):
        return {
            "id": str(self.id),
            "program_name": self.program_name,
            "subdomain": self.subdomain or "",
            "event_type": self.event_type,
            "event_class": event_class(self.event_type),
            "label": event_label(self.event_type),
            "old_value": self.old_value or "",
            "new_value": self.new_value or "",
            "created_date": self.created_date,
        }


def event_class(event_type) -> str:
    """CSS-safe class token for a change event.

    Defence-in-depth: the value is rendered into a class="" attribute by the
    templates. Jinja autoescape already prevents attribute breakout, but the
    class is derived from a strict whitelist anyway -- anything unknown maps
    to the neutral 'other' class.
    """
    if isinstance(event_type, str) and event_type in EVENT_TYPES:
        return event_type
    return "other"


def event_label(event_type) -> str:
    """Human label for a change event, with a fixed icon prefix."""
    label, icon = EVENT_LABELS.get(event_type, ("Change", "•"))
    return f"{icon} {label}"


def _safe(value) -> str:
    if value is None:
        return ""
    s = str(value)
    # Keep the log bounded: truncate absurdly long values (full titles are
    # fine, but defensive cap prevents giant HTML/headers from being stored).
    return s[:4000]


def _log_persist_failure(op, program_name, event_type, exc):
    """Log a change-event persistence failure without leaking secrets.

    Only the exception class and the first 200 chars of the message are
    emitted. ``old_value`` / ``new_value`` are deliberately NOT logged --
    they can carry user-controlled input (titles, paths, IPs, ...).
    """
    try:
        msg = str(exc)[:200]
    except Exception:
        msg = "<unprintable>"
    _log.warning(
        "change_events %s failed: program=%s event_type=%s exc=%s msg=%s",
        op, program_name, event_type, type(exc).__name__, msg,
    )


def record_change(program_name, subdomain, event_type, old_value="", new_value=""):
    """Persist one change event (best-effort).

    Missing/unknown event types and empty program names are ignored. Any
    Mongo/validation error is swallowed so the caller (a crawler upsert)
    is never interrupted by change tracking, but a structured warning is
    logged so silent breakage is observable in the next pipeline log.
    """
    if not program_name or event_type not in EVENT_TYPES:
        return
    try:
        ChangeEvent(
            program_name=program_name,
            subdomain=subdomain or "",
            event_type=event_type,
            old_value=_safe(old_value),
            new_value=_safe(new_value),
            created_date=datetime.now(),
        ).save()
    except Exception as exc:
        _log_persist_failure("record_change", program_name, event_type, exc)


def record_changes(events: Iterable[tuple]) -> int:
    """Persist many change events in ONE insert_many call (best-effort).

    ``events`` items: (program_name, subdomain, event_type, old, new).
    Invalid entries are skipped silently. Returns the number of valid
    events submitted. Never raises, but logs a structured warning on
    Mongo/validation failure so silent breakage is observable.
    """
    docs = []
    last_program = None
    last_event_type = None
    for (p, s, t, o, n) in events:
        last_program, last_event_type = p, t
        if not p or t not in EVENT_TYPES:
            continue
        docs.append(
            ChangeEvent(
                program_name=p,
                subdomain=s or "",
                event_type=t,
                old_value=_safe(o),
                new_value=_safe(n),
                created_date=datetime.now(),
            )
        )
    if not docs:
        return 0
    try:
        ChangeEvent.objects.insert(docs, load_bulk=False)
        return len(docs)
    except Exception as exc:
        _log_persist_failure(
            "record_changes",
            last_program or "<unknown>",
            last_event_type or "<unknown>",
            exc,
        )
        return 0


def build_recon_events(ep_agg: dict, snapshot: dict, max_param_events: int = 500):
    """Pure diff -> recon change events for one crawl batch (no I/O).

    ``ep_agg``:   {(program, subdomain, path): {"params": set([...]), ...}}
    ``snapshot``: {(program, subdomain, path): set(existing param names)};
                  a MISSING key means the endpoint did not exist yet.

    Emits:
      * new_endpoint  -- once per endpoint key absent from the snapshot
      * new_parameter -- once per genuinely new parameter name. Parameter
        events are de-duplicated across the whole run by (program, name) so a
        big first crawl cannot flood the change log, and capped by
        ``max_param_events`` as a final guard.

    Only genuinely new items produce events; nothing is emitted for pure
    hit-count/last_update updates.
    """
    events = []
    seen_params = set()
    param_events = 0
    for key, data in (ep_agg or {}).items():
        program, subdomain, path = key
        params = set((data or {}).get("params") or [])
        prev = (snapshot or {}).get(key)
        if prev is None:
            # Endpoint did not exist before this run: every param is new.
            events.append((program, subdomain, "new_endpoint", "", path))
            new_params = params
        else:
            new_params = params - set(prev)
        for name in sorted(new_params):
            dkey = (program, name)
            if dkey in seen_params:
                continue
            if param_events >= max_param_events:
                break
            seen_params.add(dkey)
            param_events += 1
            events.append((program, subdomain, "new_parameter", "", name))
    return events


def recent_events(limit=50, program_name=None, event_type=None):
    """Newest ChangeEvents, optionally filtered by program / event type."""
    q = ChangeEvent.objects()
    if program_name:
        q = q(program_name=program_name)
    if event_type:
        q = q(event_type=event_type)
    return list(q.order_by("-created_date").limit(limit))
