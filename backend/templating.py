"""
backend/templating.py — The single Jinja2Templates instance used by every
router, with all dashboard filters registered once.

Why a shared instance: routers used to each build ``Jinja2Templates(...)``,
which meant custom filters had to be registered N times (and never were —
``/ui/tasks`` 500'd at runtime because ``tasks.html`` uses a ``| basename``
filter that was never registered anywhere). Any new filter belongs here.

Filters:
  tehran(dt)  -> "31 Aug 2026 15:42"  (absolute, Asia/Tehran)
  ago(dt)     -> "2h ago"             (relative, Asia/Tehran)
  shortdt(dt) -> "31 Aug 14:20"       (timeline stamp, Asia/Tehran)
  fmtnum(n)   -> "12,431"             (thousands separator)
  basename(p) -> "file.log"
  cdn_slug(v) -> "cloudflare"         (CSS-safe token for cdn-* classes;
                                       anything unknown/empty degrades to
                                       a neutral token -- CDN strings come
                                       from the network and must never be
                                       interpolated into class="" raw)
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import quote

from fastapi.templating import Jinja2Templates

from backend.tz import fmt_ago, fmt_short, fmt_tehran

_TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "web" / "templates"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

_env = templates.env
_env.filters["tehran"] = fmt_tehran
_env.filters["ago"] = fmt_ago
_env.filters["shortdt"] = fmt_short
_env.filters["basename"] = os.path.basename


def _fmt_num(value) -> str:
    if value is None:
        return "0"
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


_env.filters["fmtnum"] = _fmt_num
_env.filters["urlencode"] = quote

# Lowercase alnum token for CSS classes derived from data (CDN names, ...).
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _cdn_slug(value) -> str:
    """CSS-safe class token for a CDN display string.

    "AWS CloudFront" -> "aws-cloudfront", "" / None / "—" -> "unknown".
    Anything exotic collapses to alnum+dashes, so an untrusted CDN value can
    never inject into a class="" attribute (Jinja autoescape also applies,
    this is defence in depth so unknown CDNs simply render neutral).
    """
    text = str(value or "").strip().lower()
    if not text or text in {"-", "—", "none", "unknown"}:
        return "unknown"
    return _SLUG_RE.sub("-", text).strip("-") or "unknown"


_env.filters["cdn_slug"] = _cdn_slug


def get_templates() -> Jinja2Templates:
    return templates
