"""
backend/deps.py — Shared dependencies and helpers for the backend package.

Carries the small pieces of api.py that every router needs:
- API_KEY (re-exported from config)
- verify_api_key dependency (kept as a dependency callable, not just a middleware,
  so routers can declare it per-route and so future per-route policy changes are
  localized here)
- build_url() for ?api_key= propagation in dashboard links
- paginate() helper used by the moved list endpoints
"""
import os
import sys
from typing import Optional

from fastapi import Depends, Query, Request
from fastapi.responses import JSONResponse

# Make sure the project root is on sys.path so `from config import config`
# and `from database.db import ...` work the same way they did in api.py.
# NOTE: we intentionally do NOT add database/ itself to sys.path anymore --
# that shim made every database/*.py importable by bare filename (letting
# database/telegram.py shadow the real python-telegram-bot package). All
# callers now use fully qualified `from database.db import ...` imports.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from config import config  # noqa: E402

API_KEY = config().get("API_KEY", "")
PAGE_LIMIT_MAX = 500
EXEMPT_PATHS = {"/docs", "/redoc", "/openapi.json"}


async def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = None,
    api_key: Optional[str] = None,
):
    """Dependency that enforces the X-API-Key header or ?api_key= query param.

    The middleware in api.py already blocks unauthenticated requests globally,
    so this dependency exists mostly as a declarative signal on mutating routes
    -- if the middleware is ever relaxed for a path, this dependency is still
    a hard gate. Endpoints that should remain public (e.g. health checks) just
    don't include it.
    """
    if not API_KEY:
        return True
    provided = (
        x_api_key
        if x_api_key is not None
        else request.headers.get("X-API-Key")
        or api_key
        or request.query_params.get("api_key")
    )
    if provided != API_KEY:
        return JSONResponse(
            {"detail": "Invalid or missing API key (header X-API-Key or ?api_key=...)"},
            status_code=401,
        )
    return True


def paginate(qs, page: int, limit: int):
    """Apply skip/limit pagination, clamping limit to [1, PAGE_LIMIT_MAX]."""
    limit = min(max(limit, 1), PAGE_LIMIT_MAX)
    page = max(page, 1)
    return qs.skip((page - 1) * limit).limit(limit)


def build_url(path, **params):
    """Build a dashboard link and auto-append ?api_key= when API_KEY is set.

    Drop-in replacement for the helper that lived in api.py -- every moved
    template/router still uses this exact signature.
    """
    if API_KEY:
        params["api_key"] = API_KEY
    qs = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
    return f"{path}?{qs}" if qs else path


def api_key_query(api_key: Optional[str] = Query(default=None)):
    """No-op dependency that just surfaces ?api_key= as a typed parameter.

    Routers that need it for link building can include this; verify_api_key is
    the real gate.
    """
    return api_key