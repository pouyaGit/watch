#!/usr/bin/env python3
"""
api.py — FastAPI entrypoint for the Watch Dashboard v2.

After the Phase 1 refactor this file is intentionally tiny. It:

  1. Creates the FastAPI app
  2. Wires the APIKeyMiddleware (X-API-Key header or ?api_key= query param)
  3. Mounts /static/ to web/static/  (CSS + JS assets)
  4. Includes the routers that live in backend/routers/
  5. Runs uvicorn on port 5000 when invoked directly

All the actual route handlers moved into backend/routers/*.py:
  - pages.py     -- /, /ui/program/{name}, /ui/tasks (HTML pages)
  - programs.py  -- subdomains/lives/http/urls/endpoints/dns-bruteforce pages + JSON API
  - system.py    -- /api/system/stats + htmx fragment variant
  - tasks.py     -- /api/tasks, POST run, history, status badge

Run:  python3 api.py
"""

import os
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.staticfiles import StaticFiles

# Importing this module triggers database/db.py -> mongoengine.connect().
# We rely on that side effect -- every Document subclass (Programs, TaskRun,
# ...) needs the connection to be open before the first query.
import database.db  # noqa: F401  (side-effect import)

from backend.routers import pages, programs, system, tasks
from config import config

API_KEY = config().get("API_KEY", "")
EXEMPT_PATHS = {
    "/docs", "/redoc", "/openapi.json",
    # static assets are served unauthenticated so the dashboard renders even
    # before the user has typed the API key (the templates reference /static/
    # directly with no key). The /api/* routes are still gated behind verify_api_key.
}

_PROJECT_ROOT = Path(__file__).resolve().parent
_STATIC_DIR = _PROJECT_ROOT / "web" / "static"


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Same behavior as the old api.py: X-API-Key header or ?api_key= param.
    OpenAPI docs paths are exempt so /docs and /openapi.json are always
    reachable without auth."""

    async def dispatch(self, request, call_next):
        if not API_KEY:
            return await call_next(request)
        path = request.url.path
        # OpenAPI docs paths are always reachable without auth.
        if path in EXEMPT_PATHS:
            return await call_next(request)
        # /static/* (CSS, JS) is also unauthenticated so the page renders
        # before the user has supplied the API key. Templates link to
        # /static/... with no key; the dashboard JS reads the key from
        # window.location.search at runtime.
        if path.startswith("/static/"):
            return await call_next(request)
        key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
        if key != API_KEY:
            return JSONResponse(
                {"detail": "Invalid or missing API key (header X-API-Key or ?api_key=...)"},
                status_code=401,
            )
        return await call_next(request)


app = FastAPI(title="Watch API")
app.add_middleware(APIKeyMiddleware)

# Static assets (CSS/JS). Mounted at /static so templates can reference
# /static/css/custom.css and /static/js/app.js.
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# Per-run task logs. Mounted at /logs/tasks so the Tasks page links
# (/logs/tasks/{filename}) actually work. Deliberately NOT added to
# EXEMPT_PATHS: log contents can include sensitive recon data, so this mount
# stays behind the API-key middleware above (middleware wraps mounted apps
# too, since it was added via add_middleware on the app).
_LOG_DIR = _PROJECT_ROOT / "logs" / "tasks"
_LOG_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/logs/tasks", StaticFiles(directory=str(_LOG_DIR)), name="task_logs")

# Routers
app.include_router(pages.router)
app.include_router(programs.router)
app.include_router(system.router)
app.include_router(tasks.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)