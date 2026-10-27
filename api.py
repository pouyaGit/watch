#!/usr/bin/env python3
"""Watch dashboard and JSON API. Routes live in backend/routers; this module wires them together.

Run: python3 api.py   (or via the watch-api systemd service)
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from backend.helpers import PAGE_CSS
from backend.routers import data_api, pages, targets, tasks, vault
from backend.tasks_registry import PROJECT_ROOT
from web_auth import AuthMiddleware, SECRET, SESSION_TTL, register_auth_routes

app = FastAPI(title="Watch API")
# Starlette runs the last-added middleware first, so SessionMiddleware wraps
# AuthMiddleware and request.session is populated before the auth check reads it.
app.add_middleware(AuthMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SECRET, same_site="lax", max_age=SESSION_TTL)
register_auth_routes(app, PAGE_CSS)
app.mount("/static", StaticFiles(directory=f"{PROJECT_ROOT}/web/static"), name="static")
app.include_router(pages.router)
app.include_router(targets.router)
app.include_router(tasks.router)
app.include_router(data_api.router)
app.include_router(vault.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
