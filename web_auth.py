"""Dashboard login: username/password (argon2id) with signed cookie sessions.

Browsers log in through /login. Programmatic /api/* clients may still send the
API key (X-API-Key header or ?api_key=) when API_KEY is set.
"""
import secrets
import sys
import threading
import time
from collections import deque
from html import escape
from urllib.parse import parse_qs, urlencode, urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config import config

_cfg = config()
DASHBOARD_USER = _cfg['DASHBOARD_USER'] or 'admin'
PASS_HASH = _cfg['DASHBOARD_PASS_HASH']
API_KEY = _cfg['API_KEY']
SESSION_TTL = int(_cfg['DASHBOARD_SESSION_TTL'] or 43200)
SECRET = _cfg['DASHBOARD_SECRET'] or secrets.token_hex(32)

PUBLIC_PATHS = {"/login", "/logout", "/healthz", "/favicon.ico"}
MAX_FAILURES = 5
FAILURE_WINDOW = 300

_hasher = PasswordHasher()
_failures = {}
_failures_lock = threading.Lock()


def _warn(message):
    print(f"\033[91m!!! WARNING: {message}\033[0m", file=sys.stderr, flush=True)


if not _cfg['DASHBOARD_SECRET']:
    _warn("DASHBOARD_SECRET is not set; using a random per-process secret. "
          "Sessions reset on every restart. Set DASHBOARD_SECRET in .env (openssl rand -hex 32).")
if not PASS_HASH:
    _warn("DASHBOARD_PASS_HASH is not set; browser login is disabled. "
          "Run scripts/set_dashboard_password.py --write.")


def _verify_login(username, password):
    user_ok = secrets.compare_digest(username.encode(), DASHBOARD_USER.encode())
    pass_ok = False
    if PASS_HASH:
        try:
            pass_ok = _hasher.verify(PASS_HASH, password)
        except (VerificationError, VerifyMismatchError, InvalidHashError):
            pass_ok = False
    return user_ok and pass_ok


def _prune_failures_locked(now):
    cutoff = now - FAILURE_WINDOW
    for ip in list(_failures):
        attempts = _failures[ip]
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if not attempts:
            del _failures[ip]


def _retry_after(ip, now):
    """Seconds until this IP may try again, or 0 when it is allowed."""
    with _failures_lock:
        _prune_failures_locked(now)
        attempts = _failures.get(ip)
        if attempts and len(attempts) >= MAX_FAILURES:
            oldest_blocking = attempts[len(attempts) - MAX_FAILURES]
            return int(oldest_blocking + FAILURE_WINDOW - now) + 1
        return 0


def _record_failure(ip, now):
    with _failures_lock:
        _prune_failures_locked(now)
        _failures.setdefault(ip, deque()).append(now)


def _is_logged_in(session):
    if session.get("user") != DASHBOARD_USER:
        return False
    ts = session.get("ts")
    return isinstance(ts, int) and time.time() - ts <= SESSION_TTL


def _api_key_ok(request):
    if not API_KEY:
        return False
    key = request.headers.get("X-API-Key") or request.query_params.get("api_key") or ""
    return secrets.compare_digest(key.encode(), API_KEY.encode())


def _is_public(path):
    return path in PUBLIC_PATHS or path == "/static" or path.startswith("/static/")


def _wants_json(request):
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


def _safe_next(value):
    if (not value or not value.startswith("/") or value.startswith("//")
            or value.startswith("/\\") or any(ord(c) < 32 for c in value)):
        return "/"
    if urlsplit(value).path in {"/login", "/logout"}:
        return "/"
    return value


LOGIN_CSS = """
<style>
  .login { max-width:340px; margin:70px auto; padding:24px 26px; border:1px solid #30363d;
           border-radius:8px; background:#161b22; }
  .login h1 { margin-top:0; }
  .login label { display:block; color:#8b949e; font-size:13px; margin:14px 0 4px; }
  .login input { width:100%; box-sizing:border-box; padding:9px 10px; background:#0d1117;
                 color:#e6edf3; border:1px solid #30363d; border-radius:6px; font-size:15px; }
  .login input:focus { outline:none; border-color:#58a6ff; }
  .login button { margin-top:20px; width:100%; padding:10px; background:#1f6feb; color:white;
                  border:none; border-radius:6px; font-size:15px; cursor:pointer; }
  .login button:hover { background:#388bfd; }
  .login .err { color:#ff6b6b; margin:12px 0 0; }
</style>
"""


def _login_page(page_css, next_url, username="", error=None):
    error_html = f'<p class="err">{escape(error)}</p>' if error else ""
    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'><title>Watch login</title>{page_css}{LOGIN_CSS}</head>
<body><form class="login" method="post" action="/login">
<h1>Watch</h1>
<label for="username">Username</label>
<input id="username" name="username" value="{escape(username)}" autocomplete="username" autofocus required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<input type="hidden" name="next" value="{escape(next_url)}">
<button type="submit">Sign in</button>
{error_html}
</form></body></html>"""


def register_auth_routes(app, page_css):
    async def login_form(request):
        next_url = _safe_next(request.query_params.get("next", "/"))
        if _is_logged_in(request.session):
            return RedirectResponse(next_url, status_code=303)
        return HTMLResponse(_login_page(page_css, next_url))

    async def login_submit(request):
        form = parse_qs((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        next_url = _safe_next(form.get("next", ["/"])[0])
        ip = request.client.host if request.client else "unknown"

        retry = _retry_after(ip, time.time())
        if retry:
            return HTMLResponse(
                _login_page(page_css, next_url, username,
                            f"Too many failed attempts. Try again in {retry} seconds."),
                status_code=429,
                headers={"Retry-After": str(retry)},
            )

        if _verify_login(username, password):
            request.session.clear()
            request.session["user"] = DASHBOARD_USER
            request.session["ts"] = int(time.time())
            return RedirectResponse(next_url, status_code=303)

        _record_failure(ip, time.time())
        return HTMLResponse(
            _login_page(page_css, next_url, username, "Invalid credentials"),
            status_code=401,
        )

    async def logout(request):
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    app.add_route("/login", login_form, methods=["GET"], include_in_schema=False)
    app.add_route("/login", login_submit, methods=["POST"], include_in_schema=False)
    app.add_route("/logout", logout, methods=["GET"], include_in_schema=False)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path
        if _is_public(path):
            return await call_next(request)
        if path.startswith("/api/") and _api_key_ok(request):
            return await call_next(request)
        if _is_logged_in(request.session):
            return await call_next(request)
        if path.startswith("/api/") or _wants_json(request):
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        target = path + (f"?{request.url.query}" if request.url.query else "")
        return RedirectResponse("/login?" + urlencode({"next": target}), status_code=303)
