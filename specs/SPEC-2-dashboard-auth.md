# SPEC 2 — Username & Password authentication for the dashboard (port 5000)

**Target project:** `/opt/watch`, FastAPI app in `api.py`, served by uvicorn on
`0.0.0.0:5000` (`api.py` `__main__` → `uvicorn.run(app, host="0.0.0.0", port=5000)`).
**Executor:** implement exactly as written.

---

## 1. Goal

Put the dashboard behind a **username + password login** with server-side
sessions (signed cookie), replacing the "anyone-with-the-link" model. Today
`api.py` has an `APIKeyMiddleware` that only checks `API_KEY` (header
`X-API-Key` or `?api_key=`) and is a **no-op when `API_KEY` is empty** — which it
currently is. After this change, a browser must log in; programmatic `/api/*`
clients may still use the API key.

---

## 2. Current state (read before editing)

In `api.py`:
```python
API_KEY = config().get("API_KEY", "")
EXEMPT_PATHS = {"/docs", "/redoc", "/openapi.json"}
class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not API_KEY or request.url.path in EXEMPT_PATHS: ...
        key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
        if key != API_KEY: return JSONResponse({...}, status_code=401)
app.add_middleware(APIKeyMiddleware)
```
`config()` comes from `config.py` and reads `.env` via python-dotenv.

---

## 3. Deliverables

1. New module `web_auth.py` (project root) — password hashing, session helpers,
   login/logout routes factory, and the combined auth middleware.
2. Edits to `api.py` — wire in the new middleware + routes, keep API-key access
   for `/api/*` only.
3. New CLI `scripts/set_dashboard_password.py` — generate/set the password hash.
4. `.env` / `.env.example` additions (see §6).
5. Add `itsdangerous>=2.1` and `argon2-cffi>=23.1` to `requirements.txt`.

---

## 4. Auth model

### 4.1 Credentials storage
- Username: env `DASHBOARD_USER` (default `admin`).
- Password: stored **only as a hash** in env `DASHBOARD_PASS_HASH` (argon2id via
  `argon2-cffi` `PasswordHasher`). Never store the plaintext anywhere.
- Session signing secret: env `DASHBOARD_SECRET` (required; if unset, generate a
  random 32-byte hex at startup, log a loud warning that sessions reset on
  restart, and use it for this process only).

### 4.2 Sessions
- Use **Starlette `SessionMiddleware`** (`from starlette.middleware.sessions
  import SessionMiddleware`) with `secret_key=DASHBOARD_SECRET`,
  `https_only=False`, `same_site="lax"`, `max_age=DASHBOARD_SESSION_TTL`
  (default `43200` sec = 12h).
- On successful login set `request.session["user"] = username` and
  `request.session["ts"] = <epoch>`.
- Logout clears the session.

### 4.3 Access policy (middleware `AuthMiddleware`, replaces `APIKeyMiddleware`)
Order of checks per request:
1. Path is in `PUBLIC_PATHS` (`/login`, `/logout`, `/static`, `/healthz`,
   `/favicon.ico`) → allow.
2. Path starts with `/api/` AND a valid `X-API-Key`/`?api_key=` matching a
   non-empty `API_KEY` → allow (programmatic clients, backward compatible).
3. `request.session.get("user")` is set and not expired → allow.
4. Otherwise:
   - For `/api/*` or any request whose `Accept` header prefers JSON → `401 JSON`.
   - For HTML/browser requests → `303` redirect to `/login?next=<path>`.
- `/docs`, `/redoc`, `/openapi.json`: require a logged-in session (do NOT leave
  them public). They are NOT in `PUBLIC_PATHS`.

### 4.4 Login routes
- `GET /login` → a clean, dark-themed HTML login form (username, password, hidden
  `next`). Matches the dashboard's visual style (reuse `PAGE_CSS` from `api.py`).
  If already logged in, redirect to `next` or `/`.
- `POST /login` (form-encoded `username,password,next`):
  - Verify username == `DASHBOARD_USER` AND argon2 `verify(hash, password)`.
  - On success: set session, `303` redirect to a **safe** local `next`
    (must start with `/` and not `//` — otherwise `/`).
  - On failure: re-render login with a generic "Invalid credentials" error and
    HTTP 401. Do NOT reveal which field was wrong.
  - **Rate limit**: in-memory sliding window per client IP — max 5 failed
    attempts per 5 minutes, then 429 with a `Retry-After`. (Simple dict keyed by
    IP; prune on access. No external store.)
- `GET /logout` → clear session, redirect to `/login`.

### 4.5 Password CLI (`scripts/set_dashboard_password.py`)
```
python scripts/set_dashboard_password.py            # prompts for a password (getpass), prints the hash line
python scripts/set_dashboard_password.py --write     # same, but appends/updates DASHBOARD_PASS_HASH in /opt/watch/.env
```
- Uses argon2 `PasswordHasher().hash(pw)`.
- Prints exactly: `DASHBOARD_PASS_HASH=<hash>` so it can be pasted into `.env`.
- `--write` must preserve all other `.env` lines and replace only the hash line
  (create it if absent).

---

## 5. Required edits to `api.py` (minimal, surgical)
- Remove `app.add_middleware(APIKeyMiddleware)` and the `APIKeyMiddleware` class
  usage; instead:
  ```python
  from starlette.middleware.sessions import SessionMiddleware
  from web_auth import AuthMiddleware, register_auth_routes, SECRET
  app.add_middleware(AuthMiddleware)          # outer: authz
  app.add_middleware(SessionMiddleware, secret_key=SECRET, same_site="lax",
                     max_age=SESSION_TTL)     # inner: provides request.session
  register_auth_routes(app)                   # adds /login, /logout
  ```
  (Middleware added later runs first; ensure `SessionMiddleware` populates
  `request.session` before `AuthMiddleware` reads it — verify ordering at
  implementation time and add a comment.)
- Keep `API_KEY` logic available for `/api/*` as described in §4.3.
- `build_url()` currently appends `?api_key=`. Change it so links no longer leak
  the API key in the browser (session auth covers the browser). If `API_KEY` is
  set, still support it for `/api/*`, but UI links must not carry it.

---

## 6. Config additions (`.env` and `.env.example`)

```
DASHBOARD_USER=admin
DASHBOARD_PASS_HASH=            # set via scripts/set_dashboard_password.py
DASHBOARD_SECRET=              # openssl rand -hex 32
DASHBOARD_SESSION_TTL=43200
# API_KEY stays for programmatic /api access (optional)
```
`config.py` `config()` must expose these keys (extend the returned dict).

---

## 7. Acceptance criteria & tests
1. With `DASHBOARD_PASS_HASH` set, `GET /` while logged out → `303` to `/login`.
2. `POST /login` with correct creds → session cookie set, `GET /` → `200`.
3. `POST /login` with wrong creds → `401`, generic error, no session.
4. 6th failed login within 5 min from one IP → `429`.
5. `GET /logout` → session cleared, `/` redirects to `/login` again.
6. `GET /api/stats` with a valid `X-API-Key` (and `API_KEY` set) → `200` without
   a session (programmatic path still works).
7. `GET /api/stats` with neither session nor key → `401 JSON`.
8. `/docs` requires login (no longer public).
9. `python -m py_compile api.py web_auth.py scripts/set_dashboard_password.py` clean.
10. Plaintext password never written to disk or logs; only the argon2 hash.

## 8. Hard constraints
- Do not break the existing JSON `/api/*` contracts or HTML routes beyond auth.
- No plaintext password storage. No hardcoded default password.
- Keep it dependency-light (argon2-cffi + itsdangerous/starlette only).
