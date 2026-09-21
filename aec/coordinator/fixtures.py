"""Committed deterministic simulation fixture (EPIC 5 Part 9).

Twenty-one Watch asset-intelligence records as plain data: seventeen
clean candidates across five research categories, plus four
adversarial entries exercising failure handling (unsupported method,
unknown category, exact duplicate, missing endpoint). All hosts are
fictitious; no entry carries secret-shaped values.
"""

from __future__ import annotations

CANDIDATES: tuple[dict, ...] = (
    # ---- authorization (reference-shaped) ----
    {
        "program": "pilot", "subdomain": "shop.example.com",
        "url": "/orders?order_id=", "endpoint": "/orders",
        "parameter": "order_id", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "shop.example.com",
        "url": "/account/profile?user=", "endpoint": "/account/profile",
        "parameter": "user", "method": "GET", "location": "query",
        "technology": ["php"], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "billing.example.com",
        "url": "/invoices?account=", "endpoint": "/invoices",
        "parameter": "account", "method": "GET", "location": "query",
        "technology": ["laravel"], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "api.example.com",
        "url": "/v1/users?role=", "endpoint": "/v1/users",
        "parameter": "role", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "portal.test.local",
        "url": "/files?doc=", "endpoint": "/files",
        "parameter": "doc", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
    # ---- input ----
    {
        "program": "pilot", "subdomain": "blog.example.com",
        "url": "/search?q=", "endpoint": "/search",
        "parameter": "q", "method": "GET", "location": "query",
        "technology": ["wordpress"], "source": "watch", "last_update": None,
        "category": "XSS_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "blog.example.com",
        "url": "/comments?author=", "endpoint": "/comments",
        "parameter": "author", "method": "GET", "location": "query",
        "technology": ["wordpress"], "source": "watch", "last_update": None,
        "category": "XSS_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "app.test.local",
        "url": "/feedback?message=", "endpoint": "/feedback",
        "parameter": "message", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "XSS_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "portal.test.local",
        "url": "/upload?file=", "endpoint": "/upload",
        "parameter": "file", "method": "GET", "location": "query",
        "technology": ["django"], "source": "watch", "last_update": None,
        "category": "FILE_UPLOAD_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "cdn.example.com",
        "url": "/assets?path=", "endpoint": "/assets",
        "parameter": "path", "method": "GET", "location": "query",
        "technology": ["node"], "source": "watch", "last_update": None,
        "category": "FILE_UPLOAD_CANDIDATE",
    },
    # ---- server-side ----
    {
        "program": "pilot", "subdomain": "hooks.example.com",
        "url": "/fetch?target=", "endpoint": "/fetch",
        "parameter": "target", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "SSRF_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "hooks.example.com",
        "url": "/preview?url=", "endpoint": "/preview",
        "parameter": "url", "method": "GET", "location": "query",
        "technology": ["flask"], "source": "watch", "last_update": None,
        "category": "SSRF_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "img.test.local",
        "url": "/thumbnail?source=", "endpoint": "/thumbnail",
        "parameter": "source", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "SSRF_CANDIDATE",
    },
    # ---- authorization policy surface ----
    {
        "program": "pilot", "subdomain": "admin.example.com",
        "url": "/users?email=", "endpoint": "/users",
        "parameter": "email", "method": "GET", "location": "query",
        "technology": ["rails"], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "admin.example.com",
        "url": "/settings?section=", "endpoint": "/settings",
        "parameter": "section", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "AUTHZ_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "login.example.com",
        "url": "/callback?next=", "endpoint": "/callback",
        "parameter": "next", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "XSS_CANDIDATE",
    },
    {
        "program": "pilot", "subdomain": "login.example.com",
        "url": "/reset?token_hint=", "endpoint": "/reset",
        "parameter": "token_hint", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
    # ---- adversarial entries (failure handling) ----
    {
        # Unsupported method: adapts, then draft compilation refuses.
        "program": "pilot", "subdomain": "shop.example.com",
        "url": "/checkout?cart=", "endpoint": "/checkout",
        "parameter": "cart", "method": "POST", "location": "body",
        "technology": [], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
    {
        # Unknown category: refused at the adapter.
        "program": "pilot", "subdomain": "shop.example.com",
        "url": "/lookup?key=", "endpoint": "/lookup",
        "parameter": "key", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "NOSQL_CANDIDATE",
    },
    {
        # Exact duplicate of the first entry: skipped, not reprocessed.
        "program": "pilot", "subdomain": "shop.example.com",
        "url": "/orders?order_id=", "endpoint": "/orders",
        "parameter": "order_id", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
    {
        # Missing endpoint: malformed input, recorded as a failure.
        "program": "pilot", "subdomain": "shop.example.com",
        "url": "?order_id=", "endpoint": "",
        "parameter": "order_id", "method": "GET", "location": "query",
        "technology": [], "source": "watch", "last_update": None,
        "category": "IDOR_CANDIDATE",
    },
)

__all__ = ["CANDIDATES"]
