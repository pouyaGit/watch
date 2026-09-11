"""External read-only client for the Watch Product API v1 (Stage R28.2).

Communicates ONLY over HTTP. This module imports only the Python standard
library plus its sibling contract module — it NEVER imports Watch internals
(``backend.*``, ``ai.knowledge.*``, ``ai.schemas.*``). Tests inject a fake
transport; the default transport uses the stdlib ``urllib`` HTTP client.

Security:
- the API key is read from an argument or environment variable and sent as
  the ``X-API-Key`` header only;
- the API key is never logged, printed, embedded in URLs, or included in any
  raised exception message;
- only Product API v1 fields are accepted; the contract validator rejects
  unknown/target/credential/payout/execution fields.

The client is read-only: it issues GET requests only.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from clients import product_api_contract as contract

DEFAULT_API_KEY_ENV = "WATCH_PRODUCT_API_KEY"
DEFAULT_TIMEOUT = 10.0

TransportResult = tuple[int, str]
Transport = Callable[[str, str, dict, float], TransportResult]


class ProductAPIClientError(Exception):
    """Base class for external client errors (never contains the API key)."""


class ProductAPITimeoutError(ProductAPIClientError):
    """The HTTP request timed out."""


class ProductAPIConnectionError(ProductAPIClientError):
    """The server could not be reached."""


class ProductAPIAuthError(ProductAPIClientError):
    """HTTP 401 — the configured API key was missing or invalid."""


class ProductAPINotFoundError(ProductAPIClientError):
    """HTTP 404 — the requested research opportunity does not exist."""


class ProductAPIRequestError(ProductAPIClientError):
    """HTTP 4xx (other than 401/404) — the request was rejected."""


class ProductAPIServerError(ProductAPIClientError):
    """HTTP 5xx — the server failed to answer."""


class ProductAPIContractError(ProductAPIClientError):
    """The response was not valid JSON or violated the public v1 contract."""


def _default_transport(method: str, url: str, headers: dict,
                       timeout: float) -> TransportResult:
    """Stdlib urllib transport (GET only by design)."""

    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return int(getattr(response, "status", 200)), body
    except urllib.error.HTTPError as exc:  # 4xx/5xx carry a body
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return int(exc.code), body
    except (TimeoutError, socket.timeout):
        raise ProductAPITimeoutError("request timed out") from None
    except urllib.error.URLError as exc:
        if isinstance(getattr(exc, "reason", None),
                      (TimeoutError, socket.timeout)):
            raise ProductAPITimeoutError("request timed out") from None
        raise ProductAPIConnectionError("could not reach the API server") \
            from None


class ProductAPIClient:
    """Read-only client for the Watch Product API v1."""

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        api_key_env: str = DEFAULT_API_KEY_ENV,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Optional[Transport] = None,
    ) -> None:
        text = str(base_url or "").strip().rstrip("/")
        if not text:
            raise ProductAPIClientError("base_url is required")
        self.base_url = text
        self.timeout = float(timeout)
        self._api_key = api_key if api_key else os.environ.get(api_key_env)
        self._transport: Transport = transport or _default_transport

    # -- introspection (never reveals the key) -----------------------------
    @property
    def api_key_configured(self) -> bool:
        return bool(self._api_key)

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return (f"ProductAPIClient(base_url={self.base_url!r}, "
                f"api_key_configured={self.api_key_configured})")

    # -- HTTP --------------------------------------------------------------
    def _build_url(self, path: str, params: dict) -> str:
        clean = {k: v for k, v in params.items() if v is not None}
        query = urllib.parse.urlencode(clean)
        url = f"{self.base_url}{path}"
        return f"{url}?{query}" if query else url

    def _request(self, path: str, params: Optional[dict] = None) -> Any:
        url = self._build_url(path, params or {})
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        try:
            status, body = self._transport("GET", url, headers, self.timeout)
        except ProductAPIClientError:
            raise
        except Exception:
            raise ProductAPIConnectionError(
                "could not reach the API server") from None

        if status == 401:
            raise ProductAPIAuthError(
                "authentication failed (check the configured API key)")
        if status == 404:
            raise ProductAPINotFoundError("research opportunity not found")
        if 400 <= status < 500:
            raise ProductAPIRequestError(
                f"request rejected with HTTP {status}")
        if status >= 500:
            raise ProductAPIServerError(
                f"server error with HTTP {status}")

        try:
            payload = json.loads(body) if body else {}
        except ValueError:
            raise ProductAPIContractError("malformed JSON response") from None
        return payload

    def _validated(self, path: str, params: Optional[dict], validator) -> Any:
        payload = self._request(path, params)
        try:
            return validator(payload)
        except contract.ContractError as exc:
            raise ProductAPIContractError(str(exc)) from None

    # -- endpoints ---------------------------------------------------------
    def list_opportunities(
        self,
        limit: int = 50,
        offset: int = 0,
        cve: Optional[str] = None,
        program: Optional[str] = None,
        opportunity_class: Optional[str] = None,
        action: Optional[str] = None,
        status: Optional[str] = None,
        min_money_score: Optional[int] = None,
    ) -> dict:
        params = {
            "limit": limit,
            "offset": offset,
            "cve": cve,
            "program": program,
            "class": opportunity_class,
            "action": action,
            "status": status,
            "min_money_score": min_money_score,
        }
        return self._validated("/api/v1/opportunities", params,
                               contract.validate_list_envelope)

    def get_opportunity(self, lead_id: str) -> dict:
        lead_id = str(lead_id or "").strip()
        if not lead_id:
            raise ProductAPIRequestError("lead_id is required")
        return self._validated(
            f"/api/v1/opportunities/{urllib.parse.quote(lead_id)}", None,
            contract.validate_detail)

    def get_summary(self) -> dict:
        return self._validated("/api/v1/opportunities/summary", None,
                               contract.validate_summary)

    def get_research_status(self) -> dict:
        return self._validated("/api/v1/research/status", None,
                               contract.validate_research_status)

    def get_error_envelope(self, payload: Any) -> dict:
        """Validate a v1 error envelope helper (used by callers/tests)."""

        try:
            return contract.validate_error_envelope(payload)
        except contract.ContractError as exc:
            raise ProductAPIContractError(str(exc)) from None
