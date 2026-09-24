"""EPIC13 test fixtures — offline, deterministic, no network.

Everything here is in-memory.  The "transport" is a plain callable, which is
the platform's own offline seam (the platform's live executor is switched off),
so the acquisition machinery is exercised for real without a single packet.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from backend.research_agents.verification import actions as ac  # noqa: E402
from backend.research_agents.verification import engine as en  # noqa: E402
from backend.research_agents.verification.acquisition import (  # noqa: E402
    markers as mk, transport as tr)

CANDIDATE_ID = "cand-7c229c48c455"
OBJECTIVE_ID = "vo-epic13-1"
SCOPE_REF = "watch:scope:dell/www.dell.com"
TARGET_URL = "https://www.dell.com/support/search?q=test&page=2"
PARAMETER = "q"
AUTH_ID = "authz-epic13-1"

#: an authorization covering the acquisition actions for this target.
AUTHORIZATION = {
    "authorization_ids": [AUTH_ID],
    "action_types": [ac.SEND_MARKER, ac.CHECK_REFLECTION,
                     ac.CLASSIFY_REFLECTION_CONTEXT],
    "scope_ref": SCOPE_REF,
}

#: parameter-inventory-only evidence (the real candidate's shape).
def inventory_rows() -> list[dict]:
    return [{
        "id": "ev-inv-1", "type": "observation",
        "signal": "xss_parameter_inventory", "category": "XSS",
        "detail": "parameter q observed on the target",
        "observation_ref": "obs-inv-1", "evidence_type": "PARAMETER_OBSERVED",
    }]


def parameters(url: str = TARGET_URL, name: str = PARAMETER,
               method: str = "GET") -> list[dict]:
    return [{"parameter": name, "url": url, "method": method}]


def chain_state(rows: list[dict] | None = None):
    """The real EPIC12 chain state for the given rows."""
    return en.evaluate_chain("XSS", list(rows if rows is not None
                                         else inventory_rows()))


def marker_for_action(action_type: str = ac.SEND_MARKER,
                      parameter: str = PARAMETER,
                      candidate_id: str = CANDIDATE_ID,
                      objective_id: str = OBJECTIVE_ID,
                      attempt: int = 1) -> str:
    """The marker the planner will use for one action (same derivation)."""
    action_id = ac.action_id_for(candidate_id=candidate_id,
                                 objective_id=objective_id,
                                 action_type=action_type, attempt=attempt,
                                 salt=parameter)
    return mk.marker_for(action_id, parameter, attempt)


class RecordingTransport:
    """A transport callable that records what it was asked to send."""

    def __init__(self, body: str | None = None, *, status_code: int = 200,
                 headers: dict | None = None,
                 outcome: str = tr.OUTCOME_RESPONDED, truncated: bool = False,
                 redirects: list | None = None, delay: float = 0.0,
                 raises: BaseException | None = None,
                 body_from_request: bool = False) -> None:
        self.body = body
        self.status_code = status_code
        self.headers = dict(headers or {"content-type": "text/html"})
        self.outcome = outcome
        self.truncated = truncated
        self.redirects = list(redirects or [])
        self.delay = delay
        self.raises = raises
        self.body_from_request = body_from_request
        self.requests: list = []

    def __call__(self, request):
        self.requests.append(request)
        if self.raises is not None:
            raise self.raises
        body = self.body
        if self.body_from_request and body is None:
            body = f"<html><body><p>{request.marker}</p></body></html>"
        return tr.AcquisitionResponse(
            outcome=self.outcome, status_code=self.status_code, body=body,
            headers=dict(self.headers), truncated=self.truncated,
            redirects=list(self.redirects), response_ref="resp-epic13-1",
            final_url=request.url, bytes_received=len(body or ""))

    @property
    def called(self) -> int:
        return len(self.requests)

    @property
    def last_marker(self) -> str:
        return str(self.requests[-1].marker) if self.requests else ""

    @property
    def last_url(self) -> str:
        return str(self.requests[-1].url) if self.requests else ""


class ReplayStub:
    """A minimal replay ledger double (records lookups and writes)."""

    def __init__(self, hit: dict | None = None) -> None:
        self.hit = hit
        self.lookups: list[str] = []
        self.records: list[dict] = []

    def lookup(self, fingerprint: str):
        self.lookups.append(fingerprint)
        return self.hit

    def record(self, **row):
        self.records.append(row)
        return row

    def report(self):
        return {"entries": len(self.records), "reusable": len(self.records)}


class BudgetStub:
    """A budget double that can refuse one resource."""

    def __init__(self, *, refuse: str = "", limits: dict | None = None) -> None:
        self.refuse = refuse
        self.limits = dict(limits or {"max_actions": 3, "max_requests": 3,
                                      "max_observations": 12})
        self.consumed: list[str] = []

    def ensure(self, resource: str, delta: int = 1, *, reason: str = "") -> None:
        if resource == self.refuse:
            raise RuntimeError(f"{resource} exhausted")
        self.consumed.append(resource)

    def allow(self, resource: str, delta: int = 1) -> bool:
        return resource != self.refuse

    def report(self):
        return {"limits": dict(self.limits), "used": {}}


def body_with(marker: str, *, context: str = "text") -> str:
    """A response body that reflects the marker in a chosen context."""
    if context == "text":
        return f"<html><body><p>results for {marker}</p></body></html>"
    if context == "attribute":
        return f'<html><body><div data-q="{marker}">x</div></body></html>'
    if context == "url":
        return f'<html><body><a href="/next?q={marker}">next</a></body></html>'
    if context == "script":
        return f'<html><body><script>var q="{marker}";</script></body></html>'
    if context == "style":
        return f"<html><head><style>/* {marker} */</style></head></html>"
    if context == "comment":
        return f"<html><body><!-- {marker} --></body></html>"
    if context == "json":
        return (f'<html><body><script type="application/json">'
                f'{{"q":"{marker}"}}</script></body></html>')
    return f"<html><body>{marker}</body></html>"
