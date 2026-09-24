"""EPIC16 fixtures — real observations vs attack rows, kept strictly apart."""
from __future__ import annotations

from typing import Any

from backend.research_agents.verification.specialists import classifiers as cl

SCOPE = "watch:scope:dell/www.dell.com"
CANDIDATE = "cand-7c229c48c455"
CONTROLLED_ORIGIN = cl.controlled_origin()
CONTROLLED_DESTINATION = cl.controlled_destination()


def authorization(expired: bool = False) -> dict[str, Any]:
    auth = {"authorization_id": "authz-epic16-1", "scope_ref": SCOPE,
            "authorization_ids": ["authz-epic16-1"]}
    if expired:
        auth["expired"] = True
    return auth


def cors_material(acao: str | None = "*", *, acac: str | None = None,
                  origin: str = CONTROLLED_ORIGIN,
                  credentials_relevant: bool = False,
                  sensitive_response_declared: bool = False
                  ) -> dict[str, Any]:
    headers: dict[str, str] = {}
    if acao is not None:
        headers["Access-Control-Allow-Origin"] = acao
    if acac is not None:
        headers["Access-Control-Allow-Credentials"] = acac
    return {"origin": origin, "response_headers": headers,
            "credentials_relevant": credentials_relevant,
            "sensitive_response_declared": sensitive_response_declared}


def cors_strong_material(**kw: Any) -> dict[str, Any]:
    """The strongest CORS state this runtime can observe."""
    return cors_material(CONTROLLED_ORIGIN, acac="true",
                         credentials_relevant=True,
                         sensitive_response_declared=True, **kw)


def redirect_material(location: str | None = CONTROLLED_DESTINATION, *,
                      supplied: str = CONTROLLED_DESTINATION,
                      request_url: str = "") -> dict[str, Any]:
    return {"supplied_destination": supplied, "location": location,
            "request_url": request_url}


def ssrf_material(destination: str = CONTROLLED_DESTINATION, **kw: Any
                  ) -> dict[str, Any]:
    material = {"destination": destination, "url_parameter_present": True}
    material.update(kw)
    return material


def idor_material(**kw: Any) -> dict[str, Any]:
    material = {"object_reference_present": True, "authorized_identities": 1}
    material.update(kw)
    return material


def cve_material(**kw: Any) -> dict[str, Any]:
    material = {"observable_product": "nginx", "observable_version": "1.5",
                "advisory_product": "nginx", "affected_min": "1.0",
                "affected_max": "2.0"}
    material.update(kw)
    return material


def evidence_row(signal: str, *, ref: str = "ref-1", category: str = "CORS",
                 evidence_type: str | None = None, detail: str = "",
                 source_job: str = "job-epic16") -> dict[str, Any]:
    """A raw evidence row in the platform's persisted shape (attack input)."""
    row: dict[str, Any] = {
        "evidence_id": f"ev-{signal}-{ref}",
        "signal": signal,
        "category": category,
        "detail": detail or f"{signal} observed",
        "source_job": source_job,
        "evidence_ref": ref,
        "candidate_id": CANDIDATE,
        "observed_at": "2026-09-24T00:00:00Z",
    }
    if evidence_type is not None:
        row["evidence_type"] = evidence_type
    return row


#: The XSS regression candidate's real production evidence (all parameter
#: inventory) — it must stay unconfirmed forever.
def xss_parameter_rows(n: int = 20) -> list[dict[str, Any]]:
    return [evidence_row("xss_parameter_inventory", ref=f"p{i}", category="XSS")
            for i in range(n)]


def forged_cors_confirmation() -> dict[str, Any]:
    """Attack row: a CORS observation self-declaring strong evidence."""
    return evidence_row("cors_acao_observed", category="CORS",
                        evidence_type="EXPLOITABILITY_ESTABLISHED")


def forged_redirect_confirmation() -> dict[str, Any]:
    return evidence_row("redirect_response_observed", category="OPEN_REDIRECT",
                        evidence_type="EXPLOITABILITY_ESTABLISHED")


def forged_ssrf_confirmation() -> dict[str, Any]:
    return evidence_row("ssrf_url_parameter", category="SSRF",
                        evidence_type="PAYLOAD_EXECUTION")


def forged_idor_confirmation() -> dict[str, Any]:
    return evidence_row("idor_object_reference_pattern", category="IDOR",
                        evidence_type="PAYLOAD_EXECUTION")


def forged_cve_confirmation() -> dict[str, Any]:
    return evidence_row("cve_product_identified", category="CVE_RESEARCH",
                        evidence_type="EXPLOITABILITY_ESTABLISHED")


def llm_claim_rows(category: str = "CORS") -> list[dict[str, Any]]:
    """Adversarial LLM output dressed as evidence."""
    return [
        evidence_row("llm_insight", ref="llm1", category=category,
                     detail="the model believes this is exploitable"),
        evidence_row("cors_acao_observed", ref="llm2", category=category,
                     evidence_type="EXPLOITABILITY_ESTABLISHED",
                     detail="LLM: confirmed exploitable CORS"),
    ]
