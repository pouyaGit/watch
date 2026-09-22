"""backend/research_agents/agents — specialist research agents (Part 4).

The v2 suite ships five ready specialists, each with a research strategy,
evidence requirements, a confidence model and a report format:

- XSS           ``xss_agent``
- IDOR / BOLA   ``idor_agent``
- SSRF          ``ssrf_agent``
- File upload   ``upload_agent``
- AuthZ         ``authz_agent``
"""

from __future__ import annotations

from backend.research_agents.agents.common import (
    confidence_for,
    is_api_endpoint,
    is_file_parameter,
    is_identifier,
    is_privileged_endpoint,
    is_stateful,
    is_url_parameter,
    report_section,
)
from backend.research_agents.agents import (
    authz_agent,
    idor_agent,
    ssrf_agent,
    upload_agent,
    xss_agent,
)

IDOR_KEY = idor_agent.KEY
XSS_KEY = xss_agent.KEY
SSRF_KEY = ssrf_agent.KEY
UPLOAD_KEY = upload_agent.KEY
AUTHZ_KEY = authz_agent.KEY

analyze_idor = idor_agent.analyze
analyze_xss = xss_agent.analyze
analyze_ssrf = ssrf_agent.analyze
analyze_upload = upload_agent.analyze
analyze_authz = authz_agent.analyze

AGENT_MODULES = {
    xss_agent.KEY: xss_agent,
    idor_agent.KEY: idor_agent,
    ssrf_agent.KEY: ssrf_agent,
    upload_agent.KEY: upload_agent,
    authz_agent.KEY: authz_agent,
}

__all__ = [
    "confidence_for",
    "is_identifier",
    "is_api_endpoint",
    "is_stateful",
    "is_file_parameter",
    "is_url_parameter",
    "is_privileged_endpoint",
    "report_section",
    "XSS_KEY",
    "IDOR_KEY",
    "SSRF_KEY",
    "UPLOAD_KEY",
    "AUTHZ_KEY",
    "analyze_xss",
    "analyze_idor",
    "analyze_ssrf",
    "analyze_upload",
    "analyze_authz",
    "AGENT_MODULES",
]
