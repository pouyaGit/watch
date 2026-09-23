"""Shared fixtures for EPIC9 AI operations tests.

Every test runs chdir'ed into a fresh tmp dir so the stores'
CWD-relative layout (``ai_data/...``) is fully isolated — the same
pattern as ``prod_intel_fixtures``.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from typing import Any

SCOPE = "watch:scope:www.example.com"
OTHER_SCOPE = "watch:scope:other.example.com"
NOW = datetime(2026, 9, 23, 14, 30, tzinfo=timezone.utc)  # 18:00 Tehran


class AiOpsEnvMixin(unittest.TestCase):
    """Isolated cwd + scrubbed WATCH_AI_OPS_* env."""

    def setUp(self) -> None:  # noqa: D102
        super().setUp()
        self._old_cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="aiops-test-")
        os.chdir(self._tmp)
        self._saved_env: dict[str, str] = {}
        for key in list(os.environ):
            if key.startswith("WATCH_AI_OPS_"):
                self._saved_env[key] = os.environ.pop(key)

    def tearDown(self) -> None:  # noqa: D102
        os.chdir(self._old_cwd)
        shutil.rmtree(self._tmp, ignore_errors=True)
        for key, val in self._saved_env.items():
            os.environ[key] = val
        super().tearDown()

    # ------------------------------------------------------------ helpers
    def set_env(self, **kv: str) -> None:
        for key, val in kv.items():
            os.environ[key] = val

    @staticmethod
    def config(**overrides: Any):
        from backend.ai_ops.config import DispatcherConfig
        env = {f"WATCH_AI_OPS_{k.upper()}": str(v)
               for k, v in overrides.items()}
        return DispatcherConfig.from_env(env)

    @staticmethod
    def at(hour: int, minute: int = 0, day: int = 23, tz: str = "UTC"):
        from zoneinfo import ZoneInfo
        return datetime(2026, 9, day, hour, minute,
                        tzinfo=ZoneInfo(tz))


# ----------------------------------------------------------- job fixture
def make_job(job_id: str = "job-aiops-1", status: str = "QUEUED",
             program: str = "www", subdomain: str = "example.com",
             **kw: Any):
    """ResearchJob with only the fields every test needs."""
    from backend.research_agents.models import ResearchJob
    defaults: dict[str, Any] = dict(
        id=job_id, status=status, program=program, subdomain=subdomain,
        category=kw.pop("category", "XSS"), candidate_id="cand-x",
        endpoint=kw.pop("endpoint", ""),
        parameter=kw.pop("parameter", ""),
        priority_score=50, created_at="2026-09-23T10:00:00+00:00",
        updated_at="2026-09-23T10:00:00+00:00",
        attempt_count=0, max_attempts=3, timeout_seconds=120,
        lease_owner=kw.pop("lease_owner", ""),
        lease_expires_at=kw.pop("lease_expires_at", ""),
    )
    defaults.update(kw)
    return ResearchJob(**defaults)


# ----------------------------------------------------- campaign fixtures
def make_campaign(campaign_id: str = "camp-aiops-1",
                  state: str = "READY", scope_ref: str = SCOPE,
                  lease_owner: str = "", lease_expires_at: str = "",
                  **kw: Any):
    from backend.research_agents.campaign.models import Campaign
    defaults: dict[str, Any] = dict(
        campaign_id=campaign_id, program="www", scope_ref=scope_ref,
        campaign_objective=kw.pop("campaign_objective",
                                  "AI operations test objective"),
        target_context={"subdomain": "example.com"},
        participating_specialists=["xss-agent"],
        priority=50, state=state,
        created_at="2026-09-23T09:00:00+00:00",
        updated_at="2026-09-23T09:00:00+00:00",
        provenance={"source": "test"},
        lease_owner=lease_owner, lease_expires_at=lease_expires_at,
    )
    defaults.update(kw)
    return Campaign(**defaults)


def make_objective(campaign_id: str = "camp-aiops-1",
                   objective_id: str = "obj-aiops-1",
                   state: str = "READY", scope_ref: str = SCOPE,
                   priority: int = 50, attempts: int = 0,
                   updated_at: str = "2026-09-23T09:00:00+00:00",
                   **kw: Any):
    from backend.research_agents.campaign.models import CampaignObjective
    defaults: dict[str, Any] = dict(
        objective_id=objective_id, campaign_id=campaign_id,
        category="XSS", scope_ref=scope_ref,
        research_question="Is it vulnerable?",
        hypothesis="test hypothesis", priority=priority, state=state,
        attempts=attempts, created_at="2026-09-23T09:00:00+00:00",
        updated_at=updated_at,
    )
    defaults.update(kw)
    return CampaignObjective(**defaults)


# -------------------------------------------------------- hunt fixtures
def make_hunt(objective_id: str = "hobj-aiops-1",
              state: str = "OPEN", scope_ref: str = SCOPE,
              job_id: str = "job-aiops-1", priority: int = 50,
              **kw: Any):
    from backend.research_agents.hunt.models import HuntObjective
    defaults: dict[str, Any] = dict(
        objective_id=objective_id, job_id=job_id, specialist="xss-agent",
        category="XSS", scope_ref=scope_ref,
        target_context={"subdomain": "example.com"},
        hypothesis="hunt hypothesis", research_objective="find it",
        evidence_requirements={"requires": "evidence"},
        state=state, priority=priority,
        provenance={"source": "test"},
        created_at="2026-09-23T09:00:00+00:00",
        updated_at="2026-09-23T09:00:00+00:00",
    )
    defaults.update(kw)
    return HuntObjective(**defaults)


# ------------------------------------------------------ finding fixtures
def make_candidate(candidate_id: str = "cand-aiops-1",
                   source_job: str = "job-aiops-1",
                   lifecycle_state: str = "VERIFICATION_PENDING",
                   scope_ref: str = SCOPE,
                   provenance: dict | None = None, **kw: Any):
    from backend.research_agents.finding.models import CandidateFinding
    defaults: dict[str, Any] = dict(
        candidate_id=candidate_id, source_job=source_job,
        scope_ref=scope_ref, vulnerability_class="XSS",
        hypothesis="candidate hypothesis", lifecycle_state=lifecycle_state,
        target="www.example.com", provenance=provenance or {"source": "test"},
        created_at="2026-09-23T09:00:00+00:00",
        updated_at="2026-09-23T09:00:00+00:00",
    )
    defaults.update(kw)
    return CandidateFinding(**defaults)


# ------------------------------------------------------------ run record
def audit_events() -> list[dict]:
    from backend.research_agents.runtime import RuntimeStore
    return RuntimeStore().audit_events(limit=500)
