"""Offline notification seam (Phase 5J).

Delivery is OUT OF SCOPE: no Telegram, no external transport, no
side effects beyond an injected in-memory sink. The ONLY alert rule:

- A NEWLY persisted (non-deduplicated), eligible 5J finding may reach
  the seam exactly once.
- A deduplicated replay MUST NOT re-trigger notification.
- A rejected / corrupt / unverifiable materialization MUST NOT reach
  the seam.

Duplicate-alert prevention: deterministic alert identity
``alert = sha256(finding_id \\x00 alert_policy_version)`` with a
put-if-absent alert ledger. Severity-UNSET findings are alertable at
the lowest handling priority with an explicit "severity pending"
marker — a DISPLAY rule consumed downstream, never a severity
assignment performed here.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ai.evidence import hashing

__all__ = [
    "ALERT_POLICY_VERSION",
    "FindingAlert",
    "NotificationSink",
    "RecordingNotificationSink",
    "AlertLedgerMemory",
    "alert_id_for",
]

#: Pinned alert-identity policy version (hashed into every alert id).
ALERT_POLICY_VERSION = "5j-alert-policy/v1"


def alert_id_for(finding_id: str) -> str:
    """Deterministic alert identity (one alert per finding, ever)."""
    basis = "\x00".join((finding_id, ALERT_POLICY_VERSION))
    return "alert-" + hashing.sha256_hex(basis.encode("utf-8"))[:32]


@dataclass(frozen=True)
class FindingAlert:
    """One offline alert record (hashes + IDs, no content)."""

    alert_id: str
    finding_id: str
    program_name: str
    severity: str
    severity_pending: bool = False
    classification_hash: str = ""


class NotificationSink(ABC):
    """Narrow offline delivery seam (one method, no authority)."""

    @abstractmethod
    def publish(self, alert: FindingAlert) -> None:
        """Record one alert (delivery lives outside 5J scope)."""


class RecordingNotificationSink(NotificationSink):
    """In-memory sink for offline tests (append-only list)."""

    def __init__(self) -> None:
        self.published: list[FindingAlert] = []
        self._lock = threading.Lock()

    def publish(self, alert: FindingAlert) -> None:
        if not isinstance(alert, FindingAlert):
            raise TypeError(
                "notification sink accepts only FindingAlert, "
                f"not {type(alert).__name__}"
            )
        with self._lock:
            self.published.append(alert)


class AlertLedgerMemory:
    """Put-if-absent alert ledger (exactly-once alert identity)."""

    def __init__(self) -> None:
        self._claimed: set[str] = set()
        self._lock = threading.Lock()

    def claim(self, alert_id: str) -> bool:
        """Claim one alert id; True only for the first claim."""
        if not isinstance(alert_id, str) or not alert_id:
            raise ValueError("alert_id must be a non-empty string")
        with self._lock:
            if alert_id in self._claimed:
                return False
            self._claimed.add(alert_id)
            return True

    def claimed(self, alert_id: str) -> bool:
        with self._lock:
            return alert_id in self._claimed
