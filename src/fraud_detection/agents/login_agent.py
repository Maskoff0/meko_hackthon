"""Login agent: assesses credential-based signals for an account."""

from __future__ import annotations

from typing import Optional

from ..domain import AccountEvent, EvidenceFinding, FindingStatus
from ..meko_adapter import MekoAdapter


class LoginAgent:
    """Assesses login-related signals (credential stuffing, failed logins)."""

    def __init__(self, meko: MekoAdapter):
        self.meko = meko
        self.agent_id = "login_agent"

    async def assess(self, event: AccountEvent) -> EvidenceFinding:
        """Evaluate login event and produce a typed finding."""
        payload = event.payload
        failed_count = payload.get("failed_count", 0)
        failure_rate = payload.get("failure_rate", 0.0)

        if failed_count >= 10 or failure_rate >= 0.8:
            conclusion = "credential_stuffing_detected"
            confidence = 0.8
        elif failed_count >= 5:
            conclusion = "elevated_failed_logins"
            confidence = 0.6
        elif failed_count > 0:
            conclusion = "minor_login_failures"
            confidence = 0.3
        else:
            conclusion = "no_login_anomaly"
            confidence = 0.1

        reason_codes = []
        if failed_count >= 5:
            reason_codes.append("failed_login_velocity")
        if failure_rate >= 0.5:
            reason_codes.append("high_failure_rate")
        if payload.get("new_location"):
            reason_codes.append("new_location")
        if payload.get("new_ip"):
            reason_codes.append("new_ip")

        return EvidenceFinding(
            investigation_id=event.event_id,
            agent_id=self.agent_id,
            conclusion=conclusion,
            confidence=confidence,
            reason_codes=reason_codes,
            evidence_refs=[event.event_id],
            source="login_agent",
            status=FindingStatus.COMPLETE,
        )
