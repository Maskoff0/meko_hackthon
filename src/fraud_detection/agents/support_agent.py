"""Support agent: assesses support-channel signals for an account."""
from __future__ import annotations

from ..domain import AccountEvent, EvidenceFinding, FindingStatus
from ..meko_adapter import MekoAdapter


class SupportAgent:
    """Assesses support-channel signals (reset requests, unusual support activity)."""

    def __init__(self, meko: MekoAdapter):
        self.meko = meko
        self.agent_id = "support_agent"

    async def assess(self, event: AccountEvent) -> EvidenceFinding:
        """Evaluate support event and produce a typed finding."""
        payload = event.payload
        reset_requests = payload.get("reset_requests", 0)
        unusual_time = payload.get("unusual_time", False)
        multiple_contacts = payload.get("multiple_contacts", False)

        if reset_requests >= 3 or (multiple_contacts and unusual_time):
            conclusion = "support_takeover_pattern"
            confidence = 0.75
        elif reset_requests >= 2:
            conclusion = "elevated_reset_requests"
            confidence = 0.6
        elif reset_requests >= 1:
            conclusion = "reset_request"
            confidence = 0.4
        else:
            conclusion = "routine_support_contact"
            confidence = 0.1

        reason_codes = []
        if reset_requests >= 2:
            reason_codes.append("multiple_reset_requests")
        if unusual_time:
            reason_codes.append("support_unusual_time")
        if multiple_contacts:
            reason_codes.append("multiple_support_contacts")

        return EvidenceFinding(
            investigation_id=event.event_id,
            agent_id=self.agent_id,
            conclusion=conclusion,
            confidence=confidence,
            reason_codes=reason_codes,
            evidence_refs=[event.event_id],
            source="support_agent",
            status=FindingStatus.COMPLETE,
        )
