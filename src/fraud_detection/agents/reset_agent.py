"""Reset agent: assesses password-reset signals for an account."""

from __future__ import annotations

from ..domain import AccountEvent, EvidenceFinding, FindingStatus
from ..meko_adapter import MekoAdapter


class ResetAgent:
    """Assesses password-reset signals (reset after failures, unusual timing)."""

    def __init__(self, meko: MekoAdapter):
        self.meko = meko
        self.agent_id = "reset_agent"

    async def assess(self, event: AccountEvent) -> EvidenceFinding:
        """Evaluate reset event and produce a typed finding."""
        payload = event.payload
        after_failures = payload.get("after_failures", False)
        unusual_time = payload.get("unusual_time", False)
        multiple_resets = payload.get("multiple_resets", False)

        if after_failures and unusual_time:
            conclusion = "reset_after_failures_unusual_time"
            confidence = 0.75
        elif after_failures:
            conclusion = "reset_after_failures"
            confidence = 0.6
        elif multiple_resets:
            conclusion = "multiple_resets"
            confidence = 0.5
        else:
            conclusion = "routine_reset"
            confidence = 0.2

        reason_codes = []
        if after_failures:
            reason_codes.append("password_reset_after_failures")
        if unusual_time:
            reason_codes.append("password_reset_unusual_time")
        if multiple_resets:
            reason_codes.append("multiple_password_resets")

        return EvidenceFinding(
            investigation_id=event.event_id,
            agent_id=self.agent_id,
            conclusion=conclusion,
            confidence=confidence,
            reason_codes=reason_codes,
            evidence_refs=[event.event_id],
            source="reset_agent",
            status=FindingStatus.COMPLETE,
        )
