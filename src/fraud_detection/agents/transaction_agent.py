"""Transaction agent: assesses transaction-related signals for an account."""

from __future__ import annotations

from ..domain import AccountEvent, EvidenceFinding, FindingStatus
from ..meko_adapter import MekoAdapter


class TransactionAgent:
    """Assesses transaction signals (new payee, test payment, limit change)."""

    def __init__(self, meko: MekoAdapter):
        self.meko = meko
        self.agent_id = "transaction_agent"

    async def assess(self, event: AccountEvent) -> EvidenceFinding:
        """Evaluate transaction event and produce a typed finding."""
        payload = event.payload
        new_payee = payload.get("new_payee", False)
        test_payment = payload.get("test_payment", False)
        limit_change = payload.get("limit_change", False)
        cash_out = payload.get("cash_out", False)

        if cash_out or (new_payee and test_payment):
            conclusion = "high_risk_transaction_sequence"
            confidence = 0.85
        elif new_payee:
            conclusion = "new_payee_added"
            confidence = 0.6
        elif test_payment:
            conclusion = "test_payment_detected"
            confidence = 0.55
        elif limit_change:
            conclusion = "limit_change_detected"
            confidence = 0.5
        else:
            conclusion = "routine_transaction"
            confidence = 0.1

        reason_codes = []
        if new_payee:
            reason_codes.append("new_payee")
        if test_payment:
            reason_codes.append("test_payment")
        if limit_change:
            reason_codes.append("limit_change")
        if cash_out:
            reason_codes.append("cash_out")

        return EvidenceFinding(
            investigation_id=event.event_id,
            agent_id=self.agent_id,
            conclusion=conclusion,
            confidence=confidence,
            reason_codes=reason_codes,
            evidence_refs=[event.event_id],
            source="transaction_agent",
            status=FindingStatus.COMPLETE,
        )
