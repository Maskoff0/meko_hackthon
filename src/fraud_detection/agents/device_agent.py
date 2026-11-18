"""Device agent: assesses device-related signals for an account."""

from __future__ import annotations

from typing import Optional

from ..domain import AccountEvent, EvidenceFinding, FindingStatus
from ..meko_adapter import MekoAdapter


class DeviceAgent:
    """Assesses device-related signals (new device, emulator, fingerprint)."""

    def __init__(self, meko: MekoAdapter):
        self.meko = meko
        self.agent_id = "device_agent"

    async def assess(self, event: AccountEvent) -> EvidenceFinding:
        """Evaluate device event and produce a typed finding."""
        payload = event.payload
        is_new = payload.get("is_new_device", False)
        is_emulator = payload.get("is_emulator", False)
        is_spoofed = payload.get("fingerprint_spoofed", False)

        if is_emulator or is_spoofed:
            conclusion = "suspicious_device"
            confidence = 0.85
        elif is_new:
            conclusion = "new_device_observed"
            confidence = 0.6
        else:
            conclusion = "known_device"
            confidence = 0.1

        reason_codes = []
        if is_new:
            reason_codes.append("new_device")
        if is_emulator:
            reason_codes.append("emulator_detected")
        if is_spoofed:
            reason_codes.append("fingerprint_spoofed")

        return EvidenceFinding(
            investigation_id=event.event_id,
            agent_id=self.agent_id,
            conclusion=conclusion,
            confidence=confidence,
            reason_codes=reason_codes,
            evidence_refs=[event.event_id],
            source="device_agent",
            status=FindingStatus.COMPLETE,
        )
