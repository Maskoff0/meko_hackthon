"""Correlator agent: reads structured findings and verifies evidence references.

The correlator reads typed findings from the investigation record and verifies
evidence references; it does not trust another agent's free-text prompt or
result as instruction.
"""
from __future__ import annotations

from ..domain import EvidenceFinding, FindingStatus
from ..meko_adapter import MekoAdapter


class CorrelatorAgent:
    """Correlates agent findings and verifies evidence references."""

    def __init__(self, meko: MekoAdapter):
        self.meko = meko
        self.agent_id = "correlator_agent"

    async def correlate(
        self,
        investigation_id: str,
        findings: list[EvidenceFinding],
    ) -> EvidenceFinding:
        """Correlate findings and verify evidence references.

        Returns a typed finding with conclusion, confidence, reason codes,
        and evidence references.
        """
        # Verify evidence references are present and non-empty
        verified_refs = []
        for finding in findings:
            for ref in finding.evidence_refs:
                if ref and ref not in verified_refs:
                    verified_refs.append(ref)

        if not findings:
            return EvidenceFinding(
                investigation_id=investigation_id,
                agent_id=self.agent_id,
                conclusion="no_findings_to_correlate",
                confidence=0.0,
                reason_codes=["no_evidence"],
                evidence_refs=[],
                source="correlator_agent",
                status=FindingStatus.COMPLETE,
            )

        # Aggregate: highest confidence, combined reason codes
        max_confidence = max(f.confidence for f in findings)
        all_reason_codes = []
        for f in findings:
            all_reason_codes.extend(f.reason_codes)
        reason_codes = list(dict.fromkeys(all_reason_codes))

        high_confidence = any(f.confidence >= 0.7 for f in findings)
        multiple_agents = len({f.agent_id for f in findings}) > 1

        if high_confidence and multiple_agents:
            conclusion = "correlated_multi_agent_high_confidence"
            confidence = min(max_confidence + 0.1, 1.0)
        elif high_confidence:
            conclusion = "correlated_high_confidence"
            confidence = max_confidence
        elif multiple_agents:
            conclusion = "correlated_multi_agent"
            confidence = min(max_confidence + 0.05, 1.0)
        else:
            conclusion = "correlated_low_confidence"
            confidence = max_confidence

        return EvidenceFinding(
            investigation_id=investigation_id,
            agent_id=self.agent_id,
            conclusion=conclusion,
            confidence=confidence,
            reason_codes=reason_codes,
            evidence_refs=verified_refs,
            source="correlator_agent",
            status=FindingStatus.COMPLETE,
        )
