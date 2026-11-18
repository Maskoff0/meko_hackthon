"""Versioned policy engine: decisions, thresholds, abstention.

Combines validated evidence and agent findings to recommend, abstain, or route
to review. Agent output is evidence, never authority. Policy is versioned and
deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .domain import (
    AccountEvent,
    EvidenceFinding,
    Recommendation,
    ShadowRecommendation,
)
from .baseline import BaselineResult


@dataclass
class PolicyDecision:
    """Internal policy decision before emitting a shadow recommendation."""

    recommendation: Recommendation
    reason_codes: list[str] = field(default_factory=list)
    baseline_result: dict = field(default_factory=dict)
    agent_findings: list[dict] = field(default_factory=list)
    uncertainty: str = "low"
    abstention: bool = False
    evidence_provenance: list[str] = field(default_factory=list)


class PolicyEngine:
    """Versioned deterministic policy engine."""

    def __init__(self, policy_version: str = "2026-11-v1"):
        self.policy_version = policy_version
        self.model_version = "deterministic-baseline-v1"
        self.prompt_version: Optional[str] = None

    def decide(
        self,
        event: AccountEvent,
        baseline: BaselineResult,
        findings: list[EvidenceFinding],
        shadow_mode: bool = True,
    ) -> ShadowRecommendation:
        """Produce a shadow recommendation from event, baseline, and findings.

        In shadow mode, the recommendation is always non-actionable (review or
        abstain). Block/allow are never emitted as executable actions.
        """
        reason_codes: list[str] = list(baseline.reason_codes)
        evidence_provenance: list[str] = ["baseline"]
        agent_findings = []
        uncertainty = "low"
        abstention = False

        # Incorporate agent findings as evidence only
        for finding in findings:
            agent_findings.append(
                {
                    "agent_id": finding.agent_id,
                    "conclusion": finding.conclusion,
                    "confidence": finding.confidence,
                    "reason_codes": finding.reason_codes,
                    "evidence_refs": finding.evidence_refs,
                }
            )
            reason_codes.extend(finding.reason_codes)
            if finding.source:
                evidence_provenance.append(finding.source)

        # Deduplicate reason codes
        reason_codes = list(dict.fromkeys(reason_codes))

        # Determine recommendation
        if shadow_mode:
            # In shadow mode: never block or allow. Route to review or abstain.
            if baseline.triggered or agent_findings:
                recommendation = Recommendation.REVIEW
                if baseline.score >= 0.8 or any(
                    f["confidence"] >= 0.8 for f in agent_findings
                ):
                    uncertainty = "high"
            else:
                recommendation = Recommendation.ABSTAIN
                abstention = True
                uncertainty = "low"
        else:
            # Production mode (gated): block/allow decisions require separate approval
            if baseline.triggered:
                recommendation = Recommendation.BLOCK
            elif agent_findings:
                recommendation = Recommendation.REVIEW
            else:
                recommendation = Recommendation.ABSTAIN
                abstention = True

        return ShadowRecommendation(
            recommendation=recommendation,
            reason_codes=reason_codes,
            baseline_result=baseline.to_dict(),
            uncertainty=uncertainty,
            abstention=abstention,
            policy_version=self.policy_version,
            model_version=self.model_version,
            prompt_version=self.prompt_version,
            evidence_provenance=evidence_provenance,
        )
