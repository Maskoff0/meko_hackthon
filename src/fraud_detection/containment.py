"""Containment gate: proposal is not authority.

A correlator may submit a structured containment proposal, but that proposal
is not authorization. In shadow mode it is logged only; no containment or
action credentials exist and no executable action path is provided. This
module enforces the boundary at the code level so it cannot be silently
bypassed.

Human-in-the-loop extension:
- A correlator or MCP client submits a proposal.
- A human analyst reviews and decides (approve / reject / escalate).
- Execution requires re-validation at execution time: shadow mode off,
  credentials present, action allowlisted, idempotency, analyst approval.
- No agent, MCP client, or Meko tool can execute directly.
"""
from __future__ import annotations

import hashlib
import uuid

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from .settings import Settings


class ContainmentDecision(str, Enum):
    PROPOSED = "proposed"
    DENIED_SHADOW_MODE = "denied_shadow_mode"
    DENIED_NO_CREDENTIALS = "denied_no_credentials"
    DENIED_NOT_ALLOWLISTED = "denied_not_allowlisted"
    REVIEW_APPROVED = "review_approved"
    REVIEW_REJECTED = "review_rejected"
    REVIEW_ESCALATED = "review_escalated"
    EXECUTED = "executed"
    EXECUTION_FAILED = "execution_failed"


class ContainmentReviewDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    ESCALATE = "escalate"


@dataclass
class ContainmentProposal:
    """A structured containment request submitted by the correlator.

    This is a request only. The ContainmentGate independently re-checks
    policy, permissions, allowlist, and shadow mode before anything can
    proceed. In Phase 1 (shadow mode), execution is always denied.
    """

    action_type: str
    target: str
    reason_codes: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    reversibility: str = "none"
    expiry_seconds: Optional[int] = None
    proposed_by: str = "correlator_agent"
    proposed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ContainmentReview:
    """A human analyst's review decision on a containment proposal."""

    review_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    proposal_action_type: str = ""
    proposal_target: str = ""
    decision: ContainmentReviewDecision = ContainmentReviewDecision.APPROVE
    analyst_id: str = ""
    analyst_reason: str = ""
    reviewed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_snapshot: dict[str, Any] = field(default_factory=dict)


@dataclass
class ContainmentResult:
    decision: ContainmentDecision
    proposal: ContainmentProposal
    reason: str
    executed: bool = False
    executed_at: Optional[datetime] = None
    actor: Optional[str] = None
    review: Optional[ContainmentReview] = None


class ContainmentGate:
    """Enforces the proposal ≠ authority boundary.

    Phase 1 invariant: shadow_mode=True and no action credentials are
    configured, so every proposal is denied with DENIED_SHADOW_MODE.
    To eliminate this constraint (move to Phase 4+), an operator must:
      1. Set shadow_mode=False in settings (explicit opt-out of shadow).
      2. Configure containment credentials (action provider identity/key).
      3. Define a fraud-owner-approved reversible action allowlist.
      4. Add human approval + re-check at execution time.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        # No action credentials are loaded in Phase 1. This is intentional:
        # without credentials, no execution path exists regardless of config.
        self._action_credentials: Optional[dict[str, Any]] = None
        self._action_allowlist: set[str] = set()
        # Idempotency: track executed proposal keys so the same proposal
        # cannot be executed twice.
        self._executed_proposals: set[str] = set()
        # Pending human reviews keyed by proposal identity.
        self._pending_reviews: dict[str, ContainmentReview] = {}

    def configure_action_credentials(
        self, credentials: dict[str, Any], allowlist: list[str]
    ) -> None:
        """Register containment/action credentials and an allowlist.

        Calling this is the mechanism to begin eliminating the
        "no executable action path" constraint. It must be paired with
        shadow_mode=False and human-approval logic before any proposal
        can execute.
        """
        self._action_credentials = credentials
        self._action_allowlist = set(allowlist)

    def _proposal_key(self, proposal: ContainmentProposal) -> str:
        """Build an idempotency key for a proposal."""
        payload = (
            f"{proposal.action_type}|{proposal.target}|"
            f"{','.join(sorted(proposal.reason_codes))}|"
            f"{','.join(sorted(proposal.evidence_refs))}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def evaluate(self, proposal: ContainmentProposal) -> ContainmentResult:
        """Evaluate a containment proposal.

        Returns a ContainmentResult. In Phase 1 (shadow mode, no
        credentials), execution is always denied.
        """
        # Shadow mode is the hard Phase 1 gate.
        if self.settings.shadow_mode:
            return ContainmentResult(
                decision=ContainmentDecision.DENIED_SHADOW_MODE,
                proposal=proposal,
                reason=(
                    "shadow_mode is enabled; containment proposals are logged "
                    "only and never executed"
                ),
            )

        # No credentials means no executable path exists.
        if self._action_credentials is None:
            return ContainmentResult(
                decision=ContainmentDecision.DENIED_NO_CREDENTIALS,
                proposal=proposal,
                reason=(
                    "no containment/action credentials configured; "
                    "no executable action path exists"
                ),
            )

        # Action must be on the fraud-owner-approved allowlist.
        if proposal.action_type not in self._action_allowlist:
            return ContainmentResult(
                decision=ContainmentDecision.DENIED_NOT_ALLOWLISTED,
                proposal=proposal,
                reason=(
                    f"action_type {proposal.action_type!r} is not on the "
                    "fraud-owner-approved allowlist"
                ),
            )

        # If all checks pass, the proposal is ready for human review.
        return ContainmentResult(
            decision=ContainmentDecision.PROPOSED,
            proposal=proposal,
            reason="proposal passed all gates; awaiting human approval",
        )

    def review(
        self,
        proposal: ContainmentProposal,
        decision: ContainmentReviewDecision,
        analyst_id: str,
        analyst_reason: str = "",
        evidence_snapshot: Optional[dict[str, Any]] = None,
    ) -> ContainmentResult:
        """Record a human analyst's review decision on a proposal.

        The analyst can approve, reject, or escalate. Approval does not
        execute; it only marks the proposal as approved. Execution requires
        a separate call to `execute()` which re-validates at execution time.
        """
        review = ContainmentReview(
            proposal_action_type=proposal.action_type,
            proposal_target=proposal.target,
            decision=decision,
            analyst_id=analyst_id,
            analyst_reason=analyst_reason,
            evidence_snapshot=evidence_snapshot or {},
        )
        key = self._proposal_key(proposal)
        self._pending_reviews[key] = review

        if decision == ContainmentReviewDecision.APPROVE:
            result_decision = ContainmentDecision.REVIEW_APPROVED
            reason = (
                f"proposal approved by analyst {analyst_id}; "
                "awaiting execution with re-validation"
            )
        elif decision == ContainmentReviewDecision.REJECT:
            result_decision = ContainmentDecision.REVIEW_REJECTED
            reason = (
                f"proposal rejected by analyst {analyst_id}: {analyst_reason}"
            )
        else:
            result_decision = ContainmentDecision.REVIEW_ESCALATED
            reason = (
                f"proposal escalated by analyst {analyst_id}: {analyst_reason}"
            )

        return ContainmentResult(
            decision=result_decision,
            proposal=proposal,
            reason=reason,
            review=review,
        )

    def execute(
        self,
        proposal: ContainmentProposal,
        analyst_id: str,
    ) -> ContainmentResult:
        """Execute an approved containment proposal.

        Re-validates at execution time:
        - shadow_mode must be off
        - credentials must be configured
        - action must be allowlisted
        - proposal must have been approved by a human analyst
        - idempotency: same proposal key cannot be executed twice

        Returns EXECUTED on success, EXECUTION_FAILED if any re-check
        fails.
        """
        key = self._proposal_key(proposal)

        # Idempotency: reject duplicate execution.
        if key in self._executed_proposals:
            return ContainmentResult(
                decision=ContainmentDecision.EXECUTION_FAILED,
                proposal=proposal,
                reason=(
                    f"proposal {key} already executed; idempotency check "
                    "prevents duplicate execution"
                ),
            )

        # Re-validation: shadow mode must be off.
        if self.settings.shadow_mode:
            return ContainmentResult(
                decision=ContainmentDecision.EXECUTION_FAILED,
                proposal=proposal,
                reason="cannot execute: shadow_mode is enabled",
            )

        # Re-validation: credentials must be present.
        if self._action_credentials is None:
            return ContainmentResult(
                decision=ContainmentDecision.EXECUTION_FAILED,
                proposal=proposal,
                reason="cannot execute: no containment/action credentials configured",
            )

        # Re-validation: action must be allowlisted.
        if proposal.action_type not in self._action_allowlist:
            return ContainmentResult(
                decision=ContainmentDecision.EXECUTION_FAILED,
                proposal=proposal,
                reason=(
                    f"cannot execute: action_type {proposal.action_type!r} "
                    "is not on the fraud-owner-approved allowlist"
                ),
            )

        # Re-validation: proposal must have human approval.
        review = self._pending_reviews.get(key)
        if review is None or review.decision != ContainmentReviewDecision.APPROVE:
            return ContainmentResult(
                decision=ContainmentDecision.EXECUTION_FAILED,
                proposal=proposal,
                reason=(
                    "cannot execute: proposal has not been approved by a "
                    "human analyst"
                ),
            )

        # All re-checks passed. Mark executed for idempotency.
        self._executed_proposals.add(key)

        return ContainmentResult(
            decision=ContainmentDecision.EXECUTED,
            proposal=proposal,
            reason=(
                f"execution completed for analyst-approved proposal; "
                f"analyst={review.analyst_id}, reason={review.analyst_reason}"
            ),
            executed=True,
            executed_at=datetime.now(timezone.utc),
            actor=review.analyst_id,
            review=review,
        )
