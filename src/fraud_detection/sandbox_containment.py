"""Sandbox containment service (plan.md Phase 4).

Wraps ContainmentGate with sandbox simulation: containment actions are
simulated (no real account holds/blocks), but every proposal, review,
and simulated execution is recorded in the audit log. This provides
a safe environment for human-in-the-loop containment before any
production credentials are configured.

function.md alignment:
- Guardrails: read-only by default, proposal ≠ authority, no agent
  or Meko tool can execute directly
- Capability 6 (feedback capture): analyst decisions are audited
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .audit import AuditLog
from .containment import (
    ContainmentDecision,
    ContainmentGate,
    ContainmentProposal,
    ContainmentReviewDecision,
    ContainmentResult,
)
from .domain import (
    Role,
    SandboxContainmentResult,
    SandboxExecutionRecord,
)
from .rbac import RBACManager


class SandboxContainmentService:
    """Sandbox containment service that simulates execution.

    All containment proposals flow through ContainmentGate (which enforces
    proposal ≠ authority). Execution is simulated in the sandbox -- no
    real account actions are taken -- but every step is audited.

    Human approval is required before simulated execution. Separation of
    duties: the analyst who approves cannot execute.
    """

    def __init__(
        self,
        gate: ContainmentGate,
        audit: AuditLog,
        rbac: Optional[RBACManager] = None,
    ):
        self.gate = gate
        self.audit = audit
        self.rbac = rbac
        self._executions: dict[str, SandboxExecutionRecord] = {}
        # Proposal key -> approval analyst (for separation of duties)
        self._approvals: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Evaluate proposal (gate check)
    # ------------------------------------------------------------------

    def evaluate_proposal(
        self, proposal: ContainmentProposal
    ) -> ContainmentResult:
        """Evaluate a containment proposal through the gate.

        Returns PROPOSED if all gates pass (shadow mode off, credentials,
        allowlist). Otherwise returns a denial decision.
        """
        result = self.gate.evaluate(proposal)

        # Audit the evaluation
        self.audit.record_containment_proposal(
            account_id=proposal.target,
            action_type=proposal.action_type,
            target=proposal.target,
            reason_codes=proposal.reason_codes,
            evidence_refs=proposal.evidence_refs,
            reversibility=proposal.reversibility,
        )

        return result

    # ------------------------------------------------------------------
    # Human review
    # ------------------------------------------------------------------

    def review_proposal(
        self,
        proposal: ContainmentProposal,
        decision: ContainmentReviewDecision,
        analyst_id: str,
        analyst_reason: str = "",
        evidence_snapshot: Optional[dict] = None,
    ) -> ContainmentResult:
        """Record a human analyst's review decision.

        RBAC: analyst must have APPROVE_CONTAINMENT permission.
        Separation of duties: record who approved for execution check.
        """
        # RBAC check
        if self.rbac is not None:
            from .domain import Permission
            try:
                self.rbac.require(
                    analyst_id,
                    Permission.APPROVE_CONTAINMENT,
                    resource=f"containment:{proposal.target}",
                )
            except PermissionError as e:
                return ContainmentResult(
                    decision=ContainmentDecision.EXECUTION_FAILED,
                    proposal=proposal,
                    reason=str(e),
                )

        result = self.gate.review(
            proposal=proposal,
            decision=decision,
            analyst_id=analyst_id,
            analyst_reason=analyst_reason,
            evidence_snapshot=evidence_snapshot,
        )

        # Record approval for separation of duties
        if decision == ContainmentReviewDecision.APPROVE:
            proposal_key = self.gate._proposal_key(proposal)
            self._approvals[proposal_key] = analyst_id
            if self.rbac is not None:
                self.rbac.record_containment_approval(proposal_key, analyst_id)

        # Audit the review
        self.audit.record_containment_review(
            account_id=proposal.target,
            action_type=proposal.action_type,
            target=proposal.target,
            review_decision=decision.value,
            analyst_id=analyst_id,
            analyst_reason=analyst_reason,
            evidence_refs=proposal.evidence_refs,
            evidence_snapshot=evidence_snapshot or {},
            review_id=result.review.review_id if result.review else "",
        )

        return result

    # ------------------------------------------------------------------
    # Simulated execution
    # ------------------------------------------------------------------

    def execute_proposal(
        self,
        proposal: ContainmentProposal,
        analyst_id: str,
    ) -> ContainmentResult:
        """Simulate execution of an approved containment proposal.

        RBAC: analyst must have EXECUTE_CONTAINMENT permission.
        Separation of duties: analyst who approved cannot execute.
        Simulation: no real action is taken; a SandboxExecutionRecord
        is created and audited.

        Returns EXECUTED on successful simulation, EXECUTION_FAILED
        if any re-check fails.
        """
        # RBAC check
        if self.rbac is not None:
            from .domain import Permission
            try:
                self.rbac.require(
                    analyst_id,
                    Permission.EXECUTE_CONTAINMENT,
                    resource=f"containment:{proposal.target}",
                )
            except PermissionError as e:
                return ContainmentResult(
                    decision=ContainmentDecision.EXECUTION_FAILED,
                    proposal=proposal,
                    reason=str(e),
                )

        # Separation of duties: analyst who approved cannot execute
        proposal_key = self.gate._proposal_key(proposal)
        if self._approvals.get(proposal_key) == analyst_id:
            return ContainmentResult(
                decision=ContainmentDecision.EXECUTION_FAILED,
                proposal=proposal,
                reason=(
                    "separation of duties: analyst who approved this "
                    "proposal cannot execute it"
                ),
            )

        # Re-validate through gate
        result = self.gate.execute(proposal, analyst_id=analyst_id)

        if result.decision == ContainmentDecision.EXECUTED:
            # Create sandbox execution record (simulated, no real action)
            record = SandboxExecutionRecord(
                proposal_id=proposal_key,
                account_id=proposal.target,
                action_type=proposal.action_type,
                target=proposal.target,
                analyst_id=analyst_id,
                result=SandboxContainmentResult.SIMULATED_EXECUTED,
                reason=(
                    f"sandbox simulated execution by {analyst_id}; "
                    f"no real action taken. {result.reason}"
                ),
            )
            self._executions[proposal_key] = record

            # Audit the simulated execution
            self.audit.record_containment_execution(
                account_id=proposal.target,
                action_type=proposal.action_type,
                target=proposal.target,
                executed=True,
                analyst_id=analyst_id,
                reason_codes=proposal.reason_codes,
                evidence_refs=proposal.evidence_refs,
                review_id=result.review.review_id if result.review else "",
                execution_reason=result.reason,
                executed_at=result.executed_at.isoformat()
                if result.executed_at
                else None,
            )

            # Clear approval after execution
            self._approvals.pop(proposal_key, None)
            if self.rbac is not None:
                self.rbac.clear_containment_approval(proposal_key)

        else:
            # Execution failed - record the failure
            record = SandboxExecutionRecord(
                proposal_id=proposal_key,
                account_id=proposal.target,
                action_type=proposal.action_type,
                target=proposal.target,
                analyst_id=analyst_id,
                result=SandboxContainmentResult.SIMULATED_DENIED,
                reason=result.reason,
            )
            self._executions[proposal_key] = record

        return result

    def reverse_execution(
        self,
        proposal_key: str,
        analyst_id: str,
        reason: str = "",
    ) -> Optional[SandboxExecutionRecord]:
        """Reverse a previously simulated execution (sandbox only).

        RBAC: analyst must have EXECUTE_CONTAINMENT permission.
        """
        if self.rbac is not None:
            from .domain import Permission
            try:
                self.rbac.require(
                    analyst_id,
                    Permission.EXECUTE_CONTAINMENT,
                    resource=f"containment:{proposal_key}",
                )
            except PermissionError:
                return None

        record = self._executions.get(proposal_key)
        if record is None:
            return None

        if record.reversed:
            return record

        record.reversed = True
        record.reversed_at = datetime.now(timezone.utc)
        record.reversal_reason = reason
        record.result = SandboxContainmentResult.SIMULATED_EXECUTED  # keep result

        # Audit the reversal
        self.audit._write_entry(
            {
                "type": "sandbox_containment_reversed",
                "execution_id": record.execution_id,
                "proposal_key": proposal_key,
                "account_id": record.account_id,
                "action_type": record.action_type,
                "target": record.target,
                "reversed_by": analyst_id,
                "reason": reason,
            }
        )

        return record

    def get_execution(self, proposal_key: str) -> Optional[SandboxExecutionRecord]:
        return self._executions.get(proposal_key)

    def list_executions(self) -> list[SandboxExecutionRecord]:
        return list(self._executions.values())
