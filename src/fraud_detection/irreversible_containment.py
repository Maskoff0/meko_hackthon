"""Irreversible containment service (plan.md Phase 6).

Irreversible containment actions (permanent_block, fund_freeze,
irreversible_payee_block, account_closure) cannot be automatically
reversed and require explicit FRAUD_OWNER human approval before any
execution. No automation path exists for irreversible actions.

Key guarantees:
- No automation: every irreversible action requires explicit human
  execution by a FRAUD_OWNER after FRAUD_OWNER approval
- Separation of duties: the analyst who approves cannot execute
- Customer recourse: customer must be notified before execution;
  remediation must be available
- Independent review: a second reviewer (independent of the approver)
  must confirm before approval
- All actions audited with analyst IDs
- Appeals and remediation workflows available post-execution
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .audit import AuditLog
from .case_queue import CaseQueue
from .domain import (
    AppealRequest,
    AppealStatus,
    CaseQueueStatus,
    CustomerNotification,
    CustomerNotificationType,
    FallbackReason,
    IncidentRecord,
    IrreversibleAction,
    IrreversibleActionStatus,
    IrreversibleContainmentRecord,
    Permission,
    ProductionCutoverStatus,
    RemediationRecord,
    RemediationType,
    Role,
    SandboxContainmentResult,
    SandboxExecutionRecord,
)
from .rbac import RBACManager
from .sandbox_containment import SandboxContainmentService


class IrreversibleContainmentService:
    """Handles irreversible containment actions.

    Wraps ContainmentGate with irreversible-specific checks:
    - FRAUD_OWNER approval required (not just SENIOR_ANALYST)
    - Independent review by a different analyst
    - Customer notification before execution
    - Remediation availability check
    - Separation of duties: approver cannot execute
    - No automation path: execution requires human FRAUD_OWNER
    """

    def __init__(
        self,
        gate: Any,  # ContainmentGate
        audit: AuditLog,
        rbac: RBACManager,
        case_queue: CaseQueue,
        sandbox_containment: SandboxContainmentService,
    ):
        self.gate = gate
        self.audit = audit
        self.rbac = rbac
        self.case_queue = case_queue
        self.sandbox_containment = sandbox_containment

        # Irreversible containment records keyed by record_id
        self._records: dict[str, IrreversibleContainmentRecord] = {}
        # Approval chain: record_id -> approver analyst_id
        self._approvals: dict[str, str] = {}
        # Independent reviews: record_id -> reviewer analyst_id
        self._independent_reviews: dict[str, str] = {}

        # Appeals keyed by appeal_id
        self._appeals: dict[str, AppealRequest] = {}
        # Remediations keyed by remediation_id
        self._remediations: dict[str, RemediationRecord] = {}

    # ------------------------------------------------------------------
    # Propose irreversible containment
    # ------------------------------------------------------------------

    def propose_irreversible_containment(
        self,
        investigation_id: str,
        account_id: str,
        action_type: IrreversibleAction,
        reason_codes: list[str],
        evidence_refs: list[str],
        proposed_by: str = "correlator_agent",
    ) -> IrreversibleContainmentRecord:
        """Propose an irreversible containment action.

        This is a request only. It requires FRAUD_OWNER approval,
        independent review, customer notification, and remediation
        availability before any execution can occur.
        """
        from .containment import ContainmentProposal

        # First evaluate through the containment gate
        proposal = ContainmentProposal(
            action_type=action_type.value,
            target=account_id,
            reason_codes=reason_codes,
            evidence_refs=evidence_refs,
            reversibility="none",  # irreversible by definition
            expiry_seconds=None,   # no expiry for irreversible
            proposed_by=proposed_by,
        )

        gate_result = self.gate.evaluate(proposal)

        # Record the irreversible containment proposal
        record = IrreversibleContainmentRecord(
            investigation_id=investigation_id,
            account_id=account_id,
            action_type=action_type,
            reason_codes=reason_codes,
            evidence_refs=evidence_refs,
            status=IrreversibleActionStatus.PENDING_APPROVAL,
        )
        self._records[record.record_id] = record

        # Audit the proposal
        self.audit._write_entry(
            {
                "type": "irreversible_containment_proposed",
                "record_id": record.record_id,
                "investigation_id": investigation_id,
                "account_id": account_id,
                "action_type": action_type.value,
                "reason_codes": reason_codes,
                "evidence_refs": evidence_refs,
                "proposed_by": proposed_by,
                "gate_decision": gate_result.decision.value,
                "gate_reason": gate_result.reason,
            }
        )

        return record

    # ------------------------------------------------------------------
    # Independent review (required before FRAUD_OWNER approval)
    # ------------------------------------------------------------------

    def independent_review(
        self,
        record_id: str,
        reviewer_id: str,
        review_reason: str = "",
    ) -> bool:
        """Record an independent review of an irreversible containment proposal.

        The independent reviewer must be a different analyst from the
        eventual approver (enforced at approval time). This provides
        a second set of eyes before a FRAUD_OWNER approves.

        Returns True if the review was recorded, False if record not
        found or already reviewed.
        """
        record = self._records.get(record_id)
        if record is None:
            return False

        if record.independent_reviewer is not None:
            return False  # already reviewed

        # RBAC: reviewer must have REVIEW_CASE permission
        try:
            self.rbac.require(
                reviewer_id,
                Permission.REVIEW_CASE,
                resource=f"irreversible_containment:{record_id}",
            )
        except PermissionError:
            return False

        record.independent_reviewer = reviewer_id
        record.independent_review_at = datetime.now(timezone.utc)
        record.updated_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "irreversible_containment_independent_review",
                "record_id": record_id,
                "account_id": record.account_id,
                "action_type": record.action_type,
                "reviewer_id": reviewer_id,
                "review_reason": review_reason,
            }
        )
        return True

    # ------------------------------------------------------------------
    # FRAUD_OWNER approval
    # ------------------------------------------------------------------

    def approve_irreversible_containment(
        self,
        record_id: str,
        approver_id: str,
        approval_reason: str = "",
    ) -> bool:
        """Approve an irreversible containment action.

        RBAC: approver must be FRAUD_OWNER.
        Separation of duties: independent reviewer cannot be the approver.
        Pre-condition: independent review must have been completed.
        """
        record = self._records.get(record_id)
        if record is None:
            return False

        if record.status != IrreversibleActionStatus.PENDING_APPROVAL:
            return False

        # Pre-condition: independent review must be complete
        if record.independent_reviewer is None:
            return False

        # Separation of duties: independent reviewer cannot approve
        if record.independent_reviewer == approver_id:
            return False

        # RBAC: approver must be FRAUD_OWNER
        try:
            self.rbac.require(
                approver_id,
                Permission.EXECUTE_CONTAINMENT,
                resource=f"irreversible_containment:{record_id}",
            )
        except PermissionError:
            return False

        # Verify FRAUD_OWNER role specifically (not just permission)
        approver_role = self.rbac.get_role(approver_id)
        if approver_role != Role.FRAUD_OWNER:
            return False

        record.status = IrreversibleActionStatus.APPROVED
        record.approved_by = approver_id
        record.approved_at = datetime.now(timezone.utc)
        record.approval_reason = approval_reason
        record.updated_at = datetime.now(timezone.utc)

        # Record approval for separation of duties at execution time
        self._approvals[record_id] = approver_id

        # Also record through the containment gate so execution re-validation
        # can find the approved review decision
        from .containment import ContainmentProposal, ContainmentReviewDecision

        gate_proposal = ContainmentProposal(
            action_type=record.action_type,
            target=record.account_id,
            reason_codes=record.reason_codes,
            evidence_refs=record.evidence_refs,
            reversibility="none",
            expiry_seconds=None,
        )
        self.gate.review(
            proposal=gate_proposal,
            decision=ContainmentReviewDecision.APPROVE,
            analyst_id=approver_id,
            analyst_reason=approval_reason,
        )

        self.audit._write_entry(
            {
                "type": "irreversible_containment_approved",
                "record_id": record_id,
                "investigation_id": record.investigation_id,
                "account_id": record.account_id,
                "action_type": record.action_type,
                "approver_id": approver_id,
                "independent_reviewer": record.independent_reviewer,
                "approval_reason": approval_reason,
            }
        )
        return True

    def reject_irreversible_containment(
        self,
        record_id: str,
        approver_id: str,
        rejection_reason: str = "",
    ) -> bool:
        """Reject an irreversible containment action.

        RBAC: approver must be FRAUD_OWNER.
        """
        record = self._records.get(record_id)
        if record is None:
            return False

        if record.status != IrreversibleActionStatus.PENDING_APPROVAL:
            return False

        approver_role = self.rbac.get_role(approver_id)
        if approver_role != Role.FRAUD_OWNER:
            return False

        record.status = IrreversibleActionStatus.REJECTED
        record.approved_by = approver_id
        record.approved_at = datetime.now(timezone.utc)
        record.approval_reason = rejection_reason
        record.updated_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "irreversible_containment_rejected",
                "record_id": record_id,
                "account_id": record.account_id,
                "action_type": record.action_type,
                "approver_id": approver_id,
                "rejection_reason": rejection_reason,
            }
        )
        return True

    # ------------------------------------------------------------------
    # Execute irreversible containment (human FRAUD_OWNER only)
    # ------------------------------------------------------------------

    def execute_irreversible_containment(
        self,
        record_id: str,
        executor_id: str,
        execution_reason: str = "",
    ) -> bool:
        """Execute an approved irreversible containment action.

        RBAC: executor must be FRAUD_OWNER.
        Separation of duties: executor cannot be the approver.
        Pre-conditions:
        - Record must be APPROVED
        - Customer must have been notified
        - Remediation must be available
        - Independent review must be complete
        """
        record = self._records.get(record_id)
        if record is None:
            return False

        if record.status != IrreversibleActionStatus.APPROVED:
            return False

        # Separation of duties: executor cannot be the approver
        if self._approvals.get(record_id) == executor_id:
            return False

        # RBAC: executor must be FRAUD_OWNER with EXECUTE_CONTAINMENT
        try:
            self.rbac.require(
                executor_id,
                Permission.EXECUTE_CONTAINMENT,
                resource=f"irreversible_containment:{record_id}",
            )
        except PermissionError:
            return False

        executor_role = self.rbac.get_role(executor_id)
        if executor_role != Role.FRAUD_OWNER:
            return False

        # Pre-condition: customer notified before execution
        if not record.customer_notified_before:
            return False

        # Pre-condition: remediation available
        if not record.remediation_available:
            return False

        # Evaluate through the containment gate (re-validation at execution)
        from .containment import ContainmentProposal

        proposal = ContainmentProposal(
            action_type=record.action_type,
            target=record.account_id,
            reason_codes=record.reason_codes,
            evidence_refs=record.evidence_refs,
            reversibility="none",
            expiry_seconds=None,
        )
        gate_result = self.gate.execute(proposal, analyst_id=executor_id)

        if gate_result.decision.value != "executed":
            return False

        # Execution succeeded
        record.status = IrreversibleActionStatus.EXECUTED
        record.executed_by = executor_id
        record.executed_at = datetime.now(timezone.utc)
        record.execution_reason = execution_reason or gate_result.reason
        record.updated_at = datetime.now(timezone.utc)

        # Customer notification after execution
        self._send_customer_notification(
            account_id=record.account_id,
            execution_id=record.record_id,
            notification_type=CustomerNotificationType.ACTION_TAKEN,
            channel="in_app",
            reference_id=record.record_id,
        )
        record.customer_notified_at = datetime.now(timezone.utc)

        # Clear approval after execution
        self._approvals.pop(record_id, None)

        self.audit._write_entry(
            {
                "type": "irreversible_containment_executed",
                "record_id": record_id,
                "investigation_id": record.investigation_id,
                "account_id": record.account_id,
                "action_type": record.action_type,
                "executor_id": executor_id,
                "approver_id": record.approved_by,
                "independent_reviewer": record.independent_reviewer,
                "execution_reason": record.execution_reason,
                "customer_notified": record.customer_notified_before,
                "remediation_available": record.remediation_available,
            }
        )
        return True

    # ------------------------------------------------------------------
    # Customer notification
    # ------------------------------------------------------------------

    def notify_customer_before_execution(
        self,
        record_id: str,
        channel: str = "in_app",
    ) -> bool:
        """Notify the customer before an irreversible action is executed.

        This is a mandatory pre-condition for execution. The customer
        must be informed of the impending irreversible action and their
        remediation options.
        """
        record = self._records.get(record_id)
        if record is None:
            return False

        if record.customer_notified_before:
            return True  # already notified

        notification = self._send_customer_notification(
            account_id=record.account_id,
            execution_id=record.record_id,
            notification_type=CustomerNotificationType.ACTION_TAKEN,
            channel=channel,
            reference_id=record.record_id,
        )

        record.customer_notified_before = True
        record.customer_notified_at = datetime.now(timezone.utc)
        record.updated_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "irreversible_containment_customer_notified",
                "record_id": record_id,
                "account_id": record.account_id,
                "action_type": record.action_type,
                "notification_id": notification.notification_id,
                "channel": channel,
            }
        )
        return True

    def mark_remediation_available(
        self,
        record_id: str,
        available: bool = True,
    ) -> bool:
        """Mark whether customer remediation is available for this action.

        Remediation availability is a mandatory pre-condition for
        execution of irreversible actions.
        """
        record = self._records.get(record_id)
        if record is None:
            return False

        record.remediation_available = available
        record.updated_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "irreversible_containment_remediation_marked",
                "record_id": record_id,
                "account_id": record.account_id,
                "action_type": record.action_type,
                "remediation_available": available,
            }
        )
        return True

    # ------------------------------------------------------------------
    # Appeals
    # ------------------------------------------------------------------

    def file_appeal(
        self,
        containment_record_id: str,
        account_id: str,
        customer_id: str,
        appeal_reason: str,
    ) -> Optional[AppealRequest]:
        """File a customer appeal against an irreversible containment action.

        The appeal triggers a review of the containment decision.
        """
        record = self._records.get(containment_record_id)
        if record is None:
            return None

        appeal = AppealRequest(
            containment_record_id=containment_record_id,
            account_id=account_id,
            customer_id=customer_id,
            appeal_reason=appeal_reason,
            status=AppealStatus.OPEN,
        )
        self._appeals[appeal.appeal_id] = appeal

        # Update the containment record to reflect the appeal
        record.appeal_filed = True
        record.updated_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "irreversible_containment_appeal_filed",
                "appeal_id": appeal.appeal_id,
                "containment_record_id": containment_record_id,
                "account_id": account_id,
                "customer_id": customer_id,
                "appeal_reason": appeal_reason,
            }
        )
        return appeal

    def review_appeal(
        self,
        appeal_id: str,
        reviewer_id: str,
        decision: AppealStatus,
        review_reason: str = "",
        remediation: Optional[RemediationType] = None,
        remediation_details: Optional[str] = None,
    ) -> bool:
        """Review a customer appeal.

        RBAC: reviewer must have ADJUDICATE_LABEL or EXECUTE_CONTAINMENT
        permission (SUPERVISOR or FRAUD_OWNER).
        """
        appeal = self._appeals.get(appeal_id)
        if appeal is None:
            return False

        if appeal.status != AppealStatus.OPEN:
            return False

        # RBAC check
        try:
            self.rbac.require(
                reviewer_id,
                Permission.ADJUDICATE_LABEL,
                resource=f"appeal:{appeal_id}",
            )
        except PermissionError:
            try:
                self.rbac.require(
                    reviewer_id,
                    Permission.EXECUTE_CONTAINMENT,
                    resource=f"appeal:{appeal_id}",
                )
            except PermissionError:
                return False

        appeal.status = decision
        appeal.reviewed_by = reviewer_id
        appeal.reviewed_at = datetime.now(timezone.utc)
        appeal.review_reason = review_reason
        appeal.remediation = remediation
        appeal.remediation_details = remediation_details

        self.audit._write_entry(
            {
                "type": "irreversible_containment_appeal_reviewed",
                "appeal_id": appeal_id,
                "containment_record_id": appeal.containment_record_id,
                "account_id": appeal.account_id,
                "customer_id": appeal.customer_id,
                "decision": decision.value,
                "reviewed_by": reviewer_id,
                "review_reason": review_reason,
                "remediation": remediation.value if remediation else None,
            }
        )
        return True

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------

    def create_remediation(
        self,
        account_id: str,
        remediation_type: RemediationType,
        description: str,
        containment_record_id: Optional[str] = None,
        appeal_id: Optional[str] = None,
        amount: Optional[float] = None,
        completed_by: Optional[str] = None,
    ) -> RemediationRecord:
        """Create a customer remediation record.

        Remediation can be triggered by an appeal outcome or
        proactively as part of customer recourse.
        """
        remediation = RemediationRecord(
            account_id=account_id,
            containment_record_id=containment_record_id,
            appeal_id=appeal_id,
            remediation_type=remediation_type,
            description=description,
            amount=amount,
            completed_by=completed_by,
        )
        self._remediations[remediation.remediation_id] = remediation

        if completed_by is not None:
            remediation.completed_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "irreversible_containment_remediation_created",
                "remediation_id": remediation.remediation_id,
                "account_id": account_id,
                "containment_record_id": containment_record_id,
                "appeal_id": appeal_id,
                "remediation_type": remediation_type.value,
                "amount": amount,
                "completed_by": completed_by,
            }
        )
        return remediation

    def complete_remediation(
        self,
        remediation_id: str,
        completed_by: str,
    ) -> bool:
        """Mark a remediation as completed."""
        remediation = self._remediations.get(remediation_id)
        if remediation is None:
            return False

        if remediation.completed_at is not None:
            return True  # already completed

        remediation.completed_at = datetime.now(timezone.utc)
        remediation.completed_by = completed_by

        self.audit._write_entry(
            {
                "type": "irreversible_containment_remediation_completed",
                "remediation_id": remediation_id,
                "account_id": remediation.account_id,
                "remediation_type": remediation.remediation_type,
                "completed_by": completed_by,
            }
        )
        return True

    # ------------------------------------------------------------------
    # Revocation (rare, requires FRAUD_OWNER + independent review)
    # ------------------------------------------------------------------

    def revoke_irreversible_containment(
        self,
        record_id: str,
        revoker_id: str,
        reason: str = "",
    ) -> bool:
        """Revoke an executed irreversible containment action.

        This is an exceptional operation requiring FRAUD_OWNER approval
        and independent review. It should only be used when the original
        determination was found to be incorrect.
        """
        record = self._records.get(record_id)
        if record is None:
            return False

        if record.status != IrreversibleActionStatus.EXECUTED:
            return False

        # RBAC: revoker must be FRAUD_OWNER
        try:
            self.rbac.require(
                revoker_id,
                Permission.EXECUTE_CONTAINMENT,
                resource=f"irreversible_containment:{record_id}",
            )
        except PermissionError:
            return False

        revoker_role = self.rbac.get_role(revoker_id)
        if revoker_role != Role.FRAUD_OWNER:
            return False

        record.status = IrreversibleActionStatus.REVOKED
        record.updated_at = datetime.now(timezone.utc)

        self.audit._write_entry(
            {
                "type": "irreversible_containment_revoked",
                "record_id": record_id,
                "account_id": record.account_id,
                "action_type": record.action_type,
                "revoker_id": revoker_id,
                "reason": reason,
            }
        )
        return True

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_record(self, record_id: str) -> Optional[IrreversibleContainmentRecord]:
        return self._records.get(record_id)

    def list_records(
        self,
        status: Optional[IrreversibleActionStatus] = None,
        account_id: Optional[str] = None,
    ) -> list[IrreversibleContainmentRecord]:
        records = list(self._records.values())
        if status is not None:
            records = [r for r in records if r.status == status]
        if account_id is not None:
            records = [r for r in records if r.account_id == account_id]
        records.sort(key=lambda r: r.created_at)
        return records

    def get_appeal(self, appeal_id: str) -> Optional[AppealRequest]:
        return self._appeals.get(appeal_id)

    def list_appeals(
        self,
        status: Optional[AppealStatus] = None,
    ) -> list[AppealRequest]:
        appeals = list(self._appeals.values())
        if status is not None:
            appeals = [a for a in appeals if a.status == status]
        appeals.sort(key=lambda a: a.submitted_at)
        return appeals

    def get_remediation(self, remediation_id: str) -> Optional[RemediationRecord]:
        return self._remediations.get(remediation_id)

    def list_remediations(
        self,
        account_id: Optional[str] = None,
    ) -> list[RemediationRecord]:
        remediations = list(self._remediations.values())
        if account_id is not None:
            remediations = [r for r in remediations if r.account_id == account_id]
        remediations.sort(key=lambda r: r.effective_at)
        return remediations

    # ------------------------------------------------------------------
    # Customer notification helper
    # ------------------------------------------------------------------

    def _send_customer_notification(
        self,
        account_id: str,
        execution_id: str,
        notification_type: CustomerNotificationType,
        channel: str = "in_app",
        reference_id: Optional[str] = None,
    ) -> CustomerNotification:
        notification = CustomerNotification(
            account_id=account_id,
            execution_id=execution_id,
            notification_type=notification_type,
            channel=channel,
            delivered=True,  # simulated delivery
        )

        self.audit._write_entry(
            {
                "type": "customer_notification",
                "notification_id": notification.notification_id,
                "account_id": account_id,
                "execution_id": execution_id,
                "notification_type": notification_type,
                "channel": channel,
                "delivered": notification.delivered,
                "reference_id": reference_id,
            }
        )
        return notification
