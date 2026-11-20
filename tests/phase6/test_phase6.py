"""Phase 6 tests: irreversible containment & full production rollout.

Tests cover:
  - Irreversible containment proposal
  - Independent review (required before approval)
  - FRAUD_OWNER approval (and rejection of non-FRAUD_OWNER)
  - Separation of duties (approver ≠ executor)
  - Customer notification before execution (mandatory pre-condition)
  - Remediation availability check (mandatory pre-condition)
  - Execution (human FRAUD_OWNER only, no automation)
  - Appeals (file, review, grant/deny)
  - Remediation (create, complete)
  - Revocation (exceptional, FRAUD_OWNER only)
  - Production cutover stage transitions
  - SLO validation
  - Rollback
  - End-to-end flow
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone

import gc
import pytest

from fraud_detection.audit import AuditLog
from fraud_detection.containment import ContainmentGate, Settings
from fraud_detection.domain import (
    AppealStatus,
    IrreversibleAction,
    IrreversibleActionStatus,
    Permission,
    ProductionCutoverStatus,
    RemediationType,
    Role,
)
from fraud_detection.irreversible_containment import IrreversibleContainmentService
from fraud_detection.production_cutover import ProductionCutoverService
from fraud_detection.rbac import RBACManager
from fraud_detection.reversible_automation import ReversibleAutomationEngine, AutomationPolicy, AutomationStage
from fraud_detection.storage import Storage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _safe_unlink(path: str) -> None:
    try:
        gc.collect()
        os.unlink(path)
    except PermissionError:
        pass


@pytest.fixture
def storage():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        s = Storage(db_path=db_path)
        s.connect()
        yield s
    finally:
        s.close()
        _safe_unlink(db_path)


@pytest.fixture
def audit():
    return AuditLog(log_path="/tmp/test_phase6_audit.log")


@pytest.fixture
def rbac(audit):
    return RBACManager(audit=audit)


@pytest.fixture
def case_queue(storage, audit):
    from fraud_detection.case_queue import CaseQueue
    return CaseQueue(storage=storage, audit=audit)


@pytest.fixture
def containment_gate():
    gate = ContainmentGate(Settings())
    gate.settings.shadow_mode = False
    gate.configure_action_credentials(
        credentials={"action_provider": "sandbox", "api_key": "test"},
        allowlist=["permanent_block", "fund_freeze", "irreversible_payee_block", "account_closure"],
    )
    return gate


@pytest.fixture
def sandbox_containment(containment_gate, audit, rbac):
    from fraud_detection.sandbox_containment import SandboxContainmentService
    return SandboxContainmentService(
        gate=containment_gate, audit=audit, rbac=rbac
    )


@pytest.fixture
def automation_engine(containment_gate, rbac, audit, case_queue):
    policy = AutomationPolicy(
        enabled=True,
        stage=AutomationStage.SANDBOX,
        allowlist=[],
    )
    from fraud_detection.label_service import LabelService
    from fraud_detection.orchestration import Orchestrator
    return ReversibleAutomationEngine(
        policy=policy,
        gate_settings=containment_gate.settings,
        rbac=rbac,
        audit=audit,
        case_queue=case_queue,
        label_service=LabelService(audit=audit),
        orchestrator=Orchestrator(storage=Storage(db_path=":memory:")),
        sandbox_containment=sandbox_containment,
    )


@pytest.fixture
def irreversible_service(containment_gate, audit, rbac, case_queue, sandbox_containment):
    return IrreversibleContainmentService(
        gate=containment_gate,
        audit=audit,
        rbac=rbac,
        case_queue=case_queue,
        sandbox_containment=sandbox_containment,
    )


@pytest.fixture
def cutover_service(audit, rbac, automation_engine):
    return ProductionCutoverService(
        audit=audit,
        rbac=rbac,
        reversible_automation=automation_engine,
    )


# ---------------------------------------------------------------------------
# Role setup helper
# ---------------------------------------------------------------------------


def setup_roles(rbac):
    """Assign standard roles for testing."""
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("analyst_001", Role.ANALYST)
    rbac.assign_role("supervisor_001", Role.SUPERVISOR)
    rbac.assign_role("auditor_001", Role.AUDITOR)


# ---------------------------------------------------------------------------
# Irreversible containment proposal tests
# ---------------------------------------------------------------------------


def test_propose_irreversible_containment(irreversible_service):
    """Proposing an irreversible containment creates a pending record."""
    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.PERMANENT_BLOCK,
        reason_codes=["confirmed_ato", "high_risk_transaction"],
        evidence_refs=["evt_1", "evt_2"],
    )

    assert record.record_id is not None
    assert record.investigation_id == "inv_001"
    assert record.account_id == "acct_1042"
    assert record.action_type == IrreversibleAction.PERMANENT_BLOCK
    assert record.status == IrreversibleActionStatus.PENDING_APPROVAL
    assert record.approved_by is None
    assert record.executed_by is None


# ---------------------------------------------------------------------------
# Independent review tests
# ---------------------------------------------------------------------------


def test_independent_review_required_before_approval(irreversible_service, rbac):
    """Independent review must be completed before FRAUD_OWNER can approve."""
    setup_roles(rbac)

    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.PERMANENT_BLOCK,
        reason_codes=["confirmed_ato"],
        evidence_refs=["evt_1"],
    )

    # Approval without independent review should fail
    result = irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Confirmed",
    )
    assert result is False

    # Complete independent review
    result = irreversible_service.independent_review(
        record_id=record.record_id,
        reviewer_id="senior_analyst_001",
        review_reason="Second review confirms ATO",
    )
    assert result is True

    # Now approval should succeed
    result = irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Confirmed ATO after independent review",
    )
    assert result is True

    updated = irreversible_service.get_record(record.record_id)
    assert updated.status == IrreversibleActionStatus.APPROVED
    assert updated.approved_by == "fraud_owner_001"
    assert updated.independent_reviewer == "senior_analyst_001"


def test_independent_reviewer_cannot_be_approver(irreversible_service, rbac):
    """Separation of duties: independent reviewer cannot approve."""
    setup_roles(rbac)

    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.PERMANENT_BLOCK,
        reason_codes=["confirmed_ato"],
        evidence_refs=["evt_1"],
    )

    # Same person reviews and tries to approve
    irreversible_service.independent_review(
        record_id=record.record_id,
        reviewer_id="fraud_owner_001",
        review_reason="Review",
    )

    result = irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Try to approve own review",
    )
    assert result is False


def test_non_fraud_owner_cannot_approve(irreversible_service, rbac):
    """Only FRAUD_OWNER can approve irreversible containment."""
    setup_roles(rbac)

    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.PERMANENT_BLOCK,
        reason_codes=["confirmed_ato"],
        evidence_refs=["evt_1"],
    )
    irreversible_service.independent_review(
        record_id=record.record_id,
        reviewer_id="senior_analyst_001",
        review_reason="Review",
    )

    # Senior analyst cannot approve (not FRAUD_OWNER)
    result = irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="senior_analyst_001",
        approval_reason="Not fraud owner",
    )
    assert result is False

    # FRAUD_OWNER can approve
    result = irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Fraud owner approves",
    )
    assert result is True


# ---------------------------------------------------------------------------
# Separation of duties: approver cannot execute
# ---------------------------------------------------------------------------


def test_approver_cannot_execute(irreversible_service, rbac):
    """Separation of duties: the analyst who approves cannot execute."""
    setup_roles(rbac)

    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.PERMANENT_BLOCK,
        reason_codes=["confirmed_ato"],
        evidence_refs=["evt_1"],
    )
    irreversible_service.independent_review(
        record_id=record.record_id,
        reviewer_id="senior_analyst_001",
        review_reason="Review",
    )
    irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Approved",
    )

    # Mark pre-conditions for execution
    irreversible_service.notify_customer_before_execution(
        record_id=record.record_id,
    )
    irreversible_service.mark_remediation_available(
        record_id=record.record_id,
        available=True,
    )

    # Approver tries to execute - should fail (separation of duties)
    result = irreversible_service.execute_irreversible_containment(
        record_id=record.record_id,
        executor_id="fraud_owner_001",
        execution_reason="Try to execute own approval",
    )
    assert result is False

    # But a different FRAUD_OWNER can execute (need another FRAUD_OWNER)
    rbac.assign_role("fraud_owner_002", Role.FRAUD_OWNER)
    result = irreversible_service.execute_irreversible_containment(
        record_id=record.record_id,
        executor_id="fraud_owner_002",
        execution_reason="Different fraud owner executes",
    )
    assert result is True


# ---------------------------------------------------------------------------
# Customer notification and remediation pre-conditions
# ---------------------------------------------------------------------------


def test_customer_notification_required_before_execution(irreversible_service, rbac):
    """Customer must be notified before irreversible execution."""
    setup_roles(rbac)
    rbac.assign_role("fraud_owner_002", Role.FRAUD_OWNER)

    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.PERMANENT_BLOCK,
        reason_codes=["confirmed_ato"],
        evidence_refs=["evt_1"],
    )
    irreversible_service.independent_review(
        record_id=record.record_id,
        reviewer_id="senior_analyst_001",
        review_reason="Review",
    )
    irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Approved",
    )
    irreversible_service.mark_remediation_available(
        record_id=record.record_id,
        available=True,
    )

    # Execute without customer notification - should fail
    result = irreversible_service.execute_irreversible_containment(
        record_id=record.record_id,
        executor_id="fraud_owner_002",
        execution_reason="No customer notification",
    )
    assert result is False

    # Notify customer, then execute
    irreversible_service.notify_customer_before_execution(
        record_id=record.record_id,
    )
    result = irreversible_service.execute_irreversible_containment(
        record_id=record.record_id,
        executor_id="fraud_owner_002",
        execution_reason="Customer notified",
    )
    assert result is True


def test_remediation_available_required_before_execution(irreversible_service, rbac):
    """Remediation must be available before irreversible execution."""
    setup_roles(rbac)
    rbac.assign_role("fraud_owner_002", Role.FRAUD_OWNER)

    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.PERMANENT_BLOCK,
        reason_codes=["confirmed_ato"],
        evidence_refs=["evt_1"],
    )
    irreversible_service.independent_review(
        record_id=record.record_id,
        reviewer_id="senior_analyst_001",
        review_reason="Review",
    )
    irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Approved",
    )
    irreversible_service.notify_customer_before_execution(
        record_id=record.record_id,
    )

    # Execute without remediation - should fail
    result = irreversible_service.execute_irreversible_containment(
        record_id=record.record_id,
        executor_id="fraud_owner_002",
        execution_reason="No remediation",
    )
    assert result is False

    # Mark remediation available, then execute
    irreversible_service.mark_remediation_available(
        record_id=record.record_id,
        available=True,
    )
    result = irreversible_service.execute_irreversible_containment(
        record_id=record.record_id,
        executor_id="fraud_owner_002",
        execution_reason="Remediation available",
    )
    assert result is True


# ---------------------------------------------------------------------------
# Appeals tests
# ---------------------------------------------------------------------------


def test_file_and_review_appeal(irreversible_service, rbac):
    """Customer can file and have an appeal reviewed."""
    setup_roles(rbac)

    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.PERMANENT_BLOCK,
        reason_codes=["confirmed_ato"],
        evidence_refs=["evt_1"],
    )
    irreversible_service.independent_review(
        record_id=record.record_id,
        reviewer_id="senior_analyst_001",
        review_reason="Review",
    )
    irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Approved",
    )
    irreversible_service.notify_customer_before_execution(
        record_id=record.record_id,
    )
    irreversible_service.mark_remediation_available(
        record_id=record.record_id,
        available=True,
    )
    irreversible_service.execute_irreversible_containment(
        record_id=record.record_id,
        executor_id="fraud_owner_002",
        execution_reason="Executed",
    )

    # Customer files an appeal
    appeal = irreversible_service.file_appeal(
        containment_record_id=record.record_id,
        account_id="acct_1042",
        customer_id="cust_999",
        appeal_reason="I did not authorize this transaction",
    )
    assert appeal is not None
    assert appeal.status == AppealStatus.OPEN
    assert appeal.customer_id == "cust_999"

    # Supervisor reviews and grants the appeal
    result = irreversible_service.review_appeal(
        appeal_id=appeal.appeal_id,
        reviewer_id="supervisor_001",
        decision=AppealStatus.GRANTED,
        review_reason="Customer was a victim of fraud",
        remediation=RemediationType.FUND_RESTORATION,
        remediation_details="Restored funds from fraudulent transaction",
    )
    assert result is True

    updated = irreversible_service.get_appeal(appeal.appeal_id)
    assert updated.status == AppealStatus.GRANTED
    assert updated.reviewed_by == "supervisor_001"
    assert updated.remediation == RemediationType.FUND_RESTORATION


# ---------------------------------------------------------------------------
# Remediation tests
# ---------------------------------------------------------------------------


def test_create_and_complete_remediation(irreversible_service, rbac):
    """Customer remediation can be created and completed."""
    setup_roles(rbac)

    remediation = irreversible_service.create_remediation(
        account_id="acct_1042",
        remediation_type=RemediationType.FUND_RESTORATION,
        description="Restored $500 from fraudulent transaction",
        amount=500.0,
        completed_by="supervisor_001",
    )
    assert remediation.remediation_id is not None
    assert remediation.account_id == "acct_1042"
    assert remediation.remediation_type == RemediationType.FUND_RESTORATION
    assert remediation.amount == 500.0
    assert remediation.completed_at is not None

    # Complete the remediation
    result = irreversible_service.complete_remediation(
        remediation_id=remediation.remediation_id,
        completed_by="supervisor_001",
    )
    assert result is True

    updated = irreversible_service.get_remediation(remediation.remediation_id)
    assert updated.completed_at is not None
    assert updated.completed_by == "supervisor_001"


# ---------------------------------------------------------------------------
# Revocation tests
# ---------------------------------------------------------------------------


def test_revoke_irreversible_containment(irreversible_service, rbac):
    """Irreversible action can be revoked (exceptional, FRAUD_OWNER only)."""
    setup_roles(rbac)
    rbac.assign_role("fraud_owner_002", Role.FRAUD_OWNER)

    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.PERMANENT_BLOCK,
        reason_codes=["confirmed_ato"],
        evidence_refs=["evt_1"],
    )
    irreversible_service.independent_review(
        record_id=record.record_id,
        reviewer_id="senior_analyst_001",
        review_reason="Review",
    )
    irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Approved",
    )
    irreversible_service.notify_customer_before_execution(
        record_id=record.record_id,
    )
    irreversible_service.mark_remediation_available(
        record_id=record.record_id,
        available=True,
    )
    irreversible_service.execute_irreversible_containment(
        record_id=record.record_id,
        executor_id="fraud_owner_002",
        execution_reason="Executed",
    )

    # Revoke (exceptional)
    result = irreversible_service.revoke_irreversible_containment(
        record_id=record.record_id,
        revoker_id="fraud_owner_001",
        reason="Original determination was incorrect",
    )
    assert result is True

    updated = irreversible_service.get_record(record.record_id)
    assert updated.status == IrreversibleActionStatus.REVOKED


# ---------------------------------------------------------------------------
# Production cutover tests
# ---------------------------------------------------------------------------


def test_production_cutover_stage_transitions(cutover_service, rbac):
    """Production cutover can advance through stages."""
    setup_roles(rbac)

    assert cutover_service.get_stage() == ProductionCutoverStatus.SHADOW

    # Take guardrail snapshot
    key = cutover_service.snapshot_guardrails(
        stage=ProductionCutoverStatus.SHADOW,
        guardrail_data={"drift_score": 0.05, "false_positive_rate": 0.02},
    )

    # SLO validation
    validation = cutover_service.validate_slos(
        validated_by="fraud_owner_001",
        metric_results=[
            {
                "metric_name": "drift_score",
                "current_value": 0.05,
                "threshold": 0.15,
                "direction": "below",
                "details": "Within acceptable bounds",
            },
            {
                "metric_name": "false_positive_rate",
                "current_value": 0.02,
                "threshold": 0.05,
                "direction": "below",
                "details": "Within acceptable bounds",
            },
        ],
        observations="All metrics within ratified limits",
    )
    assert validation.overall_passed is True

    # Advance to HUMAN_APPROVAL
    result = cutover_service.advance_stage(
        to_stage=ProductionCutoverStatus.HUMAN_APPROVAL,
        approver_id="fraud_owner_001",
        reason="Ready for human approval phase",
        guardrail_snapshot_key=key,
    )
    assert result is True
    assert cutover_service.get_stage() == ProductionCutoverStatus.HUMAN_APPROVAL


def test_slo_validation_required_for_automation(cutover_service, rbac):
    """SLO validation must pass before advancing to limited automation."""
    setup_roles(rbac)

    # Try to advance to LIMITED_AUTOMATION without SLO validation
    result = cutover_service.advance_stage(
        to_stage=ProductionCutoverStatus.LIMITED_AUTOMATION,
        approver_id="fraud_owner_001",
        reason="Skip SLO validation",
    )
    assert result is False


def test_failed_slo_validation_blocks_cutover(cutover_service, rbac):
    """Failed SLO validation blocks production cutover."""
    setup_roles(rbac)

    # Failed SLO validation
    validation = cutover_service.validate_slos(
        validated_by="fraud_owner_001",
        metric_results=[
            {
                "metric_name": "drift_score",
                "current_value": 0.5,  # above 0.15 threshold
                "threshold": 0.15,
                "direction": "below",
                "details": "Drift too high",
            },
        ],
        observations="Drift exceeds limit",
    )
    assert validation.overall_passed is False

    # Cannot advance with failed SLO
    result = cutover_service.advance_stage(
        to_stage=ProductionCutoverStatus.FULL_PRODUCTION,
        approver_id="fraud_owner_001",
        reason="Try with failed SLO",
    )
    assert result is False


def test_non_fraud_owner_cannot_advance_cutover(cutover_service, rbac):
    """Only FRAUD_OWNER can advance production cutover."""
    setup_roles(rbac)

    key = cutover_service.snapshot_guardrails(
        stage=ProductionCutoverStatus.SHADOW,
        guardrail_data={},
    )

    # Senior analyst cannot advance (not FRAUD_OWNER)
    result = cutover_service.advance_stage(
        to_stage=ProductionCutoverStatus.HUMAN_APPROVAL,
        approver_id="senior_analyst_001",
        reason="Not fraud owner",
        guardrail_snapshot_key=key,
    )
    assert result is False


def test_production_rollback(cutover_service, rbac):
    """Production cutover can be rolled back."""
    setup_roles(rbac)

    key = cutover_service.snapshot_guardrails(
        stage=ProductionCutoverStatus.SHADOW,
        guardrail_data={},
    )
    cutover_service.advance_stage(
        to_stage=ProductionCutoverStatus.HUMAN_APPROVAL,
        approver_id="fraud_owner_001",
        reason="Advance",
        guardrail_snapshot_key=key,
    )
    assert cutover_service.get_stage() == ProductionCutoverStatus.HUMAN_APPROVAL

    # Rollback
    result = cutover_service.rollback(
        approver_id="fraud_owner_001",
        reason="Guardrail violation detected",
    )
    assert result is True
    assert cutover_service.get_stage() == ProductionCutoverStatus.ROLLED_BACK


# ---------------------------------------------------------------------------
# End-to-end: full irreversible containment flow
# ---------------------------------------------------------------------------


def test_end_to_end_irreversible_containment_flow(irreversible_service, rbac):
    """Full flow: propose → independent review → approve → notify customer →
    mark remediation → execute → appeal → remediate → revoke."""
    setup_roles(rbac)
    rbac.assign_role("fraud_owner_002", Role.FRAUD_OWNER)

    # 1. Propose
    record = irreversible_service.propose_irreversible_containment(
        investigation_id="inv_001",
        account_id="acct_1042",
        action_type=IrreversibleAction.FUND_FREEZE,
        reason_codes=["confirmed_ato", "large_transfer"],
        evidence_refs=["evt_1", "evt_2"],
    )
    assert record.status == IrreversibleActionStatus.PENDING_APPROVAL

    # 2. Independent review
    assert irreversible_service.independent_review(
        record_id=record.record_id,
        reviewer_id="senior_analyst_001",
        review_reason="Second review confirms fraud",
    )

    # 3. FRAUD_OWNER approval
    assert irreversible_service.approve_irreversible_containment(
        record_id=record.record_id,
        approver_id="fraud_owner_001",
        approval_reason="Confirmed fund freeze warranted",
    )
    record = irreversible_service.get_record(record.record_id)
    assert record.status == IrreversibleActionStatus.APPROVED

    # 4. Customer notification
    assert irreversible_service.notify_customer_before_execution(
        record_id=record.record_id,
    )
    record = irreversible_service.get_record(record.record_id)
    assert record.customer_notified_before is True

    # 5. Remediation available
    assert irreversible_service.mark_remediation_available(
        record_id=record.record_id,
        available=True,
    )
    record = irreversible_service.get_record(record.record_id)
    assert record.remediation_available is True

    # 6. Execute (different FRAUD_OWNER than approver)
    assert irreversible_service.execute_irreversible_containment(
        record_id=record.record_id,
        executor_id="fraud_owner_002",
        execution_reason="Fund freeze executed",
    )
    record = irreversible_service.get_record(record.record_id)
    assert record.status == IrreversibleActionStatus.EXECUTED
    assert record.executed_by == "fraud_owner_002"

    # 7. Customer appeal
    appeal = irreversible_service.file_appeal(
        containment_record_id=record.record_id,
        account_id="acct_1042",
        customer_id="cust_999",
        appeal_reason="Funds were legitimate",
    )
    assert appeal is not None

    # 8. Appeal review - grant with remediation
    assert irreversible_service.review_appeal(
        appeal_id=appeal.appeal_id,
        reviewer_id="supervisor_001",
        decision=AppealStatus.GRANTED,
        review_reason="Customer provided proof of legitimate transfer",
        remediation=RemediationType.FUND_RESTORATION,
        remediation_details="Restored frozen funds",
    )

    # 9. Remediation
    remediation = irreversible_service.create_remediation(
        account_id="acct_1042",
        remediation_type=RemediationType.FUND_RESTORATION,
        description="Restored frozen funds after successful appeal",
        amount=1000.0,
        appeal_id=appeal.appeal_id,
        completed_by="supervisor_001",
    )
    assert remediation.completed_at is not None

    # 10. Revoke the irreversible action (exceptional)
    assert irreversible_service.revoke_irreversible_containment(
        record_id=record.record_id,
        revoker_id="fraud_owner_001",
        reason="Appeal granted; original determination incorrect",
    )
    record = irreversible_service.get_record(record.record_id)
    assert record.status == IrreversibleActionStatus.REVOKED
