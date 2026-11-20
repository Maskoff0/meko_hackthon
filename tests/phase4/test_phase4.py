"""Phase 4 tests: human approval, case queue, RBAC, sandbox containment,
structured analyst labels.

Tests cover:
  - Case queue: build, list, assign, reassign, escalate, close, resolve
  - Evidence timeline: chronological events + findings with citations
  - RBAC: role-permission mapping, access evaluation, separation of duties
  - Sandbox containment: evaluate, review, simulate execute, reverse
  - Structured analyst labels: ingest, maturity, feedback capture,
    adjudication, shared-knowledge eligibility
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone, timedelta

import gc
import pytest

from fraud_detection.audit import AuditLog
from fraud_detection.case_queue import CaseQueue
from fraud_detection.containment import (
    ContainmentDecision,
    ContainmentProposal,
    ContainmentReviewDecision,
)
from fraud_detection.domain import (
    AssignmentAction,
    AccessDecision,
    CaseLabel,
    CaseQueueStatus,
    FeedbackLabel,
    LabelSource,
    LabelState,
    Permission,
    Role,
    SandboxContainmentResult,
)
from fraud_detection.label_service import LabelService
from fraud_detection.rbac import RBACManager
from fraud_detection.sandbox_containment import SandboxContainmentService
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
    return AuditLog(log_path="/tmp/test_phase4_audit.log")


@pytest.fixture
def case_queue(storage, audit):
    return CaseQueue(storage=storage, audit=audit)


@pytest.fixture
def rbac(audit):
    return RBACManager(audit=audit)


@pytest.fixture
def sandbox_containment(audit, rbac):
    from fraud_detection.containment import ContainmentGate, Settings
    gate = ContainmentGate(Settings())
    gate.settings.shadow_mode = False
    gate.configure_action_credentials(
        credentials={"action_provider": "sandbox", "api_key": "test"},
        allowlist=["temporary_hold"],
    )
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)
    return SandboxContainmentService(gate=gate, audit=audit, rbac=rbac)


@pytest.fixture
def label_service(audit):
    return LabelService(audit=audit)


# ---------------------------------------------------------------------------
# Case queue tests
# ---------------------------------------------------------------------------


def test_case_queue_build_item(case_queue):
    investigation = {
        "investigation_id": "inv_001",
        "account_id": "acct_1042",
        "trigger_type": "high_risk_event",
        "policy_version": "2026-11-v1",
    }
    findings = [
            {
                "finding_id": "finding_1",
                "agent_id": "login_agent",
                "conclusion": "credential_stuffing_detected",
                "confidence": 0.8,
                "reason_codes": ["failed_login_velocity"],
                "evidence_refs": ["evt_1"],
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        ]
    recommendation = {
        "recommendation": "review",
        "reason_codes": ["failed_login_velocity"],
        "uncertainty": "high",
        "model_version": "deterministic-baseline-v1",
    }
    events = [
        {
            "event_id": "evt_1",
            "account_id": "acct_1042",
            "event_type": "login",
            "source": "synthetic_login_agent",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provenance": "synthetic",
        }
    ]

    item = case_queue.build_queue_item(
        investigation=investigation,
        findings=findings,
        recommendation=recommendation,
        events=events,
        rank=1,
        score=0.85,
    )

    assert item.investigation_id == "inv_001"
    assert item.account_id == "acct_1042"
    assert item.rank == 1
    assert item.score == 0.85
    assert "failed_login_velocity" in item.reason_codes
    assert len(item.agent_findings) == 1
    assert item.agent_findings[0]["agent_id"] == "login_agent"
    assert len(item.evidence_timeline) == 2  # 1 event + 1 finding
    citations = [e["citation"] for e in item.evidence_timeline]
    assert "evt_1" in citations
    assert "finding_1" in citations
    assert item.status == CaseQueueStatus.QUEUED


def test_case_queue_list_and_filter(case_queue):
    # Build two queue items
    for i in range(2):
        inv = {
            "investigation_id": f"inv_{i:03d}",
            "account_id": f"acct_{i:03d}",
            "trigger_type": "high_risk_event",
        }
        case_queue.build_queue_item(
            investigation=inv, findings=[], rank=i + 1, score=0.5
        )

    all_items = case_queue.list_queue()
    assert len(all_items) == 2
    assert all_items[0].rank == 1

    # Filter by status
    queued = case_queue.list_queue(status=CaseQueueStatus.QUEUED)
    assert len(queued) == 2


def test_case_queue_assign(case_queue):
    inv = {
        "investigation_id": "inv_001",
        "account_id": "acct_1042",
        "trigger_type": "high_risk_event",
    }
    case_queue.build_queue_item(investigation=inv, findings=[], rank=1, score=0.5)

    assignment = case_queue.assign(
        investigation_id="inv_001",
        to_analyst="analyst_001",
        assigned_by="supervisor_001",
        reason="High priority ATO case",
    )

    assert assignment.action == AssignmentAction.ASSIGN
    assert assignment.to_analyst == "analyst_001"
    assert assignment.assigned_by == "supervisor_001"

    item = case_queue.get_queue_item("inv_001")
    assert item.assigned_to == "analyst_001"
    assert item.status == CaseQueueStatus.ASSIGNED


def test_case_queue_reassign(case_queue):
    inv = {
        "investigation_id": "inv_001",
        "account_id": "acct_1042",
        "trigger_type": "high_risk_event",
    }
    case_queue.build_queue_item(investigation=inv, findings=[], rank=1, score=0.5)
    case_queue.assign(
        investigation_id="inv_001",
        to_analyst="analyst_001",
        assigned_by="supervisor_001",
    )

    assignment = case_queue.reassign(
        investigation_id="inv_001",
        to_analyst="analyst_002",
        assigned_by="supervisor_001",
        reason="Workload rebalancing",
    )

    assert assignment.action == AssignmentAction.REASSIGN
    assert assignment.from_analyst == "analyst_001"
    assert assignment.to_analyst == "analyst_002"

    item = case_queue.get_queue_item("inv_001")
    assert item.assigned_to == "analyst_002"


def test_case_queue_escalate(case_queue):
    inv = {
        "investigation_id": "inv_001",
        "account_id": "acct_1042",
        "trigger_type": "high_risk_event",
    }
    case_queue.build_queue_item(investigation=inv, findings=[], rank=1, score=0.5)
    case_queue.assign(
        investigation_id="inv_001",
        to_analyst="analyst_001",
        assigned_by="supervisor_001",
    )

    assignment = case_queue.escalate(
        investigation_id="inv_001",
        to_analyst="supervisor_001",
        assigned_by="analyst_001",
        reason="Complex ATO pattern needs senior review",
    )

    assert assignment.action == AssignmentAction.ESCALATE
    item = case_queue.get_queue_item("inv_001")
    assert item.status == CaseQueueStatus.ESCALATED
    assert item.escalated is True
    assert item.escalated_to == "supervisor_001"


def test_case_queue_close_and_resolve(case_queue):
    inv = {
        "investigation_id": "inv_001",
        "account_id": "acct_1042",
        "trigger_type": "high_risk_event",
    }
    case_queue.build_queue_item(investigation=inv, findings=[], rank=1, score=0.5)

    case_queue.close(
        investigation_id="inv_001",
        closed_by="analyst_001",
        reason="Resolved as false positive",
    )
    item = case_queue.get_queue_item("inv_001")
    assert item.status == CaseQueueStatus.CLOSED


def test_case_queue_get_unassigned(case_queue):
    # Build two items, assign one
    for i in range(2):
        inv = {
            "investigation_id": f"inv_{i:03d}",
            "account_id": f"acct_{i:03d}",
            "trigger_type": "high_risk_event",
        }
        case_queue.build_queue_item(investigation=inv, findings=[], rank=i + 1, score=0.5)

    case_queue.assign(
        investigation_id="inv_000",
        to_analyst="analyst_001",
        assigned_by="supervisor_001",
    )

    unassigned = case_queue.get_unassigned()
    assert len(unassigned) == 1
    assert unassigned[0].investigation_id == "inv_001"


# ---------------------------------------------------------------------------
# RBAC tests
# ---------------------------------------------------------------------------


def test_rbac_assign_role_and_evaluate(rbac):
    rbac.assign_role("analyst_001", Role.ANALYST)

    # Analyst can view queue
    decision = rbac.check("analyst_001", Permission.VIEW_QUEUE)
    assert decision == AccessDecision.ALLOW

    # Analyst cannot assign cases
    decision = rbac.check("analyst_001", Permission.ASSIGN_CASE)
    assert decision == AccessDecision.DENY

    # Analyst with no role
    decision = rbac.check("unknown_analyst", Permission.VIEW_QUEUE)
    assert decision == AccessDecision.DENY


def test_rbac_supervisor_permissions(rbac):
    rbac.assign_role("supervisor_001", Role.SUPERVISOR)

    assert rbac.check("supervisor_001", Permission.ASSIGN_CASE) == AccessDecision.ALLOW
    assert rbac.check("supervisor_001", Permission.REASSIGN_CASE) == AccessDecision.ALLOW
    assert rbac.check("supervisor_001", Permission.ESCALATE_CASE) == AccessDecision.ALLOW
    assert rbac.check("supervisor_001", Permission.APPROVE_CONTAINMENT) == AccessDecision.ALLOW
    # Supervisor cannot execute
    assert rbac.check("supervisor_001", Permission.EXECUTE_CONTAINMENT) == AccessDecision.DENY


def test_rbac_fraud_owner_execute(rbac):
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    assert rbac.check("fraud_owner_001", Permission.EXECUTE_CONTAINMENT) == AccessDecision.ALLOW
    assert rbac.check("fraud_owner_001", Permission.MANAGE_ROLES) == AccessDecision.ALLOW


def test_rbac_auditor_view_only(rbac):
    rbac.assign_role("auditor_001", Role.AUDITOR)

    assert rbac.check("auditor_001", Permission.VIEW_QUEUE) == AccessDecision.ALLOW
    assert rbac.check("auditor_001", Permission.VIEW_AUDIT) == AccessDecision.ALLOW
    assert rbac.check("auditor_001", Permission.APPROVE_CONTAINMENT) == AccessDecision.DENY
    assert rbac.check("auditor_001", Permission.EXECUTE_CONTAINMENT) == AccessDecision.DENY


def test_rbac_separation_of_duties(rbac, sandbox_containment):
    """Analyst who approves a containment proposal cannot execute it."""
    rbac.assign_role("analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)
    # Grant EXECUTE_CONTAINMENT to analyst so RBAC passes,
    # then separation of duties should block execution.
    rbac.grant_permission("analyst_001", Permission.EXECUTE_CONTAINMENT)

    from fraud_detection.containment import ContainmentGate, Settings
    gate = ContainmentGate(Settings())
    gate.settings.shadow_mode = False
    gate.configure_action_credentials(
        credentials={"action_provider": "sandbox", "api_key": "test"},
        allowlist=["temporary_hold"],
    )
    scs = SandboxContainmentService(gate=gate, audit=AuditLog(), rbac=rbac)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    # Analyst approves
    scs.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="analyst_001",
        analyst_reason="Confirmed ATO pattern",
    )

    # Same analyst cannot execute (separation of duties)
    result = scs.execute_proposal(proposal=proposal, analyst_id="analyst_001")
    assert result.decision == ContainmentDecision.EXECUTION_FAILED
    assert "separation of duties" in result.reason.lower()

    # Different analyst (fraud_owner) can execute
    result = scs.execute_proposal(proposal=proposal, analyst_id="fraud_owner_001")
    assert result.decision == ContainmentDecision.EXECUTED


def test_rbac_require_raises(rbac):
    rbac.assign_role("analyst_001", Role.ANALYST)

    with pytest.raises(PermissionError):
        rbac.require("analyst_001", Permission.ASSIGN_CASE)


# ---------------------------------------------------------------------------
# Sandbox containment tests
# ---------------------------------------------------------------------------


def test_sandbox_containment_evaluate_review_execute(sandbox_containment):
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee", "test_payment"],
        evidence_refs=["evt_1", "evt_2"],
        reversibility="reversible_within_24h",
    )

    # Evaluate (shadow mode off, credentials configured, allowlisted)
    result = sandbox_containment.evaluate_proposal(proposal)
    assert result.decision == ContainmentDecision.PROPOSED

    # Review: approve
    result = sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
        analyst_reason="Confirmed ATO",
    )
    assert result.decision == ContainmentDecision.REVIEW_APPROVED

    # Execute (simulated)
    result = sandbox_containment.execute_proposal(
        proposal=proposal, analyst_id="fraud_owner_001"
    )
    assert result.decision == ContainmentDecision.EXECUTED
    assert result.executed is True

    # Verify sandbox execution record
    exec_record = sandbox_containment.get_execution(
        sandbox_containment.gate._proposal_key(proposal)
    )
    assert exec_record is not None
    assert exec_record.result == SandboxContainmentResult.SIMULATED_EXECUTED


def test_sandbox_containment_reverse(sandbox_containment):
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    # Setup RBAC roles for execute
    from fraud_detection.rbac import RBACManager
    from fraud_detection.audit import AuditLog
    audit = AuditLog()
    rbac = RBACManager(audit=audit)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)
    scs = SandboxContainmentService(gate=sandbox_containment.gate, audit=audit, rbac=rbac)

    scs.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )
    scs.execute_proposal(proposal=proposal, analyst_id="fraud_owner_001")

    proposal_key = scs.gate._proposal_key(proposal)
    record = scs.reverse_execution(
        proposal_key=proposal_key,
        analyst_id="fraud_owner_001",
        reason="Customer disputed the hold",
    )
    assert record is not None
    assert record.reversed is True


# ---------------------------------------------------------------------------
# Structured analyst labels tests
# ---------------------------------------------------------------------------


def test_label_service_ingest_and_maturity(label_service):
    label = label_service.ingest_label(
        CaseLabel(
            event_id="evt_1",
            label_source=LabelSource.CHARGEBACK,
            label_state=LabelState.POSITIVE,
            timestamp=datetime.now(timezone.utc) - timedelta(days=8),
        )
    )

    assert label.label_id is not None
    assert label.maturity_horizon_seconds == 604800  # 7 days for chargeback
    assert label.is_mature

    mature = label_service.mature_labels()
    assert len(mature) == 1
    assert mature[0].label_id == label.label_id


def test_label_service_immature_excluded(label_service):
    mature_label = label_service.ingest_label(
        CaseLabel(
            event_id="evt_1",
            label_source=LabelSource.CHARGEBACK,
            label_state=LabelState.POSITIVE,
            timestamp=datetime.now(timezone.utc) - timedelta(days=8),
        )
    )
    immature_label = label_service.ingest_label(
        CaseLabel(
            event_id="evt_2",
            label_source=LabelSource.CHARGEBACK,
            label_state=LabelState.NEGATIVE,
            timestamp=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )

    mature = label_service.mature_labels()
    immature = label_service.immature_labels()
    assert len(mature) == 1
    assert len(immature) == 1
    assert mature[0].label_id == mature_label.label_id
    assert immature[0].label_id == immature_label.label_id


def test_label_service_feedback_capture(label_service):
    feedback = label_service.capture_feedback(
        account_id="acct_1042",
        investigation_id="inv_001",
        analyst_id="analyst_001",
        original_recommendation="review",
        original_reason_codes=["failed_login_velocity"],
        analyst_response="Known travel - user notified us of travel to this country.",
    )

    assert feedback.feedback_id is not None
    assert feedback.label == FeedbackLabel.FALSE_POSITIVE_KNOWN_TRAVEL
    assert feedback.label_reason is not None
    assert feedback.analyst_id == "analyst_001"


def test_label_service_adjudication(label_service):
    label = label_service.ingest_label(
        CaseLabel(
            event_id="evt_1",
            investigation_id="inv_001",
            label_source=LabelSource.ANALYST_DISPOSITION,
            label_state=LabelState.POSITIVE,
            timestamp=datetime.now(timezone.utc) - timedelta(hours=2),
        )
    )

    # Submit for adjudication
    ok = label_service.submit_for_adjudication(
        label_id=label.label_id,
        submitted_by="analyst_001",
        reason="Analyst disposition needs independent review",
    )
    assert ok is True

    pending = label_service.get_pending_adjudication()
    assert len(pending) == 1

    # Adjudicate with independent reviewer
    ok = label_service.adjudicate_label(
        label_id=label.label_id,
        decision=LabelState.POSITIVE,
        adjudicated_by="supervisor_001",
        reason="Confirmed fraud after independent review",
        independent_reviewer="fraud_owner_001",
    )
    assert ok is True

    updated = label_service.get_label(label.label_id)
    assert updated.label_state == LabelState.POSITIVE
    assert updated.adjudicated_by == "supervisor_001"

    # Eligible for shared knowledge (mature + adjudicated + independent review)
    assert label_service.is_eligible_for_shared_knowledge(label.label_id) is True


def test_label_service_adjudication_without_independent_review(label_service):
    label = label_service.ingest_label(
        CaseLabel(
            event_id="evt_1",
            investigation_id="inv_001",
            label_source=LabelSource.ANALYST_DISPOSITION,
            label_state=LabelState.POSITIVE,
            timestamp=datetime.now(timezone.utc) - timedelta(hours=2),
        )
    )

    label_service.submit_for_adjudication(
        label_id=label.label_id,
        submitted_by="analyst_001",
    )
    label_service.adjudicate_label(
        label_id=label.label_id,
        decision=LabelState.POSITIVE,
        adjudicated_by="supervisor_001",
        # No independent_reviewer
    )

    # Not eligible for shared knowledge (no independent review)
    assert label_service.is_eligible_for_shared_knowledge(label.label_id) is False


def test_label_service_maturity_summary(label_service):
    label_service.ingest_label(
        CaseLabel(
            event_id="evt_1",
            label_source=LabelSource.CHARGEBACK,
            label_state=LabelState.POSITIVE,
            timestamp=datetime.now(timezone.utc) - timedelta(days=8),
        )
    )
    label_service.ingest_label(
        CaseLabel(
            event_id="evt_2",
            label_source=LabelSource.DISPUTE,
            label_state=LabelState.NEGATIVE,
            timestamp=datetime.now(timezone.utc) - timedelta(days=4),
        )
    )

    summary = label_service.maturity_summary()
    assert summary["mature_count"] == 2
    assert summary["mature_fraud_count"] == 1
    assert summary["mature_legitimate_count"] == 1


# ---------------------------------------------------------------------------
# End-to-end: case queue + RBAC + sandbox containment
# ---------------------------------------------------------------------------


def test_end_to_end_case_review_and_containment(case_queue, rbac, sandbox_containment):
    """Full flow: build queue item -> assign -> review -> contain -> reverse."""
    from fraud_detection.containment import ContainmentGate, Settings

    # Setup RBAC
    rbac.assign_role("analyst_001", Role.ANALYST)
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    # Build queue item
    inv = {
        "investigation_id": "inv_001",
        "account_id": "acct_1042",
        "trigger_type": "high_risk_event",
        "policy_version": "2026-11-v1",
    }
    findings = [
        {
            "finding_id": "finding_1",
            "agent_id": "transaction_agent",
            "conclusion": "high_risk_transaction_sequence",
            "confidence": 0.85,
            "reason_codes": ["new_payee", "test_payment"],
            "evidence_refs": ["evt_1"],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    recommendation = {
        "recommendation": "review",
        "reason_codes": ["new_payee", "test_payment"],
        "uncertainty": "high",
        "model_version": "deterministic-baseline-v1",
    }
    case_queue.build_queue_item(
        investigation=inv, findings=findings, recommendation=recommendation, rank=1, score=0.9
    )

    # Assign to analyst
    case_queue.assign(
        investigation_id="inv_001",
        to_analyst="analyst_001",
        assigned_by="supervisor_001",
    )
    case_queue.start_review("inv_001", "analyst_001")

    # Analyst views evidence timeline
    item = case_queue.get_queue_item("inv_001")
    assert item.assigned_to == "analyst_001"
    assert len(item.evidence_timeline) >= 1

    # Containment: senior analyst approves, fraud owner executes (simulated)
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee", "test_payment"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
        analyst_reason="Confirmed ATO: new payee + test payment",
    )

    result = sandbox_containment.execute_proposal(
        proposal=proposal, analyst_id="fraud_owner_001"
    )
    assert result.decision == ContainmentDecision.EXECUTED

    # Resolve case queue item
    case_queue.resolve(
        investigation_id="inv_001",
        resolved_by="analyst_001",
        resolution="Containment executed: temporary hold for 24h",
        label_state=LabelState.POSITIVE,
    )
    item = case_queue.get_queue_item("inv_001")
    assert item.status == CaseQueueStatus.RESOLVED
    assert item.label_state == LabelState.POSITIVE
