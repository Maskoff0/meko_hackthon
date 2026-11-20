"""Phase 5 tests: limited reversible automation.

Tests cover:
  - Action simulator
  - Proposal-versus-authorization boundary
  - Allowlist and permission denial
  - Limit boundaries (per-account daily, global hourly)
  - Budget/deadline enforcement
  - Kill switch
  - Expiry/reversal
  - Race and replay safety (idempotency)
  - Provider outage (Meko unavailable)
  - Drift/guardrail trip
  - Staged rollout and rollback drills
  - Deterministic fallback
  - Customer notification
  - Incident procedures
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
    ContainmentProposal,
    ContainmentReviewDecision,
    ContainmentGate,
    Settings,
)
from fraud_detection.domain import (
    AutomationAction,
    AutomationDecision,
    AutomationExecutionStatus,
    AutomationPolicy,
    AutomationStage,
    FallbackReason,
    FreshCheckResult,
    LabelState,
    Permission,
    Role,
    SandboxContainmentResult,
)
from fraud_detection.label_service import LabelService
from fraud_detection.rbac import RBACManager
from fraud_detection.reversible_automation import (
    ActionSimulator,
    ReversibleAutomationEngine,
)
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
    return AuditLog(log_path="/tmp/test_phase5_audit.log")


@pytest.fixture
def rbac(audit):
    return RBACManager(audit=audit)


@pytest.fixture
def case_queue(storage, audit):
    return CaseQueue(storage=storage, audit=audit)


@pytest.fixture
def label_service(audit):
    return LabelService(audit=audit)


@pytest.fixture
def orchestrator(storage):
    from fraud_detection.orchestration import Orchestrator
    return Orchestrator(storage=storage)


@pytest.fixture
def containment_gate():
    gate = ContainmentGate(Settings())
    gate.settings.shadow_mode = False
    gate.configure_action_credentials(
        credentials={"action_provider": "sandbox", "api_key": "test"},
        allowlist=["temporary_hold", "limit_reduction"],
    )
    return gate


@pytest.fixture
def sandbox_containment(containment_gate, audit, rbac):
    from fraud_detection.sandbox_containment import SandboxContainmentService
    return SandboxContainmentService(
        gate=containment_gate, audit=audit, rbac=rbac
    )


@pytest.fixture
def automation_policy():
    return AutomationPolicy(
        enabled=True,
        stage=AutomationStage.COHORT_1,
        allowlist=[AutomationAction.TEMPORARY_HOLD, AutomationAction.LIMIT_REDUCTION],
        max_actions_per_account_per_day=2,
        max_actions_global_per_hour=5,
        min_confidence_for_automation=0.90,
        customer_notification_required=True,
        kill_switch_active=False,
        cohort_percentage=100.0,
    )


@pytest.fixture
def automation_engine(
    automation_policy, containment_gate, rbac, audit, case_queue,
    label_service, orchestrator, sandbox_containment,
):
    return ReversibleAutomationEngine(
        policy=automation_policy,
        gate_settings=containment_gate.settings,
        rbac=rbac,
        audit=audit,
        case_queue=case_queue,
        label_service=label_service,
        orchestrator=orchestrator,
        sandbox_containment=sandbox_containment,
        action_simulator=ActionSimulator(failure_rate=0.0),
    )


# ---------------------------------------------------------------------------
# Action simulator tests
# ---------------------------------------------------------------------------


def test_action_simulator_success():
    sim = ActionSimulator(failure_rate=0.0)
    success, reason = sim.simulate(
        AutomationAction.TEMPORARY_HOLD, "acct_1042", "acct_1042"
    )
    assert success is True
    assert "success" in reason.lower()


def test_action_simulator_failure():
    sim = ActionSimulator(failure_rate=1.0)
    success, reason = sim.simulate(
        AutomationAction.TEMPORARY_HOLD, "acct_1042", "acct_1042"
    )
    assert success is False
    assert "failure" in reason.lower()


# ---------------------------------------------------------------------------
# Fresh execution checks tests
# ---------------------------------------------------------------------------


def test_fresh_checks_kill_switch(automation_engine, automation_policy):
    """Kill switch active blocks all automation."""
    automation_engine.activate_kill_switch("fraud_owner_001")

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is False
    assert any(c.name == "kill_switch" for c in decision.fresh_checks)
    assert any(c.result == FreshCheckResult.FAIL for c in decision.fresh_checks)

    automation_engine.deactivate_kill_switch("fraud_owner_001")


def test_fresh_checks_policy_disabled(automation_engine, automation_policy):
    """Disabled policy blocks automation."""
    automation_policy.enabled = False

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is False


def test_fresh_checks_not_allowlisted(automation_engine, automation_policy):
    """Action not on allowlist is denied."""
    automation_policy.allowlist = [AutomationAction.SESSION_RESET]

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is False
    assert any(c.name == "allowlist" for c in decision.fresh_checks)
    assert any(
        c.result == FreshCheckResult.FAIL for c in decision.fresh_checks
        if c.name == "allowlist"
    )


def test_fresh_checks_insufficient_permissions(automation_engine, rbac):
    """Analyst without EXECUTE_CONTAINMENT permission is denied."""
    rbac.assign_role("analyst_001", Role.ANALYST)  # no EXECUTE_CONTAINMENT

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="analyst_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is False
    assert any(c.name == "permissions" for c in decision.fresh_checks)


def test_fresh_checks_separation_of_duties(automation_engine, sandbox_containment):
    """Analyst who approved cannot execute."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    # Senior analyst approves
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
        analyst_reason="Confirmed",
    )

    # Same analyst tries to execute - separation of duties
    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="senior_analyst_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is False
    assert any(c.name == "separation_of_duties" for c in decision.fresh_checks)


def test_fresh_checks_idempotency(automation_engine, sandbox_containment):
    """Duplicate proposal execution is denied."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    # First execution: senior analyst approves, fraud owner executes
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )
    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert result.result == AutomationExecutionStatus.EXECUTED

    # Second execution of same proposal - idempotency
    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is False
    assert any(c.name == "idempotency" for c in decision.fresh_checks)


def test_fresh_checks_low_confidence(automation_engine, automation_policy):
    """Evidence confidence below minimum threshold is denied."""
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.5,  # below 0.90 minimum
    )
    assert decision.execute is False
    assert any(c.name == "evidence_confidence" for c in decision.fresh_checks)


def test_fresh_checks_no_reversal_path(automation_engine, automation_policy):
    """Proposal without reversibility/expiry is denied."""
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="none",  # no reversal path
        expiry_seconds=None,
    )

    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is False
    assert any(c.name == "reversal_path" for c in decision.fresh_checks)


def test_fresh_checks_all_pass(automation_engine, sandbox_containment):
    """All fresh checks pass for a valid proposal."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )

    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is True
    assert all(c.result == FreshCheckResult.PASS for c in decision.fresh_checks)


# ---------------------------------------------------------------------------
# Limit boundary tests
# ---------------------------------------------------------------------------


def test_per_account_daily_limit(automation_engine, automation_policy, sandbox_containment):
    """Per-account daily limit blocks additional actions."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    # Execute up to the limit (2 per account per day)
    for i in range(2):
        proposal = ContainmentProposal(
            action_type="temporary_hold",
            target="acct_1042",
            reason_codes=["new_payee"],
            evidence_refs=[f"evt_{i}"],
            reversibility="reversible_within_24h",
        )
        sandbox_containment.review_proposal(
            proposal=proposal,
            decision=ContainmentReviewDecision.APPROVE,
            analyst_id="senior_analyst_001",
        )
        result = automation_engine.execute(
            proposal=proposal,
            analyst_id="fraud_owner_001",
            evidence_confidence=0.95,
        )
        assert result.result == AutomationExecutionStatus.EXECUTED

    # Third execution should be denied by per-account daily limit
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_3"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )
    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert result.result == AutomationExecutionStatus.DENIED
    assert result.fallback_reason == FallbackReason.GUARDRAIL_VIOLATION


def test_global_hourly_limit(automation_engine, automation_policy, sandbox_containment):
    """Global hourly limit blocks additional actions."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    # Set global limit very low
    automation_policy.max_actions_global_per_hour = 2

    # Execute up to the limit across different accounts
    for i in range(2):
        proposal = ContainmentProposal(
            action_type="temporary_hold",
            target=f"acct_{i:03d}",
            reason_codes=["new_payee"],
            evidence_refs=[f"evt_{i}"],
            reversibility="reversible_within_24h",
        )
        sandbox_containment.review_proposal(
            proposal=proposal,
            decision=ContainmentReviewDecision.APPROVE,
            analyst_id="senior_analyst_001",
        )
        result = automation_engine.execute(
            proposal=proposal,
            analyst_id="fraud_owner_001",
            evidence_confidence=0.95,
        )
        assert result.result == AutomationExecutionStatus.EXECUTED

    # Third execution should be denied by global hourly limit
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_999",
        reason_codes=["new_payee"],
        evidence_refs=["evt_999"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )
    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert result.result == AutomationExecutionStatus.DENIED


# ---------------------------------------------------------------------------
# Budget/deadline enforcement tests
# ---------------------------------------------------------------------------


def test_budget_exhaustion_fallback(automation_engine, orchestrator, storage, sandbox_containment):
    """Budget exhaustion triggers deterministic fallback."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    # Create an investigation and exhaust its budget
    from fraud_detection.domain import AccountEvent, EventType
    event = AccountEvent(
        account_id="acct_1042",
        event_type=EventType.LOGIN,
        source="synthetic_login_agent",
    )
    investigation = orchestrator.create_investigation(
        event=event,
        trigger_type="high_risk_event",
        hypothesis="test",
    )

    # Exhaust the tool call budget
    inv_id = investigation.investigation_id
    for _ in range(investigation.tool_call_budget):
        orchestrator.record_tool_call(inv_id)

    # Budget should be exhausted
    ok, reason = orchestrator.check_budget(inv_id)
    assert ok is False

    # Automation should fall back
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )

    record = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        investigation_id=inv_id,
        evidence_confidence=0.95,
    )
    assert record.result == AutomationExecutionStatus.DENIED
    assert "budget" in record.reason.lower()


# ---------------------------------------------------------------------------
# Kill switch tests
# ---------------------------------------------------------------------------


def test_kill_switch_activate_deactivate(automation_engine, rbac):
    """Kill switch can be activated and deactivated by authorized user."""
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    assert automation_engine.activate_kill_switch("fraud_owner_001") is True
    assert automation_engine._kill_switch_active is True
    assert automation_engine.policy.kill_switch_active is True

    assert automation_engine.deactivate_kill_switch("fraud_owner_001") is True
    assert automation_engine._kill_switch_active is False
    assert automation_engine.policy.kill_switch_active is False


def test_kill_switch_blocks_execution(automation_engine, sandbox_containment):
    """Kill switch blocks all automation executions."""
    rbac = automation_engine.rbac
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    automation_engine.activate_kill_switch("fraud_owner_001")

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="fraud_owner_001",
    )

    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert result.result == AutomationExecutionStatus.DENIED

    automation_engine.deactivate_kill_switch("fraud_owner_001")


# ---------------------------------------------------------------------------
# Expiry/reversal tests
# ---------------------------------------------------------------------------


def test_reversal(automation_engine, sandbox_containment):
    """Executed action can be reversed."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )

    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert result.result == AutomationExecutionStatus.EXECUTED

    # Reverse it
    reversed_record = automation_engine.reverse(
        execution_id=result.execution_id,
        analyst_id="fraud_owner_001",
        reason="Customer disputed the hold",
    )
    assert reversed_record is not None
    assert reversed_record.reversed is True
    assert reversed_record.result == AutomationExecutionStatus.REVERSED


def test_double_reversal_returns_same(automation_engine, sandbox_containment):
    """Reversing an already-reversed action returns the same record."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )

    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    automation_engine.reverse(
        execution_id=result.execution_id,
        analyst_id="fraud_owner_001",
    )

    # Second reversal should return the same record (already reversed)
    again = automation_engine.reverse(
        execution_id=result.execution_id,
        analyst_id="fraud_owner_001",
    )
    assert again is not None
    assert again.reversed is True


# ---------------------------------------------------------------------------
# Race and replay safety (idempotency) tests
# ---------------------------------------------------------------------------


def test_idempotent_replay_denied(automation_engine, sandbox_containment):
    """Same proposal cannot be executed twice (idempotency)."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )

    # First execution
    result1 = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert result1.result == AutomationExecutionStatus.EXECUTED

    # Second execution of same proposal - should be denied
    result2 = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert result2.result == AutomationExecutionStatus.DENIED


# ---------------------------------------------------------------------------
# Provider outage tests
# ---------------------------------------------------------------------------


def test_meko_outage_fallback(automation_engine, sandbox_containment):
    """Meko outage triggers deterministic fallback."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )

    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        meko_available=False,
        evidence_confidence=0.95,
    )
    assert result.result == AutomationExecutionStatus.DENIED
    assert "meko" in result.reason.lower()


# ---------------------------------------------------------------------------
# Drift/guardrail trip tests
# ---------------------------------------------------------------------------


def test_drift_guardrail_trip(automation_engine, automation_policy):
    """High drift score triggers guardrail violation and denial."""
    # Set drift score above the max
    metrics = automation_engine._canary_metrics[automation_policy.stage]
    metrics.drift_score = 0.5  # above 0.15 max
    metrics.false_positive_rate = 0.01  # low FPR

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is False
    assert any(c.name == "drift_within_bounds" for c in decision.fresh_checks)
    assert len(decision.guardrail_violations) > 0
    assert decision.guardrail_violations[0].auto_stopped is True


def test_false_positive_rate_guardrail_trip(automation_engine, automation_policy):
    """High false positive rate triggers guardrail violation."""
    metrics = automation_engine._canary_metrics[automation_policy.stage]
    metrics.drift_score = 0.01  # low drift
    metrics.false_positive_rate = 0.2  # above 0.05 max

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )

    decision = automation_engine.run_fresh_checks(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert decision.execute is False
    assert any(c.name == "false_positive_rate_within_bounds" for c in decision.fresh_checks)


# ---------------------------------------------------------------------------
# Staged rollout and rollback tests
# ---------------------------------------------------------------------------


def test_canary_stage_advance(automation_engine, rbac):
    """Canary stage can be advanced by authorized user."""
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    assert automation_engine.policy.stage == AutomationStage.COHORT_1
    assert automation_engine.advance_stage(AutomationStage.COHORT_2, "fraud_owner_001") is True
    assert automation_engine.policy.stage == AutomationStage.COHORT_2


def test_canary_auto_rollback_on_violations(automation_engine, rbac):
    """Guardrail violations cause automatic rollback instead of advancement."""
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    # Create a recent guardrail violation
    from fraud_detection.domain import GuardrailViolation, GuardrailSeverity
    violation = GuardrailViolation(
        account_id="acct_1042",
        action_type=AutomationAction.TEMPORARY_HOLD,
        severity=GuardrailSeverity.TRIP,
        description="test violation",
        limit_type="drift",
        current_value=0.5,
        limit_value=0.15,
        auto_stopped=True,
    )
    automation_engine._violations.append(violation)

    # Try to advance - should auto-rollback instead
    result = automation_engine.advance_stage(AutomationStage.COHORT_2, "fraud_owner_001")
    assert result is False
    assert automation_engine.policy.stage == AutomationStage.ROLLED_BACK


def test_manual_rollback(automation_engine, rbac):
    """Manual rollback sets stage to rolled_back."""
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    automation_engine.advance_stage(AutomationStage.COHORT_2, "fraud_owner_001")
    assert automation_engine.policy.stage == AutomationStage.COHORT_2

    automation_engine.rollback("fraud_owner_001", "Guardrail violation")
    assert automation_engine.policy.stage == AutomationStage.ROLLED_BACK


# ---------------------------------------------------------------------------
# Deterministic fallback tests
# ---------------------------------------------------------------------------


def test_uncertain_evidence_fallback(automation_engine, sandbox_containment):
    """Uncertain evidence triggers fallback (not execution)."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )

    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.5,  # below 0.90
    )
    assert result.result == AutomationExecutionStatus.DENIED
    assert result.fallback_reason == FallbackReason.UNCERTAIN_EVIDENCE


# ---------------------------------------------------------------------------
# Customer notification tests
# ---------------------------------------------------------------------------


def test_customer_notification_sent(automation_engine, sandbox_containment):
    """Customer is notified when automation executes."""
    rbac = automation_engine.rbac
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee"],
        evidence_refs=["evt_1"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
    )

    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert result.customer_notified is True
    assert result.notification_id is not None


# ---------------------------------------------------------------------------
# Incident procedure tests
# ---------------------------------------------------------------------------


def test_open_and_close_incident(automation_engine):
    """Incident can be opened and closed."""
    incident = automation_engine.open_incident(
        execution_id="exec_123",
        account_id="acct_1042",
        title="Test incident",
        severity="high",
    )
    assert incident.incident_id is not None
    assert incident.severity == "high"

    closed = automation_engine.close_incident(
        incident_id=incident.incident_id,
        resolution="Resolved",
        reversed=True,
    )
    assert closed is not None
    assert closed.closed_at is not None
    assert closed.resolution == "Resolved"
    assert closed.reversed is True


# ---------------------------------------------------------------------------
# End-to-end: full automation flow
# ---------------------------------------------------------------------------


def test_end_to_end_automation_flow(automation_engine, sandbox_containment, rbac):
    """Full flow: approve -> execute -> reverse -> incident."""
    rbac.assign_role("senior_analyst_001", Role.SENIOR_ANALYST)
    rbac.assign_role("fraud_owner_001", Role.FRAUD_OWNER)

    # 1. Senior analyst approves containment proposal
    proposal = ContainmentProposal(
        action_type="temporary_hold",
        target="acct_1042",
        reason_codes=["new_payee", "test_payment"],
        evidence_refs=["evt_1", "evt_2"],
        reversibility="reversible_within_24h",
    )
    sandbox_containment.review_proposal(
        proposal=proposal,
        decision=ContainmentReviewDecision.APPROVE,
        analyst_id="senior_analyst_001",
        analyst_reason="Confirmed ATO: new payee + test payment",
    )

    # 2. Fraud owner executes (automation)
    result = automation_engine.execute(
        proposal=proposal,
        analyst_id="fraud_owner_001",
        evidence_confidence=0.95,
    )
    assert result.result == AutomationExecutionStatus.EXECUTED
    assert result.customer_notified is True

    # 3. Reverse the action
    reversed_record = automation_engine.reverse(
        execution_id=result.execution_id,
        analyst_id="fraud_owner_001",
        reason="Customer disputed the hold",
    )
    assert reversed_record is not None
    assert reversed_record.reversed is True

    # 4. Open and close an incident
    incident = automation_engine.open_incident(
        execution_id=result.execution_id,
        account_id="acct_1042",
        title="ATO containment reversed",
        severity="medium",
    )
    assert incident is not None

    closed = automation_engine.close_incident(
        incident_id=incident.incident_id,
        resolution="Reversed after customer dispute",
        reversed=True,
    )
    assert closed is not None
    assert closed.reversed is True
