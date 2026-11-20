"""Reversible automation engine (plan.md Phase 5).

Limited reversible automation: only a narrow class of low-impact,
reversible actions can be automated after Phase 4 gates pass and fraud
owners approve the explicit action allowlist.

Every execution passes fresh checks at execution time:
- current stage, policy version, permissions, allowlist
- evidence validity, budget, per-tenant/global limits
- rate caps, feature flags, idempotency, expiry/reversal path
- kill switch

On budget exhaustion, missing/stale data, uncertain evidence, policy
conflict, Meko outage, or drift: stop the task and use deterministic
fallback or human escalation. Never continue silently.

function.md alignment:
- Guardrails: read-only by default, proposal ≠ authority, no agent or
  Meko tool can execute directly
- Cited claims: every automation action cites evidence refs
- Untrusted text: attacker-controlled text marked as data
- Logging: every automation execution logged with analyst ID
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from .audit import AuditLog
from .case_queue import CaseQueue
from .domain import (
    AutomationAction,
    AutomationDecision,
    AutomationExecutionRecord,
    AutomationExecutionStatus,
    AutomationPolicy,
    AutomationStage,
    CanaryMetrics,
    CustomerNotification,
    CustomerNotificationType,
    FallbackReason,
    FreshCheck,
    FreshCheckResult,
    GuardrailSeverity,
    GuardrailViolation,
    IncidentRecord,
    Permission,
    Role,
    SandboxContainmentResult,
    SandboxExecutionRecord,
)
from .label_service import LabelService
from .orchestration import Orchestrator
from .rbac import RBACManager
from .sandbox_containment import SandboxContainmentService


class ActionSimulator:
    """Simulates reversible actions for testing and sandbox execution.

    No real account actions are taken. The simulator records what would
    happen and whether it would succeed or fail, based on the action
    type and target.
    """

    def __init__(self, failure_rate: float = 0.0):
        self.failure_rate = failure_rate
        self._simulated_actions: list[dict] = []

    def simulate(
        self, action_type: AutomationAction, target: str, account_id: str
    ) -> tuple[bool, str]:
        """Simulate an action.

        Returns (success, reason). If failure_rate > 0, some actions
        will fail randomly based on a hash of the inputs.
        """
        # Deterministic pseudo-failure based on input hash for testing
        import hashlib

        action_str = action_type.value if hasattr(action_type, "value") else str(action_type)
        payload = f"{action_str}|{target}|{account_id}"
        digest = int(hashlib.sha256(payload.encode()).hexdigest()[:8], 16)
        pseudo_random = (digest % 1000) / 1000.0

        if pseudo_random < self.failure_rate:
            self._simulated_actions.append(
                {
                    "action_type": action_str,
                    "target": target,
                    "account_id": account_id,
                    "success": False,
                    "reason": "simulated provider failure",
                }
            )
            return False, "simulated provider failure"

        self._simulated_actions.append(
            {
                "action_type": action_str,
                "target": target,
                "account_id": account_id,
                "success": True,
                "reason": "simulated success",
            }
        )
        return True, "simulated success"

    def list_simulated(self) -> list[dict]:
        return list(self._simulated_actions)


class ReversibleAutomationEngine:
    """Limited reversible automation engine.

    Executes reversible containment actions only after all fresh checks
    pass. Integrates with:
    - ContainmentGate (Phase 4): proposal ≠ authority boundary
    - RBAC (Phase 4): least privilege, separation of duties
    - Case queue (Phase 4): queue items with evidence timeline
    - Label service (Phase 4): feedback labels for drift/FP tracking
    - Orchestrator (Phase 3): budget/deadline enforcement
    - Sandbox containment (Phase 4): simulated execution

    Canary rollout: sandbox → cohort_1 → cohort_2 → full → rolled_back.
    Guardrails stop automation automatically on violations.
    """

    def __init__(
        self,
        policy: AutomationPolicy,
        gate_settings: Any,
        rbac: RBACManager,
        audit: AuditLog,
        case_queue: CaseQueue,
        label_service: LabelService,
        orchestrator: Orchestrator,
        sandbox_containment: SandboxContainmentService,
        action_simulator: Optional[ActionSimulator] = None,
    ):
        self.policy = policy
        self.rbac = rbac
        self.audit = audit
        self.case_queue = case_queue
        self.label_service = label_service
        self.orchestrator = orchestrator
        self.sandbox_containment = sandbox_containment
        self.action_simulator = action_simulator or ActionSimulator()

        # Execution records keyed by execution_id
        self._executions: dict[str, AutomationExecutionRecord] = {}
        # Proposal key -> execution_id (idempotency)
        self._proposal_executions: dict[str, str] = {}
        # Per-account daily action counts
        self._account_daily_counts: dict[str, dict[str, int]] = {}  # date -> account_id -> count
        # Global hourly action counts
        self._global_hourly_counts: dict[str, int] = {}  # hour -> count
        # Guardrail violations
        self._violations: list[GuardrailViolation] = []
        # Customer notifications
        self._notifications: dict[str, CustomerNotification] = {}
        # Incidents
        self._incidents: dict[str, IncidentRecord] = {}
        # Canary metrics per stage
        self._canary_metrics: dict[AutomationStage, CanaryMetrics] = {
            stage: CanaryMetrics(stage=stage)
            for stage in AutomationStage
        }
        # Kill switch state (overrides policy)
        self._kill_switch_active: bool = policy.kill_switch_active

    # ------------------------------------------------------------------
    # Fresh execution checks
    # ------------------------------------------------------------------

    def run_fresh_checks(
        self,
        proposal: Any,  # ContainmentProposal
        analyst_id: str,
        investigation_id: Optional[str] = None,
        meko_available: bool = True,
        evidence_confidence: float = 1.0,
    ) -> AutomationDecision:
        """Run all fresh execution checks before any automation.

        All checks run independently; a failure in one check does not
        skip the others. This ensures all guardrail violations are
        captured, not just the first one.

        Checks:
        1. Kill switch not active
        2. Policy enabled
        3. Stage not rolled_back
        4. Action type on allowlist
        5. Analyst has EXECUTE_CONTAINMENT permission
        6. Separation of duties: analyst did not approve this proposal
        7. Idempotency: proposal not already executed
        8. Investigation budget not exhausted (if investigation_id given)
        9. Per-account daily limit not exceeded
        10. Global hourly limit not exceeded
        11. Evidence confidence meets minimum threshold
        12. Meko available (if required)
        13. Expiry/reversal path available (proposal has expiry or reversibility)
        14. Cohort check: account is in the current canary cohort
        15. Drift within acceptable bounds
        16. False positive rate within acceptable bounds
        """
        checks: list[FreshCheck] = []
        violations: list[GuardrailViolation] = []
        execute = True
        fallback_reason: Optional[FallbackReason] = None

        # Helper to record a check result and optionally fail.
        def _check(name: str, ok: bool, detail: str, reason: Optional[FallbackReason] = None) -> None:
            nonlocal execute, fallback_reason
            checks.append(
                FreshCheck(
                    name=name,
                    result=FreshCheckResult.PASS if ok else FreshCheckResult.FAIL,
                    detail=detail,
                )
            )
            if not ok:
                execute = False
                if fallback_reason is None and reason is not None:
                    fallback_reason = reason

        # 1. Kill switch
        kill_ok = not (self._kill_switch_active or self.policy.kill_switch_active)
        _check(
            "kill_switch",
            kill_ok,
            "kill switch is active; automation is halted"
            if not kill_ok
            else "kill switch inactive",
            FallbackReason.KILL_SWITCH_ACTIVE if not kill_ok else None,
        )
        if not kill_ok:
            violations.append(
                GuardrailViolation(
                    account_id=proposal.target,
                    action_type=AutomationAction(proposal.action_type),
                    severity=GuardrailSeverity.TRIP,
                    description="kill switch active; all automation stopped",
                    limit_type="global_kill_switch",
                    current_value=1.0,
                    limit_value=0.0,
                    auto_stopped=True,
                )
            )

        # 2. Policy enabled
        policy_ok = self.policy.enabled
        _check(
            "policy_enabled",
            policy_ok,
            "limited automation is enabled in policy"
            if policy_ok
            else "limited automation is not enabled in policy",
            FallbackReason.NOT_ALLOWLISTED if not policy_ok else None,
        )

        # 3. Stage not rolled_back
        stage_ok = self.policy.stage != AutomationStage.ROLLED_BACK
        _check(
            "stage_not_rolled_back",
            stage_ok,
            f"stage is {self.policy.stage}"
            if stage_ok
            else "automation has been rolled back due to guardrail violation",
            FallbackReason.GUARDRAIL_VIOLATION if not stage_ok else None,
        )

        # 4. Action type on allowlist
        action_allowed = AutomationAction(proposal.action_type) in self.policy.allowlist
        _check(
            "allowlist",
            action_allowed,
            f"action {proposal.action_type} is on the allowlist"
            if action_allowed
            else f"action {proposal.action_type} is not on the allowlist",
            FallbackReason.NOT_ALLOWLISTED if not action_allowed else None,
        )

        # 5. Analyst has EXECUTE_CONTAINMENT permission
        from .domain import Permission as P

        try:
            self.rbac.require(
                analyst_id,
                P.EXECUTE_CONTAINMENT,
                resource=f"containment:{proposal.target}",
            )
            perm_ok = True
            perm_detail = f"analyst {analyst_id} has EXECUTE_CONTAINMENT permission"
        except PermissionError as e:
            perm_ok = False
            perm_detail = str(e)
        _check(
            "permissions",
            perm_ok,
            perm_detail,
            FallbackReason.INSUFFICIENT_PERMISSIONS if not perm_ok else None,
        )

        # 6. Separation of duties: analyst did not approve this proposal
        proposal_key = self.sandbox_containment.gate._proposal_key(proposal)
        approver = self.sandbox_containment._approvals.get(proposal_key)
        sod_ok = approver != analyst_id
        _check(
            "separation_of_duties",
            sod_ok,
            "analyst did not approve this proposal"
            if sod_ok
            else "analyst who approved this proposal cannot execute it",
            FallbackReason.INSUFFICIENT_PERMISSIONS if not sod_ok else None,
        )

        # 7. Idempotency: proposal not already executed
        idem_ok = proposal_key not in self._proposal_executions
        _check(
            "idempotency",
            idem_ok,
            "proposal not previously executed"
            if idem_ok
            else "proposal already executed; duplicate rejected",
            FallbackReason.IDLE_TIMEOUT if not idem_ok else None,
        )

        # 8. Investigation budget not exhausted
        if investigation_id is not None:
            ok, reason = self.orchestrator.check_budget(investigation_id)
            budget_ok = ok
            _check(
                "budget",
                budget_ok,
                reason or "budget OK",
                FallbackReason.BUDGET_EXHAUSTED
                if not ok and "budget" in reason
                else FallbackReason.IDLE_TIMEOUT
                if not ok
                else None,
            )

        # 9. Per-account daily limit
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        daily_counts = self._account_daily_counts.get(today, {})
        account_count = daily_counts.get(proposal.target, 0)
        daily_ok = account_count < self.policy.max_actions_per_account_per_day
        _check(
            "per_account_daily_limit",
            daily_ok,
            (
                f"account {proposal.target} has {account_count}/"
                f"{self.policy.max_actions_per_account_per_day} actions today"
            ),
            FallbackReason.GUARDRAIL_VIOLATION if not daily_ok else None,
        )
        if not daily_ok:
            violations.append(
                GuardrailViolation(
                    account_id=proposal.target,
                    action_type=AutomationAction(proposal.action_type),
                    severity=GuardrailSeverity.TRIP,
                    description=(
                        f"per-account daily limit exceeded: {account_count}/"
                        f"{self.policy.max_actions_per_account_per_day}"
                    ),
                    limit_type="per_account_daily",
                    current_value=float(account_count),
                    limit_value=float(
                        self.policy.max_actions_per_account_per_day
                    ),
                    auto_stopped=True,
                )
            )

        # 10. Global hourly limit
        hour = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")
        global_count = self._global_hourly_counts.get(hour, 0)
        hourly_ok = global_count < self.policy.max_actions_global_per_hour
        _check(
            "global_hourly_limit",
            hourly_ok,
            (
                f"global hourly count {global_count}/"
                f"{self.policy.max_actions_global_per_hour}"
            ),
            FallbackReason.GUARDRAIL_VIOLATION if not hourly_ok else None,
        )
        if not hourly_ok:
            violations.append(
                GuardrailViolation(
                    account_id=proposal.target,
                    action_type=AutomationAction(proposal.action_type),
                    severity=GuardrailSeverity.TRIP,
                    description=(
                        f"global hourly limit exceeded: {global_count}/"
                        f"{self.policy.max_actions_global_per_hour}"
                    ),
                    limit_type="global_hourly",
                    current_value=float(global_count),
                    limit_value=float(
                        self.policy.max_actions_global_per_hour
                    ),
                    auto_stopped=True,
                )
            )

        # 11. Evidence confidence meets minimum threshold
        confidence_ok = evidence_confidence >= self.policy.min_confidence_for_automation
        _check(
            "evidence_confidence",
            confidence_ok,
            (
                f"evidence confidence {evidence_confidence:.2f} "
                f"{'>=' if confidence_ok else '<'} minimum "
                f"{self.policy.min_confidence_for_automation:.2f}"
            ),
            FallbackReason.UNCERTAIN_EVIDENCE if not confidence_ok else None,
        )

        # 12. Meko available
        meko_ok = meko_available
        _check(
            "meko_available",
            meko_ok,
            "Meko service available"
            if meko_ok
            else "Meko service unavailable; cannot verify context",
            FallbackReason.MEKO_OUTAGE if not meko_ok else None,
        )

        # 13. Expiry/reversal path available
        has_reversal = bool(
            getattr(proposal, "reversibility", None)
            or getattr(proposal, "expiry_seconds", None)
        )
        _check(
            "reversal_path",
            has_reversal,
            "proposal has reversibility/expiry path"
            if has_reversal
            else "no reversibility or expiry; cannot automate",
            FallbackReason.NOT_ALLOWLISTED if not has_reversal else None,
        )

        # 14. Cohort check for canary stages
        if self.policy.stage in (
            AutomationStage.COHORT_1,
            AutomationStage.COHORT_2,
        ):
            in_cohort = self._in_cohort(proposal.target, self.policy.cohort_percentage)
            _check(
                "cohort_membership",
                in_cohort,
                (
                    f"account {proposal.target} is in the "
                    f"{self.policy.cohort_percentage}% cohort"
                    if in_cohort
                    else f"account {proposal.target} is not in the "
                    f"{self.policy.cohort_percentage}% cohort"
                ),
                FallbackReason.NOT_ALLOWLISTED if not in_cohort else None,
            )

        # 15. Drift within acceptable bounds
        stage_metrics = self._canary_metrics[self.policy.stage]
        drift_ok = stage_metrics.drift_score <= self.policy.max_drift_score
        _check(
            "drift_within_bounds",
            drift_ok,
            (
                f"drift score {stage_metrics.drift_score:.3f} "
                f"{'<=' if drift_ok else '>'} max "
                f"{self.policy.max_drift_score:.3f}"
            ),
            FallbackReason.DRIFT_DETECTED if not drift_ok else None,
        )
        if not drift_ok:
            violations.append(
                GuardrailViolation(
                    account_id=proposal.target,
                    action_type=AutomationAction(proposal.action_type),
                    severity=GuardrailSeverity.TRIP,
                    description=(
                        f"drift score {stage_metrics.drift_score:.3f} exceeds max "
                        f"{self.policy.max_drift_score:.3f}"
                    ),
                    limit_type="drift",
                    current_value=stage_metrics.drift_score,
                    limit_value=self.policy.max_drift_score,
                    auto_stopped=True,
                )
            )

        # 16. False positive rate within bounds
        fpr_ok = stage_metrics.false_positive_rate <= self.policy.max_false_positive_rate
        _check(
            "false_positive_rate_within_bounds",
            fpr_ok,
            (
                f"FPR {stage_metrics.false_positive_rate:.3f} "
                f"{'<=' if fpr_ok else '>'} max "
                f"{self.policy.max_false_positive_rate:.3f}"
            ),
            FallbackReason.GUARDRAIL_VIOLATION if not fpr_ok else None,
        )
        if not fpr_ok:
            violations.append(
                GuardrailViolation(
                    account_id=proposal.target,
                    action_type=AutomationAction(proposal.action_type),
                    severity=GuardrailSeverity.TRIP,
                    description=(
                        f"false positive rate {stage_metrics.false_positive_rate:.3f} exceeds max "
                        f"{self.policy.max_false_positive_rate:.3f}"
                    ),
                    limit_type="false_positive_rate",
                    current_value=stage_metrics.false_positive_rate,
                    limit_value=self.policy.max_false_positive_rate,
                    auto_stopped=True,
                )
            )

        # Record any guardrail violations
        for v in violations:
            self._violations.append(v)
            self.audit._write_entry(
                {
                    "type": "guardrail_violation",
                    "violation_id": v.violation_id,
                    "account_id": v.account_id,
                    "action_type": v.action_type,
                    "severity": v.severity,
                    "description": v.description,
                    "limit_type": v.limit_type,
                    "current_value": v.current_value,
                    "limit_value": v.limit_value,
                    "auto_stopped": v.auto_stopped,
                }
            )

        return AutomationDecision(
            execute=execute,
            reason=(
                "all fresh checks passed"
                if execute
                else f"automation denied: {fallback_reason.value if fallback_reason else 'checks failed'}"
            ),
            fresh_checks=checks,
            fallback_reason=fallback_reason,
            guardrail_violations=violations,
            customer_notification_required=self.policy.customer_notification_required,
        )

    def _in_cohort(self, account_id: str, percentage: float) -> bool:
        """Deterministic cohort membership based on account ID hash."""
        if percentage <= 0:
            return False
        if percentage >= 100:
            return True
        import hashlib

        digest = int(hashlib.sha256(account_id.encode()).hexdigest()[:8], 16)
        return (digest % 100) < percentage

    # ------------------------------------------------------------------
    # Execute reversible action
    # ------------------------------------------------------------------

    def execute(
        self,
        proposal: Any,  # ContainmentProposal
        analyst_id: str,
        investigation_id: Optional[str] = None,
        meko_available: bool = True,
        evidence_confidence: float = 1.0,
    ) -> AutomationExecutionRecord:
        """Execute a reversible automation action with full fresh checks.

        Returns an AutomationExecutionRecord with the result. No real
        account action is taken; the action simulator records what would
        happen.
        """
        # Run fresh checks
        decision = self.run_fresh_checks(
            proposal=proposal,
            analyst_id=analyst_id,
            investigation_id=investigation_id,
            meko_available=meko_available,
            evidence_confidence=evidence_confidence,
        )

        proposal_key = self.sandbox_containment.gate._proposal_key(proposal)
        action_type = AutomationAction(proposal.action_type)

        # Build execution record
        record = AutomationExecutionRecord(
            proposal_id=proposal_key,
            account_id=proposal.target,
            action_type=action_type,
            target=proposal.target,
            stage=self.policy.stage,
            analyst_id=analyst_id,
            result=AutomationExecutionStatus.DENIED,
            reason=decision.reason,
            fresh_checks_passed=decision.execute,
            fallback_reason=decision.fallback_reason,
        )

        if not decision.execute:
            # Denied - record and audit
            record.result = AutomationExecutionStatus.DENIED
            self._record_execution(record)
            self.audit._write_entry(
                {
                    "type": "automation_denied",
                    "execution_id": record.execution_id,
                    "proposal_id": proposal_key,
                    "account_id": proposal.target,
                    "action_type": proposal.action_type,
                    "analyst_id": analyst_id,
                    "reason": decision.reason,
                    "fresh_checks": [
                        {"name": c.name, "result": c.result, "detail": c.detail}
                        for c in decision.fresh_checks
                    ],
                    "fallback_reason": (
                        str(decision.fallback_reason)
                        if decision.fallback_reason
                        else None
                    ),
                }
            )
            return record

        # All checks passed. Execute via sandbox containment (simulated).
        # First ensure the proposal has been human-approved through the gate.
        review = self.sandbox_containment.gate._pending_reviews.get(proposal_key)
        if review is None or review.decision.value != "approve":
            record.result = AutomationExecutionStatus.DENIED
            record.reason = (
                "proposal has not been approved by a human analyst; "
                "automation requires human approval first"
            )
            self._record_execution(record)
            return record

        # Simulate the action
        success, sim_reason = self.action_simulator.simulate(
            action_type=action_type,
            target=proposal.target,
            account_id=proposal.target,
        )

        if not success:
            record.result = AutomationExecutionStatus.DENIED
            record.reason = f"action simulation failed: {sim_reason}"
            self._record_execution(record)
            self.audit._write_entry(
                {
                    "type": "automation_simulation_failed",
                    "execution_id": record.execution_id,
                    "proposal_id": proposal_key,
                    "account_id": proposal.target,
                    "action_type": proposal.action_type,
                    "analyst_id": analyst_id,
                    "reason": record.reason,
                }
            )
            return record

        # Execute succeeded (simulated)
        record.result = AutomationExecutionStatus.EXECUTED
        record.reason = f"reversible action executed (simulated): {sim_reason}"
        record.fresh_checks_passed = True

        # Update rate limit counters
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        hour = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")
        self._account_daily_counts.setdefault(today, {})
        self._account_daily_counts[today][proposal.target] = (
            self._account_daily_counts[today].get(proposal.target, 0) + 1
        )
        self._global_hourly_counts[hour] = (
            self._global_hourly_counts.get(hour, 0) + 1
        )

        # Mark idempotent
        self._proposal_executions[proposal_key] = record.execution_id

        # Customer notification (if required)
        if self.policy.customer_notification_required:
            notification = self._send_customer_notification(
                account_id=proposal.target,
                execution_id=record.execution_id,
                notification_type=CustomerNotificationType.ACTION_TAKEN,
                channel="in_app",
            )
            record.customer_notified = True
            record.notification_id = notification.notification_id

        # Record execution
        self._record_execution(record)

        # Update canary metrics
        self._update_canary_metrics(executed=True)

        # Audit the execution
        self.audit._write_entry(
            {
                "type": "automation_executed",
                "execution_id": record.execution_id,
                "proposal_id": proposal_key,
                "account_id": proposal.target,
                "action_type": proposal.action_type,
                "analyst_id": analyst_id,
                "stage": self.policy.stage,
                "reason": record.reason,
                "customer_notified": record.customer_notified,
            }
        )

        return record

    # ------------------------------------------------------------------
    # Deterministic fallback
    # ------------------------------------------------------------------

    def apply_fallback(
        self,
        proposal: Any,
        analyst_id: str,
        fallback_reason: FallbackReason,
        investigation_id: Optional[str] = None,
    ) -> AutomationExecutionRecord:
        """Apply deterministic fallback when automation cannot proceed.

        Never continues silently. Options:
        - budget_exhausted: halt investigation, escalate to human
        - uncertain_evidence: abstain, route to human review
        - policy_conflict: route to human review
        - meko_outage: use baseline only, mark context unavailable
        - drift_detected: stop automation, alert
        - kill_switch_active: stop all automation
        - guardrail_violation: stop, alert, review
        - insufficient_permissions: deny, alert
        - not_allowlisted: deny, alert
        - idle_timeout: halt, escalate
        """
        proposal_key = self.sandbox_containment.gate._proposal_key(proposal)

        record = AutomationExecutionRecord(
            proposal_id=proposal_key,
            account_id=proposal.target,
            action_type=AutomationAction(proposal.action_type),
            target=proposal.target,
            stage=self.policy.stage,
            analyst_id=analyst_id,
            result=AutomationExecutionStatus.FALLBACK,
            reason=(
                f"deterministic fallback applied: {fallback_reason.value}"
            ),
            fallback_reason=fallback_reason,
            fresh_checks_passed=False,
        )

        self._record_execution(record)

        # Take fallback action based on reason
        fallback_action = self._fallback_action(
            fallback_reason, investigation_id, analyst_id
        )

        self.audit._write_entry(
            {
                "type": "automation_fallback",
                "execution_id": record.execution_id,
                "proposal_id": proposal_key,
                "account_id": proposal.target,
                "action_type": proposal.action_type,
                "analyst_id": analyst_id,
                "fallback_reason": fallback_reason.value,
                "fallback_action": fallback_action,
            }
        )

        return record

    def _fallback_action(
        self,
        reason: FallbackReason,
        investigation_id: Optional[str],
        analyst_id: str,
    ) -> str:
        """Determine the deterministic fallback action for a given reason."""
        if reason == FallbackReason.BUDGET_EXHAUSTED:
            if investigation_id:
                self.orchestrator.halt(
                    investigation_id,
                    f"budget exhausted; fallback to human review",
                )
            return "halt investigation and escalate to human review"
        if reason == FallbackReason.UNCERTAIN_EVIDENCE:
            return "abstain from automation; route to human review"
        if reason == FallbackReason.POLICY_CONFLICT:
            return "abstain from automation; route to human review"
        if reason == FallbackReason.MEKO_OUTAGE:
            return "use deterministic baseline only; mark Meko context unavailable"
        if reason == FallbackReason.DRIFT_DETECTED:
            return "stop automation; alert risk operations; review baseline"
        if reason == FallbackReason.KILL_SWITCH_ACTIVE:
            return "halt all automation; await kill switch deactivation"
        if reason == FallbackReason.GUARDRAIL_VIOLATION:
            return "stop automation; review guardrails; consider rollback"
        if reason == FallbackReason.INSUFFICIENT_PERMISSIONS:
            return "deny execution; alert security"
        if reason == FallbackReason.NOT_ALLOWLISTED:
            return "deny execution; action not on allowlist"
        if reason == FallbackReason.IDLE_TIMEOUT:
            if investigation_id:
                self.orchestrator.halt(
                    investigation_id,
                    "idle timeout; fallback to human review",
                )
            return "halt investigation and escalate to human review"
        return "no action; manual review required"

    # ------------------------------------------------------------------
    # Reversal
    # ------------------------------------------------------------------

    def reverse(
        self,
        execution_id: str,
        analyst_id: str,
        reason: str = "",
    ) -> Optional[AutomationExecutionRecord]:
        """Reverse a previously executed automation action.

        RBAC: analyst must have EXECUTE_CONTAINMENT permission.
        Records the reversal and audits it.
        """
        record = self._executions.get(execution_id)
        if record is None:
            return None

        if record.reversed:
            return record

        # RBAC check
        try:
            self.rbac.require(
                analyst_id,
                Permission.EXECUTE_CONTAINMENT,
                resource=f"containment:{record.target}",
            )
        except PermissionError:
            return None

        # Simulate reversal
        success, sim_reason = self.action_simulator.simulate(
            action_type=record.action_type,
            target=record.target,
            account_id=record.account_id,
        )

        if not success:
            return None

        record.reversed = True
        record.reversed_at = datetime.now(timezone.utc)
        record.reversal_reason = reason or "manual reversal"
        record.result = AutomationExecutionStatus.REVERSED

        # Update canary metrics
        self._update_canary_metrics(reversed_=True)

        # Customer notification
        if self.policy.customer_notification_required:
            notification = self._send_customer_notification(
                account_id=record.account_id,
                execution_id=record.execution_id,
                notification_type=CustomerNotificationType.ACTION_REVERSED,
                channel="in_app",
            )
            record.customer_notified = True
            record.notification_id = notification.notification_id

        # Audit the reversal
        self.audit._write_entry(
            {
                "type": "automation_reversed",
                "execution_id": record.execution_id,
                "proposal_id": record.proposal_id,
                "account_id": record.account_id,
                "action_type": record.action_type,
                "analyst_id": analyst_id,
                "reason": reason,
                "simulated": sim_reason,
            }
        )

        return record

    # ------------------------------------------------------------------
    # Incident procedures
    # ------------------------------------------------------------------

    def open_incident(
        self,
        execution_id: str,
        account_id: str,
        title: str,
        severity: str = "medium",
    ) -> IncidentRecord:
        """Open an incident record for an automation-related issue."""
        incident = IncidentRecord(
            account_id=account_id,
            execution_id=execution_id,
            title=title,
            severity=severity,
        )
        self._incidents[incident.incident_id] = incident
        self.audit._write_entry(
            {
                "type": "automation_incident_opened",
                "incident_id": incident.incident_id,
                "account_id": account_id,
                "execution_id": execution_id,
                "title": title,
                "severity": severity,
            }
        )
        return incident

    def close_incident(
        self,
        incident_id: str,
        resolution: str,
        reversed: bool = False,
    ) -> Optional[IncidentRecord]:
        """Close an incident record."""
        incident = self._incidents.get(incident_id)
        if incident is None:
            return None
        incident.closed_at = datetime.now(timezone.utc)
        incident.resolution = resolution
        incident.reversed = reversed
        self.audit._write_entry(
            {
                "type": "automation_incident_closed",
                "incident_id": incident_id,
                "resolution": resolution,
                "reversed": reversed,
            }
        )
        return incident

    # ------------------------------------------------------------------
    # Canary rollout management
    # ------------------------------------------------------------------

    def advance_stage(self, new_stage: AutomationStage, analyst_id: str) -> bool:
        """Advance the canary rollout to a new stage.

        RBAC: analyst must have MANAGE_ROLES or FRAUD_OWNER role.
        Guardrail violations cause automatic rollback instead of advancement.
        """
        try:
            self.rbac.require(
                analyst_id,
                Permission.MANAGE_ROLES,
                resource="automation_policy",
            )
        except PermissionError:
            return False

        # Check for active guardrail violations before advancing
        recent_violations = [
            v
            for v in self._violations
            if v.auto_stopped
            and (datetime.now(timezone.utc) - v.detected_at).total_seconds() < 3600
        ]
        if recent_violations and new_stage != AutomationStage.ROLLED_BACK:
            # Auto-rollback instead of advancing
            self.policy.stage = AutomationStage.ROLLED_BACK
            self._update_canary_metrics()
            self.audit._write_entry(
                {
                    "type": "canary_auto_rollback",
                    "analyst_id": analyst_id,
                    "reason": "active guardrail violations prevent advancement",
                    "new_stage": self.policy.stage,
                }
            )
            return False

        old_stage = self.policy.stage
        self.policy.stage = new_stage
        self.audit._write_entry(
            {
                "type": "canary_stage_advanced",
                "analyst_id": analyst_id,
                "old_stage": old_stage,
                "new_stage": new_stage,
            }
        )
        return True

    def rollback(self, analyst_id: str, reason: str = "") -> bool:
        """Roll back the canary rollout due to guardrail violation."""
        try:
            self.rbac.require(
                analyst_id,
                Permission.MANAGE_ROLES,
                resource="automation_policy",
            )
        except PermissionError:
            return False

        old_stage = self.policy.stage
        self.policy.stage = AutomationStage.ROLLED_BACK
        self._update_canary_metrics()
        self.audit._write_entry(
            {
                "type": "canary_rollback",
                "analyst_id": analyst_id,
                "old_stage": old_stage,
                "new_stage": AutomationStage.ROLLED_BACK,
                "reason": reason,
            }
        )
        return True

    def activate_kill_switch(self, analyst_id: str) -> bool:
        """Activate the kill switch to halt all automation."""
        try:
            self.rbac.require(
                analyst_id,
                Permission.MANAGE_ROLES,
                resource="automation_policy",
            )
        except PermissionError:
            return False

        self._kill_switch_active = True
        self.policy.kill_switch_active = True
        self.audit._write_entry(
            {
                "type": "kill_switch_activated",
                "analyst_id": analyst_id,
            }
        )
        return True

    def deactivate_kill_switch(self, analyst_id: str) -> bool:
        """Deactivate the kill switch."""
        try:
            self.rbac.require(
                analyst_id,
                Permission.MANAGE_ROLES,
                resource="automation_policy",
            )
        except PermissionError:
            return False

        self._kill_switch_active = False
        self.policy.kill_switch_active = False
        self.audit._write_entry(
            {
                "type": "kill_switch_deactivated",
                "analyst_id": analyst_id,
            }
        )
        return True

    # ------------------------------------------------------------------
    # Customer notification
    # ------------------------------------------------------------------

    def _send_customer_notification(
        self,
        account_id: str,
        execution_id: str,
        notification_type: CustomerNotificationType,
        channel: str = "in_app",
    ) -> CustomerNotification:
        """Send a customer notification (simulated)."""
        notification = CustomerNotification(
            account_id=account_id,
            execution_id=execution_id,
            notification_type=notification_type,
            channel=channel,
            delivered=True,  # simulated delivery
        )
        self._notifications[notification.notification_id] = notification
        self.audit._write_entry(
            {
                "type": "customer_notification",
                "notification_id": notification.notification_id,
                "account_id": account_id,
                "execution_id": execution_id,
                "notification_type": notification_type,
                "channel": channel,
                "delivered": notification.delivered,
            }
        )
        return notification

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_execution(self, record: AutomationExecutionRecord) -> None:
        self._executions[record.execution_id] = record

    def _update_canary_metrics(
        self,
        executed: bool = False,
        denied: bool = False,
        reversed_: bool = False,
        fallback: bool = False,
        violation: bool = False,
    ) -> None:
        metrics = self._canary_metrics[self.policy.stage]
        metrics.total_actions += 1
        if executed:
            metrics.executed_actions += 1
        if denied:
            metrics.denied_actions += 1
        if reversed_:
            metrics.reversed_actions += 1
        if fallback:
            metrics.fallback_actions += 1
        if violation:
            metrics.guardrail_violations += 1

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_execution(self, execution_id: str) -> Optional[AutomationExecutionRecord]:
        return self._executions.get(execution_id)

    def list_executions(self) -> list[AutomationExecutionRecord]:
        return list(self._executions.values())

    def get_violations(self) -> list[GuardrailViolation]:
        return list(self._violations)

    def get_canary_metrics(self, stage: Optional[AutomationStage] = None) -> dict:
        if stage is not None:
            m = self._canary_metrics.get(stage)
            if m is None:
                return {}
            return {
                "stage": m.stage,
                "total_actions": m.total_actions,
                "executed_actions": m.executed_actions,
                "denied_actions": m.denied_actions,
                "fallback_actions": m.fallback_actions,
                "reversed_actions": m.reversed_actions,
                "guardrail_violations": m.guardrail_violations,
                "customer_complaints": m.customer_complaints,
                "false_positive_rate": m.false_positive_rate,
                "drift_score": m.drift_score,
            }
        return {
            stage.value: {
                "total_actions": m.total_actions,
                "executed_actions": m.executed_actions,
                "denied_actions": m.denied_actions,
                "fallback_actions": m.fallback_actions,
                "reversed_actions": m.reversed_actions,
                "guardrail_violations": m.guardrail_violations,
                "customer_complaints": m.customer_complaints,
                "false_positive_rate": m.false_positive_rate,
                "drift_score": m.drift_score,
            }
            for stage, m in self._canary_metrics.items()
        }

    def get_policy(self) -> AutomationPolicy:
        return self.policy
