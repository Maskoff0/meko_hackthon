"""Core domain models for the fraud detection system.

Canonical event, investigation, case, evidence, and decision models.
Records event and observation times, source, entity tokens, provenance,
schema version, and idempotency key.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator


class EventType(str, Enum):
    LOGIN = "login"
    DEVICE = "device"
    RESET = "reset"
    TRANSACTION = "transaction"
    SUPPORT = "support"


class InvestigationStatus(str, Enum):
    OPEN = "open"
    CORRELATING = "correlating"
    ASSESSING = "assessing"
    DECIDED = "decided"
    CLOSED = "closed"
    ESCALATED = "escalated"


class FindingStatus(str, Enum):
    PENDING = "pending"
    COMPLETE = "complete"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TIMEOUT = "timeout"
    FAILED = "failed"


class Recommendation(str, Enum):
    ABSTAIN = "abstain"
    REVIEW = "review"
    BLOCK = "block"
    ALLOW = "allow"


class LabelSource(str, Enum):
    CHARGEBACK = "chargeback"
    DISPUTE = "dispute"
    ANALYST_DISPOSITION = "analyst_disposition"
    CONFIRMED_NON_FRAUD = "confirmed_non_fraud"


class LabelState(str, Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    UNKNOWN = "unknown"
    IMMATURE = "immature"


class AccountEvent(BaseModel):
    """A normalized, schema-validated event from an event source."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str
    event_type: EventType
    source: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    schema_version: str = "1.0"
    idempotency_key: str = Field(default_factory=lambda: str(uuid4()))
    payload: dict[str, Any] = Field(default_factory=dict)
    provenance: str = "synthetic"

    @validator("idempotency_key")
    def _non_empty_idempotency_key(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("idempotency_key must not be empty")
        return v

    @validator("account_id")
    def _non_empty_account_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("account_id must not be empty")
        return v


class Investigation(BaseModel):
    """An investigation task owned by the deterministic supervisor."""

    investigation_id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str
    trigger_event_id: str
    trigger_type: str
    hypothesis: str
    status: InvestigationStatus = InvestigationStatus.OPEN
    allowed_tools: list[str] = Field(default_factory=list)
    evidence_scopes: list[str] = Field(default_factory=list)
    tool_call_budget: int = 10
    meko_retrieval_budget: int = 5
    token_budget: int = 4000
    wall_clock_deadline_seconds: int = 60
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    policy_version: str = "2026-11-v1"
    findings: list[str] = Field(default_factory=list)  # finding ids
    error: Optional[str] = None

    class Config:
        use_enum_values = True


class EvidenceFinding(BaseModel):
    """A typed result written by a scoped agent to the investigation record."""

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    agent_id: str
    conclusion: str
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    source: str = "agent"
    status: FindingStatus = FindingStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        use_enum_values = True


class ShadowRecommendation(BaseModel):
    """A non-actionable shadow recommendation produced by the policy engine."""

    recommendation: Recommendation
    reason_codes: list[str] = Field(default_factory=list)
    baseline_result: dict[str, Any] = Field(default_factory=dict)
    uncertainty: str = "low"
    abstention: bool = False
    policy_version: str
    model_version: str
    prompt_version: Optional[str] = None
    evidence_provenance: list[str] = Field(default_factory=list)
    decision_ttl_seconds: int = 300


class CaseLabel(BaseModel):
    """A label for an event/case with source, timestamps, and adjudication state."""

    label_id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str
    investigation_id: Optional[str] = None
    label_source: LabelSource
    label_state: LabelState = LabelState.UNKNOWN
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    adjudicated_at: Optional[datetime] = None
    adjudicated_by: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    maturity_horizon_seconds: int = 86400

    class Config:
        use_enum_values = True

    @property
    def is_mature(self) -> bool:
        age = (datetime.now(timezone.utc) - self.timestamp).total_seconds()
        return age >= self.maturity_horizon_seconds


# --- Analyst copilot models (function.md) ---


class DraftStatus(str, Enum):
    DRAFT = "draft"
    EDITED = "edited"
    SIGNED = "signed"
    REJECTED = "rejected"


class FeedbackLabel(str, Enum):
    FALSE_POSITIVE_KNOWN_TRAVEL = "false_positive: known travel"
    FALSE_POSITIVE_OTHER = "false positive: other"
    TRUE_POSITIVE = "true positive"
    TRUE_POSITIVE_MISSED_SIGNAL = "true positive: missed signal"
    UNKNOWN = "unknown"


class BriefTimelineEntry(BaseModel):
    """A single entry in a case brief timeline with source system and citation."""

    timestamp: datetime
    event_type: str
    source_system: str
    description: str
    event_id: str
    trace_id: Optional[str] = None


class CaseBrief(BaseModel):
    """One-screen case brief for an analyst, delivered through the MCP server.

    Every factual claim cites a source ID. If it can't be cited, it
    doesn't go in the brief.
    """

    brief_id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str
    investigation_id: str
    analyst_id: Optional[str] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # What happened, as an ordered timeline with source systems
    timeline: list[BriefTimelineEntry] = Field(default_factory=list)

    # Which signals drove the score, and how confident each agent was
    signals: list[dict] = Field(default_factory=list)

    # Matching prior incidents, with incident IDs
    prior_incidents: list[dict] = Field(default_factory=list)

    # What's still unknown
    unknowns: list[str] = Field(default_factory=list)

    # All citations used in this brief
    citations: list[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True


class CaseDraft(BaseModel):
    """A draft case note / customer communication / regulator explanation.

    Drafts are stored as drafts, never as the official record. The
    analyst edits and signs.
    """

    draft_id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str
    investigation_id: str
    analyst_id: Optional[str] = None

    draft_type: str  # "case_note", "customer_communication", "regulator_explanation"
    content: str
    status: DraftStatus = DraftStatus.DRAFT

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    edited_at: Optional[datetime] = None
    signed_at: Optional[datetime] = None
    signed_by: Optional[str] = None

    citations: list[str] = Field(default_factory=list)
    edit_count: int = 0

    class Config:
        use_enum_values = True


class TriageQueueItem(BaseModel):
    """An investigation entry in the analyst triage queue with rank and explanation."""

    investigation_id: str
    account_id: str
    rank: int
    score: float
    reason_codes: list[str] = Field(default_factory=list)
    agent_findings: list[dict] = Field(default_factory=list)
    recommendation: str
    uncertainty: str
    trigger_type: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Why ranked high — plain-language explanation
    ranking_explanation: Optional[str] = None

    class Config:
        use_enum_values = True


class AnalystFeedback(BaseModel):
    """Structured feedback from an analyst: structured 'why?' -> labelled outcome."""

    feedback_id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str
    investigation_id: str
    analyst_id: str

    # The recommendation the analyst disagreed with
    original_recommendation: str
    original_reason_codes: list[str] = Field(default_factory=list)

    # Structured question: "why?" — analyst's free-text response
    analyst_response: str

    # Labelled outcome derived from the response
    label: FeedbackLabel
    label_reason: Optional[str] = None

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        use_enum_values = True


# --- Phase 4: Human approval domain models ---


class CaseQueueStatus(str, Enum):
    QUEUED = "queued"
    ASSIGNED = "assigned"
    IN_REVIEW = "in_review"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    CLOSED = "closed"


class AssignmentAction(str, Enum):
    ASSIGN = "assign"
    REASSIGN = "reassign"
    ESCALATE = "escalate"
    UNASSIGN = "unassign"


class Role(str, Enum):
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    SUPERVISOR = "supervisor"
    FRAUD_OWNER = "fraud_owner"
    AUDITOR = "auditor"


class Permission(str, Enum):
    VIEW_QUEUE = "view_queue"
    ASSIGN_CASE = "assign_case"
    REASSIGN_CASE = "reassign_case"
    ESCALATE_CASE = "escalate_case"
    REVIEW_CASE = "review_case"
    APPROVE_CONTAINMENT = "approve_containment"
    EXECUTE_CONTAINMENT = "execute_containment"
    MANAGE_ROLES = "manage_roles"
    VIEW_AUDIT = "view_audit"
    ADJUDICATE_LABEL = "adjudicate_label"


# Default role -> permission mapping (least privilege).
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.ANALYST: {
        Permission.VIEW_QUEUE,
        Permission.REVIEW_CASE,
    },
    Role.SENIOR_ANALYST: {
        Permission.VIEW_QUEUE,
        Permission.REVIEW_CASE,
        Permission.APPROVE_CONTAINMENT,
    },
    Role.SUPERVISOR: {
        Permission.VIEW_QUEUE,
        Permission.ASSIGN_CASE,
        Permission.REASSIGN_CASE,
        Permission.ESCALATE_CASE,
        Permission.REVIEW_CASE,
        Permission.APPROVE_CONTAINMENT,
        Permission.ADJUDICATE_LABEL,
    },
    Role.FRAUD_OWNER: {
        Permission.VIEW_QUEUE,
        Permission.ASSIGN_CASE,
        Permission.REASSIGN_CASE,
        Permission.ESCALATE_CASE,
        Permission.REVIEW_CASE,
        Permission.APPROVE_CONTAINMENT,
        Permission.EXECUTE_CONTAINMENT,
        Permission.MANAGE_ROLES,
        Permission.ADJUDICATE_LABEL,
    },
    Role.AUDITOR: {
        Permission.VIEW_QUEUE,
        Permission.VIEW_AUDIT,
    },
}


class CaseQueueItem(BaseModel):
    """An investigation entry in the analyst case queue.

    Contains the evidence timeline, reason codes, model/rule versions,
    label state, investigation status, assignment, and escalation info.
    """

    queue_item_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    account_id: str
    status: CaseQueueStatus = CaseQueueStatus.QUEUED
    rank: int
    score: float
    reason_codes: list[str] = Field(default_factory=list)
    agent_findings: list[dict] = Field(default_factory=list)
    recommendation: str
    uncertainty: str
    trigger_type: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Assignment
    assigned_to: Optional[str] = None
    assigned_at: Optional[datetime] = None
    assigned_by: Optional[str] = None

    # Escalation
    escalated: bool = False
    escalated_to: Optional[str] = None
    escalated_at: Optional[datetime] = None
    escalation_reason: Optional[str] = None

    # Label state
    label_state: LabelState = LabelState.UNKNOWN
    label_confidence: float = 0.5

    # Evidence timeline (chronological events with citations)
    evidence_timeline: list[dict] = Field(default_factory=list)

    # Model/rule versions for audit
    policy_version: str = "2026-11-v1"
    model_version: str = "deterministic-baseline-v1"

    class Config:
        use_enum_values = True


class CaseAssignment(BaseModel):
    """A case assignment/reassignment/escalation record."""

    assignment_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    queue_item_id: str
    action: AssignmentAction
    from_analyst: Optional[str] = None
    to_analyst: str
    assigned_by: str
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        use_enum_values = True


class AccessDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class AccessRequest(BaseModel):
    """An access request for RBAC evaluation."""

    analyst_id: str
    role: Role
    permission: Permission
    resource: str  # e.g., investigation_id or "queue"
    context: dict[str, Any] = Field(default_factory=dict)


class AccessControlEntry(BaseModel):
    """An audit record of an access control decision."""

    entry_id: str = Field(default_factory=lambda: str(uuid4()))
    analyst_id: str
    role: Role
    permission: Permission
    resource: str
    decision: AccessDecision
    reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        use_enum_values = True


class SandboxContainmentResult(str, Enum):
    SIMULATED_EXECUTED = "simulated_executed"
    SIMULATED_DENIED = "simulated_denied"
    SIMULATION_ERROR = "simulation_error"


class SandboxExecutionRecord(BaseModel):
    """A sandbox containment execution record (simulated, no real action)."""

    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    proposal_id: str
    account_id: str
    action_type: str
    target: str
    analyst_id: str
    result: SandboxContainmentResult
    reason: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reversed: bool = False
    reversed_at: Optional[datetime] = None
    reversal_reason: Optional[str] = None

    class Config:
        use_enum_values = True


# --- Phase 5: Limited reversible automation domain models ---


class AutomationAction(str, Enum):
    """Reversible action types eligible for limited automation.

    Only fraud-owner-approved, reversible actions can be automated.
    Irreversible blocks require separate human approval (Phase 6).
    """

    TEMPORARY_HOLD = "temporary_hold"
    LIMIT_REDUCTION = "limit_reduction"
    PAYEE_BLOCK = "payee_block"
    DEVICE_CHALLENGE = "device_challenge"
    SESSION_RESET = "session_reset"


class AutomationStage(str, Enum):
    """Canary rollout stages for limited automation."""

    SANDBOX = "sandbox"  # internal/sandbox traffic only (0% real)
    COHORT_1 = "cohort_1"  # small controlled cohort (e.g., 1% real)
    COHORT_2 = "cohort_2"  # gradual expansion (e.g., 10% real)
    FULL = "full"  # full rollout (100% real)
    ROLLED_BACK = "rolled_back"  # rolled back due to guardrail violation


class GuardrailSeverity(str, Enum):
    WARNING = "warning"
    TRIP = "trip"  # automatic stop


class AutomationExecutionStatus(str, Enum):
    PENDING = "pending"
    EXECUTED = "executed"
    DENIED = "denied"
    FALLBACK = "fallback"
    ESCALATED = "escalated"
    REVERSED = "reversed"


class FallbackReason(str, Enum):
    BUDGET_EXHAUSTED = "budget_exhausted"
    UNCERTAIN_EVIDENCE = "uncertain_evidence"
    POLICY_CONFLICT = "policy_conflict"
    MEKO_OUTAGE = "meko_outage"
    DRIFT_DETECTED = "drift_detected"
    KILL_SWITCH_ACTIVE = "kill_switch_active"
    GUARDRAIL_VIOLATION = "guardrail_violation"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"
    NOT_ALLOWLISTED = "not_allowlisted"
    IDLE_TIMEOUT = "idle_timeout"


class CustomerNotificationType(str, Enum):
    ACTION_TAKEN = "action_taken"
    ACTION_REVERSED = "action_reversed"
    ESCALATION = "escalation"
    AUTOMATION_STOPPED = "automation_stopped"


class AutomationExecutionRecord(BaseModel):
    """A record of an automation execution attempt.

    Captures every action attempted by the reversible automation engine
    including checks performed, result, and reversal info.
    """

    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    proposal_id: str
    account_id: str
    action_type: AutomationAction
    target: str
    stage: AutomationStage
    analyst_id: Optional[str] = None  # human who approved (if any)
    result: AutomationExecutionStatus
    reason: str
    fresh_checks_passed: bool = False
    fallback_reason: Optional[FallbackReason] = None
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reversed: bool = False
    reversed_at: Optional[datetime] = None
    reversal_reason: Optional[str] = None
    customer_notified: bool = False
    notification_id: Optional[str] = None
    incident_id: Optional[str] = None

    class Config:
        use_enum_values = True


class GuardrailViolation(BaseModel):
    """A guardrail violation that triggered an automatic stop."""

    violation_id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str
    action_type: AutomationAction
    severity: GuardrailSeverity
    description: str
    limit_type: str  # e.g., "per_account_daily", "global_hourly", "drift"
    current_value: float
    limit_value: float
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    auto_stopped: bool = False

    class Config:
        use_enum_values = True


class CustomerNotification(BaseModel):
    """A customer notification about an automation action."""

    notification_id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str
    execution_id: str
    notification_type: CustomerNotificationType
    channel: str  # "email", "sms", "in_app"
    sent_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    delivered: bool = False

    class Config:
        use_enum_values = True


class IncidentRecord(BaseModel):
    """An incident record for automation-related issues."""

    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str
    execution_id: str
    title: str
    severity: str  # "low", "medium", "high", "critical"
    opened_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: Optional[datetime] = None
    resolution: Optional[str] = None
    reversed: bool = False

    class Config:
        use_enum_values = True


class CanaryMetrics(BaseModel):
    """Metrics tracked per canary stage for rollout decisions."""

    stage: AutomationStage
    total_actions: int = 0
    executed_actions: int = 0
    denied_actions: int = 0
    fallback_actions: int = 0
    reversed_actions: int = 0
    guardrail_violations: int = 0
    customer_complaints: int = 0
    false_positive_rate: float = 0.0  # from analyst feedback labels
    drift_score: float = 0.0  # deviation from human-approved baseline

    class Config:
        use_enum_values = True


class AutomationPolicy(BaseModel):
    """Policy governing limited reversible automation.

    Configured by fraud owners. Defines what can be automated,
    rate limits, canary stages, and guardrails.
    """

    enabled: bool = False
    stage: AutomationStage = AutomationStage.SANDBOX
    allowlist: list[AutomationAction] = Field(default_factory=list)
    max_actions_per_account_per_day: int = 1
    max_actions_global_per_hour: int = 10
    max_drift_score: float = 0.15  # 15% deviation from baseline
    max_false_positive_rate: float = 0.05  # 5%
    min_confidence_for_automation: float = 0.90
    reversal_window_seconds: int = 86400  # 24 hours
    customer_notification_required: bool = True
    kill_switch_active: bool = False
    cohort_percentage: float = 0.0  # 0-100, used in cohort stages

    class Config:
        use_enum_values = True


class FreshCheckResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"


class FreshCheck(BaseModel):
    """A single fresh execution check result."""

    name: str
    result: FreshCheckResult
    detail: str


class AutomationDecision(BaseModel):
    """The decision reached by the reversible automation engine."""

    execute: bool
    reason: str
    fresh_checks: list[FreshCheck] = Field(default_factory=list)
    fallback_reason: Optional[FallbackReason] = None
    guardrail_violations: list[GuardrailViolation] = Field(default_factory=list)
    customer_notification_required: bool = False

    class Config:
        use_enum_values = True


# --- Phase 6: Irreversible containment & full production rollout ---


class IrreversibleAction(str, Enum):
    """Irreversible containment action types.

    These actions cannot be automatically reversed and require
    explicit FRAUD_OWNER human approval before any execution.
    No automation path exists for irreversible actions.
    """

    PERMANENT_BLOCK = "permanent_block"
    FUND_FREEZE = "fund_freeze"
    IRREVERSIBLE_PAYEE_BLOCK = "irreversible_payee_block"
    ACCOUNT_CLOSURE = "account_closure"


class IrreversibleActionStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    EXECUTED = "executed"
    REVOKED = "revoked"


class AppealStatus(str, Enum):
    OPEN = "open"
    UNDER_REVIEW = "under_review"
    GRANTED = "granted"
    DENIED = "denied"
    ESCALATED = "escalated"


class RemediationType(str, Enum):
    FUND_RESTORATION = "fund_restoration"
    ACCOUNT_REINSTATEMENT = "account_reinstatement"
    PAYEE_UNBLOCK = "payee_unblock"
    GOODWILL_CREDIT = "goodwill_credit"
    OTHER = "other"


class ProductionCutoverStatus(str, Enum):
    SHADOW = "shadow"
    HUMAN_APPROVAL = "human_approval"
    LIMITED_AUTOMATION = "limited_automation"
    FULL_PRODUCTION = "full_production"
    ROLLED_BACK = "rolled_back"


class IrreversibleContainmentRecord(BaseModel):
    """A record of an irreversible containment action.

    Requires explicit FRAUD_OWNER approval. No automation path exists.
    Customer remediation must be available before execution.
    """

    record_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    account_id: str
    action_type: IrreversibleAction
    reason_codes: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    # Approval chain
    status: IrreversibleActionStatus = IrreversibleActionStatus.PENDING_APPROVAL
    approved_by: Optional[str] = None  # must be FRAUD_OWNER
    approved_at: Optional[datetime] = None
    approval_reason: Optional[str] = None
    independent_reviewer: Optional[str] = None  # separate from approver
    independent_review_at: Optional[datetime] = None

    # Execution
    executed_by: Optional[str] = None
    executed_at: Optional[datetime] = None
    execution_reason: Optional[str] = None

    # Customer recourse
    customer_notified_before: bool = False
    customer_notified_at: Optional[datetime] = None
    remediation_available: bool = False
    appeal_filed: bool = False

    # Audit
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        use_enum_values = True


class AppealRequest(BaseModel):
    """A customer appeal against an irreversible containment action."""

    appeal_id: str = Field(default_factory=lambda: str(uuid4()))
    containment_record_id: str
    account_id: str
    customer_id: str
    appeal_reason: str
    status: AppealStatus = AppealStatus.OPEN
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_reason: Optional[str] = None
    remediation: Optional[RemediationType] = None
    remediation_details: Optional[str] = None

    class Config:
        use_enum_values = True


class RemediationRecord(BaseModel):
    """A customer remediation record for an irreversible action or appeal."""

    remediation_id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str
    containment_record_id: Optional[str] = None
    appeal_id: Optional[str] = None
    remediation_type: RemediationType
    description: str
    amount: Optional[float] = None  # for goodwill_credit or fund_restoration
    effective_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    completed_by: Optional[str] = None

    class Config:
        use_enum_values = True


class ProductionCutoverRecord(BaseModel):
    """A record of production cutover stage transitions."""

    cutover_id: str = Field(default_factory=lambda: str(uuid4()))
    from_stage: ProductionCutoverStatus
    to_stage: ProductionCutoverStatus
    approved_by: str  # must be FRAUD_OWNER or risk operations owner
    approved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str
    guardrail_status: dict  # snapshot of guardrail metrics at cutover time
    slo_validation_passed: bool

    class Config:
        use_enum_values = True


class SLOValidationResult(BaseModel):
    """Result of final SLO validation before production cutover."""

    passed: bool
    metric_name: str
    current_value: float
    threshold: float
    direction: str  # "below" or "above"
    details: str

    class Config:
        use_enum_values = True


class FinalSLOValidation(BaseModel):
    """Complete SLO validation report before production cutover."""

    validation_id: str = Field(default_factory=lambda: str(uuid4()))
    validated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    validated_by: str
    overall_passed: bool
    results: list[SLOValidationResult] = Field(default_factory=list)
    observations: str

    class Config:
        use_enum_values = True

