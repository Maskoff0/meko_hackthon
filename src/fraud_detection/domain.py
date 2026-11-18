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
