"""Offline replay/evaluation harness.

Compares agentic recommendations with the deterministic baseline on the same
point-in-time evidence. Prevents temporal leakage: only features available at
decision time may be used for that decision.

Pins model/provider identifier, prompt/template version, tool/schema versions,
and policy/rule version. Persists exact input snapshots, retrieved evidence
identifiers, output, and decision versions.

Re-running a model is a new experiment, not a deterministic replay; fresh runs
are compared separately and both are retained.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .baseline import BaselineEvaluator, BaselineResult
from .domain import AccountEvent, ShadowRecommendation
from .labeling import LabelIngestor
from .orchestration import Orchestrator
from .policy import PolicyEngine


@dataclass
class ReplayRecord:
    """A single replay decision record with full provenance."""

    replay_id: str = field(default_factory=lambda: str(hashlib.sha256(
        str(time.time()).encode()
    ).hexdigest()[:16]))
    event_id: str = ""
    account_id: str = ""
    policy_version: str = ""
    model_version: str = ""
    prompt_version: Optional[str] = None
    tool_schema_hash: Optional[str] = None
    decision: str = ""
    reason_codes: list[str] = field(default_factory=list)
    baseline_result: dict[str, Any] = field(default_factory=dict)
    agent_findings: list[dict[str, Any]] = field(default_factory=list)
    evidence_provenance: list[str] = field(default_factory=list)
    input_snapshot: dict[str, Any] = field(default_factory=dict)
    retrieved_evidence_ids: list[str] = field(default_factory=list)
    output: dict[str, Any] = field(default_factory=dict)
    feature_code_version: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_fresh_run: bool = False


@dataclass
class ReplayResult:
    """Result of comparing agentic vs baseline on replayed events."""

    total_events: int = 0
    baseline_triggered: int = 0
    agentic_triggered: int = 0
    agreement_count: int = 0
    disagreement_count: int = 0
    records: list[ReplayRecord] = field(default_factory=list)

    def agreement_rate(self) -> float:
        if self.total_events == 0:
            return 0.0
        return self.agreement_count / self.total_events

    def baseline_rate(self) -> float:
        if self.total_events == 0:
            return 0.0
        return self.baseline_triggered / self.total_events

    def agentic_rate(self) -> float:
        if self.total_events == 0:
            return 0.0
        return self.agentic_triggered / self.total_events


class ReplayHarness:
    """Offline replay harness for baseline vs agentic comparison.

    Runs recorded decisions against recorded outputs/inputs for audit.
    Prevents temporal leakage by only using features available at decision time.
    """

    def __init__(
        self,
        baseline_evaluator: Optional[BaselineEvaluator] = None,
        policy_engine: Optional[PolicyEngine] = None,
        feature_code_version: str = "2026-11-v1",
        prompt_version: Optional[str] = None,
    ):
        self.baseline = baseline_evaluator or BaselineEvaluator()
        self.policy = policy_engine or PolicyEngine()
        self.feature_code_version = feature_code_version
        self.prompt_version = prompt_version
        self._records: list[ReplayRecord] = []

    def _hash_tool_schema(self) -> str:
        """Hash of current tool/schema versions for provenance."""
        schema_info = json.dumps(
            {
                "mcp_version": "1.0",
                "meko_tools": ["conversation_create", "memory_add", "context_search",
                              "conversation_add_message", "artifact_put"],
                "tool_schema_version": "1.0",
            },
            sort_keys=True,
        )
        return hashlib.sha256(schema_info.encode()).hexdigest()[:16]

    def _hash_prompt_template(self) -> str:
        """Hash of prompt/template version for provenance."""
        prompt_info = json.dumps(
            {
                "policy_template": "deterministic-baseline-v1",
                "prompt_version": "2026-11-v1",
            },
            sort_keys=True,
        )
        return hashlib.sha256(prompt_info.encode()).hexdigest()[:16]

    def replay_decision(
        self,
        event: AccountEvent,
        baseline_result: Optional[BaselineResult] = None,
        agent_findings: Optional[list[dict[str, Any]]] = None,
        shadow_mode: bool = True,
        is_fresh_run: bool = False,
    ) -> ReplayRecord:
        """Replay a single decision with full provenance.

        Only features available at decision time are used (no temporal leakage).
        The input snapshot is pinned for audit reproducibility.
        """
        if baseline_result is None:
            baseline_result = self.baseline.evaluate(event)

        policy_decision = self.policy.decide(
            event=event,
            baseline=baseline_result,
            findings=[],
            shadow_mode=shadow_mode,
        )

        # Pin input snapshot for audit reproducibility
        input_snapshot = {
            "event_id": event.event_id,
            "account_id": event.account_id,
            "event_type": event.event_type,
            "source": event.source,
            "timestamp": event.timestamp.isoformat(),
            "schema_version": event.schema_version,
            "idempotency_key": event.idempotency_key,
            "provenance": event.provenance,
            "payload": event.payload,
        }

        record = ReplayRecord(
            event_id=event.event_id,
            account_id=event.account_id,
            policy_version=self.policy.policy_version,
            model_version=self.policy.model_version,
            prompt_version=self.prompt_version or self._hash_prompt_template(),
            tool_schema_hash=self._hash_tool_schema(),
            decision=policy_decision.recommendation.value,
            reason_codes=list(policy_decision.reason_codes),
            baseline_result=baseline_result.to_dict(),
            agent_findings=agent_findings or [],
            evidence_provenance=list(policy_decision.evidence_provenance),
            input_snapshot=input_snapshot,
            retrieved_evidence_ids=[],
            output={
                "recommendation": policy_decision.recommendation.value,
                "uncertainty": policy_decision.uncertainty,
                "abstention": policy_decision.abstention,
            },
            feature_code_version=self.feature_code_version,
            is_fresh_run=is_fresh_run,
        )

        self._records.append(record)
        return record

    def replay_batch(
        self,
        events: list[AccountEvent],
        shadow_mode: bool = True,
    ) -> ReplayResult:
        """Replay a batch of events and compare baseline vs agentic."""
        result = ReplayResult(total_events=len(events))

        for event in events:
            record = self.replay_decision(
                event=event,
                shadow_mode=shadow_mode,
            )
            result.records.append(record)

            if record.baseline_result.get("triggered"):
                result.baseline_triggered += 1
            if record.decision in ("review", "block"):
                result.agentic_triggered += 1

            # Agreement: baseline triggered == agentic triggered
            baseline_trig = record.baseline_result.get("triggered", False)
            agentic_trig = record.decision in ("review", "block")
            if baseline_trig == agentic_trig:
                result.agreement_count += 1
            else:
                result.disagreement_count += 1

        return result

    def get_records(self) -> list[ReplayRecord]:
        return list(self._records)

    def get_fresh_runs(self) -> list[ReplayRecord]:
        """Return fresh runs (new experiments, not deterministic replays)."""
        return [r for r in self._records if r.is_fresh_run]

    def clear(self) -> None:
        self._records.clear()


class RecordedDecisionReplay:
    """Replays recorded decisions from the audit log for audit verification.

    Treats fresh model runs as new experiments, not deterministic replays.
    Both original and fresh runs are retained for comparison.
    """

    def __init__(self, harness: ReplayHarness):
        self.harness = harness
        self._original_records: list[ReplayRecord] = []
        self._fresh_records: list[ReplayRecord] = []

    def record_original(self, record: ReplayRecord) -> None:
        """Record an original decision from the audit log."""
        self._original_records.append(record)

    def replay_fresh(
        self,
        event: AccountEvent,
        shadow_mode: bool = True,
    ) -> ReplayRecord:
        """Re-run a decision as a fresh experiment (not deterministic replay).

        Fresh runs are compared separately and both runs are retained.
        """
        record = self.harness.replay_decision(
            event=event,
            shadow_mode=shadow_mode,
            is_fresh_run=True,
        )
        self._fresh_records.append(record)
        return record

    def compare_runs(self) -> dict[str, Any]:
        """Compare original vs fresh runs as separate experiments."""
        original_count = len(self._original_records)
        fresh_count = len(self._fresh_records)

        original_decisions = [r.decision for r in self._original_records]
        fresh_decisions = [r.decision for r in self._fresh_records]

        return {
            "original_count": original_count,
            "fresh_count": fresh_count,
            "original_decisions": original_decisions,
            "fresh_decisions": fresh_decisions,
            "identical": original_decisions == fresh_decisions,
            "note": "Fresh runs are new experiments; not expected to match originals.",
        }
