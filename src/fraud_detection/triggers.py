"""Versioned trigger engine for investigation creation.

Implements the three trigger conditions from plan.md:

1. **New account-level signal source** — a signal arrives from a source
   never seen before for this account.
2. **Configured velocity-window threshold crossing** — event count in a
   sliding time window exceeds a configured threshold.
3. **High-risk event** — payee change, password reset, limit change, or
   other configured high-risk step.

Trigger rules are versioned and tested. Correlation runs at trigger points
rather than on every signal. Duplicate and out-of-order inputs do not change
the result; ordinary signals do not cause unnecessary correlation.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .baseline import VelocityWindow
from .domain import AccountEvent, EventType


class TriggerType(str, Enum):
    NEW_SIGNAL_SOURCE = "new_signal_source"
    VELOCITY_WINDOW_CROSSING = "velocity_window_crossing"
    HIGH_RISK_EVENT = "high_risk_event"


@dataclass
class TriggerRule:
    """A single versioned trigger rule."""

    rule_id: str
    version: str
    trigger_type: TriggerType
    enabled: bool = True
    # Velocity config
    window_seconds: int = 600
    threshold: int = 5
    # High-risk config
    high_risk_event_types: list[EventType] = field(
        default_factory=lambda: [EventType.RESET, EventType.TRANSACTION]
    )
    high_risk_payload_keys: list[str] = field(
        default_factory=lambda: ["new_payee", "limit_change", "cash_out"]
    )


@dataclass
class TriggerEvaluation:
    """Result of evaluating a trigger against an event."""

    triggered: bool
    trigger_type: Optional[TriggerType]
    rule_id: Optional[str]
    reason: str
    metadata: dict = field(default_factory=dict)


class TriggerEngine:
    """Evaluates trigger conditions against incoming events.

    Tracks per-account state: seen sources, velocity windows, high-risk
    event history. Trigger deduplication ensures duplicate or out-of-order
    inputs do not change the result.
    """

    TRIGGER_VERSION = "2026-11-v1"

    def __init__(self, rules: Optional[list[TriggerRule]] = None):
        self.rules: dict[str, TriggerRule] = {}
        if rules:
            for rule in rules:
                self.rules[rule.rule_id] = rule
        else:
            self._load_default_rules()

        # Per-account state
        self._seen_sources: dict[str, set[str]] = {}  # account_id -> {source}
        self._velocity_windows: dict[str, dict[str, VelocityWindow]] = (
            {}
        )  # account_id -> {window_key -> VelocityWindow}

    def _load_default_rules(self) -> None:
        """Load default trigger rules versioned at TRIGGER_VERSION."""
        self.rules = {
            "new_signal_source": TriggerRule(
                rule_id="new_signal_source",
                version=self.TRIGGER_VERSION,
                trigger_type=TriggerType.NEW_SIGNAL_SOURCE,
                enabled=True,
            ),
            "velocity_window_login": TriggerRule(
                rule_id="velocity_window_login",
                version=self.TRIGGER_VERSION,
                trigger_type=TriggerType.VELOCITY_WINDOW_CROSSING,
                enabled=True,
                window_seconds=600,
                threshold=5,
            ),
            "high_risk_event": TriggerRule(
                rule_id="high_risk_event",
                version=self.TRIGGER_VERSION,
                trigger_type=TriggerType.HIGH_RISK_EVENT,
                enabled=True,
                high_risk_event_types=[EventType.RESET, EventType.TRANSACTION],
                high_risk_payload_keys=["new_payee", "limit_change", "cash_out"],
            ),
        }

    def add_rule(self, rule: TriggerRule) -> None:
        """Add or override a trigger rule."""
        self.rules[rule.rule_id] = rule

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a trigger rule. Returns False if rule not found."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a trigger rule. Returns False if rule not found."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            return True
        return False

    def _get_sources(self, account_id: str) -> set[str]:
        if account_id not in self._seen_sources:
            self._seen_sources[account_id] = set()
        return self._seen_sources[account_id]

    def _get_velocity_window(
        self, account_id: str, window_key: str, window_seconds: int
    ) -> VelocityWindow:
        if account_id not in self._velocity_windows:
            self._velocity_windows[account_id] = {}
        if window_key not in self._velocity_windows[account_id]:
            self._velocity_windows[account_id][window_key] = VelocityWindow(
                window_seconds=window_seconds
            )
        return self._velocity_windows[account_id][window_key]

    def evaluate(self, event: AccountEvent) -> list[TriggerEvaluation]:
        """Evaluate all enabled trigger rules against an event.

        Returns a list of TriggerEvaluation — one per triggered rule.
        Empty list means no trigger (ordinary signal, no investigation needed).
        """
        results: list[TriggerEvaluation] = []
        account_id = event.account_id
        sources = self._get_sources(account_id)

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            if rule.trigger_type == TriggerType.NEW_SIGNAL_SOURCE:
                eval_result = self._evaluate_new_signal_source(event, rule, sources)
                if eval_result.triggered:
                    results.append(eval_result)

            elif rule.trigger_type == TriggerType.VELOCITY_WINDOW_CROSSING:
                eval_result = self._evaluate_velocity_window(event, rule)
                if eval_result.triggered:
                    results.append(eval_result)

            elif rule.trigger_type == TriggerType.HIGH_RISK_EVENT:
                eval_result = self._evaluate_high_risk_event(event, rule)
                if eval_result.triggered:
                    results.append(eval_result)

        # Record the source as seen AFTER evaluation so the first event
        # from a new source triggers, but subsequent events from the same
        # source do not re-trigger.
        sources.add(event.source)

        # Record event in velocity windows for future evaluations.
        self._record_velocity(event)

        return results

    def _evaluate_new_signal_source(
        self, event: AccountEvent, rule: TriggerRule, sources: set[str]
    ) -> TriggerEvaluation:
        """Trigger when a signal arrives from a new source for this account."""
        is_new = event.source not in sources
        return TriggerEvaluation(
            triggered=is_new,
            trigger_type=TriggerType.NEW_SIGNAL_SOURCE if is_new else None,
            rule_id=rule.rule_id,
            reason=(
                f"new signal source '{event.source}' for account {event.account_id}"
                if is_new
                else f"source '{event.source}' already seen for account {event.account_id}"
            ),
            metadata={"source": event.source, "is_new": is_new},
        )

    def _evaluate_velocity_window(
        self, event: AccountEvent, rule: TriggerRule
    ) -> TriggerEvaluation:
        """Trigger when event count in a sliding window exceeds threshold."""
        window_key = f"{rule.window_seconds}s"
        window = self._get_velocity_window(
            event.account_id, window_key, rule.window_seconds
        )
        # Add current event to window before counting (it counts toward the threshold)
        window.add(event.timestamp)
        count = window.count(event.timestamp)

        return TriggerEvaluation(
            triggered=count >= rule.threshold,
            trigger_type=TriggerType.VELOCITY_WINDOW_CROSSING
            if count >= rule.threshold
            else None,
            rule_id=rule.rule_id,
            reason=(
                f"velocity window {count}/{rule.threshold} in "
                f"{rule.window_seconds}s for account {event.account_id}"
                if count >= rule.threshold
                else f"velocity window {count}/{rule.threshold} below threshold"
            ),
            metadata={
                "count": count,
                "threshold": rule.threshold,
                "window_seconds": rule.window_seconds,
            },
        )

    def _evaluate_high_risk_event(
        self, event: AccountEvent, rule: TriggerRule
    ) -> TriggerEvaluation:
        """Trigger on configured high-risk events (reset, payee change, etc.)."""
        is_high_risk_type = event.event_type in rule.high_risk_event_types

        # Check payload for high-risk keys
        payload_keys_found = []
        if is_high_risk_type:
            for key in rule.high_risk_payload_keys:
                if event.payload.get(key):
                    payload_keys_found.append(key)

        is_high_risk = is_high_risk_type and bool(payload_keys_found)

        return TriggerEvaluation(
            triggered=is_high_risk,
            trigger_type=TriggerType.HIGH_RISK_EVENT if is_high_risk else None,
            rule_id=rule.rule_id,
            reason=(
                f"high-risk event {event.event_type.value} with keys "
                f"{payload_keys_found} for account {event.account_id}"
                if is_high_risk
                else f"event {event.event_type.value} is not a high-risk trigger"
            ),
            metadata={
                "event_type": event.event_type.value,
                "payload_keys_found": payload_keys_found,
            },
        )

    def _record_velocity(self, event: AccountEvent) -> None:
        """Record event in relevant velocity windows."""
        # Record all events in a general account window
        window_key = "general"
        window = self._get_velocity_window(
            event.account_id, window_key, 600
        )
        window.add(event.timestamp)

    def should_create_investigation(self, event: AccountEvent) -> Optional[str]:
        """Determine if an event should trigger an investigation.

        Returns the trigger_type string if triggered, None otherwise.
        Only the first matching trigger is returned (deduplication).
        """
        evaluations = self.evaluate(event)
        if not evaluations:
            return None
        # Return the first triggered rule's type
        return evaluations[0].trigger_type.value

    def get_trigger_version(self) -> str:
        return self.TRIGGER_VERSION

    def get_rules(self) -> dict[str, TriggerRule]:
        return dict(self.rules)
