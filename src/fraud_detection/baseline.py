"""Deterministic baseline: rules and velocity features.

Provides a transparent, reproducible comparison independent of Meko or an LLM.
Rules include failed-login count in a time window, new-device/reset sequences,
and high-risk step detection (payee change, reset, limit change).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Optional

from .domain import AccountEvent, EventType


@dataclass
class VelocityWindow:
    """Sliding time-window counter for velocity features."""

    window_seconds: int
    events: Deque[datetime] = field(default_factory=deque)

    def add(self, timestamp: datetime) -> None:
        self.events.append(timestamp)
        self._evict(timestamp)

    def _evict(self, current: datetime) -> None:
        cutoff = current.timestamp() - self.window_seconds
        while self.events and self.events[0].timestamp() < cutoff:
            self.events.popleft()

    def count(self, at: Optional[datetime] = None) -> int:
        if at is None:
            return len(self.events)
        cutoff = at.timestamp() - self.window_seconds
        return sum(1 for t in self.events if t.timestamp() >= cutoff)


@dataclass
class BaselineResult:
    """Result of deterministic baseline evaluation."""

    triggered: bool
    reason_codes: list[str] = field(default_factory=list)
    score: float = 0.0
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "triggered": self.triggered,
            "reason_codes": self.reason_codes,
            "score": self.score,
            "details": self.details,
        }


class BaselineEvaluator:
    """Deterministic rules-and-velocity baseline for fraud detection."""

    def __init__(
        self,
        failed_login_threshold: int = 5,
        velocity_window_seconds: int = 600,
    ):
        self.failed_login_threshold = failed_login_threshold
        self.velocity_window_seconds = velocity_window_seconds
        self._login_windows: dict[str, VelocityWindow] = {}
        self._device_events: dict[str, list[datetime]] = {}
        self._reset_events: dict[str, list[datetime]] = {}
        self._high_risk_events: dict[str, list[datetime]] = {}

    def _get_window(self, account_id: str) -> VelocityWindow:
        if account_id not in self._login_windows:
            self._login_windows[account_id] = VelocityWindow(
                window_seconds=self.velocity_window_seconds
            )
        return self._login_windows[account_id]

    def evaluate(self, event: AccountEvent) -> BaselineResult:
        """Evaluate a single event against deterministic rules.

        Returns a BaselineResult with triggered flag, reason codes, score, and details.
        """
        reason_codes: list[str] = []
        score = 0.0
        details: dict = {}

        now = event.timestamp
        account_id = event.account_id

        if event.event_type == EventType.LOGIN:
            window = self._get_window(account_id)
            window.add(now)
            count = window.count(now)
            details["failed_login_count_window"] = count
            details["velocity_window_seconds"] = self.velocity_window_seconds

            if count >= self.failed_login_threshold:
                reason_codes.append("velocity_breach")
                score += 0.4
                details["velocity_breach"] = True

            if event.payload.get("failed", False):
                reason_codes.append("failed_login")
                score += 0.2

        elif event.event_type == EventType.DEVICE:
            if account_id not in self._device_events:
                self._device_events[account_id] = []
            self._device_events[account_id].append(now)
            is_new = len(self._device_events[account_id]) == 1
            details["new_device"] = is_new
            if is_new:
                reason_codes.append("new_device")
                score += 0.25

        elif event.event_type == EventType.RESET:
            if account_id not in self._reset_events:
                self._reset_events[account_id] = []
            self._reset_events[account_id].append(now)
            details["password_reset"] = True
            reason_codes.append("password_reset")
            score += 0.2

        elif event.event_type == EventType.TRANSACTION:
            if account_id not in self._high_risk_events:
                self._high_risk_events[account_id] = []
            self._high_risk_events[account_id].append(now)

            payload = event.payload
            if payload.get("new_payee"):
                reason_codes.append("new_payee")
                score += 0.3
            if payload.get("test_payment"):
                reason_codes.append("test_payment")
                score += 0.2
            if payload.get("limit_change"):
                reason_codes.append("limit_change")
                score += 0.25

        # Combined pattern: new device + reset sequence
        device_count = len(self._device_events.get(account_id, []))
        reset_count = len(self._reset_events.get(account_id, []))
        if device_count >= 1 and reset_count >= 1:
            reason_codes.append("device_reset_sequence")
            score += 0.15

        # Cap score at 1.0
        score = min(score, 1.0)
        triggered = score >= 0.5

        return BaselineResult(
            triggered=triggered,
            reason_codes=reason_codes,
            score=score,
            details=details,
        )
