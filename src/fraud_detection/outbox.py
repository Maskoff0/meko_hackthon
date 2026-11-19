"""Outbox pattern for reliable Meko enrichment delivery.

Per plan.md Phase 3:
  - Use an outbox or equivalent reliable delivery for Meko enrichment.
  - Handle retries, budgets, rate limits, backpressure, dead letters,
    and provider outages explicitly.
  - Never block a legitimate transaction solely because a non-critical
    context provider failed.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .storage import Storage


class OutboxMessage:
    """A message in the outbox awaiting delivery."""

    def __init__(self, row):
        self.id = row["id"]
        self.aggregate_type = row["aggregate_type"]
        self.aggregate_id = row["aggregate_id"]
        self.event_type = row["event_type"]
        self.payload = json.loads(row["payload"]) if row["payload"] else {}
        self.status = row["status"]
        self.attempts = row["attempts"]
        self.max_attempts = row["max_attempts"]
        self.created_at = row["created_at"]
        self.delivered_at = row["delivered_at"]
        self.last_error = row["last_error"]


class Outbox:
    """Reliable outbox for Meko enrichment and other side effects.

    Writes are transactional with the business event. A background worker
    polls for pending messages, attempts delivery, and retries on failure.
    After max_attempts, messages are moved to the dead letter queue.
    """

    def __init__(
        self,
        storage: Storage,
        deliver: Optional[Callable[[dict], Any]] = None,
        poll_interval: float = 1.0,
        max_attempts: int = 5,
        retry_backoff_seconds: float = 2.0,
    ):
        self.storage = storage
        self.deliver = deliver
        self.poll_interval = poll_interval
        self.max_attempts = max_attempts
        self.retry_backoff_seconds = retry_backoff_seconds
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._delivery_count = 0
        self._failure_count = 0

    def enqueue(
        self,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: dict,
        max_attempts: Optional[int] = None,
    ) -> int:
        """Enqueue a message for delivery. Returns the outbox id."""
        if max_attempts is None:
            max_attempts = self.max_attempts
        return self.storage.outbox_insert(
            aggregate_type, aggregate_id, event_type, payload, max_attempts
        )

    def start(self) -> None:
        """Start the background delivery worker."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._delivery_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the background delivery worker."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _delivery_loop(self) -> None:
        """Poll for pending messages and attempt delivery."""
        while self._running:
            try:
                self._process_pending()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _process_pending(self) -> None:
        """Process all pending outbox messages."""
        messages = self.storage.outbox_pending(limit=50)
        for row in messages:
            msg = OutboxMessage(row)
            self._attempt_delivery(msg)

    def _attempt_delivery(self, msg: OutboxMessage) -> None:
        """Attempt to deliver a single outbox message."""
        if msg.attempts >= self.max_attempts:
            self._move_to_dead_letter(msg, "max_attempts_exceeded")
            return

        try:
            if self.deliver is not None:
                self.deliver(msg.payload)
            self.storage.outbox_mark_sent(msg.id)
            self._delivery_count += 1
        except Exception as exc:
            self.storage.outbox_increment_attempts(msg.id, str(exc))
            self._failure_count += 1
            if msg.attempts + 1 >= self.max_attempts:
                self._move_to_dead_letter(msg, str(exc))

    def _move_to_dead_letter(self, msg: OutboxMessage, reason: str) -> None:
        """Move a failed message to the dead letter queue."""
        self.storage.dead_letter_insert(
            source_table="outbox",
            source_id=str(msg.id),
            reason=reason,
            payload={
                "id": msg.id,
                "aggregate_type": msg.aggregate_type,
                "aggregate_id": msg.aggregate_id,
                "event_type": msg.event_type,
                "payload": msg.payload,
                "attempts": msg.attempts,
            },
        )
        self.storage.outbox_mark_sent(msg.id)  # mark as handled (dead-lettered)

    def stats(self) -> dict:
        """Return delivery statistics."""
        with self._lock:
            return {
                "delivered": self._delivery_count,
                "failed": self._failure_count,
                "pending": len(self.storage.outbox_pending(limit=10000)),
            }


class OutboxWorker:
    """Context manager that starts and stops the outbox worker."""

    def __init__(self, outbox: Outbox):
        self.outbox = outbox

    def __enter__(self):
        self.outbox.start()
        return self.outbox

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.outbox.stop()
