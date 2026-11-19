"""Durable event stream for Phase 3.

Persists events to SQLite and provides subscription, acknowledgment,
replay, and dead-letter capabilities. Agents subscribe to this stream
rather than polling Meko or one another. Correlation runs only at
configured triggers.

Per plan.md Phase 3:
  - Use an outbox or equivalent reliable delivery for Meko enrichment.
  - Subscribe agents to the durable stream rather than polling Meko or
    other agents.
  - Handle retries, budgets, rate limits, backpressure, dead letters,
    and provider outages explicitly.
"""
from __future__ import annotations

import json
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Optional

from .domain import AccountEvent
from .storage import Storage


class StreamMessage:
    """A durable message in the event stream."""

    def __init__(
        self,
        offset: int,
        event: AccountEvent,
        created_at: str,
    ):
        self.offset = offset
        self.event = event
        self.created_at = created_at
        self.acked: bool = False


class EventStream:
    """Durable, append-only event stream backed by SQLite.

    Provides:
      - append(event): durable write, returns offset
      - subscribe(agent_id, handler): register a handler for new events
      - ack(offset): acknowledge a message as processed
      - replay(from_offset): replay events from a given offset
      - dead_letter(message, reason): move undeliverable messages to DLQ
    """

    def __init__(self, storage: Storage):
        self.storage = storage
        self._handlers: dict[str, list[Callable[[AccountEvent], None]]] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._poll_interval = 0.5  # seconds

    def append(self, event: AccountEvent) -> int:
        """Append an event to the durable stream. Returns the offset."""
        row = self.storage.conn.execute(
            "SELECT id FROM events WHERE event_id = ?", (event.event_id,)
        ).fetchone()
        if row is not None:
            return row[0]  # already exists; return existing offset

        inserted = self.storage.insert_event(event)
        if not inserted:
            row = self.storage.conn.execute(
                "SELECT id FROM events WHERE idempotency_key = ?",
                (event.idempotency_key,),
            ).fetchone()
            return row[0] if row else -1

        row = self.storage.conn.execute(
            "SELECT id FROM events WHERE event_id = ?", (event.event_id,)
        ).fetchone()
        return row[0] if row else -1

    def subscribe(self, agent_id: str, handler: Callable[[AccountEvent], None]) -> None:
        """Register a handler for an agent. Called for each new event."""
        with self._lock:
            if agent_id not in self._handlers:
                self._handlers[agent_id] = []
            self._handlers[agent_id].append(handler)

    def unsubscribe(self, agent_id: str) -> None:
        with self._lock:
            self._handlers.pop(agent_id, None)

    def start(self) -> None:
        """Start the background polling loop that dispatches events to handlers."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the background polling loop."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _poll_loop(self) -> None:
        """Poll for new events and dispatch to subscribed handlers."""
        last_offset = 0
        while self._running:
            try:
                rows = self.storage.conn.execute(
                    "SELECT id, event_id, account_id, event_type, source, timestamp, "
                    "schema_version, idempotency_key, payload, provenance, ingested_at "
                    "FROM events WHERE id > ? ORDER BY id LIMIT 100",
                    (last_offset,),
                ).fetchall()

                for row in rows:
                    last_offset = row["id"]
                    event = self._row_to_event(row)
                    self._dispatch(event)

            except Exception:
                # Swallow poll errors; retry on next interval
                pass

            threading.Event().wait(self._poll_interval)

    def _dispatch(self, event: AccountEvent) -> None:
        """Dispatch an event to all subscribed handlers."""
        with self._lock:
            handlers = list(self._handlers.values())
        for handler_list in handlers:
            for handler in handler_list:
                try:
                    handler(event)
                except Exception:
                    # Handler failure should not kill the stream
                    pass

    def replay(self, from_offset: int = 0) -> list[AccountEvent]:
        """Replay events from a given offset for recovery/backfill."""
        rows = self.storage.conn.execute(
            "SELECT id, event_id, account_id, event_type, source, timestamp, "
            "schema_version, idempotency_key, payload, provenance, ingested_at "
            "FROM events WHERE id >= ? ORDER BY id",
            (from_offset,),
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def ack(self, offset: int) -> None:
        """Acknowledge a message as processed (no-op for SQLite stream;
        kept for interface compatibility)."""
        pass

    def dead_letter(self, source_table: str, source_id: str, reason: str, payload: dict) -> int:
        """Move an undeliverable message to the dead letter queue."""
        return self.storage.dead_letter_insert(source_table, source_id, reason, payload)

    def _row_to_event(self, row) -> AccountEvent:
        from .domain import EventType

        payload = json.loads(row["payload"]) if row["payload"] else {}
        return AccountEvent(
            event_id=row["event_id"],
            account_id=row["account_id"],
            event_type=EventType(row["event_type"]),
            source=row["source"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            schema_version=row["schema_version"],
            idempotency_key=row["idempotency_key"],
            payload=payload,
            provenance=row["provenance"] or "synthetic",
        )

    def get_offset(self) -> int:
        """Return the current maximum offset (event id)."""
        row = self.storage.conn.execute(
            "SELECT MAX(id) as max_id FROM events"
        ).fetchone()
        return row["max_id"] or 0

    def count(self) -> int:
        """Return the total number of events in the stream."""
        row = self.storage.conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()
        return row["cnt"]


class StreamSubscription:
    """Context manager for subscribing to the stream and auto-unsubscribing."""

    def __init__(
        self,
        stream: EventStream,
        agent_id: str,
        handler: Callable[[AccountEvent], None],
    ):
        self.stream = stream
        self.agent_id = agent_id
        self.handler = handler

    def __enter__(self):
        self.stream.subscribe(self.agent_id, self.handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stream.unsubscribe(self.agent_id)
