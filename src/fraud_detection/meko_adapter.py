"""Meko MCP adapter.

Wraps the hosted Meko MCP endpoint behind an adapter/interface with contract
tests. Meko is enrichment only -- memory writes and context searches are real
hosted operations, but they never execute fraud containment. All retrieved
content and agent output are treated as untrusted evidence.
"""
from __future__ import annotations

import base64
import asyncio
import hashlib
import json
import pathlib
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from .settings import Settings


class MekoAdapterError(RuntimeError):
    """Raised when a Meko MCP operation fails."""


class TraceEvent:
    """A single traced Meko MCP operation with latency, tokens, and result."""

    def __init__(
        self,
        tool: str,
        args: dict[str, Any],
        result: Any,
        latency_seconds: float,
        estimated_tokens: int,
        trace_id: str,
        error: Optional[str] = None,
    ):
        self.tool = tool
        self.args = args
        self.result = result
        self.latency_seconds = latency_seconds
        self.estimated_tokens = estimated_tokens
        self.trace_id = trace_id
        self.error = error
        self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "args": self.args,
            "result": self.result,
            "latency_seconds": self.latency_seconds,
            "estimated_tokens": self.estimated_tokens,
            "trace_id": self.trace_id,
            "error": self.error,
            "timestamp": self.timestamp,
        }


class MekoAdapter:
    """Thin adapter around the Meko MCP server tools."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        trace_id: Optional[str] = None,
        trace_persistence_path: Optional[str] = None,
    ):
        self.settings = settings or Settings()
        self._session: Optional[ClientSession] = None
        self._http_client: Optional[httpx.AsyncClient] = None
        self.trace_id = trace_id or str(uuid.uuid4())
        self.trace_persistence_path = trace_persistence_path
        self.trace_events: list[TraceEvent] = []
        self.trace_start_time = time.time()

    @asynccontextmanager
    async def connect(self):
        """Establish an authenticated MCP client session to the hosted Meko endpoint."""
        headers = {"Authorization": f"Bearer {self.settings.meko_api_key}"}
        timeout = httpx.Timeout(30, read=self.settings.meko_timeout_seconds * 10)
        self._http_client = httpx.AsyncClient(headers=headers, timeout=timeout)
        try:
            async with streamable_http_client(
                self.settings.meko_mcp_url, http_client=self._http_client
            ) as (read, write, _get_session_id):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self._session = session
                    yield self
        finally:
            self._session = None
            await self._http_client.aclose()
            self._http_client = None

    async def _require_session(self) -> ClientSession:
        if self._session is None:
            raise MekoAdapterError("MekoAdapter session not initialized. Use 'async with connect()'.")
        return self._session

    async def call(self, tool: str, **args: Any) -> Any:
        """Call a Meko MCP tool, returning parsed JSON or raw text.

        Traces each call with latency, estimated tokens, and trace_id for
        end-to-end observability and chain-of-thought traceability. The
        trace_id is recorded in trace events (not forwarded as a tool arg,
        since MCP tools use conversation_id for call correlation).
        """
        session = await self._require_session()
        args.setdefault("datapack_id", self.settings.meko_datapack_id)

        start = time.monotonic()
        res = await session.call_tool(tool, args)
        latency_seconds = time.monotonic() - start

        text = "".join(c.text for c in res.content if isinstance(c, TextContent))
        if res.isError:
            error_msg = text or "no error details"
            event = TraceEvent(
                tool=tool,
                args=args,
                result=None,
                latency_seconds=latency_seconds,
                estimated_tokens=len(text) // 4,
                trace_id=self.trace_id,
                error=error_msg,
            )
            self.trace_events.append(event)
            self._persist_trace()
            raise MekoAdapterError(
                f"Meko MCP tool {tool!r} failed: {error_msg}"
            )

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = text

        estimated_tokens = len(text) // 4
        event = TraceEvent(
            tool=tool,
            args=args,
            result=parsed,
            latency_seconds=latency_seconds,
            estimated_tokens=estimated_tokens,
            trace_id=self.trace_id,
        )
        self.trace_events.append(event)
        self._persist_trace()
        return parsed

    # --- Trace observability --------------------------------------------------
    def set_trace_id(self, trace_id: str) -> None:
        """Set the trace ID for all subsequent MCP calls."""
        self.trace_id = trace_id

    def get_trace_events(self) -> list[dict[str, Any]]:
        """Return all recorded trace events as dictionaries."""
        return [e.to_dict() for e in self.trace_events]

    def get_trace_summary(self) -> dict[str, Any]:
        """Return a summary of all trace events."""
        if not self.trace_events:
            return {
                "trace_id": self.trace_id,
                "total_events": 0,
                "total_latency_seconds": 0.0,
                "total_estimated_tokens": 0,
                "error_count": 0,
                "tools_called": [],
            }

        total_latency = sum(e.latency_seconds for e in self.trace_events)
        total_tokens = sum(e.estimated_tokens for e in self.trace_events)
        error_count = sum(1 for e in self.trace_events if e.error is not None)
        tools_called = sorted(set(e.tool for e in self.trace_events))

        return {
            "trace_id": self.trace_id,
            "total_events": len(self.trace_events),
            "total_latency_seconds": round(total_latency, 4),
            "total_estimated_tokens": total_tokens,
            "error_count": error_count,
            "tools_called": tools_called,
            "start_time": self.trace_start_time,
            "duration_seconds": round(time.time() - self.trace_start_time, 4),
        }

    def export_trace_meko_format(self) -> dict[str, Any]:
        """Export trace data in Meko's native trace schema format.

        Format matches Meko's trace observability model:
        - trace_id: unique trace identifier
        - span_id: unique span per operation
        - parent_span_id: parent span (none for root operations)
        - operation: MCP tool name
        - duration_ms: call latency in milliseconds
        - tokens: estimated token count
        - status: success/error
        - timestamp: event timestamp
        """
        spans = []
        for i, event in enumerate(self.trace_events):
            span_id = hashlib.sha256(
                f"{self.trace_id}:{i}:{event.tool}".encode()
            ).hexdigest()[:16]
            spans.append({
                "trace_id": self.trace_id,
                "span_id": span_id,
                "parent_span_id": None,
                "operation": event.tool,
                "duration_ms": round(event.latency_seconds * 1000, 2),
                "tokens": event.estimated_tokens,
                "status": "error" if event.error else "ok",
                "timestamp": event.timestamp,
                "args": event.args,
                "result": event.result,
                "error": event.error,
            })

        return {
            "trace_id": self.trace_id,
            "spans": spans,
            "summary": self.get_trace_summary(),
        }

    def save_trace(self, path: Optional[str] = None) -> None:
        """Persist trace events to disk for resumability across sessions."""
        target = path or self.trace_persistence_path
        if not target:
            return
        target_path = pathlib.Path(target)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "trace_id": self.trace_id,
            "trace_start_time": self.trace_start_time,
            "events": [e.to_dict() for e in self.trace_events],
        }
        target_path.write_text(json.dumps(payload, indent=2))

    def load_trace(self, path: str) -> None:
        """Load trace events from disk for resumability."""
        target_path = pathlib.Path(path)
        if not target_path.exists():
            return
        payload = json.loads(target_path.read_text())
        self.trace_id = payload.get("trace_id", self.trace_id)
        self.trace_start_time = payload.get("trace_start_time", self.trace_start_time)
        self.trace_events = [
            TraceEvent(
                tool=e["tool"],
                args=e.get("args", {}),
                result=e.get("result"),
                latency_seconds=e.get("latency_seconds", 0.0),
                estimated_tokens=e.get("estimated_tokens", 0),
                trace_id=e.get("trace_id", self.trace_id),
                error=e.get("error"),
            )
            for e in payload.get("events", [])
        ]

    def _persist_trace(self) -> None:
        """Auto-persist trace after each event if a path is configured."""
        if self.trace_persistence_path:
            self.save_trace(self.trace_persistence_path)

    # --- Conversation lifecycle -------------------------------------------
    async def create_conversation(self, agent_id: str, title: str, metadata: dict) -> str:
        conversation = await self.call(
            "conversation_create",
            agent_id=agent_id,
            title=title,
            metadata=json.dumps(metadata),
        )
        conversation_id = (
            conversation.get("id") if isinstance(conversation, dict) else conversation
        )
        if not isinstance(conversation_id, str) or not conversation_id:
            raise MekoAdapterError("Meko conversation_create returned no conversation ID.")
        return conversation_id

    # --- Share signals ------------------------------------------------------
    async def write_signal(
        self,
        agent_id: str,
        account_id: str,
        signal_type: str,
        value: str,
        confidence: float,
        evidence_refs=(),
    ):
        signal = {
            "account_id": account_id,
            "agent": agent_id,
            "signal_type": signal_type,
            "value": value,
            "confidence": confidence,
            "timestamp": time.time(),
            "evidence_refs": list(evidence_refs),
        }
        text = (
            f"ATO signal for account {account_id}: {signal_type}={value} "
            f"(confidence {confidence}) from {agent_id}. "
            f"JSON: {json.dumps(signal)}"
        )
        conversation_id = await self.create_conversation(
            agent_id,
            f"ATO signals for account {account_id}",
            {"kind": "signal", "account_id": account_id},
        )
        return await self.memory_add(
            text=text,
            agent_id=agent_id,
            conversation_id=conversation_id,
            run_id=account_id,
            metadata=json.dumps({"kind": "signal", "account_id": account_id}),
        )

    async def batch_write_signals(
        self,
        signals: list[dict],
        *,
        shared_conversation_id: Optional[str] = None,
        agent_id: str = "ingestion_agent",
        account_id: Optional[str] = None,
    ):
        """Write multiple signals into shared conversations.

        When shared_conversation_id is provided, all signals are written to
        that single conversation, enabling Meko's built-in deduplication
        and server-side LLM extraction of durable facts across signals.
        When shared_conversation_id is None, each signal gets its own
        conversation (backward-compatible default).

        Args:
            signals: List of signal dicts with keys: signal_type, value,
                confidence, evidence_refs, account_id (optional override).
            shared_conversation_id: Existing conversation ID to reuse for all
                signals. If None, creates one conversation per signal.
            agent_id: Agent identity for the writes.
            account_id: Default account_id for signals that don't specify one.

        Returns:
            List of results from memory_add calls.
        """
        results = []
        conv_id = shared_conversation_id

        for signal in signals:
            signal_account_id = signal.get("account_id") or account_id or "unknown"
            signal_text = (
                f"ATO signal for account {signal_account_id}: "
                f"{signal.get('signal_type', 'unknown')}="
                f"{signal.get('value', '')} "
                f"(confidence {signal.get('confidence', 0.0)}) from {agent_id}. "
                f"JSON: {json.dumps(signal)}"
            )

            if conv_id is None:
                conv_id = await self.create_conversation(
                    agent_id,
                    f"ATO signals for account {signal_account_id}",
                    {"kind": "signal", "account_id": signal_account_id},
                )

            result = await self.call(
                "memory_add",
                text=signal_text,
                agent_id=agent_id,
                conversation_id=conv_id,
                run_id=signal_account_id,
                metadata=json.dumps(
                    {"kind": "signal", "account_id": signal_account_id}
                ),
            )
            results.append(result)

        return results

    async def memory_add(
        self,
        text: str,
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[str] = None,
    ) -> Any:
        """Store a memory with the given text.

        Returns the memory record including its ID.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"Memory add",
                {"kind": "memory_add"},
            )
        args: dict[str, Any] = {
            "text": text,
            "agent_id": agent_id,
            "conversation_id": conversation_id,
        }
        if run_id is not None:
            args["run_id"] = run_id
        if metadata is not None:
            args["metadata"] = metadata
        return await self.call("memory_add", **args)

    # --- Connect the dots / remember past attacks ---------------------------
    async def correlate(self, account_id: str, agent_id: str = "correlator_agent"):
        conversation_id = await self.create_conversation(
            agent_id,
            f"ATO correlation for account {account_id}",
            {"kind": "correlation", "account_id": account_id},
        )
        return await self.call(
            "context_search",
            query=(
                f"recent ATO signals for account {account_id}, "
                "and known attacker playbooks matching them"
            ),
            conversation_id=conversation_id,
            agent_id=agent_id,
            limit=20,
        )

    async def past_attack_patterns(
        self, description: str, agent_id: str = "correlator_agent"
    ):
        conversation_id = await self.create_conversation(
            agent_id,
            "ATO past-attack pattern search",
            {"kind": "past_attack_patterns"},
        )
        return await self.call(
            "context_search",
            query=description,
            conversation_id=conversation_id,
            agent_id=agent_id,
            force_source="knowledge_base",
            limit=10,
        )

    # --- Memory search (memories only, not KB/conversations) -------------
    async def memory_search(
        self,
        query: str,
        *,
        limit: int = 10,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Search private memories in the datapack.

        Uses memory_search (scoped to memories) instead of context_search
        (memory + knowledge base + conversations). Results are ordered by
        combined score (semantic + keyword + entity). Setting limit bounds
        LLM context size.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"Memory search: {query[:50]}",
                {"kind": "memory_search", "query": query},
            )
        return await self.call(
            "memory_search",
            query=query,
            limit=limit,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    async def memory_update(
        self,
        memory_id: str,
        text: str,
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Update an existing memory's text without creating a duplicate.

        Use memory_update instead of memory_add when changing a fact that's
        already stored. memory_add does no dedup check and stores text twice.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"Memory update: {memory_id[:12]}",
                {"kind": "memory_update", "memory_id": memory_id},
            )
        return await self.call(
            "memory_update",
            memory_id=memory_id,
            text=text,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    async def memory_get_all(
        self,
        *,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """List all memories in the datapack, paged.

        Omits page -> returns newest page only. page_size sets rows per page.
        Returns results plus total page count.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                "Memory list all",
                {"kind": "memory_get_all"},
            )
        args: dict[str, Any] = {"conversation_id": conversation_id}
        if page is not None:
            args["page"] = page
        if page_size is not None:
            args["page_size"] = page_size
        return await self.call("memory_get_all", **args)

    async def memory_get_by_id(
        self,
        memory_id: str,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Retrieve a specific memory by its ID."""
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"Memory get by id: {memory_id[:12]}",
                {"kind": "memory_get_by_id", "memory_id": memory_id},
            )
        return await self.call(
            "memory_get_by_id",
            memory_id=memory_id,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    async def memory_delete_by_id(
        self,
        memory_id: str,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Permanently delete one memory by its ID.

        Only available for memories created on or after September 9, 2026.
        Deleted memories cannot be recovered.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"Memory delete: {memory_id[:12]}",
                {"kind": "memory_delete_by_id", "memory_id": memory_id},
            )
        return await self.call(
            "memory_delete_by_id",
            memory_id=memory_id,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    async def memory_delete_all(
        self,
        *,
        agent_id: Optional[str] = None,
        datapack_id: Optional[str] = None,
        run_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Remove memories written under one agent_id, optionally narrowed by run_id.

        Deletes only the caller's memories under that agent_id, never another
        member's. Omitting agent_id deletes the meko_agent bucket. Returns
        {deleted_count, complete}; if complete is False, call again to continue.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id or "meko_agent",
                "Memory delete all",
                {"kind": "memory_delete_all"},
            )
        args: dict[str, Any] = {"conversation_id": conversation_id}
        if agent_id is not None:
            args["agent_id"] = agent_id
        if datapack_id is not None:
            args["datapack_id"] = datapack_id
        if run_id is not None:
            args["run_id"] = run_id
        return await self.call("memory_delete_all", **args)

    async def memory_promote(
        self,
        memory_ids: list[str],
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Move private memories into the datapack's shared knowledge base.

        Promotion is one-way and irreversible via MCP. Private records are
        removed from private memory but memory_search still returns them
        alongside private memories. Datapack owners and maintainers only.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                "Memory promote to shared knowledge",
                {"kind": "memory_promote"},
            )
        return await self.call(
            "memory_promote",
            memory_ids=memory_ids,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    # --- Knowledge base ------------------------------------------------------
    async def knowledgebase_upload_document(
        self,
        filename: str,
        file_bytes: bytes,
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Request an upload URL for a knowledge-base document.

        Per Meko docs, the agent sends the file's first 3,072 bytes
        (content_head_base64) plus a content hash. Meko validates the
        sample against the file extension before issuing an upload URL.
        After receiving the URL, the caller must PUT the full file bytes
        to that URL, then poll knowledgebase_document_status until
        indexing finishes.
        """
        import base64 as _b64
        import hashlib as _hashlib

        content_head = file_bytes[:3072]
        content_head_base64 = _b64.b64encode(content_head).decode()
        content_hash = _hashlib.sha256(file_bytes).hexdigest()
        size = len(file_bytes)

        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"KB upload: {filename}",
                {"kind": "kb_upload", "filename": filename, "size": size},
            )
        return await self.call(
            "knowledgebase_upload_document",
            filename=filename,
            size=size,
            content_hash=content_hash,
            content_head_base64=content_head_base64,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    async def knowledgebase_document_status(
        self,
        document_key: str,
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Poll the indexing status of a knowledge-base document.

        Returns status such as ``indexed``, ``abandoned``, or ``failed``
        along with any error message.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"KB status: {document_key[:12]}",
                {"kind": "kb_document_status", "document_key": document_key},
            )
        return await self.call(
            "knowledgebase_document_status",
            document_key=document_key,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    async def knowledgebase_delete_document(
        self,
        document_key: str,
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Remove a document from the knowledge base.

        Only the owner, a maintainer, or the uploader can remove a document.
        Removal is not undoable and only available after indexing completes.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"KB delete: {document_key[:12]}",
                {"kind": "kb_delete_document", "document_key": document_key},
            )
        return await self.call(
            "knowledgebase_delete_document",
            document_key=document_key,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    async def upload_document_and_wait(
        self,
        file_path: str,
        *,
        agent_id: str = "meko_agent",
        poll_interval_seconds: float = 2.0,
        max_poll_seconds: float = 300.0,
    ) -> Any:
        """Upload a local file to the knowledge base and wait for indexing.

        Reads the file from disk, requests an upload URL, PUTs the file bytes,
        then polls ``knowledgebase_document_status`` until indexing finishes
        or ``max_poll_seconds`` is exceeded.

        Args:
            file_path: Path to the local file to upload.
            agent_id: Agent identity for the upload.
            poll_interval_seconds: Seconds between status polls.
            max_poll_seconds: Maximum total time to wait for indexing.

        Returns:
            The final status response from ``knowledgebase_document_status``.

        Raises:
            MekoAdapterError: If indexing does not complete within the
                timeout, or if the document is abandoned/failed.
        """
        path = pathlib.Path(file_path)
        if not path.exists():
            raise MekoAdapterError(f"File not found: {file_path}")

        file_bytes = path.read_bytes()
        upload_result = await self.knowledgebase_upload_document(
            filename=path.name,
            file_bytes=file_bytes,
            agent_id=agent_id,
        )

        # Extract S3 upload URL and document identifier from the result
        if isinstance(upload_result, dict):
            s3_url = upload_result.get("url")
            s3_fields = upload_result.get("fields", {})
            s3_key = upload_result.get("key")
            document_key = upload_result.get("document_key") or s3_key
        elif isinstance(upload_result, str):
            try:
                parsed = json.loads(upload_result)
                s3_url = parsed.get("url")
                s3_fields = parsed.get("fields", {})
                s3_key = parsed.get("key")
                document_key = parsed.get("document_key") or s3_key
            except json.JSONDecodeError:
                s3_url = s3_fields = s3_key = document_key = None
        else:
            s3_url = s3_fields = s3_key = document_key = None

        if not s3_url or not s3_key or not document_key:
            # File may already be uploaded (from a previous attempt).
            # Use the key as document_key and proceed to status polling.
            if isinstance(upload_result, dict) and upload_result.get("already_uploaded"):
                document_key = upload_result.get("key")
                if not document_key:
                    raise MekoAdapterError(
                        f"KB upload returned already_uploaded but no key: {upload_result}"
                    )
                # Skip S3 POST, go straight to polling
                s3_url = None
            else:
                raise MekoAdapterError(
                    f"KB upload did not return S3 url/key/document_key: {upload_result}"
                )

        # POST the file bytes to the S3 presigned upload URL.
        # Use a separate client without the Meko Bearer token, since
        # S3 presigned POST uses AWS Signature V4 via form fields.
        if s3_url:
            files = {"file": (path.name, file_bytes, "text/markdown")}
            async with httpx.AsyncClient(timeout=60.0) as s3_client:
                put_resp = await s3_client.post(
                    s3_url, data=s3_fields, files=files
                )
            if put_resp.status_code not in (200, 201, 204):
                raise MekoAdapterError(
                    f"File upload to KB failed: HTTP {put_resp.status_code} "
                    f"{put_resp.text[:200]}"
                )

        # Poll for indexing completion
        elapsed = 0.0
        while elapsed < max_poll_seconds:
            status = await self.knowledgebase_document_status(
                document_key=document_key, agent_id=agent_id
            )
            if isinstance(status, dict):
                state = (
                    status.get("document_status")
                    or status.get("state")
                    or status.get("status")
                    or "unknown"
                )
                if state in ("indexed", "completed", "ready", "COMPLETED"):
                    return status
                if state in ("abandoned", "failed", "error", "ABANDONED", "FAILED", "ERROR"):
                    raise MekoAdapterError(
                        f"KB document indexing {state}: "
                        f"{status.get('message', status.get('reason', ''))}"
                    )
            await asyncio.sleep(poll_interval_seconds)
            elapsed += poll_interval_seconds

        raise MekoAdapterError(
            f"KB document {document_key} did not finish indexing within "
            f"{max_poll_seconds}s"
        )

    # --- Artifacts -----------------------------------------------------------
    async def artifact_put(
        self,
        filename: str,
        content_base64: str,
        content_type: str,
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Upload an artifact and return its content hash.

        The hash can be saved as a memory for later retrieval across agents
        and sessions. Uploading the same file twice returns the same hash
        and stores no duplicate.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"Artifact put: {filename}",
                {"kind": "artifact_put", "filename": filename},
            )
        return await self.call(
            "artifact_put",
            filename=filename,
            content_base64=content_base64,
            content_type=content_type,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    async def artifact_get(
        self,
        artifact_hash: str,
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Retrieve an artifact by its content hash.

        Files under 1 MB return contents directly; files 1 MB or more return
        a path to the file in object storage. Each retrieval resets the
        expiry clock.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"Artifact get: {artifact_hash[:16]}",
                {"kind": "artifact_get", "artifact_hash": artifact_hash},
            )
        return await self.call(
            "artifact_get",
            artifact_hash=artifact_hash,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    async def put_artifact_and_remember(
        self,
        filename: str,
        content_base64: str,
        content_type: str,
        memory_name: str,
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Upload an artifact and save its hash as a named memory.

        This enables cross-agent retrieval: any agent in the same datapack
        can look up the hash from memory and call ``artifact_get`` to
        retrieve the file whole.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"Artifact put and remember: {filename}",
                {"kind": "artifact_put_remember", "filename": filename,
                 "memory_name": memory_name},
            )
        result = await self.call(
            "artifact_put",
            filename=filename,
            content_base64=content_base64,
            content_type=content_type,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

        # Extract the hash from the result
        artifact_hash = None
        if isinstance(result, dict):
            artifact_hash = (
                result.get("hash")
                or result.get("artifact_hash")
                or result.get("id")
            )
        elif isinstance(result, str):
            try:
                parsed = json.loads(result)
                artifact_hash = (
                    parsed.get("hash")
                    or parsed.get("artifact_hash")
                    or parsed.get("id")
                )
            except json.JSONDecodeError:
                pass

        if not artifact_hash:
            raise MekoAdapterError(
                f"artifact_put did not return a hash: {result}"
            )

        # Save the hash as a named memory so any agent can find it later
        memory_text = (
            f"Artifact hash for '{filename}' ({content_type}): "
            f"{artifact_hash}. Use artifact_get with this hash to retrieve "
            f"the file whole."
        )
        await self.memory_add(
            text=memory_text,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

        return {"artifact_hash": artifact_hash, "filename": filename}

    async def get_artifact_by_memory_name(
        self,
        memory_name: str,
        *,
        agent_id: str = "meko_agent",
        conversation_id: Optional[str] = None,
    ) -> Any:
        """Retrieve an artifact by looking up its hash from a named memory.

        Enables cross-agent sharing: Agent A saves an artifact's hash as a
        memory named "Q3 sales report"; Agent B looks it up and retrieves
        the file using artifact_get.
        """
        if conversation_id is None:
            conversation_id = await self.create_conversation(
                agent_id,
                f"Artifact get by memory: {memory_name}",
                {"kind": "artifact_get_by_memory", "memory_name": memory_name},
            )

        # Search memory for the named artifact hash
        search_results = await self.memory_search(
            query=memory_name,
            limit=5,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

        artifact_hash = None
        if isinstance(search_results, dict):
            matches = search_results.get("matches", [])
            for match in matches:
                text = match.get("text", "")
                if f"Artifact hash for '{memory_name}'" in text or memory_name in text:
                    # Extract hash from memory text (last token)
                    parts = text.strip().split()
                    if parts:
                        artifact_hash = parts[-1]
                    break

        if not artifact_hash:
            raise MekoAdapterError(
                f"No artifact hash found in memory for '{memory_name}'"
            )

        return await self.artifact_get(
            artifact_hash=artifact_hash,
            agent_id=agent_id,
            conversation_id=conversation_id,
        )

    # --- Record decision (shadow / non-actionable in prototype) -------------
    async def record_decision(
        self,
        account_id: str,
        decision: str,
        trace: dict,
        agent_id: str = "decision_agent",
    ):
        conv_id = await self.create_conversation(
            agent_id,
            f"ATO decision {decision} / {account_id}",
            {
                "account_id": account_id,
                "decision": decision,
                "policy_version": trace.get("policy_version", "unknown"),
            },
        )
        await self.call(
            "conversation_add_message",
            conversation_id=conv_id,
            agent_id=agent_id,
            input=f"Evaluate account {account_id}",
            output=f"{decision}: {trace.get('summary', '')}",
            reasoning=trace.get("why_this_action", ""),
            plan=trace.get("steps", []),
            metadata=json.dumps(trace),
        )
        trace_json = json.dumps(trace, indent=2)
        content_b64 = base64.b64encode(trace_json.encode()).decode()
        artifact_result = await self.artifact_put(
            filename=f"trace_{account_id}_{int(time.time())}.json",
            content_base64=content_b64,
            content_type="application/json",
            agent_id=agent_id,
            conversation_id=conv_id,
        )
        artifact_hash = None
        if isinstance(artifact_result, dict):
            artifact_hash = artifact_result.get("hash") or artifact_result.get("artifact_hash")
        elif isinstance(artifact_result, str):
            try:
                parsed = json.loads(artifact_result)
                artifact_hash = parsed.get("hash") or parsed.get("artifact_hash")
            except json.JSONDecodeError:
                pass
        if artifact_hash:
            memory_text = (
                f"Decision trace artifact for account {account_id}: "
                f"{artifact_hash}. Use artifact_get to retrieve the trace file whole."
            )
            await self.memory_add(
                text=memory_text,
                agent_id=agent_id,
                conversation_id=conv_id,
            )
        return conv_id
