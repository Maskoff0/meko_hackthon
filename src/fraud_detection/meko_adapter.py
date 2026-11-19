"""Meko MCP adapter.

Wraps the hosted Meko MCP endpoint behind an adapter/interface with contract
tests. Meko is enrichment only -- memory writes and context searches are real
hosted operations, but they never execute fraud containment. All retrieved
content and agent output are treated as untrusted evidence.
"""
from __future__ import annotations

import base64
import json
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from .settings import Settings


class MekoAdapterError(RuntimeError):
    """Raised when a Meko MCP operation fails."""


class MekoAdapter:
    """Thin adapter around the Meko MCP server tools."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        self._session: Optional[ClientSession] = None
        self._http_client: Optional[httpx.AsyncClient] = None

    @asynccontextmanager
    async def connect(self):
        """Establish an authenticated MCP client session to the hosted Meko endpoint."""
        headers = {"Authorization": f"Bearer {self.settings.meko_api_key}"}
        timeout = httpx.Timeout(30, read=self.settings.meko_timeout_seconds * 10)
        self._http_client = httpx.AsyncClient(headers=headers, timeout=timeout)
        try:
            async with streamable_http_client(
                self.settings.meko_mcp_url, http_client=self._http_client
            ) as (read, write):
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
        """Call a Meko MCP tool, returning parsed JSON or raw text."""
        session = await self._require_session()
        args.setdefault("datapack_id", self.settings.meko_datapack_id)
        res = await session.call_tool(tool, args)
        text = "".join(c.text for c in res.content if isinstance(c, TextContent))
        if res.is_error:
            raise MekoAdapterError(
                f"Meko MCP tool {tool!r} failed: {text or 'no error details'}"
            )
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

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
        return await self.call(
            "memory_add",
            text=text,
            agent_id=agent_id,
            conversation_id=conversation_id,
            run_id=account_id,
            metadata=json.dumps({"kind": "signal", "account_id": account_id}),
        )

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
        await self.call(
            "artifact_put",
            filename=f"trace_{account_id}_{int(time.time())}.json",
            content_base64=base64.b64encode(
                json.dumps(trace, indent=2).encode()
            ).decode(),
            content_type="application/json",
            conversation_id=conv_id,
            agent_id=agent_id,
        )
        return conv_id
