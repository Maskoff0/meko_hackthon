"""
Meko tool wrappers over the MCP session.

Exposes the Meko MCP tools as methods on the `Meko` class:
conversation_create, memory_add, context_search, conversation_add_message,
artifact_put. Keeps the transport/authentication out of this module so
main.py owns the MCP client lifecycle.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from mcp import ClientSession
from mcp.types import TextContent


class Meko:
    """Thin wrapper around the Meko MCP server tools."""

    def __init__(self, session: ClientSession, datapack_id: str):
        self.s = session
        self.datapack_id = datapack_id

    async def call(self, tool: str, **args: Any) -> Any:
        args.setdefault("datapack_id", self.datapack_id)
        # Don't send `scope`: retired in Meko v2.1.0.
        res = await self.s.call_tool(tool, args)
        text = "".join(c.text for c in res.content if isinstance(c, TextContent))
        if res.isError:
            raise RuntimeError(
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
            raise RuntimeError("Meko conversation_create returned no conversation ID.")
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
        # Distinct agent_id per detection agent; one API key + datapack means
        # all of them read the same store. Searchable text first, JSON after.
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
        # One call searches memory + knowledge base + past conversations.
        # Results come back in separate buckets, plus match_quality/agent_hint.
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
        # Confirmed patterns live in the knowledge base; limit search to it.
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
                "policy_version": trace["policy_version"],
            },
        )
        await self.call(
            "conversation_add_message",
            conversation_id=conv_id,
            agent_id=agent_id,
            input=f"Evaluate account {account_id}",
            output=f"{decision}: {trace['summary']}",
            reasoning=trace["why_this_action"],
            plan=trace["steps"],
            metadata=json.dumps(trace),
        )
        # Keep the full trace as an immutable, content-addressed file for audit.
        await self.call(
            "artifact_put",
            filename=f"trace_{account_id}_{int(time.time())}.json",
            content_base64=base64.b64encode(json.dumps(trace, indent=2).encode()).decode(),
            content_type="application/json",
            conversation_id=conv_id,
            agent_id=agent_id,
        )
        return conv_id
