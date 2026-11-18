"""Scoped agent tasks and typed handoff results.

Narrowly scoped agents collect or assess evidence available to their task.
Each writes a typed result to the investigation record with conclusion,
confidence, reason codes, and evidence references.
"""
from __future__ import annotations

from .login_agent import LoginAgent
from .device_agent import DeviceAgent
from .reset_agent import ResetAgent
from .transaction_agent import TransactionAgent
from .support_agent import SupportAgent
from .correlator_agent import CorrelatorAgent

__all__ = [
    "LoginAgent",
    "DeviceAgent",
    "ResetAgent",
    "TransactionAgent",
    "SupportAgent",
    "CorrelatorAgent",
]
