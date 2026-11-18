"""Containment gate: proposal is not authority.

A correlator may submit a structured containment proposal, but that proposal
is not authorization. In shadow mode it is logged only; no containment or
action credentials exist and no executable action path is provided. This
module enforces the boundary at the code level so it cannot be silently
bypassed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from .settings import Settings


class ContainmentDecision(str, Enum):
    PROPOSED = "proposed"
    DENIED_SHADOW_MODE = "denied_shadow_mode"
    DENIED_NO_CREDENTIALS = "denied_no_credentials"
    DENIED_NOT_ALLOWLISTED = "denied_not_allowlisted"


@dataclass
class ContainmentProposal:
    """A structured containment request submitted by the correlator.

    This is a request only. The ContainmentGate independently re-checks
    policy, permissions, allowlist, and shadow mode before anything can
    proceed. In Phase 1 (shadow mode), execution is always denied.
    """

    action_type: str
    target: str
    reason_codes: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    reversibility: str = "none"
    expiry_seconds: Optional[int] = None
    proposed_by: str = "correlator_agent"
    proposed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ContainmentResult:
    decision: ContainmentDecision
    proposal: ContainmentProposal
    reason: str
    executed: bool = False
    executed_at: Optional[datetime] = None
    actor: Optional[str] = None


class ContainmentGate:
    """Enforces the proposal ≠ authority boundary.

    Phase 1 invariant: shadow_mode=True and no action credentials are
    configured, so every proposal is denied with DENIED_SHADOW_MODE.
    To eliminate this constraint (move to Phase 4+), an operator must:
      1. Set shadow_mode=False in settings (explicit opt-out of shadow).
      2. Configure containment credentials (action provider identity/key).
      3. Define a fraud-owner-approved reversible action allowlist.
      4. Add human approval + re-check at execution time.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        # No action credentials are loaded in Phase 1. This is intentional:
        # without credentials, no execution path exists regardless of config.
        self._action_credentials: Optional[dict[str, Any]] = None
        self._action_allowlist: set[str] = set()

    def configure_action_credentials(
        self, credentials: dict[str, Any], allowlist: list[str]
    ) -> None:
        """Register containment/action credentials and an allowlist.

        Calling this is the mechanism to begin eliminating the
        "no executable action path" constraint. It must be paired with
        shadow_mode=False and human-approval logic before any proposal
        can execute.
        """
        self._action_credentials = credentials
        self._action_allowlist = set(allowlist)

    def evaluate(self, proposal: ContainmentProposal) -> ContainmentResult:
        """Evaluate a containment proposal.

        Returns a ContainmentResult. In Phase 1 (shadow mode, no
        credentials), execution is always denied.
        """
        # Shadow mode is the hard Phase 1 gate.
        if self.settings.shadow_mode:
            return ContainmentResult(
                decision=ContainmentDecision.DENIED_SHADOW_MODE,
                proposal=proposal,
                reason=(
                    "shadow_mode is enabled; containment proposals are logged "
                    "only and never executed"
                ),
            )

        # No credentials means no executable path exists.
        if self._action_credentials is None:
            return ContainmentResult(
                decision=ContainmentDecision.DENIED_NO_CREDENTIALS,
                proposal=proposal,
                reason=(
                    "no containment/action credentials configured; "
                    "no executable action path exists"
                ),
            )

        # Action must be on the fraud-owner-approved allowlist.
        if proposal.action_type not in self._action_allowlist:
            return ContainmentResult(
                decision=ContainmentDecision.DENIED_NOT_ALLOWLISTED,
                proposal=proposal,
                reason=(
                    f"action_type {proposal.action_type!r} is not on the "
                    "fraud-owner-approved allowlist"
                ),
            )

        # If all checks pass (post-Phase-1 only), execution would be
        # gated on human approval + re-check at execution time.
        return ContainmentResult(
            decision=ContainmentDecision.PROPOSED,
            proposal=proposal,
            reason="proposal passed all gates; awaiting human approval",
        )
