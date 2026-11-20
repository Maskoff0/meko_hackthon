"""Authenticated role-based access control (plan.md Phase 4).

Implements least-privilege RBAC for analyst operations on the case queue,
containment decisions, and audit records. Every access decision is
audited with the analyst ID, role, permission, resource, and result.

Separation of duties:
- An analyst who approves a containment proposal cannot execute it.
- Fraud owners can execute; analysts/supervisors can only approve.
- Auditors can view but not modify.

function.md alignment:
- Guardrails: read-only by default, cited claims, logging with analyst ID
- Capability 6 (feedback capture): analyst actions are audited
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .audit import AuditLog
from .domain import (
    AccessControlEntry,
    AccessDecision,
    AccessRequest,
    Permission,
    Role,
    ROLE_PERMISSIONS,
)


class RBACManager:
    """Role-based access control manager.

    Evaluates access requests against role-permission mappings and
    enforces separation of duties. All decisions are audited.
    """

    def __init__(self, audit: AuditLog):
        self.audit = audit
        # Analyst ID -> Role mapping
        self._analyst_roles: dict[str, Role] = {}
        # Analyst ID -> set of additional granted permissions (beyond role)
        self._analyst_extra_permissions: dict[str, set[Permission]] = {}
        # Track who approved which proposal (for separation of duties)
        self._containment_approvals: dict[str, str] = {}  # proposal_key -> analyst_id

    # ------------------------------------------------------------------
    # Analyst registration
    # ------------------------------------------------------------------

    def assign_role(self, analyst_id: str, role: Role, assigned_by: str = "system") -> None:
        """Assign a role to an analyst."""
        self._analyst_roles[analyst_id] = role
        self.audit._write_entry(
            {
                "type": "rbac_role_assigned",
                "analyst_id": analyst_id,
                "role": role,
                "assigned_by": assigned_by,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def get_role(self, analyst_id: str) -> Optional[Role]:
        return self._analyst_roles.get(analyst_id)

    def grant_permission(
        self, analyst_id: str, permission: Permission, granted_by: str = "system"
    ) -> None:
        """Grant an additional permission to an analyst (beyond role)."""
        if analyst_id not in self._analyst_extra_permissions:
            self._analyst_extra_permissions[analyst_id] = set()
        self._analyst_extra_permissions[analyst_id].add(permission)
        self.audit._write_entry(
            {
                "type": "rbac_permission_granted",
                "analyst_id": analyst_id,
                "permission": permission,
                "granted_by": granted_by,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def revoke_permission(
        self, analyst_id: str, permission: Permission, revoked_by: str = "system"
    ) -> None:
        """Revoke an additional permission from an analyst."""
        if analyst_id in self._analyst_extra_permissions:
            self._analyst_extra_permissions[analyst_id].discard(permission)
        self.audit._write_entry(
            {
                "type": "rbac_permission_revoked",
                "analyst_id": analyst_id,
                "permission": permission,
                "revoked_by": revoked_by,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    # ------------------------------------------------------------------
    # Access evaluation
    # ------------------------------------------------------------------

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        """Evaluate an access request.

        Returns ALLOW if the analyst's role (plus extra permissions)
        includes the requested permission. Returns DENY otherwise.

        Separation of duties: an analyst who approved a containment
        proposal cannot execute it.
        """
        role = self._analyst_roles.get(request.analyst_id)
        if role is None:
            decision = AccessDecision.DENY
            reason = f"analyst {request.analyst_id} has no assigned role"
            self._audit_access(request, decision, reason)
            return decision

        role_perms = ROLE_PERMISSIONS.get(role, set())
        extra_perms = self._analyst_extra_permissions.get(request.analyst_id, set())
        all_perms = role_perms | extra_perms

        # Separation of duties: execution requires separate approval
        if (
            request.permission == Permission.EXECUTE_CONTAINMENT
            and request.resource in self._containment_approvals
            and self._containment_approvals[request.resource] == request.analyst_id
        ):
            decision = AccessDecision.DENY
            reason = (
                f"separation of duties: analyst {request.analyst_id} approved "
                f"this proposal and cannot execute it"
            )
            self._audit_access(request, decision, reason)
            return decision

        if request.permission in all_perms:
            decision = AccessDecision.ALLOW
            reason = f"role {role} has permission {request.permission}"
        else:
            decision = AccessDecision.DENY
            reason = (
                f"role {role} does not have permission {request.permission}; "
                f"available: {sorted(p.value for p in all_perms)}"
            )

        self._audit_access(request, decision, reason)
        return decision

    def check(
        self,
        analyst_id: str,
        permission: Permission,
        resource: str = "queue",
        role: Optional[Role] = None,
    ) -> AccessDecision:
        """Convenience: evaluate access for an analyst."""
        if role is None:
            role = self._analyst_roles.get(analyst_id)
            if role is None:
                request = AccessRequest(
                    analyst_id=analyst_id,
                    role=Role.ANALYST,  # placeholder; will be DENY
                    permission=permission,
                    resource=resource,
                )
                return self.evaluate(request)
        request = AccessRequest(
            analyst_id=analyst_id,
            role=role,
            permission=permission,
            resource=resource,
        )
        return self.evaluate(request)

    def require(
        self,
        analyst_id: str,
        permission: Permission,
        resource: str = "queue",
        role: Optional[Role] = None,
    ) -> None:
        """Require access; raise PermissionError if denied."""
        decision = self.check(analyst_id, permission, resource, role)
        if decision == AccessDecision.DENY:
            raise PermissionError(
                f"Access denied: analyst {analyst_id} lacks permission "
                f"{permission} on {resource}"
            )

    # ------------------------------------------------------------------
    # Containment separation of duties
    # ------------------------------------------------------------------

    def record_containment_approval(self, proposal_key: str, analyst_id: str) -> None:
        """Record that an analyst approved a containment proposal."""
        self._containment_approvals[proposal_key] = analyst_id
        self.audit._write_entry(
            {
                "type": "rbac_containment_approval_recorded",
                "proposal_key": proposal_key,
                "analyst_id": analyst_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def clear_containment_approval(self, proposal_key: str) -> None:
        """Clear a containment approval record (after execution or rejection)."""
        self._containment_approvals.pop(proposal_key, None)

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _audit_access(
        self,
        request: AccessRequest,
        decision: AccessDecision,
        reason: str,
    ) -> None:
        entry = AccessControlEntry(
            analyst_id=request.analyst_id,
            role=request.role,
            permission=request.permission,
            resource=request.resource,
            decision=decision,
            reason=reason,
        )
        self.audit._write_entry(
            {
                "type": "access_control",
                "entry_id": entry.entry_id,
                "analyst_id": entry.analyst_id,
                "role": entry.role,
                "permission": entry.permission,
                "resource": entry.resource,
                "decision": entry.decision,
                "reason": entry.reason,
            }
        )

    def get_access_audit(self, limit: int = 100) -> list[dict]:
        """Return recent access control audit entries."""
        return self.audit.get_audit_entries(entry_type="access_control", limit=limit)
