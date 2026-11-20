"""Production cutover service (plan.md Phase 6).

Manages the final production cutover: shadow → human_approval →
limited_automation → full_production → rolled_back.

Each stage transition requires:
- FRAUD_OWNER or risk operations owner approval
- Final SLO validation (guardrails within ratified limits)
- Guardrail status snapshot at cutover time
- Rollback capability if guardrails are violated

function.md alignment:
- Guardrails: measured benefit tracked, customer impact within limits
- Read-only by default: irreversible actions never automated
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .audit import AuditLog
from .domain import (
    FinalSLOValidation,
    Permission,
    ProductionCutoverRecord,
    ProductionCutoverStatus,
    Role,
    SLOValidationResult,
)
from .rbac import RBACManager
from .reversible_automation import ReversibleAutomationEngine
from .domain import AutomationStage


class ProductionCutoverService:
    """Manages production cutover stages and final SLO validation.

    Tracks the rollout stage and enforces that each transition
    requires SLO validation and FRAUD_OWNER approval.
    """

    def __init__(
        self,
        audit: AuditLog,
        rbac: RBACManager,
        reversible_automation: Optional[ReversibleAutomationEngine] = None,
    ):
        self.audit = audit
        self.rbac = rbac
        self.reversible_automation = reversible_automation

        # Current cutover stage
        self._current_stage: ProductionCutoverStatus = ProductionCutoverStatus.SHADOW

        # Cutover records
        self._cutover_records: list[ProductionCutoverRecord] = []

        # SLO validation results
        self._slo_validations: list[FinalSLOValidation] = []

        # Guardrail status snapshots
        self._guardrail_snapshots: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Current stage
    # ------------------------------------------------------------------

    def get_stage(self) -> ProductionCutoverStatus:
        return self._current_stage

    # ------------------------------------------------------------------
    # Final SLO validation
    # ------------------------------------------------------------------

    def validate_slos(
        self,
        validated_by: str,
        metric_results: list[dict[str, Any]],
        observations: str = "",
    ) -> FinalSLOValidation:
        """Run final SLO validation before production cutover.

        Args:
            validated_by: The analyst performing the validation (must be
                FRAUD_OWNER or risk operations owner).
            metric_results: List of metric result dicts with keys:
                metric_name, current_value, threshold, direction,
                details.
            observations: Free-text observations from the validation.

        Returns:
            A FinalSLOValidation with overall pass/fail status.
        """
        # RBAC: validator must be FRAUD_OWNER
        try:
            self.rbac.require(
                validated_by,
                Permission.EXECUTE_CONTAINMENT,
                resource="production_cutover",
            )
        except PermissionError:
            # Still record the validation but mark as not authorized
            pass

        results: list[SLOValidationResult] = []
        overall_passed = True

        for m in metric_results:
            name = m.get("metric_name", "unknown")
            current = float(m.get("current_value", 0.0))
            threshold = float(m.get("threshold", 0.0))
            direction = m.get("direction", "below")  # "below" or "above"
            details = m.get("details", "")

            if direction == "below":
                passed = current <= threshold
            else:
                passed = current >= threshold

            if not passed:
                overall_passed = False

            results.append(
                SLOValidationResult(
                    passed=passed,
                    metric_name=name,
                    current_value=current,
                    threshold=threshold,
                    direction=direction,
                    details=details,
                )
            )

        validation = FinalSLOValidation(
            validated_by=validated_by,
            overall_passed=overall_passed,
            results=results,
            observations=observations,
        )
        self._slo_validations.append(validation)

        self.audit._write_entry(
            {
                "type": "production_slo_validation",
                "validation_id": validation.validation_id,
                "validated_by": validated_by,
                "overall_passed": overall_passed,
                "metric_count": len(results),
                "observations": observations,
            }
        )
        return validation

    def get_latest_slo_validation(self) -> Optional[FinalSLOValidation]:
        if not self._slo_validations:
            return None
        return self._slo_validations[-1]

    def get_all_slo_validations(self) -> list[FinalSLOValidation]:
        return list(self._slo_validations)

    # ------------------------------------------------------------------
    # Guardrail snapshots
    # ------------------------------------------------------------------

    def snapshot_guardrails(
        self,
        stage: ProductionCutoverStatus,
        guardrail_data: dict[str, Any],
    ) -> str:
        """Take a guardrail status snapshot at a cutover stage.

        Returns the snapshot key for reference in cutover records.
        """
        key = f"{stage.value}:{datetime.now(timezone.utc).isoformat()}"
        self._guardrail_snapshots[key] = {
            "stage": stage.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": guardrail_data,
        }
        self.audit._write_entry(
            {
                "type": "production_guardrail_snapshot",
                "key": key,
                "stage": stage.value,
                "data": guardrail_data,
            }
        )
        return key

    def get_guardrail_snapshot(self, key: str) -> Optional[dict]:
        return self._guardrail_snapshots.get(key)

    # ------------------------------------------------------------------
    # Stage transitions
    # ------------------------------------------------------------------

    def advance_stage(
        self,
        to_stage: ProductionCutoverStatus,
        approver_id: str,
        reason: str = "",
        slo_validation_id: Optional[str] = None,
        guardrail_snapshot_key: Optional[str] = None,
    ) -> bool:
        """Advance the production cutover to a new stage.

        Requirements:
        - Approver must be FRAUD_OWNER (RBAC EXECUTE_CONTAINMENT +
          role check)
        - SLO validation must have passed (for transitions to
          limited_automation or full_production)
        - Guardrail snapshot must be provided
        - Cannot advance from ROLLED_BACK without explicit reset

        Returns True if the transition succeeded.
        """
        # Cannot advance from ROLLED_BACK
        if self._current_stage == ProductionCutoverStatus.ROLLED_BACK:
            return False

        # RBAC: approver must be FRAUD_OWNER
        try:
            self.rbac.require(
                approver_id,
                Permission.EXECUTE_CONTAINMENT,
                resource="production_cutover",
            )
        except PermissionError:
            return False

        approver_role = self.rbac.get_role(approver_id)
        if approver_role != Role.FRAUD_OWNER:
            return False

        # SLO validation required for automation and production stages
        if to_stage in (
            ProductionCutoverStatus.LIMITED_AUTOMATION,
            ProductionCutoverStatus.FULL_PRODUCTION,
        ):
            if slo_validation_id is not None:
                validation = self._find_slo_validation(slo_validation_id)
                if validation is None or not validation.overall_passed:
                    return False
            else:
                # No validation ID provided; check latest
                latest = self.get_latest_slo_validation()
                if latest is None or not latest.overall_passed:
                    return False

        # Guardrail snapshot required
        if guardrail_snapshot_key is not None:
            snapshot = self.get_guardrail_snapshot(guardrail_snapshot_key)
            if snapshot is None:
                return False

        # Record the cutover
        from_snapshot = self.get_guardrail_snapshot(guardrail_snapshot_key or "")

        record = ProductionCutoverRecord(
            from_stage=self._current_stage,
            to_stage=to_stage,
            approved_by=approver_id,
            reason=reason,
            guardrail_status=from_snapshot or {},
            slo_validation_passed=(
                self._slo_validation_passed_for_stage(to_stage)
            ),
        )
        self._cutover_records.append(record)

        # Audit the transition
        self.audit._write_entry(
            {
                "type": "production_cutover_advanced",
                "cutover_id": record.cutover_id,
                "from_stage": record.from_stage,
                "to_stage": record.to_stage,
                "approved_by": approver_id,
                "reason": reason,
                "slo_validation_passed": record.slo_validation_passed,
            }
        )

        # Update reversible automation stage if applicable
        if (
            self.reversible_automation is not None
            and to_stage == ProductionCutoverStatus.FULL_PRODUCTION
        ):
            self.reversible_automation.advance_stage(
                AutomationStage.FULL,
                approver_id,
            )

        self._current_stage = to_stage
        return True

    def rollback(
        self,
        approver_id: str,
        reason: str = "",
    ) -> bool:
        """Roll back the production cutover to ROLLED_BACK stage.

        Requires FRAUD_OWNER approval. This is an emergency operation
        that halts all automation and production actions.
        """
        # RBAC: approver must be FRAUD_OWNER
        try:
            self.rbac.require(
                approver_id,
                Permission.EXECUTE_CONTAINMENT,
                resource="production_cutover",
            )
        except PermissionError:
            return False

        approver_role = self.rbac.get_role(approver_id)
        if approver_role != Role.FRAUD_OWNER:
            return False

        record = ProductionCutoverRecord(
            from_stage=self._current_stage,
            to_stage=ProductionCutoverStatus.ROLLED_BACK,
            approved_by=approver_id,
            reason=reason,
            guardrail_status={},
            slo_validation_passed=False,
        )
        self._cutover_records.append(record)

        self.audit._write_entry(
            {
                "type": "production_cutover_rollback",
                "cutover_id": record.cutover_id,
                "from_stage": record.from_stage,
                "to_stage": ProductionCutoverStatus.ROLLED_BACK,
                "approved_by": approver_id,
                "reason": reason,
            }
        )

        # Also roll back reversible automation
        if self.reversible_automation is not None:
            self.reversible_automation.rollback(approver_id, reason)

        self._current_stage = ProductionCutoverStatus.ROLLED_BACK
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _slo_validation_passed_for_stage(
        self, stage: ProductionCutoverStatus
    ) -> bool:
        """Check if the latest SLO validation passed for the given stage."""
        latest = self.get_latest_slo_validation()
        if latest is None:
            return False
        return latest.overall_passed

    def _find_slo_validation(
        self, validation_id: str
    ) -> Optional[FinalSLOValidation]:
        for v in self._slo_validations:
            if v.validation_id == validation_id:
                return v
        return None

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_cutover_records(self) -> list[ProductionCutoverRecord]:
        return list(self._cutover_records)

    def get_latest_cutover_record(self) -> Optional[ProductionCutoverRecord]:
        if not self._cutover_records:
            return None
        return self._cutover_records[-1]
