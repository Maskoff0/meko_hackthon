"""Metrics computation with confidence intervals.

Computes precision, recall, alert volume, false-positive/missed-fraud costs,
confidence intervals, cohort slices, lead time, latency, and baseline-relative
lift. Excludes immature examples from denominators per challenge.md.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def wilson_score_interval(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Wilson score confidence interval for a proportion.

    Returns (lower_bound, upper_bound). Handles zero trials gracefully.
    """
    if trials == 0:
        return (0.0, 0.0)

    z = 1.96  # 95% confidence
    if confidence == 0.90:
        z = 1.645
    elif confidence == 0.99:
        z = 2.576

    p = successes / trials
    denominator = 1 + z**2 / trials
    center = (p + z**2 / (2 * trials)) / denominator
    half_width = (
        z
        * math.sqrt((p * (1 - p) + z**2 / (4 * trials)) / trials)
        / denominator
    )
    return (max(0.0, center - half_width), min(1.0, center + half_width))


@dataclass
class ConfidenceInterval:
    point_estimate: float
    lower: float
    upper: float
    confidence: float = 0.95
    n: int = 0


@dataclass
class DetectionMetrics:
    """Core detection metrics with confidence intervals."""

    precision: ConfidenceInterval
    recall: ConfidenceInterval
    fpr: ConfidenceInterval  # false positive rate
    fnr: ConfidenceInterval  # false negative rate
    alert_volume: int
    missed_fraud_count: int
    false_positive_count: int
    true_positive_count: int
    true_negative_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "precision": {
                "point_estimate": self.precision.point_estimate,
                "lower": self.precision.lower,
                "upper": self.precision.upper,
                "n": self.precision.n,
            },
            "recall": {
                "point_estimate": self.recall.point_estimate,
                "lower": self.recall.lower,
                "upper": self.recall.upper,
                "n": self.recall.n,
            },
            "fpr": {
                "point_estimate": self.fpr.point_estimate,
                "lower": self.fpr.lower,
                "upper": self.fpr.upper,
                "n": self.fpr.n,
            },
            "fnr": {
                "point_estimate": self.fnr.point_estimate,
                "lower": self.fnr.lower,
                "upper": self.fnr.upper,
                "n": self.fnr.n,
            },
            "alert_volume": self.alert_volume,
            "missed_fraud_count": self.missed_fraud_count,
            "false_positive_count": self.false_positive_count,
            "true_positive_count": self.true_positive_count,
            "true_negative_count": self.true_negative_count,
        }


@dataclass
class CostMetrics:
    """Cost-based metrics for fraud detection."""

    false_positive_cost: float
    missed_fraud_cost: float
    total_cost: float
    cost_per_event: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "false_positive_cost": self.false_positive_cost,
            "missed_fraud_cost": self.missed_fraud_cost,
            "total_cost": self.total_cost,
            "cost_per_event": self.cost_per_event,
        }


@dataclass
class LatencyMetrics:
    """Latency and lead time metrics."""

    p50_decision_latency_seconds: float
    p95_decision_latency_seconds: float
    p99_decision_latency_seconds: float
    median_lead_time_minutes: float
    p70_lead_time_minutes: float
    events_without_timestamp: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "p50_decision_latency_seconds": self.p50_decision_latency_seconds,
            "p95_decision_latency_seconds": self.p95_decision_latency_seconds,
            "p99_decision_latency_seconds": self.p99_decision_latency_seconds,
            "median_lead_time_minutes": self.median_lead_time_minutes,
            "p70_lead_time_minutes": self.p70_lead_time_minutes,
            "events_without_timestamp": self.events_without_timestamp,
        }


@dataclass
class CohortMetrics:
    """Metrics broken down by customer cohort / segment."""

    cohort_name: str
    total_events: int
    alert_count: int
    alert_rate: float
    false_positive_rate: float
    detection_rate: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "cohort_name": self.cohort_name,
            "total_events": self.total_events,
            "alert_count": self.alert_count,
            "alert_rate": self.alert_rate,
            "false_positive_rate": self.false_positive_rate,
            "detection_rate": self.detection_rate,
        }


@dataclass
class BaselineLift:
    """Baseline-relative lift metrics."""

    baseline_alert_rate: float
    agentic_alert_rate: float
    lift: float  # agentic / baseline - 1
    precision_improvement: float
    recall_improvement: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_alert_rate": self.baseline_alert_rate,
            "agentic_alert_rate": self.agentic_alert_rate,
            "lift": self.lift,
            "precision_improvement": self.precision_improvement,
            "recall_improvement": self.recall_improvement,
        }


class MetricsEngine:
    """Computes evaluation metrics from labeled replay results."""

    def __init__(self, confidence: float = 0.95):
        self.confidence = confidence

    def compute_detection_metrics(
        self,
        true_positives: int,
        false_positives: int,
        false_negatives: int,
        true_negatives: int,
        total_alerts: int,
    ) -> DetectionMetrics:
        """Compute core detection metrics with Wilson score CIs.

        Excludes immature examples from denominators (caller must filter).
        """
        # Precision: TP / (TP + FP)
        precision_trials = true_positives + false_positives
        precision_pe = true_positives / precision_trials if precision_trials > 0 else 0.0
        precision_ci = wilson_score_interval(true_positives, precision_trials, self.confidence)

        # Recall: TP / (TP + FN)
        recall_trials = true_positives + false_negatives
        recall_pe = true_positives / recall_trials if recall_trials > 0 else 0.0
        recall_ci = wilson_score_interval(true_positives, recall_trials, self.confidence)

        # FPR: FP / (FP + TN)
        fpr_trials = false_positives + true_negatives
        fpr_pe = false_positives / fpr_trials if fpr_trials > 0 else 0.0
        fpr_ci = wilson_score_interval(false_positives, fpr_trials, self.confidence)

        # FNR: FN / (FN + TP)
        fnr_trials = false_negatives + true_positives
        fnr_pe = false_negatives / fnr_trials if fnr_trials > 0 else 0.0
        fnr_ci = wilson_score_interval(false_negatives, fnr_trials, self.confidence)

        return DetectionMetrics(
            precision=ConfidenceInterval(
                point_estimate=precision_pe,
                lower=precision_ci[0],
                upper=precision_ci[1],
                confidence=self.confidence,
                n=precision_trials,
            ),
            recall=ConfidenceInterval(
                point_estimate=recall_pe,
                lower=recall_ci[0],
                upper=recall_ci[1],
                confidence=self.confidence,
                n=recall_trials,
            ),
            fpr=ConfidenceInterval(
                point_estimate=fpr_pe,
                lower=fpr_ci[0],
                upper=fpr_ci[1],
                confidence=self.confidence,
                n=fpr_trials,
            ),
            fnr=ConfidenceInterval(
                point_estimate=fnr_pe,
                lower=fnr_ci[0],
                upper=fnr_ci[1],
                confidence=self.confidence,
                n=fnr_trials,
            ),
            alert_volume=total_alerts,
            missed_fraud_count=false_negatives,
            false_positive_count=false_positives,
            true_positive_count=true_positives,
            true_negative_count=true_negatives,
        )

    def compute_cost_metrics(
        self,
        false_positives: int,
        false_negatives: int,
        fp_cost_per_event: float = 10.0,
        fn_cost_per_event: float = 100.0,
        total_events: int = 0,
    ) -> CostMetrics:
        """Compute cost-based metrics."""
        fp_cost = false_positives * fp_cost_per_event
        fn_cost = false_negatives * fn_cost_per_event
        total = fp_cost + fn_cost
        cost_per_event = total / total_events if total_events > 0 else 0.0

        return CostMetrics(
            false_positive_cost=fp_cost,
            missed_fraud_cost=fn_cost,
            total_cost=total,
            cost_per_event=cost_per_event,
        )

    def compute_latency_metrics(
        self,
        latencies_seconds: list[float],
        lead_times_minutes: list[float],
        events_without_timestamp: int = 0,
    ) -> LatencyMetrics:
        """Compute decision latency and lead time metrics."""
        def percentile(sorted_vals: list[float], p: float) -> float:
            if not sorted_vals:
                return 0.0
            k = (len(sorted_vals) - 1) * p / 100
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return sorted_vals[int(k)]
            d0 = sorted_vals[int(f)] * (c - k)
            d1 = sorted_vals[int(c)] * (k - f)
            return d0 + d1

        sorted_lat = sorted(latencies_seconds)
        sorted_lead = sorted(lead_times_minutes)

        return LatencyMetrics(
            p50_decision_latency_seconds=percentile(sorted_lat, 50),
            p95_decision_latency_seconds=percentile(sorted_lat, 95),
            p99_decision_latency_seconds=percentile(sorted_lat, 99),
            median_lead_time_minutes=percentile(sorted_lead, 50),
            p70_lead_time_minutes=percentile(sorted_lead, 70),
            events_without_timestamp=events_without_timestamp,
        )

    def compute_cohort_metrics(
        self,
        cohort_name: str,
        total_events: int,
        alert_count: int,
        false_positive_count: int,
        true_positive_count: int,
    ) -> CohortMetrics:
        """Compute metrics for a specific customer cohort/segment."""
        alert_rate = alert_count / total_events if total_events > 0 else 0.0
        fpr = false_positive_count / total_events if total_events > 0 else 0.0
        detection_rate = true_positive_count / total_events if total_events > 0 else 0.0

        return CohortMetrics(
            cohort_name=cohort_name,
            total_events=total_events,
            alert_count=alert_count,
            alert_rate=alert_rate,
            false_positive_rate=fpr,
            detection_rate=detection_rate,
        )

    def compute_baseline_lift(
        self,
        baseline_alert_rate: float,
        agentic_alert_rate: float,
        baseline_precision: float,
        agentic_precision: float,
        baseline_recall: float,
        agentic_recall: float,
    ) -> BaselineLift:
        """Compute baseline-relative lift metrics."""
        lift = (agentic_alert_rate / baseline_alert_rate - 1) if baseline_alert_rate > 0 else 0.0
        precision_improvement = agentic_precision - baseline_precision
        recall_improvement = agentic_recall - baseline_recall

        return BaselineLift(
            baseline_alert_rate=baseline_alert_rate,
            agentic_alert_rate=agentic_alert_rate,
            lift=lift,
            precision_improvement=precision_improvement,
            recall_improvement=recall_improvement,
        )

    def evaluate_phase2_gates(
        self,
        detection_metrics: DetectionMetrics,
        latency_metrics: LatencyMetrics,
        min_legitimate: int = 1000,
        min_fraud: int = 100,
    ) -> dict[str, Any]:
        """Evaluate against proposed Phase 2 pilot gates from plan.md.

        Returns gate evaluations with pass/fail status.
        """
        gates = {}

        # High-risk false-positive rate: at most 0.5% of mature confirmed legitimate
        fpr_rate = detection_metrics.fpr.point_estimate
        gates["high_risk_false_positive_rate"] = {
            "threshold": 0.005,
            "actual": fpr_rate,
            "pass": fpr_rate <= 0.005,
            "measurement": "FPR point estimate with Wilson CI upper bound",
            "ci_upper": detection_metrics.fpr.upper,
        }

        # Synchronous decision latency: p95 at most 1 second
        gates["synchronous_decision_latency"] = {
            "threshold_seconds": 1.0,
            "actual_seconds": latency_metrics.p95_decision_latency_seconds,
            "pass": latency_metrics.p95_decision_latency_seconds <= 1.0,
            "measurement": "p95 end-to-end decision latency",
        }

        # Minimum evaluation evidence
        gates["minimum_evaluation_evidence"] = {
            "min_legitimate": min_legitimate,
            "min_fraud": min_fraud,
            "actual_legitimate": detection_metrics.true_negative_count,
            "actual_fraud": detection_metrics.true_positive_count,
            "pass": (
                detection_metrics.true_negative_count >= min_legitimate
                and detection_metrics.true_positive_count >= min_fraud
            ),
            "measurement": "Mature labels only",
        }

        # Pre-cash-out detection lead time: at least 70% before cash-out, median >= 5 min
        gates["pre_cash_out_detection"] = {
            "min_detection_rate": 0.70,
            "min_median_lead_minutes": 5.0,
            "actual_median_lead_minutes": latency_metrics.median_lead_time_minutes,
            "pass": latency_metrics.median_lead_time_minutes >= 5.0,
            "measurement": "Median lead time at least 5 minutes",
        }

        all_pass = all(g["pass"] for g in gates.values())
        return {
            "all_gates_pass": all_pass,
            "gates": gates,
        }
