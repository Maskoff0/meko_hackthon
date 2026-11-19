"""Unit tests for Phase 2: metrics computation."""
from __future__ import annotations

from fraud_detection.metrics import (
    MetricsEngine,
    wilson_score_interval,
    DetectionMetrics,
    CostMetrics,
    LatencyMetrics,
    CohortMetrics,
    BaselineLift,
)


def test_wilson_score_interval_zero_trials():
    lower, upper = wilson_score_interval(0, 0)
    assert lower == 0.0
    assert upper == 0.0


def test_wilson_score_interval_perfect():
    lower, upper = wilson_score_interval(10, 10)
    assert lower > 0.5
    assert upper == 1.0


def test_wilson_score_interval_zero_success():
    lower, upper = wilson_score_interval(0, 100)
    assert lower == 0.0
    assert upper < 0.1


def test_detection_metrics_perfect():
    engine = MetricsEngine()
    m = engine.compute_detection_metrics(
        true_positives=50,
        false_positives=0,
        false_negatives=0,
        true_negatives=950,
        total_alerts=50,
    )
    assert m.precision.point_estimate == 1.0
    assert m.recall.point_estimate == 1.0
    assert m.fpr.point_estimate == 0.0
    assert m.fnr.point_estimate == 0.0
    assert m.alert_volume == 50


def test_detection_metrics_with_errors():
    engine = MetricsEngine()
    m = engine.compute_detection_metrics(
        true_positives=80,
        false_positives=10,
        false_negatives=10,
        true_negatives=900,
        total_alerts=90,
    )
    assert m.precision.point_estimate == 80 / 90
    assert m.recall.point_estimate == 80 / 90
    assert 0.0 < m.fpr.point_estimate < 0.05
    assert m.false_positive_count == 10
    assert m.missed_fraud_count == 10


def test_cost_metrics():
    engine = MetricsEngine()
    c = engine.compute_cost_metrics(
        false_positives=5,
        false_negatives=2,
        fp_cost_per_event=10.0,
        fn_cost_per_event=100.0,
        total_events=1000,
    )
    assert c.false_positive_cost == 50.0
    assert c.missed_fraud_cost == 200.0
    assert c.total_cost == 250.0
    assert c.cost_per_event == 0.25


def test_latency_metrics():
    engine = MetricsEngine()
    latencies = [0.1, 0.2, 0.3, 0.5, 0.8, 1.0, 1.5, 2.0, 3.0, 5.0]
    lead_times = [2.0, 5.0, 8.0, 10.0, 15.0]
    lm = engine.compute_latency_metrics(latencies, lead_times, events_without_timestamp=1)
    assert lm.p50_decision_latency_seconds > 0
    assert lm.p95_decision_latency_seconds >= lm.p50_decision_latency_seconds
    assert lm.p99_decision_latency_seconds >= lm.p95_decision_latency_seconds
    assert lm.median_lead_time_minutes == 8.0
    assert lm.events_without_timestamp == 1


def test_cohort_metrics():
    engine = MetricsEngine()
    c = engine.compute_cohort_metrics(
        cohort_name="high_value",
        total_events=1000,
        alert_count=50,
        false_positive_count=5,
        true_positive_count=40,
    )
    assert c.cohort_name == "high_value"
    assert c.alert_rate == 0.05
    assert c.false_positive_rate == 0.005
    assert c.detection_rate == 0.04


def test_baseline_lift():
    engine = MetricsEngine()
    lift = engine.compute_baseline_lift(
        baseline_alert_rate=0.05,
        agentic_alert_rate=0.08,
        baseline_precision=0.6,
        agentic_precision=0.75,
        baseline_recall=0.5,
        agentic_recall=0.65,
    )
    assert abs(lift.lift - 0.6) < 1e-10
    assert abs(lift.precision_improvement - 0.15) < 1e-10
    assert abs(lift.recall_improvement - 0.15) < 1e-10


def test_phase2_gates_pass():
    engine = MetricsEngine()
    dm = engine.compute_detection_metrics(
        true_positives=200,
        false_positives=1,
        false_negatives=0,
        true_negatives=200000,
        total_alerts=201,
    )
    lm = engine.compute_latency_metrics([0.1, 0.2, 0.5], [10.0, 15.0, 20.0])

    result = engine.evaluate_phase2_gates(dm, lm, min_legitimate=1000, min_fraud=100)
    assert result["all_gates_pass"] is True
    assert result["gates"]["high_risk_false_positive_rate"]["pass"] is True
    assert result["gates"]["synchronous_decision_latency"]["pass"] is True


def test_phase2_gates_fail_fpr():
    engine = MetricsEngine()
    dm = engine.compute_detection_metrics(
        true_positives=50,
        false_positives=2000,
        false_negatives=0,
        true_negatives=100000,
        total_alerts=2050,
    )
    lm = engine.compute_latency_metrics([0.1], [10.0])

    result = engine.evaluate_phase2_gates(dm, lm, min_legitimate=1000, min_fraud=100)
    assert result["all_gates_pass"] is False
    assert result["gates"]["high_risk_false_positive_rate"]["pass"] is False
