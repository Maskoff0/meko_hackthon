"""MCP schema contract tests (plan.md line 24).

Verify that the MCP server exposes the expected analyst copilot tools
with correct input/output schemas. These tests ensure the adapter's
tool schemas are stable and versioned, per plan.md's requirement that
"schema contract tests should be part of the adapter from the start."

Uses Python's inspect module on the underlying tool functions (accessible
via tool.fn) since the MCP Tool object wraps the original async function.
"""
from __future__ import annotations

import inspect

import pytest

from fraud_detection.mcp_server import server


# ---------------------------------------------------------------------------
# Tool registry contract
# ---------------------------------------------------------------------------


def test_mcp_server_has_all_analyst_tools():
    """The MCP server exposes all 12 analyst copilot tools."""
    tools = server._tool_manager.list_tools()
    tool_names = {t.name for t in tools}

    expected = {
        "generate_case_brief",
        "explain_trace",
        "explain_investigation",
        "lookup_patterns",
        "draft_case_note",
        "draft_customer_communication",
        "draft_regulator_explanation",
        "build_triage_queue",
        "capture_feedback",
        "edit_draft",
        "sign_draft",
        "get_draft_edit_rate",
    }

    assert expected == tool_names, (
        f"MCP tool set mismatch. Missing: {expected - tool_names}, "
        f"Extra: {tool_names - expected}"
    )


def test_mcp_server_tool_count():
    """Exactly 12 analyst copilot tools are registered."""
    tools = server._tool_manager.list_tools()
    assert len(tools) == 12


def _get_tool_fn(name: str):
    """Retrieve the underlying function of an MCP tool by name."""
    tools = server._tool_manager.list_tools()
    for t in tools:
        if t.name == name:
            return t.fn
    raise AssertionError(f"Tool '{name}' not found in MCP server")


def _tool_params(name: str) -> dict:
    """Get the parameters dict of an MCP tool's function signature."""
    fn = _get_tool_fn(name)
    sig = inspect.signature(fn)
    params = {}
    for pname, p in sig.parameters.items():
        if pname == "self":
            continue
        params[pname] = {
            "default": p.default if p.default is not inspect.Parameter.empty else None,
            "required": p.default is inspect.Parameter.empty,
            "annotation": p.annotation,
        }
    return params


# ---------------------------------------------------------------------------
# generate_case_brief contract (function.md Capability 1)
# ---------------------------------------------------------------------------


def test_generate_case_brief_required_params():
    """generate_case_brief requires account_id and investigation_id."""
    params = _tool_params("generate_case_brief")

    assert params["account_id"]["required"] is True
    assert params["investigation_id"]["required"] is True
    assert params["analyst_id"]["required"] is False
    assert params["findings_json"]["required"] is False
    assert params["recommendation_json"]["required"] is False
    assert params["prior_incidents_json"]["required"] is False


# ---------------------------------------------------------------------------
# explain_trace contract (function.md Capability 2)
# ---------------------------------------------------------------------------


def test_explain_trace_required_params():
    """explain_trace requires trace_id, account_id, event_type."""
    params = _tool_params("explain_trace")

    assert params["trace_id"]["required"] is True
    assert params["account_id"]["required"] is True
    assert params["event_type"]["required"] is True
    assert params["agent_finding"]["required"] is False
    assert params["agent_confidence"]["required"] is False
    assert params["baseline_triggered"]["required"] is False
    assert params["baseline_score"]["required"] is False
    assert params["recommendation"]["required"] is False
    assert params["reason_codes"]["required"] is False
    assert params["evidence_refs"]["required"] is False


# ---------------------------------------------------------------------------
# explain_investigation contract (function.md Capability 2)
# ---------------------------------------------------------------------------


def test_explain_investigation_required_params():
    """explain_investigation requires investigation_id and account_id."""
    params = _tool_params("explain_investigation")

    assert params["investigation_id"]["required"] is True
    assert params["account_id"]["required"] is True
    assert params["findings_json"]["required"] is False
    assert params["correlated_finding_json"]["required"] is False
    assert params["recommendation_json"]["required"] is False


# ---------------------------------------------------------------------------
# lookup_patterns contract (function.md Capability 3)
# ---------------------------------------------------------------------------


def test_lookup_patterns_required_params():
    """lookup_patterns requires description."""
    params = _tool_params("lookup_patterns")

    assert params["description"]["required"] is True
    assert params["account_id"]["required"] is False
    assert params["limit"]["required"] is False


# ---------------------------------------------------------------------------
# Draft tools contract (function.md Capability 4)
# ---------------------------------------------------------------------------


def test_draft_case_note_required_params():
    """draft_case_note requires account_id and investigation_id."""
    params = _tool_params("draft_case_note")

    assert params["account_id"]["required"] is True
    assert params["investigation_id"]["required"] is True
    assert params["analyst_id"]["required"] is False
    assert params["brief_json"]["required"] is False
    assert params["recommendation_json"]["required"] is False


def test_draft_customer_communication_required_params():
    """draft_customer_communication requires account_id and investigation_id."""
    params = _tool_params("draft_customer_communication")

    assert params["account_id"]["required"] is True
    assert params["investigation_id"]["required"] is True


def test_draft_regulator_explanation_required_params():
    """draft_regulator_explanation requires account_id and investigation_id."""
    params = _tool_params("draft_regulator_explanation")

    assert params["account_id"]["required"] is True
    assert params["investigation_id"]["required"] is True


# ---------------------------------------------------------------------------
# build_triage_queue contract (function.md Capability 5)
# ---------------------------------------------------------------------------


def test_build_triage_queue_required_params():
    """build_triage_queue requires investigations_json."""
    params = _tool_params("build_triage_queue")

    assert params["investigations_json"]["required"] is False
    assert params["findings_json"]["required"] is False
    assert params["recommendations_json"]["required"] is False


# ---------------------------------------------------------------------------
# capture_feedback contract (function.md Capability 6)
# ---------------------------------------------------------------------------


def test_capture_feedback_required_params():
    """capture_feedback requires account_id, investigation_id, analyst_id,
    original_recommendation, analyst_response."""
    params = _tool_params("capture_feedback")

    assert params["account_id"]["required"] is True
    assert params["investigation_id"]["required"] is True
    assert params["analyst_id"]["required"] is True
    assert params["original_recommendation"]["required"] is True
    assert params["analyst_response"]["required"] is False
    assert params["original_reason_codes"]["required"] is False


# ---------------------------------------------------------------------------
# edit_draft / sign_draft contract (function.md Capability 4)
# ---------------------------------------------------------------------------


def test_edit_draft_required_params():
    """edit_draft requires draft_id, new_content, analyst_id."""
    params = _tool_params("edit_draft")

    assert params["draft_id"]["required"] is True
    assert params["new_content"]["required"] is True
    assert params["analyst_id"]["required"] is True


def test_sign_draft_required_params():
    """sign_draft requires draft_id and analyst_id."""
    params = _tool_params("sign_draft")

    assert params["draft_id"]["required"] is True
    assert params["analyst_id"]["required"] is True


# ---------------------------------------------------------------------------
# get_draft_edit_rate contract (function.md Guardrails)
# ---------------------------------------------------------------------------


def test_get_draft_edit_rate_no_required_params():
    """get_draft_edit_rate has no required parameters."""
    params = _tool_params("get_draft_edit_rate")

    assert len(params) == 0
