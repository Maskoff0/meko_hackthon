"""MCP server exposing analyst copilot capabilities (function.md).

Delivers case briefs, trace explanations, pattern lookups, drafts,
triage ordering, and feedback capture through the MCP protocol.

function.md: "The case brief with citations, delivered through the MCP server.
It gives the most time savings with the least risk, and it is easy to measure
against current average handling time."
"""
from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from .analyst import (
    CaseBriefService,
    CaseDraftService,
    FeedbackCaptureService,
    PatternLookupService,
    TraceExplanationService,
    TriageService,
)
from .audit import AuditLog
from .domain import (
    CaseBrief,
    CaseDraft,
    EvidenceFinding,
    ShadowRecommendation,
)
from .meko_adapter import MekoAdapter, MekoAdapterError
from .settings import Settings

server = FastMCP(
    name="meko-analyst-copilot",
    instructions="Analyst copilot for fraud detection investigations. "
    "Provides case briefs with citations, trace explanations, pattern lookup, "
    "drafting, triage ordering, and feedback capture.",
)

settings = Settings()
audit = AuditLog()
brief_service = CaseBriefService()
trace_service = TraceExplanationService()
pattern_service = PatternLookupService()
draft_service = CaseDraftService()
triage_service = TriageService()
feedback_service = FeedbackCaptureService()

# In-memory stores for the demo (Phase 1; durable storage in Phase 3)
_briefs: dict[str, CaseBrief] = {}
_drafts: dict[str, CaseDraft] = {}
_feedbacks: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Tool: generate_case_brief (function.md Capability 1 - build first)
# ---------------------------------------------------------------------------

@server.tool()
async def generate_case_brief(
    account_id: str,
    investigation_id: str,
    analyst_id: str | None = None,
    findings_json: str = "[]",
    recommendation_json: str = "{}",
    prior_incidents_json: str = "[]",
) -> str:
    """Generate a one-screen case brief from the decision log and Meko context.

    Every claim cites a source ID. If it can't be cited, it doesn't go
    in the brief. Delivered through the MCP server.
    """
    findings: list[EvidenceFinding] = []
    try:
        findings_data = json.loads(findings_json)
        for f in findings_data:
            findings.append(EvidenceFinding(**f))
    except (json.JSONDecodeError, TypeError, ValueError):
        findings = []

    recommendation = ShadowRecommendation(
        recommendation="review",
        reason_codes=[],
        policy_version="2026-11-v1",
        model_version="deterministic-baseline-v1",
    )
    try:
        rec_data = json.loads(recommendation_json)
        recommendation = ShadowRecommendation(**rec_data)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    prior_incidents: list[dict] = []
    try:
        prior_incidents = json.loads(prior_incidents_json)
    except (json.JSONDecodeError, TypeError):
        prior_incidents = []

    brief = brief_service.build_brief(
        account_id=account_id,
        investigation_id=investigation_id,
        findings=findings,
        recommendation=recommendation,
        prior_incidents=prior_incidents,
        analyst_id=analyst_id,
    )

    # Validate citations (function.md: no citation, no claim)
    missing = brief_service.validate_citations(brief)

    # Log with analyst ID (function.md guardrail: logging)
    audit.record_case_brief(brief)

    _briefs[brief.brief_id] = brief

    result = {
        "brief_id": brief.brief_id,
        "account_id": brief.account_id,
        "investigation_id": brief.investigation_id,
        "generated_at": brief.generated_at.isoformat(),
        "analyst_id": brief.analyst_id,
        "timeline": [
            {
                "timestamp": t.timestamp.isoformat(),
                "event_type": t.event_type,
                "source_system": t.source_system,
                "description": t.description,
                "event_id": t.event_id,
                "trace_id": t.trace_id,
            }
            for t in brief.timeline
        ],
        "signals": brief.signals,
        "prior_incidents": brief.prior_incidents,
        "unknowns": brief.unknowns,
        "citations": brief.citations,
        "citation_warnings": missing,
    }
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool: explain_trace (function.md Capability 2)
# ---------------------------------------------------------------------------

@server.tool()
async def explain_trace(
    trace_id: int,
    account_id: str,
    event_type: str,
    agent_finding: str = "",
    agent_confidence: float = 0.0,
    baseline_triggered: bool = False,
    baseline_score: float = 0.0,
    recommendation: str = "review",
    reason_codes: list[str] | None = None,
    evidence_refs: list[str] | None = None,
) -> str:
    """Translate an agent trace into plain language for an analyst.

    The raw trace stays the record of truth; this is a plain-language
    rendering for analyst consumption.
    """
    if reason_codes is None:
        reason_codes = []
    if evidence_refs is None:
        evidence_refs = []

    explanation = trace_service.explain_trace(
        trace_id=trace_id,
        account_id=account_id,
        event_type=event_type,
        agent_finding=agent_finding,
        agent_confidence=agent_confidence,
        baseline_triggered=baseline_triggered,
        baseline_score=baseline_score,
        recommendation=recommendation,
        reason_codes=reason_codes,
        evidence_refs=evidence_refs,
    )
    return explanation


# ---------------------------------------------------------------------------
# Tool: explain_investigation (function.md Capability 2)
# ---------------------------------------------------------------------------

@server.tool()
async def explain_investigation(
    investigation_id: str,
    account_id: str,
    findings_json: str = "[]",
    correlated_finding_json: str = "null",
    recommendation_json: str = "{}",
) -> str:
    """Explain an entire investigation in plain language.

    Translates the full trace into a narrative an analyst can read.
    """
    findings: list[EvidenceFinding] = []
    try:
        findings_data = json.loads(findings_json)
        for f in findings_data:
            findings.append(EvidenceFinding(**f))
    except (json.JSONDecodeError, TypeError, ValueError):
        findings = []

    correlated = None
    try:
        cf = json.loads(correlated_finding_json)
        if cf is not None:
            correlated = EvidenceFinding(**cf)
    except (json.JSONDecodeError, TypeError, ValueError):
        correlated = None

    rec = ShadowRecommendation(
        recommendation="review",
        reason_codes=[],
        policy_version="2026-11-v1",
        model_version="deterministic-baseline-v1",
    )
    try:
        rec_data = json.loads(recommendation_json)
        rec = ShadowRecommendation(**rec_data)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    return trace_service.explain_investigation(
        investigation_id=investigation_id,
        account_id=account_id,
        findings=findings,
        correlated_finding=correlated,
        recommendation=rec,
    )


# ---------------------------------------------------------------------------
# Tool: lookup_patterns (function.md Capability 3)
# ---------------------------------------------------------------------------

@server.tool()
async def lookup_patterns(
    description: str,
    account_id: str | None = None,
    limit: int = 10,
) -> str:
    """Run hybrid retrieval against the knowledge base and past confirmed cases.

    Creates a conversation and searches it without force_source so Meko
    searches memory, knowledge base, and conversations.
    """
    meko = MekoAdapter(settings)
    try:
        async with meko.connect() as session:
            pattern_service.meko = session

            conversation_id = await session.create_conversation(
                "analyst_pattern_lookup",
                "Pattern lookup",
                {"kind": "pattern_lookup"},
            )

            # Search everything (memory + KB + conversations)
            hybrid_result = await session.call(
                "context_search",
                query=description,
                conversation_id=conversation_id,
                limit=limit,
                agent_id="analyst_pattern_lookup",
            )

            # KB-only search for similar patterns
            kb_result = await session.call(
                "context_search",
                query=description,
                conversation_id=conversation_id,
                force_source="knowledge_base",
                limit=limit,
                agent_id="analyst_pattern_lookup",
            )

            # Extract similar patterns from KB results (results.knowledge_base is a list)
            kb_list = []
            if isinstance(kb_result, dict):
                kb_list = kb_result.get("results", {}).get("knowledge_base", [])
            if not isinstance(kb_list, list):
                kb_list = []

            similar = []
            for m in kb_list[:10]:
                if isinstance(m, dict):
                    similar.append({
                        "incident_id": m.get("id", "unknown"),
                        "description": m.get("memory", ""),
                        "similarity": m.get("score", "unknown"),
                        "outcome": m.get("metadata", {}).get("kind", "unknown"),
                    })

            # Extract distinguishing factors from hybrid memory results
            memory_list = []
            if isinstance(hybrid_result, dict):
                memory_list = hybrid_result.get("results", {}).get("memory", [])
            if not isinstance(memory_list, list):
                memory_list = []

            different = []
            for m in memory_list[:5]:
                if isinstance(m, dict):
                    different.append({
                        "factor": m.get("memory", "")[:200],
                        "match_quality": m.get("score", "unknown"),
                        "source": m.get("metadata", {}).get("agent_id", "hybrid_retrieval"),
                    })

            result = {
                "query": description,
                "similar": similar,
                "different": different,
                "source": "meko_hybrid_retrieval",
                "limit": limit,
            }
    except (MekoAdapterError, ExceptionGroup, OSError) as e:
        return json.dumps({
            "query": description,
            "similar": [],
            "different": [],
            "source": "knowledge_base_unavailable",
            "message": f"Meko pattern lookup unavailable: {e}",
            "limit": limit,
        }, indent=2)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool: query_knowledge (knowledge base search)
# ---------------------------------------------------------------------------

@server.tool()
async def query_knowledge(
    query: str,
    limit: int = 10,
) -> str:
    """Search the Meko knowledge base for fraud playbooks and risk rules.

    Creates a conversation and searches it without force_source so Meko
    searches memory, knowledge base, and conversations within that scope.
    """
    meko = MekoAdapter(settings)
    try:
        async with meko.connect() as session:
            conversation_id = await session.create_conversation(
                "analyst_knowledge_query",
                "Knowledge base search",
                {"kind": "knowledge_base_search"},
            )
            result = await session.call(
                "context_search",
                query=query,
                conversation_id=conversation_id,
                limit=limit,
                agent_id="analyst_knowledge_query",
            )
    except (MekoAdapterError, ExceptionGroup, OSError) as e:
        return json.dumps({
            "query": query,
            "matches": [],
            "source": "knowledge_base_unavailable",
            "message": f"Knowledge base search unavailable: {e}",
        }, indent=2)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool: get_artifact (artifact retrieval by hash)
# ---------------------------------------------------------------------------

@server.tool()
async def get_artifact(
    artifact_hash: str,
) -> str:
    """Retrieve an artifact from the Meko datapack by its content hash.

    Returns the file's contents. Files under 1 MB return contents directly;
    files 1 MB or more return a path to the file in object storage.
    Each retrieval resets the artifact's expiry clock.
    """
    meko = MekoAdapter(settings)
    try:
        async with meko.connect() as session:
            result = await session.artifact_get(
                artifact_hash=artifact_hash,
                agent_id="analyst_artifact_get",
            )
    except (MekoAdapterError, ExceptionGroup, OSError) as e:
        return json.dumps({
            "artifact_hash": artifact_hash,
            "source": "artifact_unavailable",
            "message": f"Artifact retrieval unavailable: {e}",
        }, indent=2)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool: draft_case_note (function.md Capability 4)
# ---------------------------------------------------------------------------

@server.tool()
async def draft_case_note(
    account_id: str,
    investigation_id: str,
    analyst_id: str | None = None,
    brief_json: str = "{}",
    recommendation_json: str = "{}",
) -> str:
    """Draft a case note from a case brief and recommendation.

    Stored as a draft; the analyst edits and signs. Drafts are never
    the official record.
    """
    brief = CaseBrief(account_id=account_id, investigation_id=investigation_id, analyst_id=analyst_id)
    try:
        brief = CaseBrief(**json.loads(brief_json))
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    rec = ShadowRecommendation(
        recommendation="review", reason_codes=[],
        policy_version="2026-11-v1", model_version="deterministic-baseline-v1",
    )
    try:
        rec = ShadowRecommendation(**json.loads(recommendation_json))
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    draft = draft_service.draft_case_note(
        account_id, investigation_id, brief, rec, analyst_id
    )
    audit.record_case_draft(draft, "created")
    _drafts[draft.draft_id] = draft

    return json.dumps({
        "draft_id": draft.draft_id,
        "draft_type": draft.draft_type,
        "status": draft.status,
        "content": draft.content,
        "citations": draft.citations,
        "edit_count": draft.edit_count,
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool: draft_customer_communication (function.md Capability 4)
# ---------------------------------------------------------------------------

@server.tool()
async def draft_customer_communication(
    account_id: str,
    investigation_id: str,
    analyst_id: str | None = None,
    brief_json: str = "{}",
    recommendation_json: str = "{}",
) -> str:
    """Draft a customer communication explaining the action taken."""
    brief = CaseBrief(account_id=account_id, investigation_id=investigation_id, analyst_id=analyst_id)
    try:
        brief = CaseBrief(**json.loads(brief_json))
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    rec = ShadowRecommendation(
        recommendation="review", reason_codes=[],
        policy_version="2026-11-v1", model_version="deterministic-baseline-v1",
    )
    try:
        rec = ShadowRecommendation(**json.loads(recommendation_json))
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    draft = draft_service.draft_customer_communication(
        account_id, investigation_id, brief, rec, analyst_id
    )
    audit.record_case_draft(draft, "created")
    _drafts[draft.draft_id] = draft

    return json.dumps({
        "draft_id": draft.draft_id,
        "draft_type": draft.draft_type,
        "status": draft.status,
        "content": draft.content,
        "citations": draft.citations,
        "edit_count": draft.edit_count,
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool: draft_regulator_explanation (function.md Capability 4)
# ---------------------------------------------------------------------------

@server.tool()
async def draft_regulator_explanation(
    account_id: str,
    investigation_id: str,
    analyst_id: str | None = None,
    brief_json: str = "{}",
    recommendation_json: str = "{}",
) -> str:
    """Draft a regulator-facing explanation of the decision."""
    brief = CaseBrief(account_id=account_id, investigation_id=investigation_id, analyst_id=analyst_id)
    try:
        brief = CaseBrief(**json.loads(brief_json))
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    rec = ShadowRecommendation(
        recommendation="review", reason_codes=[],
        policy_version="2026-11-v1", model_version="deterministic-baseline-v1",
    )
    try:
        rec = ShadowRecommendation(**json.loads(recommendation_json))
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    draft = draft_service.draft_regulator_explanation(
        account_id, investigation_id, brief, rec, analyst_id
    )
    audit.record_case_draft(draft, "created")
    _drafts[draft.draft_id] = draft

    return json.dumps({
        "draft_id": draft.draft_id,
        "draft_type": draft.draft_type,
        "status": draft.status,
        "content": draft.content,
        "citations": draft.citations,
        "edit_count": draft.edit_count,
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool: build_triage_queue (function.md Capability 5)
# ---------------------------------------------------------------------------

@server.tool()
async def build_triage_queue(
    investigations_json: str = "[]",
    findings_json: str = "{}",
    recommendations_json: str = "{}",
) -> str:
    """Build a prioritized triage queue with 'why ranked high' explanations.

    Ranking stays with deterministic scoring logic; this service only
    adds the plain-language explanation of why each item is ranked
    where it is.
    """
    investigations = json.loads(investigations_json)
    findings_map: dict[str, list[EvidenceFinding]] = {}
    try:
        raw = json.loads(findings_json)
        for inv_id, findings_list in raw.items():
            findings_map[inv_id] = [EvidenceFinding(**f) for f in findings_list]
    except (json.JSONDecodeError, TypeError, ValueError):
        findings_map = {}

    recs_map: dict[str, ShadowRecommendation] = {}
    try:
        raw = json.loads(recommendations_json)
        for inv_id, rec_data in raw.items():
            recs_map[inv_id] = ShadowRecommendation(**rec_data)
    except (json.JSONDecodeError, TypeError, ValueError):
        recs_map = {}

    queue = triage_service.build_queue(
        investigations, findings_map, recs_map
    )

    result = [
        {
            "investigation_id": item.investigation_id,
            "account_id": item.account_id,
            "rank": item.rank,
            "score": item.score,
            "reason_codes": item.reason_codes,
            "agent_findings": item.agent_findings,
            "recommendation": item.recommendation,
            "uncertainty": item.uncertainty,
            "trigger_type": item.trigger_type,
            "ranking_explanation": item.ranking_explanation,
        }
        for item in queue
    ]
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool: capture_feedback (function.md Capability 6)
# ---------------------------------------------------------------------------

@server.tool()
async def capture_feedback(
    account_id: str,
    investigation_id: str,
    analyst_id: str,
    original_recommendation: str,
    original_reason_codes: list[str] | None = None,
    analyst_response: str = "",
) -> str:
    """Capture analyst feedback: structured 'why?' -> labelled outcome.

    When an analyst disagrees with a recommendation, ask one structured
    question ("why?"). The answer becomes a labelled outcome (e.g.,
    "false positive: known travel") feeding the detection feedback loop.
    """
    if original_reason_codes is None:
        original_reason_codes = []

    feedback = feedback_service.capture_feedback(
        account_id=account_id,
        investigation_id=investigation_id,
        analyst_id=analyst_id,
        original_recommendation=original_recommendation,
        original_reason_codes=original_reason_codes,
        analyst_response=analyst_response,
    )

    # Log with analyst ID (function.md guardrail: logging)
    audit.record_analyst_feedback(feedback)

    _feedbacks[feedback.feedback_id] = feedback

    return json.dumps({
        "feedback_id": feedback.feedback_id,
        "account_id": feedback.account_id,
        "investigation_id": feedback.investigation_id,
        "analyst_id": feedback.analyst_id,
        "original_recommendation": feedback.original_recommendation,
        "analyst_response": feedback.analyst_response,
        "label": feedback.label,
        "label_reason": feedback.label_reason,
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool: edit_draft (function.md Capability 4)
# ---------------------------------------------------------------------------

@server.tool()
async def edit_draft(
    draft_id: str,
    new_content: str,
    analyst_id: str,
) -> str:
    """Apply an analyst edit to a draft. Increments edit count.

    Tracked for measured benefit: a high edit rate means the output
    isn't helping.
    """
    draft = _drafts.get(draft_id)
    if not draft:
        return json.dumps({"error": "Draft not found"})

    draft_service.edit_draft(draft, new_content, analyst_id)
    audit.record_case_draft(draft, "edited")

    return json.dumps({
        "draft_id": draft.draft_id,
        "status": draft.status,
        "edit_count": draft.edit_count,
        "edited_at": draft.edited_at.isoformat() if draft.edited_at else None,
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool: sign_draft (function.md Capability 4)
# ---------------------------------------------------------------------------

@server.tool()
async def sign_draft(
    draft_id: str,
    analyst_id: str,
) -> str:
    """Sign a draft, making it the analyst's official submission."""
    draft = _drafts.get(draft_id)
    if not draft:
        return json.dumps({"error": "Draft not found"})

    draft_service.sign_draft(draft, analyst_id)
    audit.record_case_draft(draft, "signed")

    return json.dumps({
        "draft_id": draft.draft_id,
        "status": draft.status,
        "signed_by": draft.signed_by,
        "signed_at": draft.signed_at.isoformat() if draft.signed_at else None,
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool: get_draft_edit_rate (function.md Guardrails: measured benefit)
# ---------------------------------------------------------------------------

@server.tool()
async def get_draft_edit_rate() -> str:
    """Get the draft edit rate for measured benefit tracking.

    A high edit rate means the output isn't helping.
    """
    total = len(_drafts)
    if total == 0:
        rate = 0.0
    else:
        edited = sum(1 for d in _drafts.values() if d.edit_count > 0)
        rate = edited / total

    result = {
        "total_drafts": total,
        "edited_drafts": sum(1 for d in _drafts.values() if d.edit_count > 0),
        "signed_drafts": sum(1 for d in _drafts.values() if d.status == "signed"),
        "edit_rate": round(rate, 3),
        "interpretation": (
            "High edit rate - output not helping."
            if rate > 0.5
            else "Output is helping analysts."
        ),
    }
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the MCP server over stdio."""
    server.run()


if __name__ == "__main__":
    main()
