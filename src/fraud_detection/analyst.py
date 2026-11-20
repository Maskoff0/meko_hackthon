"""Analyst copilot service (function.md).

Implements the six analyst capabilities defined in function.md:

1. Case briefs on demand — one-screen brief from decision log + Meko context,
   delivered through the MCP server. Every claim cites a source ID.
2. Trace explanation — plain-language translation of agent traces.
3. Pattern lookup — hybrid retrieval against knowledge base and past cases.
4. Drafting, not deciding — drafts case notes, customer communications,
   regulator-facing explanations. Analyst edits and signs.
5. Triage ordering — queue summarization with "why ranked high" explanation.
6. Feedback capture — structured "why?" → labelled outcome → feedback loop.

The back-end detection pipeline (challenge.md) produces traces, findings,
and recommendations. This service consumes them and turns them into
analyst efficiency.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .domain import (
    AnalystFeedback,
    BriefTimelineEntry,
    CaseBrief,
    CaseDraft,
    DraftStatus,
    EvidenceFinding,
    FeedbackLabel,
    Recommendation,
    ShadowRecommendation,
    TriageQueueItem,
)


class CaseBriefService:
    """Generates one-screen case briefs from the decision log and Meko context."""

    def __init__(self, meko_adapter: Any | None = None):
        self.meko = meko_adapter

    def build_brief(
        self,
        account_id: str,
        investigation_id: str,
        findings: list[EvidenceFinding],
        recommendation: ShadowRecommendation,
        prior_incidents: list[dict] | None = None,
        meko_context: list[dict] | None = None,
        analyst_id: str | None = None,
    ) -> CaseBrief:
        """Build a case brief with citations.

        Args:
            account_id: The account under investigation.
            investigation_id: The investigation this brief belongs to.
            findings: Agent findings from the investigation.
            recommendation: The shadow recommendation from the policy engine.
            prior_incidents: Matching prior incidents from pattern lookup.
            meko_context: Retrieved context from Meko (hybrid retrieval results).
            analyst_id: The analyst requesting the brief (for logging).

        Returns:
            A CaseBrief where every factual claim cites an event ID or trace ID.
        """
        timeline: list[BriefTimelineEntry] = []
        signals: list[dict] = []
        citations: list[str] = []
        unknowns: list[str] = []

        # Build timeline from findings, ordered by creation time
        sorted_findings = sorted(findings, key=lambda f: f.created_at)
        for finding in sorted_findings:
            for ref in finding.evidence_refs:
                timeline.append(
                    BriefTimelineEntry(
                        timestamp=finding.created_at,
                        event_type=finding.source,
                        source_system="agent_finding",
                        description=f"{finding.agent_id}: {finding.conclusion} "
                        f"(confidence={finding.confidence})",
                        event_id=ref,
                    )
                )
                citations.append(ref)

        # Add recommendation to timeline
        for ref in recommendation.evidence_provenance:
            citations.append(ref)

        # Signals driving the score, with per-agent confidence
        for finding in sorted_findings:
            signals.append({
                "agent_id": finding.agent_id,
                "conclusion": finding.conclusion,
                "confidence": finding.confidence,
                "reason_codes": finding.reason_codes,
                "evidence_refs": finding.evidence_refs,
            })
            citations.extend(finding.evidence_refs)

        # Determine unknowns
        if recommendation.abstention:
            unknowns.append("Insufficient evidence to make a determination")
        if recommendation.uncertainty == "high":
            unknowns.append(
                "High uncertainty — multiple conflicting signals or low confidence"
            )
        if not prior_incidents:
            unknowns.append("No matching prior incidents found in knowledge base")
        if recommendation.recommendation == Recommendation.ABSTAIN:
            unknowns.append("No actionable recommendation — abstaining")

        brief = CaseBrief(
            account_id=account_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            timeline=timeline,
            signals=signals,
            prior_incidents=prior_incidents or [],
            unknowns=unknowns,
            citations=list(dict.fromkeys(citations)),  # deduplicate, preserve order
        )
        return brief

    def validate_citations(self, brief: CaseBrief) -> list[str]:
        """Return any claims in the brief that lack citations.

        function.md: "If Claude can't cite it, it doesn't go in the brief."
        """
        missing: list[str] = []
        if not brief.citations and (brief.signals or brief.prior_incidents):
            missing.append("Brief contains signals or prior incidents without citations")
        return missing


class TraceExplanationService:
    """Translates agent traces into plain language for analysts.

    The raw trace stays the record of truth; this is a plain-language
    rendering for analyst consumption.
    """

    def explain_trace(
        self,
        trace_id: int,
        account_id: str,
        event_type: str,
        agent_finding: str,
        agent_confidence: float,
        baseline_triggered: bool,
        baseline_score: float,
        recommendation: str,
        reason_codes: list[str],
        evidence_refs: list[str],
    ) -> str:
        """Produce a plain-language explanation of a single trace step.

        Args:
            trace_id: The trace walkthrough ID.
            account_id: The account under investigation.
            event_type: The event type (login, device, reset, transaction, support).
            agent_finding: The agent's conclusion.
            agent_confidence: The agent's confidence score (0-1).
            baseline_triggered: Whether the deterministic baseline triggered.
            baseline_score: The baseline score.
            recommendation: The policy recommendation.
            reason_codes: The reason codes behind the decision.
            evidence_refs: Event/trace IDs cited as evidence.

        Returns:
            A plain-language explanation string.
        """
        confidence_word = self._confidence_word(agent_confidence)
        baseline_word = "triggered" if baseline_triggered else "did not trigger"

        explanation = (
            f"Trace {trace_id} for account {account_id} ({event_type} event): "
            f"The {event_type} agent detected '{agent_finding}' with {confidence_word} "
            f"confidence ({agent_confidence:.0%}). The deterministic baseline "
            f"{baseline_word} with a score of {baseline_score:.2f}. "
            f"The policy engine recommended '{recommendation}'. "
            f"Key signals: {', '.join(reason_codes) if reason_codes else 'none'}. "
            f"Evidence: {', '.join(evidence_refs) if evidence_refs else 'none'}."
        )
        return explanation

    def explain_investigation(
        self,
        investigation_id: str,
        account_id: str,
        findings: list[EvidenceFinding],
        correlated_finding: EvidenceFinding | None,
        recommendation: ShadowRecommendation,
    ) -> str:
        """Produce a plain-language explanation of an entire investigation.

        Translates the full trace into a narrative an analyst can read.
        """
        parts: list[str] = [
            f"Investigation {investigation_id} for account {account_id}:"
        ]

        for finding in findings:
            parts.append(
                f"  • {finding.agent_id} found '{finding.conclusion}' "
                f"(confidence {finding.confidence:.0%}, "
                f"reason codes: {', '.join(finding.reason_codes) or 'none'})."
            )

        if correlated_finding:
            parts.append(
                f"  • Correlator found '{correlated_finding.conclusion}' "
                f"(confidence {correlated_finding.confidence:.0%})."
            )

        parts.append(
            f"  • Policy recommendation: {recommendation.recommendation.value} "
            f"(uncertainty: {recommendation.uncertainty})."
        )
        parts.append(
            f"  • Baseline: {'triggered' if recommendation.baseline_result.get('triggered') else 'not triggered'} "
            f"(score: {recommendation.baseline_result.get('score', 0.0):.2f})."
        )
        parts.append(
            f"  • Evidence provenance: {', '.join(recommendation.evidence_provenance)}."
        )

        return "\n".join(parts)

    @staticmethod
    def _confidence_word(confidence: float) -> str:
        if confidence >= 0.8:
            return "high"
        if confidence >= 0.6:
            return "moderate"
        if confidence >= 0.4:
            return "low"
        return "very low"


class PatternLookupService:
    """Analyst-facing pattern lookup via hybrid retrieval.

    Runs hybrid retrieval against the knowledge base and past confirmed
    cases to surface what's similar and what's different.
    """

    def __init__(self, meko_adapter: Any | None = None):
        self.meko = meko_adapter

    async def lookup_patterns(
        self,
        description: str,
        account_id: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        """Look up similar past attack patterns.

        Uses Meko context_search with force_source="knowledge_base" to
        search confirmed patterns, plus general hybrid retrieval for
        past confirmed cases.

        Returns:
            A dict with 'similar' (matching patterns) and 'different'
            (distinguishing factors) sections for the analyst.
        """
        if self.meko is None:
            return {
                "query": description,
                "similar": [],
                "different": [],
                "source": "knowledge_base_unavailable",
                "message": "Meko adapter not configured; pattern lookup unavailable.",
            }

        # Search knowledge base for confirmed patterns
        kb_results = await self.meko.past_attack_patterns(
            description=description,
            agent_id="analyst_pattern_lookup",
        )

        # General hybrid retrieval across memory + knowledge base + conversations
        hybrid_results = await self.meko.correlate(
            account_id or "unknown",
            agent_id="analyst_pattern_lookup",
        )

        similar = self._extract_similar(kb_results)
        different = self._extract_different(hybrid_results, kb_results)

        return {
            "query": description,
            "similar": similar,
            "different": different,
            "source": "meko_hybrid_retrieval",
            "limit": limit,
        }

    @staticmethod
    def _extract_similar(kb_results: Any) -> list[dict]:
        """Extract similar patterns from knowledge base results."""
        if not isinstance(kb_results, dict):
            return []
        matches = kb_results.get("matches", kb_results.get("results", []))
        if not isinstance(matches, list):
            return []
        similar = []
        for m in matches[:10]:
            if isinstance(m, dict):
                similar.append({
                    "incident_id": m.get("incident_id", m.get("id", "unknown")),
                    "description": m.get("description", m.get("text", "")),
                    "similarity": m.get("match_quality", m.get("score", "unknown")),
                    "outcome": m.get("outcome", "unknown"),
                })
        return similar

    @staticmethod
    def _extract_different(
        hybrid_results: Any, kb_results: Any
    ) -> list[dict]:
        """Extract distinguishing factors from hybrid vs KB results."""
        different: list[dict] = []
        if isinstance(hybrid_results, dict):
            matches = hybrid_results.get("matches", hybrid_results.get("results", []))
            if isinstance(matches, list):
                for m in matches[:5]:
                    if isinstance(m, dict):
                        different.append({
                            "factor": m.get("description", m.get("text", ""))[:200],
                            "match_quality": m.get(
                                "match_quality", m.get("score", "unknown")
                            ),
                            "source": m.get("source", "hybrid_retrieval"),
                        })
        return different


class CaseDraftService:
    """Drafts case notes, customer communications, and regulator explanations.

    Drafts are stored as drafts, never as the official record. The
    analyst edits and signs.
    """

    def draft_case_note(
        self,
        account_id: str,
        investigation_id: str,
        brief: CaseBrief,
        recommendation: ShadowRecommendation,
        analyst_id: str | None = None,
    ) -> CaseDraft:
        """Draft a case note from the case brief and recommendation."""
        content = self._build_case_note_content(brief, recommendation)
        return CaseDraft(
            account_id=account_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            draft_type="case_note",
            content=content,
            status=DraftStatus.DRAFT,
            citations=brief.citations,
        )

    def draft_customer_communication(
        self,
        account_id: str,
        investigation_id: str,
        brief: CaseBrief,
        recommendation: ShadowRecommendation,
        analyst_id: str | None = None,
    ) -> CaseDraft:
        """Draft a customer communication explaining the action taken."""
        content = self._build_customer_communication_content(brief, recommendation)
        return CaseDraft(
            account_id=account_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            draft_type="customer_communication",
            content=content,
            status=DraftStatus.DRAFT,
            citations=brief.citations,
        )

    def draft_regulator_explanation(
        self,
        account_id: str,
        investigation_id: str,
        brief: CaseBrief,
        recommendation: ShadowRecommendation,
        analyst_id: str | None = None,
    ) -> CaseDraft:
        """Draft a regulator-facing explanation of the decision."""
        content = self._build_regulator_explanation_content(brief, recommendation)
        return CaseDraft(
            account_id=account_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            draft_type="regulator_explanation",
            content=content,
            status=DraftStatus.DRAFT,
            citations=brief.citations,
        )

    def edit_draft(self, draft: CaseDraft, new_content: str, analyst_id: str) -> CaseDraft:
        """Apply an analyst edit to a draft. Increments edit count."""
        draft.content = new_content
        draft.status = DraftStatus.EDITED
        draft.edited_at = datetime.now(timezone.utc)
        draft.edit_count += 1
        return draft

    def sign_draft(self, draft: CaseDraft, analyst_id: str) -> CaseDraft:
        """Sign a draft, making it the analyst's official submission."""
        draft.status = DraftStatus.SIGNED
        draft.signed_at = datetime.now(timezone.utc)
        draft.signed_by = analyst_id
        return draft

    def reject_draft(self, draft: CaseDraft, analyst_id: str) -> CaseDraft:
        """Reject a draft."""
        draft.status = DraftStatus.REJECTED
        return draft

    @staticmethod
    def _build_case_note_content(
        brief: CaseBrief, recommendation: ShadowRecommendation
    ) -> str:
        lines: list[str] = [
            f"Case Note — Account {brief.account_id}",
            f"Investigation: {brief.investigation_id}",
            f"Generated: {brief.generated_at.isoformat()}",
            "",
            "Summary:",
        ]
        if brief.signals:
            for sig in brief.signals:
                lines.append(
                    f"  - {sig['agent_id']}: {sig['conclusion']} "
                    f"(confidence {sig['confidence']:.0%})"
                )
        else:
            lines.append("  No agent signals recorded.")
        lines.append("")
        lines.append("Recommendation:")
        lines.append(f"  {recommendation.recommendation.value} "
                     f"(uncertainty: {recommendation.uncertainty})")
        lines.append("")
        lines.append("Reason codes:")
        lines.append(f"  {', '.join(recommendation.reason_codes) or 'none'}")
        lines.append("")
        lines.append("Unknowns:")
        for unk in brief.unknowns:
            lines.append(f"  - {unk}")
        lines.append("")
        lines.append("Citations:")
        for cite in brief.citations:
            lines.append(f"  - {cite}")
        return "\n".join(lines)

    @staticmethod
    def _build_customer_communication_content(
        brief: CaseBrief, recommendation: ShadowRecommendation
    ) -> str:
        lines: list[str] = [
            f"Account Security Notice — Account {brief.account_id}",
            "",
            "We reviewed recent activity on your account and detected "
            "unusual patterns that may indicate unauthorized access.",
            "",
            "What we found:",
        ]
        if brief.signals:
            for sig in brief.signals:
                lines.append(f"  - {sig['conclusion']}")
        else:
            lines.append("  No specific concerns identified.")
        lines.append("")
        lines.append("What we're doing:")
        lines.append(f"  {recommendation.recommendation.value.title()}")
        lines.append("")
        lines.append("If you did not initiate this activity, please contact "
                     "customer support immediately.")
        return "\n".join(lines)

    @staticmethod
    def _build_regulator_explanation_content(
        brief: CaseBrief, recommendation: ShadowRecommendation
    ) -> str:
        lines: list[str] = [
            f"Regulator Explanation — Account {brief.account_id}",
            f"Investigation ID: {brief.investigation_id}",
            f"Policy version: {recommendation.policy_version}",
            f"Model version: {recommendation.model_version}",
            "",
            "Decision:",
            f"  {recommendation.recommendation.value}",
            "",
            "Basis:",
        ]
        for sig in brief.signals:
            lines.append(
                f"  - {sig['agent_id']} detected {sig['conclusion']} "
                f"with {sig['confidence']:.0%} confidence"
            )
        lines.append("")
        lines.append("Evidence references:")
        for cite in brief.citations:
            lines.append(f"  - {cite}")
        lines.append("")
        lines.append("This decision was made by a deterministic policy engine "
                     "using agent findings as evidence. No automated containment "
                     "action was taken without human review.")
        return "\n".join(lines)


class TriageService:
    """Triage ordering for analysts: queue summarization with 'why ranked high'."""

    def build_queue(
        self,
        investigations: list[dict],
        findings_by_inv: dict[str, list[EvidenceFinding]],
        recommendations_by_inv: dict[str, ShadowRecommendation],
    ) -> list[TriageQueueItem]:
        """Build a prioritized triage queue.

        Ranking stays with deterministic scoring logic; this service
        only adds the plain-language explanation of why each item
        is ranked where it is.
        """
        items: list[TriageQueueItem] = []

        for inv in investigations:
            inv_id = inv["investigation_id"]
            account_id = inv.get("account_id", "unknown")
            findings = findings_by_inv.get(inv_id, [])
            rec = recommendations_by_inv.get(inv_id)

            score = 0.0
            reason_codes: list[str] = []
            for f in findings:
                score += f.confidence * 0.3
                reason_codes.extend(f.reason_codes)

            if rec:
                baseline = rec.baseline_result or {}
                score += float(baseline.get("score", 0.0)) * 0.4
                reason_codes.extend(baseline.get("reason_codes", []))
                recommendation = rec.recommendation.value
                uncertainty = rec.uncertainty
            else:
                recommendation = "review"
                uncertainty = "medium"

            reason_codes = list(dict.fromkeys(reason_codes))

            items.append(
                TriageQueueItem(
                    investigation_id=inv_id,
                    account_id=account_id,
                    rank=0,  # assigned after sort
                    score=round(score, 3),
                    reason_codes=reason_codes,
                    agent_findings=[
                        {
                            "agent_id": f.agent_id,
                            "conclusion": f.conclusion,
                            "confidence": f.confidence,
                        }
                        for f in findings
                    ],
                    recommendation=recommendation,
                    uncertainty=uncertainty,
                    trigger_type=inv.get("trigger_type", "unknown"),
                )
            )

        # Sort by score descending (deterministic ranking)
        items.sort(key=lambda x: x.score, reverse=True)

        # Assign ranks and add ranking explanation
        for rank, item in enumerate(items, start=1):
            item.rank = rank
            item.ranking_explanation = self._explain_ranking(item)

        return items

    @staticmethod
    def _explain_ranking(item: TriageQueueItem) -> str:
        """Plain-language explanation of why this investigation is ranked where it is."""
        parts: list[str] = [
            f"Ranked #{item.rank} with score {item.score:.2f}."
        ]
        if item.reason_codes:
            parts.append(
                f"Key signals: {', '.join(item.reason_codes)}."
            )
        if item.agent_findings:
            top = max(item.agent_findings, key=lambda f: f["confidence"])
            parts.append(
                f"Highest-confidence finding: {top['agent_id']} "
                f"detected {top['conclusion']} ({top['confidence']:.0%})."
            )
        parts.append(
            f"Recommendation: {item.recommendation} "
            f"(uncertainty: {item.uncertainty})."
        )
        return " ".join(parts)


class FeedbackCaptureService:
    """Feedback capture: structured 'why?' → labelled outcome → feedback loop.

    When an analyst disagrees with a recommendation, ask one structured
    question ("why?"). The answer becomes a labelled outcome (e.g.,
    "false positive: known travel") feeding the detection feedback loop.
    """

    def capture_feedback(
        self,
        account_id: str,
        investigation_id: str,
        analyst_id: str,
        original_recommendation: str,
        original_reason_codes: list[str],
        analyst_response: str,
    ) -> AnalystFeedback:
        """Capture analyst feedback on a recommendation.

        Args:
            account_id: The account under investigation.
            investigation_id: The investigation ID.
            analyst_id: The analyst providing feedback.
            original_recommendation: The recommendation the analyst disagreed with.
            original_reason_codes: The reason codes from the original recommendation.
            analyst_response: The analyst's free-text response to "why?".

        Returns:
            An AnalystFeedback with a derived label.
        """
        label, label_reason = self._derive_label(analyst_response)

        return AnalystFeedback(
            account_id=account_id,
            investigation_id=investigation_id,
            analyst_id=analyst_id,
            original_recommendation=original_recommendation,
            original_reason_codes=original_reason_codes,
            analyst_response=analyst_response,
            label=label,
            label_reason=label_reason,
        )

    @staticmethod
    def _derive_label(response: str) -> tuple[FeedbackLabel, str | None]:
        """Derive a labelled outcome from the analyst's free-text response."""
        lowered = response.lower()

        if "known travel" in lowered or "travel" in lowered:
            return (
                FeedbackLabel.FALSE_POSITIVE_KNOWN_TRAVEL,
                "Analyst identified the activity as known travel.",
            )
        if "false positive" in lowered or "not fraud" in lowered or "legitimate" in lowered:
            return (
                FeedbackLabel.FALSE_POSITIVE_OTHER,
                "Analyst marked as false positive (non-travel reason).",
            )
        if "true positive" in lowered or "confirmed fraud" in lowered or "correct" in lowered:
            return (
                FeedbackLabel.TRUE_POSITIVE,
                "Analyst confirmed the recommendation was correct.",
            )
        if "missed" in lowered or "should have" in lowered:
            return (
                FeedbackLabel.TRUE_POSITIVE_MISSED_SIGNAL,
                "Analyst indicated additional signals were missed.",
            )
        return (FeedbackLabel.UNKNOWN, None)

    @staticmethod
    def feedback_question() -> str:
        """The structured question asked when an analyst disagrees."""
        return "Why do you disagree with this recommendation?"
