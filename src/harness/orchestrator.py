"""
Orchestrator — Main pipeline controller for the Rule-Based Validation Engine.

Implements the full Harness workflow (steps 1-12 from problem_definition §11.4):
  1. Receive a finding
  2. Check data-usage status (governance)
  3. Validate the input schema
  4. Run deterministic checks
  5. Retrieve relevant EVVO rules (KB/RAG)
  6. (Prompt build — skipped in rule-based mode)
  7. (SLM call — skipped in rule-based mode)
  8. (SLM output validation — skipped in rule-based mode)
  9. Run consistency and evidence checks
  10. Determine human escalation
  11. Record traceability
  12. Return the structured review result
"""

import json
import time
from pathlib import Path
from typing import Any

from .input_validator import InputValidator
from .rule_checks import (
    reset_comment_counter,
    check_completeness,
    check_evidence,
    check_classification,
    check_severity,
    check_cvss,
    check_cwe,
    check_impact,
    check_recommendation,
    check_retest,
)
from .consistency import check_consistency
from .confidence import compute_confidence
from .escalation import decide_escalation
from .output_assembler import assemble_output
from .kb.retriever import KBRetriever


class HarnessOrchestrator:
    """
    Rule-Based Validation Engine — full pipeline with KB integration.

    Usage:
        harness = HarnessOrchestrator()
        result = harness.review(finding_dict)
        # result is Output Schema v0.1 compliant
    """

    def __init__(self, schema_path: str | None = None, kb_root: str | None = None):
        self.validator = InputValidator(schema_path=schema_path)
        self.kb_retriever = KBRetriever(kb_root=kb_root)
        self.stats = {
            "total_reviews": 0,
            "pass": 0,
            "needs_revision": 0,
            "human_review": 0,
            "errors": 0,
        }

    def review(self, finding: dict) -> dict:
        """
        Run the full review pipeline on a normalized finding.

        Args:
            finding: dict matching Input Schema v0.2

        Returns:
            dict matching Output Schema v0.1
        """
        start_time = time.time()

        # Reset comment counter for this review
        reset_comment_counter()

        # ── Step 1-3: Validate input ──
        validation = self.validator.validate(finding)
        if not validation["is_valid"]:
            # Input is invalid — return error result
            self.stats["errors"] += 1
            return self._make_error_result(finding, validation)

        # ── Step 4: Run deterministic checks ──
        all_comments = []

        # Completeness
        completeness_review, comp_comments = check_completeness(finding)
        all_comments.extend(comp_comments)

        # Evidence
        evidence_review, evid_comments = check_evidence(finding)
        all_comments.extend(evid_comments)

        # Classification (depends on evidence)
        classification_review, class_comments = check_classification(finding, evidence_review)
        all_comments.extend(class_comments)

        # Severity
        severity_review, sev_comments = check_severity(finding)
        all_comments.extend(sev_comments)

        # CVSS
        cvss_review, cvss_comments = check_cvss(finding)
        all_comments.extend(cvss_comments)

        # CWE
        cwe_review, cwe_comments = check_cwe(finding)
        all_comments.extend(cwe_comments)

        # Impact
        impact_review, imp_comments = check_impact(finding)
        all_comments.extend(imp_comments)

        # Recommendation
        recommendation_review, rec_comments = check_recommendation(finding)
        all_comments.extend(rec_comments)

        # Retest
        retest_review, ret_comments = check_retest(finding)
        all_comments.extend(ret_comments)

        # ── Step 5: Retrieve relevant EVVO rules (KB/RAG) ──
        # Determine finding domain for KB retrieval
        finding_domain = None
        if finding.get("affected_targets"):
            finding_domain = finding["affected_targets"][0].get("target_type")

        kb_result = self.kb_retriever.retrieve_for_review(
            taxonomy_codes=["COMP", "EVID", "CLASS", "SEV", "CVSS", "CWE", "IMP", "REC", "RET"],
            domain=finding_domain,
        )

        # ── Step 9: Consistency checks ──
        consistency_review, cons_comments = check_consistency(
            finding, evidence_review, severity_review, classification_review
        )
        all_comments.extend(cons_comments)

        # ── Confidence scoring ──
        confidence_result = compute_confidence(
            evidence_review, classification_review, severity_review,
            completeness_review, retest_review,
        )

        # ── Step 10: Human escalation ──
        escalation_result = decide_escalation(
            finding, confidence_result, classification_review,
            severity_review, evidence_review,
        )

        # ── Step 11-12: Assemble output ──
        result = assemble_output(
            finding=finding,
            completeness_review=completeness_review,
            evidence_review=evidence_review,
            classification_review=classification_review,
            severity_review=severity_review,
            cvss_review=cvss_review,
            cwe_review=cwe_review,
            impact_review=impact_review,
            recommendation_review=recommendation_review,
            consistency_review=consistency_review,
            retest_review=retest_review,
            review_comments=all_comments,
            confidence_result=confidence_result,
            escalation_result=escalation_result,
        )

        # Track stats
        elapsed = time.time() - start_time
        self.stats["total_reviews"] += 1
        status = result.get("review_status", "unknown")
        if status in self.stats:
            self.stats[status] += 1

        # Attach pipeline metadata (not in output schema — for debugging)
        result["_pipeline_meta"] = {
            "elapsed_seconds": round(elapsed, 4),
            "comment_count": len(all_comments),
            "escalation_required": escalation_result["required"],
            "validation_issues": len(validation.get("issues", [])),
            "kb_rules_retrieved": kb_result.total_matched,
            "kb_categories_matched": kb_result.categories_matched,
        }

        return result

    def review_batch(self, findings: list[dict]) -> list[dict]:
        """Run review pipeline on multiple findings."""
        return [self.review(f) for f in findings]

    def get_stats(self) -> dict:
        """Get pipeline statistics."""
        return dict(self.stats)

    def _make_error_result(self, finding: dict, validation: dict) -> dict:
        """Create a minimal result for invalid inputs."""
        from datetime import datetime, timezone

        return {
            "schema_version": "0.1",
            "review_id": "REV-000000",
            "finding_id": finding.get("finding_id", "FND-000000"),
            "review_status": "human_review",
            "classification": {
                "label": "undetermined",
                "rationale": "Input validation failed — cannot review",
                "supported_by_evidence": None,
            },
            "completeness_review": {
                "is_complete": False,
                "missing_required_fields": [],
                "missing_conditional_fields": [],
                "comments": ["Input validation failed"],
            },
            "evidence_review": {
                "is_sufficient": None,
                "evidence_items_reviewed": [],
                "supported_claims": [],
                "unsupported_claims": [],
                "missing_evidence": [],
                "comments": ["Input validation failed — cannot assess evidence"],
            },
            "severity_review": {
                "reported_severity": finding.get("severity"),
                "suggested_severity": finding.get("severity"),
                "is_consistent": None,
                "change_recommended": False,
                "rationale": "Input validation failed",
            },
            "cvss_review": {
                "reported_version": None,
                "reported_score": None,
                "reported_vector": None,
                "vector_is_valid": None,
                "score_matches_vector": None,
                "severity_matches_score": None,
                "requires_manual_recalculation": True,
                "comments": ["Input validation failed"],
            },
            "cwe_review": {
                "reported_cwe": finding.get("cwe_id"),
                "is_relevant": None,
                "suggested_cwe": None,
                "rationale": "Input validation failed",
            },
            "impact_review": {
                "is_supported_by_evidence": None,
                "is_proportionate": None,
                "unsupported_impact_claims": [],
                "comments": ["Input validation failed"],
            },
            "recommendation_review": {
                "addresses_root_cause": None,
                "is_actionable": None,
                "is_technically_relevant": None,
                "missing_recommendations": [],
                "comments": ["Input validation failed"],
            },
            "consistency_review": {
                "is_consistent": None,
                "issues": ["Input validation failed"],
            },
            "retest_review": {
                "applicable": None,
                "reported_status": None,
                "status_supported_by_evidence": None,
                "missing_retest_evidence": [],
                "comments": ["Input validation failed"],
            },
            "review_comments": [
                {
                    "comment_id": "RC-001",
                    "taxonomy_code": "COMP-000",
                    "category": "completeness",
                    "severity": "error",
                    "field": None,
                    "message": f"Input validation failed: {json.dumps(validation['issues'])}",
                    "evidence_reference": None,
                    "suggested_action": "fix_input_and_resubmit",
                }
            ],
            "confidence": {
                "overall_score": None,
                "level": "not_calculated",
                "basis": [],
                "limitations": ["Input validation failed — confidence cannot be calculated"],
            },
            "human_escalation": {
                "required": True,
                "reasons": ["Input validation failed — human must review and correct"],
                "recommended_reviewer": "technical_reviewer",
            },
            "traceability": {
                "source_document_id": finding.get("source", {}).get("document_id", "DOC-000000"),
                "source_location": finding.get("source", {}).get("location"),
                "input_schema_version": "0.2",
                "output_schema_version": "0.1",
                "model_version": None,
                "knowledge_base_version": "1.0",
                "ruleset_version": "1.0",
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
            },
        }