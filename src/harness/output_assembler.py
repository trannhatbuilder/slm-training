"""
Output Assembler — Assembles final result conforming to Output Schema v0.1.

Step 11 of Harness workflow: Record traceability + return structured review result.
"""

import uuid
from datetime import datetime, timezone

from .config import PIPELINE_VERSION, RULESET_VERSION, KNOWLEDGE_BASE_VERSION


def assemble_output(
    finding: dict,
    completeness_review: dict,
    evidence_review: dict,
    classification_review: dict,
    severity_review: dict,
    cvss_review: dict,
    cwe_review: dict,
    impact_review: dict,
    recommendation_review: dict,
    consistency_review: dict,
    retest_review: dict,
    review_comments: list[dict],
    confidence_result: dict,
    escalation_result: dict,
) -> dict:
    """
    Assemble the final Output Schema v0.1 compliant result.

    Returns:
        dict matching schemas/output_schema.json
    """
    finding_id = finding.get("finding_id", "FND-000000")
    document_id = finding.get("source", {}).get("document_id", "DOC-000000")

    # Generate review_id
    review_id = f"REV-{uuid.uuid4().int % 1000000:06d}"

    # Determine review_status
    review_status = _determine_review_status(
        escalation_result, completeness_review, evidence_review
    )

    # Build traceability
    traceability = {
        "source_document_id": document_id,
        "source_location": finding.get("source", {}).get("location"),
        "input_schema_version": "0.2",
        "output_schema_version": "0.1",
        "model_version": None,  # No SLM in rule-based mode
        "knowledge_base_version": KNOWLEDGE_BASE_VERSION,
        "ruleset_version": RULESET_VERSION,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    }

    # Build result
    result = {
        "schema_version": "0.1",
        "review_id": review_id,
        "finding_id": finding_id,
        "review_status": review_status,
        "classification": classification_review,
        "completeness_review": completeness_review,
        "evidence_review": evidence_review,
        "severity_review": severity_review,
        "cvss_review": cvss_review,
        "cwe_review": cwe_review,
        "impact_review": impact_review,
        "recommendation_review": recommendation_review,
        "consistency_review": consistency_review,
        "retest_review": retest_review,
        "review_comments": review_comments,
        "confidence": _clean_confidence(confidence_result),
        "human_escalation": escalation_result,
        "traceability": traceability,
    }

    return result


def _determine_review_status(
    escalation: dict,
    completeness: dict,
    evidence: dict,
) -> str:
    """
    Determine review_status based on escalation and check results.

    Priority:
      1. human_review — if escalation is required
      2. needs_revision — if completeness or evidence has issues
      3. pass — all checks pass
    """
    if escalation.get("required", False):
        return "human_review"

    is_complete = completeness.get("is_complete")
    is_sufficient = evidence.get("is_sufficient")

    if is_complete is False or is_sufficient is False:
        return "needs_revision"

    if is_complete is True and is_sufficient is True:
        return "pass"

    # If we can't determine, needs revision
    return "needs_revision"


def _clean_confidence(confidence_result: dict) -> dict:
    """Extract only the fields needed for output schema."""
    return {
        "overall_score": confidence_result.get("overall_score"),
        "level": confidence_result.get("level"),
        "basis": confidence_result.get("basis", []),
        "limitations": confidence_result.get("limitations", []),
    }