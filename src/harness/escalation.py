"""
Human Escalation Decider — Step 10 of Harness workflow.

Escalation rules:
  - If confidence < 0.7 → escalate
  - If evidence_completeness < 0.5 → always escalate regardless of total score
  - If severity is critical or high → escalate for human approval
  - If classification is 'potential_issue' with conflicting evidence → escalate
  - If CVSS-severity mismatch → escalate for severity decision
"""

from .config import ESCALATION_THRESHOLD, EVIDENCE_COMPLETNESS_ESCALATION_THRESHOLD


def decide_escalation(
    finding: dict,
    confidence_result: dict,
    classification_review: dict,
    severity_review: dict,
    evidence_review: dict,
) -> dict:
    """
    Determine whether human escalation is required.

    Returns:
        {
            "required": bool,
            "reasons": list[str],
            "recommended_reviewer": str | None,
        }
    """
    reasons = []
    recommended_reviewer = None

    overall_score = confidence_result.get("overall_score")
    factors = confidence_result.get("factors", {})
    level = confidence_result.get("level")

    # Rule 1: Low confidence
    if overall_score is not None and overall_score < ESCALATION_THRESHOLD:
        reasons.append(
            f"Confidence score ({overall_score:.2f}) is below escalation threshold ({ESCALATION_THRESHOLD})"
        )

    # Rule 2: Evidence completeness critically low
    evidence_score = factors.get("evidence_completeness", 1.0)
    if evidence_score < EVIDENCE_COMPLETNESS_ESCALATION_THRESHOLD:
        reasons.append(
            f"Evidence completeness ({evidence_score:.2f}) is critically low — always requires human review"
        )

    # Rule 3: Critical or high severity findings
    severity = finding.get("severity")
    if severity in ("critical", "high"):
        reasons.append(f"Finding severity is '{severity}' — requires human approval per policy")
        recommended_reviewer = "senior_pentester"

    # Rule 4: Classification-evidence conflict
    label = classification_review.get("label")
    supported = classification_review.get("supported_by_evidence")
    if label == "confirmed_vulnerability" and not supported:
        reasons.append(
            "Classification is 'confirmed_vulnerability' but evidence does not support it — requires human decision"
        )
        if not recommended_reviewer:
            recommended_reviewer = "technical_reviewer"

    # Rule 5: CVSS-severity mismatch
    is_consistent = severity_review.get("is_consistent")
    if is_consistent is False:
        reasons.append("CVSS-severity mismatch requires human review for final severity decision")
        if not recommended_reviewer:
            recommended_reviewer = "report_reviewer"

    # Rule 6: No retest for confirmed vulnerabilities
    retest_status = finding.get("retest", {}).get("status")
    if label == "confirmed_vulnerability" and (not retest_status or retest_status == "not_retested"):
        reasons.append("Confirmed vulnerability has not been retested — recommend scheduling retest")
        # This is a softer escalation — don't override reviewer

    required = len(reasons) > 0

    return {
        "required": required,
        "reasons": reasons,
        "recommended_reviewer": recommended_reviewer,
    }