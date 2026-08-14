"""
Consistency Checker — Cross-field consistency rules.

Implements consistency_rules from review_taxonomy.yaml:
  - severity_cvss_alignment
  - evidence_classification_alignment
  - title_content_alignment
  - recommendation_root_cause
"""

from typing import Any

from .config import CVSS_RANGES
from .rule_checks import _make_comment, _cvss_score_to_severity


def check_consistency(
    finding: dict,
    evidence_review: dict,
    severity_review: dict,
    classification_review: dict,
) -> tuple[dict, list[dict]]:
    """
    Run cross-field consistency checks.

    Returns:
        (sub_review, comments)
    """
    comments = []
    issues = []
    is_consistent = True

    # 1. severity_cvss_alignment
    sev_issue = _check_severity_cvss_alignment(finding)
    if sev_issue:
        issues.append(sev_issue)
        is_consistent = False
        comments.append(_make_comment(
            "CONS-001", "warning", "severity",
            sev_issue,
            suggested_action="review_with_human",
        ))

    # 2. evidence_classification_alignment
    class_issue = _check_evidence_classification_alignment(
        finding, evidence_review, classification_review
    )
    if class_issue:
        issues.append(class_issue)
        is_consistent = False
        comments.append(_make_comment(
            "CONS-002", "warning", "classification",
            class_issue,
            suggested_action="correct_classification_based_on_evidence",
        ))

    # 3. title_content_alignment
    title_issue = _check_title_content_alignment(finding)
    if title_issue:
        issues.append(title_issue)
        # Don't mark as inconsistent — just flag
        comments.append(_make_comment(
            "CONS-003", "suggestion", "title",
            title_issue,
            suggested_action="review_title_accuracy",
        ))

    # 4. recommendation_root_cause
    rec_issue = _check_recommendation_root_cause_alignment(finding, severity_review)
    if rec_issue:
        issues.append(rec_issue)
        comments.append(_make_comment(
            "CONS-004", "suggestion", "recommendation",
            rec_issue,
            suggested_action="strengthen_recommendation",
        ))

    sub_review = {
        "is_consistent": is_consistent,
        "issues": issues,
    }

    return sub_review, comments


def _check_severity_cvss_alignment(finding: dict) -> str | None:
    """Check if severity aligns with CVSS score."""
    severity = finding.get("severity")
    score = finding.get("cvss", {}).get("score")
    implied = _cvss_score_to_severity(score)

    if severity and implied and severity != implied:
        return f"Reported severity '{severity}' does not match CVSS {score} (implies '{implied}')"
    return None


def _check_evidence_classification_alignment(
    finding: dict,
    evidence_review: dict,
    classification_review: dict,
) -> str | None:
    """
    CRITICAL rule: Classification must not be 'confirmed_vulnerability'
    if exploitation is not demonstrated or evidence is insufficient.
    """
    label = classification_review.get("label")
    is_sufficient = evidence_review.get("is_sufficient")

    if label == "confirmed_vulnerability" and is_sufficient is not True:
        return (
            "Classification is 'confirmed_vulnerability' but evidence is insufficient "
            "— should be 'potential_issue'"
        )
    return None


def _check_title_content_alignment(finding: dict) -> str | None:
    """Basic check that title reflects finding content."""
    title = (finding.get("title") or "").lower()
    observation = (finding.get("observation") or "").lower()

    if not title or not observation:
        return None

    # Extract key words from title (skip common words)
    skip = {"in", "of", "the", "a", "an", "not", "is", "are", "during", "use", "weak", "hardcoded"}
    title_words = [w for w in title.split() if w not in skip and len(w) > 3]

    # Check if at least some title keywords appear in observation
    matches = sum(1 for w in title_words if w in observation)
    if title_words and matches / len(title_words) < 0.2:
        return f"Finding title keywords are barely reflected in observation content ({matches}/{len(title_words)} matches)"
    return None


def _check_recommendation_root_cause_alignment(
    finding: dict,
    severity_review: dict,
) -> str | None:
    """Check if recommendation addresses the actual issue described."""
    recommendation = finding.get("recommendation", [])
    observation = (finding.get("observation") or "").lower()

    if not recommendation or not observation:
        return None

    # Generic recommendations that don't address specific issues
    generic_phrases = ["follow best practices", "ensure security", "review security"]
    rec_text = " ".join(recommendation).lower()

    if any(phrase in rec_text for phrase in generic_phrases):
        return "Recommendation contains generic advice — may not address root cause"

    return None