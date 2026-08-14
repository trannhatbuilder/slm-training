"""
Confidence Scorer — Computes confidence based on taxonomy CONF factors.

Factors and weights from review_taxonomy.yaml:
  evidence_completeness:      0.35
  classification_certainty:  0.25
  cvss_severity_consistency: 0.15
  section_completeness:      0.15
  retest_availability:       0.10

Confidence level:
  high:          score >= 0.8
  medium:        score >= 0.5
  low:           score >= 0.3
  not_calculated: score is None
"""

from .config import CONFIDENCE_WEIGHTS


def compute_confidence(
    evidence_review: dict,
    classification_review: dict,
    severity_review: dict,
    completeness_review: dict,
    retest_review: dict,
) -> dict:
    """
    Compute overall confidence score and level.

    Returns:
        {
            "overall_score": float | None,
            "level": str,
            "basis": list[str],
            "limitations": list[str],
            "factors": dict  — per-factor scores for debugging
        }
    """
    factors = {}
    basis = []
    limitations = []

    # 1. Evidence completeness (0.35)
    evidence_score = _score_evidence_completeness(evidence_review)
    factors["evidence_completeness"] = evidence_score
    if evidence_score >= 0.8:
        basis.append("Evidence is sufficient and supports the vulnerability claim")
    elif evidence_score >= 0.5:
        basis.append("Evidence is partial — some gaps exist")
    else:
        limitations.append("Evidence is insufficient or absent")
        basis.append("Evidence is insufficient to support the claim")

    # 2. Classification certainty (0.25)
    class_score = _score_classification_certainty(classification_review)
    factors["classification_certainty"] = class_score
    if class_score >= 0.8:
        basis.append("Classification is well-supported by evidence")
    elif class_score >= 0.5:
        basis.append("Classification has moderate support")
    else:
        limitations.append("Classification is uncertain or contradicted by evidence")

    # 3. CVSS-severity consistency (0.15)
    cvss_score = _score_cvss_severity_consistency(severity_review)
    factors["cvss_severity_consistency"] = cvss_score
    if cvss_score >= 0.8:
        basis.append("CVSS score and reported severity are consistent")
    else:
        limitations.append("CVSS score and reported severity are inconsistent")

    # 4. Section completeness (0.15)
    section_score = _score_section_completeness(completeness_review)
    factors["section_completeness"] = section_score
    if section_score >= 0.8:
        basis.append("All required sections are present and complete")
    else:
        limitations.append("Some required sections are missing or incomplete")

    # 5. Retest availability (0.10)
    retest_score = _score_retest_availability(retest_review)
    factors["retest_availability"] = retest_score
    if retest_score >= 0.8:
        basis.append("Retest has been performed")
    else:
        limitations.append("No retest has been performed")

    # Compute weighted score
    overall = 0.0
    total_weight = 0.0
    for factor_name, weight in CONFIDENCE_WEIGHTS.items():
        score = factors.get(factor_name)
        if score is not None:
            overall += weight * score
            total_weight += weight

    if total_weight > 0:
        overall = overall / total_weight
        overall = round(overall, 3)
    else:
        overall = None

    # Determine level
    level = _score_to_level(overall)

    return {
        "overall_score": overall,
        "level": level,
        "basis": basis,
        "limitations": limitations,
        "factors": factors,
    }


def _score_evidence_completeness(review: dict) -> float:
    """Score evidence completeness: 1.0 sufficient, 0.5 partial, 0.0 none."""
    is_sufficient = review.get("is_sufficient")
    missing = review.get("missing_evidence", [])
    unsupported = review.get("unsupported_claims", [])

    if is_sufficient is True:
        return 1.0
    elif is_sufficient is False:
        if unsupported:
            return 0.2
        return 0.5
    else:
        # None — no evidence at all
        return 0.0


def _score_classification_certainty(review: dict) -> float:
    """Score classification certainty."""
    label = review.get("label")
    supported = review.get("supported_by_evidence")

    if label == "confirmed_vulnerability" and supported:
        return 1.0
    elif label == "confirmed_vulnerability" and not supported:
        return 0.3  # Claimed confirmed but not supported — low certainty
    elif label == "potential_issue":
        return 0.7  # Honest assessment — moderate-high certainty
    elif label == "informational":
        return 0.8
    elif label == "false_positive":
        return 0.6
    elif label == "undetermined":
        return 0.2
    return 0.5


def _score_cvss_severity_consistency(review: dict) -> float:
    """Score CVSS-severity consistency."""
    is_consistent = review.get("is_consistent")
    if is_consistent is True:
        return 1.0
    elif is_consistent is False:
        return 0.2
    return 0.5  # Unknown


def _score_section_completeness(review: dict) -> float:
    """Score section completeness."""
    is_complete = review.get("is_complete")
    missing_required = review.get("missing_required_fields", [])
    missing_conditional = review.get("missing_conditional_fields", [])

    if is_complete is True and not missing_conditional:
        return 1.0
    elif is_complete is True and missing_conditional:
        return 0.8
    elif missing_required:
        return 0.3
    return 0.5


def _score_retest_availability(review: dict) -> float:
    """Score retest availability."""
    applicable = review.get("applicable")
    status = review.get("reported_status")
    supported = review.get("status_supported_by_evidence")

    if applicable is False:
        return 1.0  # Not applicable — no retest needed
    if status in ("fixed", "partially_fixed", "not_fixed", "accepted_risk") and supported:
        return 1.0
    if status in ("fixed", "partially_fixed", "not_fixed", "accepted_risk") and not supported:
        return 0.5
    if status == "not_retested" or status is None:
        return 0.1
    return 0.3


def _score_to_level(score: float | None) -> str:
    """Map score to confidence level."""
    if score is None:
        return "not_calculated"
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    if score >= 0.3:
        return "low"
    return "low"