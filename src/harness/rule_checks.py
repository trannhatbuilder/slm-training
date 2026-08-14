"""
Rule-Based Checks — 9 taxonomy categories (COMP, EVID, CLASS, SEV, CVSS, CWE, IMP, REC, RET).

Each check function takes a normalized finding and returns a dict with:
  - sub_review: dict matching the output_schema sub-object
  - comments: list of review_comment dicts

Step 4 of Harness workflow: Run deterministic checks.
"""

import re
from typing import Any

from .config import CVSS_RANGES, CLASSIFICATION_LABELS, TAXONOMY_CATEGORIES


# ──────────────────────────────────────────────
# Comment ID counter (per-review-run)
# ──────────────────────────────────────────────
_comment_counter = 0

def _next_comment_id() -> str:
    global _comment_counter
    _comment_counter += 1
    return f"RC-{_comment_counter:03d}"

def reset_comment_counter():
    global _comment_counter
    _comment_counter = 0


def _make_comment(
    taxonomy_code: str,
    severity: str,
    field: str | None,
    message: str,
    evidence_reference: str | None = None,
    suggested_action: str = "review",
) -> dict:
    """Create a review_comment dict matching output_schema."""
    return {
        "comment_id": _next_comment_id(),
        "taxonomy_code": taxonomy_code,
        "category": TAXONOMY_CATEGORIES.get(taxonomy_code.split("-")[0], "completeness"),
        "severity": severity,
        "field": field,
        "message": message,
        "evidence_reference": evidence_reference,
        "suggested_action": suggested_action,
    }


# ══════════════════════════════════════════════
# COMP — Completeness Review
# ══════════════════════════════════════════════

def check_completeness(finding: dict) -> tuple[dict, list[dict]]:
    """
    Check whether all required fields and sections are present
    and populated with meaningful content.
    """
    comments = []
    missing_required = []
    missing_conditional = []

    # Check core required fields
    required_text_fields = {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "observation": finding.get("observation"),
    }

    for field_name, value in required_text_fields.items():
        if not value or (isinstance(value, str) and len(value.strip()) == 0):
            missing_required.append(field_name)
            comments.append(_make_comment(
                "COMP-001", "error", field_name,
                f"Required field '{field_name}' is missing or empty",
                suggested_action="provide_missing_content",
            ))

    # Check evidence array
    evidence = finding.get("evidence", [])
    if not evidence:
        missing_required.append("evidence")
        comments.append(_make_comment(
            "COMP-002", "error", "evidence",
            "No exploitation evidence provided",
            suggested_action="provide_exploitation_evidence",
        ))

    # Check recommendation
    recommendation = finding.get("recommendation", [])
    if not recommendation:
        missing_conditional.append("recommendation")
        comments.append(_make_comment(
            "COMP-003", "warning", "recommendation",
            "No recommendation/remediation provided",
            suggested_action="add_recommendation",
        ))

    # Check CVSS
    cvss = finding.get("cvss", {})
    if not cvss.get("score") and cvss.get("score") != 0:
        missing_conditional.append("cvss.score")
        comments.append(_make_comment(
            "COMP-004", "warning", "cvss.score",
            "CVSS score is missing",
            suggested_action="provide_cvss_score",
        ))

    # Check CWE
    if not finding.get("cwe_id"):
        missing_conditional.append("cwe_id")
        comments.append(_make_comment(
            "COMP-005", "warning", "cwe_id",
            "CWE ID is missing",
            suggested_action="assign_cwe_id",
        ))

    # Check impact
    if not finding.get("impact"):
        missing_conditional.append("impact")
        comments.append(_make_comment(
            "COMP-006", "warning", "impact",
            "Impact description is missing",
            suggested_action="describe_impact",
        ))

    is_complete = len(missing_required) == 0

    sub_review = {
        "is_complete": is_complete,
        "missing_required_fields": missing_required,
        "missing_conditional_fields": missing_conditional,
        "comments": [c["message"] for c in comments],
    }

    return sub_review, comments


# ══════════════════════════════════════════════
# EVID — Evidence Review
# ══════════════════════════════════════════════

def check_evidence(finding: dict) -> tuple[dict, list[dict]]:
    """
    Assess whether exploitation evidence sufficiently supports
    the vulnerability claim.
    """
    comments = []
    evidence = finding.get("evidence", [])
    observation = finding.get("observation", "") or ""

    supported_claims = []
    unsupported_claims = []
    missing_evidence = []
    evidence_items_reviewed = []

    # Analyze each evidence item
    has_manual_exploit = False
    has_scanner_only = True  # assume scanner-only until proven otherwise
    has_reproduction_steps = False
    has_successful_exploit = False

    for item in evidence:
        eid = item.get("evidence_id", "unknown")
        etype = item.get("evidence_type", "unknown")
        desc = item.get("description", "")
        content = item.get("content", "") or ""

        evidence_items_reviewed.append(eid)

        if etype in ("manual_observation", "reproduction_steps", "command", "command_output"):
            has_manual_exploit = True
            has_scanner_only = False

        if etype == "reproduction_steps":
            has_reproduction_steps = True

        # Check for exploitation confirmation signals in content
        content_lower = (desc + " " + content).lower()
        exploit_signals = [
            "successfully", "confirmed", "verified", "authenticated",
            "gained access", "enumerated", "established", "accepted",
        ]
        if any(s in content_lower for s in exploit_signals):
            has_successful_exploit = True
            supported_claims.append(f"Evidence {eid}: exploitation demonstrated")

        # Check for explicit "no exploitation" signals
        no_exploit_signals = [
            "no evidence was found", "no successful exploitation",
            "could not be recovered", "not demonstrated",
            "insufficient to confirm", "could not exploit",
        ]
        if any(s in content_lower for s in no_exploit_signals):
            unsupported_claims.append(f"Evidence {eid}: no successful exploitation demonstrated")
            comments.append(_make_comment(
                "EVID-002", "warning", "evidence",
                f"Evidence item {eid} indicates exploitation was NOT demonstrated",
                evidence_reference=eid,
                suggested_action="confirm_classification_as_potential_issue",
            ))

    # Check if exploitation section exists but is empty/weak
    if not evidence:
        missing_evidence.append("No exploitation evidence provided at all")
        is_sufficient = None
        comments.append(_make_comment(
            "EVID-003", "error", "evidence",
            "Finding has no exploitation evidence — classification cannot be Confirmed",
            suggested_action="provide_exploitation_evidence_or_downgrade",
        ))
    elif has_successful_exploit and has_manual_exploit:
        is_sufficient = True
        supported_claims.append("Manual exploitation with successful outcome confirmed")
    elif has_manual_exploit and not has_successful_exploit:
        is_sufficient = False
        missing_evidence.append("Manual testing performed but successful exploitation not demonstrated")
        comments.append(_make_comment(
            "EVID-004", "warning", "evidence",
            "Evidence shows manual testing but no successful exploitation — consider Potential Issue",
            suggested_action="evaluate_evidence_strength_for_classification",
        ))
    elif has_scanner_only:
        is_sufficient = False
        missing_evidence.append("Only scanner output — no manual verification")
        comments.append(_make_comment(
            "EVID-005", "warning", "evidence",
            "Evidence is scanner-only — requires manual verification before confirming",
            suggested_action="perform_manual_verification",
        ))
    else:
        is_sufficient = False

    sub_review = {
        "is_sufficient": is_sufficient,
        "evidence_items_reviewed": evidence_items_reviewed,
        "supported_claims": supported_claims,
        "unsupported_claims": unsupported_claims,
        "missing_evidence": missing_evidence,
        "comments": [c["message"] for c in comments],
    }

    return sub_review, comments


# ══════════════════════════════════════════════
# CLASS — Classification Review
# ══════════════════════════════════════════════

def check_classification(finding: dict, evidence_review: dict) -> tuple[dict, list[dict]]:
    """
    Determine the correct classification label based on evidence strength.
    
    Key rule:
    - If exploitation demonstrated AND evidence supports → Confirmed Vulnerability
    - If exploitation NOT demonstrated → Potential Issue (NEVER Confirmed)
    """
    comments = []
    severity = finding.get("severity")

    is_sufficient = evidence_review.get("is_sufficient")
    unsupported = evidence_review.get("unsupported_claims", [])

    # Determine classification
    if is_sufficient is True and not unsupported:
        label = "confirmed_vulnerability"
        rationale = "Exploitation demonstrated and evidence sufficiently supports the vulnerability claim."
        supported_by_evidence = True
    elif is_sufficient is False or unsupported:
        label = "potential_issue"
        rationale = "Exploitation was not fully demonstrated or evidence is insufficient to confirm the vulnerability."
        supported_by_evidence = False
        comments.append(_make_comment(
            "CLASS-001", "warning", "classification",
            "Evidence does not support Confirmed Vulnerability — classified as Potential Issue",
            suggested_action="provide_additional_evidence_to_confirm",
        ))
    else:
        # is_sufficient is None — no evidence at all
        label = "potential_issue"
        rationale = "No sufficient evidence to confirm the vulnerability. Classification defaults to Potential Issue."
        supported_by_evidence = False
        comments.append(_make_comment(
            "CLASS-002", "error", "classification",
            "No evidence to support any classification — defaulting to Potential Issue",
            suggested_action="provide_evidence_or_mark_as_informational",
        ))

    sub_review = {
        "label": label,
        "rationale": rationale,
        "supported_by_evidence": supported_by_evidence,
    }

    return sub_review, comments


# ══════════════════════════════════════════════
# SEV — Severity Review
# ══════════════════════════════════════════════

def check_severity(finding: dict) -> tuple[dict, list[dict]]:
    """
    Compare reported severity against CVSS score and evidence impact.
    Flag mismatch without changing the reported value.
    NEVER auto-correct.
    """
    comments = []
    reported = finding.get("severity")
    cvss = finding.get("cvss", {})
    score = cvss.get("score")

    # Determine CVSS-implied severity
    cvss_implied = _cvss_score_to_severity(score)

    is_consistent = reported == cvss_implied if (reported and cvss_implied) else None
    change_recommended = False
    suggested = reported

    if reported and cvss_implied and reported != cvss_implied:
        change_recommended = True
        suggested = cvss_implied
        comments.append(_make_comment(
            "SEV-001", "warning", "severity",
            f"Severity mismatch: reported='{reported}', CVSS {score} implies '{cvss_implied}'",
            suggested_action="review_with_human",
        ))

    if not reported:
        comments.append(_make_comment(
            "SEV-002", "warning", "severity",
            "Severity is not specified",
            suggested_action="assign_severity",
        ))

    sub_review = {
        "reported_severity": reported,
        "suggested_severity": suggested if change_recommended else reported,
        "is_consistent": is_consistent,
        "change_recommended": change_recommended,
        "rationale": (
            f"CVSS {score} maps to '{cvss_implied}', reported severity is '{reported}'. "
            f"Mismatch flagged for human review." if change_recommended
            else f"Reported severity '{reported}' is consistent with CVSS score {score}."
            if is_consistent else "Could not determine consistency."
        ),
    }

    return sub_review, comments


def _cvss_score_to_severity(score: float | None) -> str | None:
    """Map CVSS score to severity level."""
    if score is None:
        return None
    for level, (lo, hi) in CVSS_RANGES.items():
        if lo <= score <= hi:
            return level
    return "unknown"


# ══════════════════════════════════════════════
# CVSS — CVSS Review
# ══════════════════════════════════════════════

def check_cvss(finding: dict) -> tuple[dict, list[dict]]:
    """
    Validate CVSS vector structure, metric values, and score calculation.
    """
    comments = []
    cvss = finding.get("cvss", {})
    version = cvss.get("version")
    score = cvss.get("score")
    vector = cvss.get("vector") or ""

    # Validate vector format
    vector_is_valid = False
    if vector:
        # CVSS 3.1 base vector pattern
        pattern = r"^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HNL]/I:[HNL]/A:[HNL]"
        vector_is_valid = bool(re.match(pattern, vector))
        if not vector_is_valid:
            comments.append(_make_comment(
                "CVSS-001", "warning", "cvss.vector",
                f"CVSS vector format is invalid or uses temporal/environmental metrics: {vector}",
                suggested_action="verify_cvss_vector",
            ))

    # Check score vs vector (basic: for 3.1, we trust the reported score)
    score_matches_vector = None  # Would need CVSS calculator to verify exactly

    # Check severity vs score
    reported_sev = finding.get("severity")
    cvss_implied = _cvss_score_to_severity(score)
    severity_matches_score = (reported_sev == cvss_implied) if (reported_sev and cvss_implied) else None

    if severity_matches_score is False:
        comments.append(_make_comment(
            "CVSS-002", "warning", "cvss.score",
            f"CVSS score {score} ({cvss_implied}) does not match reported severity '{reported_sev}'",
            suggested_action="review_with_human",
        ))

    requires_manual_recalculation = not vector_is_valid

    sub_review = {
        "reported_version": version,
        "reported_score": score,
        "reported_vector": vector,
        "vector_is_valid": vector_is_valid,
        "score_matches_vector": score_matches_vector,
        "severity_matches_score": severity_matches_score,
        "requires_manual_recalculation": requires_manual_recalculation,
        "comments": [c["message"] for c in comments],
    }

    return sub_review, comments


# ══════════════════════════════════════════════
# CWE — CWE Review
# ══════════════════════════════════════════════

def check_cwe(finding: dict) -> tuple[dict, list[dict]]:
    """
    Validate CWE ID format and check alignment with finding title.
    """
    comments = []
    cwe_id = finding.get("cwe_id")
    title = finding.get("title", "").lower()

    is_relevant = None
    suggested_cwe = None

    if cwe_id:
        # Check format
        if not re.match(r"^CWE-[0-9]+$", cwe_id):
            comments.append(_make_comment(
                "CWE-001", "warning", "cwe_id",
                f"CWE ID format is invalid: {cwe_id}",
                suggested_action="correct_cwe_id_format",
            ))
        else:
            # Basic relevance check — CWE-to-keyword mapping
            cwe_keywords = {
                "CWE-798": ["hardcoded", "hard-coded", "credential", "password"],
                "CWE-327": ["crypto", "algorithm", "signing", "jwt", "symmetric", "broken"],
                "CWE-693": ["protection", "mechanism", "root", "detection", "bypass"],
                "CWE-295": ["certificate", "ssl", "tls", "pinning", "validation"],
                "CWE-204": ["enumeration", "response", "discrepancy", "observable"],
            }
            keywords = cwe_keywords.get(cwe_id, [])
            if keywords:
                matched = any(kw in title for kw in keywords)
                is_relevant = matched
                if not matched:
                    comments.append(_make_comment(
                        "CWE-002", "suggestion", "cwe_id",
                        f"CWE {cwe_id} may not align with finding title — no matching keywords found",
                        suggested_action="verify_cwe_relevance",
                    ))
    else:
        comments.append(_make_comment(
            "CWE-003", "warning", "cwe_id",
            "No CWE ID assigned",
            suggested_action="assign_cwe_id",
        ))

    sub_review = {
        "reported_cwe": cwe_id,
        "is_relevant": is_relevant,
        "suggested_cwe": suggested_cwe,
        "rationale": (
            f"CWE {cwe_id} keywords found in finding title." if is_relevant
            else f"CWE {cwe_id} relevance could not be confirmed." if is_relevant is False
            else "No CWE ID to evaluate."
        ),
    }

    return sub_review, comments


# ══════════════════════════════════════════════
# IMP — Impact Review
# ══════════════════════════════════════════════

def check_impact(finding: dict) -> tuple[dict, list[dict]]:
    """
    Evaluate whether the impact description accurately reflects
    the potential consequences.
    """
    comments = []
    impact = finding.get("impact")
    evidence = finding.get("evidence", [])
    severity = finding.get("severity")

    is_supported = None
    is_proportionate = None
    unsupported_claims = []

    if impact:
        # Basic checks
        impact_lower = impact.lower()

        # Check if impact mentions are supported by evidence
        impact_keywords = ["unauthorized", "data", "access", "exposure", "bypass", "compromise"]
        evidence_text = " ".join(
            (e.get("description", "") + " " + (e.get("content", "") or ""))
            for e in evidence
        ).lower()

        for kw in impact_keywords:
            if kw in impact_lower and kw not in evidence_text:
                unsupported_claims.append(f"Impact mentions '{kw}' but evidence does not confirm")

        is_supported = len(unsupported_claims) == 0

        # Check proportionality: severity vs impact language
        high_severity_words = ["critical", "severe", "catastrophic", "complete"]
        if severity in ("critical", "high") and not any(w in impact_lower for w in high_severity_words):
            is_proportionate = False
            comments.append(_make_comment(
                "IMP-001", "suggestion", "impact",
                "High severity finding has mild impact language — consider strengthening impact description",
                suggested_action="review_impact_description",
            ))
        else:
            is_proportionate = True
    else:
        unsupported_claims.append("No impact description provided")
        comments.append(_make_comment(
            "IMP-002", "warning", "impact",
            "Impact description is missing",
            suggested_action="describe_impact",
        ))

    sub_review = {
        "is_supported_by_evidence": is_supported,
        "is_proportionate": is_proportionate,
        "unsupported_impact_claims": unsupported_claims,
        "comments": [c["message"] for c in comments],
    }

    return sub_review, comments


# ══════════════════════════════════════════════
# REC — Recommendation Review
# ══════════════════════════════════════════════

def check_recommendation(finding: dict) -> tuple[dict, list[dict]]:
    """
    Assess whether the recommendation addresses the root cause
    and provides actionable steps.
    """
    comments = []
    recommendation = finding.get("recommendation", [])
    cwe_id = finding.get("cwe_id")
    observation = finding.get("observation", "") or ""

    addresses_root_cause = None
    is_actionable = None
    is_technically_relevant = None
    missing_recommendations = []

    if recommendation:
        # Join all recommendation items
        rec_text = " ".join(recommendation).lower()

        # Check for actionable indicators
        actionable_indicators = [
            "implement", "remove", "rotate", "replace", "migrate",
            "configure", "update", "upgrade", "enforce", "restrict",
            "apply", "deploy", "disable", "enable", "use",
        ]
        is_actionable = any(ind in rec_text for ind in actionable_indicators)
        if not is_actionable:
            comments.append(_make_comment(
                "REC-001", "warning", "recommendation",
                "Recommendation lacks actionable steps — appears generic",
                suggested_action="add_specific_actionable_steps",
            ))

        # Check root cause alignment with CWE
        root_cause_map = {
            "CWE-798": ["remove", "credential", "secret", "hardcoded", "environment variable", "vault"],
            "CWE-327": ["asymmetric", "rs256", "es256", "replace", "algorithm", "key management"],
            "CWE-693": ["implement", "root detection", "safety net", "attestation", "integrity"],
            "CWE-295": ["certificate", "pinning", "validation", "ssl", "trust", "fingerprint"],
            "CWE-204": ["consistent", "error message", "response", "generic", "normalize"],
        }
        root_keywords = root_cause_map.get(cwe_id, [])
        if root_keywords:
            addresses_root_cause = any(kw in rec_text for kw in root_keywords)
            if not addresses_root_cause:
                missing_recommendations.append(f"Recommendation may not address root cause for {cwe_id}")
                comments.append(_make_comment(
                    "REC-002", "warning", "recommendation",
                    f"Recommendation may not address the root cause ({cwe_id})",
                    suggested_action="add_root_cause_remediation",
                ))
        else:
            addresses_root_cause = None  # Can't determine

        # Check technical relevance
        is_technically_relevant = True  # Assume relevant if present
    else:
        missing_recommendations.append("No recommendation provided")
        comments.append(_make_comment(
            "REC-003", "error", "recommendation",
            "No recommendation or remediation provided",
            suggested_action="add_recommendation",
        ))

    sub_review = {
        "addresses_root_cause": addresses_root_cause,
        "is_actionable": is_actionable,
        "is_technically_relevant": is_technically_relevant,
        "missing_recommendations": missing_recommendations,
        "comments": [c["message"] for c in comments],
    }

    return sub_review, comments


# ══════════════════════════════════════════════
# RET — Retest Review
# ══════════════════════════════════════════════

def check_retest(finding: dict) -> tuple[dict, list[dict]]:
    """
    Check retest status and verification result.
    Findings without retest are flagged for follow-up but not blocked.
    """
    comments = []
    retest = finding.get("retest", {})
    applicable = retest.get("applicable")
    status = retest.get("status")
    verification = retest.get("verification_result")
    retest_evidence = retest.get("evidence", [])

    status_supported_by_evidence = None
    missing_retest_evidence = []

    if applicable is False:
        # Not applicable — OK
        pass
    elif status == "not_retested" or status is None or applicable is None:
        comments.append(_make_comment(
            "RET-001", "suggestion", "retest",
            "Finding has not been retested — retest status is empty or not_retested",
            suggested_action="schedule_retest",
        ))
        missing_retest_evidence.append("No retest performed")
    elif status in ("fixed", "partially_fixed", "not_fixed", "accepted_risk"):
        # Has retest status — check if supported by evidence
        if retest_evidence:
            status_supported_by_evidence = True
        else:
            status_supported_by_evidence = False
            missing_retest_evidence.append(f"Retest status is '{status}' but no retest evidence provided")
            comments.append(_make_comment(
                "RET-002", "warning", "retest",
                f"Retest marked as '{status}' but no retest evidence provided",
                suggested_action="provide_retest_evidence",
            ))
    else:
        # Unknown status
        if status:
            comments.append(_make_comment(
                "RET-003", "warning", "retest",
                f"Unrecognized retest status: '{status}'",
                suggested_action="verify_retest_status",
            ))

    sub_review = {
        "applicable": applicable,
        "reported_status": status,
        "status_supported_by_evidence": status_supported_by_evidence,
        "missing_retest_evidence": missing_retest_evidence,
        "comments": [c["message"] for c in comments],
    }

    return sub_review, comments