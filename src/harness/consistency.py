import re
from typing import Any

from .config import CVSS_RANGES
from .rule_checks import _make_comment, _cvss_score_to_severity


# ── Shared constants for keyword extraction ─────────────────────────────

_STOP_WORDS: frozenset[str] = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "in", "on", "at", "to", "for", "of", "with", "by", "from", "as",
    "and", "or", "but", "not", "no", "nor", "so", "yet", "both",
    "this", "that", "these", "those", "it", "its", "has", "have", "had",
    "do", "does", "did", "will", "would", "could", "should", "may",
    "can", "shall", "must", "might", "need", "dare", "ought", "used",
    "during", "use", "weak", "hardcoded", "which", "their", "there",
    "also", "than", "then", "if", "when", "where", "how", "what",
    "all", "each", "every", "any", "some", "such", "only", "own",
    "same", "other", "into", "through", "about", "up", "out",
    "page", "section", "found", "identified", "test", "testing",
    "performed", "conducted", "review", "assessment", "vulnerability",
    "vulnerable", "finding", "report", "issue", "target", "system",
    "application", "server", "client", "user", "data", "information",
})

# Severity-appropriate impact language.
# Each severity level maps to keywords that should appear in the impact
# description when that severity is justified.
_SEVERITY_IMPACT_KEYWORDS: dict[str, list[str]] = {
    "critical": [
        "unauthorized access", "data breach", "remote code execution",
        "rce", "full control", "takeover", "compromise", "arbitrary",
        "complete", "total", "entire system", "critical", "catastrophic",
        "root", "administrator", "privilege", "database", "all users",
    ],
    "high": [
        "unauthorized", "sensitive data", "privilege escalation",
        "injection", "bypass", "exposure", "compromise",
        "significant", "serious", "major", "exploit",
    ],
    "medium": [
        "partial", "limited", "moderate", "some",
        "information disclosure", "specific", "certain users",
    ],
    "low": [
        "minor", "cosmetic", "minimal", "negligible",
        "low risk", "little", "small",
    ],
    "informational": [
        "informational", "best practice", "recommendation",
        "no direct impact", "no security impact", "advisory",
    ],
}

# Strong impact indicators — if present in impact text, they suggest
# at least HIGH severity.  Used to detect severity under-statement.
_STRONG_IMPACT_INDICATORS: list[str] = [
    "remote code execution", "rce", "arbitrary code", "full control",
    "takeover", "compromise", "data breach", "unauthorized access",
    "privilege escalation", "root access", "administrator access",
    "sensitive data", "database", "all users", "entire system",
]

# Weak impact indicators — if impact text ONLY contains these, the
# finding probably should not be critical or high.
_WEAK_IMPACT_INDICATORS: list[str] = [
    "minor", "cosmetic", "negligible", "informational", "best practice",
    "no direct impact", "no security impact", "low risk", "advisory",
]

# Generic recommendation phrases that don't address any specific root cause.
_GENERIC_REC_PHRASES: list[str] = [
    "follow best practices", "ensure security", "review security",
    "update to latest", "apply security patches", "implement security measures",
    "follow security guidelines", "conduct security review",
]


# ═══════════════════════════════════════════════════════════════════════
#  Main entry point
# ═══════════════════════════════════════════════════════════════════════

def check_consistency(
    finding: dict,
    evidence_review: dict,
    severity_review: dict,
    classification_review: dict,
) -> tuple[dict, list[dict]]:
    """
    Run all cross-field consistency checks (8 rules).

    Checks:
      CONS-001  severity_cvss_alignment          (existing)
      CONS-002  evidence_classification_alignment  (existing)
      CONS-003  title_content_alignment            (existing — title vs observation)
      CONS-004  recommendation_root_cause          (enhanced)
      CONS-005  title_evidence_alignment           (new — title vs evidence)
      CONS-006  evidence_description_alignment     (new — evidence vs observation)
      CONS-007  impact_severity_alignment          (new — impact vs severity)
      CONS-008  report_summary                     (new — aggregated summary)

    Returns:
        (sub_review, comments)
        sub_review = {"is_consistent": bool, "issues": [str, ...]}
    """
    comments = []
    issues = []
    is_consistent = True

    # ── 1. CONS-001: severity_cvss_alignment ──
    sev_issue = _check_severity_cvss_alignment(finding)
    if sev_issue:
        issues.append(sev_issue)
        is_consistent = False
        comments.append(_make_comment(
            "CONS-001", "warning", "severity",
            sev_issue,
            suggested_action="review_with_human",
        ))

    # ── 2. CONS-002: evidence_classification_alignment ──
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

    # ── 3. CONS-003: title_content_alignment (title vs observation) ──
    title_obs_issue = _check_title_content_alignment(finding)
    if title_obs_issue:
        issues.append(title_obs_issue)
        # Suggestion only — don't mark overall as inconsistent
        comments.append(_make_comment(
            "CONS-003", "suggestion", "title",
            title_obs_issue,
            suggested_action="review_title_accuracy",
        ))

    # ── 4. CONS-004: recommendation_root_cause (enhanced) ──
    rec_issue = _check_recommendation_root_cause_alignment(finding, severity_review)
    if rec_issue:
        issues.append(rec_issue)
        comments.append(_make_comment(
            "CONS-004", "suggestion", "recommendation",
            rec_issue,
            suggested_action="strengthen_recommendation",
        ))

    # ── 5. CONS-005: title_evidence_alignment (title vs evidence) ──
    title_evid_issue = _check_title_evidence_alignment(finding)
    if title_evid_issue:
        issues.append(title_evid_issue)
        is_consistent = False
        comments.append(_make_comment(
            "CONS-005", "warning", "title",
            title_evid_issue,
            suggested_action="verify_title_matches_evidence",
        ))

    # ── 6. CONS-006: evidence_description_alignment (evidence vs observation) ──
    evid_desc_issue = _check_evidence_description_alignment(finding)
    if evid_desc_issue:
        issues.append(evid_desc_issue)
        is_consistent = False
        comments.append(_make_comment(
            "CONS-006", "warning", "evidence",
            evid_desc_issue,
            suggested_action="verify_evidence_relevance",
        ))

    # ── 7. CONS-007: impact_severity_alignment ──
    impact_sev_issue = _check_impact_severity_alignment(finding)
    if impact_sev_issue:
        issues.append(impact_sev_issue)
        is_consistent = False
        comments.append(_make_comment(
            "CONS-007", "warning", "impact",
            impact_sev_issue,
            suggested_action="align_impact_with_severity",
        ))

    # ── 8. CONS-008: report_summary (aggregated consistency assessment) ──
    summary_comment = _compute_consistency_summary(issues, is_consistent)
    if summary_comment:
        comments.append(_make_comment(
            "CONS-008", "info", "consistency",
            summary_comment,
            suggested_action="review_all_consistency_flags",
        ))

    sub_review = {
        "is_consistent": is_consistent,
        "issues": issues,
    }

    return sub_review, comments


# ═══════════════════════════════════════════════════════════════════════
#  CONS-001: severity_cvss_alignment (existing)
# ═══════════════════════════════════════════════════════════════════════

def _check_severity_cvss_alignment(finding: dict) -> str | None:
    """Check if severity aligns with CVSS score."""
    severity = finding.get("severity")
    score = finding.get("cvss", {}).get("score")
    implied = _cvss_score_to_severity(score)

    if severity and implied and severity != implied:
        return f"Reported severity '{severity}' does not match CVSS {score} (implies '{implied}')"
    return None


# ═══════════════════════════════════════════════════════════════════════
#  CONS-002: evidence_classification_alignment (existing)
# ═══════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════
#  CONS-003: title_content_alignment (existing — title vs observation)
# ═══════════════════════════════════════════════════════════════════════

def _check_title_content_alignment(finding: dict) -> str | None:
    """Check that title reflects finding observation content."""
    title = (finding.get("title") or "").lower()
    observation = (finding.get("observation") or "").lower()

    if not title or not observation:
        return None

    title_words = _extract_keywords(title)
    if not title_words:
        return None

    matches = sum(1 for w in title_words if w in observation)
    if matches / len(title_words) < 0.2:
        return (
            f"Finding title keywords are barely reflected in observation content "
            f"({matches}/{len(title_words)} matches)"
        )
    return None


# ═══════════════════════════════════════════════════════════════════════
#  CONS-004: recommendation_root_cause (enhanced)
# ═══════════════════════════════════════════════════════════════════════

def _check_recommendation_root_cause_alignment(
    finding: dict,
    severity_review: dict,
) -> str | None:
    """
    Check if recommendation addresses the actual root cause.

    Enhanced logic (v2):
      1. Detect generic recommendation phrases (original check).
      2. Extract vulnerability-specific terms from title and observation.
      3. Verify that the recommendation mentions at least one specific term.
      4. If recommendation is entirely generic with no specific references, flag it.
    """
    recommendation = finding.get("recommendation", [])
    observation = (finding.get("observation") or "").lower()
    title = (finding.get("title") or "").lower()

    if not recommendation or (not observation and not title):
        return None

    rec_text = " ".join(str(r) for r in recommendation).lower()
    source_text = f"{title} {observation}"

    # 1. Generic phrase detection (original)
    generic_hits = [p for p in _GENERIC_REC_PHRASES if p in rec_text]

    # 2. Extract specific technical terms from the finding
    source_keywords = _extract_keywords(source_text)
    # Keep only terms that are likely technical/specific (length >= 4)
    specific_terms = [w for w in source_keywords if len(w) >= 4]

    # 3. Check if recommendation mentions any specific term
    specific_matches = [t for t in specific_terms if t in rec_text]

    # 4. Decision
    if generic_hits and not specific_matches:
        return (
            "Recommendation contains only generic advice (e.g., '" + generic_hits[0] + "') "
            "and does not reference any specific vulnerability terms from the finding. "
            "Recommendation should address the specific root cause."
        )

    if not generic_hits and not specific_matches:
        # No generic phrases but also no specific terms matched —
        # recommendation may be off-topic
        return (
            "Recommendation does not reference any specific vulnerability terms "
            "from the finding. Verify that the remediation addresses the root cause."
        )

    return None


# ═══════════════════════════════════════════════════════════════════════
#  CONS-005: title_evidence_alignment (new — title vs evidence)
# ═══════════════════════════════════════════════════════════════════════

def _check_title_evidence_alignment(finding: dict) -> str | None:
    """
    Check that the finding title is reflected in the evidence content.

    Unlike CONS-003 (title vs observation), this checks title against
    what the evidence actually demonstrates.  A title claiming 'SQL Injection'
    should have evidence containing SQL-related content.

    Detection approach:
      - Extract meaningful keywords from title.
      - Concatenate all evidence description + content into one text.
      - Require at least 25% of title keywords to appear in evidence.
      - Completely absent keywords → stronger issue.
    """
    title = (finding.get("title") or "").lower()
    evidence = finding.get("evidence", [])

    if not title or not evidence:
        return None

    title_words = _extract_keywords(title)
    if not title_words:
        return None

    # Build combined evidence text
    evidence_text_parts = []
    for item in evidence:
        desc = (item.get("description") or "").lower()
        content = (item.get("content") or "").lower()
        evidence_text_parts.append(f"{desc} {content}")
    evidence_text = " ".join(evidence_text_parts)

    if not evidence_text.strip():
        return None

    matches = sum(1 for w in title_words if w in evidence_text)
    ratio = matches / len(title_words) if title_words else 0

    if ratio == 0:
        # No title keywords at all in evidence — strong mismatch
        return (
            f"None of the title keywords appear in evidence content "
            f"(0/{len(title_words)} matches). Title may not describe what "
            f"the evidence actually demonstrates."
        )

    if ratio < 0.25:
        return (
            f"Title keywords are poorly reflected in evidence content "
            f"({matches}/{len(title_words)} matches, {ratio:.0%}). "
            f"Verify that the title accurately describes the evidence."
        )

    return None


# ═══════════════════════════════════════════════════════════════════════
#  CONS-006: evidence_description_alignment (new — evidence vs observation)
# ═══════════════════════════════════════════════════════════════════════

def _check_evidence_description_alignment(finding: dict) -> str | None:
    """
    Check that evidence items are relevant to the finding description.

    Detects the 'unrelated evidence' hard negative case where evidence
    from a different finding is attached to this one.

    Detection approach:
      - Extract key terms from observation (the finding description).
      - For each evidence item, check overlap with observation key terms.
      - If ALL evidence items have zero overlap → strong issue (all unrelated).
      - If SOME evidence items have zero overlap → weaker issue (partially unrelated).
      - Evidence with evidence_type='scanner_output' gets a lower bar since
        scanner output may use different terminology.
    """
    observation = (finding.get("observation") or "").lower()
    title = (finding.get("title") or "").lower()
    evidence = finding.get("evidence", [])

    if not evidence or (not observation and not title):
        return None

    # Extract key terms from the finding description
    source_text = f"{title} {observation}"
    source_keywords = _extract_keywords(source_text)
    if not source_keywords:
        return None

    # Check each evidence item
    unrelated_items = []
    related_count = 0

    for item in evidence:
        eid = item.get("evidence_id", "unknown")
        etype = item.get("evidence_type", "unknown")
        desc = (item.get("description") or "").lower()
        content = (item.get("content") or "").lower()
        item_text = f"{desc} {content}"

        # Check overlap
        matches = sum(1 for kw in source_keywords if kw in item_text)
        overlap_ratio = matches / len(source_keywords) if source_keywords else 0

        # Scanner output gets a lower threshold (may use different terminology)
        threshold = 0.05 if etype == "scanner_output" else 0.1

        if overlap_ratio < threshold:
            unrelated_items.append(eid)
        else:
            related_count += 1

    # Decision
    if unrelated_items and related_count == 0:
        # ALL evidence items are unrelated — strong issue
        return (
            f"None of the {len(evidence)} evidence items contain keywords "
            f"matching the finding description. Unrelated items: "
            f"{', '.join(unrelated_items)}. Evidence may belong to a different finding."
        )

    if unrelated_items and related_count > 0:
        # Some evidence items are unrelated — weaker issue
        return (
            f"{len(unrelated_items)} of {len(evidence)} evidence items appear "
            f"unrelated to the finding description. Unrelated items: "
            f"{', '.join(unrelated_items)}. Verify these are attached correctly."
        )

    return None


# ═══════════════════════════════════════════════════════════════════════
#  CONS-007: impact_severity_alignment (new — impact vs severity)
# ═══════════════════════════════════════════════════════════════════════

def _check_impact_severity_alignment(finding: dict) -> str | None:
    """
    Check that impact description is proportionate to severity level.

    Rules:
      - Critical/high severity findings should describe significant impact.
      - Low/informational findings should not describe catastrophic impact.
      - Medium severity findings should describe moderate impact.

    Detection approach:
      1. Check for 'severity under-statement': high/critical severity but
         impact text only contains weak indicators → flag.
      2. Check for 'severity over-statement': low/informational severity but
         impact text contains strong indicators → flag.
      3. Check expected keywords for the reported severity level.
    """
    severity = finding.get("severity")
    impact = finding.get("impact")

    if not severity or not impact:
        return None

    # Normalise impact to string
    if isinstance(impact, list):
        impact_text = " ".join(str(i) for i in impact).lower()
    else:
        impact_text = str(impact).lower()

    if not impact_text.strip():
        return None

    # 1. Severity under-statement: high severity with weak impact language
    if severity in ("critical", "high"):
        strong_hits = [kw for kw in _STRONG_IMPACT_INDICATORS if kw in impact_text]
        # Also check severity-specific keywords
        sev_keywords = _SEVERITY_IMPACT_KEYWORDS.get(severity, [])
        sev_hits = [kw for kw in sev_keywords if kw in impact_text]

        if not strong_hits and not sev_hits:
            return (
                f"Severity is '{severity}' but impact description lacks "
                f"severity-appropriate language. Expected terms like: "
                f"{', '.join(sev_keywords[:5])}. "
                f"Impact may be overstated or the description needs strengthening."
            )

    # 2. Severity over-statement: low severity with strong impact language
    if severity in ("low", "informational"):
        strong_hits = [kw for kw in _STRONG_IMPACT_INDICATORS if kw in impact_text]
        if strong_hits:
            return (
                f"Severity is '{severity}' but impact description contains "
                f"strong impact language: {', '.join(strong_hits[:3])}. "
                f"Impact may be overstated for the assigned severity level."
            )

    # 3. Check expected keywords for the reported severity
    expected_keywords = _SEVERITY_IMPACT_KEYWORDS.get(severity, [])
    if expected_keywords:
        hits = [kw for kw in expected_keywords if kw in impact_text]
        if not hits:
            # No expected keywords found — mild flag
            # Only flag if the impact text is long enough to be meaningful
            if len(impact_text.split()) > 5:
                return (
                    f"Impact description does not contain typical language "
                    f"expected for '{severity}' severity. "
                    f"Review whether the impact description matches the severity level."
                )

    return None


# ═══════════════════════════════════════════════════════════════════════
#  CONS-008: report_summary (new — aggregated consistency assessment)
# ═══════════════════════════════════════════════════════════════════════

def _compute_consistency_summary(issues: list[str], is_consistent: bool) -> str | None:
    """
    Generate an aggregated consistency summary.

    This is a meta-check that does not add a new issue but provides
    a summary comment for the reviewer.

    Summary levels:
      - 0 issues: 'All consistency checks passed'
      - 1-2 issues: 'Minor consistency issues found'
      - 3+ issues: 'Significant consistency issues detected'
    """
    if not issues:
        return "All 8 consistency checks passed — finding is internally consistent."

    count = len(issues)

    if count <= 2:
        # List the CONS codes involved
        return (
            f"{count} minor consistency issue(s) found out of 8 checks. "
            f"Finding is mostly consistent but review the flagged items."
        )

    # 3+ issues — significant
    return (
        f"{count} consistency issues found out of 8 checks. "
        f"Significant inconsistencies detected — this finding requires "
        f"careful review before finalisation."
    )


# ═══════════════════════════════════════════════════════════════════════
#  Shared helpers
# ═══════════════════════════════════════════════════════════════════════

def _extract_keywords(text: str) -> list[str]:
    """
    Extract meaningful keywords from text.

    Strips punctuation, splits on whitespace, removes stop words
    and short tokens (< 3 chars). Returns deduplicated list preserving
    first-occurrence order.
    """
    if not text:
        return []

    # Normalise and split
    cleaned = re.sub(r"[^a-z0-9\s_-]", " ", text.lower())
    tokens = cleaned.split()

    # Filter stop words and short tokens
    seen = set()
    keywords = []
    for token in tokens:
        if len(token) < 3:
            continue
        if token in _STOP_WORDS:
            continue
        if token not in seen:
            seen.add(token)
            keywords.append(token)

    return keywords