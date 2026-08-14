"""Configuration constants for the EVVO SLM Harness.

All review parameters, thresholds, taxonomy mappings, and version
identifiers are centralised here so that every module references a
single source of truth.
"""

from __future__ import annotations

# ── CVSS Severity Ranges ──────────────────────────────────────────────
# Maps each severity label to its (low, high) inclusive score range.
CVSS_RANGES: dict[str, tuple[float, float]] = {
    "critical":      (9.0, 10.0),
    "high":          (7.0,  8.9),
    "medium":        (4.0,  6.9),
    "low":           (0.1,  3.9),
    "informational": (0.0,  0.0),
}


# ── Confidence Weights ────────────────────────────────────────────────
CONFIDENCE_WEIGHTS: dict[str, float] = {
    "evidence_completeness":        0.35,
    "classification_certainty":    0.25,
    "cvss_severity_consistency":   0.15,
    "section_completeness":        0.15,
    "retest_availability":         0.10,
}


# ── Escalation Thresholds ─────────────────────────────────────────────
ESCALATION_THRESHOLD: float = 0.7
EVIDENCE_COMPLETENESS_ESCALATION_THRESHOLD: float = 0.5


# ── Classification Labels ─────────────────────────────────────────────
CLASSIFICATION_LABELS: list[str] = [
    "confirmed_vulnerability",
    "potential_issue",
    "informational",
    "false_positive",
    "undetermined",
]


# ── Review Statuses ───────────────────────────────────────────────────
REVIEW_STATUSES: list[str] = [
    "pass",
    "needs_revision",
    "human_review",
]


# ── Severity Levels ───────────────────────────────────────────────────
SEVERITY_LEVELS: list[str] = [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
]


# ── Required Input Fields (Input Schema v0.2) ─────────────────────────
# The 16 top-level fields every normalised finding must contain.
REQUIRED_INPUT_FIELDS: list[str] = [
    "schema_version",
    "finding_id",
    "title",
    "severity",
    "affected_targets",
    "affected_user_roles",
    "cwe_id",
    "cvss",
    "impact",
    "observation",
    "evidence",
    "recommendation",
    "retest",
    "references",
    "source",
    "governance",
]


# ── Required Review Sections ──────────────────────────────────────────
REQUIRED_SECTIONS: list[str] = [
    "observation",
    "evidence",
    "recommendation",
]


# ── Taxonomy Codes ────────────────────────────────────────────────────
# 11 codes from the review taxonomy mapping code → human-readable name.
TAXONOMY_CODES: dict[str, str] = {
    "COMP": "Completeness Review",
    "EVID": "Evidence Review",
    "CLASS": "Classification Review",
    "SEV":  "Severity Review",
    "CVSS": "CVSS Review",
    "CWE":  "CWE Review",
    "IMP":  "Impact Review",
    "REC":  "Recommendation Review",
    "RET":  "Retest Review",
    "CONS": "Consistency Review",
    "CONF": "Confidence Scoring",
}


# ── Taxonomy Code → Output Category Mapping ───────────────────────────
# Maps each taxonomy code to its corresponding output_schema category enum
# value used in review_comments[].category.
TAXONOMY_CATEGORIES: dict[str, str] = {
    "COMP": "completeness",
    "EVID": "evidence",
    "CLASS": "classification",
    "SEV":  "severity",
    "CVSS": "cvss",
    "CWE":  "cwe",
    "IMP":  "impact",
    "REC":  "recommendation",
    "RET":  "retest",
    "CONS": "consistency",
    "CONF": "governance",
}


# ── Governance Constants ──────────────────────────────────────────────
GOVERNANCE_ALLOWED_REDACTION = {
    "provider_preprocessed",
    "automated_check_passed",
    "manual_check_passed",
    "not_applicable",
}

GOVERNANCE_ALLOWED_USAGE_SCOPES = {
    "internal",
    "evaluation_only",
}

GOVERNANCE_ALLOWED_DATA_CLASSIFICATIONS = {
    "public",
    "internal",
    "confidential",
}

GOVERNANCE: dict[str, object] = {
    "ACCEPTABLE_REDACTION_STATUSES": GOVERNANCE_ALLOWED_REDACTION,
    "ACCEPTABLE_USAGE_SCOPES": GOVERNANCE_ALLOWED_USAGE_SCOPES,
    "ALLOWED_DATA_CLASSIFICATIONS": GOVERNANCE_ALLOWED_DATA_CLASSIFICATIONS,
}


# ── Pipeline & Schema Versions ────────────────────────────────────────
PIPELINE_VERSION: str = "0.2.0"
RULESET_VERSION: str = "1.0"
KNOWLEDGE_BASE_VERSION: str = "1.0"