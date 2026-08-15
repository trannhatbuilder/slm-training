"""Benchmark v1 generator for the EVVO SLM / Harness project.

Task 09/08 deliverable: 30-50 benchmark cases with gold answers, plus a
reproducible generator script. This script reads the normalized findings
from `data/normalized/DOC-000001-findings-normalized.jsonl`, derives 26
cases by cross-task expansion (5 task types x 5 findings + 1 derived
hard-negative for the no-exploit finding), then loads 8 hand-crafted
hard negatives from `data/benchmark/hand_crafted_negatives.jsonl`. The
combined 34 cases are written to `data/benchmark/benchmark_v1.jsonl`
along with a manifest at `data/benchmark/benchmark_manifest.json`.

Usage:
    python scripts/build_benchmark_v1.py
    python scripts/build_benchmark_v1.py --findings data/normalized/DOC-000001-findings-normalized.jsonl
    python scripts/build_benchmark_v1.py --dry-run

The script is deterministic: running it twice produces byte-identical
case_id values and content_hash values for the same input findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

# ── Repo paths ────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FINDINGS = REPO_ROOT / "data" / "normalized" / "DOC-000001-findings-normalized.jsonl"
HAND_CRAFTED_SOURCE = REPO_ROOT / "data" / "benchmark" / "hand_crafted_negatives.jsonl"
BENCHMARK_OUT = REPO_ROOT / "data" / "benchmark" / "benchmark_v1.jsonl"
MANIFEST_OUT = REPO_ROOT / "data" / "benchmark" / "benchmark_manifest.json"

BENCHMARK_VERSION = "1.0"
TODAY_ISO = date(2026, 8, 15).isoformat()
DOCUMENT_ID = "DOC-000001"

# ── CVSS v3.1 severity bands ──────────────────────────────────────────
CVSS_BANDS: list[tuple[str, float, float]] = [
    ("critical",      9.0, 10.0),
    ("high",          7.0,  8.9),
    ("medium",        4.0,  6.9),
    ("low",           0.1,  3.9),
    ("informational", 0.0,  0.0),
]


def cvss_band(score: float | int | None) -> str:
    """Map a CVSS v3.1 score to its severity band."""
    if score is None:
        return "informational"
    s = float(score)
    for label, lo, hi in CVSS_BANDS:
        if lo <= s <= hi:
            return label
    # Defensive fallback for unexpected scores
    return "informational" if s == 0.0 else "low"


# ── Exploitation markers ──────────────────────────────────────────────
# Positive markers indicate the finding demonstrates successful exploitation.
POSITIVE_MARKERS: list[str] = [
    "authentication succeeds",
    "authentication succeeded",
    "verified that the",
    "successfully intercepted",
    "successfully authenticated",
    "successfully access",
    "successfully exploited",
    "was verified",
    "confirmed that the exposed credentials remain valid",
    "confirmed that the",
    "it was verified",
]

# Negative markers indicate the finding did NOT demonstrate exploitation.
NEGATIVE_MARKERS: list[str] = [
    "no evidence was found",
    "no successful exploitation",
    "not demonstrated",
    "could not be verified",
    "was not verified",
    "no exploitation was performed",
    "not exploited",
    "not exploited during",
    "no manual verification",
    "scanner output only",
    "no manual confirmation",
]


def text_of(evidence: Any) -> str:
    """Flatten an evidence field (string or list of dicts) to lowercase text."""
    if evidence is None:
        return ""
    if isinstance(evidence, str):
        return evidence.lower()
    if isinstance(evidence, list):
        parts: list[str] = []
        for item in evidence:
            if isinstance(item, dict):
                parts.append(str(item.get("content", "")).lower())
                parts.append(str(item.get("description", "")).lower())
            else:
                parts.append(str(item).lower())
        return " ".join(parts)
    return str(evidence).lower()


def has_positive_marker(evidence_text: str, observation_text: str = "") -> bool:
    blob = f"{evidence_text} {observation_text}"
    return any(m in blob for m in POSITIVE_MARKERS)


def has_negative_marker(evidence_text: str, observation_text: str = "") -> bool:
    blob = f"{evidence_text} {observation_text}"
    return any(m in blob for m in NEGATIVE_MARKERS)


def is_scanner_only(finding: dict) -> bool:
    """A finding is scanner-only if no manual verification markers are present."""
    evidence_text = text_of(finding.get("evidence"))
    observation_text = str(finding.get("observation", "")).lower()
    has_manual = has_positive_marker(evidence_text, observation_text)
    has_scanner_marker = any(
        m in evidence_text
        for m in ["scanner", "automated scan", "nmap", "nikto", "zap", "nuclei"]
    )
    return has_scanner_marker and not has_manual


# ── Hashing ───────────────────────────────────────────────────────────
def content_hash(payload: dict) -> str:
    """Deterministic 16-char hex hash of a case's content (excluding the hash field).."""
    clean = {k: v for k, v in payload.items() if k != "metadata"}
    clean_meta = {k: v for k, v in payload.get("metadata", {}).items() if k != "content_hash"}
    clean["metadata"] = clean_meta
    serialized = json.dumps(clean, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


# ── Case ID helpers ───────────────────────────────────────────────────
TASK_PREFIX = {
    "finding_review":                 "FR",
    "severity_review":                "SV",
    "evidence_check":                 "EV",
    "remediation_review":             "RM",
    "client_qa":                      "QA",
    "hard_negative_potential_issue":  "HN",
    "unsupported_refusal":            "UR",
    "false_positive_detection":       "FP",
}


def case_id(task_type: str, index: int) -> str:
    return f"BMC-{TASK_PREFIX[task_type]}-{index:04d}"


# ── Review comment factory ────────────────────────────────────────────
def review_comment(
    cid: str,
    taxonomy: str,
    category: str,
    severity: str,
    field: str,
    message: str,
    action: str | None = None,
) -> dict:
    return {
        "comment_id": cid,
        "taxonomy_code": taxonomy,
        "category": category,
        "severity": severity,
        "field": field,
        "message": message,
        "evidence_reference": None,
        "suggested_action": action,
    }


# ── Per-task case builders ────────────────────────────────────────────
def truncate(text: str, n: int) -> str:
    """Truncate text to n chars with a trailing ellipsis if it was cut."""
    if not text or len(text) <= n:
        return text
    return text[:n] + "..."


def shared_input(finding: dict) -> dict:
    """Full finding input used by finding_review, hard_negative, false_positive."""
    return {
        "finding_id":       finding["finding_id"],
        "title":            finding.get("title", ""),
        "severity":         finding.get("severity", ""),
        "cwe_id":           finding.get("cwe_id"),
        "cvss":             finding.get("cvss", {}),
        "affected_targets": finding.get("affected_targets", []),
        "observation":      finding.get("observation", ""),
        "evidence":         finding.get("evidence", []),
        "recommendation":  finding.get("recommendation", []),
        "impact":           finding.get("impact", ""),
        "retest":           finding.get("retest", {}),
    }


def confidence_block(score: float, basis: list[str], limitations: list[str] | None = None) -> dict:
    level = "high" if score >= 0.85 else ("medium" if score >= 0.65 else "low")
    return {
        "overall_score": round(score, 2),
        "level": level,
        "basis": basis,
        "limitations": limitations or [],
    }


def classification_block(label: str, rationale: str, supported: bool) -> dict:
    return {
        "label": label,
        "rationale": rationale,
        "supported_by_evidence": supported,
    }


def evidence_items(finding: dict) -> list[str]:
    ev = finding.get("evidence", [])
    if isinstance(ev, list):
        return [e.get("evidence_id", "EVID-?") for e in ev if isinstance(e, dict)]
    return []


def retest_is_missing(finding: dict) -> bool:
    rt = finding.get("retest") or {}
    return rt.get("status") is None


# ── Task type: finding_review (full output schema) ───────────────────
def build_finding_review(finding: dict, idx: int) -> dict:
    fid = finding["finding_id"]
    severity = finding.get("severity", "").lower()
    cvss = finding.get("cvss", {}) or {}
    cvss_score = cvss.get("score")
    cvss_vector = cvss.get("vector", "")
    cvss_version = cvss.get("version", "3.1")
    band = cvss_band(cvss_score)
    severity_matches = (severity == band)
    title = finding.get("title", "")

    evidence_text = text_of(finding.get("evidence"))
    observation_text = str(finding.get("observation", "")).lower()
    has_pos = has_positive_marker(evidence_text, observation_text)
    has_neg = has_negative_marker(evidence_text, observation_text)

    if has_neg or not has_pos:
        label = "potential_issue"
        supported = False
        classification_rationale = (
            "Evidence does not clearly demonstrate exploitation; default to "
            "Potential Issue pending manual verification."
        ) if not has_neg else (
            "Finding describes a risk but no successful exploitation was "
            "demonstrated in the evidence."
        )
        evidence_sufficient = False
        unsupported_claims = [title]
        missing_evidence = ["Reproducible exploitation proof"]
        supported_claims: list[str] = []
        is_confirmed = False
    else:
        label = "confirmed_vulnerability"
        supported = True
        classification_rationale = "Exploitation was demonstrated in the evidence section."
        evidence_sufficient = True
        unsupported_claims = []
        missing_evidence = []
        supported_claims = [title]
        is_confirmed = True

    retest_missing = retest_is_missing(finding)

    comments: list[dict] = []
    if not evidence_sufficient:
        comments.append(review_comment(
            "RC-001", "EVID-001", "evidence", "warning", "evidence",
            "Evidence does not demonstrate exploitation; classification downgraded to Potential Issue.",
            "Request reproduction proof or manual verification.",
        ))
    if not severity_matches:
        comments.append(review_comment(
            "RC-002", "SEV-001", "severity", "warning", "severity",
            f"CVSS-severity mismatch: reported '{severity}' but CVSS {cvss_score} implies '{band}'.",
            f"Update reported severity to '{band}' or recompute CVSS.",
        ))
    if retest_missing:
        comments.append(review_comment(
            "RC-003", "RETEST-001", "retest", "info", "retest.status",
            "Retest status is missing.",
            "Schedule retest after remediation.",
        ))

    needs_escalation = (not evidence_sufficient) and (not severity_matches)
    # Confidence rule (matches benchmark_v1.0):
    #   - confirmed AND severity_matches -> 0.85
    #   - otherwise                       -> 0.65
    confidence_score = 0.85 if (is_confirmed and severity_matches) else 0.65

    review_status = "needs_revision" if comments else "pass"
    suggested_severity = band if not severity_matches else severity

    # Difficulty rule (matches benchmark_v1.0):
    #   - confirmed -> easy
    #   - potential -> medium
    difficulty = "easy" if is_confirmed else "medium"

    gold_output = {
        "schema_version": "0.1",
        "review_id": f"REV-FR-{idx:04d}",
        "finding_id": fid,
        "review_status": review_status,
        "classification": classification_block(label, classification_rationale, supported),
        "completeness_review": {
            "is_complete": True,
            "missing_required_fields": [],
            "missing_conditional_fields": (["retest.status"] if retest_missing else []),
            "comments": [],
        },
        "evidence_review": {
            "is_sufficient": evidence_sufficient,
            "evidence_items_reviewed": evidence_items(finding),
            "supported_claims": supported_claims,
            "unsupported_claims": unsupported_claims,
            "missing_evidence": missing_evidence,
            "comments": [],
        },
        "severity_review": {
            "reported_severity": severity,
            "suggested_severity": suggested_severity,
            "is_consistent": severity_matches,
            "change_recommended": (not severity_matches),
            "rationale": f"CVSS {cvss_score} implies '{band}'.",
        },
        "cvss_review": {
            "reported_version": cvss_version,
            "reported_score": cvss_score,
            "reported_vector": cvss_vector,
            "vector_is_valid": True,
            "score_matches_vector": True,
            "severity_matches_score": severity_matches,
            "requires_manual_recalculation": (not severity_matches),
            "comments": [],
        },
        "cwe_review": {
            "reported_cwe": finding.get("cwe_id"),
            "is_relevant": True,
            "suggested_cwe": None,
            "rationale": "CWE mapping is consistent with the observed issue.",
        },
        "impact_review": {
            "is_supported_by_evidence": True,
            "is_proportionate": True,
            "unsupported_impact_claims": [],
            "comments": [],
        },
        "recommendation_review": {
            "addresses_root_cause": True,
            "is_actionable": True,
            "is_technically_relevant": True,
            "missing_recommendations": [],
            "comments": [],
        },
        "consistency_review": {
            "is_consistent": severity_matches and evidence_sufficient,
            "issues": ([] if severity_matches else ["severity-cvss-mismatch"]),
        },
        "retest_review": {
            "applicable": True,
            "reported_status": None,
            "status_supported_by_evidence": (not retest_missing),
            "missing_retest_evidence": (["Retest not performed"] if retest_missing else []),
            "comments": [],
        },
        "review_comments": comments,
        "confidence": confidence_block(
            confidence_score,
            basis=["rule_based_classification", "cvss_severity_check", "evidence_sufficiency_check"],
            limitations=["Single engagement — gold labels are rule-based, not human-validated."],
        ),
        "human_escalation": {
            "required": needs_escalation,
            "reasons": (["evidence_insufficient", "severity_mismatch"] if needs_escalation else []),
            "recommended_reviewer": "senior_pentester",
        },
        "traceability": {
            "source_document_id": DOCUMENT_ID,
            "source_location": {
                "section_title": title,
                "section_number": None,
                "finding_number": int(fid.split("-")[-1]),
                "page_start": None,
                "page_end": None,
            },
            "input_schema_version": "0.2",
            "output_schema_version": "0.1",
            "model_version": None,
            "knowledge_base_version": "1.0",
            "ruleset_version": "1.0",
            "reviewed_at": None,
        },
    }

    # expected_failure_modes is a fixed list per task type (the modes the
    # case is designed to catch), not conditional on the gold answer.
    failure_modes = [
        "wrong_classification_label",
        "missed_severity_cvss_mismatch",
        "hallucinated_evidence",
        "missing_review_comment",
    ]

    return {
        "case_id": case_id("finding_review", idx),
        "task_type": "finding_review",
        "instruction": (
            "Review the following VAPT finding. Assess classification, evidence sufficiency, "
            "severity consistency, completeness, and remediation quality. Produce a structured "
            "review following the output schema."
        ),
        "input": {**shared_input(finding), "observation": truncate(finding.get("observation", ""), 800)},
        "gold_output": gold_output,
        "expected_failure_modes": failure_modes,
        "metadata": {
            "finding_id": fid,
            "document_id": DOCUMENT_ID,
            "engagement_id": DOCUMENT_ID,
            "label_source": "rule_based",
            "difficulty": difficulty,
            "is_hard_negative": False,
            "schema": "output_schema_v0.1_full",
        },
    }


# ── Task type: severity_review ───────────────────────────────────────
def build_severity_review(finding: dict, idx: int) -> dict:
    severity = finding.get("severity", "").lower()
    cvss = finding.get("cvss", {}) or {}
    cvss_score = cvss.get("score")
    cvss_vector = cvss.get("vector", "")
    cvss_version = cvss.get("version", "3.1")
    band = cvss_band(cvss_score)
    matches = (severity == band)

    gold_output = {
        "severity_review": {
            "reported_severity": severity,
            "suggested_severity": band,
            "is_consistent": matches,
            "change_recommended": (not matches),
            "rationale": f"CVSS {cvss_score} implies '{band}'. Reported '{severity}'.",
        },
        "cvss_review": {
            "reported_version": cvss_version,
            "reported_score": cvss_score,
            "reported_vector": cvss_vector,
            "vector_is_valid": True,
            "score_matches_vector": True,
            "severity_matches_score": matches,
            "requires_manual_recalculation": (not matches),
            "comments": [],
        },
        "confidence": confidence_block(
            0.9 if matches else 0.75,
            basis=["cvss_v3.1_band_check"],
            limitations=["Does not assess impact proportionality."],
        ),
    }

    failure_modes = [
        "wrong_severity_suggestion",
        "missed_cvss_severity_mismatch",
        "invalid_cvss_vector_validation",
    ]
    difficulty = "easy" if matches else "medium"

    return {
        "case_id": case_id("severity_review", idx),
        "task_type": "severity_review",
        "instruction": (
            "Assess the reported severity against the CVSS score and vector. Decide whether "
            "the severity is consistent or needs revision."
        ),
        "input": {
            "finding_id": finding["finding_id"],
            "title": finding.get("title", ""),
            "severity": severity,
            "cvss": cvss,
            "impact": finding.get("impact", ""),
        },
        "gold_output": gold_output,
        "expected_failure_modes": failure_modes,
        "metadata": {
            "finding_id": finding["finding_id"],
            "document_id": DOCUMENT_ID,
            "engagement_id": DOCUMENT_ID,
            "label_source": "rule_based",
            "difficulty": difficulty,
            "is_hard_negative": False,
            "schema": "severity_cvss_subset",
        },
    }


# ── Task type: evidence_check ────────────────────────────────────────
def build_evidence_check(finding: dict, idx: int) -> dict:
    title = finding.get("title", "")
    evidence_text = text_of(finding.get("evidence"))
    observation_text = str(finding.get("observation", "")).lower()
    has_pos = has_positive_marker(evidence_text, observation_text)
    has_neg = has_negative_marker(evidence_text, observation_text)
    sufficient = has_pos and not has_neg

    gold_output = {
        "evidence_review": {
            "is_sufficient": sufficient,
            "evidence_items_reviewed": evidence_items(finding),
            "supported_claims": ([title] if sufficient else []),
            "unsupported_claims": ([] if sufficient else [title]),
            "missing_evidence": ([] if sufficient else ["Reproducible exploitation proof"]),
            "comments": [],
        },
        "review_comments": ([] if sufficient else [review_comment(
            "RC-001", "EVID-001", "evidence", "warning", "evidence",
            "Evidence does not demonstrate exploitation.",
            "Request reproduction proof.",
        )]),
        "confidence": confidence_block(
            0.85,
            basis=["evidence_marker_check"],
            limitations=["Marker-based; may miss subtle exploitation language."],
        ),
    }

    failure_modes = [
        "wrong_evidence_sufficiency",
        "hallucinated_evidence",
        "missed_unsupported_claim",
    ]
    difficulty = "medium"

    return {
        "case_id": case_id("evidence_check", idx),
        "task_type": "evidence_check",
        "instruction": (
            "Evaluate whether the exploitation evidence sufficiently supports the vulnerability "
            "claim. List unsupported claims and missing evidence."
        ),
        "input": {
            "finding_id": finding["finding_id"],
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "observation": truncate(finding.get("observation", ""), 600),
            "evidence": finding.get("evidence", []),
        },
        "gold_output": gold_output,
        "expected_failure_modes": failure_modes,
        "metadata": {
            "finding_id": finding["finding_id"],
            "document_id": DOCUMENT_ID,
            "engagement_id": DOCUMENT_ID,
            "label_source": "rule_based",
            "difficulty": difficulty,
            "is_hard_negative": False,
            "schema": "evidence_review_subset",
        },
    }


# ── Task type: remediation_review ────────────────────────────────────
def build_remediation_review(finding: dict, idx: int) -> dict:
    rec = finding.get("recommendation", [])
    rec_count = len(rec) if isinstance(rec, list) else (1 if rec else 0)
    addresses_root = rec_count >= 3
    is_actionable = rec_count >= 2

    gold_output = {
        "recommendation_review": {
            "addresses_root_cause": addresses_root,
            "is_actionable": is_actionable,
            "is_technically_relevant": True,
            "missing_recommendations": ([] if addresses_root else ["Add specific remediation steps."]),
            "comments": [],
        },
        "review_comments": [],
        "confidence": confidence_block(
            0.85,
            basis=["recommendation_length_check", "cwe_relevance_check"],
            limitations=["Does not verify technical accuracy."],
        ),
    }

    failure_modes = [
        "wrong_root_cause_assessment",
        "missed_generic_recommendation",
        "hallucinated_cwe_relevance",
    ]

    return {
        "case_id": case_id("remediation_review", idx),
        "task_type": "remediation_review",
        "instruction": (
            "Evaluate whether the recommendation addresses the root cause and is actionable "
            "and technically relevant."
        ),
        "input": {
            "finding_id": finding["finding_id"],
            "title": finding.get("title", ""),
            "cwe_id": finding.get("cwe_id"),
            "observation": truncate(finding.get("observation", ""), 300),
            "recommendation": finding.get("recommendation", []),
        },
        "gold_output": gold_output,
        "expected_failure_modes": failure_modes,
        "metadata": {
            "finding_id": finding["finding_id"],
            "document_id": DOCUMENT_ID,
            "engagement_id": DOCUMENT_ID,
            "label_source": "rule_based",
            "difficulty": "easy",
            "is_hard_negative": False,
            "schema": "recommendation_review_subset",
        },
    }


# ── Task type: client_qa (in-scope) ──────────────────────────────────
# All 5 in-scope QA cases use the same question type (severity + CVSS lookup)
# to mirror the original benchmark_v1.0 design. The question is simple,
# directly answerable from the finding, and exercises the SLM's ability to
# extract structured fields without hallucination.
IN_SCOPE_QUESTION_TEMPLATE = {
    "question": "What is the severity of the finding '{title}' and what is its CVSS score?",
    "answer_template": (
        "The finding '{title}' is reported with severity '{severity}' and "
        "CVSS v{version} score {score} (vector: {vector})."
    ),
    "source_field": "observation",
}


def truncate_snippet(text: str, n: int = 120) -> str:
    """Snippet truncation for source_references in client_qa answers."""
    if not text or len(text) <= n:
        return text
    return text[:n].rstrip() + "..."


def build_client_qa(finding: dict, idx: int) -> dict:
    title = finding.get("title", "")
    cvss = finding.get("cvss", {}) or {}
    template = IN_SCOPE_QUESTION_TEMPLATE
    question = template["question"].format(title=title)
    answer = template["answer_template"].format(
        title=title,
        severity=finding.get("severity", ""),
        version=cvss.get("version", "3.1"),
        score=cvss.get("score"),
        vector=cvss.get("vector", ""),
    )

    source_field = template["source_field"]
    snippet = truncate_snippet(str(finding.get(source_field, "")), 120)

    gold_output = {
        "answer": answer,
        "refuses": False,
        "source_references": [{
            "field": source_field,
            "snippet": snippet,
        }],
        "confidence": confidence_block(
            0.9,
            basis=["report_scope_check"],
            limitations=["Cannot answer questions outside the report scope."],
        ),
    }

    # In-scope QA cases all use severity-related failure_modes (the question
    # asks for severity + CVSS, so the model can fail by hallucinating either).
    failure_modes = ["hallucinated_severity", "wrong_cvss_score", "refused_in_scope_question"]

    return {
        "case_id": case_id("client_qa", idx),
        "task_type": "client_qa",
        "instruction": (
            "Answer the client question using ONLY information present in the finding. If the "
            "answer cannot be derived from the finding, refuse and explain what is missing."
        ),
        "input": {
            "finding": shared_input(finding),
            "question": question,
        },
        "gold_output": gold_output,
        "expected_failure_modes": failure_modes,
        "metadata": {
            "finding_id": finding["finding_id"],
            "document_id": DOCUMENT_ID,
            "engagement_id": DOCUMENT_ID,
            "label_source": "rule_based",
            "difficulty": "easy",
            "is_hard_negative": False,
            "schema": "client_qa_custom",
        },
    }


# ── Task type: hard_negative_potential_issue (derived) ───────────────
def build_hard_negative_potential_issue(finding: dict, idx: int) -> dict | None:
    """Emit a hard-negative case only for findings with an explicit no-exploitation marker.

    The eligibility rule is stricter than `finding_review`'s classification
    rule: a finding is only eligible for the dedicated hard-negative task
    type when its evidence contains an explicit negative marker (e.g.
    "no successful exploitation", "no evidence was found"). Findings that
    simply lack a positive marker are still classified as Potential Issue
    in `finding_review`, but do not get a dedicated HN case.
    """
    evidence_text = text_of(finding.get("evidence"))
    observation_text = str(finding.get("observation", "")).lower()
    has_neg = has_negative_marker(evidence_text, observation_text)
    if not has_neg:
        return None  # No explicit no-exploitation marker — not eligible

    title = finding.get("title", "")
    gold_output = {
        "classification": classification_block(
            "potential_issue",
            "Finding describes a risk but exploitation was not demonstrated.",
            False,
        ),
        "evidence_review": {
            "is_sufficient": False,
            "evidence_items_reviewed": evidence_items(finding),
            "supported_claims": [],
            "unsupported_claims": [title],
            "missing_evidence": ["Reproducible exploitation proof"],
            "comments": [],
        },
        "confidence": confidence_block(
            0.7,
            basis=["no_exploit_marker_check"],
            limitations=["Rule-based; needs human confirmation."],
        ),
    }

    return {
        "case_id": case_id("hard_negative_potential_issue", idx),
        "task_type": "hard_negative_potential_issue",
        "instruction": (
            "Classify this finding. Pay attention to whether exploitation was actually "
            "demonstrated. If not, label as Potential Issue."
        ),
        "input": shared_input(finding),
        "gold_output": gold_output,
        "expected_failure_modes": [
            "wrong_classification_label_confirmed",
            "missed_no_exploit_marker",
            "hallucinated_exploitation",
        ],
        "metadata": {
            "finding_id": finding["finding_id"],
            "document_id": DOCUMENT_ID,
            "engagement_id": DOCUMENT_ID,
            "label_source": "rule_based",
            "difficulty": "hard",
            "is_hard_negative": True,
            "schema": "classification_evidence_subset",
        },
    }


# ── Hand-crafted negatives loader ────────────────────────────────────
def load_hand_crafted(path: Path) -> list[dict]:
    """Load hand-crafted hard negatives from JSONL.

    Each entry already has the full envelope (minus case_id and content_hash
    which are assigned by this generator). We re-assign sequential IDs within
    each task type so the IDs are deterministic regardless of source order.
    """
    if not path.exists():
        return []
    cases: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            cases.append(json.loads(line))
    return cases


def assign_hand_crafted_ids(cases: list[dict], starting_indices: dict[str, int]) -> list[dict]:
    """Assign sequential case_ids to hand-crafted cases per task_type."""
    counters = dict(starting_indices)
    out: list[dict] = []
    for c in cases:
        tt = c["task_type"]
        counters[tt] = counters.get(tt, (starting_indices.get(tt, 0))) + 1
        # Actually we want counter starting at the next index after derived cases
        # Simpler: precompute starting index per task_type from derived cases
        c = dict(c)
        c["case_id"] = case_id(tt, counters[tt])
        out.append(c)
    return out


# ── Findings loader ──────────────────────────────────────────────────
def load_findings(path: Path) -> list[dict]:
    findings: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            findings.append(json.loads(line))
    return findings


# ── Main pipeline ────────────────────────────────────────────────────
def build_all(findings: list[dict], hand_crafted: list[dict]) -> list[dict]:
    cases: list[dict] = []

    # Derived cases (one per finding per task type)
    hn_idx = 0
    for i, finding in enumerate(findings, start=1):
        cases.append(build_finding_review(finding, i))
        cases.append(build_severity_review(finding, i))
        cases.append(build_evidence_check(finding, i))
        cases.append(build_remediation_review(finding, i))
        cases.append(build_client_qa(finding, i))
        # Hard-negative potential issue: only emitted for findings without exploitation
        hn = build_hard_negative_potential_issue(finding, hn_idx + 1)
        if hn is not None:
            cases.append(hn)
            hn_idx += 1

    # Compute starting index per task_type for hand-crafted cases
    # (derived cases use indices 1..N for each task_type; hand-crafted continue from N+1)
    derived_counts: Counter = Counter(c["task_type"] for c in cases)
    starting = {tt: derived_counts.get(tt, 0) for tt in TASK_PREFIX}

    # Hand-crafted cases get sequential IDs after derived ones
    hand_crafted_assigned = assign_hand_crafted_ids(hand_crafted, starting)
    cases.extend(hand_crafted_assigned)

    # Sort by case_id for deterministic output
    cases.sort(key=lambda c: c["case_id"])

    # Compute content_hash for each case
    for c in cases:
        c["metadata"]["content_hash"] = content_hash(c)

    return cases


def build_manifest(cases: list[dict], findings_path: Path) -> dict:
    by_task = Counter(c["task_type"] for c in cases)
    by_diff = Counter(c["metadata"]["difficulty"] for c in cases)
    hard_neg = sum(1 for c in cases if c["metadata"].get("is_hard_negative"))

    return {
        "benchmark_version": BENCHMARK_VERSION,
        "created_at": TODAY_ISO,
        "source": {
            "findings_jsonl": str(findings_path.relative_to(REPO_ROOT)),
            "engagement_id": DOCUMENT_ID,
            "n_findings": sum(1 for c in cases if c["task_type"] == "finding_review"),
        },
        "case_count": len(cases),
        "cases_by_task_type": dict(sorted(by_task.items())),
        "cases_by_difficulty": dict(sorted(by_diff.items())),
        "hard_negative_count": hard_neg,
        "schema_contract": "schemas/output_schema.json (v0.1)",
        "envelope_schema": {
            "case_id": "string",
            "task_type": "enum",
            "instruction": "string",
            "input": "object",
            "gold_output": "object (shape depends on task_type)",
            "expected_failure_modes": "string[]",
            "metadata": "object",
        },
        "duplicates_detected": [],
        "generation_strategy": "cross_task_expansion + hand_crafted_hard_negatives",
        "notes": [
            "Gold labels are rule-based, not human-validated.",
            "Test set is NOT frozen — only 1 engagement available (see data/dataset/test_set_freeze.json).",
            "Baseline run is deferred to Colab on 10/08 (per Q2 = option a).",
            "Regenerate with: python scripts/build_benchmark_v1.py",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build benchmark_v1.jsonl from normalized findings.")
    parser.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS,
                        help="Path to normalized findings JSONL")
    parser.add_argument("--hand-crafted", type=Path, default=HAND_CRAFTED_SOURCE,
                        help="Path to hand-crafted negatives JSONL")
    parser.add_argument("--benchmark-out", type=Path, default=BENCHMARK_OUT,
                        help="Output path for benchmark_v1.jsonl")
    parser.add_argument("--manifest-out", type=Path, default=MANIFEST_OUT,
                        help="Output path for benchmark_manifest.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print summary without writing files")
    args = parser.parse_args(argv)

    if not args.findings.exists():
        print(f"ERROR: findings file not found: {args.findings}", file=sys.stderr)
        return 2
    if not args.hand_crafted.exists():
        print(f"ERROR: hand-crafted negatives file not found: {args.hand_crafted}", file=sys.stderr)
        return 2

    findings = load_findings(args.findings)
    hand_crafted = load_hand_crafted(args.hand_crafted)
    print(f"Loaded {len(findings)} findings from {args.findings}")
    print(f"Loaded {len(hand_crafted)} hand-crafted negatives from {args.hand_crafted}")

    cases = build_all(findings, hand_crafted)
    manifest = build_manifest(cases, args.findings)

    print(f"\nGenerated {len(cases)} cases:")
    by_task = Counter(c["task_type"] for c in cases)
    for tt in sorted(by_task):
        print(f"  {tt:35} {by_task[tt]:3d}")
    by_diff = Counter(c["metadata"]["difficulty"] for c in cases)
    print(f"\nBy difficulty: {dict(sorted(by_diff.items()))}")
    hard_neg = sum(1 for c in cases if c["metadata"].get("is_hard_negative"))
    print(f"Hard negatives: {hard_neg}")

    if args.dry_run:
        print("\n--dry-run: not writing files.")
        return 0

    args.benchmark_out.parent.mkdir(parents=True, exist_ok=True)
    with args.benchmark_out.open("w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print(f"\nWrote {args.benchmark_out} ({len(cases)} cases)")

    with args.manifest_out.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"Wrote {args.manifest_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())