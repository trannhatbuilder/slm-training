"""
Self-Validation Checklist — Post-pipeline response action decider.

Runs AFTER the standard 12-step harness pipeline. It re-examines
the harness result and decides one of four response actions:

    re-check    → A single automated retry of a specific check (e.g.
                  re-check evidence after internal data refresh).
    request_data → Ask the upstream provider for missing/additional data
                  that cannot be obtained internally.
    pending     → The finding cannot be finalised now; park it until an
                  external condition changes (e.g. retest scheduled).
    escalate    → Route to a human reviewer immediately.

Each of the 8 checklist items maps to an existing harness function
and contains a decision tree:

    PASS  → no action needed (checklist item satisfied)
    FAIL  → one of {re-check, request_data, pending, escalate}
           depending on severity, confidence, and finding context.

This module does NOT duplicate detection logic — it reads the results
already produced by rule_checks, consistency, confidence, and escalation
modules, then applies response-action rules on top.

Usage:
    from harness.self_validation import SelfValidationChecklist

    checklist = SelfValidationChecklist()
    report   = checklist.run_checklist(finding, harness_result)
    # report["response_action"]  → "re-check" | "request_data" | "pending" | "escalate" | "pass"
    # report["items"]            → per-checklist-item detail
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Response Action enum ─────────────────────────────────────────────────
class ResponseAction(str, Enum):
    """Possible response actions after self-validation."""
    PASS = "pass"                 # All checks passed — no action needed
    RECHECK = "re-check"          # Retry a specific check internally
    REQUEST_DATA = "request_data"  # Ask upstream for missing data
    PENDING = "pending"           # Park until external condition changes
    ESCALATE = "escalate"         # Route to human reviewer


# ── Per-item result ───────────────────────────────────────────────────────
@dataclass
class ChecklistItemResult:
    """Result of a single checklist item evaluation."""
    item_id: str                          # e.g. "SV-01"
    item_name: str                        # e.g. "Field Completeness"
    status: str                           # "pass" or "fail"
    response_action: ResponseAction       # action if failed, PASS if passed
    reason: str                           # human-readable explanation
    taxonomy_codes: list[str] = field(default_factory=list)  # related codes
    actionable_fields: list[str] = field(default_factory=list)  # fields to fix
    retry_check: str | None = None        # which harness function to re-run (re-check only)
    data_request: str | None = None       # what data to request (request_data only)
    pending_condition: str | None = None  # what condition to wait for (pending only)
    escalate_reason: str | None = None    # escalation justification (escalate only)


# ── Main class ────────────────────────────────────────────────────────────
class SelfValidationChecklist:
    """
    Post-pipeline self-validation checklist with 8 items.

    Each item inspects the harness result produced by the 12-step
    pipeline and decides a response action when the item fails.
    The overall response action is the most severe action among
    all failing items (escalate > pending > request_data > re-check > pass).
    """

    # Severity ordering for response-action priority
    _ACTION_PRIORITY: dict[ResponseAction, int] = {
        ResponseAction.ESCALATE:     4,
        ResponseAction.PENDING:      3,
        ResponseAction.REQUEST_DATA: 2,
        ResponseAction.RECHECK:      1,
        ResponseAction.PASS:         0,
    }

    def __init__(self) -> None:
        pass

    # ── Public API ─────────────────────────────────────────────────────

    def run_checklist(self, finding: dict, harness_result: dict) -> dict:
        """
        Run all 8 checklist items against the harness result.

        Args:
            finding:        The original normalised finding (Input Schema v0.2).
            harness_result:  The full review result from HarnessOrchestrator.review()
                            (Output Schema v0.1 + _pipeline_meta).

        Returns:
            {
                "response_action": str,        # most severe action
                "total_items": int,             # 8
                "passed": int,
                "failed": int,
                "items": [ChecklistItemResult.asdict(), ...],
            }
        """
        item_results: list[ChecklistItemResult] = []

        # Unpack sub-reviews from harness result
        completeness_review = harness_result.get("completeness_review", {})
        evidence_review     = harness_result.get("evidence_review", {})
        classification_review = harness_result.get("classification", {})
        severity_review     = harness_result.get("severity_review", {})
        consistency_review  = harness_result.get("consistency_review", {})
        confidence_result   = harness_result.get("confidence", {})
        escalation_result   = harness_result.get("human_escalation", {})
        cvss_review         = harness_result.get("cvss_review", {})
        impact_review       = harness_result.get("impact_review", {})
        recommendation_review = harness_result.get("recommendation_review", {})
        retest_review       = harness_result.get("retest_review", {})

        # Run each checklist item
        item_results.append(self._check_field_completeness(
            finding, completeness_review))
        item_results.append(self._check_evidence_sufficiency(
            finding, evidence_review, classification_review))
        item_results.append(self._check_classification_evidence_alignment(
            finding, classification_review, evidence_review, confidence_result))
        item_results.append(self._check_severity_cvss_consistency(
            finding, severity_review, cvss_review))
        item_results.append(self._check_cross_field_consistency(
            finding, consistency_review))
        item_results.append(self._check_scanner_only_trap(
            finding, evidence_review, classification_review, severity_review))
        item_results.append(self._check_confidence_and_escalation(
            finding, confidence_result, escalation_result))
        item_results.append(self._check_retest_and_closure(
            finding, retest_review, classification_review))

        # Determine overall response action (most severe)
        overall_action = ResponseAction.PASS
        for item in item_results:
            if self._ACTION_PRIORITY[item.response_action] > self._ACTION_PRIORITY[overall_action]:
                overall_action = item.response_action

        passed = sum(1 for i in item_results if i.status == "pass")
        failed = sum(1 for i in item_results if i.status == "fail")

        return {
            "response_action": overall_action.value,
            "total_items": len(item_results),
            "passed": passed,
            "failed": failed,
            "items": [self._item_to_dict(i) for i in item_results],
        }

    # ── Checklist Items ───────────────────────────────────────────────

    def _check_field_completeness(
        self,
        finding: dict,
        completeness_review: dict,
    ) -> ChecklistItemResult:
        """
        SV-01: Field Completeness

        Check logic: Uses completeness_review from rule_checks.check_completeness().
        If required fields are missing, decide what to do.

        Decision tree:
            PASS  → all required fields present
            FAIL + conditional fields missing only
                  → re-check (maybe data exists but wasn't included)
            FAIL + required fields missing
                  → request_data (upstream must provide core data)
        """
        is_complete = completeness_review.get("is_complete", True)
        missing_required = completeness_review.get("missing_required_fields", [])
        missing_conditional = completeness_review.get("missing_conditional_fields", [])

        if is_complete and not missing_conditional:
            return ChecklistItemResult(
                item_id="SV-01",
                item_name="Field Completeness",
                status="pass",
                response_action=ResponseAction.PASS,
                reason="All required and conditional fields are present.",
                taxonomy_codes=["COMP"],
            )

        if not is_complete and missing_required:
            # Required fields are missing — need upstream data
            return ChecklistItemResult(
                item_id="SV-01",
                item_name="Field Completeness",
                status="fail",
                response_action=ResponseAction.REQUEST_DATA,
                reason=(
                    f"Required fields missing: {missing_required}. "
                    f"These must be provided by the upstream data source before review can proceed."
                ),
                taxonomy_codes=["COMP-001", "COMP-002"],
                actionable_fields=missing_required,
                data_request=(
                    f"Provide missing required fields: {', '.join(missing_required)}. "
                    f"Without these, the finding cannot be reviewed."
                ),
            )

        # Only conditional fields missing
        return ChecklistItemResult(
            item_id="SV-01",
            item_name="Field Completeness",
            status="fail",
            response_action=ResponseAction.RECHECK,
            reason=(
                f"Conditional fields missing: {missing_conditional}. "
                f"These may be available in the source data but were not included. "
                f"Re-check the source document for these fields."
            ),
            taxonomy_codes=["COMP-003", "COMP-004", "COMP-005", "COMP-006"],
            actionable_fields=missing_conditional,
            retry_check="check_completeness",
        )

    def _check_evidence_sufficiency(
        self,
        finding: dict,
        evidence_review: dict,
        classification_review: dict,
    ) -> ChecklistItemResult:
        """
        SV-02: Evidence Sufficiency

        Check logic: Uses evidence_review from rule_checks.check_evidence().
        If evidence is insufficient or absent, decide what to do.

        Decision tree:
            PASS  → evidence is sufficient
            FAIL + no evidence at all
                  → request_data (cannot review without evidence)
            FAIL + scanner-only evidence
                  → request_data (manual verification needed from pentester)
            FAIL + evidence exists but exploitation not demonstrated
                  → pending (wait for pentester to complete testing)
            FAIL + evidence is unrelated to finding
                  → re-check (maybe wrong evidence was attached)
        """
        is_sufficient = evidence_review.get("is_sufficient")
        missing = evidence_review.get("missing_evidence", [])
        unsupported = evidence_review.get("unsupported_claims", [])
        items_reviewed = evidence_review.get("evidence_items_reviewed", [])

        if is_sufficient is True:
            return ChecklistItemResult(
                item_id="SV-02",
                item_name="Evidence Sufficiency",
                status="pass",
                response_action=ResponseAction.PASS,
                reason="Evidence is sufficient and supports the vulnerability claim.",
                taxonomy_codes=["EVID_SUFF"],
            )

        # No evidence at all
        if is_sufficient is None or not items_reviewed:
            return ChecklistItemResult(
                item_id="SV-02",
                item_name="Evidence Sufficiency",
                status="fail",
                response_action=ResponseAction.REQUEST_DATA,
                reason=(
                    "No exploitation evidence provided. "
                    "Evidence is required before any classification can be made. "
                    "Request the pentester to provide exploitation evidence."
                ),
                taxonomy_codes=["EVID_NONE", "EVID-003"],
                actionable_fields=["evidence"],
                data_request=(
                    "Provide exploitation evidence for this finding: "
                    "reproduction steps, screenshots, or command output."
                ),
            )

        # Scanner-only evidence
        scanner_missing = [m for m in missing if "scanner" in m.lower()]
        if scanner_missing:
            return ChecklistItemResult(
                item_id="SV-02",
                item_name="Evidence Sufficiency",
                status="fail",
                response_action=ResponseAction.REQUEST_DATA,
                reason=(
                    "Evidence is scanner-only with no manual verification. "
                    "Manual exploitation evidence is required to confirm the vulnerability."
                ),
                taxonomy_codes=["EVID_SCANNER_ONLY", "EVID-005"],
                actionable_fields=["evidence"],
                data_request=(
                    "Perform manual verification of this scanner finding and provide "
                    "exploitation evidence (reproduction steps, proof of concept)."
                ),
            )

        # Evidence exists but exploitation not demonstrated
        if unsupported:
            return ChecklistItemResult(
                item_id="SV-02",
                item_name="Evidence Sufficiency",
                status="fail",
                response_action=ResponseAction.PENDING,
                reason=(
                    "Evidence exists but exploitation was not successfully demonstrated. "
                    f"Unsupported claims: {unsupported}. "
                    "Pending until the pentester completes exploitation testing."
                ),
                taxonomy_codes=["EVID_INSUFF", "EVID-002", "EVID-004"],
                actionable_fields=["evidence"],
                pending_condition=(
                    "Awaiting pentester to complete exploitation testing and provide "
                    "evidence of successful exploitation or confirm the finding cannot be exploited."
                ),
            )

        # Fallback: evidence insufficient for unclear reason
        return ChecklistItemResult(
            item_id="SV-02",
            item_name="Evidence Sufficiency",
            status="fail",
            response_action=ResponseAction.RECHECK,
            reason=(
                "Evidence is marked insufficient but the specific reason is unclear. "
                f"Missing evidence notes: {missing}. "
                "Re-check evidence content against the vulnerability claim."
            ),
            taxonomy_codes=["EVID_INSUFF"],
            actionable_fields=["evidence"],
            retry_check="check_evidence",
        )

    def _check_classification_evidence_alignment(
        self,
        finding: dict,
        classification_review: dict,
        evidence_review: dict,
        confidence_result: dict,
    ) -> ChecklistItemResult:
        """
        SV-03: Classification-Evidence Alignment

        Check logic: Uses classification_review from rule_checks.check_classification()
        and evidence_review. Detects classification that conflicts with evidence strength.

        Decision tree:
            PASS  → classification aligns with evidence strength
            FAIL + classified as confirmed but evidence insufficient
                  → escalate (critical misclassification risk)
            FAIL + classified as confirmed but scanner-only
                  → escalate (must not confirm scanner-only findings)
            FAIL + classification is potential_issue with low confidence
                  → pending (wait for additional evidence before deciding)
        """
        label = classification_review.get("label", "")
        supported = classification_review.get("supported_by_evidence")
        is_sufficient = evidence_review.get("is_sufficient")

        # Check for scanner-only signal in evidence
        evidence_items_reviewed = evidence_review.get("evidence_items_reviewed", [])
        missing = evidence_review.get("missing_evidence", [])
        is_scanner_only = any("scanner" in m.lower() for m in missing)

        # PASS: confirmed with sufficient evidence, or non-confirmed labels
        if label == "confirmed_vulnerability" and supported is True and is_sufficient is True:
            return ChecklistItemResult(
                item_id="SV-03",
                item_name="Classification-Evidence Alignment",
                status="pass",
                response_action=ResponseAction.PASS,
                reason=(
                    "Classification 'confirmed_vulnerability' is properly supported "
                    "by sufficient exploitation evidence."
                ),
                taxonomy_codes=["CLASS", "EVID_SUFF"],
            )

        if label in ("potential_issue", "informational", "false_positive", "undetermined"):
            if supported is not False:
                return ChecklistItemResult(
                    item_id="SV-03",
                    item_name="Classification-Evidence Alignment",
                    status="pass",
                    response_action=ResponseAction.PASS,
                    reason=(
                        f"Classification '{label}' is appropriate given the evidence strength."
                    ),
                    taxonomy_codes=["CLASS"],
                )

        # FAIL: confirmed but evidence insufficient
        if label == "confirmed_vulnerability" and is_sufficient is not True:
            return ChecklistItemResult(
                item_id="SV-03",
                item_name="Classification-Evidence Alignment",
                status="fail",
                response_action=ResponseAction.ESCALATE,
                reason=(
                    f"Classification is 'confirmed_vulnerability' but evidence is "
                    f"insufficient (is_sufficient={is_sufficient}). "
                    f"This is a critical misclassification risk — human reviewer must decide."
                ),
                taxonomy_codes=["CLASS-001", "EVID_INSUFF", "CONS-002"],
                actionable_fields=["classification"],
                escalate_reason=(
                    "Critical: Finding classified as Confirmed Vulnerability without "
                    "sufficient evidence. Reviewer must verify classification or downgrade."
                ),
            )

        # FAIL: confirmed but scanner-only
        if label == "confirmed_vulnerability" and is_scanner_only:
            return ChecklistItemResult(
                item_id="SV-03",
                item_name="Classification-Evidence Alignment",
                status="fail",
                response_action=ResponseAction.ESCALATE,
                reason=(
                    "Classification is 'confirmed_vulnerability' but evidence is "
                    "scanner-only. Scanner findings must not be confirmed without "
                    "manual verification."
                ),
                taxonomy_codes=["CLASS-001", "EVID_SCANNER_ONLY", "EVID-005"],
                actionable_fields=["classification", "evidence"],
                escalate_reason=(
                    "Critical: Scanner-only finding classified as Confirmed Vulnerability. "
                    "Manual verification is required before confirmation."
                ),
            )

        # FAIL: potential_issue with low confidence — park and wait
        confidence_score = confidence_result.get("overall_score")
        if label == "potential_issue" and confidence_score is not None and confidence_score < 0.5:
            return ChecklistItemResult(
                item_id="SV-03",
                item_name="Classification-Evidence Alignment",
                status="fail",
                response_action=ResponseAction.PENDING,
                reason=(
                    f"Classification is 'potential_issue' with low confidence ({confidence_score:.2f}). "
                    f"Pending additional evidence before final classification can be determined."
                ),
                taxonomy_codes=["CLASS", "CONF"],
                actionable_fields=["evidence", "classification"],
                pending_condition=(
                    "Awaiting additional evidence or manual testing to determine "
                    "whether this finding can be confirmed or should be closed."
                ),
            )

        # Fallback pass for non-critical situations
        return ChecklistItemResult(
            item_id="SV-03",
            item_name="Classification-Evidence Alignment",
            status="pass",
            response_action=ResponseAction.PASS,
            reason=f"Classification '{label}' is reasonable given available evidence.",
            taxonomy_codes=["CLASS"],
        )

    def _check_severity_cvss_consistency(
        self,
        finding: dict,
        severity_review: dict,
        cvss_review: dict,
    ) -> ChecklistItemResult:
        """
        SV-04: Severity-CVSS Consistency

        Check logic: Uses severity_review from rule_checks.check_severity()
        and cvss_review from rule_checks.check_cvss().

        Decision tree:
            PASS  → severity matches CVSS score range
            FAIL + CVSS vector is malformed
                  → re-check (recalculate after fixing vector)
            FAIL + severity mismatch but CVSS is valid
                  → escalate (human decides final severity)
        """
        is_consistent = severity_review.get("is_consistent")
        vector_valid = cvss_review.get("vector_is_valid")
        change_recommended = severity_review.get("change_recommended", False)

        if is_consistent is True or is_consistent is None:
            return ChecklistItemResult(
                item_id="SV-04",
                item_name="Severity-CVSS Consistency",
                status="pass",
                response_action=ResponseAction.PASS,
                reason=(
                    "Reported severity is consistent with CVSS score"
                    if is_consistent is True
                    else "Severity consistency could not be determined (missing CVSS or severity)."
                ),
                taxonomy_codes=["SEV", "CVSS"],
            )

        # FAIL: CVSS vector malformed — try re-check first
        if vector_valid is False:
            return ChecklistItemResult(
                item_id="SV-04",
                item_name="Severity-CVSS Consistency",
                status="fail",
                response_action=ResponseAction.RECHECK,
                reason=(
                    f"CVSS vector is malformed. Severity mismatch may be caused by "
                    f"invalid CVSS data rather than an actual severity error. "
                    f"Re-check after CVSS vector is corrected."
                ),
                taxonomy_codes=["SEV-001", "CVSS"],
                actionable_fields=["cvss.vector", "severity"],
                retry_check="check_cvss",
            )

        # FAIL: severity mismatch with valid CVSS — human decides
        if change_recommended:
            reported = severity_review.get("reported_severity", "unknown")
            suggested = severity_review.get("suggested_severity", "unknown")
            return ChecklistItemResult(
                item_id="SV-04",
                item_name="Severity-CVSS Consistency",
                status="fail",
                response_action=ResponseAction.ESCALATE,
                reason=(
                    f"Severity mismatch: reported='{reported}', CVSS implies '{suggested}'. "
                    f"CVSS vector is valid, so the mismatch is in the severity assignment. "
                    f"Human reviewer must decide the final severity."
                ),
                taxonomy_codes=["SEV-001", "CONS-001"],
                actionable_fields=["severity"],
                escalate_reason=(
                    f"Severity '{reported}' does not match CVSS-implied '{suggested}'. "
                    f"Reviewer must confirm or correct the severity level."
                ),
            )

        # Fallback
        return ChecklistItemResult(
            item_id="SV-04",
            item_name="Severity-CVSS Consistency",
            status="pass",
            response_action=ResponseAction.PASS,
            reason="No actionable severity-CVSS inconsistency detected.",
            taxonomy_codes=["SEV", "CVSS"],
        )

    def _check_cross_field_consistency(
        self,
        finding: dict,
        consistency_review: dict,
    ) -> ChecklistItemResult:
        """
        SV-05: Cross-Field Consistency

        Check logic: Uses consistency_review from consistency.check_consistency().
        Checks severity-CVSS alignment, evidence-classification alignment,
        title-content alignment, and recommendation-root-cause alignment.

        Decision tree:
            PASS  → no consistency issues
            FAIL + critical alignment issue (evidence-classification)
                  → escalate (affects classification accuracy)
            FAIL + non-critical alignment issue (title, recommendation)
                  → re-check (may be fixable internally)
        """
        is_consistent = consistency_review.get("is_consistent", True)
        issues = consistency_review.get("issues", [])

        if is_consistent and not issues:
            return ChecklistItemResult(
                item_id="SV-05",
                item_name="Cross-Field Consistency",
                status="pass",
                response_action=ResponseAction.PASS,
                reason="All cross-field consistency checks passed.",
                taxonomy_codes=["CONS"],
            )

        # Separate critical from non-critical issues
        critical_keywords = ["classification", "confirmed", "evidence"]
        critical_issues = [i for i in issues if any(k in i.lower() for k in critical_keywords)]
        non_critical_issues = [i for i in issues if i not in critical_issues]

        # Critical consistency issue (evidence-classification conflict)
        if critical_issues:
            return ChecklistItemResult(
                item_id="SV-05",
                item_name="Cross-Field Consistency",
                status="fail",
                response_action=ResponseAction.ESCALATE,
                reason=(
                    f"Critical consistency issue detected: {'; '.join(critical_issues)}. "
                    f"This affects the reliability of the classification and requires human review."
                ),
                taxonomy_codes=["CONS-001", "CONS-002"],
                actionable_fields=["classification", "evidence", "severity"],
                escalate_reason=(
                    f"Cross-field consistency violation: {'; '.join(critical_issues)}. "
                    f"Reviewer must verify the finding's internal consistency."
                ),
            )

        # Non-critical consistency issue (title, recommendation)
        if non_critical_issues:
            return ChecklistItemResult(
                item_id="SV-05",
                item_name="Cross-Field Consistency",
                status="fail",
                response_action=ResponseAction.RECHECK,
                reason=(
                    f"Non-critical consistency issues: {'; '.join(non_critical_issues)}. "
                    f"These may be fixable by re-checking the relevant fields."
                ),
                taxonomy_codes=["CONS-003", "CONS-004"],
                actionable_fields=["title", "recommendation", "impact"],
                retry_check="check_consistency",
            )

        # Fallback
        return ChecklistItemResult(
            item_id="SV-05",
            item_name="Cross-Field Consistency",
            status="pass",
            response_action=ResponseAction.PASS,
            reason="No actionable consistency issues detected.",
            taxonomy_codes=["CONS"],
        )

    def _check_scanner_only_trap(
        self,
        finding: dict,
        evidence_review: dict,
        classification_review: dict,
        severity_review: dict,
    ) -> ChecklistItemResult:
        """
        SV-06: Scanner-Only Trap Detection

        Check logic: Detects when a finding is based solely on scanner output
        but is classified with high severity or as confirmed vulnerability.
        This is a specialised check that combines evidence type detection
        with classification and severity validation.

        Decision tree:
            PASS  → not scanner-only, OR scanner-only with appropriate
                   classification (potential_issue) and low severity
            FAIL + scanner-only + confirmed_vulnerability
                  → escalate (critical: must not confirm scanner-only)
            FAIL + scanner-only + high/critical severity
                  → escalate (severity inflation without verification)
            FAIL + scanner-only + potential_issue + medium or below
                  → request_data (request manual verification)
        """
        missing = evidence_review.get("missing_evidence", [])
        is_scanner_only = any("scanner" in m.lower() for m in missing)

        if not is_scanner_only:
            return ChecklistItemResult(
                item_id="SV-06",
                item_name="Scanner-Only Trap Detection",
                status="pass",
                response_action=ResponseAction.PASS,
                reason="Finding is not scanner-only (has manual evidence or other verification).",
                taxonomy_codes=["EVID_SCANNER_ONLY"],
            )

        label = classification_review.get("label", "")
        severity = finding.get("severity", "")

        # FAIL: scanner-only + confirmed
        if label == "confirmed_vulnerability":
            return ChecklistItemResult(
                item_id="SV-06",
                item_name="Scanner-Only Trap Detection",
                status="fail",
                response_action=ResponseAction.ESCALATE,
                reason=(
                    "TRAP DETECTED: Scanner-only finding classified as 'confirmed_vulnerability'. "
                    "This violates EVVO policy — scanner findings must have manual verification "
                    "before confirmation. Severity may also be inflated."
                ),
                taxonomy_codes=["EVID_SCANNER_ONLY", "EVID-005", "CLASS-001"],
                actionable_fields=["classification", "evidence", "severity"],
                escalate_reason=(
                    "POLICY VIOLATION: Scanner-only finding cannot be classified as "
                    "Confirmed Vulnerability. Downgrade to Potential Issue and request "
                    "manual verification from the pentester."
                ),
            )

        # FAIL: scanner-only + high/critical severity
        if severity in ("critical", "high"):
            return ChecklistItemResult(
                item_id="SV-06",
                item_name="Scanner-Only Trap Detection",
                status="fail",
                response_action=ResponseAction.ESCALATE,
                reason=(
                    f"TRAP DETECTED: Scanner-only finding with {severity} severity. "
                    f"High-severity scanner findings often produce false positives. "
                    f"Manual verification is required before accepting this severity."
                ),
                taxonomy_codes=["EVID_SCANNER_ONLY", "EVID-005", "SEV-001"],
                actionable_fields=["severity", "evidence"],
                escalate_reason=(
                    f"Scanner-only finding reported as {severity} severity. "
                    f"Manual verification required to confirm severity is not inflated."
                ),
            )

        # Scanner-only but appropriately classified as potential_issue
        # Still request manual verification
        return ChecklistItemResult(
            item_id="SV-06",
            item_name="Scanner-Only Trap Detection",
            status="fail",
            response_action=ResponseAction.REQUEST_DATA,
            reason=(
                "Finding is scanner-only but appropriately classified as "
                f"'{label}' with '{severity}' severity. "
                "However, manual verification is still recommended to confirm or exclude."
            ),
            taxonomy_codes=["EVID_SCANNER_ONLY", "EVID-005"],
            actionable_fields=["evidence"],
            data_request=(
                "Perform manual verification of this scanner finding. Provide reproduction "
                "steps or confirm this is a false positive."
            ),
        )

    def _check_confidence_and_escalation(
        self,
        finding: dict,
        confidence_result: dict,
        escalation_result: dict,
    ) -> ChecklistItemResult:
        """
        SV-07: Confidence and Escalation Check

        Check logic: Uses confidence_result from confidence.compute_confidence()
        and escalation_result from escalation.decide_escalation().

        Decision tree:
            PASS  → confidence >= 0.7 and no escalation required
            FAIL + confidence < 0.3
                  → escalate (extremely low confidence — human must review)
            FAIL + confidence 0.3-0.5 + evidence_completeness < 0.5
                  → request_data (evidence is the main gap)
            FAIL + confidence 0.5-0.7
                  → pending (moderate uncertainty — wait for more info)
            FAIL + escalation already required by pipeline
                  → escalate (respect pipeline escalation decision)
        """
        score = confidence_result.get("overall_score")
        level = confidence_result.get("level", "not_calculated")
        factors = confidence_result.get("factors", {})
        escalation_required = escalation_result.get("required", False)
        escalation_reasons = escalation_result.get("reasons", [])

        # PASS: high confidence, no escalation
        if score is not None and score >= 0.7 and not escalation_required:
            return ChecklistItemResult(
                item_id="SV-07",
                item_name="Confidence and Escalation",
                status="pass",
                response_action=ResponseAction.PASS,
                reason=f"Confidence is high ({score:.2f}, level={level}). No escalation needed.",
                taxonomy_codes=["CONF"],
            )

        # FAIL: pipeline already requires escalation — respect it
        if escalation_required:
            score_str = f"{score:.2f}" if score is not None else "N/A"
            return ChecklistItemResult(
                item_id="SV-07",
                item_name="Confidence and Escalation",
                status="fail",
                response_action=ResponseAction.ESCALATE,
                reason=(
                    f"Pipeline escalation is required. Reasons: {'; '.join(escalation_reasons)}. "
                    f"Confidence: {score_str} (level={level})."
                ),
                taxonomy_codes=["CONF"],
                escalate_reason="; ".join(escalation_reasons),
            )

        # FAIL: extremely low confidence
        if score is not None and score < 0.3:
            return ChecklistItemResult(
                item_id="SV-07",
                item_name="Confidence and Escalation",
                status="fail",
                response_action=ResponseAction.ESCALATE,
                reason=(
                    f"Extremely low confidence ({score:.2f}, level={level}). "
                    f"Automated review is unreliable — human reviewer must assess."
                ),
                taxonomy_codes=["CONF"],
                escalate_reason=(
                    f"Confidence score {score:.2f} is below minimum threshold (0.3). "
                    f"Human review required for all aspects of this finding."
                ),
            )

        # FAIL: low confidence + evidence is the main gap
        evidence_score = factors.get("evidence_completeness", 1.0)
        if score is not None and score < 0.5 and evidence_score < 0.5:
            return ChecklistItemResult(
                item_id="SV-07",
                item_name="Confidence and Escalation",
                status="fail",
                response_action=ResponseAction.REQUEST_DATA,
                reason=(
                    f"Low confidence ({score:.2f}) driven primarily by insufficient evidence "
                    f"(evidence_completeness={evidence_score:.2f}). "
                    f"Requesting additional evidence to improve confidence."
                ),
                taxonomy_codes=["CONF", "EVID_INSUFF"],
                actionable_fields=["evidence"],
                data_request=(
                    f"Confidence is low ({score:.2f}) mainly due to insufficient evidence. "
                    f"Provide additional exploitation evidence to improve review confidence."
                ),
            )

        # FAIL: moderate uncertainty
        if score is not None and score < 0.7:
            return ChecklistItemResult(
                item_id="SV-07",
                item_name="Confidence and Escalation",
                status="fail",
                response_action=ResponseAction.PENDING,
                reason=(
                    f"Moderate confidence ({score:.2f}, level={level}). "
                    f"Finding is not unreliable but has some uncertainty. "
                    f"Pending additional information before finalising."
                ),
                taxonomy_codes=["CONF"],
                pending_condition=(
                    f"Awaiting additional context or evidence to improve confidence "
                    f"from {score:.2f} above the escalation threshold (0.7)."
                ),
            )

        # Score is None — not calculated
        return ChecklistItemResult(
            item_id="SV-07",
            item_name="Confidence and Escalation",
            status="fail",
            response_action=ResponseAction.ESCALATE,
            reason=(
                "Confidence could not be calculated. "
                "Cannot assess review reliability — human review required."
            ),
            taxonomy_codes=["CONF"],
            escalate_reason="Confidence score not calculated — unable to assess review quality.",
        )

    def _check_retest_and_closure(
        self,
        finding: dict,
        retest_review: dict,
        classification_review: dict,
    ) -> ChecklistItemResult:
        """
        SV-08: Retest and Closure Status

        Check logic: Uses retest_review from rule_checks.check_retest().
        Checks whether confirmed vulnerabilities have been retested.

        Decision tree:
            PASS  → retest not applicable, or retest completed with evidence
            FAIL + confirmed_vulnerability + no retest
                  → pending (schedule retest)
            FAIL + retest status is "fixed" but no evidence
                  → request_data (request retest evidence)
            FAIL + retest status is "not_fixed" or "partially_fixed"
                  → pending (remediation in progress)
        """
        applicable = retest_review.get("applicable")
        reported_status = retest_review.get("reported_status")
        supported = retest_review.get("status_supported_by_evidence")
        label = classification_review.get("label", "")

        # PASS: retest not applicable
        if applicable is False:
            return ChecklistItemResult(
                item_id="SV-08",
                item_name="Retest and Closure Status",
                status="pass",
                response_action=ResponseAction.PASS,
                reason="Retest is not applicable for this finding.",
                taxonomy_codes=["RET"],
            )

        # PASS: retest completed and supported by evidence
        if reported_status in ("fixed", "partially_fixed", "not_fixed", "accepted_risk") and supported:
            return ChecklistItemResult(
                item_id="SV-08",
                item_name="Retest and Closure Status",
                status="pass",
                response_action=ResponseAction.PASS,
                reason=f"Retest completed (status={reported_status}) with supporting evidence.",
                taxonomy_codes=["RET"],
            )

        # FAIL: confirmed vulnerability + no retest
        if label == "confirmed_vulnerability" and (not reported_status or reported_status == "not_retested"):
            return ChecklistItemResult(
                item_id="SV-08",
                item_name="Retest and Closure Status",
                status="fail",
                response_action=ResponseAction.PENDING,
                reason=(
                    f"Confirmed vulnerability has not been retested (status={reported_status}). "
                    f"Retest must be scheduled to verify remediation effectiveness."
                ),
                taxonomy_codes=["RET"],
                actionable_fields=["retest"],
                pending_condition=(
                    "Awaiting retest to be scheduled and completed for this confirmed vulnerability. "
                    "The finding should remain open until retest confirms remediation."
                ),
            )

        # FAIL: retest claims fixed but no evidence
        if reported_status == "fixed" and not supported:
            return ChecklistItemResult(
                item_id="SV-08",
                item_name="Retest and Closure Status",
                status="fail",
                response_action=ResponseAction.REQUEST_DATA,
                reason=(
                    "Retest status is 'fixed' but no supporting evidence is provided. "
                    "Request retest evidence (retest report, screenshots, or test results)."
                ),
                taxonomy_codes=["RET"],
                actionable_fields=["retest"],
                data_request=(
                    "Provide retest evidence for this finding: retest report, "
                    "screenshots showing the fix, or test results confirming remediation."
                ),
            )

        # FAIL: not fixed or partially fixed — remediation in progress
        if reported_status in ("not_fixed", "partially_fixed"):
            return ChecklistItemResult(
                item_id="SV-08",
                item_name="Retest and Closure Status",
                status="fail",
                response_action=ResponseAction.PENDING,
                reason=(
                    f"Remediation is {'partially ' if reported_status == 'partially_fixed' else ''}'"
                    f"incomplete (status={reported_status}). Pending remediation completion."
                ),
                taxonomy_codes=["RET"],
                actionable_fields=["retest"],
                pending_condition=(
                    f"Awaiting remediation to be completed (current status: {reported_status}). "
                    f"Retest should be scheduled after remediation is finished."
                ),
            )

        # Fallback: no retest info but not a confirmed vulnerability
        if not reported_status and label != "confirmed_vulnerability":
            return ChecklistItemResult(
                item_id="SV-08",
                item_name="Retest and Closure Status",
                status="pass",
                response_action=ResponseAction.PASS,
                reason=(
                    f"No retest status reported, but finding is classified as '{label}' "
                    f"(not confirmed). Retest is recommended but not blocking."
                ),
                taxonomy_codes=["RET"],
            )

        # Catch-all
        return ChecklistItemResult(
            item_id="SV-08",
            item_name="Retest and Closure Status",
            status="pass",
            response_action=ResponseAction.PASS,
            reason="No actionable retest issues detected.",
            taxonomy_codes=["RET"],
        )

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _item_to_dict(item: ChecklistItemResult) -> dict:
        """Convert a ChecklistItemResult to a plain dict for JSON serialisation."""
        return {
            "item_id": item.item_id,
            "item_name": item.item_name,
            "status": item.status,
            "response_action": item.response_action.value,
            "reason": item.reason,
            "taxonomy_codes": item.taxonomy_codes,
            "actionable_fields": item.actionable_fields,
            "retry_check": item.retry_check,
            "data_request": item.data_request,
            "pending_condition": item.pending_condition,
            "escalate_reason": item.escalate_reason,
        }