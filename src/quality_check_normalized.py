import json
import re
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "normalized"
    / "DOC-000001-findings-normalized.json"
)

SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "input_schema.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "artifacts"
    / "metrics"
    / "DOC-000001-normalized-quality.json"
)


PLACEHOLDER_VALUES = {
    "tbd",
    "to be determined",
    "to be updated",
    "todo",
    "placeholder",
    "pending update",
}


def load_json(path: Path) -> dict:
    """Load one UTF-8 JSON file."""
    if not path.exists():
        raise FileNotFoundError(
            f"Required file was not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def is_blank(value) -> bool:
    """Return True when a value contains no useful content."""
    if value is None:
        return True

    if isinstance(value, str):
        return not value.strip()

    if isinstance(value, list):
        return len(value) == 0

    return False


def contains_placeholder(value: str | None) -> bool:
    """Detect explicit unfinished placeholder text."""
    if not value:
        return False

    normalized = " ".join(value.split()).casefold()
    normalized = normalized.rstrip(":.")

    return normalized in PLACEHOLDER_VALUES


def expected_severity_from_score(
    score: float | None,
) -> str | None:
    """
    Map a CVSS score to its standard severity range.
    This check records a consistency flag only. It does not
    change the severity reported in the source document.
    """
    if score is None:
        return None

    if score == 0:
        return "informational"

    if 0.1 <= score <= 3.9:
        return "low"

    if 4.0 <= score <= 6.9:
        return "medium"

    if 7.0 <= score <= 8.9:
        return "high"

    if 9.0 <= score <= 10.0:
        return "critical"

    return None


def validate_schema(
    finding: dict,
    schema: dict,
) -> list:
    """Return JSON Schema validation issues."""
    validator = Draft202012Validator(schema)

    errors = sorted(
        validator.iter_errors(finding),
        key=lambda error: list(error.absolute_path),
    )

    issues = []

    for error in errors:
        location = ".".join(
            str(part)
            for part in error.absolute_path
        )

        issues.append(
            {
                "check_id": "QC-SCHEMA-001",
                "category": "schema",
                "severity": "error",
                "field": location or "<root>",
                "message": error.message,
            }
        )

    return issues


def check_required_content(
    finding: dict,
) -> list:
    """Check whether core review content is present."""
    issues = []

    required_content = {
        "title": finding.get("title"),
        "affected_targets": finding.get(
            "affected_targets"
        ),
        "impact": finding.get("impact"),
        "observation": finding.get("observation"),
        "evidence": finding.get("evidence"),
        "recommendation": finding.get(
            "recommendation"
        ),
    }

    for field, value in required_content.items():
        if is_blank(value):
            issues.append(
                {
                    "check_id": "QC-CONTENT-001",
                    "category": "completeness",
                    "severity": "error",
                    "field": field,
                    "message": (
                        f"Required review content is empty: "
                        f"{field}."
                    ),
                }
            )

    return issues


def check_placeholders(
    finding: dict,
) -> list:
    """Detect unfinished placeholders in text fields."""
    issues = []

    text_fields = {
        "title": finding.get("title"),
        "impact": finding.get("impact"),
        "observation": finding.get("observation"),
    }

    for field, value in text_fields.items():
        if contains_placeholder(value):
            issues.append(
                {
                    "check_id": "QC-CONTENT-002",
                    "category": "completeness",
                    "severity": "warning",
                    "field": field,
                    "message": (
                        f"Placeholder content detected "
                        f"in {field}."
                    ),
                }
            )

    for index, recommendation in enumerate(
        finding.get("recommendation", [])
    ):
        if contains_placeholder(recommendation):
            issues.append(
                {
                    "check_id": "QC-CONTENT-002",
                    "category": "completeness",
                    "severity": "warning",
                    "field": (
                        f"recommendation[{index}]"
                    ),
                    "message": (
                        "Placeholder content detected "
                        "in recommendation."
                    ),
                }
            )

    return issues


def check_cvss_consistency(
    finding: dict,
) -> list:
    """Compare reported severity with the CVSS score range."""
    issues = []

    reported_severity = finding.get("severity")
    score = finding.get("cvss", {}).get("score")

    expected_severity = expected_severity_from_score(
        score
    )

    if (
        reported_severity is not None
        and expected_severity is not None
        and reported_severity != expected_severity
    ):
        issues.append(
            {
                "check_id": "QC-CVSS-001",
                "category": "cvss",
                "severity": "warning",
                "field": "severity",
                "message": (
                    f"Reported severity "
                    f"{reported_severity!r} does not match "
                    f"the CVSS score range for score {score}. "
                    f"Expected range: "
                    f"{expected_severity!r}."
                ),
                "reported_severity": reported_severity,
                "cvss_score": score,
                "expected_severity": expected_severity,
            }
        )

    return issues


def check_retest_state(
    finding: dict,
) -> list:
    """Record incomplete retest information without inferring status."""
    issues = []

    retest = finding.get("retest", {})

    status = retest.get("status")
    verification_result = retest.get(
        "verification_result"
    )

    if status is None and verification_result is None:
        issues.append(
            {
                "check_id": "QC-RETEST-001",
                "category": "retest",
                "severity": "warning",
                "field": "retest",
                "message": (
                    "Retest status and verification result "
                    "are not available in the extracted finding."
                ),
            }
        )

    elif status is not None and verification_result is None:
        issues.append(
            {
                "check_id": "QC-RETEST-002",
                "category": "retest",
                "severity": "warning",
                "field": "retest.verification_result",
                "message": (
                    "A retest status exists without a "
                    "verification result."
                ),
            }
        )

    return issues


def check_source_traceability(
    finding: dict,
) -> list:
    """Check whether a normalized finding can be traced."""
    issues = []

    source = finding.get("source", {})

    if not source.get("document_id"):
        issues.append(
            {
                "check_id": "QC-SOURCE-001",
                "category": "traceability",
                "severity": "error",
                "field": "source.document_id",
                "message": "Source document ID is missing.",
            }
        )

    if not source.get("source_reference"):
        issues.append(
            {
                "check_id": "QC-SOURCE-002",
                "category": "traceability",
                "severity": "error",
                "field": "source.source_reference",
                "message": "Source reference is missing.",
            }
        )

    return issues


def check_governance(
    finding: dict,
) -> list:
    """Check whether the record is approved for this project."""
    issues = []

    governance = finding.get("governance", {})

    if governance.get("usage_approved") is not True:
        issues.append(
            {
                "check_id": "QC-GOV-001",
                "category": "governance",
                "severity": "error",
                "field": "governance.usage_approved",
                "message": (
                    "The finding is not approved for use."
                ),
            }
        )

    if governance.get("usage_scope") != "internal":
        issues.append(
            {
                "check_id": "QC-GOV-002",
                "category": "governance",
                "severity": "warning",
                "field": "governance.usage_scope",
                "message": (
                    "The finding is not marked for "
                    "internal usage."
                ),
            }
        )

    return issues


def text_fingerprint(finding: dict) -> str:
    """
    Create a simple exact duplicate fingerprint.

    This does not detect near duplicates.
    """
    title = finding.get("title") or ""
    observation = finding.get("observation") or ""

    normalized = (
        f"{title}\n{observation}"
        .casefold()
        .strip()
    )

    normalized = re.sub(
        r"\s+",
        " ",
        normalized,
    )

    return normalized


def evaluate_finding(
    finding: dict,
    schema: dict,
) -> dict:
    """Run all current deterministic quality checks."""
    issues = []

    issues.extend(
        validate_schema(
            finding,
            schema,
        )
    )

    issues.extend(
        check_required_content(finding)
    )

    issues.extend(
        check_placeholders(finding)
    )

    issues.extend(
        check_cvss_consistency(finding)
    )

    issues.extend(
        check_retest_state(finding)
    )

    issues.extend(
        check_source_traceability(finding)
    )

    issues.extend(
        check_governance(finding)
    )

    severity_counts = Counter(
        issue["severity"]
        for issue in issues
    )

    if severity_counts["error"] > 0:
        quality_status = "blocked"

    elif severity_counts["warning"] > 0:
        quality_status = "needs_review"

    else:
        quality_status = "passed"

    return {
        "finding_id": finding["finding_id"],
        "title": finding["title"],
        "quality_status": quality_status,
        "issue_counts": {
            "error": severity_counts["error"],
            "warning": severity_counts["warning"],
            "suggestion": severity_counts[
                "suggestion"
            ],
        },
        "issues": issues,
    }


def detect_exact_duplicates(
    findings: list[dict],
) -> list:
    """Detect exact title and observation duplicates."""
    fingerprints = {}

    for finding in findings:
        fingerprint = text_fingerprint(finding)

        fingerprints.setdefault(
            fingerprint,
            [],
        ).append(
            finding["finding_id"]
        )

    duplicates = []

    for finding_ids in fingerprints.values():
        if len(finding_ids) > 1:
            duplicates.append(
                {
                    "finding_ids": finding_ids,
                    "duplicate_type": (
                        "exact_title_observation"
                    ),
                }
            )

    return duplicates


def main() -> None:
    normalized_data = load_json(INPUT_PATH)
    schema = load_json(SCHEMA_PATH)

    findings = normalized_data.get(
        "findings",
        [],
    )

    if len(findings) != 5:
        raise ValueError(
            f"Expected 5 findings, found {len(findings)}."
        )

    results = [
        evaluate_finding(
            finding,
            schema,
        )
        for finding in findings
    ]

    duplicates = detect_exact_duplicates(
        findings
    )

    total_counts = Counter()

    for result in results:
        total_counts.update(
            result["issue_counts"]
        )

    summary = {
        "document_id": normalized_data[
            "document_id"
        ],
        "quality_check_version": "0.1",
        "finding_count": len(findings),
        "status_counts": dict(
            Counter(
                result["quality_status"]
                for result in results
            )
        ),
        "issue_counts": {
            "error": total_counts["error"],
            "warning": total_counts["warning"],
            "suggestion": total_counts[
                "suggestion"
            ],
        },
        "exact_duplicate_groups": duplicates,
    }

    output = {
        "summary": summary,
        "finding_results": results,
    }

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_PATH.write_text(
        json.dumps(
            output,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("Normalized quality check completed")
    print(f"Findings checked: {len(findings)}")
    print(
        f"Errors: {summary['issue_counts']['error']}"
    )
    print(
        f"Warnings: "
        f"{summary['issue_counts']['warning']}"
    )
    print(
        f"Exact duplicate groups: "
        f"{len(duplicates)}"
    )
    print()

    for result in results:
        print(
            f"- {result['finding_id']}: "
            f"{result['quality_status']} "
            f"(errors="
            f"{result['issue_counts']['error']}, "
            f"warnings="
            f"{result['issue_counts']['warning']})"
        )

        for issue in result["issues"]:
            print(
                f"  - {issue['check_id']} "
                f"[{issue['severity']}]: "
                f"{issue['message']}"
            )

    print()
    print(f"Quality report: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()