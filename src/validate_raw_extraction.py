import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "redacted"
    / "DOC-000001-findings-raw.json"
)

EXPECTED_FINDINGS = {
    "FND-000001": {
        "title": (
            "Hardcoded RabbitMQ Credentials "
            "in Mobile Application"
        ),
        "expected_table_number": 20,
    },
    "FND-000002": {
        "title": (
            "Use of Symmetric JWT Signing "
            "Algorithm (HS256)"
        ),
        "expected_table_number": 21,
    },
    "FND-000003": {
        "title": "Root Detection Not Implemented",
        "expected_table_number": 22,
    },
    "FND-000004": {
        "title": "Weak SSL Pinning Implementation",
        "expected_table_number": 23,
    },
    "FND-000005": {
        "title": (
            "Email Enumeration Possible "
            "During User Registration"
        ),
        "expected_table_number": 24,
    },
}

EXPECTED_SECTION_LABELS = [
    "observation",
    "exploitation",
]

RECOMMENDATION_LABELS = [
    "recommendation",
    "recommendations",
    "remediation",
]


def load_json(path: Path) -> dict:
    """Load one UTF-8 JSON document."""
    if not path.exists():
        raise FileNotFoundError(
            f"Raw extraction file was not found: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def get_paragraph_texts(finding: dict) -> list:
    """Return non-empty paragraph text from one finding."""
    return [
        block["text"]
        for block in finding["raw_blocks"]
        if (
            block["block_type"] == "paragraph"
            and block.get("text")
        )
    ]


def get_normalized_paragraphs(
    finding: dict,
) -> list:
    """Return case-insensitive paragraph values."""
    return [
        text.strip().casefold()
        for text in get_paragraph_texts(finding)
    ]


def get_table_blocks(finding: dict) -> list:
    """Return all table blocks belonging to one finding."""
    return [
        block
        for block in finding["raw_blocks"]
        if block["block_type"] == "table"
    ]


def find_recommendation_label(
    normalized_paragraphs: list[str],
) -> str | None:
    """Return the recommendation-style label if present."""
    for paragraph in normalized_paragraphs:
        label = paragraph.rstrip(":")

        if label in RECOMMENDATION_LABELS:
            return paragraph

    return None


def validate_finding(
    finding: dict,
    expected: dict,
) -> list:
    """
    Validate extraction structure only.
    This function does not assess whether the finding is
    technically correct.
    """
    issues = []

    finding_id = finding.get("finding_id")
    title = finding.get("title")

    if title != expected["title"]:
        issues.append(
            {
                "check": "title_match",
                "status": "failed",
                "message": (
                    f"Expected title {expected['title']!r}, "
                    f"but found {title!r}."
                ),
            }
        )

    paragraph_texts = get_paragraph_texts(finding)
    normalized_paragraphs = get_normalized_paragraphs(
        finding
    )

    if not paragraph_texts:
        issues.append(
            {
                "check": "paragraph_content",
                "status": "failed",
                "message": "No non-empty paragraphs were extracted.",
            }
        )

    elif paragraph_texts[0] != expected["title"]:
        issues.append(
            {
                "check": "first_paragraph_title",
                "status": "failed",
                "message": (
                    "The first non-empty paragraph is not "
                    "the expected finding title."
                ),
            }
        )

    table_blocks = get_table_blocks(finding)

    if len(table_blocks) != 1:
        issues.append(
            {
                "check": "metadata_table_count",
                "status": "failed",
                "message": (
                    "Expected exactly one metadata table, "
                    f"but found {len(table_blocks)}."
                ),
            }
        )

    elif (
        table_blocks[0].get("table_number")
        != expected["expected_table_number"]
    ):
        issues.append(
            {
                "check": "metadata_table_number",
                "status": "failed",
                "message": (
                    "Unexpected metadata table number: "
                    f"{table_blocks[0].get('table_number')}."
                ),
            }
        )

    for section_label in EXPECTED_SECTION_LABELS:
        if section_label not in normalized_paragraphs:
            issues.append(
                {
                    "check": (
                        f"section_label_{section_label}"
                    ),
                    "status": "failed",
                    "message": (
                        f"Section label {section_label!r} "
                        "was not found."
                    ),
                }
            )

    recommendation_label = find_recommendation_label(
        normalized_paragraphs
    )

    if recommendation_label is None:
        issues.append(
            {
                "check": "recommendation_section",
                "status": "failed",
                "message": (
                    "No Recommendation, Recommendations, "
                    "or Remediation label was found."
                ),
            }
        )

    retest_labels = [
        paragraph
        for paragraph in normalized_paragraphs
        if paragraph.startswith(
            "re-test verification result"
        )
    ]

    if len(retest_labels) != 1:
        issues.append(
            {
                "check": "retest_label_count",
                "status": "failed",
                "message": (
                    "Expected one Re-Test Verification "
                    f"Result label, but found {len(retest_labels)}."
                ),
            }
        )

    block_numbers = [
        block["block_number"]
        for block in finding["raw_blocks"]
    ]

    if block_numbers != list(
        range(
            block_numbers[0],
            block_numbers[-1] + 1,
        )
    ):
        issues.append(
            {
                "check": "continuous_block_range",
                "status": "failed",
                "message": (
                    "Finding raw blocks are not continuous."
                ),
            }
        )

    return issues


def main() -> None:
    data = load_json(INPUT_PATH)

    findings = data.get("findings", [])

    if data.get("finding_count") != 5:
        raise ValueError(
            "The top-level finding_count is not 5."
        )

    if len(findings) != 5:
        raise ValueError(
            f"Expected 5 finding records, found {len(findings)}."
        )

    observed_ids = [
        finding.get("finding_id")
        for finding in findings
    ]

    expected_ids = list(EXPECTED_FINDINGS.keys())

    if observed_ids != expected_ids:
        raise ValueError(
            "Finding IDs or finding order do not match "
            "the registered inventory."
        )

    total_issues = 0

    print("Raw extraction validation")
    print(f"Input: {INPUT_PATH.name}")
    print(f"Findings checked: {len(findings)}")
    print()

    for finding in findings:
        finding_id = finding["finding_id"]
        expected = EXPECTED_FINDINGS[finding_id]

        issues = validate_finding(
            finding,
            expected,
        )

        if issues:
            total_issues += len(issues)
            status = "FAILED"
        else:
            status = "PASSED"

        print(
            f"{finding_id}: {status} - "
            f"{finding['title']}"
        )

        for issue in issues:
            print(
                f"  - {issue['check']}: "
                f"{issue['message']}"
            )

    print()
    print(f"Total validation issues: {total_issues}")

    if total_issues:
        raise SystemExit(1)

    print("Raw extraction structure is valid.")


if __name__ == "__main__":
    main()