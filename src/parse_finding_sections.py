import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "redacted"
    / "DOC-000001-findings-raw.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "normalized"
    / "DOC-000001-sections.json"
)


SECTION_ALIASES = {
    "observation": {
        "observation",
        "observations",
    },
    "exploitation": {
        "exploitation",
        "proof of concept",
        "proof-of-concept",
        "reproduction",
        "reproduction steps",
        "steps to reproduce",
    },
    "recommendation": {
        "recommendation",
        "recommendations",
        "remediation",
        "remediations",
    },
    "retest_verification": {
        "re-test verification result",
        "retest verification result",
        "re-test result",
        "retest result",
    },
}


def load_json(path: Path) -> dict:
    """Load one UTF-8 JSON file."""
    if not path.exists():
        raise FileNotFoundError(
            f"Input file was not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def normalize_whitespace(value: str) -> str:
    """Collapse repeated whitespace without changing wording."""
    return " ".join(value.split())


def normalize_section_label(value: str) -> str:
    """Normalize a paragraph for section-label matching."""
    normalized = normalize_whitespace(value).casefold()
    normalized = normalized.rstrip(":")
    normalized = normalize_whitespace(normalized)

    return normalized


def identify_section_label(value: str) -> str | None:
    """Return a canonical section name when value is a known label."""
    normalized = normalize_section_label(value)

    for section_name, aliases in SECTION_ALIASES.items():
        if normalized in aliases:
            return section_name

    return None


def get_paragraph_blocks(finding: dict) -> list:
    """Return paragraph blocks from one raw finding."""
    return [
        block
        for block in finding["raw_blocks"]
        if block["block_type"] == "paragraph"
    ]


def create_section_record(
    section_name: str,
    source_label: str | None,
    source_label_block: int | None,
    content_blocks: list[dict],
) -> dict:
    """Create one section record while preserving source blocks."""
    non_empty_blocks = [
        block
        for block in content_blocks
        if block.get("text")
    ]

    paragraphs = [
        block["text"]
        for block in non_empty_blocks
    ]

    combined_text = (
        "\n\n".join(paragraphs)
        if paragraphs
        else None
    )

    return {
        "section_name": section_name,
        "source_label": source_label,
        "source_label_block": source_label_block,
        "content_block_numbers": [
            block["block_number"]
            for block in non_empty_blocks
        ],
        "paragraphs": paragraphs,
        "combined_text": combined_text,
        "content_present": bool(paragraphs),
    }


def parse_sections(finding: dict) -> dict:
    """
    Split finding paragraphs into general narrative sections.

    The first paragraph is the finding title. Table blocks are excluded
    because metadata is parsed separately.
    """
    paragraph_blocks = get_paragraph_blocks(finding)

    non_empty_paragraphs = [
        block
        for block in paragraph_blocks
        if block.get("text")
    ]

    if not non_empty_paragraphs:
        raise ValueError(
            f"{finding['finding_id']} has no paragraph content."
        )

    first_paragraph = non_empty_paragraphs[0]

    if first_paragraph["text"] != finding["title"]:
        raise ValueError(
            f"{finding['finding_id']} does not begin with "
            "its registered finding title."
        )

    section_markers = []

    for index, block in enumerate(paragraph_blocks):
        text = block.get("text")

        if not text:
            continue

        section_name = identify_section_label(text)

        if section_name is not None:
            section_markers.append(
                {
                    "paragraph_list_index": index,
                    "section_name": section_name,
                    "source_label": text,
                    "block_number": block["block_number"],
                }
            )

    observed_section_names = [
        marker["section_name"]
        for marker in section_markers
    ]

    duplicates = sorted(
        {
            section_name
            for section_name in observed_section_names
            if observed_section_names.count(section_name) > 1
        }
    )

    if duplicates:
        raise ValueError(
            f"{finding['finding_id']} has duplicate section labels: "
            f"{duplicates}"
        )

    sections = {
        "observation": create_section_record(
            "observation",
            None,
            None,
            [],
        ),
        "exploitation": create_section_record(
            "exploitation",
            None,
            None,
            [],
        ),
        "recommendation": create_section_record(
            "recommendation",
            None,
            None,
            [],
        ),
        "retest_verification": create_section_record(
            "retest_verification",
            None,
            None,
            [],
        ),
    }

    for marker_index, marker in enumerate(section_markers):
        content_start = marker["paragraph_list_index"] + 1

        if marker_index + 1 < len(section_markers):
            content_end = section_markers[
                marker_index + 1
            ]["paragraph_list_index"]
        else:
            content_end = len(paragraph_blocks)

        content_blocks = paragraph_blocks[
            content_start:content_end
        ]

        sections[marker["section_name"]] = (
            create_section_record(
                section_name=marker["section_name"],
                source_label=marker["source_label"],
                source_label_block=marker["block_number"],
                content_blocks=content_blocks,
            )
        )

    unclassified_blocks = []

    first_section_index = (
        section_markers[0]["paragraph_list_index"]
        if section_markers
        else len(paragraph_blocks)
    )

    for block in paragraph_blocks[1:first_section_index]:
        if block.get("text"):
            unclassified_blocks.append(
                {
                    "block_number": block["block_number"],
                    "text": block["text"],
                }
            )

    missing_labels = [
        section_name
        for section_name in sections
        if sections[section_name]["source_label"] is None
    ]

    empty_sections = [
        section_name
        for section_name in sections
        if (
            sections[section_name]["source_label"] is not None
            and not sections[section_name]["content_present"]
        )
    ]

    return {
        "finding_id": finding["finding_id"],
        "document_id": finding["document_id"],
        "title": finding["title"],
        "sections": sections,
        "unclassified_paragraphs": unclassified_blocks,
        "section_parse_summary": {
            "labels_found": observed_section_names,
            "missing_labels": missing_labels,
            "empty_sections": empty_sections,
            "unclassified_paragraph_count": len(
                unclassified_blocks
            ),
        },
    }


def main() -> None:
    raw_data = load_json(INPUT_PATH)

    parsed_findings = [
        parse_sections(finding)
        for finding in raw_data["findings"]
    ]

    output = {
        "section_parser_version": "0.1",
        "document_id": raw_data["document_id"],
        "source_extraction_version": raw_data[
            "extraction_version"
        ],
        "finding_count": len(parsed_findings),
        "technical_content_reviewed": False,
        "findings": parsed_findings,
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

    print("Finding section parsing completed")
    print(f"Findings parsed: {len(parsed_findings)}")
    print(f"Output: {OUTPUT_PATH}")
    print()

    for finding in parsed_findings:
        summary = finding["section_parse_summary"]

        print(
            f"- {finding['finding_id']}: "
            f"labels={summary['labels_found']}, "
            f"missing={summary['missing_labels']}, "
            f"empty={summary['empty_sections']}, "
            f"unclassified="
            f"{summary['unclassified_paragraph_count']}"
        )


if __name__ == "__main__":
    main()