import json
from pathlib import Path
from typing import Iterator, Union

from docx import Document
from docx.document import Document as DocumentObject
from docx.oxml.table import CT_Tbl
from docx.oxml.text.paragraph import CT_P
from docx.table import Table
from docx.text.paragraph import Paragraph


PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "DOC-000001.docx"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "redacted"
    / "DOC-000001-findings-raw.json"
)

DOCUMENT_ID = "DOC-000001"

FINDING_TITLES = [
    "Hardcoded RabbitMQ Credentials in Mobile Application",
    "Use of Symmetric JWT Signing Algorithm (HS256)",
    "Root Detection Not Implemented",
    "Weak SSL Pinning Implementation",
    "Email Enumeration Possible During User Registration",
]


def normalize_whitespace(text: str) -> str:
    """
    Normalize repeated whitespace produced by DOCX extraction.

    This function does not change technical meaning or wording.
    """
    return " ".join(text.split())


def iter_document_blocks(
    document: DocumentObject,
) -> Iterator[Union[Paragraph, Table]]:
    """Yield paragraphs and tables in their actual document order."""
    for child in document.element.body.iterchildren():
        if isinstance(child, CT_P):
            yield Paragraph(child, document)

        elif isinstance(child, CT_Tbl):
            yield Table(child, document)


def extract_table_rows(table: Table) -> list:
    """
    Extract table rows without interpreting their technical meaning.

    Each row is preserved as a list of cell values because some tables
    may differ across customers and report templates.
    """
    extracted_rows = []

    for row_number, row in enumerate(table.rows, start=1):
        cells = [
            normalize_whitespace(cell.text)
            for cell in row.cells
        ]

        extracted_rows.append(
            {
                "row_number": row_number,
                "cells": cells,
            }
        )

    return extracted_rows


def create_block_inventory(
    document: DocumentObject,
) -> list:
    """Create an ordered inventory of all DOCX body blocks."""
    blocks = []

    paragraph_number = 0
    table_number = 0

    for block_number, block in enumerate(
        iter_document_blocks(document),
        start=1,
    ):
        if isinstance(block, Paragraph):
            paragraph_number += 1

            style_name = (
                block.style.name
                if block.style
                else None
            )

            blocks.append(
                {
                    "block_number": block_number,
                    "block_type": "paragraph",
                    "paragraph_number": paragraph_number,
                    "table_number": None,
                    "style": style_name,
                    "text": normalize_whitespace(block.text),
                    "rows": None,
                }
            )

        elif isinstance(block, Table):
            table_number += 1

            blocks.append(
                {
                    "block_number": block_number,
                    "block_type": "table",
                    "paragraph_number": None,
                    "table_number": table_number,
                    "style": None,
                    "text": None,
                    "rows": extract_table_rows(block),
                }
            )

    return blocks


def find_exact_title_block(
    blocks: list[dict],
    title: str,
) -> int:
    """Return the list index of one exact finding-title paragraph."""
    matches = []

    for index, block in enumerate(blocks):
        if block["block_type"] != "paragraph":
            continue

        if block["text"].casefold() == title.casefold():
            matches.append(index)

    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one title match for {title!r}, "
            f"but found {len(matches)}."
        )

    return matches[0]


def extract_finding_blocks(
    blocks: list[dict],
) -> list:
    """
    Extract each finding from its exact title until the next finding.

    The final finding ends before the report's
    CONCLUSION & RECOMMENDATIONS heading.
    """
    title_indexes = [
        find_exact_title_block(blocks, title)
        for title in FINDING_TITLES
    ]

    if title_indexes != sorted(title_indexes):
        raise ValueError(
            "Finding titles were not found in the expected document order."
        )

    findings = []

    for finding_offset, title in enumerate(
        FINDING_TITLES,
        start=1,
    ):
        start_index = title_indexes[finding_offset - 1]

        if finding_offset < len(FINDING_TITLES):
            end_index = title_indexes[finding_offset]

        else:
            end_index = None

            for index in range(start_index + 1, len(blocks)):
                block = blocks[index]

                if block["block_type"] != "paragraph":
                    continue

                if (
                    block["text"].casefold()
                    == "CONCLUSION & RECOMMENDATIONS".casefold()
                ):
                    end_index = index
                    break

            if end_index is None:
                raise ValueError(
                    "The final finding end marker was not found."
                )

        finding_blocks = blocks[start_index:end_index]

        non_empty_blocks = [
            block
            for block in finding_blocks
            if (
                block["block_type"] == "table"
                or block["text"]
            )
        ]

        finding_id = f"FND-{finding_offset:06d}"

        findings.append(
            {
                "finding_id": finding_id,
                "document_id": DOCUMENT_ID,
                "title": title,
                "source_title_block": {
                    "block_number": blocks[start_index]["block_number"],
                    "paragraph_number": blocks[start_index][
                        "paragraph_number"
                    ],
                    "style": blocks[start_index]["style"],
                },
                "extraction": {
                    "start_block_number": blocks[start_index][
                        "block_number"
                    ],
                    "end_block_number": blocks[end_index - 1][
                        "block_number"
                    ],
                    "block_count": len(finding_blocks),
                    "non_empty_block_count": len(non_empty_blocks),
                },
                "raw_blocks": finding_blocks,
            }
        )

    return findings


def validate_extraction(findings: list[dict]) -> None:
    """Run basic extraction checks without reviewing technical content."""
    if len(findings) != 5:
        raise ValueError(
            f"Expected 5 findings, but extracted {len(findings)}."
        )

    finding_ids = [
        finding["finding_id"]
        for finding in findings
    ]

    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("Duplicate finding IDs were generated.")

    for finding in findings:
        table_blocks = [
            block
            for block in finding["raw_blocks"]
            if block["block_type"] == "table"
        ]

        if not table_blocks:
            raise ValueError(
                f"{finding['finding_id']} does not contain "
                "a metadata table."
            )


def main() -> None:
    if not REPORT_PATH.exists():
        raise FileNotFoundError(
            f"Source report was not found: {REPORT_PATH}"
        )

    document = Document(REPORT_PATH)
    blocks = create_block_inventory(document)
    findings = extract_finding_blocks(blocks)

    validate_extraction(findings)

    output = {
        "extraction_version": "0.1",
        "document_id": DOCUMENT_ID,
        "source_filename": REPORT_PATH.name,
        "finding_count": len(findings),
        "normalization_applied": [
            "repeated_whitespace_collapsed"
        ],
        "technical_content_reviewed": False,
        "findings": findings,
    }

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_PATH.write_text(
        json.dumps(
            output,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print("Raw finding extraction completed")
    print(f"Source document: {REPORT_PATH.name}")
    print(f"Findings extracted: {len(findings)}")
    print(f"Output: {OUTPUT_PATH}")

    for finding in findings:
        print(
            f"- {finding['finding_id']}: "
            f"{finding['title']} "
            f"({finding['extraction']['block_count']} blocks)"
        )


if __name__ == "__main__":
    main()