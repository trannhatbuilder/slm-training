from pathlib import Path
from typing import Iterator, Union

from docx import Document
from docx.document import Document as DocumentObject
from docx.table import Table
from docx.text.paragraph import Paragraph
from docx.oxml.table import CT_Tbl
from docx.oxml.text.paragraph import CT_P


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "DOC-000001.docx"
)

FINDING_TITLES = [
    "Hardcoded RabbitMQ Credentials in Mobile Application",
    "Use of Symmetric JWT Signing Algorithm (HS256)",
    "Root Detection Not Implemented",
    "Weak SSL Pinning Implementation",
    "Email Enumeration Possible During User Registration",
]


def normalize_text(text: str) -> str:
    """Normalize whitespace for inspection output only."""
    return " ".join(text.split())


def iter_document_blocks(
    document: DocumentObject,
) -> Iterator[Union[Paragraph, Table]]:
    """
    Yield paragraphs and tables in their actual document order.

    python-docx normally exposes paragraphs and tables separately.
    This function preserves their interleaved order.
    """
    document_element = document.element.body

    for child in document_element.iterchildren():
        if isinstance(child, CT_P):
            yield Paragraph(child, document)
        elif isinstance(child, CT_Tbl):
            yield Table(child, document)


def get_table_text(table: Table) -> str:
    """Return compact text for one table."""
    rows = []

    for row in table.rows:
        values = []

        for cell in row.cells:
            value = normalize_text(cell.text)

            if value:
                values.append(value)

        if values:
            rows.append(" | ".join(values))

    return " || ".join(rows)


def create_block_inventory(
    document: DocumentObject,
) -> list:
    """Create an ordered inventory of paragraphs and tables."""
    blocks = []
    paragraph_number = 0
    table_number = 0

    for block_number, block in enumerate(
        iter_document_blocks(document),
        start=1,
    ):
        if isinstance(block, Paragraph):
            paragraph_number += 1
            text = normalize_text(block.text)

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
                    "text": text,
                }
            )

        elif isinstance(block, Table):
            table_number += 1
            text = get_table_text(block)

            blocks.append(
                {
                    "block_number": block_number,
                    "block_type": "table",
                    "paragraph_number": None,
                    "table_number": table_number,
                    "style": None,
                    "text": text,
                }
            )

    return blocks


def find_finding_blocks(
    blocks: list[dict],
) -> None:
    """Print ordered context around each finding title."""
    print("=" * 90)
    print("ORDERED FINDING BLOCK CONTEXT")
    print("=" * 90)

    for title in FINDING_TITLES:
        matching_indexes = []

        for index, block in enumerate(blocks):
            if block["block_type"] != "paragraph":
                continue

            if (
                block["text"].casefold()
                == title.casefold()
            ):
                matching_indexes.append(index)

        print(f"\nFinding title: {title}")

        if not matching_indexes:
            print("Ordered block match: NOT FOUND")
            continue

        for matching_index in matching_indexes:
            start = max(0, matching_index - 2)
            end = min(
                len(blocks),
                matching_index + 10,
            )

            for context_index in range(start, end):
                block = blocks[context_index]

                marker = (
                    ">>>"
                    if context_index == matching_index
                    else "   "
                )

                text_preview = block["text"][:1200]

                if block["block_type"] == "paragraph":
                    identity = (
                        f"P{block['paragraph_number']} "
                        f"[{block['style']}]"
                    )
                else:
                    identity = (
                        f"T{block['table_number']}"
                    )

                print(
                    f"{marker} "
                    f"B{block['block_number']} "
                    f"{identity}: "
                    f"{text_preview}"
                )


def print_finding_region(
    blocks: list[dict],
) -> None:
    """
    Print all non-empty blocks from DETAILED FINDINGS
    to CONCLUSION & RECOMMENDATIONS.
    """
    start_index = None
    end_index = None

    for index, block in enumerate(blocks):
        if block["block_type"] != "paragraph":
            continue

        text = block["text"].casefold()

        if text == "detailed findings".casefold():
            start_index = index

        if (
            start_index is not None
            and text
            == "conclusion & recommendations".casefold()
        ):
            end_index = index
            break

    print("\n" + "=" * 90)
    print("DETAILED FINDINGS REGION")
    print("=" * 90)

    if start_index is None:
        print("Start marker was not found.")
        return

    if end_index is None:
        print("End marker was not found.")
        return

    for block in blocks[start_index : end_index + 1]:
        if not block["text"]:
            continue

        text_preview = block["text"][:1500]

        if block["block_type"] == "paragraph":
            identity = (
                f"P{block['paragraph_number']} "
                f"[{block['style']}]"
            )
        else:
            identity = f"T{block['table_number']}"

        print(
            f"B{block['block_number']} "
            f"{identity}: "
            f"{text_preview}"
        )


def main() -> None:
    if not REPORT_PATH.exists():
        raise FileNotFoundError(
            f"Source report was not found: {REPORT_PATH}"
        )

    document = Document(REPORT_PATH)
    blocks = create_block_inventory(document)

    paragraph_blocks = [
        block
        for block in blocks
        if block["block_type"] == "paragraph"
    ]

    table_blocks = [
        block
        for block in blocks
        if block["block_type"] == "table"
    ]

    print("Ordered DOCX block inspection")
    print(f"Report: {REPORT_PATH.name}")
    print(f"Total ordered blocks: {len(blocks)}")
    print(f"Paragraph blocks: {len(paragraph_blocks)}")
    print(f"Table blocks: {len(table_blocks)}")

    find_finding_blocks(blocks)
    print_finding_region(blocks)


if __name__ == "__main__":
    main()