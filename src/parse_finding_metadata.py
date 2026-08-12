import html
import json
import re
from pathlib import Path
from urllib.parse import urlparse


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
    / "DOC-000001-metadata.json"
)


FIELD_ALIASES = {
    "severity": {
        "severity",
    },
    "affected_targets": {
        "affected target",
        "affected targets",
    },
    "cwe": {
        "cwe",
        "cwe-id",
        "cwe id",
    },
    "impact": {
        "impact",
        "impact potential",
    },
    "retest_status": {
        "retest status",
        "re-test status",
    },
    "affected_user_roles": {
        "affected user role",
        "affected user roles",
    },
    "cvss": {
        "cvss",
        "cvss score",
    },
}


TARGET_TYPE_RULES = {
    "android": "android_application",
    "apk": "android_application",
    "ios": "ios_application",
    "web": "web_application",
    "url": "web_application",
    "api": "api",
    "jwt": "cryptographic_component",
    "token": "cryptographic_component",
    "network": "network",
    "cloud": "cloud_resource",
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
    """Collapse repeated whitespace."""
    return " ".join(value.split())


def normalize_field_name(value: str) -> str:
    """
    Normalize a metadata label for alias matching.

    The original label is preserved separately.
    """
    normalized = normalize_whitespace(value).casefold()
    normalized = normalized.replace("(", " ")
    normalized = normalized.replace(")", " ")
    normalized = normalized.replace(":", " ")

    return normalize_whitespace(normalized)


def identify_field(label: str) -> str | None:
    """Map one source-table label to a general field name."""
    normalized_label = normalize_field_name(label)

    for field_name, aliases in FIELD_ALIASES.items():
        if normalized_label in aliases:
            return field_name

    return None


def get_metadata_table(finding: dict) -> dict:
    """Return the single metadata table for one finding."""
    tables = [
        block
        for block in finding["raw_blocks"]
        if block["block_type"] == "table"
    ]

    if len(tables) != 1:
        raise ValueError(
            f"{finding['finding_id']} must contain exactly "
            f"one metadata table, found {len(tables)}."
        )

    return tables[0]


def table_to_field_map(table: dict) -> dict:
    """
    Convert two-column rows into a field map.

    Original labels and values are preserved.
    """
    field_map = {}

    for row in table["rows"]:
        cells = row.get("cells", [])

        if len(cells) < 2:
            raise ValueError(
                f"Table {table['table_number']}, "
                f"row {row['row_number']} contains fewer "
                "than two cells."
            )

        source_label = cells[0]
        source_value = cells[1]

        field_name = identify_field(source_label)

        if field_name is None:
            raise ValueError(
                f"Unknown metadata label: {source_label!r}"
            )

        if field_name in field_map:
            raise ValueError(
                f"Duplicate metadata field: {field_name}"
            )

        field_map[field_name] = {
            "source_label": source_label,
            "source_value": source_value,
            "row_number": row["row_number"],
        }

    return field_map


def parse_severity(raw_value: str) -> dict:
    """Normalize a reported severity without changing the source."""
    normalized = (
        normalize_whitespace(raw_value).casefold()
        if raw_value
        else None
    )

    allowed_values = {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "info",
        "unknown",
    }

    if normalized == "info":
        normalized = "informational"

    if normalized not in allowed_values:
        normalized = None

    return {
        "reported_value": raw_value,
        "normalized_value": normalized,
    }


def parse_cwe(raw_value: str) -> dict:
    """Extract a CWE identifier while preserving the full source value."""
    match = re.search(
        r"\bCWE-\d+\b",
        raw_value,
        flags=re.IGNORECASE,
    )

    cwe_id = match.group(0).upper() if match else None

    description = None

    if match:
        remaining = raw_value[match.end():]
        remaining = remaining.lstrip(" :-")

        if remaining:
            description = remaining

    return {
        "reported_value": raw_value,
        "cwe_id": cwe_id,
        "description": description,
        "parse_successful": cwe_id is not None,
    }


def parse_cvss(raw_value: str) -> dict:
    """
    Extract the reported score, version, and vector.

    This parser does not recalculate or correct CVSS.
    """
    score_match = re.search(
        r"^\s*([0-9]+(?:\.[0-9]+)?)",
        raw_value,
    )

    vector_match = re.search(
        r"CVSS:(\d\.\d)/"
        r"(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/"
        r"S:[UC]/C:[NLH]/I:[NLH]/A:[NLH])",
        raw_value,
        flags=re.IGNORECASE,
    )

    score = (
        float(score_match.group(1))
        if score_match
        else None
    )

    version = (
        vector_match.group(1)
        if vector_match
        else None
    )

    vector = (
        f"CVSS:{version}/{vector_match.group(2).upper()}"
        if vector_match
        else None
    )

    notes = []

    if score is None:
        notes.append("Reported CVSS score could not be parsed.")

    if vector is None:
        notes.append("Reported CVSS vector could not be parsed.")

    normalized_rendering = None

    if score is not None and vector is not None:
        normalized_rendering = f"{score} ({vector})"

        if normalize_whitespace(raw_value) != normalized_rendering:
            notes.append(
                "Source formatting differs from the normalized "
                "score and vector representation."
            )

    return {
        "reported_value": raw_value,
        "score": score,
        "version": version,
        "vector": vector,
        "normalized_rendering": normalized_rendering,
        "parse_successful": (
            score is not None
            and vector is not None
        ),
        "normalization_notes": notes,
    }


def extract_url(raw_value: str) -> str | None:
    """Extract the first HTTP or HTTPS URL if present."""
    decoded_value = html.unescape(raw_value)

    match = re.search(
        r"https?://[^\s\"'<>]+",
        decoded_value,
        flags=re.IGNORECASE,
    )

    if not match:
        return None

    return match.group(0).rstrip("])}.,;")


def infer_target_type(raw_value: str) -> str:
    """
    Infer only a broad structural target type.

    The original target value remains authoritative.
    """
    normalized = raw_value.casefold()

    extracted_url = extract_url(raw_value)

    if extracted_url:
        return "web_application"

    for indicator, target_type in TARGET_TYPE_RULES.items():
        if indicator in normalized:
            return target_type

    return "unknown"


def parse_affected_target(raw_value: str) -> dict:
    """Parse a general affected-target record."""
    extracted_url = extract_url(raw_value)

    notes = []

    if "<" in raw_value and ">" in raw_value:
        notes.append(
            "The source value appears to contain markup. "
            "The raw value has been preserved."
        )

    if extracted_url:
        parsed_url = urlparse(extracted_url)

        if not parsed_url.netloc:
            notes.append(
                "A URL-like value was found but the hostname "
                "could not be validated."
            )

    normalized_value = (
        extracted_url
        if extracted_url
        else normalize_whitespace(raw_value)
    )

    return {
        "target_type": infer_target_type(raw_value),
        "reported_value": raw_value,
        "normalized_value": normalized_value,
        "normalization_notes": notes,
    }


def parse_retest_status(raw_value: str) -> dict:
    """Represent an empty retest status as null."""
    normalized = normalize_whitespace(raw_value)

    return {
        "reported_value": raw_value,
        "normalized_value": normalized or None,
    }


def parse_user_roles(raw_value: str) -> dict:
    """Preserve the reported role statement."""
    normalized = normalize_whitespace(raw_value)

    return {
        "reported_value": raw_value,
        "normalized_values": (
            [normalized]
            if normalized
            else []
        ),
    }


def parse_impact(
    source_label: str,
    raw_value: str,
) -> dict:
    """Parse impact text and preserve whether it was marked potential."""
    normalized_label = normalize_field_name(source_label)

    return {
        "reported_value": raw_value,
        "is_marked_potential": (
            "potential" in normalized_label
        ),
    }


def parse_one_finding(finding: dict) -> dict:
    """Parse metadata for one raw finding."""
    table = get_metadata_table(finding)
    fields = table_to_field_map(table)

    required_fields = {
        "severity",
        "affected_targets",
        "cwe",
        "impact",
        "retest_status",
        "affected_user_roles",
        "cvss",
    }

    missing_fields = sorted(
        required_fields - set(fields.keys())
    )

    if missing_fields:
        raise ValueError(
            f"{finding['finding_id']} is missing fields: "
            f"{missing_fields}"
        )

    return {
        "finding_id": finding["finding_id"],
        "document_id": finding["document_id"],
        "title": finding["title"],
        "source_table_number": table["table_number"],
        "severity": parse_severity(
            fields["severity"]["source_value"]
        ),
        "affected_targets": [
            parse_affected_target(
                fields["affected_targets"]["source_value"]
            )
        ],
        "cwe": parse_cwe(
            fields["cwe"]["source_value"]
        ),
        "impact": parse_impact(
            fields["impact"]["source_label"],
            fields["impact"]["source_value"],
        ),
        "retest_status": parse_retest_status(
            fields["retest_status"]["source_value"]
        ),
        "affected_user_roles": parse_user_roles(
            fields["affected_user_roles"]["source_value"]
        ),
        "cvss": parse_cvss(
            fields["cvss"]["source_value"]
        ),
        "source_fields": fields,
    }


def main() -> None:
    raw_data = load_json(INPUT_PATH)

    parsed_findings = [
        parse_one_finding(finding)
        for finding in raw_data["findings"]
    ]

    output = {
        "parser_version": "0.1",
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

    print("Finding metadata parsing completed")
    print(f"Findings parsed: {len(parsed_findings)}")
    print(f"Output: {OUTPUT_PATH}")

    for finding in parsed_findings:
        cvss = finding["cvss"]

        print(
            f"- {finding['finding_id']}: "
            f"severity={finding['severity']['normalized_value']}, "
            f"cwe={finding['cwe']['cwe_id']}, "
            f"cvss_score={cvss['score']}, "
            f"cvss_vector_parsed={cvss['parse_successful']}"
        )


if __name__ == "__main__":
    main()