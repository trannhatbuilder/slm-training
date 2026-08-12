import json
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


PROJECT_ROOT = Path(__file__).resolve().parent.parent

METADATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "normalized"
    / "DOC-000001-metadata.json"
)

SECTIONS_PATH = (
    PROJECT_ROOT
    / "data"
    / "normalized"
    / "DOC-000001-sections.json"
)

RAW_EXTRACTION_PATH = (
    PROJECT_ROOT
    / "data"
    / "redacted"
    / "DOC-000001-findings-raw.json"
)

INPUT_SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "input_schema.json"
)

OUTPUT_JSON_PATH = (
    PROJECT_ROOT
    / "data"
    / "normalized"
    / "DOC-000001-findings-normalized.json"
)

OUTPUT_JSONL_PATH = (
    PROJECT_ROOT
    / "data"
    / "normalized"
    / "DOC-000001-findings-normalized.jsonl"
)

DOCUMENT_ID = "DOC-000001"
INPUT_SCHEMA_VERSION = "0.2"
NORMALIZATION_VERSION = "0.1"


def load_json(path: Path) -> dict:
    """Load one UTF-8 JSON file."""
    if not path.exists():
        raise FileNotFoundError(
            f"Required input file was not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def index_findings(data: dict) -> dict[str, dict]:
    """Index finding records by finding_id."""
    findings = data.get("findings", [])

    indexed = {}

    for finding in findings:
        finding_id = finding.get("finding_id")

        if not finding_id:
            raise ValueError(
                "A finding record does not contain finding_id."
            )

        if finding_id in indexed:
            raise ValueError(
                f"Duplicate finding ID: {finding_id}"
            )

        indexed[finding_id] = finding

    return indexed


def build_affected_targets(
    metadata_finding: dict,
) -> list:
    """
    Convert parsed targets to Input Schema v0.2.
    Source values remain available in the metadata artifact.
    """
    targets = []

    for target in metadata_finding["affected_targets"]:
        targets.append(
            {
                "target_type": target["target_type"],
                "value": target["normalized_value"],
                "description": None,
            }
        )

    return targets


def build_evidence(
    finding_id: str,
    sections_finding: dict,
) -> list:
    """
    Represent source exploitation or reproduction content as evidence.
    This does not conclude that the evidence is sufficient.
    """
    exploitation = sections_finding["sections"]["exploitation"]

    if not exploitation["content_present"]:
        return []

    return [
        {
            "evidence_id": f"{finding_id}-EVID-001",
            "evidence_type": "reproduction_steps",
            "description": (
                "Exploitation or reproduction information "
                "extracted from the source finding."
            ),
            "content": exploitation["combined_text"],
            "availability": "full_content",
        }
    ]


def build_references(
    metadata_finding: dict,
) -> list:
    """Build references without duplicating cwe_id semantics."""
    references = []

    cwe_id = metadata_finding["cwe"]["cwe_id"]

    if cwe_id:
        references.append(
            {
                "reference_type": "cwe",
                "value": cwe_id,
            }
        )

    return references


def build_retest(
    metadata_finding: dict,
    sections_finding: dict,
) -> dict:
    """
    Build retest data without inferring a status.

    A blank source status and an empty verification section remain null.
    """
    status = metadata_finding[
        "retest_status"
    ]["normalized_value"]

    verification = sections_finding[
        "sections"
    ]["retest_verification"]

    verification_result = (
        verification["combined_text"]
        if verification["content_present"]
        else None
    )

    if status is None and verification_result is None:
        applicable = None
    else:
        applicable = True

    return {
        "applicable": applicable,
        "status": status,
        "verification_result": verification_result,
        "evidence": [],
    }


def build_source(
    raw_finding: dict,
) -> dict:
    """Build general source traceability."""
    title_block = raw_finding["source_title_block"]
    extraction = raw_finding["extraction"]

    return {
        "document_id": DOCUMENT_ID,
        "document_type": "unknown",
        "location": {
            "section_title": raw_finding["title"],
            "section_number": None,
            "finding_number": int(
                raw_finding["finding_id"].split("-")[-1]
            ),
            "page_start": None,
            "page_end": None,
        },
        "source_reference": (
            f"blocks:"
            f"{extraction['start_block_number']}-"
            f"{extraction['end_block_number']};"
            f"title_paragraph:"
            f"{title_block['paragraph_number']}"
        ),
    }


def build_normalized_finding(
    metadata_finding: dict,
    sections_finding: dict,
    raw_finding: dict,
) -> dict:
    """Build one Input Schema v0.2 finding record."""
    finding_id = metadata_finding["finding_id"]

    severity = metadata_finding[
        "severity"
    ]["normalized_value"]

    cwe_id = metadata_finding["cwe"]["cwe_id"]

    cvss = metadata_finding["cvss"]

    observation = sections_finding[
        "sections"
    ]["observation"]["combined_text"]

    recommendation = sections_finding[
        "sections"
    ]["recommendation"]["paragraphs"]

    finding = {
        "schema_version": INPUT_SCHEMA_VERSION,
        "finding_id": finding_id,
        "title": metadata_finding["title"],
        "severity": severity,
        "affected_targets": build_affected_targets(
            metadata_finding
        ),
        "affected_user_roles": metadata_finding[
            "affected_user_roles"
        ]["normalized_values"],
        "cwe_id": cwe_id,
        "cvss": {
            "version": cvss["version"],
            "score": cvss["score"],
            "vector": cvss["vector"],
        },
        "impact": metadata_finding[
            "impact"
        ]["reported_value"],
        "observation": observation,
        "evidence": build_evidence(
            finding_id,
            sections_finding,
        ),
        "recommendation": recommendation,
        "retest": build_retest(
            metadata_finding,
            sections_finding,
        ),
        "references": build_references(
            metadata_finding
        ),
        "source": build_source(raw_finding),
        "governance": {
            "source_type": "company_provided",
            "data_classification": "confidential",
            "redaction_status": "provider_preprocessed",
            "usage_approved": True,
            "usage_scope": "internal",
            "training_environment": "google_colab",
            "dataset_version": "0.1",
        },
    }

    return finding


def validate_schema_definition(schema: dict) -> None:
    """Check that the JSON Schema itself is valid."""
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as error:
        raise ValueError(
            f"Input Schema definition is invalid: {error}"
        ) from error


def validate_findings(
    findings: list[dict],
    schema: dict,
) -> None:
    """Validate every normalized finding against Input Schema v0.2."""
    validator = Draft202012Validator(schema)

    total_errors = 0

    for finding in findings:
        errors = sorted(
            validator.iter_errors(finding),
            key=lambda error: list(error.absolute_path),
        )

        if not errors:
            print(
                f"{finding['finding_id']}: "
                "SCHEMA VALIDATION PASSED"
            )
            continue

        total_errors += len(errors)

        print(
            f"{finding['finding_id']}: "
            "SCHEMA VALIDATION FAILED"
        )

        for error in errors:
            location = ".".join(
                str(part)
                for part in error.absolute_path
            )

            if not location:
                location = "<root>"

            print(
                f"  - {location}: {error.message}"
            )

    if total_errors:
        raise ValueError(
            f"Normalized findings contain "
            f"{total_errors} schema validation error(s)."
        )


def write_json(
    path: Path,
    data: dict,
) -> None:
    """Write indented JSON."""
    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def write_jsonl(
    path: Path,
    findings: list[dict],
) -> None:
    """Write one finding record per JSONL line."""
    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        for finding in findings:
            file.write(
                json.dumps(
                    finding,
                    ensure_ascii=False,
                )
            )
            file.write("\n")


def main() -> None:
    metadata_data = load_json(METADATA_PATH)
    sections_data = load_json(SECTIONS_PATH)
    raw_data = load_json(RAW_EXTRACTION_PATH)
    input_schema = load_json(INPUT_SCHEMA_PATH)

    validate_schema_definition(input_schema)

    metadata_findings = index_findings(metadata_data)
    sections_findings = index_findings(sections_data)
    raw_findings = index_findings(raw_data)

    id_sets = {
        "metadata": set(metadata_findings),
        "sections": set(sections_findings),
        "raw": set(raw_findings),
    }

    if not (
        id_sets["metadata"]
        == id_sets["sections"]
        == id_sets["raw"]
    ):
        raise ValueError(
            "Finding IDs do not match across metadata, "
            "sections, and raw extraction artifacts."
        )

    ordered_ids = [
        finding["finding_id"]
        for finding in raw_data["findings"]
    ]

    normalized_findings = []

    for finding_id in ordered_ids:
        normalized_findings.append(
            build_normalized_finding(
                metadata_findings[finding_id],
                sections_findings[finding_id],
                raw_findings[finding_id],
            )
        )

    validate_findings(
        normalized_findings,
        input_schema,
    )

    output = {
        "normalization_version": NORMALIZATION_VERSION,
        "input_schema_version": INPUT_SCHEMA_VERSION,
        "document_id": DOCUMENT_ID,
        "finding_count": len(normalized_findings),
        "technical_content_reviewed": False,
        "source_artifacts": {
            "metadata": METADATA_PATH.name,
            "sections": SECTIONS_PATH.name,
            "raw_extraction": RAW_EXTRACTION_PATH.name,
        },
        "findings": normalized_findings,
    }

    OUTPUT_JSON_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    write_json(
        OUTPUT_JSON_PATH,
        output,
    )

    write_jsonl(
        OUTPUT_JSONL_PATH,
        normalized_findings,
    )

    print()
    print("Normalized finding build completed")
    print(
        f"Findings normalized: "
        f"{len(normalized_findings)}"
    )
    print(f"JSON output: {OUTPUT_JSON_PATH}")
    print(f"JSONL output: {OUTPUT_JSONL_PATH}")


if __name__ == "__main__":
    main()