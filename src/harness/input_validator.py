"""
Input Validator — Schema validation (Input Schema v0.2) + Governance check.

Steps 1-3 of the Harness workflow:
  1. Receive a finding
  2. Check data-usage status (governance)
  3. Validate the input schema
"""

import json
import re
from pathlib import Path
from typing import Any

import jsonschema

from .config import (
    REQUIRED_INPUT_FIELDS,
    GOVERNANCE_ALLOWED_USAGE_SCOPES,
    GOVERNANCE_ALLOWED_REDACTION,
)


class InputValidator:
    """Validates a normalized finding against Input Schema v0.2 and governance rules."""

    def __init__(self, schema_path: str | None = None):
        self.schema = self._load_schema(schema_path)
        self.issues: list[dict] = []

    def _load_schema(self, schema_path: str | None) -> dict:
        """Load Input Schema v0.2 from file."""
        if schema_path is None:
            schema_path = str(
                Path(__file__).parent.parent.parent / "schemas" / "input_schema.json"
            )
        with open(schema_path) as f:
            return json.load(f)

    def validate(self, finding: dict) -> dict:
        """
        Full validation: schema + governance + structural.

        Returns:
            dict with keys:
                is_valid: bool
                schema_valid: bool
                governance_valid: bool
                structural_valid: bool
                issues: list[dict]  — each has {code, severity, message, field}
        """
        self.issues = []

        # 1. JSON Schema validation
        schema_valid = self._validate_schema(finding)

        # 2. Governance check
        governance_valid = self._validate_governance(finding)

        # 3. Structural / semantic checks beyond schema
        structural_valid = self._validate_structural(finding)

        is_valid = schema_valid and governance_valid and structural_valid

        return {
            "is_valid": is_valid,
            "schema_valid": schema_valid,
            "governance_valid": governance_valid,
            "structural_valid": structural_valid,
            "issues": self.issues,
        }

    def _validate_schema(self, finding: dict) -> bool:
        """Validate against JSON Schema v0.2."""
        try:
            jsonschema.validate(finding, self.schema)
            return True
        except jsonschema.ValidationError as e:
            self.issues.append({
                "code": "SCHEMA",
                "severity": "error",
                "message": f"Schema validation failed: {e.message}",
                "field": str(e.json_path) if hasattr(e, 'json_path') else None,
            })
            return False
        except jsonschema.SchemaError as e:
            self.issues.append({
                "code": "SCHEMA",
                "severity": "error",
                "message": f"Schema itself is invalid: {e.message}",
                "field": None,
            })
            return False

    def _validate_governance(self, finding: dict) -> bool:
        """Check data-usage status — step 2 of Harness workflow."""
        gov = finding.get("governance", {})
        valid = True

        # Check usage_approved
        if not gov.get("usage_approved", False):
            self.issues.append({
                "code": "GOV",
                "severity": "error",
                "message": "Finding is not approved for usage (governance.usage_approved != true)",
                "field": "governance.usage_approved",
            })
            valid = False

        # Check usage_scope
        scope = gov.get("usage_scope")
        if scope not in GOVERNANCE_ALLOWED_USAGE_SCOPES:
            self.issues.append({
                "code": "GOV",
                "severity": "warning",
                "message": f"Usage scope '{scope}' is outside allowed scopes: {GOVERNANCE_ALLOWED_USAGE_SCOPES}",
                "field": "governance.usage_scope",
            })
            valid = False

        # Check redaction_status
        redaction = gov.get("redaction_status")
        if redaction not in GOVERNANCE_ALLOWED_REDACTION:
            self.issues.append({
                "code": "GOV",
                "severity": "warning",
                "message": f"Redaction status '{redaction}' indicates data may contain sensitive information",
                "field": "governance.redaction_status",
            })
            # Don't mark as invalid — just warn. Harness can still run with needs_review redaction.

        return valid

    def _validate_structural(self, finding: dict) -> bool:
        """Additional structural checks beyond JSON Schema."""
        valid = True

        # Check finding_id format
        fid = finding.get("finding_id", "")
        if not re.match(r"^FND-[0-9]{6}$", fid):
            self.issues.append({
                "code": "STRUCT",
                "severity": "error",
                "message": f"finding_id '{fid}' does not match FND-NNNNNN format",
                "field": "finding_id",
            })
            valid = False

        # Check CVSS vector format (basic)
        cvss = finding.get("cvss", {})
        vector = cvss.get("vector", "")
        if vector and not vector.startswith("CVSS:"):
            self.issues.append({
                "code": "STRUCT",
                "severity": "warning",
                "message": f"CVSS vector does not start with 'CVSS:': {vector}",
                "field": "cvss.vector",
            })

        # Check CWE format
        cwe = finding.get("cwe_id")
        if cwe and not re.match(r"^CWE-[0-9]+$", cwe):
            self.issues.append({
                "code": "STRUCT",
                "severity": "warning",
                "message": f"CWE ID '{cwe}' does not match CWE-NNN format",
                "field": "cwe_id",
            })

        # Check observation is not empty/null
        obs = finding.get("observation")
        if not obs or (isinstance(obs, str) and len(obs.strip()) < 10):
            self.issues.append({
                "code": "STRUCT",
                "severity": "warning",
                "message": "Observation is empty or too short (< 10 chars)",
                "field": "observation",
            })

        return valid