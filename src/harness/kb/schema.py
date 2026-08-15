"""
Knowledge Base Schema — Type definitions and validation for KB entries.

Every KB entry follows a uniform schema so the retriever can index,
filter, and rank rules consistently.

KB Entry Schema v1.1 (added 2026-08-15):
  {
    "kb_id":            str   — unique identifier (e.g., "KB-SEV-001")
    "category":         str   — one of KB_CATEGORIES
    "subcategory":      str   — fine-grained grouping within category
    "title":            str   — short descriptive title
    "description":      str   — full rule/guidance text
    "conditions":       list  — when this rule applies (triggers)
    "action":           str   — what the system should do
    "references":       list  — external references (CWE, OWASP, etc.)
    "severity":         str   — rule severity: critical/warning/info
    "applicable_to":    list  — finding types/domains this rule applies to
    "version":          str   — rule version
    "source":           str   — human-readable source description
    "tags":             list  — search/filter tags
    --- new in v1.1 (per task 08/08 Definition of Done, PDF §3.3) ---
    "document_type":    str   — type of source document (evvo_rule, evvo_sop, schema_definition, ...)
    "section":          str   — section path in source document (e.g., "finding_validation")
    "vulnerability_type": str — vuln class this rule addresses (general, hardcoded_credentials, xss, ...)
    "effective_date":   str   — ISO date when rule became effective (YYYY-MM-DD)
    "access_scope":     str   — internal | evaluation_only | external
    "source_id":        str   — identifier of the source document (DOC-000001, POLICY-xxx, ...)
  }
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any


# ── KB Categories ──
KB_CATEGORIES = [
    "severity_guidance",       # Severity-CVSS mapping and alignment rules
    "evidence_standards",      # Evidence sufficiency and classification rules
    "classification_criteria", # Vulnerability classification decision rules
    "remediation_guidance",    # Remediation quality and template rules
    "writing_guidelines",      # Writing quality and style rules
    "validation_requirements", # Schema and structural validation rules
    "escalation_rules",        # Human escalation triggers and thresholds
    "consistency_rules",       # Cross-field consistency rules
    "governance_rules",        # Data governance and protection rules
    "taxonomy_definitions",    # Taxonomy code definitions
    "sop",                     # Standard operating procedures
]

# ── Rule Severity Levels ──
RULE_SEVERITY_LEVELS = ["critical", "warning", "info"]

# ── Document Types (for `document_type` field, new in v1.1) ──
DOCUMENT_TYPES = [
    "evvo_rule",            # rule from EVVO rule files (data/kb/rules/*.json)
    "evvo_sop",             # SOP from EVVO SOP files (data/kb/sops/*.json)
    "schema_definition",    # schema registry entry (data/kb/schemas/*.json)
    "pentest_report",       # extracted from a real pentest report (DOC-xxxxxx)
    "policy_document",      # sourced from policies/*.yaml or *.md
    "internal_guideline",   # internal EVVO guideline (no public source)
]

# ── Access Scopes (for `access_scope` field, new in v1.1) ──
ACCESS_SCOPES = ["internal", "evaluation_only", "external"]

# ── Vulnerability Types (for `vulnerability_type` field, new in v1.1) ──
# Use "general" for rules that apply to all vulnerability types.
VULNERABILITY_TYPES = [
    "general",
    "hardcoded_credentials",
    "broken_cryptography",
    "weak_crypto_algorithm",
    "missing_root_detection",
    "weak_ssl_pinning",
    "user_enumeration",
    "xss",
    "sqli",
    "csrf",
    "ssrf",
    "authentication_bypass",
    "authorization_bypass",
    "information_disclosure",
    "insecure_deserialization",
    "business_logic",
    "misconfiguration",
]

# ── Applicable Domains (from problem_definition §6) ──
APPLICABLE_DOMAINS = [
    "web_application",
    "api",
    "android_application",
    "ios_application",
    "network",
    "cloud_resource",
    "identity_system",
    "cryptographic_component",
    "configuration_review",
    "business_logic",
    "all",  # applies to every domain
]

# ── Taxonomy codes that map to KB categories ──
TAXONOMY_TO_KB_CATEGORY = {
    "COMP": "validation_requirements",
    "EVID": "evidence_standards",
    "CLASS": "classification_criteria",
    "SEV": "severity_guidance",
    "CVSS": "severity_guidance",
    "CWE": "validation_requirements",
    "IMP": "severity_guidance",
    "REC": "remediation_guidance",
    "RET": "validation_requirements",
    "CONS": "consistency_rules",
    "CONF": "escalation_rules",
}


@dataclass
class KBEntry:
    """
    A single Knowledge Base entry — a rule, guideline, or definition.

    Attributes:
        kb_id: Unique identifier (format: KB-{CAT}-{NNN})
        category: One of KB_CATEGORIES
        subcategory: Fine-grained grouping within category
        title: Short descriptive title
        description: Full rule/guidance text
        conditions: List of conditions/triggers for when this rule applies
        action: What the system should do when conditions are met
        references: External references (CWE IDs, OWASP, etc.)
        severity: Rule severity: critical/warning/info
        applicable_to: Finding types/domains this rule applies to
        version: Rule version string
        source: Where this rule came from (policy doc, SOP, etc.)
        tags: Search and filter tags
        document_type: Type of source document (new in v1.1)
        section: Section path in source document (new in v1.1)
        vulnerability_type: Vuln class this rule addresses (new in v1.1)
        effective_date: ISO date when rule became effective (new in v1.1)
        access_scope: internal | evaluation_only | external (new in v1.1)
        source_id: Identifier of the source document (new in v1.1)
    """
    kb_id: str
    category: str
    subcategory: str = ""
    title: str = ""
    description: str = ""
    conditions: list[str] = field(default_factory=list)
    action: str = ""
    references: list[str] = field(default_factory=list)
    severity: str = "info"
    applicable_to: list[str] = field(default_factory=lambda: ["all"])
    version: str = "1.0"
    source: str = ""
    tags: list[str] = field(default_factory=list)
    # ── new in v1.1 (PDF §3.3 metadata fields) ──
    document_type: str = "evvo_rule"
    section: str = ""
    vulnerability_type: str = "general"
    effective_date: str = "2026-08-15"
    access_scope: str = "internal"
    source_id: str = ""

    def __post_init__(self):
        """Validate fields after initialization."""
        if self.category not in KB_CATEGORIES:
            raise ValueError(
                f"Invalid KB category: {self.category!r}. "
                f"Must be one of: {KB_CATEGORIES}"
            )
        if self.severity not in RULE_SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid rule severity: {self.severity!r}. "
                f"Must be one of: {RULE_SEVERITY_LEVELS}"
            )
        for domain in self.applicable_to:
            if domain not in APPLICABLE_DOMAINS:
                raise ValueError(
                    f"Invalid applicable_to domain: {domain!r}. "
                    f"Must be one of: {APPLICABLE_DOMAINS}"
                )
        # ── new in v1.1: validate metadata fields ──
        if self.document_type not in DOCUMENT_TYPES:
            raise ValueError(
                f"Invalid document_type: {self.document_type!r}. "
                f"Must be one of: {DOCUMENT_TYPES}"
            )
        if self.access_scope not in ACCESS_SCOPES:
            raise ValueError(
                f"Invalid access_scope: {self.access_scope!r}. "
                f"Must be one of: {ACCESS_SCOPES}"
            )
        if self.vulnerability_type not in VULNERABILITY_TYPES:
            raise ValueError(
                f"Invalid vulnerability_type: {self.vulnerability_type!r}. "
                f"Must be one of: {VULNERABILITY_TYPES}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KBEntry:
        """Create KBEntry from dictionary."""
        return cls(
            kb_id=data["kb_id"],
            category=data["category"],
            subcategory=data.get("subcategory", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            conditions=data.get("conditions", []),
            action=data.get("action", ""),
            references=data.get("references", []),
            severity=data.get("severity", "info"),
            applicable_to=data.get("applicable_to", ["all"]),
            version=data.get("version", "1.0"),
            source=data.get("source", ""),
            tags=data.get("tags", []),
            # ── new in v1.1: metadata fields (with sensible defaults) ──
            document_type=data.get("document_type", "evvo_rule"),
            section=data.get("section", ""),
            vulnerability_type=data.get("vulnerability_type", "general"),
            effective_date=data.get("effective_date", "2026-08-15"),
            access_scope=data.get("access_scope", "internal"),
            source_id=data.get("source_id", ""),
        )

    def matches_taxonomy(self, taxonomy_code: str) -> bool:
        """Check if this entry is relevant to a taxonomy code."""
        kb_cat = TAXONOMY_TO_KB_CATEGORY.get(taxonomy_code)
        if kb_cat is None:
            return False
        return self.category == kb_cat

    def matches_domain(self, domain: str) -> bool:
        """Check if this entry applies to a specific domain."""
        if "all" in self.applicable_to:
            return True
        return domain in self.applicable_to

    def matches_tags(self, query_tags: list[str]) -> bool:
        """Check if this entry has any matching tags."""
        return bool(set(self.tags) & set(query_tags))