"""
Knowledge Base Schema — Type definitions and validation for KB entries.

Every KB entry follows a uniform schema so the retriever can index,
filter, and rank rules consistently.

KB Entry Schema v1.0:
  {
    "kb_id":        str   — unique identifier (e.g., "KB-SEV-001")
    "category":     str   — one of KB_CATEGORIES
    "subcategory":  str   — fine-grained grouping within category
    "title":        str   — short descriptive title
    "description":  str   — full rule/guidance text
    "conditions":   list  — when this rule applies (triggers)
    "action":       str   — what the system should do
    "references":   list  — external references (CWE, OWASP, etc.)
    "severity":     str   — rule severity: critical/warning/info
    "applicable_to":list  — finding types/domains this rule applies to
    "version":      str   — rule version
    "source":       str   — where this rule came from
    "tags":         list  — search/filter tags
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