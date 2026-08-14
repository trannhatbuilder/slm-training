"""
Knowledge Base Retriever — Retrieve relevant rules for a review task.

Implements Harness step 5: "Retrieve relevant EVVO rules" from
problem_definition §11.4.

The retriever supports multiple retrieval strategies:
  1. taxonomy-based: retrieve rules matching review taxonomy codes
  2. domain-based: retrieve rules matching the finding's domain
  3. tag-based: retrieve rules matching specific tags
  4. combined: intersection/union of multiple strategies

For v1 (rule-based engine without SLM), the retriever returns
all matching rules as context that can be injected into the
review pipeline. When SLM is integrated, these rules become
part of the RAG context for prompt building (step 6).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .schema import KBEntry, TAXONOMY_TO_KB_CATEGORY
from .loader import KBLoader

logger = logging.getLogger(__name__)


# ── Retrieval Result ──

@dataclass
class RetrievalResult:
    """
    Result of a KB retrieval operation.

    Attributes:
        query: The original query parameters
        entries: Matched KB entries
        total_matched: Total number of matched entries
        categories_matched: Categories that had matches
        retrieval_strategy: Strategy used for retrieval
    """
    query: dict[str, Any]
    entries: list[KBEntry]
    total_matched: int = 0
    categories_matched: list[str] = field(default_factory=list)
    retrieval_strategy: str = ""

    def __post_init__(self):
        self.total_matched = len(self.entries)
        self.categories_matched = sorted(
            set(e.category for e in self.entries)
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for output/logging."""
        return {
            "query": self.query,
            "total_matched": self.total_matched,
            "categories_matched": self.categories_matched,
            "retrieval_strategy": self.retrieval_strategy,
            "entries": [e.to_dict() for e in self.entries],
        }

    def get_rules_text(self) -> str:
        """
        Get all matched rules as a single text block.

        Useful for prompt building (step 6) when SLM is integrated.
        """
        lines = []
        for entry in self.entries:
            lines.append(f"[{entry.kb_id}] {entry.title}")
            if entry.description:
                lines.append(f"  Description: {entry.description}")
            if entry.conditions:
                lines.append(f"  Conditions: {'; '.join(entry.conditions)}")
            if entry.action:
                lines.append(f"  Action: {entry.action}")
            lines.append("")
        return "\n".join(lines)

    def get_rules_summary(self) -> list[dict[str, str]]:
        """Get compact summary of matched rules (id + title + action)."""
        return [
            {
                "kb_id": e.kb_id,
                "title": e.title,
                "action": e.action,
                "severity": e.severity,
            }
            for e in self.entries
        ]


# ── Retriever ──

class KBRetriever:
    """
    Retrieve relevant KB entries for a review task.

    Usage:
        retriever = KBRetriever(kb_root="/path/to/data/kb")
        result = retriever.retrieve_for_review(
            taxonomy_codes=["SEV", "EVID", "CLASS"],
            domain="web_application",
        )
        for entry in result.entries:
            print(entry.kb_id, entry.title)
    """

    def __init__(self, kb_root: str | None = None):
        """
        Initialize the retriever and load KB entries.

        Args:
            kb_root: Path to the KB data directory.
        """
        self.loader = KBLoader(kb_root=kb_root)
        self.entries: list[KBEntry] = []
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Load entries if not already loaded."""
        if not self._loaded:
            self.entries = self.loader.load_all()
            self._loaded = True
            logger.info(f"KB retriever loaded {len(self.entries)} entries")

    def retrieve_for_review(
        self,
        taxonomy_codes: list[str] | None = None,
        domain: str | None = None,
        tags: list[str] | None = None,
        categories: list[str] | None = None,
        min_severity: str | None = None,
    ) -> RetrievalResult:
        """
        Retrieve KB entries relevant to a review task.

        This is the primary retrieval method called by the Harness
        orchestrator at step 5.

        Args:
            taxonomy_codes: Review taxonomy codes to match (e.g., ["SEV", "EVID"])
            domain: Finding domain to match (e.g., "web_application")
            tags: Tags to match
            categories: Direct category filter
            min_severity: Minimum rule severity filter
                         ("critical" > "warning" > "info")

        Returns:
            RetrievalResult with matched entries.
        """
        self._ensure_loaded()

        query = {
            "taxonomy_codes": taxonomy_codes,
            "domain": domain,
            "tags": tags,
            "categories": categories,
            "min_severity": min_severity,
        }

        # Start with all entries
        candidates = list(self.entries)

        # Filter by taxonomy codes
        if taxonomy_codes:
            taxonomy_categories = set()
            for code in taxonomy_codes:
                mapped = TAXONOMY_TO_KB_CATEGORY.get(code)
                if mapped:
                    taxonomy_categories.add(mapped)

            if taxonomy_categories:
                candidates = [
                    e for e in candidates
                    if e.category in taxonomy_categories
                ]

        # Filter by domain
        if domain:
            candidates = [
                e for e in candidates
                if e.matches_domain(domain)
            ]

        # Filter by tags
        if tags:
            candidates = [
                e for e in candidates
                if e.matches_tags(tags)
            ]

        # Filter by direct category
        if categories:
            candidates = [
                e for e in candidates
                if e.category in categories
            ]

        # Filter by minimum severity
        if min_severity:
            severity_order = {"critical": 3, "warning": 2, "info": 1}
            min_level = severity_order.get(min_severity, 0)
            candidates = [
                e for e in candidates
                if severity_order.get(e.severity, 0) >= min_level
            ]

        # Sort by severity (critical first), then by kb_id
        severity_order = {"critical": 3, "warning": 2, "info": 1}
        candidates.sort(
            key=lambda e: (-severity_order.get(e.severity, 0), e.kb_id)
        )

        return RetrievalResult(
            query=query,
            entries=candidates,
            retrieval_strategy="combined_taxonomy_domain",
        )

    def retrieve_by_id(self, kb_id: str) -> KBEntry | None:
        """
        Retrieve a single KB entry by its ID.

        Args:
            kb_id: The KB entry ID (e.g., "KB-SEV-001").

        Returns:
            KBEntry if found, None otherwise.
        """
        self._ensure_loaded()
        for entry in self.entries:
            if entry.kb_id == kb_id:
                return entry
        return None

    def retrieve_escalation_rules(self) -> RetrievalResult:
        """
        Retrieve all escalation rules.

        Convenience method for the escalation module.
        """
        return self.retrieve_for_review(categories=["escalation_rules"])

    def retrieve_consistency_rules(self) -> RetrievalResult:
        """
        Retrieve all consistency rules.

        Convenience method for the consistency module.
        """
        return self.retrieve_for_review(categories=["consistency_rules"])

    def get_stats(self) -> dict[str, Any]:
        """Get retriever statistics."""
        self._ensure_loaded()
        return self.loader.get_stats()