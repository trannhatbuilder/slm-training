"""
Knowledge Base Loader — Load KB entries from YAML/JSON source files.

Reads KB data files from data/kb/ and produces a list of validated
KBEntry objects. The loader supports:

  - JSON rule files (data/kb/rules/*.json)
  - JSON SOP files (data/kb/sops/*.json)
  - JSON schema registry (data/kb/schemas/schema_registry.json)
  - KB manifest (data/kb/kb_manifest.json)

The loader performs validation on every entry and reports any
entries that fail schema validation (logged, not raised, so
partial loads are possible).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .schema import KBEntry, KB_CATEGORIES

logger = logging.getLogger(__name__)


class KBLoader:
    """
    Load and validate Knowledge Base entries from source files.

    Usage:
        loader = KBLoader(kb_root="/path/to/data/kb")
        entries = loader.load_all()
        # entries: list[KBEntry]
    """

    def __init__(self, kb_root: str | Path | None = None):
        """
        Initialize the loader.

        Args:
            kb_root: Path to the KB data directory.
                     Defaults to data/kb/ relative to project root.
        """
        if kb_root is None:
            # Default: project_root/data/kb/
            project_root = Path(__file__).resolve().parents[4]
            kb_root = project_root / "data" / "kb"
        self.kb_root = Path(kb_root)
        self.entries: list[KBEntry] = []
        self.load_errors: list[dict[str, Any]] = []

    def load_all(self) -> list[KBEntry]:
        """
        Load all KB entries from all source directories.

        Returns:
            List of validated KBEntry objects.
        """
        self.entries = []
        self.load_errors = []

        # Load from rules/
        rules_dir = self.kb_root / "rules"
        if rules_dir.exists():
            self._load_json_dir(rules_dir)

        # Load from sops/
        sops_dir = self.kb_root / "sops"
        if sops_dir.exists():
            self._load_json_dir(sops_dir)

        # Load from schemas/
        schemas_dir = self.kb_root / "schemas"
        if schemas_dir.exists():
            self._load_json_dir(schemas_dir)

        logger.info(
            f"KB loaded: {len(self.entries)} entries, "
            f"{len(self.load_errors)} errors"
        )
        return self.entries

    def load_by_category(self, category: str) -> list[KBEntry]:
        """
        Load and filter entries by category.

        Args:
            category: One of KB_CATEGORIES.

        Returns:
            List of KBEntry objects matching the category.
        """
        if category not in KB_CATEGORIES:
            raise ValueError(f"Invalid category: {category!r}")

        all_entries = self.load_all() if not self.entries else self.entries
        return [e for e in all_entries if e.category == category]

    def get_manifest(self) -> dict[str, Any]:
        """
        Load the KB manifest file.

        Returns:
            Manifest dict, or empty dict if not found.
        """
        manifest_path = self.kb_root / "kb_manifest.json"
        if not manifest_path.exists():
            logger.warning(f"KB manifest not found: {manifest_path}")
            return {}
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_stats(self) -> dict[str, Any]:
        """
        Get loading statistics.

        Returns:
            Dict with counts by category and error count.
        """
        stats: dict[str, Any] = {
            "total_entries": len(self.entries),
            "total_errors": len(self.load_errors),
            "by_category": {},
        }
        for entry in self.entries:
            cat = entry.category
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
        return stats

    # ── Private Methods ──

    def _load_json_dir(self, directory: Path) -> None:
        """Load all JSON files from a directory."""
        for json_file in sorted(directory.glob("*.json")):
            try:
                self._load_json_file(json_file)
            except Exception as e:
                self.load_errors.append({
                    "file": str(json_file),
                    "error": str(e),
                })
                logger.error(f"Failed to load {json_file}: {e}")

    def _load_json_file(self, filepath: Path) -> None:
        """
        Load entries from a single JSON file.

        Supports two formats:
          1. Array of entries: [{...}, {...}]
          2. Object with "entries" key: {"entries": [{...}, ...]}
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Extract entries list
        if isinstance(data, list):
            raw_entries = data
        elif isinstance(data, dict) and "entries" in data:
            raw_entries = data["entries"]
        elif isinstance(data, dict) and "kb_id" in data:
            # Single entry file
            raw_entries = [data]
        else:
            logger.warning(f"Unrecognized format in {filepath}")
            return

        for i, raw in enumerate(raw_entries):
            try:
                entry = KBEntry.from_dict(raw)
                self.entries.append(entry)
            except (ValueError, KeyError, TypeError) as e:
                self.load_errors.append({
                    "file": str(filepath),
                    "entry_index": i,
                    "kb_id": raw.get("kb_id", "UNKNOWN"),
                    "error": str(e),
                })
                logger.warning(
                    f"Invalid entry {i} in {filepath} "
                    f"(kb_id={raw.get('kb_id', '?')}): {e}"
                )