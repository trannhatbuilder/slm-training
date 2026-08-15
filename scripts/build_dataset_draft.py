"""Dataset draft generator for the EVVO SLM / Harness project.

Task 08/08 fix: cross-task expand the 5 normalized findings from
`data/normalized/DOC-000001-findings-normalized.jsonl` into ~35 dataset
examples covering all 8 task types, with rule-based gold_output.

This script delegates the heavy lifting (case construction, gold-output
rules) to `scripts/build_benchmark_v1.py` by importing its `build_all`
function. The benchmark and the dataset draft therefore share identical
content; the only difference is the output path and the envelope shape:

- benchmark_v1.jsonl  : envelope = {case_id, task_type, instruction,
                        input, gold_output, expected_failure_modes,
                        metadata}
- dataset_draft.jsonl : envelope = {task_type, instruction, input,
                        output, metadata}  (legacy field name `output`
                        instead of `gold_output`, no case_id, no
                        expected_failure_modes — kept for backward
                        compatibility with split_freeze_leakage.py)

Usage:
    python scripts/build_dataset_draft.py
    python scripts/build_dataset_draft.py --dry-run

The script is deterministic: same input findings -> same content hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path

# Import case builders from the benchmark generator (single source of truth)
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from build_benchmark_v1 import (  # noqa: E402
    build_all,
    load_findings,
    load_hand_crafted,
    HAND_CRAFTED_SOURCE,
    DEFAULT_FINDINGS,
)

DATASET_OUT = REPO_ROOT / "data" / "dataset" / "dataset_draft.jsonl"
DATASET_VERSION = "1.0"
TODAY_ISO = date(2026, 8, 15).isoformat()


def content_hash(payload: dict) -> str:
    """Stable 16-char hash of a payload, used for dedup / leakage detection."""
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def benchmark_to_dataset(case: dict) -> dict:
    """Convert a benchmark case to the legacy dataset_draft envelope.

    Legacy envelope (kept for compatibility with split_freeze_leakage.py):
        {
          "task_type": str,
          "instruction": str,
          "input": dict,
          "output": dict,         # was "gold_output" in benchmark
          "metadata": {
            "finding_id": str,
            "document_id": str,
            "engagement_id": str,
            "label_source": str,
            "difficulty": str,
            "is_hard_negative": bool,
            "content_hash": str,  # added here for leakage detection
            "schema": str,        # added here for traceability
          }
        }
    """
    meta = dict(case.get("metadata", {}))
    # Inject content_hash based on (task_type, input) — same as split script.
    meta["content_hash"] = content_hash({
        "task_type": case["task_type"],
        "input": case["input"],
    })
    return {
        "task_type": case["task_type"],
        "instruction": case["instruction"],
        "input": case["input"],
        "output": case["gold_output"],
        "metadata": meta,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build dataset_draft.jsonl")
    parser.add_argument(
        "--findings", type=Path, default=DEFAULT_FINDINGS,
        help="Path to normalized findings JSONL",
    )
    parser.add_argument(
        "--hand-crafted", type=Path, default=HAND_CRAFTED_SOURCE,
        help="Path to hand-crafted negatives JSONL",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print stats, do not write")
    args = parser.parse_args(argv)

    if not args.findings.exists():
        print(f"ERROR: findings file not found: {args.findings}", file=sys.stderr)
        return 1
    if not args.hand_crafted.exists():
        print(f"ERROR: hand-crafted file not found: {args.hand_crafted}", file=sys.stderr)
        return 1

    findings = load_findings(args.findings)
    hand_crafted = load_hand_crafted(args.hand_crafted)
    print(f"Loaded {len(findings)} findings from {args.findings}")
    print(f"Loaded {len(hand_crafted)} hand-crafted negatives from {args.hand_crafted}")

    cases = build_all(findings, hand_crafted)
    print(f"Built {len(cases)} cases via cross-task expansion + hand-crafted negatives")

    # Convert to dataset envelope
    examples = [benchmark_to_dataset(c) for c in cases]

    # Sanity: no duplicate content hashes
    hashes = [e["metadata"]["content_hash"] for e in examples]
    dupes = [h for h in set(hashes) if hashes.count(h) > 1]
    if dupes:
        print(f"WARNING: {len(dupes)} duplicate content hashes: {dupes[:5]}", file=sys.stderr)

    # Stats
    by_task = Counter(e["task_type"] for e in examples)
    by_diff = Counter(e["metadata"]["difficulty"] for e in examples)
    hard_neg = sum(1 for e in examples if e["metadata"].get("is_hard_negative"))

    print()
    print("By task type:")
    for tt in sorted(by_task):
        print(f"  {tt:35} {by_task[tt]:3d}")
    print(f"\nBy difficulty: {dict(sorted(by_diff.items()))}")
    print(f"Hard negatives: {hard_neg}")
    print(f"Total: {len(examples)}")

    if args.dry_run:
        print("\n[dry-run] No files written.")
        return 0

    DATASET_OUT.parent.mkdir(parents=True, exist_ok=True)
    with DATASET_OUT.open("w", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"\nWrote {DATASET_OUT} ({DATASET_OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())