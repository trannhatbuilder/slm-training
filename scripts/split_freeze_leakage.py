"""
Split by Engagement + Test Set Freeze + Leakage Check

CRITICAL CONSTRAINT:
- Current dataset has only 1 document (DOC-000001) from 1 engagement
- All 5 findings share the same engagement context (same client, same pentesters, same timeframe)
- Splitting by finding within the same engagement creates train-test leakage risk
  because findings from the same report share vocabulary, template patterns, and contextual clues

SPLIT POLICY:
- With 1 engagement: HOLD — all examples in one bucket (no split)
- With 2+ engagements: Split by engagement_id (never by finding)
  - 1 engagement → test (smallest first, ensure test has representative task types)
  - Remaining → train/validation (80/20)

This script:
1. Analyzes engagement distribution in dataset_draft.jsonl
2. Creates split strategy with HOLD decision
3. Checks leakage risks
4. Creates split_manifest.csv
5. Creates test_set_freeze manifest
6. Generates split_report.md
"""

import json
import csv
import hashlib
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime


BASE_DIR = Path(__file__).parent.parent
DATASET_PATH = BASE_DIR / "data" / "dataset" / "dataset_draft.jsonl"
SPLIT_DIR = BASE_DIR / "data" / "dataset"
ARTIFACTS_DIR = BASE_DIR / "artifacts" / "metrics"


def load_dataset():
    records = []
    with open(DATASET_PATH) as f:
        for i, line in enumerate(f, 1):
            rec = json.loads(line.strip())
            rec["_line"] = i
            records.append(rec)
    return records


def compute_content_hash(rec: dict) -> str:
    """Compute hash of example content for dedup/leakage detection."""
    content = json.dumps({
        "task_type": rec.get("task_type"),
        "input": rec.get("input"),
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def analyze_engagement_distribution(records):
    """Analyze which engagements/documents the examples come from."""
    by_doc = defaultdict(list)
    by_finding = defaultdict(list)
    by_engagement = defaultdict(list)

    for rec in records:
        doc_id = rec.get("metadata", {}).get("document_id", "UNKNOWN")
        finding_id = rec.get("metadata", {}).get("finding_id", "UNKNOWN")
        # For now, engagement = document (1 doc = 1 engagement)
        engagement_id = doc_id  # In future, engagement may span multiple docs
        by_doc[doc_id].append(rec)
        by_finding[finding_id].append(rec)
        by_engagement[engagement_id].append(rec)

    return by_doc, by_finding, by_engagement


def check_leakage_risks(records, by_doc, by_finding):
    """
    Check for potential train-test leakage risks.
    
    Leakage vectors:
    1. Same engagement in train and test → shared vocabulary, template patterns
    2. Same finding in both train and test (different task types) → direct content overlap
    3. Same CWE/severity pattern overrepresented in one split
    4. Text overlap between examples (shared observation/evidence text)
    """
    risks = []

    # Risk 1: Single engagement — any split by finding leaks engagement context
    n_engagements = len(by_doc)
    if n_engagements == 1:
        risks.append({
            "risk_id": "LEAK-001",
            "severity": "critical",
            "category": "engagement_contamination",
            "description": "Only 1 engagement (DOC-000001) in dataset — splitting by finding will leak shared engagement context (same client, pentesters, template, timeframe)",
            "recommendation": "Do NOT split. Place all examples in same bucket until 2+ engagements available.",
            "affected_examples": len(records),
        })

    # Risk 2: Same finding appears in multiple task types
    for fid, examples in by_finding.items():
        if len(examples) > 1:
            task_types = [e["task_type"] for e in examples]
            risks.append({
                "risk_id": f"LEAK-002-{fid}",
                "severity": "high",
                "category": "finding_cross_contamination",
                "description": f"Finding {fid} appears in {len(examples)} examples ({', '.join(task_types)}) — if split across train/test, SLM learns from one task and is tested on another with same input",
                "recommendation": f"Keep all {len(examples)} examples for {fid} in the same split bucket.",
                "affected_examples": len(examples),
            })

    # Risk 3: Content hash duplication
    hashes = defaultdict(list)
    for rec in records:
        h = compute_content_hash(rec)
        hashes[h].append(rec["_line"])
    for h, lines in hashes.items():
        if len(lines) > 1:
            risks.append({
                "risk_id": f"LEAK-003-{h}",
                "severity": "critical",
                "category": "exact_duplicate",
                "description": f"Lines {lines} have identical input content — exact duplicates",
                "recommendation": "Remove duplicates before training.",
                "affected_examples": len(lines),
            })

    # Risk 4: Template/vocabulary leakage (all findings share report template)
    risks.append({
        "risk_id": "LEAK-004",
        "severity": "medium",
        "category": "template_contamination",
        "description": "All findings from same VAPT report share template structure, section labels, and writing style — SLM may overfit to template rather than learn review logic",
        "recommendation": "Add findings from different report templates/clients when available. Monitor for template overfitting.",
        "affected_examples": len(records),
    })

    # Risk 5: Small dataset — any split reduces already minimal coverage
    risks.append({
        "risk_id": "LEAK-005",
        "severity": "high",
        "category": "small_dataset_split",
        "description": f"Dataset has only {len(records)} examples — any split (even 80/10/10) leaves test with ~{max(1, len(records)//10)} examples, insufficient for meaningful evaluation",
        "recommendation": "Do NOT split until dataset has at least 100 examples from 3+ engagements.",
        "affected_examples": len(records),
    })

    return risks


def create_split_strategy(records, by_engagement, risks):
    """
    Determine split strategy based on data constraints.
    
    Returns:
        strategy: dict with split assignments for each example
    """
    n_engagements = len(by_engagement)
    has_critical_leakage = any(r["severity"] == "critical" for r in risks)

    if n_engagements < 2 or has_critical_leakage:
        # HOLD strategy — cannot safely split
        strategy = {
            "decision": "HOLD",
            "rationale": (
                f"Only {n_engagements} engagement(s) in dataset with critical leakage risks. "
                "All examples remain in a single 'draft' bucket. "
                "No train/validation/test split until 2+ engagements from different clients/assessments are available."
            ),
            "buckets": {
                "draft": list(range(len(records))),
                "train": [],
                "validation": [],
                "test": [],
            },
        }
    else:
        # Would implement engagement-based split here
        strategy = {
            "decision": "SPLIT_BY_ENGAGEMENT",
            "rationale": "Multiple engagements available — split by engagement.",
            "buckets": {"draft": [], "train": [], "validation": [], "test": []},
        }

    return strategy


def create_test_set_freeze(strategy, records):
    """
    Create test set freeze manifest.
    
    With HOLD strategy: test set is empty but freeze policy is documented.
    """
    freeze = {
        "freeze_version": "v0.1-draft",
        "freeze_date": datetime.now().isoformat(),
        "status": "NOT_FROZEN" if strategy["decision"] == "HOLD" else "FROZEN",
        "reason": (
            "Test set cannot be frozen because dataset has only 1 engagement. "
            "Freeze will be applied when 2+ engagements are available and split is performed."
        ),
        "freeze_policy": {
            "condition": "2+ engagements from different clients/assessments available",
            "min_test_examples": 10,
            "min_task_type_coverage": "At least 1 example per task type in test set",
            "engagement_exclusivity": "An engagement appears in EXACTLY ONE of train/validation/test",
            "once_frozen": "Test set content and labels MUST NOT change — only append if new engagements added",
        },
        "current_test_set": {
            "examples": [],
            "engagements": [],
            "task_types_covered": [],
        },
        "future_test_set_plan": {
            "target_engagements": "Next 1-2 engagements added to dataset",
            "expected_examples": "8-15 examples covering all 8 task types",
            "selection_criteria": [
                "Must include at least 1 hard-negative example",
                "Must include at least 1 severity mismatch example",
                "Must include at least 1 finding_review example",
                "Must represent different vulnerability categories (CWE)",
            ],
        },
    }
    return freeze


def write_split_manifest(strategy, records):
    """Write split_manifest.csv."""
    csv_path = SPLIT_DIR / "split_manifest.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "example_index", "task_type", "finding_id", "document_id",
            "engagement_id", "bucket", "difficulty", "is_hard_negative",
            "content_hash"
        ])
        for i, rec in enumerate(records):
            meta = rec.get("metadata", {})
            # Determine bucket
            if i in strategy["buckets"].get("draft", []):
                bucket = "draft"
            elif i in strategy["buckets"].get("train", []):
                bucket = "train"
            elif i in strategy["buckets"].get("validation", []):
                bucket = "validation"
            elif i in strategy["buckets"].get("test", []):
                bucket = "test"
            else:
                bucket = "unassigned"

            writer.writerow([
                i,
                rec.get("task_type", ""),
                meta.get("finding_id", ""),
                meta.get("document_id", ""),
                meta.get("document_id", ""),  # engagement_id = document_id for now
                bucket,
                meta.get("difficulty", ""),
                meta.get("is_hard_negative", False),
                compute_content_hash(rec),
            ])
    return csv_path


def write_split_report(records, by_doc, by_finding, by_engagement, risks, strategy, freeze, csv_path):
    """Write split_report.md."""
    report_path = BASE_DIR / "docs" / "split_report.md"

    n_critical = sum(1 for r in risks if r["severity"] == "critical")
    n_high = sum(1 for r in risks if r["severity"] == "high")
    n_medium = sum(1 for r in risks if r["severity"] == "medium")

    report = f"""# Split Report — EVVO SLM / Harness

**Version:** 1.1
**Date:** {datetime.now().strftime('%Y-%m-%d')}
**Scope:** Ngày 08/08 — Split by engagement, freeze test set, check leakage (regenerated after cross-task expansion)

---

## 1. Dataset Summary

| Metric | Value |
|---|---|
| Total examples | {len(records)} |
| Total engagements | {len(by_engagement)} |
| Total documents | {len(by_doc)} |
| Total findings | {len(by_finding)} |
| Task types covered | {len(set(r['task_type'] for r in records))}/8 |

### Per-Engagement Distribution

| Engagement ID | Document ID | Findings | Examples | Task Types |
|---|---|---|---|---|
"""

    for eng_id, examples in sorted(by_engagement.items()):
        findings = set(e.get("metadata", {}).get("finding_id", "") for e in examples)
        tasks = set(e["task_type"] for e in examples)
        report += f"| {eng_id} | {eng_id} | {len(findings)} | {len(examples)} | {', '.join(sorted(tasks))} |\n"

    report += f"""
### Per-Finding Distribution

| Finding ID | Examples | Task Types |
|---|---|---|
"""

    for fid, examples in sorted(by_finding.items()):
        tasks = [e["task_type"] for e in examples]
        report += f"| {fid} | {len(examples)} | {', '.join(tasks)} |\n"

    report += f"""
---

## 2. Leakage Risk Analysis

| Severity | Count |
|---|---|
| Critical | {n_critical} |
| High | {n_high} |
| Medium | {n_medium} |
| **Total** | **{len(risks)}** |

### Risk Details

"""

    for risk in risks:
        report += f"""#### {risk['risk_id']} — {risk['category']} [{risk['severity'].upper()}]

{risk['description']}

**Recommendation:** {risk['recommendation']}

**Affected examples:** {risk['affected_examples']}

---

"""

    report += f"""## 3. Split Decision

**Decision: {strategy['decision']}**

{strategy['rationale']}

### Bucket Assignment

| Bucket | Examples | Percentage |
|---|---|---|
"""

    for bucket_name, indices in strategy["buckets"].items():
        pct = f"{len(indices)/len(records)*100:.1f}%" if records else "0%"
        report += f"| {bucket_name} | {len(indices)} | {pct} |\n"

    report += f"""
### Split Policy (for future multi-engagement data)

1. **Primary key:** engagement_id (NOT finding_id)
2. **Rule:** All findings from the same engagement MUST be in the same bucket
3. **Test set source:** Next 1-2 engagements added to dataset
4. **Train/validation source:** Remaining engagements (80/20 split by engagement)
5. **Minimum test set:** 10 examples covering all 8 task types
6. **Once frozen:** Test set MUST NOT change — only append new engagements

---

## 4. Test Set Freeze Status

| Field | Value |
|---|---|
| Freeze version | {freeze['freeze_version']} |
| Status | **{freeze['status']}** |
| Reason | {freeze['reason']} |

### Freeze Policy

| Condition | Requirement |
|---|---|
| Minimum engagements | {freeze['freeze_policy']['condition']} |
| Minimum test examples | {freeze['freeze_policy']['min_test_examples']} |
| Task type coverage | {freeze['freeze_policy']['min_task_type_coverage']} |
| Engagement exclusivity | {freeze['freeze_policy']['engagement_exclusivity']} |
| Once frozen | {freeze['freeze_policy']['once_frozen']} |

### Future Test Set Plan

- **Target engagements:** {freeze['future_test_set_plan']['target_engagements']}
- **Expected examples:** {freeze['future_test_set_plan']['expected_examples']}
- **Selection criteria:**
"""

    for crit in freeze['future_test_set_plan']['selection_criteria']:
        report += f"  - {crit}\n"

    report += f"""
---

## 5. Manifest File

Split manifest saved to: `data/dataset/split_manifest.csv`

Format: CSV with columns:
- example_index, task_type, finding_id, document_id, engagement_id, bucket, difficulty, is_hard_negative, content_hash

---

## 6. Week 1 Exit Criteria — Test Set Item

| Exit Criterion | Status | Evidence |
|---|---|---|
| Test set frozen and not mixed with train | ⚠️ HOLD | Cannot freeze with 1 engagement — documented in §4 |
| At least one complete sample for each task type | ✅ | 8/8 task types have examples (after cross-task expansion on 08/08) |
| Data redacted before uploading to Colab | ⚠️ Partial | Redaction markers applied in dataset_draft.jsonl; full redaction pipeline pending |

---

## 7. Recommendations

1. **Do NOT split** the current {len(records)}-example dataset — the leakage risk is too high
2. **Add 2-3 engagements** from different clients/assessments as the NEXT priority
3. When new engagements are added, apply the split policy in §3
4. **Freeze test set** immediately after split — document hash of all test examples
5. **Monitor for template overfitting** — all current findings share the same report template
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    return report_path


def main():
    print("=" * 70)
    print("NGÀY 08/08: Split + Freeze + Leakage Check")
    print("=" * 70)
    print()

    # 1. Load dataset
    records = load_dataset()
    print(f"📊 Loaded {len(records)} examples from dataset_draft.jsonl")

    # 2. Analyze engagement distribution
    by_doc, by_finding, by_engagement = analyze_engagement_distribution(records)
    print(f"   Engagements: {len(by_engagement)}")
    print(f"   Documents: {len(by_doc)}")
    print(f"   Findings: {len(by_finding)}")
    print()

    # 3. Check leakage risks
    print("🔍 Checking leakage risks...")
    risks = check_leakage_risks(records, by_doc, by_finding)
    for r in risks:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(r["severity"], "⚪")
        print(f"   {icon} {r['risk_id']}: {r['category']} [{r['severity']}]")
    print()

    # 4. Determine split strategy
    print("📋 Determining split strategy...")
    strategy = create_split_strategy(records, by_engagement, risks)
    print(f"   Decision: {strategy['decision']}")
    print(f"   Buckets: {', '.join(f'{k}={len(v)}' for k, v in strategy['buckets'].items())}")
    print()

    # 5. Create test set freeze manifest
    print("🔒 Creating test set freeze manifest...")
    freeze = create_test_set_freeze(strategy, records)
    print(f"   Status: {freeze['status']}")
    print()

    # 6. Write split_manifest.csv
    print("📝 Writing split_manifest.csv...")
    csv_path = write_split_manifest(strategy, records)
    print(f"   ✅ {csv_path}")

    # 7. Write freeze manifest
    freeze_path = SPLIT_DIR / "test_set_freeze.json"
    with open(freeze_path, "w") as f:
        json.dump(freeze, f, indent=2, ensure_ascii=False)
    print(f"   ✅ {freeze_path}")

    # 8. Write split_report.md
    print("📝 Writing split_report.md...")
    report_path = write_split_report(records, by_doc, by_finding, by_engagement, risks, strategy, freeze, csv_path)
    print(f"   ✅ {report_path}")

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Split decision:     {strategy['decision']}")
    print(f"  Leakage risks:      {len(risks)} ({sum(1 for r in risks if r['severity']=='critical')} critical)")
    print(f"  Test set status:    {freeze['status']}")
    print(f"  Manifest:           {csv_path}")
    print(f"  Freeze manifest:    {freeze_path}")
    print(f"  Report:             {report_path}")


if __name__ == "__main__":
    main()