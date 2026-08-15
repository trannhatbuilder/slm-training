# Dataset Draft — Data Card

**Version:** 1.0
**Created:** 2026-08-15
**Author:** Nhat Tran (intern, EVVO Labs)
**Task:** 08/08 — Split + Freeze + Leakage check (regenerated after cross-task expansion)
**Status:** Draft (not frozen — single engagement)

---

## 1. Overview

| Field | Value |
|---|---|
| Dataset ID | `dataset_draft` |
| File | `data/dataset/dataset_draft.jsonl` |
| Split manifest | `data/dataset/split_manifest.csv` |
| Freeze manifest | `data/dataset/test_set_freeze.json` |
| Example count | 34 |
| Source engagement | DOC-000001 (1 engagement only) |
| Schema contract | `schemas/output_schema.json` v0.1 |
| Generation strategy | Cross-task expansion + hand-crafted hard negatives |
| Label source | Rule-based (no human validation yet) |
| Split status | **HOLD** — cannot freeze with 1 engagement |

---

## 2. Composition

### 2.1 By task type

| Task type | Count | Hard negatives |
|---|---|---|
| `finding_review` | 5 | 0 |
| `severity_review` | 5 | 0 |
| `evidence_check` | 5 | 0 |
| `remediation_review` | 5 | 0 |
| `client_qa` | 7 | 2 |
| `hard_negative_potential_issue` | 1 | 1 |
| `unsupported_refusal` | 3 | 3 |
| `false_positive_detection` | 3 | 3 |
| **Total** | **34** | **9 hard negatives** |

### 2.2 By difficulty

| Difficulty | Count |
|---|---|
| easy | 14 |
| medium | 11 |
| hard | 9 |

---

## 3. Provenance

- **Source document:** `data/raw/DOC-000001.pdf` (1 VAPT engagement, 5 findings)
- **Normalized findings:** `data/normalized/DOC-000001-findings-normalized.jsonl`
- **Generator:** `scripts/build_dataset_draft.py` — delegates to `scripts/build_benchmark_v1.py` for case construction
- **Hand-crafted negatives:** `data/benchmark/hand_crafted_negatives.jsonl` (8 cases: 3 false_positive_detection + 2 client_qa refusal + 3 unsupported_refusal)

The dataset draft and the benchmark share identical content; the only difference is the envelope shape (see §5 below).

---

## 4. Label Source & Quality

- **Method:** Rule-based heuristics on CVSS score, evidence markers, and exploitation language
- **Human validation:** None — labels are auto-generated, not reviewed
- **Confidence field:** Each `gold_output` includes a `confidence` block with `overall_score`, `level`, `basis`, and `limitations`
- **Known limitations:**
  - All examples come from a single engagement → high template contamination risk
  - Severity mismatch detection is purely CVSS-band based (may disagree with human judgment)
  - Hard negatives rely on hand-crafted `scanner-only` markers — real scanner outputs may differ

---

## 5. Envelope Schema

```jsonc
{
  "task_type": "finding_review | severity_review | evidence_check | remediation_review | client_qa | hard_negative_potential_issue | unsupported_refusal | false_positive_detection",
  "instruction": "string — task prompt for the SLM",
  "input": { ... },           // task-specific input payload
  "output": { ... },          // task-specific gold answer (a.k.a. gold_output in benchmark_v1)
  "metadata": {
    "finding_id": "FND-XXXXXX",
    "document_id": "DOC-XXXXXX",
    "engagement_id": "DOC-XXXXXX",
    "label_source": "rule_based | manual",
    "difficulty": "easy | medium | hard",
    "is_hard_negative": bool,
    "content_hash": "16-char SHA256 prefix",
    "schema": "string — task-specific schema name"
  }
}
```

---

## 6. Split & Freeze Status

| Field | Value |
|---|---|
| Decision | **HOLD** |
| Reason | Only 1 engagement in dataset → splitting by finding leaks engagement context |
| Buckets | draft=34, train=0, validation=0, test=0 |
| Test set status | NOT_FROZEN |
| Freeze condition | 2+ engagements from different clients/assessments |
| Min test examples | 10 |
| Min task type coverage | At least 1 example per task type |

See `data/dataset/test_set_freeze.json` for the full freeze policy and `docs/split_report.md` for the leakage risk analysis.

---

## 7. Leakage Risks

8 risks detected (1 critical, 6 high, 1 medium). Summary:

| Risk ID | Severity | Category | Description |
|---|---|---|---|
| LEAK-001 | critical | engagement_contamination | Only 1 engagement → split by finding leaks engagement context |
| LEAK-002-FND-* | high | finding_cross_contamination | Same finding appears in multiple task types — must stay in same bucket |
| LEAK-004 | medium | template_contamination | All findings share the same report template |
| LEAK-005 | high | small_dataset_split | 34 examples is too few for a meaningful split |

Full details: `docs/split_report.md` §2.

---

## 8. Refresh Policy

- **When to regenerate:** Whenever normalized findings are updated or new hand-crafted negatives are added
- **How to regenerate:** `python scripts/build_dataset_draft.py`
- **After regeneration:** Re-run `python scripts/split_freeze_leakage.py` to refresh manifests and report
- **Do NOT edit `dataset_draft.jsonl` manually** — always regenerate from the script

---

## 9. Relationship to benchmark_v1

| Aspect | dataset_draft | benchmark_v1 |
|---|---|---|
| File | `data/dataset/dataset_draft.jsonl` | `data/benchmark/benchmark_v1.jsonl` |
| Generator | `scripts/build_dataset_draft.py` | `scripts/build_benchmark_v1.py` |
| Content | Identical (34 examples) | Identical (34 cases) |
| Envelope | `{task_type, instruction, input, output, metadata}` | `{case_id, task_type, instruction, input, gold_output, expected_failure_modes, metadata}` |
| Purpose | Input to split/freeze/leakage pipeline | Input to baseline evaluation |

The dataset_draft envelope is the legacy shape expected by `scripts/split_freeze_leakage.py`. The benchmark envelope is the shape expected by `scripts/05_baseline.py`.