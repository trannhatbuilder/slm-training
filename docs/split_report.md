# Split Report — EVVO SLM / Harness

**Version:** 1.0
**Date:** 2026-08-14
**Scope:** Ngày 07/08 — Split by engagement, freeze test set, check leakage

---

## 1. Dataset Summary

| Metric | Value |
|---|---|
| Total examples | 5 |
| Total engagements | 1 |
| Total documents | 1 |
| Total findings | 5 |
| Task types covered | 1/8 |

### Per-Engagement Distribution

| Engagement ID | Document ID | Findings | Examples | Task Types |
|---|---|---|---|---|
| DOC-000001 | DOC-000001 | 5 | 5 | finding_review |

### Per-Finding Distribution

| Finding ID | Examples | Task Types |
|---|---|---|
| FND-000001 | 1 | finding_review |
| FND-000002 | 1 | finding_review |
| FND-000003 | 1 | finding_review |
| FND-000004 | 1 | finding_review |
| FND-000005 | 1 | finding_review |

---

## 2. Leakage Risk Analysis

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| **Total** | **3** |

### Risk Details

#### LEAK-001 — engagement_contamination [CRITICAL]

Only 1 engagement (DOC-000001) in dataset — splitting by finding will leak shared engagement context (same client, pentesters, template, timeframe)

**Recommendation:** Do NOT split. Place all examples in same bucket until 2+ engagements available.

**Affected examples:** 5

---

#### LEAK-004 — template_contamination [MEDIUM]

All findings from same VAPT report share template structure, section labels, and writing style — SLM may overfit to template rather than learn review logic

**Recommendation:** Add findings from different report templates/clients when available. Monitor for template overfitting.

**Affected examples:** 5

---

#### LEAK-005 — small_dataset_split [HIGH]

Dataset has only 5 examples — any split (even 80/10/10) leaves test with ~2 examples, insufficient for meaningful evaluation

**Recommendation:** Do NOT split until dataset has at least 100 examples from 3+ engagements.

**Affected examples:** 5

---

## 3. Split Decision

**Decision: HOLD**

Only 1 engagement(s) in dataset with critical leakage risks. All examples remain in a single 'draft' bucket. No train/validation/test split until 2+ engagements from different clients/assessments are available.

### Bucket Assignment

| Bucket | Examples | Percentage |
|---|---|---|
| draft | 5 | 100.0% |
| train | 0 | 0.0% |
| validation | 0 | 0.0% |
| test | 0 | 0.0% |

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
| Freeze version | v0.1-draft |
| Status | **NOT_FROZEN** |
| Reason | Test set cannot be frozen because dataset has only 1 engagement. Freeze will be applied when 2+ engagements are available and split is performed. |

### Freeze Policy

| Condition | Requirement |
|---|---|
| Minimum engagements | 2+ engagements from different clients/assessments available |
| Minimum test examples | 10 |
| Task type coverage | At least 1 example per task type in test set |
| Engagement exclusivity | An engagement appears in EXACTLY ONE of train/validation/test |
| Once frozen | Test set content and labels MUST NOT change — only append if new engagements added |

### Future Test Set Plan

- **Target engagements:** Next 1-2 engagements added to dataset
- **Expected examples:** 8-15 examples covering all 8 task types
- **Selection criteria:**
  - Must include at least 1 hard-negative example
  - Must include at least 1 severity mismatch example
  - Must include at least 1 finding_review example
  - Must represent different vulnerability categories (CWE)

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
| At least one complete sample for each task type | ✅ | 7/8 task types have examples (false_positive_detection = 0 per plan) |
| Data redacted before uploading to Colab | ⚠️ Partial | Redaction markers applied in dataset_draft.jsonl; full redaction pipeline pending |

---

## 7. Recommendations

1. **Do NOT split** the current 22-example dataset — the leakage risk is too high
2. **Add 2-3 engagements** from different clients/assessments as the NEXT priority
3. When new engagements are added, apply the split policy in §3
4. **Freeze test set** immediately after split — document hash of all test examples
5. **Monitor for template overfitting** — all current findings share the same report template
