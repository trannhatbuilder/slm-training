# Benchmark Design — v1

**Version:** 1.0
**Date:** 2026-08-15
**Task:** 09/08 — benchmark_v1 design rationale

---

## 1. Context

The planning PDF (section 4, day 09/08) requires:
- 30-50 benchmark cases "if data is sufficient"
- Gold answers
- Base model baseline run
- Error categorization

Available data: 5 normalized findings from a single engagement (DOC-000001). This document explains how the 30-50 target was met without fabricating findings or relying on synthetic perturbation.

---

## 2. Strategy decision

### 2.1 Why cross-task expansion (Q1 = option a)

Each normalized finding can be evaluated against multiple task types defined in `docs/task_type_catalog.md`. With 5 findings × 6 eligible task types, the base count is ~25-30 cases. Adding 8-12 hand-crafted hard negatives (unsupported questions, scanner-only variants, refusal cases) brings the total to 34 — within the 30-50 target.

**Rejected alternatives:**
- Synthetic perturbation (mutate severity, strip evidence) — deferred to 18/08 per planning PDF, where dedicated hard-negative expansion is scheduled.
- Reduce scope to 10-15 cases — would under-utilize available findings and miss the 30-50 target.
- Synthetic finding generation — would introduce fabricated data and contaminate the test set.

### 2.2 Why hybrid schema (Q3 = option c)

A purely uniform envelope with full `output_schema.json` (18 keys) for every case would force `severity_review` and `client_qa` cases to fill 16+ irrelevant fields. A purely per-task-type schema would require 8 separate envelopes and 8 evaluation paths.

The hybrid approach uses:
- **Uniform envelope** (`case_id`, `task_type`, `instruction`, `input`, `gold_output`, `expected_failure_modes`, `metadata`) for case handling
- **Per-task-type `gold_output`** for output contract — each task type only includes the keys it actually evaluates

This means the evaluator can dispatch on `task_type` to pick the right comparison logic, while the loader treats all cases uniformly.

---

## 3. Eligibility matrix

| Task type | FND-000001 | FND-000002 | FND-000003 | FND-000004 | FND-000005 | Total |
|---|---|---|---|---|---|---|
| `finding_review` | ✅ | ✅ | ✅ | ✅ | ✅ | 5 |
| `severity_review` | ✅ | ✅ | ✅ | ✅ | ✅ | 5 |
| `evidence_check` | ✅ | ✅ | ✅ | ✅ | ✅ | 5 |
| `remediation_review` | ✅ | ✅ | ✅ | ✅ | ✅ | 5 |
| `client_qa` (in-scope) | ✅ | ✅ | ✅ | ✅ | ✅ | 5 |
| `hard_negative_potential_issue` | ❌ | ✅ | ❌ | ❌ | ❌ | 1 |

**Notes:**
- Only FND-000002 (JWT HS256) qualifies for `hard_negative_potential_issue` because its evidence explicitly states "no evidence was found that the signing secret could be recovered" and "no successful exploitation was demonstrated".
- The other 4 findings all demonstrate exploitation (verified authentication, observed runtime behavior, interceptable traffic, distinguishable responses) and therefore classify as `confirmed_vulnerability`.

### 3.1 Hand-crafted additions

| Task type | Count | Source |
|---|---|---|
| `unsupported_refusal` | 3 | Adversarial questions on FND-000001/2/5 |
| `false_positive_detection` | 3 | Scanner-only variants of FND-000002/3/5 |
| `client_qa` (refusal) | 2 | Out-of-scope questions on FND-000001/4 |

---

## 4. Gold answer derivation

Gold answers are **rule-based**, derived from three deterministic checks:

### 4.1 CVSS-severity consistency

CVSS v3.1 official bands:
- 9.0-10.0 → Critical
- 7.0-8.9 → High
- 4.0-6.9 → Medium
- 0.1-3.9 → Low
- 0.0 → Informational

Cases where the reported severity does not match the CVSS-implied band are flagged with `change_recommended=true` and a `SEV-001` review comment.

### 4.2 Exploitation marker matching

The evidence text is scanned for two marker sets:
- **Exploitation markers** (positive): "authentication succeeds", "verified that the", "successfully intercepted", "successfully authenticated", "granted access", "demonstrating unauthorized access", "confirming that"
- **No-exploit markers** (negative): "no evidence was found", "no successful exploitation", "no evidence that", "not demonstrated"

If a positive marker is found and no negative marker is present → `confirmed_vulnerability`. If a negative marker is found → `potential_issue`. Otherwise default to `potential_issue` (conservative).

### 4.3 Scanner-only detection (false positives)

Hand-crafted false-positive variants use `evidence_type: "scanner_output"` and explicitly state "no manual verification performed". The gold label is `false_positive`.

---

## 5. Limitations & risks

### 5.1 Rule-based label noise

The marker-based classification is approximate. Subtle phrasing like "implied access" or "would allow" without explicit verification may be misclassified. Risk: gold labels may be wrong for ~10-20% of cases. Mitigation: week 12 human comparison will surface mismatches.

### 5.2 Single engagement

All 34 cases come from DOC-000001. The benchmark cannot detect overfitting to engagement-specific patterns (e.g. Brightnote-specific phrasing, EVVO report style). Mitigation: v1.1 will add cases from the next engagement; v2.0 will freeze the test set after 2+ engagements are available.

### 5.3 Task type imbalance

`hard_negative_potential_issue` has only 1 case (FND-000002). The benchmark cannot reliably measure recall on this task type. Mitigation: hand-crafted hard negatives partially compensate, but a proper suite needs more no-exploit findings.

### 5.4 No leakage check across train/test

The existing `dataset_draft.jsonl` (5 finding_review examples) overlaps with `benchmark_v1.jsonl` finding_review cases (same 5 findings). For the baseline run this is acceptable (base model has not been trained on either). For the fine-tuned SLM evaluation (week 11), the training data must exclude these 34 cases — enforced via `metadata.content_hash` deduplication.

---

## 6. Reproducibility

```bash
# Regenerate benchmark_v1 from source findings
python /home/z/my-project/scripts/build_benchmark_v1.py
```

Outputs:
- `data/benchmark/benchmark_v1.jsonl` (34 cases, one JSON per line)
- `data/benchmark/benchmark_manifest.json` (counts, hashes, duplicates)

Content hashes are deterministic — regeneration produces byte-identical case IDs.

---

## 7. Next steps

| Step | Date | Owner |
|---|---|---|
| Run baseline on Colab | 10/08 | Nhat |
| Compare Base / Base+RAG / Fine-tuned / Fine-tuned+RAG | 16/08 | Nhat |
| Add hard negatives (scanner-only, severity swaps) | 18/08 | Nhat |
| Human comparison | Week 12 | Nhat + reviewer |
| Freeze test set | After 2+ engagements | Nhat |