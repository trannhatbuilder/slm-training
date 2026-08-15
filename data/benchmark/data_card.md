# Benchmark v1 — Data Card

**Version:** 1.0
**Created:** 2026-08-15
**Author:** Nhat Tran (intern, EVVO Labs)
**Task:** 09/08 — benchmark_v1 + data_card
**Status:** Draft (not frozen — single engagement)

---

## 1. Overview

| Field | Value |
|---|---|
| Benchmark ID | `benchmark_v1` |
| File | `data/benchmark/benchmark_v1.jsonl` |
| Manifest | `data/benchmark/benchmark_manifest.json` |
| Case count | 34 |
| Source engagement | DOC-000001 (1 engagement only) |
| Schema contract | `schemas/output_schema.json` v0.1 |
| Generation strategy | Cross-task expansion + hand-crafted hard negatives |
| Label source | Rule-based (no human validation yet) |

---

## 2. Composition

### 2.1 By task type

| Task type | Count | Eligible findings | Hard negatives |
|---|---|---|---|
| `finding_review` | 5 | 5/5 | 0 |
| `severity_review` | 5 | 5/5 | 0 |
| `evidence_check` | 5 | 5/5 | 0 |
| `remediation_review` | 5 | 5/5 | 0 |
| `client_qa` | 7 | 5 in-scope + 2 refusal | 2 |
| `hard_negative_potential_issue` | 1 | 1/5 (only FND-000002) | 1 |
| `unsupported_refusal` | 3 | Hand-crafted | 3 |
| `false_positive_detection` | 3 | Hand-crafted (scanner-only variants) | 3 |
| **Total** | **34** | | **9 hard negatives** |

### 2.2 By difficulty

| Difficulty | Count |
|---|---|
| easy | 14 |
| medium | 11 |
| hard | 9 |

### 2.3 By CWE coverage

| CWE | Finding | Count |
|---|---|---|
| CWE-798 (Hard-coded Credentials) | FND-000001 | 6 cases |
| CWE-327 (Broken/Risky Crypto) | FND-000002 | 7 cases (incl. FP variant) |
| CWE-693 (Protection Mechanism Failure) | FND-000003 | 7 cases (incl. FP variant) |
| CWE-295 (Improper Certificate Validation) | FND-000004 | 6 cases |
| CWE-204 (Observable Response Discrepancy) | FND-000005 | 7 cases (incl. FP variant) |

---

## 3. Envelope schema

Each case is a JSON object with this uniform envelope:

```json
{
  "case_id": "BMC-FR-0001",
  "task_type": "finding_review",
  "instruction": "Review the following VAPT finding...",
  "input": { ... },
  "gold_output": { ... },
  "expected_failure_modes": ["wrong_classification_label", ...],
  "metadata": {
    "finding_id": "FND-000001",
    "document_id": "DOC-000001",
    "engagement_id": "DOC-000001",
    "label_source": "rule_based",
    "difficulty": "easy",
    "is_hard_negative": false,
    "schema": "output_schema_v0.1_full",
    "content_hash": "abc123..."
  }
}
```

### 3.1 Per-task-type `gold_output` shape

| Task type | `gold_output` shape | Schema ref |
|---|---|---|
| `finding_review` | Full output_schema.json (18 keys) | `schemas/output_schema.json` |
| `severity_review` | `severity_review` + `cvss_review` + `confidence` | Subset |
| `evidence_check` | `evidence_review` + `review_comments` + `confidence` | Subset |
| `remediation_review` | `recommendation_review` + `review_comments` + `confidence` | Subset |
| `client_qa` | `answer` + `refuses` + `source_references` + `confidence` | Custom |
| `hard_negative_potential_issue` | `classification` + `evidence_review` + `confidence` | Subset |
| `unsupported_refusal` | `answer=null` + `refuses=true` + `refusal_reason` + `missing_info_needed` + `confidence` | Custom |
| `false_positive_detection` | `classification` + `confidence` | Subset |

---

## 4. Generation methodology

### 4.1 Base cases (cross-task expansion)

For each of the 5 normalized findings in `data/normalized/DOC-000001-findings-normalized.jsonl`, the generator (`scripts/build_benchmark_v1.py`) checks eligibility for each of the 8 task types defined in `docs/task_type_catalog.md`. Eligible cases are emitted with rule-based gold answers.

**Eligibility rules:**
- `finding_review` — finding has Observation AND Evidence AND Recommendation
- `severity_review` — finding has severity AND CVSS score AND vector
- `evidence_check` — finding has at least one evidence item
- `remediation_review` — finding has Recommendation
- `client_qa` — always eligible (uses in-scope derived question)
- `hard_negative_potential_issue` — finding evidence contains "no evidence was found" / "no successful exploitation" / "not demonstrated"

### 4.2 Hand-crafted hard negatives

| Category | Count | Source |
|---|---|---|
| `unsupported_refusal` | 3 | Adversarial questions outside report scope (credentials, incident history, user count) |
| `false_positive_detection` | 3 | Scanner-only variants of FND-000002/3/5 — stripped manual verification, left scanner output only |
| `client_qa` (refusal) | 2 | Questions about rotation schedule, Frida script names — answerable only with info not in the report |

### 4.3 Gold answer derivation

Gold labels are **rule-based**, derived from:
- CVSS v3.1 severity bands (9.0-10.0 Critical / 7.0-8.9 High / 4.0-6.9 Medium / 0.1-3.9 Low / 0.0 Info)
- Exploitation marker matching (e.g. "authentication succeeds", "verified that the", "successfully intercepted")
- No-exploit marker matching (e.g. "no evidence was found", "no successful exploitation", "not demonstrated")
- Scanner-only markers (evidence_type == "scanner_output" + absence of manual verification)

**No synthetic perturbation** is applied. Mutation-based hard negatives (strip evidence, swap severity, mutate CWE) are deferred to 18/08 (Dataset v1.1).

---

## 5. Limitations

1. **Single engagement.** All 34 cases derive from DOC-000001. Test set is **NOT frozen** (see `data/dataset/test_set_freeze.json`, status `NOT_FROZEN`). Benchmark v1 is suitable for **smoke testing and baseline** only — not for production regression.
2. **Rule-based labels.** Gold answers are derived by deterministic rules, not human review. False negatives possible when exploitation language is subtle (e.g. "implied access" without explicit "verified"). Human validation deferred to week 12 (human comparison).
3. **Limited task type coverage.** 5 findings × 6 task types gives limited diversity per task. `hard_negative_potential_issue` has only 1 case (FND-000002) because the other 4 findings all demonstrate exploitation.
4. **No severity mismatch hard negative.** FND-000003, FND-000004, FND-000005 all have Low vs Medium mismatch — already covered by `severity_review` cases but no dedicated mismatch hard negative.
5. **No multi-finding context.** All cases are single-finding. Cross-finding consistency (duplicates, severity drift across engagements) is not exercised.

---

## 6. Intended use

- **Baseline run** — load `benchmark_v1.jsonl`, feed `input` to base SLM (Qwen2.5-0.5B / 1.5B / 7B-Instruct), parse output, compare to `gold_output` per metric in `data/benchmark/error_categories.md`.
- **Smoke test for fine-tuned SLM v0.1** (week 11) — same cases, compare base vs fine-tuned.
- **Error categorization** — bucket failures using `expected_failure_modes` per case.

**NOT intended for:**
- Final accuracy reporting (engagement diversity insufficient)
- Train/test split (cases may overlap with training data — benchmark_v1 is for evaluation only, must NOT be used as training data)

---

## 7. Reproducibility

```bash
# Regenerate from source findings
python ./scripts/build_benchmark_v1.py
```

Script reads `data/normalized/DOC-000001-findings-normalized.jsonl` and writes:
- `data/benchmark/benchmark_v1.jsonl`
- `data/benchmark/benchmark_manifest.json`

Content hashes (`metadata.content_hash`) are deterministic — regeneration produces byte-identical case IDs.

---

## 8. Versioning

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-08-15 | Initial release. 34 cases from DOC-000001. |

**Next version (planned):**
- v1.1 — add hard negatives from 18/08 (scanner-only perturbations, severity swaps)
- v2.0 — freeze test set after 2+ engagements (per `data/dataset/test_set_freeze.json` policy)