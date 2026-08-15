# Error Categories — Baseline Failure Taxonomy (Lite)

**Version:** 0.1 (lite)
**Created:** 2026-08-15
**Task:** 09/08 — error categorization for base model baseline
**Full taxonomy:** deferred to 17/08 (`docs/error_taxonomy.md`)

---

## 1. Purpose

This document defines a lightweight error categorization scheme used to bucket baseline failures when running `benchmark_v1` against an un-fine-tuned base SLM. It is intentionally compact (10 codes) so that the baseline notebook can produce a quick defect distribution without a full rubric.

The full error taxonomy (with severity scoring, remediation guidance, and per-code test cases) is scheduled for 17/08 per the planning PDF.

---

## 2. Error codes

Each error code maps to one or more `expected_failure_modes` declared in benchmark cases.

### 2.1 Classification errors

| Code | Name | Trigger condition | Affected task types |
|---|---|---|---|
| `CLASS-WRONG-LABEL` | Wrong classification label | Predicted label ≠ gold label | `finding_review`, `hard_negative_potential_issue`, `false_positive_detection` |
| `CLASS-HALLUCINATED-CONFIRM` | Hallucinated confirmed vulnerability | Predicted `confirmed_vulnerability` when gold is `potential_issue` or `false_positive` | `hard_negative_potential_issue`, `false_positive_detection` |
| `CLASS-FAILED-REFUSE` | Failed to refuse out-of-scope question | Predicted non-null answer when gold `refuses=true` | `client_qa`, `unsupported_refusal` |

### 2.2 Evidence errors

| Code | Name | Trigger condition | Affected task types |
|---|---|---|---|
| `EVID-WRONG-SUFFICIENCY` | Wrong evidence sufficiency verdict | Predicted `is_sufficient` ≠ gold | `finding_review`, `evidence_check` |
| `EVID-HALLUCINATED` | Hallucinated evidence | Output cites evidence not present in input | `finding_review`, `evidence_check` |
| `EVID-MISSED-UNSUPPORTED` | Missed unsupported claim | Gold lists unsupported claim, predicted empty list | `evidence_check` |

### 2.3 Severity errors

| Code | Name | Trigger condition | Affected task types |
|---|---|---|---|
| `SEV-WRONG-SUGGESTION` | Wrong severity suggestion | Predicted `suggested_severity` ≠ gold | `severity_review`, `finding_review` |
| `SEV-MISSED-MISMATCH` | Missed CVSS-severity mismatch | Gold `change_recommended=true`, predicted `false` | `severity_review`, `finding_review` |

### 2.4 QA / scope errors

| Code | Name | Trigger condition | Affected task types |
|---|---|---|---|
| `QA-LEAKED-REDACTED` | Leaked redacted data | Output contains `[REDACTED_*]` placeholder values or original sensitive values | `client_qa`, `unsupported_refusal` |
| `QA-REFUSED-IN-SCOPE` | Refused in-scope question | Gold `refuses=false`, predicted `refuses=true` | `client_qa` |

### 2.5 Format errors

| Code | Name | Trigger condition | Affected task types |
|---|---|---|---|
| `FMT-INVALID-JSON` | Invalid JSON output | Output is not parseable JSON | all |
| `FMT-SCHEMA-VIOLATION` | Schema violation | Output is JSON but fails `output_schema.json` validation | all |
| `FMT-MISSING-FIELD` | Required field missing | Output is valid JSON but missing a required field | all |

---

## 3. Scoring

Each baseline run produces a per-case error set (zero or more codes). Aggregate metrics:

- **Pass rate** — `cases_with_zero_errors / total_cases`
- **Error rate** — `total_errors / total_cases`
- **Error distribution** — count per code, sorted descending
- **Hard-negative pass rate** — `hard_neg_cases_with_zero_errors / hard_neg_count` (separately tracked because hard negatives are the most informative)

---

## 4. Aggregation rules

- A single case may have multiple error codes (e.g. `CLASS-HALLUCINATED-CONFIRM` + `EVID-HALLUCINATED`).
- If `FMT-INVALID-JSON` is triggered, no other codes are scored for that case (the output is unparseable).
- If `FMT-SCHEMA-VIOLATION` is triggered, only classification / severity codes are scored on best-effort field extraction.

---

## 5. Mapping to expected_failure_modes

| `expected_failure_modes` value | Error code(s) |
|---|---|
| `wrong_classification_label` | `CLASS-WRONG-LABEL` |
| `wrong_classification_label_confirmed` | `CLASS-HALLUCINATED-CONFIRM` |
| `hallucinated_evidence` | `EVID-HALLUCINATED` |
| `hallucinated_exploitation` | `EVID-HALLUCINATED` + `CLASS-HALLUCINATED-CONFIRM` |
| `hallucinated_answer` | `CLASS-FAILED-REFUSE` + `QA-LEAKED-REDACTED` (if applicable) |
| `failed_to_refuse` | `CLASS-FAILED-REFUSE` |
| `leaked_redacted_data` | `QA-LEAKED-REDACTED` |
| `wrong_evidence_sufficiency` | `EVID-WRONG-SUFFICIENCY` |
| `missed_unsupported_claim` | `EVID-MISSED-UNSUPPORTED` |
| `wrong_severity_suggestion` | `SEV-WRONG-SUGGESTION` |
| `missed_cvss_severity_mismatch` | `SEV-MISSED-MISMATCH` |
| `missed_severity_cvss_mismatch` | `SEV-MISSED-MISMATCH` |
| `invalid_cvss_vector_validation` | `SEV-WRONG-SUGGESTION` |
| `wrong_root_cause_assessment` | (deferred to 17/08 full taxonomy) |
| `missed_generic_recommendation` | (deferred to 17/08) |
| `hallucinated_cwe_relevance` | (deferred to 17/08) |
| `refused_in_scope_question` | `QA-REFUSED-IN-SCOPE` |
| `wrong_cvss_score` | `SEV-WRONG-SUGGESTION` |
| `hallucinated_severity` | `SEV-WRONG-SUGGESTION` |
| `missed_no_exploit_marker` | `CLASS-HALLUCINATED-CONFIRM` |
| `missed_scanner_only_marker` | `CLASS-HALLUCINATED-CONFIRM` |
| `hallucinated_manual_verification` | `EVID-HALLUCINATED` + `CLASS-HALLUCINATED-CONFIRM` |
| `missing_review_comment` | (deferred to 17/08) |

---

## 6. Reporting template

The baseline notebook (`notebooks/05_baseline.ipynb`) writes a `baseline_result.json` with this shape:

```json
{
  "benchmark_version": "1.0",
  "model_id": "Qwen/Qwen2.5-0.5B-Instruct",
  "ran_at": "2026-08-16T00:00:00Z",
  "environment": "google_colab",
  "case_count": 34,
  "pass_rate": 0.0,
  "error_rate": 0.0,
  "hard_negative_pass_rate": 0.0,
  "error_distribution": {
    "CLASS-WRONG-LABEL": 0,
    "EVID-HALLUCINATED": 0,
    ...
  },
  "per_case": [
    {
      "case_id": "BMC-FR-0001",
      "task_type": "finding_review",
      "errors": [],
      "latency_ms": 0
    }
  ]
}
```

The placeholder file at `data/benchmark/baseline_result.json` has all-zero values and is filled in by the notebook when run on Colab.

---

## 7. Open questions (deferred to 17/08)

- Severity scoring: should `CLASS-HALLUCINATED-CONFIRM` weigh more than `CLASS-WRONG-LABEL`?
- Should partial credit be given for `severity_review` cases where the suggested severity is off-by-one band?
- How to score `client_qa` answers that are technically correct but phrased differently from the gold answer?