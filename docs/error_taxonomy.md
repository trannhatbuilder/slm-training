# Error Taxonomy — Full Version

**Version:** 1.1  
**Created:** 2026-08-17  
**Last updated:** 2026-08-19 (fix: RETR-002 KB verification, FMT-002 count, EVID-001 scope, Section 11 counts, CLASS-001 scope)  
**Task:** 17/08 — Error analysis from 16/08 metrics report and PoC pipeline results  
**Supersedes:** `data/benchmark/error_categories.md` (lite v0.1)  

---

## 1. Purpose

This document provides the full error taxonomy for the EVVO SLM + Harness project. It extends the lite taxonomy (v0.1, created 15/08) with:

- **Severity scoring** per error code (critical / high / medium / low)
- **Remediation guidance** — what to fix in the model, pipeline, or data
- **Root cause analysis** — why the error occurs and which component is responsible
- **Per-code test cases** — concrete examples observed in the 16/08 evaluation
- **Resolution tracking** — status and v0.2 target

### Data sources analyzed

| Source | Findings | Variants | Date |
|--------|----------|----------|------|
| `data/poc_pipeline_results.json` | 5 (FND-000001 to FND-000005) | Fine-tuned + Harness PoC v1 | 15-16/08 |
| `data/metrics_report_16aug.json` | 3 (FND-000001, 000002, 000005) | Base, Base+RAG, Fine-tuned, Fine-tuned+RAG | 16/08 |

> **Scope note:** `metrics_report` only tested 3/5 findings (FND-000003, FND-000004 not included). Some error codes have data from both sources; when counts differ, the source is explicitly labeled.

---

## 2. Error Code Structure

Notation: `<CATEGORY>-<SUBTYPE>-<NNN>`

### Component classification

Each error code is tagged with the responsible component:

| Tag | Meaning |
|-----|---------|
| **SLM** | Error originates from the SLM model output (E-01 through E-06 in Step 1 analysis) |
| **HARNESS** | Finding from the Harness rule-based engine or pipeline integration (H-01, H-02 in Step 1) |
| **DATA** | Issue in input data quality, not caused by SLM or Harness |

Categories:

| Category | Scope |
|----------|-------|
| `CLASS` | Classification errors |
| `EVID` | Evidence errors |
| `SEV` | Severity errors |
| `FMT` | Format / schema errors |
| `RETR` | Retrieval / RAG errors |
| `QA` | Question-answering scope errors |
| `REC` | Remediation errors |
| `CONF` | Confidence scoring errors |
| `DATA` | Input data quality issues (not SLM fault) |

---

## 3. Classification Errors

### CLASS-001 — Wrong Classification Label

| Field | Value |
|-------|-------|
| **Code** | `CLASS-001` |
| **Severity** | Critical |
| **Trigger** | SLM outputs a classification label not in the Output Schema controlled vocabulary: `confirmed_vulnerability`, `potential_issue`, `informational`, `false_positive`, `undetermined` |
| **Affected task types** | `finding_review`, `evidence_check`, `severity_review`, `false_positive_detection` |
| **v0.2 Target** | Eliminate — 0% occurrence on test set |

**Observed instances (16/08):**

> **Note:** SLM outputs non-deterministic wrong labels across inference runs. The same finding produces *different* invalid labels in PoC pipeline vs metrics_report runs.

**PoC pipeline (Fine-tuned, 1 run each):**

| Finding | SLM Output | Expected | Source |
|---------|-----------|----------|--------|
| FND-000001 | `"Critical"` | `confirmed_vulnerability` | PoC pipeline |
| FND-000002 | `"Symmetric JWT Signing Algorithm"` | `potential_issue` | PoC pipeline |
| FND-000003 | `"security"` | `confirmed_vulnerability` | PoC pipeline |
| FND-000004 | `"Weakness"` | `confirmed_vulnerability` | PoC pipeline |
| FND-000005 | `"Information Disclosure"` | `potential_issue` | PoC pipeline |

**Metrics report (all 4 variants, 12 additional instances):**

| Finding | Base | Base+RAG | Fine-tuned | Fine-tuned+RAG |
|---------|------|----------|------------|----------------|
| FND-000001 | `"Insecure Credential Exposure"` | `"Insecure Credential Exposure"` | `"Insecure Credential Exposure"` | `"Insecure Credential Exposure"` |
| FND-000002 | `"Misconfiguration"` | `"Symmetric JWT Signing Algorithm"` | `"Misconfiguration"` | `"Misconfiguration"` |
| FND-000005 | `"Informational"` | `"Information Disclosure"` | `"Informational"` | `"Information Disclosure"` |

> All 17 instances (5 PoC + 12 metrics) use labels outside the controlled vocabulary. None match any of the 5 allowed values.

**Root cause:** SLM v0.1 training data did not enforce strict classification vocabulary. The model learned to generate descriptive labels from the input title/category rather than the 5 allowed labels. The inference prompt did not include an explicit vocabulary constraint.

**Impact:** Classification output cannot be consumed by downstream Harness logic (escalation rules, confidence scoring, consistency checks) which all depend on the controlled vocabulary.

**Remediation:**
1. **v0.2 training:** Add explicit vocabulary constraint in the instruction prompt (system message listing the 5 allowed labels)
2. **v0.2 training:** Ensure every training example in `benchmark_v1.jsonl` uses only the 5 allowed labels in `gold_output`
3. **Pipeline:** Add a post-processing step that maps common free-text labels to the closest controlled label as a fallback
4. **Validation:** Add schema validation on SLM output before passing to Harness (reject or remap if label not in vocabulary)

---

### CLASS-002 — Hallucinated Confirmed Vulnerability

| Field | Value |
|-------|-------|
| **Code** | `CLASS-002` |
| **Severity** | Critical |
| **Trigger** | SLM predicts `confirmed_vulnerability` when gold label is `potential_issue` or `false_positive` |
| **Affected task types** | `hard_negative_potential_issue`, `false_positive_detection` |
| **v0.2 Target** | 0% on hard-negative test set |

**Observed instances:** None in the 16/08 evaluation. Expected to surface when hard-negative test cases are added (18/08).

**Root cause:** Model over-associates certain evidence patterns (e.g., successful authentication) with confirmed exploitation without checking all evidence quality criteria.

**Remediation:**
1. Add hard-negative training cases where exploitation partially succeeds but evidence is insufficient for confirmation
2. Emphasize in training prompt: "Only classify as confirmed_vulnerability if manual exploitation is demonstrated with successful outcome"
3. Self-validation workflow (19/08) should re-check evidence sufficiency before confirming

---

### CLASS-003 — Failed to Refuse Out-of-Scope Question

| Field | Value |
|-------|-------|
| **Code** | `CLASS-003` |
| **Severity** | High |
| **Trigger** | SLM provides a non-null answer when gold indicates the question should be refused |
| **Affected task types** | `client_qa`, `unsupported_refusal` |
| **v0.2 Target** | 0% on unsupported question test cases |

**Observed instances:** Not tested in 16/08 (no client_qa cases in the 3-finding subset).

**Root cause:** SLM not trained on refusal examples or the refusal instruction is not strong enough.

**Remediation:**
1. Add explicit refusal training examples to dataset v1.1 (18/08)
2. Add system prompt: "If the question cannot be answered from the provided report and knowledge base, respond: 'I cannot answer this question based on the available report.'"
3. Validate SLM output contains refusal marker before accepting answer

---

### CLASS-004 — Refused In-Scope Question

| Field | Value |
|-------|-------|
| **Code** | `CLASS-004` |
| **Severity** | Medium |
| **Trigger** | SLM refuses a question that is within report scope |
| **Affected task types** | `client_qa` |
| **v0.2 Target** | 0% on in-scope question test cases |

**Observed instances:** Not tested in 16/08.

**Remediation:** Ensure refusal training examples clearly distinguish in-scope vs out-of-scope boundaries. Avoid over-training on refusal patterns.

---

## 4. Evidence Errors

### EVID-001 — Hallucinated Evidence

| Field | Value |
|-------|-------|
| **Code** | `EVID-001` |
| **Severity** | Critical |
| **Trigger** | SLM cites evidence, file paths, or data not present in the input finding |
| **Affected task types** | `finding_review`, `evidence_check` |
| **v0.2 Target** | 0% hallucinated evidence items |

**Observed instances (16/08):**

**PoC pipeline (Fine-tuned):**

| Finding | Hallucinated Content | Expected |
|---------|-------------------|----------|
| FND-000001 | File path: `/path/to/mobile_app/src/main/res/values/strings.xml` | No file path in input; evidence type is reproduction_steps |
| FND-000001 | `"code_snippet": "The code snippet containing the RabbitMQ credentials was found during static analysis."` | Input evidence describes APK string extraction, not static analysis of a code snippet |
| FND-000003 | `evidence_check: "[Rule 1], [Rule 2], [Rule 3], [Rule 4], [Rule 5]"` (plain string, not real evidence items) | Input has 1 evidence item (FND-000003-EVID-001, reproduction_steps). No "Rule N" references exist. |

**Metrics report — hallucinated file paths (3 different paths for same finding):**

| Finding | Variant | Hallucinated Path |
|---------|---------|----------------|
| FND-000001 | Base | `/path/to/mobile/app/src/main/res/values/strings.xml` |
| FND-000001 | Fine-tuned | `/path/to/mobile/app/src/main/java/com/example/MyApp.java` |

> Non-deterministic: the SLM invents *different* file paths on each run for the same finding.

**Root cause:** SLM v0.1 generates plausible-sounding but ungrounded evidence descriptions. The model lacks explicit instruction to only reference evidence items provided in the input.

**Impact:** Hallucinated evidence could lead to incorrect confidence scores and wrong escalation decisions. In production, this could cause reviewers to trust false claims.

**Remediation:**
1. **v0.2 training:** Add instruction: "Only reference evidence items provided in the input. Do not invent or assume additional evidence."
2. **Pipeline:** Implement evidence grounding check — compare every claim in SLM output against input evidence items; flag unmatched claims as EVID-001
3. **Self-validation (19/08):** Add a dedicated evidence grounding validation step

---

### EVID-002 — Wrong Evidence Sufficiency Verdict

| Field | Value |
|-------|-------|
| **Code** | `EVID-002` |
| **Severity** | High |
| **Trigger** | SLM verdict on `is_sufficient` differs from gold answer |
| **Affected task types** | `finding_review`, `evidence_check` |
| **v0.2 Target** | 100% match on test set |

**Observed instances:** Not directly measurable in 16/08 because SLM output does not produce structured `is_sufficient` field. This will be measurable after v0.2 training enforces output schema.

**Remediation:** Ensure training data has clear `is_sufficient` labels and that the prompt explains the criteria (manual exploitation demonstrated, successful outcome confirmed).

---

### EVID-003 — Missed Unsupported Claim

| Field | Value |
|-------|-------|
| **Code** | `EVID-003` |
| **Severity** | Medium |
| **Trigger** | Gold lists unsupported claims, but SLM output has empty unsupported_claims |
| **Affected task types** | `evidence_check` |
| **v0.2 Target** | Recall >= 0.8 on unsupported claim detection |

**Observed instances:** Not measurable in 16/08 (SLM does not produce structured `unsupported_claims`). Target for v0.2.

---

## 5. Severity Errors

### SEV-001 — Wrong Severity Suggestion

| Field | Value |
|-------|-------|
| **Code** | `SEV-001` |
| **Severity** | High |
| **Trigger** | SLM suggested severity differs from gold (or from CVSS-implied severity) |
| **Affected task types** | `severity_review`, `finding_review` |
| **v0.2 Target** | 100% severity match |

**Observed instances (16/08):**

| Finding | Variant | SLM Output | Gold | Match |
|---------|---------|-----------|------|-------|
| FND-000001 | Base | Critical | Critical | Yes |
| FND-000001 | Base+RAG | High | Critical | **No** |
| FND-000001 | Fine-tuned | Critical | Critical | Yes |
| FND-000001 | Fine-tuned+RAG | High | Critical | **No** |
| FND-000002 | All 4 | Medium | Medium | Yes |
| FND-000005 | All 4 | Low | Low | Yes |

**Root cause (RAG-specific):** When RAG retrieves KB rules, the additional context appears to influence the SLM to be more conservative, downgrading severity from Critical to High. The KB rules about credential exposure may describe "high risk" which the SLM interprets as severity=High rather than Critical.

**Impact:** Severity downgrade on critical findings is dangerous — it could deprioritize fixes for the most serious vulnerabilities.

**Remediation:**
1. **v0.2 strategy:** Use Fine-tuned without RAG as primary severity assessor (confirmed best by 16/08 metrics)
2. **RAG as advisory:** When using RAG, instruct the SLM that KB rules provide context but should not override the evidence-based severity assessment
3. **Pipeline guard:** Add a post-processing check: if SLM severity contradicts CVSS-implied severity, flag for human review instead of silently accepting

---

### SEV-002 — Missed CVSS-Severity Mismatch

| Field | Value |
|-------|-------|
| **Code** | `SEV-002` |
| **Severity** | Medium |
| **Trigger** | Gold `change_recommended=true` (CVSS score implies different severity), but SLM does not flag the mismatch |
| **Affected task types** | `severity_review`, `finding_review` |
| **v0.2 Target** | 100% detection of CVSS-severity mismatches |

**Observed instances:** Not directly tested in 16/08 (SLM does not produce structured `change_recommended` field). Harness rule-based engine correctly detects these mismatches for FND-003, FND-004, FND-000005.

**Remediation:** Ensure training data includes cases where reported severity contradicts CVSS score. The SLM should output `change_recommended: true` and explain the mismatch.

---

## 6. Format / Schema Errors

### FMT-001 — Invalid JSON Output

| Field | Value |
|-------|-------|
| **Code** | `FMT-001` |
| **Severity** | Critical |
| **Trigger** | SLM output is not parseable as JSON |
| **Affected task types** | All |
| **v0.2 Target** | 0% parse failures |

**Observed instances (16/08):**

All 12 raw outputs in `metrics_report_16aug.json` were truncated (stored with ~500 char limit), causing `Unterminated string` JSON parse errors. This is a **storage/logging issue**, not an SLM generation issue — the actual SLM outputs were valid JSON when parsed in real-time during the Colab run.

However, the PoC pipeline results show `parse_error: false` for all 5 findings, confirming the SLM does generate valid JSON during live inference.

**Root cause:** Metrics logging script truncated `raw_output` field to ~500 characters, breaking multi-line JSON strings.

**Remediation:**
1. Fix metrics logging to store full raw output (or at minimum, increase truncation limit to 5000 chars)
2. Store raw output as separate file if too large, with a reference path in the metrics JSON

---

### FMT-002 — Markdown Code Fence Wrapping

| Field | Value |
|-------|-------|
| **Code** | `FMT-002` |
| **Severity** | Medium |
| **Trigger** | SLM wraps JSON output in ``` ```json ... ``` ``` markdown code fences |
| **Affected task types** | All |
| **v0.2 Target** | 0% fence wrapping |

**Observed instances (16/08):**

| Finding | Base | Base+RAG | Fine-tuned | Fine-tuned+RAG |
|---------|------|----------|------------|----------------|
| FND-000001 | No | **Yes** | No | **Yes** |
| FND-000002 | **Yes** | **Yes** | **Yes** | **Yes** |
| FND-000005 | No | **Yes** | No | **Yes** |

**Pattern:** RAG variants consistently produce markdown fences (6/6 RAG runs). Non-RAG variants sometimes do (2/6 — FND-000002 Base and Fine-tuned). Root cause: when RAG context is injected into the prompt, the SLM treats the response as a "code" block, likely because the retrieved KB rules are formatted as structured text. Additionally, FND-000002 consistently triggers fences even without RAG, suggesting the JWT/algorithm topic may also prompt code-block formatting.

**Remediation:**
1. **Pipeline:** Add pre-parse stripping: `re.sub(r'^```(?:json)?\s*', '', output)` and `re.sub(r'\s*```$', '', output)`
2. **v0.2 training:** Add instruction: "Respond with raw JSON only. Do not wrap in markdown code fences."
3. **Validation:** After parsing, verify no leading/trailing fence markers remain

---

### FMT-003 — Schema Violation

| Field | Value |
|-------|-------|
| **Code** | `FMT-003` |
| **Severity** | High |
| **Trigger** | SLM output is valid JSON but fails `output_schema.json` validation (wrong field names, wrong types, missing required fields) |
| **Affected task types** | All |
| **v0.2 Target** | 100% schema-compliant output |

**Observed instances (16/08):**

All 5 PoC pipeline SLM outputs violate the Output Schema v0.1 in multiple ways:

| Schema Field | SLM Output Type | Expected Type | Findings Affected |
|-------------|-----------------|---------------|------------------|
| `classification` | Free-text string ("Critical", "security") | Object `{label, rationale, supported_by_evidence}` | 5/5 |
| `severity_review` | Flat string (`"severity_assessment"`) | Object `{reported_severity, suggested_severity, is_consistent, ...}` | 5/5 |
| `evidence_review` | Dict, list, or **plain string** (varies per finding) | Object `{is_sufficient, evidence_items_reviewed, ...}` | 5/5 |
| `confidence` | String (`"Very High"`, `"High"`) | Object `{overall_score, level, basis, limitations}` | 5/5 |
| `review_comments` | Absent | Array of review_comment objects | 5/5 |
| `traceability` | Absent | Object with source document info | 5/5 |

> **Note:** `evidence_check` type varies across findings: FND-000001/000002 output as dict with arbitrary keys, FND-000004/000005 as list of objects, but FND-000003 outputs as a **plain string** (`"[Rule 1], [Rule 2], [Rule 3], [Rule 4], [Rule 5]"`) — the most severe form of schema violation for this field.

**Root cause:** SLM v0.1 was trained with a simplified output format (5-key JSON: classification, severity_assessment, evidence_check, remediation, confidence) that does not match the full Output Schema v0.1. The training prompt likely used this simplified schema.

**Impact:** The SLM output cannot be directly validated against `output_schema.json`. The PoC pipeline works around this by using the SLM output for display only, while the Harness rule-based engine produces the actual schema-compliant output.

**Remediation:**
1. **v0.2 training:** Redesign training prompt to request the full Output Schema v0.1 structure (or a compatible subset)
2. **v0.2 training:** Update all gold_output in `benchmark_v1.jsonl` to use the correct schema structure
3. **Gradual approach:** Start with a "bridge schema" that includes the 5 most critical fields in the correct format, then expand

---

### FMT-004 — Missing Required Field

| Field | Value |
|-------|-------|
| **Code** | `FMT-004` |
| **Severity** | Medium |
| **Trigger** | SLM output is valid JSON and mostly schema-compliant, but one or more required fields are missing |
| **Affected task types** | All |
| **v0.2 Target** | 0% missing required fields |

**Observed instances:** Not separately tracked in 16/08 (all outputs were FMT-003 violations anyway). Will be tracked separately once FMT-003 is resolved.

---

## 7. Retrieval / RAG Errors

### RETR-001 — RAG Causes Severity Downgrade

| Field | Value |
|-------|-------|
| **Code** | `RETR-001` |
| **Severity** | High |
| **Trigger** | Adding RAG context changes SLM severity assessment in an incorrect direction |
| **Affected task types** | `finding_review`, `severity_review` |
| **v0.2 Target** | RAG must not cause incorrect severity changes |

**Observed instances (16/08):**

| Finding | Without RAG | With RAG | Direction |
|---------|-------------|----------|----------|
| FND-000001 | Critical (correct) | High (wrong) | Downgrade |

**Root cause:** KB rules retrieved for FND-000001 include escalation rules (`KB-ESC-006`) and remediation templates (`KB-REC-TPL-001`) that describe the finding in terms of "high risk" or "exposure risk". The SLM appears to interpret these contextual descriptions as severity indicators, overriding its correct evidence-based assessment.

**Impact:** Critical severity findings may be incorrectly downgraded when RAG is enabled, potentially deprioritizing the most dangerous vulnerabilities.

**Remediation:**
1. **v0.2 strategy (confirmed):** Fine-tuned without RAG as primary decision-maker
2. **RAG positioning:** Move RAG context after the SLM's own assessment, or clearly label it as "reference material only"
3. **Prompt engineering:** Add instruction: "KB rules below are for reference. Your severity assessment must be based on CVSS score and evidence impact, not on rule descriptions."
4. **Pipeline guard:** Compare RAG and non-RAG severity; if they differ, flag for human review

---

### RETR-002 — Unverified KB Rule References

| Field | Value |
|-------|-------|
| **Code** | `RETR-002` |
| **Severity** | Low |
| **Trigger** | SLM cites KB rule IDs in its output without verification that the cited rule actually exists and is relevant |
| **Affected task types** | `finding_review` (RAG variants) |
| **v0.2 Target** | All cited KB rule IDs must be verified against the KB index |

**Observed instances (16/08):**

> **Verification status:** Each cited KB rule ID was checked against the actual KB files in `data/kb/rules/`.

| Finding | Variant | Cited KB Rule | Exists in KB? | KB File |
|---------|---------|--------------|--------------|--------|
| FND-000001 | Base+RAG | `KB-REC-TPL-001` | Valid | `remediation_templates.json` |
| FND-000001 | Base+RAG | `KB-ESC-006` | Valid | `escalation_rules.json` |
| FND-000001 | Fine-tuned+RAG | `KB-REC-TPL-001` | Valid | `remediation_templates.json` |
| FND-000001 | Fine-tuned+RAG | `KB-ESC-006` | Valid | `escalation_rules.json` |
| FND-000002 | Base+RAG | `KB-ESC-006` | Valid | `escalation_rules.json` |
| FND-000002 | Fine-tuned+RAG | `KB-ESC-006` | Valid | `escalation_rules.json` |
| FND-000004 | Fine-tuned (PoC) | `KB-REC-TPL-003` | Valid | `remediation_templates.json` |
| FND-000004 | Fine-tuned (PoC) | `KB-REC-006` | Valid | `remediation_quality.json` |
| FND-000005 | Base+RAG | `KB-RULE-ID-001` | **Invalid — does not exist** | N/A |
| FND-000005 | Fine-tuned+RAG | `KB-RULE-ID-001` | **Invalid — does not exist** | N/A |
| FND-000005 | Fine-tuned (PoC) | `KB-EVID-001` | Valid | `evidence_standards.json` |
| FND-000005 | Fine-tuned (PoC) | `KB-RULE-ID-001` | **Invalid — does not exist** | N/A |

> **Summary:** 9/12 cited KB IDs are valid (exist in KB). Only 3/12 are fake (`KB-RULE-ID-001`, all from FND-000005). The fake ID uses a non-standard naming pattern (`KB-RULE-ID-*`) that does not match any KB file's `kb_id` format.

**Root cause:** When RAG injects KB rules into the prompt, the SLM copies the rule IDs into its output. In most cases (9/12), the copied IDs are genuine rules from the injected context. However, for FND-000005, the SLM also generated a plausible-looking but fake ID (`KB-RULE-ID-001`) that uses a non-standard naming pattern not found in any KB file.

**Impact:** Low — this is a trust/traceability issue rather than a correctness issue. Citing non-existent rules could mislead reviewers.

**Remediation:**
1. **Pipeline:** After SLM inference, extract all KB rule IDs from the output and verify against the loaded KB entries
2. Strip or flag any unverified rule references
3. **Prompt:** Instruct SLM to only cite rules that were provided in the context

---

## 8. Confidence Scoring Errors

### CONF-001 — Confidence as Free-Text String

| Field | Value |
|-------|-------|
| **Code** | `CONF-001` |
| **Severity** | High |
| **Trigger** | SLM outputs confidence as a free-text string ("Very High", "High", "high") instead of a numeric score (0.0-1.0) |
| **Affected task types** | `finding_review` |
| **v0.2 Target** | 100% numeric confidence output |

**Observed instances (16/08):**

> **Scope:** 100% rate applies to PoC pipeline (5/5 findings). The `metrics_report` variants (12 runs) use a simplified 5-key schema that does **not** include a `confidence` field at all (0/12 produce confidence). This means the issue is universal when the field is present, but the simplified inference prompt omits it entirely.

| Finding | SLM Confidence | Expected | Source |
|---------|---------------|----------|--------|
| FND-000001 | `"Very High"` | `0.85` (or similar numeric) | PoC pipeline |
| FND-000002 | `"High"` | `0.7` | PoC pipeline |
| FND-000003 | `"high"` (lowercase) | `0.7` | PoC pipeline |
| FND-000004 | `"High"` | `0.7` | PoC pipeline |
| FND-000005 | `"High"` | `0.5` | PoC pipeline |

**Root cause:** Training prompt did not specify the confidence output format. The SLM learned to produce qualitative confidence labels from the training data pattern.

**Impact:** String confidence cannot be used in numeric threshold comparisons (escalation at 0.7, evidence completeness at 0.5). The Harness confidence scoring module (`confidence.py`) requires numeric input.

**Remediation:**
1. **v0.2 training:** Instruct: "Output confidence as a numeric score between 0.0 and 1.0"
2. **Pipeline fallback:** Add a string-to-number mapping: `{"very high": 0.9, "high": 0.75, "medium": 0.5, "low": 0.25, "very low": 0.1}`
3. **Validation:** Reject or remap if confidence is not a number

---

## 9. Remediation Errors

### REC-001 — Generic Remediation

| Field | Value |
|-------|-------|
| **Code** | `REC-001` |
| **Severity** | Low |
| **Trigger** | SLM produces generic remediation advice that does not address the specific root cause |
| **Affected task types** | `finding_review`, `remediation_review` |
| **v0.2 Target** | All remediations address root cause |

**Observed instances (16/08):**

| Finding | SLM Remediation | Issue |
|---------|-------------------|-------|
| FND-000001 | "Review the application's source code for any references to RabbitMQ credentials. Remove or obfuscate the credentials if they cannot be removed." | "Remove or obfuscate" is insufficient — credentials must be removed entirely, not obfuscated |

**Root cause:** SLM v0.1 generates shorter, less specific remediations compared to the input finding's detailed recommendation list. The model may be averaging across training examples.

**Remediation:**
1. **v0.2 training:** Include the full input recommendation in the prompt context so the SLM can evaluate it rather than regenerating from scratch
2. **Task design:** Change the SLM task from "generate remediation" to "evaluate the provided remediation" (aligns with review workflow, not generation)

---

## 10. Data Quality Issues (Not SLM Fault)

### DATA-001 — CVSS-Severity Mismatch in Source Report

| Field | Value |
|-------|-------|
| **Code** | `DATA-001` |
| **Severity** | Medium |
| **Trigger** | The source pentest report contains findings where the reported severity does not match the CVSS score |
| **Responsible component** | Source report (not SLM or Harness) |

**Observed instances:**

| Finding | Reported Severity | CVSS Score | CVSS Implied | Mismatch |
|---------|-----------------|------------|-------------|----------|
| FND-000003 | `low` | 6.5 | `medium` | Yes |
| FND-000004 | `low` | 6.5 | `medium` | Yes |
| FND-000005 | `low` | 5.3 | `medium` | Yes |

**Root cause:** The original pentest report assigned severity="low" to these findings, but the CVSS scores (6.5, 6.5, 5.3) all fall in the "medium" range (4.0-6.9) per CVSS v3.1 specification.

**Impact:** The Harness correctly flags these as CVSS-severity mismatches. In production, this triggers unnecessary human escalation for what may be an intentional severity override by the pentester.

**Remediation:**
1. Confirm with EVVO pentesters whether the severity override is intentional
2. If intentional, document the rationale in the finding metadata
3. If unintentional, correct the severity in the normalized finding
4. Consider adding a `severity_override_reason` field to the input schema for cases where pentesters intentionally set severity different from CVSS

---

### DATA-002 — Missing Retest Information

| Field | Value |
|-------|-------|
| **Code** | `DATA-002` |
| **Severity** | Low |
| **Trigger** | All 5 findings have `retest.status = null`, `retest.applicable = null` |
| **Responsible component** | Source report (initial assessment, no retest yet) |

**Observed instances:** All 5 findings (FND-000001 to FND-000005).

**Impact:** Low — this is expected for initial assessment reports. The Harness correctly identifies this and adds a soft escalation flag for confirmed vulnerabilities without retest.

---

## 11. Summary: Error Distribution (16/08 Evaluation)

### By error code

> Counts are labeled by data source: **[PoC]** = poc_pipeline_results.json (5 findings, Fine-tuned only), **[M]** = metrics_report_16aug.json (3 findings x 4 variants = 12 runs). Codes without a label combine both sources.

| Code | Name | Component | Severity | Count | Source | Findings Affected |
|------|------|-----------|----------|-------|--------|-------------------|
| CLASS-001 | Wrong Classification Label | SLM | Critical | 17 | 5 [PoC] + 12 [M] | All 5 (PoC), FND-000001/002/005 (M) |
| FMT-003 | Schema Violation | SLM | High | 5 | [PoC] | All 5 |
| CONF-001 | Confidence as String | SLM | High | 5 | [PoC] | All 5 |
| FMT-002 | Markdown Code Fence | SLM | Medium | 8 | [M] (of 12 runs) | FND-000002 (all 4), FND-000001 RAG (2), FND-000005 RAG (2) |
| SEV-001 | Wrong Severity (RAG) | SLM | High | 2 | [M] | FND-000001 (RAG only) |
| EVID-001 | Hallucinated Evidence | SLM | Critical | 5 | 3 [PoC] + 2 [M] | FND-000001 (3 paths), FND-000003 (fake rules) |
| RETR-001 | RAG Severity Downgrade | SLM | High | 2 | [M] | FND-000001 (RAG only) |
| RETR-002 | Fake KB References | SLM | Low | 3 | [M]+[PoC] | FND-000005 (3 instances of KB-RULE-ID-001) |
| REC-001 | Generic Remediation | SLM | Low | 1 | [PoC] | FND-000001 |
| DATA-001 | CVSS-Severity Mismatch in Source | DATA | Medium | 3 | [PoC] | FND-000003, FND-000004, FND-000005 |
| DATA-002 | Missing Retest Info | DATA | Low | 5 | [PoC] | All 5 |

### By severity

| Severity | Codes | Instance Count | Breakdown |
|----------|-------|---------------|----------|
| Critical | CLASS-001, EVID-001 | 22 | CLASS-001: 17, EVID-001: 5 |
| High | FMT-003, CONF-001, SEV-001, RETR-001 | 14 | FMT-003: 5, CONF-001: 5, SEV-001: 2, RETR-001: 2 |
| Medium | FMT-002, DATA-001 | 11 | FMT-002: 8, DATA-001: 3 |
| Low | RETR-002, REC-001, DATA-002 | 9 | RETR-002: 3, REC-001: 1, DATA-002: 5 |
| **Total** | **11 codes** | **56** | |

> Codes with 0 observed instances (deferred): CLASS-002, CLASS-003, CLASS-004, EVID-002, EVID-003, SEV-002, FMT-001, FMT-004. These are defined for future benchmark coverage.

### By component

| Component | Codes | Role |
|-----------|-------|------|
| **SLM** | CLASS-001, EVID-001, SEV-001, FMT-002, FMT-003, CONF-001, RETR-001, RETR-002, REC-001 | Errors in SLM model output (E-01 through E-06 from Step 1) |
| **DATA** | DATA-001, DATA-002 | Input data quality issues (H-01 from Step 1) |

---

## 12. v0.2 Remediation Priority

### Must fix before v0.2 training (blocks quality gate)

1. **CLASS-001** — Update all training examples to use controlled vocabulary; add vocabulary constraint to prompt
2. **FMT-003** — Redesign SLM output format to match (a subset of) Output Schema v0.1
3. **CONF-001** — Change confidence from string to numeric in training examples and prompt

### Should fix in v0.2 pipeline

4. **FMT-002** — Add markdown fence stripping pre-processor
5. **EVID-001** — Add evidence grounding check in self-validation workflow
6. **RETR-001** — Use Fine-tuned without RAG for severity; RAG as advisory only

### Can defer to post-v0.2

7. **RETR-002** — KB reference verification (low impact)
8. **REC-001** — Improve remediation specificity (change task to evaluation)
9. **DATA-001** — Confirm with pentesters about intentional severity overrides

---

## 13. Lite Taxonomy Mapping

This document supersedes `data/benchmark/error_categories.md` (v0.1 lite). Mapping from old codes to new codes:

| Lite Code (v0.1) | Full Code (v1.1) | Status |
|-------------------|-------------------|--------|
| `CLASS-WRONG-LABEL` | `CLASS-001` | Active — 17 instances observed |
| `CLASS-HALLUCINATED-CONFIRM` | `CLASS-002` | Defined — 0 instances (deferred to hard-negative testing) |
| `CLASS-FAILED-REFUSE` | `CLASS-003` | Defined — 0 instances (deferred to client_qa testing) |
| `QA-REFUSED-IN-SCOPE` | `CLASS-004` | Defined — 0 instances (deferred to client_qa testing) |
| `EVID-HALLUCINATED` | `EVID-001` | Active — 5 instances observed |
| `EVID-WRONG-SUFFICIENCY` | `EVID-002` | Defined — 0 instances (not measurable until schema fixed) |
| `EVID-MISSED-UNSUPPORTED` | `EVID-003` | Defined — 0 instances (not measurable until schema fixed) |
| `SEV-WRONG-SUGGESTION` | `SEV-001` | Active — 2 instances observed |
| `SEV-MISSED-MISMATCH` | `SEV-002` | Defined — Harness detects this; SLM does not yet produce `change_recommended` |
| `FMT-INVALID-JSON` | `FMT-001` | Defined — 0 instances (storage truncation issue, not SLM) |
| `FMT-SCHEMA-VIOLATION` | `FMT-003` | Active — 5 instances observed |
| `FMT-MISSING-FIELD` | `FMT-004` | Defined — subsumed by FMT-003 until schema format is closer |
| `QA-LEAKED-REDACTED` | (kept as `QA-LEAKED-REDACTED`) | Not remapped — no equivalent in full taxonomy yet |

New codes added in v1.1 (not in lite): `FMT-002` (markdown fence), `CONF-001` (confidence string), `RETR-001` (RAG severity downgrade), `RETR-002` (fake KB references), `REC-001` (generic remediation), `DATA-001` (CVSS-severity mismatch), `DATA-002` (missing retest).

---

## 14. Open Questions (Resolved)

| Question | Resolution |
|----------|------------|
| Should `CLASS-002` weigh more than `CLASS-001`? | Yes. CLASS-002 (hallucinated confirmed) is more dangerous than CLASS-001 (wrong label) because it could cause a false-positive vulnerability to reach the final report. Severity: CLASS-002 = Critical, CLASS-001 = Critical (but lower priority for fix since CLASS-001 is a format/vocabulary issue, not a reasoning issue). |
| Should partial credit be given for off-by-one severity? | Yes for SLM-only assessment (e.g., medium vs low is partially correct). No for CVSS-based assessment (CVSS ranges are deterministic). |
| How to score client_qa answers phrased differently from gold? | Use semantic equivalence check (not exact match). Consider using the base model itself as a judge if available, or simple keyword overlap with >70% threshold. |
| Should `wrong_root_cause_assessment` be a separate code? | Yes, assigned as REC-002 (deferred — no instances observed yet). |
| Should `missing_review_comment` be a separate code? | Yes, assigned as FMT-005 (deferred — not applicable until SLM produces schema-compliant output). |