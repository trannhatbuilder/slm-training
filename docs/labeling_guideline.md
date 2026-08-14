# Labeling Guideline — EVVO SLM / Harness

**Version:** 1.0
**Date:** 2026-08-06
**Purpose:** Define instruction format, output schema per task type, labeling rules, and quality criteria for creating training examples from VAPT findings.

---

## 1. Instruction Format

All training examples follow a unified instruction-tuning format:

```json
{
  "task_type": "<task_type_name>",
  "instruction": "<natural language instruction>",
  "input": "<structured finding context>",
  "output": "<expected structured output>",
  "metadata": {
    "finding_id": "FND-XXXXXX",
    "document_id": "DOC-XXXXXX",
    "label_source": "human | heuristic | rule_based",
    "difficulty": "easy | medium | hard",
    "is_hard_negative": false
  }
}
```

### Field Rules

| Field | Required | Description |
|---|---|---|
| `task_type` | Yes | One of the 8 defined task types (see §2) |
| `instruction` | Yes | Natural language prompt telling the SLM what to do |
| `input` | Yes | Structured context from the finding (always include finding_id, title, severity) |
| `output` | Yes | Expected structured response matching the task type's output schema |
| `metadata.finding_id` | Yes | Source finding for traceability |
| `metadata.document_id` | Yes | Source document for traceability |
| `metadata.label_source` | Yes | How the output label was created (human > rule_based > heuristic) |
| `metadata.difficulty` | Yes | Estimated difficulty for the SLM |
| `metadata.is_hard_negative` | Yes | Whether this is a hard-negative example |

---

## 2. Task Types and Output Schemas

### 2.1 finding_review

**Instruction template:**
> Review the following VAPT finding. Assess its classification, evidence sufficiency, severity consistency, and completeness. Provide structured review comments.

**Input must include:**
- `finding_id`, `title`, `severity`, `cwe_id`, `cvss`, `observation` (summary), `evidence` (summary), `recommendation` (summary), `affected_targets`

**Output schema:**
```json
{
  "review_status": "pass | needs_revision | human_review",
  "classification": "Confirmed Vulnerability | Potential Issue | Informational Finding | False Positive",
  "evidence_review": {
    "supported_by_evidence": true,
    "evidence_sufficiency": "sufficient | partial | insufficient | none",
    "missing_information": ["..."]
  },
  "severity_review": {
    "current": "critical | high | medium | low | informational",
    "suggested": "same | needs_review",
    "reason": "..."
  },
  "review_comments": [
    {"code": "EVID|SEV|COMP|...", "severity": "critical|warning|info", "message": "..."}
  ],
  "confidence": 0.85
}
```

**Labeling rules:**
- If exploitation demonstrated AND evidence supports → `classification = Confirmed Vulnerability`
- If exploitation NOT demonstrated → `classification = Potential Issue` (never Confirmed)
- If evidence missing → `evidence_review.supported_by_evidence = false`
- `confidence` is based on evidence completeness + classification certainty + consistency

---

### 2.2 severity_review

**Instruction template:**
> Compare the reported severity against the CVSS score and evidence impact. Flag any mismatch without changing the reported value.

**Input must include:**
- `finding_id`, `title`, `severity`, `cvss.score`, `cvss.vector`, `impact`

**Output schema:**
```json
{
  "reported_severity": "critical|high|medium|low|informational",
  "cvss_score": 9.8,
  "cvss_implied_severity": "critical|high|medium|low|informational",
  "mismatch": true,
  "suggested_action": "review_with_human | no_action",
  "reason": "..."
}
```

**Labeling rules:**
- CVSS ranges: Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9, Info 0.0
- If `reported_severity` ≠ `cvss_implied_severity` → `mismatch = true`, `suggested_action = review_with_human`
- **NEVER** set `suggested_action = auto_correct` — the SLM does not change severity

---

### 2.3 evidence_check

**Instruction template:**
> Assess whether the exploitation evidence sufficiently supports the vulnerability claim. Identify any missing evidence.

**Input must include:**
- `finding_id`, `title`, `severity`, `observation` (summary), `evidence` (exploitation summary)

**Output schema:**
```json
{
  "evidence_status": "sufficient | partial | insufficient | none",
  "supports_classification": true,
  "has_reproduction_steps": true,
  "has_manual_verification": true,
  "missing_evidence": ["..."],
  "evidence_type": "manual_exploit | scanner_only | theoretical | none"
}
```

**Labeling rules:**
- If reproduction steps present AND verified → `evidence_status = sufficient`
- If reproduction steps but NOT verified → `evidence_status = partial`
- If scanner output only → `evidence_status = insufficient`, `evidence_type = scanner_only`
- If no evidence at all → `evidence_status = none`
- If `evidence_status` is insufficient/none → `supports_classification = false`

---

### 2.4 remediation_review

**Instruction template:**
> Evaluate whether the recommendation/remediation addresses the root cause and provides actionable steps.

**Input must include:**
- `finding_id`, `title`, `cwe_id`, `recommendation`

**Output schema:**
```json
{
  "remediation_quality": "specific_and_actionable | addresses_symptom | generic | missing",
  "addresses_root_cause": true,
  "is_actionable": true,
  "issues": ["..."],
  "suggested_improvements": ["..."]
}
```

**Labeling rules:**
- If recommendation has specific steps + addresses CWE root cause → `remediation_quality = specific_and_actionable`
- If recommendation addresses symptom but not root cause → `remediation_quality = addresses_symptom`
- If recommendation is generic template → `remediation_quality = generic`
- **NEVER** generate new remediation text in `suggested_improvements` — only describe what type of improvement is needed

---

### 2.5 client_qa

**Instruction template:**
> Answer the following client question about this finding using only information from the report. Cite sources.

**Input must include:**
- `finding_id`, `title`, `severity`, finding context, `question`

**Output schema:**
```json
{
  "answer": "...",
  "can_answer": true,
  "source_references": [
    {"finding_id": "FND-XXXXXX", "section": "observation|exploitation|recommendation", "text_snippet": "..."}
  ],
  "confidence": 0.9
}
```

**Labeling rules:**
- Answer MUST be grounded in report content — no external knowledge
- Every claim in answer MUST have a source_reference
- If question cannot be answered from report → `can_answer = false`, answer explains what info is needed
- **NEVER** hallucinate details not in the report

---

### 2.6 hard_negative_potential_issue

**Instruction template:**
> Review the following finding. Determine whether it should be classified as a Confirmed Vulnerability or a Potential Issue.

**Input must include:**
- `finding_id`, `title`, `severity`, `observation`, `evidence` (especially the part stating no successful exploitation)

**Output schema:**
```json
{
  "classification": "Potential Issue",
  "reason": "Exploitation was not demonstrated / Evidence is insufficient to confirm",
  "evidence_assessment": "...",
  "what_would_make_confirmed": ["..."],
  "confidence": 0.85
}
```

**Labeling rules:**
- `classification` MUST be `Potential Issue` — this is a hard-negative example
- The SLM must learn: "no successful exploitation" → never Confirmed Vulnerability
- `what_would_make_confirmed` lists what evidence would be needed
- This is the most important task type for preventing hallucination

---

### 2.7 unsupported_refusal

**Instruction template:**
> Answer the following question about this finding.

**Input must include:**
- `finding_id`, finding context, `question` (deliberately unanswerable from report)

**Output schema:**
```json
{
  "can_answer": false,
  "refusal_reason": "The requested information is not available in the report",
  "what_is_available": "I can answer questions about [...]",
  "what_is_needed": "To answer this question, I would need [...]"
}
```

**Labeling rules:**
- The SLM MUST refuse — never guess or hallucinate
- `what_is_available` tells the client what questions CAN be answered
- `what_is_needed` explains what additional information would be required
- Questions must be constructed adversarially (outside report scope)

---

### 2.8 false_positive_detection

**Instruction template:**
> Determine whether this finding is a likely false positive based on evidence quality and verification status.

**Input must include:**
- `finding_id`, `title`, `severity`, `evidence`, `retest` status

**Output schema:**
```json
{
  "false_positive_likelihood": "unlikely | possible | likely",
  "reason": "...",
  "verification_status": "manually_confirmed | scanner_only | unverified",
  "confidence": 0.8
}
```

**Labeling rules:**
- If manually confirmed → `false_positive_likelihood = unlikely`
- If scanner-only with no manual check → `false_positive_likelihood = possible`
- If retest shows not reproducible → `false_positive_likelihood = likely`
- **NEVER** declare `likely` without retest evidence

---

## 3. Labeling Quality Criteria

### Mandatory Checks Before Adding to Dataset

| Check | Rule |
|---|---|
| Schema compliance | Output must match the task type's output schema |
| No PII in output | Output must not contain credentials, names, or client-identifying data |
| Source traceability | metadata.finding_id and document_id must be present and valid |
| Groundedness | Every claim in output must be traceable to input finding content |
| No hallucination | Output must not contain information not present in input |
| Hard-negative correctness | `is_hard_negative = true` only when classification is deliberately Potential Issue / refusal |

### Label Source Priority

| Source | Trust Level | Use Case |
|---|---|---|
| `human` | Highest | Gold labels from EVVO Labs reviewer |
| `rule_based` | Medium | Deterministic labels from quality check / validation engine |
| `heuristic` | Lowest | Labels inferred from finding structure (must be spot-checked) |

For Day 06/08 draft, most labels will be `rule_based` or `heuristic`. Human review is planned for later.

---

## 4. Difficulty Rating Guide

| Difficulty | Criteria | Examples |
|---|---|---|
| `easy` | Clear evidence, straightforward classification, no ambiguity | FND-000001 (hardcoded credentials, confirmed exploit) |
| `medium` | Some ambiguity — CVSS mismatch, partial evidence, generic remediation | FND-000003-005 (severity mismatch + missing retest) |
| `hard` | Counter-intuitive or requires nuanced judgment | FND-000002 (Medium severity but no exploit — must say Potential Issue) |

---

## 5. Hard-Negative Examples

Hard-negative examples are critical for preventing SLM hallucination. They teach the model what NOT to do.

### Hard-Negative Categories (from Kế hoạch §3.2)

| Category | Description | Example from Dataset |
|---|---|---|
| Title correct but evidence insufficient | Finding title suggests vulnerability but evidence does not prove it | FND-000002: JWT title implies crypto vuln but no exploitation demonstrated |
| Scanner-only output | Only automated tool output, no manual verification | (Not in current dataset — construct artificially) |
| High severity but weak impact | Severity claim is high but impact is not demonstrated | (Not in current dataset — construct artificially) |
| Generic remediation | Recommendation does not address root cause | (Partial: some recommendations are more generic than others) |
| Duplicate finding | Same finding reported twice | (Not in current dataset — no duplicates found) |
| Unanswerable question | Client question that cannot be answered from report | (Construct adversarially) |

### Hard-Negative Labeling Rule

- Set `metadata.is_hard_negative = true`
- The expected output MUST show the correct refusal/downgrade behavior
- The SLM must learn: insufficient evidence → Potential Issue, NOT Confirmed Vulnerability

---

## 6. Dataset Draft Constraints

For Day 06/08, the dataset draft has these limitations:

- **No train/val/test split** — only 1 document family, splitting by finding risks leakage
- **Labels are rule_based or heuristic** — human review needed before training
- **Small dataset** — 5 findings × ~5 task types = ~25 examples (minimum viable)
- **Redaction not yet applied** — dataset draft contains sensitive data; MUST redact before Colab upload
- **English only** — all findings are in English

### Minimum Viable Coverage

| Task Type | Minimum Examples | Source |
|---|---|---|
| finding_review | 5 | All findings |
| severity_review | 2 | FND-000001 (match) + FND-000003 (mismatch) |
| evidence_check | 5 | All findings |
| remediation_review | 4 | FND-000001, FND-000003, FND-000004, FND-000005 |
| client_qa | 3 | Construct 3 questions for FND-000001, FND-000002, FND-000005 |
| hard_negative_potential_issue | 1 | FND-000002 |
| unsupported_refusal | 2 | Construct 2 unanswerable questions |
| false_positive_detection | 0 | No false positive candidates in current dataset |

**Total minimum: ~22 examples**