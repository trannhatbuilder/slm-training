# Task Type Catalog

**Version:** 1.0
**Date:** 2026-08-05
**Scope:** EVVO SLM / Harness — Day 05/08 eligibility assignment

---

## 1. Task Type Definitions

Each task type defines a specific instruction format that the SLM will be trained on. A finding is eligible for a task type only if it has sufficient content to form a valid training example.

### finding_review

- **Description:** Full structured review of a VAPT finding — classification, evidence assessment, severity review, consistency checks.
- **Required input:** title, severity, observation, evidence (exploitation), recommendation, CWE, CVSS.
- **Required output:** review_status, classification, evidence_review, severity_review, review_comments, confidence.
- **Eligibility condition:** Finding has Observation AND Exploitation AND Recommendation sections.

### severity_review

- **Description:** Targeted severity assessment — compare reported severity against CVSS score and evidence impact.
- **Required input:** severity, cvss (score + vector), impact.
- **Required output:** severity_review (current, suggested, reason).
- **Eligibility condition:** Finding has both severity AND CVSS score/vector present.
- **Special case:** Findings with CVSS-severity mismatch are high-value training examples.

### evidence_check

- **Description:** Assess whether exploitation evidence sufficiently supports the vulnerability claim.
- **Required input:** observation, exploitation section, severity.
- **Required output:** evidence_review (supported_by_evidence, missing_information), review_comments.
- **Eligibility condition:** Finding has Exploitation section (even if empty or inconclusive).

### remediation_review

- **Description:** Evaluate whether recommendation/remediation addresses root cause and is actionable.
- **Required input:** recommendation, observation, CWE.
- **Required output:** recommendation_review, review_comments.
- **Eligibility condition:** Finding has Recommendation or Remediation section.

### client_qa

- **Description:** Answer client questions about a finding using only information from the report.
- **Required input:** all finding fields.
- **Required output:** answer, source references.
- **Eligibility condition:** Finding is normalized and passes schema validation.

### hard_negative_potential_issue

- **Description:** Training example where the SLM must output "Potential Issue" instead of "Confirmed Vulnerability" because exploitation was not demonstrated.
- **Required input:** observation, exploitation section showing no successful exploit.
- **Required output:** classification = "Potential Issue", confidence rationale.
- **Eligibility condition:** Finding has Exploitation section that explicitly states no successful exploitation or insufficient evidence.
- **Purpose:** Prevent hallucination of confirmed vulnerability when evidence does not support it.

### unsupported_refusal

- **Description:** Training example where the SLM must refuse to answer a question that cannot be answered from the report.
- **Required input:** a question outside report scope.
- **Required output:** refusal + explanation of what information is needed.
- **Eligibility condition:** Requires constructing adversarial questions (not directly from finding data).
- **Note:** Cannot be generated from findings alone; requires additional question construction step.

### false_positive_detection

- **Description:** Identify findings that are likely false positives (scanner-only, no manual confirmation).
- **Required input:** observation, evidence, retest status.
- **Required output:** classification, confidence, review_comments.
- **Eligibility condition:** Finding lacks manual verification evidence or retest confirmation.
- **Note:** None of the current 5 findings are scanner-only; all have manual analysis.

---

## 2. Eligibility Matrix — DOC-000001 (5 Findings)

| Task Type | FND-000001 | FND-000002 | FND-000003 | FND-000004 | FND-000005 |
|---|---|---|---|---|---|
| finding_review | ✅ | ✅ | ✅ | ✅ | ✅ |
| severity_review | ✅ | ✅ | ⚠️* | ⚠️* | ⚠️* |
| evidence_check | ✅ | ✅ | ✅ | ✅ | ✅ |
| remediation_review | ✅ | ✅** | ✅ | ✅ | ✅ |
| client_qa | ✅ | ✅ | ✅ | ✅ | ✅ |
| hard_negative_potential_issue | ❌ | ✅ | ❌ | ❌ | ❌ |
| unsupported_refusal | ⬚ | ⬚ | ⬚ | ⬚ | ⬚ |
| false_positive_detection | ❌ | ❌ | ❌ | ❌ | ❌ |

**Legend:**
- ✅ Eligible
- ⚠️* Eligible — CVSS-severity mismatch makes this a high-value training example
- ✅** Eligible — note: FND-000002 uses "Remediation" label instead of "Recommendation"
- ❌ Not eligible (does not meet condition)
- ⬚ Cannot be determined from finding data alone (requires additional construction)

---

## 3. Processing Status per Finding

| Finding ID | Processing Status | Eligible Task Count | Quality Status | Labeling Ready |
|---|---|---|---|---|
| FND-000001 | normalized | 5 | needs_review | ✅ Yes (after redaction) |
| FND-000002 | normalized | 6 | needs_review | ✅ Yes |
| FND-000003 | normalized | 4 | needs_review | ✅ Yes |
| FND-000004 | normalized | 4 | needs_review | ✅ Yes |
| FND-000005 | normalized | 4 | needs_review | ✅ Yes (after redaction) |

---

## 4. High-Value Training Examples

These findings are especially valuable for training and should be prioritized:

1. **FND-000002 + hard_negative_potential_issue:** The SLM must learn that "no successful exploitation demonstrated" → classification = Potential Issue, NOT Confirmed Vulnerability. This is the most important training example in the current dataset.

2. **FND-000003, FND-000004, FND-000005 + severity_review:** CVSS-severity mismatch (Low vs Medium by CVSS) teaches the SLM to flag severity discrepancies without auto-correcting them.

3. **FND-000001 + evidence_check:** Full reproduction steps + verified credentials → strong example of confirmed vulnerability with sufficient evidence.

---

## 5. Labeling Readiness

| Condition | Status |
|---|---|
| All findings have eligible tasks assigned | ✅ |
| All findings pass Input Schema v0.2 | ✅ |
| Redaction applied | ❌ Pending (FND-000001, FND-000005) |
| Train/validation/test split | ❌ Not yet — only 1 document family |
| Gold labels created | ❌ Not yet — Day 06/08 |
| Labeling guideline written | ❌ Not yet — Day 06/08 |

**Next step after redaction:** Findings are ready for labeling guideline creation and instruction dataset draft (Day 06/08).

---

## 6. Constraints

- **Do NOT split train/validation/test** with only 1 document family — risk of data leakage across findings from the same engagement.
- **Do NOT use AI-generated review as gold label** without human review.
- **Do NOT create training dataset** from normalized JSONL directly — instruction format must be designed first (Day 06/08).
- **unsupported_refusal** and **false_positive_detection** tasks require additional data construction beyond what the findings provide.