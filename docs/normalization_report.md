# Normalization Report

**Document ID:** DOC-000001
**Source file:** DOC-000001.docx (BRIGHTREE VAPT)
**Schema version:** Input Schema v0.2
**Report date:** 2026-08-05
**Pipeline:** DOCX → inspect → extract → validate → parse metadata → parse sections → normalize → schema validation → quality check

---

## 1. Source Document Summary

| Field | Value |
|---|---|
| Document ID | DOC-000001 |
| Total paragraphs | 343 |
| Total tables | 24 |
| Finding title style | EvvoH2 |
| Findings extracted | 5 |
| Client | GlobalSign.In Pte Ltd |
| VAPT Team | Tung Phan (Kai), Nguyen Trong Dao (OSCP), Quyen Hong Son (OSCP) |
| Review By | Dung Bui (Andrew) |
| Approved By | Vince Chew |
| Testing period | 21/Oct/2025 – 28/Mar/2026 |

---

## 2. Per-Finding Normalization Summary

### FND-000001 — Hardcoded RabbitMQ Credentials in Mobile Application

| Field | Reported Value | Normalized Value | Note |
|---|---|---|---|
| Severity | CRITICAL | critical | Match |
| CWE | CWE-798: Use of Hard-coded Credentials | CWE-798 | Parsed |
| CVSS score | 9.8 | 9.8 | Match |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | Parsed all 6 metrics | Valid |
| Affected target | Android Mobile Application (APK) | target_type: mobile_application | Inferred |
| Retest status | (empty) | not_tested | Warning: missing retest |
| User roles | No authentication required | unauthenticated | Parsed |
| Sections | Observation, Exploitation, Recommendation | All 3 present | OK |
| Evidence | Exploitation section contains reproduction steps + verified auth | 1 evidence item extracted | Simplified |

**Quality status:** needs_review
**Warnings:** Missing retest status and verification result

---

### FND-000002 — Use of Symmetric JWT Signing Algorithm (HS256)

| Field | Reported Value | Normalized Value | Note |
|---|---|---|---|
| Severity | MEDIUM | medium | Match |
| CWE | CWE-327: Use of a Broken or Risky Cryptographic Algorithm | CWE-327 | Parsed |
| CVSS score | 4.8 | 4.8 | Match |
| CVSS vector | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N | Parsed all 6 metrics | Valid |
| Affected target | JWT token | target_type: api_endpoint | Inferred |
| Retest status | (empty) | not_tested | Warning: missing retest |
| User roles | No authentication required | unauthenticated | Parsed |
| Sections | Observation, Exploitation, Remediation | All 3 present (note: label is "Remediation" not "Recommendation") | OK |
| Evidence | "No evidence was found that the signing secret could be recovered" | 1 evidence item extracted | Hard-negative candidate |

**Quality status:** needs_review
**Warnings:** Missing retest status and verification result
**Special note:** Exploitation section states no successful exploitation was demonstrated. This finding is a **Potential Issue**, not a Confirmed Vulnerability. Strong candidate for hard-negative example in training dataset.

---

### FND-000003 — Root Detection Not Implemented

| Field | Reported Value | Normalized Value | Note |
|---|---|---|---|
| Severity | LOW | low | Mismatch warning |
| CWE | CWE-693: Protection Mechanism Failure | CWE-693 | Parsed |
| CVSS score | 6.5 | 6.5 | Mismatch warning |
| CVSS vector | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N | Parsed all 6 metrics | Valid |
| Affected target | Android Mobile Application | target_type: mobile_application | Inferred |
| Retest status | (empty) | not_tested | Warning: missing retest |
| User roles | No authentication required | unauthenticated | Parsed |
| Sections | Observation, Exploitation, Recommendation | All 3 present | OK |

**Quality status:** needs_review
**Warnings:**
- Severity LOW does not match CVSS 6.5 (expected MEDIUM)
- Missing retest status and verification result

**Policy:** Pipeline does NOT auto-correct severity. Reported value preserved. Warning flagged for human review.

---

### FND-000004 — Weak SSL Pinning Implementation

| Field | Reported Value | Normalized Value | Note |
|---|---|---|---|
| Severity | LOW | low | Mismatch warning |
| CWE | CWE-295: Improper Certificate Validation | CWE-295 | Parsed |
| CVSS score | 6.5 | 6.5 | Mismatch warning |
| CVSS vector | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N | Parsed all 6 metrics | Valid |
| Affected target | Android Mobile Application | target_type: mobile_application | Inferred |
| Retest status | (empty) | not_tested | Warning: missing retest |
| User roles | No authentication required | unauthenticated | Parsed |
| Sections | Observation, Exploitation, Recommendation | All 3 present | OK |

**Quality status:** needs_review
**Warnings:**
- Severity LOW does not match CVSS 6.5 (expected MEDIUM)
- Missing retest status and verification result

**Policy:** Pipeline does NOT auto-correct severity. Reported value preserved. Warning flagged for human review.

---

### FND-000005 — Email Enumeration Possible During User Registration

| Field | Reported Value | Normalized Value | Note |
|---|---|---|---|
| Severity | LOW | low | Mismatch warning |
| CWE | CWE-204: Observable Response Discrepancy | CWE-204 | Parsed |
| CVSS score | 5.3 | 5.3 | Mismatch warning |
| CVSS vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | Parsed all 6 metrics | Valid |
| Affected target | https://eform.brightree.com.sg/users/sign_up | target_type: web_application | Inferred |
| Retest status | (empty) | not_tested | Warning: missing retest |
| User roles | No authentication required | unauthenticated | Parsed |
| Sections | Observation, Exploitation, Recommendation | All 3 present | OK |

**Quality status:** needs_review
**Warnings:**
- Severity LOW does not match CVSS 5.3 (expected MEDIUM)
- Missing retest status and verification result

**Policy:** Pipeline does NOT auto-correct severity. Reported value preserved. Warning flagged for human review.

---

## 3. Quality Check Summary

| Metric | Count |
|---|---|
| Total findings | 5 |
| Schema validation pass | 5/5 |
| Errors | 0 |
| Warnings | 8 |
| Blocked | 0 |
| Exact duplicates | 0 |

### Warning Breakdown

| Warning Type | Count | Findings Affected |
|---|---|---|
| Missing retest status | 5 | FND-000001, FND-000002, FND-000003, FND-000004, FND-000005 |
| CVSS-severity mismatch | 3 | FND-000003 (Low vs 6.5), FND-000004 (Low vs 6.5), FND-000005 (Low vs 5.3) |

### Quality Status Distribution

| Status | Count | Findings |
|---|---|---|
| needs_review | 5 | All findings |
| passed | 0 | — |
| blocked | 0 | — |

---

## 4. Schema Compliance

- All 5 findings pass Input Schema v0.2 validation.
- Required fields present: finding_id, title, severity, observation, evidence, recommendation, source, governance.
- CVSS vectors valid for all 5 findings (CVSS 3.1 base format).
- CWE IDs valid format for all 5 findings.

---

## 5. Redaction Status

| Field | Status | Note |
|---|---|---|
| RabbitMQ credentials | NOT YET REDACTED | FND-000001 exploitation section contains hostname, username, password. Must redact before uploading to Colab. |
| Client domain | NOT YET REDACTED | FND-000005 affected target contains `eform.brightree.com.sg`. Evaluate whether to redact. |
| APK name | NOT YET REDACTED | FND-000001 contains `BrightNote.apk`. Evaluate whether to pseudonymize. |
| Client contact names | NOT YET REDACTED | Engagement table contains names of client contacts and pentesters. Not in finding data but in source document. |

**Action required:** Run redaction pipeline on normalized data before creating training dataset.

---

## 6. Source Traceability

All 5 findings include source traceability:
- `document_id`: DOC-000001
- `location.title_paragraph`: finding title paragraph index
- `location.block_range`: start/end block indices in document
- `traceability.extraction_timestamp`, `traceability.pipeline_version`

---

## 7. Consistency Checks Performed

- [x] 5/5 finding records pass Input Schema v0.2
- [x] 5/5 findings have Observation section
- [x] 5/5 findings have Exploitation section
- [x] 5/5 findings have Recommendation or Remediation section
- [x] 5/5 CVSS vectors parsed successfully
- [x] No exact duplicates detected
- [x] Source traceability preserved for all findings
- [x] Source document and data artifacts excluded from Git

---

## 8. Outstanding Items

1. **Redaction not yet applied** — credentials and PII still present in normalized data.
2. **Retest status empty for all findings** — not auto-filled; requires human input.
3. **Severity-CVSS mismatch for 3 findings** — preserved as-is with warning; human review needed.
4. **Evidence model is simplified** — only 1 evidence item per finding; screenshots, HTTP requests not extracted separately.
5. **Governance fields hardcoded** — not sourced from per-document config.
6. **Training dataset not yet created** — normalized JSONL is not a training dataset.