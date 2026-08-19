# Self-Validation Checklist — Spec v1.0

**Version:** 1.0
**Created:** 2026-08-19
**Task:** Week 12, Day 19/08 — Self-validation workflow

---

## 1. Purpose

Self-validation checklist chạy **sau** harness pipeline (sau step 12), trước khi output được gửi cho client hoặc human reviewer. Mỗi checklist item trả lời một câu hỏi chất lượng, và khi fail, triggering một **response action** thay vì chỉ flag comment.

Khác với harness hiện tại (chỉ tạo `review_comments`), self-validation thêm **quyết định hành động**:

- **re-check**: SLM phân tích lại với prompt điều chỉnh
- **request_data**: Yêu cầu thêm thông tin từ pentester/client
- **pending**: Tạm dừng, chờ input hoặc event khác
- **escalate**: Gửi lên human reviewer

---

## 2. Position in Pipeline

```
Input Finding
  │
  ├─ Steps 1-3: Input validation
  ├─ Step 4: Deterministic checks (rule_checks.py)
  ├─ Step 5: KB retrieval
  ├─ Step 6-7: SLM call (future)
  ├─ Step 8: SLM output validation (future)
  ├─ Step 9: Consistency checks (consistency.py)
  ├─ Step 10: Escalation (escalation.py)
  ├─ Step 11-12: Assemble output (output_assembler.py)
  │
  ├─ ★ NEW: Self-Validation Checklist (self_validation.py)
  │     ├─ SV-001..SV-008 checks
  │     └─ Response action determination
  │
  └─ Output: review result + action disposition
```

Self-validation **không thay thế** escalation.py. Nó bổ sung:
- Escalation.py quyết định **có cần human không**
- Self-validation quyết định **hành động cụ thể** khi check fail

---

## 3. Response Action Definitions

| Action | Code | Mô tả | Ai thực hiện | Output
|---|---|---|---|---|
| **Pass** | `pass` | Checklist item passed — không cần hành động | — | — |
| **Re-check** | `recheck` | SLM phân tích lại với prompt điều chỉnh (narrower scope, focus vào gap) | SLM (automated) | Retry pipeline với modified prompt |
| **Request Data** | `request_data` | Yêu cầu pentester/client cung cấp thêm thông tin cụ thể | System → Pentester | `data_request` object (field, reason, urgency)
| **Pending** | `pending` | Tạm dừng review, chờ sự kiện khác (retest, data response, external input) | System | `pending_reason` + `resume_condition`
| **Escalate** | `escalate` | Gửi lên human reviewer với đầy đủ context | Human | `escalation_detail` object |
| **Warn** | `warn` | Fail nhưng không block — ghi nhận và tiếp tục | System | Warning trong output |

### 3.1 Action Priority Order

Khi một checklist item fail, response action được chọn theo thứ tự ưu tiên:

```
1. recheck     → thử tự sửa trước (cheap, fast)
2. request_data → cần thông tin từ bên ngoài
3. pending     → không thể tiếp tục ngay, chờ event
4. escalate    → cần human quyết định
5. warn        → fail nhẹ, không block flow
```

Tuy nhiên, một số điều kiện **bypass re-check** và đi thẳng đến escalate (xem §6).

---

## 4. Checklist Items

### SV-001: Asset Identification

**Câu hỏi:** Asset (affected target) có xác định được không?

| Field | Giá trị |
|---|---|
| Check ID | `SV-001` |
| Maps to | `check_completeness()` → `missing_required_fields`;
`finding.affected_targets` |
| Severity nếu fail | `warning` |

**Check logic:**
1. `affected_targets` có tồn tại và không empty?
2. Mỗi target có `target_type` và `value`?
3. `value` không phải placeholder ("N/A", "TBD", "unknown")?

**Pass criteria:** Tất cả 3 checks pass.

**Fail response tree:**
```
affected_targets empty hoặc missing
  ├─ observation có đề cập target cụ thể?
  │   ├─ YES → recheck (prompt: extract target from observation)
  │   └─ NO  → request_data (field: affected_targets,
  │            reason: "No identifiable asset in finding")
  └─ target value là placeholder
      └─ request_data (field: affected_targets[0].value,
                       reason: "Asset identifier is placeholder")
```
**Bypass to escalate:** Finding severity = critical/high và asset không xác định → escalate trực tiếp (không re-check).

---

### SV-002: Evidence Source

**Câu hỏi:** Evidence đến từ đâu?

| Field | Giá trị |
|---|---|
| Check ID | `SV-002` |
| Maps to | `check_evidence()` → `evidence_type` detection;
`review_taxonomy.yaml` EVID_SCANNER_ONLY |
| Severity nếu fail | `critical` (scanner-only) / `warning` (không xác định nguồn) |

**Check logic:**
1. Evidence có tồn tại (≥1 evidence item)?
2. Mỗi evidence item có `evidence_type`?
3. `evidence_type` là gì? (`reproduction_steps`, `scanner_output`, `interview`, `configuration_review`, other)
4. Nếu `scanner_output`: có kèm `manual_verification` không?

**Pass criteria:**
- Có evidence với `evidence_type` rõ ràng, HOẶC
- `scanner_output` nhưng có kèm manual verification evidence

**Fail response tree:**
```
no evidence at all
  └─ request_data (field: evidence,
                   reason: "No evidence provided for this finding",
                   urgency: high)

evidence_type missing
  ├─ evidence content có reproduction steps?
  │   ├─ YES → recheck (prompt: classify evidence type from content)
  │   └─ NO  → request_data (field: evidence[0].evidence_type,
                       reason: "Cannot determine evidence source")

evidence_type = scanner_output, no manual verification
  └─ escalate (reason: "Scanner-only finding requires human verification",
             reviewer: technical_reviewer)

evidence_type = scanner_output, HAS manual verification
  └─ pass (scanner + manual = acceptable)
```
**Bypass to escalate:** Scanner-only findings LUÔN escalate (per EVVO policy: không tự quyết định FP/TP chỉ từ scanner output).

---

### SV-003: Evidence-Vulnerability Alignment

**Câu hỏi:** Evidence có chứng minh vulnerability không?

| Field | Giá trị |
|---|---|
| Check ID | `SV-003` |
| Maps to | `check_evidence()` → `is_sufficient`, `supported_claims`, `unsupported_claims`;
`check_consistency()` → `evidence_classification_alignment` |
| Severity nếu fail | `critical` |

**Check logic:**
1. `evidence_review.is_sufficient` = true?
2. `unsupported_claims` empty?
3. Evidence content có chứa exploitation marker? ("authentication succeeds", "successfully intercepted", "confirmed that", etc.)
4. Evidence topic match finding topic? (kiểm tra keyword overlap giữa evidence content và finding title/observation)

**Pass criteria:** `is_sufficient = true` VÀ `unsupported_claims` empty.

**Fail response tree:**
```
is_sufficient = false, unsupported_claims = []
  └─ request_data (field: evidence,
                   reason: "Evidence is incomplete — does not fully demonstrate exploitation",
                   urgency: medium)

is_sufficient = false, unsupported_claims non-empty
  ├─ unsupported claims là do evidence thiếu chi tiết?
  │   ├─ YES → request_data (field: evidence,
  │                      reason: "Claims X not supported — need additional evidence",
  │                      detail: list unsupported claims)
  │   └─ NO (claims contradict evidence)
  │       └─ escalate (reason: "Evidence contradicts vulnerability claim",
  │                  reviewer: senior_pentester)

evidence topic mismatch (evidence nói về A, finding nói về B)
  └─ escalate (reason: "Evidence appears to describe a different vulnerability",
             reviewer: technical_reviewer)
```
**Bypass to escalate:** Evidence contradicts claim → escalate trực tiếp (re-check vô nghĩa).

---

### SV-004: Reproducibility

**Câu hỏi:** Có thể tái hiện (reproduce) không?

| Field | Giá trị |
|---|---|
| Check ID | `SV-004` |
| Maps to | `check_evidence()` → evidence_type check;
New: reproduction step clarity validation |
| Severity nếu fail | `warning` |

**Check logic:**
1. Có evidence với `evidence_type = reproduction_steps`?
2. Reproduction steps có chứa action verbs? ("navigate", "submit", "configure", "extract", "attach", "run", "send")
3. Steps có chứa expected outcome? ("observe", "confirm", "verify", "should see")
4. Steps có chứa tool/command cụ thể? (URL, command line, file path)

**Pass criteria:** Có reproduction steps với ≥1 action verb + ≥1 expected outcome.

**Fail response tree:**
```
no reproduction_steps evidence
  ├─ finding là informational / false_positive?
  │   ├─ YES → warn (informational findings may not need reproduction)
  │   └─ NO  → request_data (field: evidence,
  │                      reason: "No reproduction steps provided",
  │                      urgency: medium)
  └─
has reproduction_steps but missing action verbs or expected outcome
  └─ warn (reason: "Reproduction steps lack clarity — may be hard to follow")
```
**Bypass to escalate:** Không có. Reproducibility issue luôn có thể request thêm data.

---

### SV-005: Impact Support

**Câu hỏi:** Impact có được hỗ trợ (bằng evidence/severity) không?

| Field | Giá trị |
|---|---|
| Check ID | `SV-005` |
| Maps to | `check_impact()` → `is_supported_by_evidence`, `is_proportionate` |
| Severity nếu fail | `warning` |

**Check logic:**
1. `impact_review.is_supported_by_evidence` = true?
2. `impact_review.is_proportionate` = true?
3. Impact description không phải generic template? (check against generic phrases: "may lead to", "could potentially", "an attacker might")

**Pass criteria:** `is_supported_by_evidence = true`.

**Fail response tree:**
```
is_supported = false
  └─ recheck (prompt: "Re-evaluate whether impact description is supported by evidence.
            Focus on specific impact claims vs what evidence demonstrates.")
  → nếu recheck vẫn fail → warn

is_proportionate = false (impact quá lớn/small so với severity)
  └─ warn (reason: "Impact description may not be proportionate to assessed severity")

generic/template impact text
  └─ request_data (field: impact,
                   reason: "Impact description is generic — please provide finding-specific impact")
```

---

### SV-006: Severity Legitimacy

**Câu hỏi:** Severity có hợp lý không?

| Field | Giá trị |
|---|---|
| Check ID | `SV-006` |
| Maps to | `check_severity()`, `check_cvss()`, `check_consistency()` → severity_cvss_alignment |
| Severity nếu fail | `warning` (mismatch) / `critical` (high/critical sans evidence) |

**Check logic:**
1. CVSS score → implied severity band (per CVSS v3.1 ranges)
2. Reported severity == implied severity?
3. Nếu mismatch: có `severity_override_reason` trong input?
4. Nếu classification = confirmed_vulnerability: severity ≥ medium?

**Pass criteria:** Severity matches CVSS band, HOẶC mismatch có override reason.

**Fail response tree:**
```
severity != CVSS band, no override reason
  ├─ severity bị underrated (reported thấp hơn CVSS)
  │   └─ escalate (reason: "Severity underrated — CVSS implies higher severity",
  │              reviewer: report_reviewer)
  └─ severity bị overrated (reported cao hơn CVSS)
      └─ escalate (reason: "Severity overrated — CVSS implies lower severity",
                 reviewer: report_reviewer)

severity != CVSS band, HAS override reason
  └─ warn (reason: "Severity-CVSS mismatch overridden by pentester")

confirmed_vulnerability + severity < medium
  └─ escalate (reason: "Confirmed vulnerability classified below medium severity",
             reviewer: senior_pentester)
```
**Bypass to escalate:** Severity mismatch LUÔN escalate (per EVVO policy: chỉ human mới được quyết định final severity). Re-check không hợp lý vì SLM không có quyền thay severity.

---

### SV-007: False Positive Probability

**Câu hỏi:** Có khả năng false positive không?

| Field | Giá trị |
|---|---|
| Check ID | `SV-007` |
| Maps to | `check_classification()`; New: FP probability scoring |
| Severity nếu fail | `critical` (high FP risk) |

**Check logic:**
1. Evidence type = `scanner_output`? → FP probability HIGH
2. Observation chứa "no evidence was found", "no successful exploitation", "not demonstrated"? → FP probability MEDIUM
3. Classification = `false_positive` nhưng không có explanation? → flag
4. Severity = critical/high nhưng evidence chỉ là theoretical? → FP probability MEDIUM

**FP Probability Scoring:**

| Signal | FP Probability |
|---|---|
| scanner_only + no manual verification | HIGH (0.9) |
| "no evidence was found" in evidence | MEDIUM (0.6) |
| "no successful exploitation" + severity ≥ high | MEDIUM (0.6) |
| Classification = false_positive | N/A (already labeled) |
| None of the above | LOW (0.1) |

Multiple signals → take max.

**Pass criteria:** FP probability = LOW, HOẶC đã được label `false_positive` với rationale.

**Fail response tree:**
```
FP probability = HIGH (scanner-only)
  └─ escalate (reason: "High false positive probability — scanner-only, no manual verification",
             reviewer: technical_reviewer)

FP probability = MEDIUM
  └─ pending (reason: "Moderate FP risk — awaiting additional verification or retest",
            resume_condition: "manual_verification_provided OR retest_completed")
```
**Bypass to escalate:** FP probability = HIGH → luôn escalate.

---

### SV-008: Unsupported Claims

**Câu hỏi:** Claim nào không có bằng chứng?

| Field | Giá trị |
|---|---|
| Check ID | `SV-008` |
| Maps to | `check_evidence()` → `unsupported_claims`;
`check_impact()` → `unsupported_impact_claims`;
`check_recommendation()` → generic recommendation detection |
| Severity nếu fail | `warning` (minor) / `critical` (claim là basis cho classification) |

**Check logic:**
1. `evidence_review.unsupported_claims` empty?
2. `impact_review.unsupported_impact_claims` empty?
3. Observation/impact có chứa quantitative claims không có evidence? (e.g., "thousands of users", "full database access")
4. Recommendation có generic phrases không rooted trong evidence?

**Pass criteria:** `unsupported_claims` empty.

**Fail response tree:**
```
unsupported_claims non-empty
  ├─ claims là supporting arguments (không phải main claim)?
  │   ├─ YES → warn (reason: "Minor claims lack evidence support")
  │   └─ NO (main claim / basis for classification)
  │       └─ recheck (prompt: "The following claims lack evidence: X. Re-evaluate classification.")
  │       → nếu recheck không resolve → escalate
  │
unsupported_impact_claims non-empty
  └─ recheck (prompt: "Impact claims X are not supported by evidence. Re-evaluate impact.")
  → nếu recheck không resolve → warn
```

---

## 5. Disposition Matrix

Sau khi tất cả 8 items chạy, tổng hợp thành một **action disposition**:

```yaml
self_validation_result:
  checklist:
    SV-001: { status: pass|fail|error, action: pass|recheck|request_data|pending|escalate|warn, detail: str }
    SV-002: { ... }
    # ... SV-003..SV-008
  overall_action: pass | recheck | request_data | pending | escalate | warn
  recheck_items: ["SV-003", "SV-005"]           # items cần re-check
  request_data_fields: [                          # data cần request
    { field: "evidence", reason: "...", urgency: high|medium|low }
  ]
  pending_reason: str | null                      # nếu overall = pending
  pending_resume_condition: str | null
  escalation_reasons: [str]                        # nếu overall = escalate
  escalation_reviewer: str | null
```

### 5.1 Overall Action Resolution

Priority (highest → lowest):

```
1. escalate    → nếu bất kỳ SV item có action = escalate
2. pending     → nếu bất kỳ SV item có action = pending (và không có escalate)
3. request_data → nếu có data request (và không có escalate/pending)
4. recheck     → nếu có recheck items (và không có action cao hơn)
5. warn        → nếu tất cả fails chỉ là warn
6. pass        → nếu tất cả pass
```

---

## 6. Escalation Triggers (Bypass Re-check)

Các điều kiện **skip re-check**, đi thẳng escalate:

| Trigger | SV Item | Reason |
|---|---|---|
| Scanner-only + severity critical/high | SV-002 | SLM không đủ thẩm quyền xác nhận từ scanner output |
| Evidence contradicts vulnerability claim | SV-003 | Re-check không thể resolve contradiction |
| Severity-CVSS mismatch (no override reason) | SV-006 | Chỉ human mới được quyết định final severity |
| FP probability = HIGH | SV-007 | Scanner-only findings cần human verification |
| Sensitive data detected in finding | SV-002/SV-003 | Credentials, PII, internal URLs — cần human check per governance policy |
| Confirmed vulnerability + severity < medium | SV-006 | Logic contradiction cần human review |
| Question outside report scope (client Q&A) | N/A | Per escalation policy — luôn refuse và flag |
| Multiple inference runs produce unstable verdict | N/A | Non-deterministic output cần human arbitrate |

---

## 7. Integration Points

### 7.1 Tích hợp vào orchestrator.py

```python
# Sau step 12 (assemble_output), thêm:
from .self_validation import run_self_validation

sv_result = run_self_validation(finding, result)
result["self_validation"] = sv_result

# Update review_status dựa trên overall_action
if sv_result["overall_action"] == "escalate":
    result["review_status"] = "human_review"
elif sv_result["overall_action"] == "pending":
    result["review_status"] = "pending"
elif sv_result["overall_action"] == "request_data":
    result["review_status"] = "needs_revision"
```

### 7.2 Tích hợp vào escalation.py

Thêm escalation triggers mới (bổ sung existing 6 rules):

| Rule # | Condition | từ SV item | Reviewer |
|---|---|---|---|
| 7 | Scanner-only finding | SV-002, SV-007 | technical_reviewer |
| 8 | Evidence contradicts claim | SV-003 | senior_pentester |
| 9 | Severity-CVSS mismatch no override | SV-006 | report_reviewer |
| 10 | High/critical + asset unidentified | SV-001 | senior_pentester |
| 11 | FP probability HIGH | SV-007 | technical_reviewer |
| 12 | Sensitive data in finding | SV-002 | data_governance |

### 7.3 Data Request Object

Khi overall_action = `request_data`, output chứa:

```json
{
  "data_requests": [
    {
      "field": "evidence",
      "reason": "No evidence provided for this finding",
      "urgency": "high",
      "requested_from": "pentester",
      "suggested_format": "reproduction_steps or manual_verification_notes"
    }
  ]
}
```

### 7.4 Pending Object

Khi overall_action = `pending`:

```json
{
  "pending": {
    "reason": "Moderate FP risk — awaiting additional verification",
    "resume_condition": "manual_verification_provided OR retest_completed",
    "resume_events": ["data_response_received", "retest_completed", "manual_verification_added"]
  }
}
```

---

## 8. Relationship to Escalation Rules (trang 8)

Bảng escalation triggers từ kế hoạch tuần 12 (trang 8) map đến checklist items:

| Escalation trigger (trang 8) | SV item | Implemented? |
|---|---|---|
| Evidence không đủ | SV-002, SV-003 | ✅ SV-002 (no evidence) + SV-003 (insufficient) |
| Model và rule engine bất đồng | SV-006, SV-008 | ✅ SV-006 (severity mismatch) + SV-008 (unsupported claims) |
| Severity High/Critical nhưng confidence thấp | SV-006, SV-007 | ✅ SV-006 (severity legitimacy) + SV-007 (FP prob) |
| Có dữ liệu nhạy cảm | SV-002 | ✅ Bypass trigger trong §6 |
| Câu hỏi nằm ngoài report | N/A | ✅ Đã có trong escalation policy |
| Nhiều inference cho verdict không ổn định | N/A | ✅ Bypass trigger trong §6 |

---

## 9. Limitations & Future Work

1. **Re-check loop không implement trong v1.0:** Spec định nghĩa response action `recheck` nhưng implementation v1.0 chỉ **flag** recheck items. Loop thực tế (gọi lại SLM với prompt mới) cần SLM integration (step 6-7) — planned week 13.

2. **Request data flow chưa có backend:** `request_data` action tạo data_request object nhưng chưa có API endpoint để gửi request đến pentester. Per plan, đây là v1.0 spec — integration với workflow engine deferred.

3. **FP probability scoring heuristic:** SV-007 FP scoring dựa trên keyword matching. Khi SLM integration hoàn thành, FP probability nên được SLM output trực tiếp.

4. **Single engagement test:** Chỉ test trên 5 findings từ DOC-000001. Checklist logic có thể cần adjust khi có thêm engagements.