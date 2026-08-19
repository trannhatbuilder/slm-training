#!/usr/bin/env python3
"""
Build hard negatives v1.1 for benchmark expansion (18/08 task).

4 types, 9 new cases:
  A) Scanner-only: FND-000001 (high-severity trap) -> BMC-FP-0004
  B) Unrelated evidence: 3 swaps -> BMC-EV-0006..0008
  C) Wrong severity: 3 mismatches -> BMC-SV-0006..0008
  D) Unsupported question: 2 adversarial QA -> BMC-QA-0008..0009

Usage:
    python scripts/build_hard_negatives_v11.py
    # Outputs: data/benchmark/hard_negatives_v11.jsonl
"""
import json, hashlib, copy

# ============================================================
# Load normalized findings (ground truth source)
# ============================================================
with open('data/normalized/DOC-000001-findings-normalized.json') as f:
    all_findings = json.load(f)['findings']

findings = {f['finding_id']: f for f in all_findings}

def content_hash(obj):
    """Deterministic hash for dedup / content tracking."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]

# ============================================================
# TYPE A: Scanner-only hard negative for FND-000001
# ============================================================
# FND-000001 is critical (CVSS 9.8) with verified exploitation.
# Converting to scanner-only tests if SLM can resist the
# severity bias and recognize the scanner-only marker.

def build_scanner_only_fnd001():
    src = findings['FND-000001']
    inp = {
        "finding_id": "FND-000001-SCANNER",
        "title": "[Scanner] Hardcoded Credentials in Mobile Application",
        "severity": "critical",
        "cwe_id": "CWE-798",
        "cvss": src["cvss"],
        "affected_targets": src["affected_targets"],
        "observation": "Automated scanner flagged hardcoded credentials in the Android APK. Scanner reported critical-severity finding based on pattern matching against known credential formats.",
        "evidence": [{
            "evidence_id": "FND-000001-EVID-SCANNER",
            "evidence_type": "scanner_output",
            "content": "Scanner reported: 'Hardcoded credentials detected in strings output. Pattern matched: rabbitmq connection string with embedded username/password.' No manual verification of credential validity or broker access was performed."
        }],
        "recommendation": src["recommendation"][:2],
        "impact": src["impact"],
        "retest": {"applicable": None, "status": None, "verification_result": None, "evidence": []}
    }
    return {
        "case_id": "BMC-FP-0004",
        "task_type": "false_positive_detection",
        "instruction": "Classify this finding. Determine whether it is a confirmed vulnerability or a false positive (scanner-only, no manual verification).",
        "input": inp,
        "gold_output": {
            "classification": {
                "label": "false_positive",
                "rationale": "Finding is scanner-only; no manual verification evidence. Despite critical severity, evidence_type is scanner_output with explicit 'no manual verification performed'.",
                "supported_by_evidence": False
            },
            "confidence": {
                "overall_score": 0.75,
                "level": "medium",
                "basis": ["scanner_only_check", "no_manual_verification_check"],
                "limitations": ["Rule-based; needs human confirmation."]
            }
        },
        "expected_failure_modes": [
            "wrong_classification_label_confirmed",
            "missed_scanner_only_marker",
            "hallucinated_exploitation"
        ],
        "metadata": {
            "finding_id": "FND-000001-SCANNER",
            "document_id": "DOC-000001",
            "engagement_id": "DOC-000001",
            "label_source": "manual",
            "difficulty": "hard",
            "is_hard_negative": True,
            "schema": "classification_subset",
            "base_finding_id": "FND-000001",
            "marker": "scanner-only",
            "hard_negative_type": "scanner_only_high_severity_trap",
            "content_hash": content_hash(inp)
        }
    }

# ============================================================
# TYPE B: Unrelated evidence (evidence swap)
# ============================================================
# The finding body stays the same, but evidence is swapped
# from a different finding. SLM must detect that evidence
# does not support the vulnerability claim.

def build_unrelated_evidence(finding_id, wrong_evid_finding_id, case_num):
    """
    finding_id: the finding whose title/observation/impact we keep
    wrong_evid_finding_id: the finding whose evidence we inject (mismatch!)
    """
    src = findings[finding_id]
    wrong_evid = findings[wrong_evid_finding_id]['evidence'][0]
    
    # Build mismatched evidence with new ID
    mismatched_evid = copy.deepcopy(wrong_evid)
    mismatched_evid['evidence_id'] = f"{finding_id}-EVID-MISMATCH-{case_num}"
    
    inp = {
        "finding_id": finding_id,
        "title": src["title"],
        "severity": src["severity"],
        "observation": src["observation"],
        "evidence": [mismatched_evid],
        "impact": src["impact"],
        "recommendation": src["recommendation"]
    }
    
    # Describe the mismatch for gold output
    src_topic = src["title"].split(")")[0].strip() if ")" in src["title"] else src["title"]
    wrong_topic = findings[wrong_evid_finding_id]["title"].split(")")[0].strip() if ")" in findings[wrong_evid_finding_id]["title"] else findings[wrong_evid_finding_id]["title"]
    
    return {
        "case_id": f"BMC-EV-{5+case_num:04d}",
        "task_type": "evidence_check",
        "instruction": "Evaluate whether the exploitation evidence sufficiently supports the vulnerability claim. List unsupported claims and missing evidence.",
        "input": inp,
        "gold_output": {
            "evidence_review": {
                "is_sufficient": False,
                "evidence_items_reviewed": [mismatched_evid['evidence_id']],
                "supported_claims": [],
                "unsupported_claims": [
                    f"Evidence describes {wrong_topic} but finding is about {src_topic}",
                    "Evidence does not demonstrate exploitation of the reported vulnerability"
                ],
                "missing_evidence": [
                    "No evidence demonstrating exploitation or reproduction of the reported vulnerability",
                    f"Expected evidence related to {src_topic} is absent"
                ],
                "comments": [
                    f"EVIDENCE MISMATCH: Injected evidence (from {wrong_evid_finding_id}) describes {wrong_topic}, not {src_topic} (this finding's actual topic).",
                    "The evidence is factually valid for a different finding but does not support any claim in this finding."
                ]
            },
            "review_comments": [
                {"field": "evidence", "comment": f"Evidence content describes {wrong_topic}, not {src_topic}. Does not support the vulnerability claim.", "severity": "critical"}
            ],
            "confidence": {
                "overall_score": 0.9,
                "level": "high",
                "basis": ["evidence_topic_mismatch_check"],
                "limitations": ["Requires the SLM to recognize the evidence topic differs from the finding topic."]
            }
        },
        "expected_failure_modes": [
            "wrong_evidence_sufficiency",
            "hallucinated_evidence",
            "missed_unsupported_claim"
        ],
        "metadata": {
            "finding_id": finding_id,
            "document_id": "DOC-000001",
            "engagement_id": "DOC-000001",
            "label_source": "manual",
            "difficulty": "hard",
            "is_hard_negative": True,
            "schema": "evidence_review_subset",
            "base_finding_id": finding_id,
            "swapped_evidence_from": wrong_evid_finding_id,
            "hard_negative_type": "unrelated_evidence",
            "content_hash": content_hash(inp)
        }
    }

# ============================================================
# TYPE C: Wrong severity (severity contradicts CVSS)
# ============================================================
# The finding keeps its CVSS score but the reported severity
# is swapped to contradict the CVSS band. SLM must detect.

def build_wrong_severity(finding_id, wrong_severity, case_num):
    src = findings[finding_id]
    cvss_score = src['cvss']['score']
    
    # Determine correct CVSS band
    if cvss_score >= 9.0:
        correct_severity = "critical"
    elif cvss_score >= 7.0:
        correct_severity = "high"
    elif cvss_score >= 4.0:
        correct_severity = "medium"
    elif cvss_score >= 0.1:
        correct_severity = "low"
    else:
        correct_severity = "informational"
    
    inp = {
        "finding_id": finding_id,
        "title": src["title"],
        "severity": wrong_severity,
        "cwe_id": src["cwe_id"],
        "cvss": src["cvss"],
        "observation": src["observation"],
        "evidence": src["evidence"],
        "impact": src["impact"],
        "recommendation": src["recommendation"]
    }
    
    return {
        "case_id": f"BMC-SV-{5+case_num:04d}",
        "task_type": "severity_review",
        "instruction": "Review the severity assessment. Check if the reported severity matches the CVSS score and vector. Suggest correction if inconsistent.",
        "input": inp,
        "gold_output": {
            "severity_review": {
                "reported_severity": wrong_severity,
                "suggested_severity": correct_severity,
                "is_consistent": False,
                "change_recommended": True,
                "rationale": f"CVSS {cvss_score} implies '{correct_severity}' per CVSS v3.1 rating bands. Reported '{wrong_severity}' does not match."
            },
            "cvss_review": {
                "reported_version": src['cvss']['version'],
                "reported_score": cvss_score,
                "reported_vector": src['cvss']['vector'],
                "vector_is_valid": True,
                "score_matches_vector": True,
                "severity_matches_score": False,
                "requires_manual_recalculation": False,
                "comments": [
                    f"SEVERITY MISMATCH: Reported '{wrong_severity}' but CVSS {cvss_score} falls in '{correct_severity}' band (CVSS v3.1)."
                ]
            },
            "confidence": {
                "overall_score": 0.95,
                "level": "high",
                "basis": ["cvss_v3.1_band_check"],
                "limitations": ["Does not assess impact proportionality."]
            }
        },
        "expected_failure_modes": [
            "missed_severity_cvss_mismatch",
            "wrong_severity_suggestion"
        ],
        "metadata": {
            "finding_id": finding_id,
            "document_id": "DOC-000001",
            "engagement_id": "DOC-000001",
            "label_source": "manual",
            "difficulty": "medium",
            "is_hard_negative": True,
            "schema": "severity_cvss_subset",
            "base_finding_id": finding_id,
            "wrong_severity": wrong_severity,
            "correct_severity": correct_severity,
            "hard_negative_type": "wrong_severity",
            "content_hash": content_hash(inp)
        }
    }

# ============================================================
# TYPE D: Unsupported question (adversarial QA)
# ============================================================

def build_unsupported_question(finding_id, question, refusal_reason, case_num):
    src = findings[finding_id]
    inp = {
        "finding": {
            "finding_id": finding_id,
            "title": src["title"],
            "severity": src["severity"],
            "cwe_id": src["cwe_id"],
            "cvss": src["cvss"],
            "affected_targets": src["affected_targets"],
            "observation": src["observation"],
            "evidence": src["evidence"],
            "recommendation": src["recommendation"],
            "impact": src["impact"],
            "retest": src["retest"]
        },
        "question": question
    }
    return {
        "case_id": f"BMC-QA-{7+case_num:04d}",
        "task_type": "client_qa",
        "instruction": "Answer the client question using ONLY information present in the finding. If the answer cannot be derived from the finding, refuse and explain what is missing.",
        "input": inp,
        "gold_output": {
            "answer": None,
            "refuses": True,
            "source_references": [],
            "confidence": {
                "overall_score": 0.9,
                "level": "high",
                "basis": ["report_scope_check"],
                "limitations": []
            }
        },
        "gold_output_override_note": f"Refusal case: refuses=True, answer=None, source_references=[]",
        "expected_failure_modes": ["hallucinated_answer", "failed_to_refuse"],
        "metadata": {
            "finding_id": finding_id,
            "document_id": "DOC-000001",
            "engagement_id": "DOC-000001",
            "label_source": "manual",
            "difficulty": "hard",
            "is_hard_negative": True,
            "schema": "client_qa_custom",
            "refusal_reason": refusal_reason,
            "hard_negative_type": "unsupported_question",
            "content_hash": content_hash(inp)
        }
    }

# ============================================================
# BUILD ALL 9 CASES
# ============================================================
new_cases = []

# A: Scanner-only (1 case)
new_cases.append(build_scanner_only_fnd001())

# B: Unrelated evidence (3 cases)
new_cases.append(build_unrelated_evidence('FND-000001', 'FND-000005', 1))  # RabbitMQ finding + Email enum evidence
new_cases.append(build_unrelated_evidence('FND-000002', 'FND-000004', 2))  # JWT finding + SSL pinning evidence
new_cases.append(build_unrelated_evidence('FND-000003', 'FND-000001', 3))  # Root detection finding + RabbitMQ evidence

# C: Wrong severity (3 cases)
new_cases.append(build_wrong_severity('FND-000001', 'low', 1))       # CVSS 9.8 but says "low"
new_cases.append(build_wrong_severity('FND-000003', 'critical', 2))   # CVSS 6.5 but says "critical"
new_cases.append(build_wrong_severity('FND-000005', 'high', 3))       # CVSS 5.3 but says "high"

# D: Unsupported question (2 cases)
new_cases.append(build_unsupported_question(
    'FND-000003',
    'What is the recommended root detection library that the client should use?',
    'The finding lists root detection approaches but does not recommend a specific commercial library or product.',
    1
))
new_cases.append(build_unsupported_question(
    'FND-000004',
    'What is the exact version of Frida used during the assessment?',
    'The finding mentions Frida as an example of a runtime instrumentation framework but does not specify the version used.',
    2
))

# ============================================================
# VALIDATE
# ============================================================
assert len(new_cases) == 9, f"Expected 9 cases, got {len(new_cases)}"

# Check no duplicate case_ids
case_ids = [c['case_id'] for c in new_cases]
assert len(case_ids) == len(set(case_ids)), "Duplicate case IDs!"

# Verify types
type_counts = {}
for c in new_cases:
    hn_type = c['metadata']['hard_negative_type']
    type_counts[hn_type] = type_counts.get(hn_type, 0) + 1
    assert c['metadata']['is_hard_negative']

print("=== Hard Negative v1.1 Summary ===")
print(f"Total new cases: {len(new_cases)}")
for t, n in sorted(type_counts.items()):
    print(f"  {t}: {n}")
print()
print("Case IDs:")
for c in new_cases:
    print(f"  {c['case_id']:12s} | {c['metadata']['hard_negative_type']:40s} | {c['task_type']}")

# ============================================================
# WRITE OUTPUT
# ============================================================
out_path = 'data/benchmark/hard_negatives_v11.jsonl'
with open(out_path, 'w', encoding='utf-8') as f:
    for c in new_cases:
        f.write(json.dumps(c, ensure_ascii=False) + '\n')

print(f"\nWritten to: {out_path}")