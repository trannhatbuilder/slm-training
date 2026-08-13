# System Responsibility — EVVO SLM / Harness

**Version:** 1.0
**Date:** 2026-08-05
**Purpose:** Define clear boundaries between what the SLM/Harness decides autonomously and what requires human review or decision.

---

## 1. Decision Authority Matrix

### SLM Decides Autonomously (No Human Required)

| Decision | Condition | Confidence Threshold |
|---|---|---|
| Flag missing sections | Finding lacks Observation, Exploitation, or Recommendation | N/A — deterministic check |
| Detect CVSS-severity mismatch | Reported severity does not match CVSS score range | N/A — deterministic check |
| Flag missing retest status | Retest field is empty | N/A — deterministic check |
| Classify as Potential Issue | Exploitation not demonstrated AND evidence insufficient | confidence >= 0.5 |
| Flag generic recommendation | Recommendation uses template language or does not address root cause | confidence >= 0.5 |
| Compute confidence score | Based on evidence completeness, classification certainty, consistency | N/A — formula-based |
| Generate structured review comments | Based on taxonomy codes (COMP, EVID, SEV, etc.) | confidence >= 0.5 |
| Refuse unsupported question | Question cannot be answered from report/knowledge base | confidence >= 0.7 |
| Answer client question | Question answerable from report content with source references | confidence >= 0.7 |

### SLM Proposes — Human Confirms (Escalation Required)

| Decision | Condition | Reason |
|---|---|---|
| Classification as Confirmed Vulnerability | Evidence supports claim but severity is High/Critical | High-impact decision requires human gate in v1 |
| Severity change suggestion | CVSS implies different severity than reported | SLM suggests but does not override reported severity |
| Classification override | Model and rule engine disagree | Uncertainty requires human judgment |
| Remediation adequacy assessment | Recommendation seems insufficient for the vulnerability | SLM flags; human writes better remediation |
| Impact assessment correction | Impact description does not match evidence | SLM flags; human provides correct impact text |

### Human Decides Only (SLM Must Not Decide)

| Decision | Reason |
|---|---|
| Final severity assignment | Severity is a business decision; SLM provides data, human decides |
| Retest status and result | Requires actual retesting by a qualified tester |
| False positive confirmation | Requires reproduction attempt and expert judgment |
| Client communication approval | Client-facing output must be reviewed before delivery |
| Engagement scope decisions | Out of SLM scope |
| Report sign-off | Legal and professional responsibility |

---

## 2. Escalation Rules

### Automatic Escalation (Always Escalate)

| Trigger | Escalation Target | Priority |
|---|---|---|
| Evidence insufficient for classification | Human reviewer | High |
| Severity High/Critical but confidence < 0.7 | Human reviewer | Critical |
| Model and rule engine disagree | Human reviewer | High |
| Sensitive data detected in finding | Data protection officer | Critical |
| Question outside report scope | Client engagement lead | Medium |

### Conditional Escalation (Escalate If Threshold Not Met)

| Trigger | Threshold | Escalation Target |
|---|---|---|
| Overall confidence score | < 0.7 | Human reviewer |
| Evidence completeness | < 0.5 | Human reviewer (regardless of total score) |
| Classification certainty | < 0.6 | Human reviewer |
| Multiple inconsistent inferences | > 2 different verdicts across runs | Human reviewer |

---

## 3. SLM Output Guarantees

### The SLM MUST

- Always provide source references for claims (document_id, section, finding_id)
- Always include a confidence score with every output
- Always flag when evidence is insufficient rather than guessing
- Always preserve reported values (never silently modify severity, CVSS, or retest status)
- Always include taxonomy codes in review comments
- Always escalate High/Critical findings with low confidence

### The SLM MUST NOT

- Hallucinate evidence that is not in the report
- Upgrade classification from Potential Issue to Confirmed Vulnerability without sufficient evidence
- Downgrade severity without human approval
- Generate client-facing text without human review
- Answer questions using knowledge outside the report and knowledge base
- Auto-fill retest status or verification results
- Include real credentials or PII in any output

---

## 4. Harness Workflow Authority

### Harness Orchestrates (Pipeline Control)

| Step | Authority | Can Skip? |
|---|---|---|
| Document ingestion and parsing | Harness | No |
| Finding normalization | Harness | No |
| Knowledge base retrieval | Harness | No |
| SLM inference call | Harness | No |
| Self-validation checks | Harness | No |
| Confidence scoring | Harness | No |
| Escalation routing | Harness | No |
| Trace ID assignment | Harness | No |

### Harness Defers (Cannot Decide)

| Step | Defers To | Reason |
|---|---|---|
| Human escalation handling | Human reviewer | Requires judgment |
| Final report assembly | Human reviewer | Client-facing output |
| Training data creation | Data pipeline (separate) | Different lifecycle |

---

## 5. Version 1 Limitations

These limitations are accepted for the August 2026 v1 delivery:

- SLM handles single-finding review only (not full report review in one call)
- No conversation memory across multiple reviews
- No multi-tenant isolation
- No authentication/authorization in v1
- No autonomous scanning (Nmap/ZAP/Nuclei integration is v2+)
- Confidence scoring is formula-based, not learned
- RAG retrieval is top-k with fixed threshold, not adaptive
- Human escalation is synchronous notification, not async workflow