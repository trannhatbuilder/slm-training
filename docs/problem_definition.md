# Problem Definition

## 1. Project Name

EVVO SLM and Harness for VAPT Finding Review

## 2. Project Context

This is a new internal project. There is no existing source code or production Harness.

The project uses company-provided VAPT reports and findings to prepare datasets and fine-tune a Small Language Model (SLM).

Company-provided documents are permitted for internal SLM training on Google Colab. The company document provider is responsible for removing important or restricted information before providing the documents for training.

The system developed in August 2026 will be reviewed internally by the company. It is not intended for direct commercial use or autonomous customer interaction during this phase.

## 3. August 2026 Outcome

By 31 August 2026, the project must deliver an SLM and Harness v1 that can:

1. Receive a VAPT finding as input.
2. Validate the finding structure.
3. Review the quality and completeness of the finding.
4. Evaluate whether the supplied evidence supports the reported conclusion.
5. Check consistency between evidence, impact, severity, CVSS, CWE, and recommendation.
6. Produce structured review comments.
7. Identify unsupported claims and missing evidence.
8. Answer report-related questions using available report evidence.
9. Escalate uncertain or high-risk decisions to a human reviewer.
10. Avoid inventing information that is not present in the input or approved knowledge base.

The final decision to approve a finding remains with the company's human reviewer.

## 4. Primary Users

### 4.1 Intern

The intern prepares the dataset, operates the development pipeline, runs experiments, and demonstrates the system.

### 4.2 Internal Company Reviewer

The company reviewer evaluates the SLM and Harness outputs and makes the final decision about finding quality and approval.

### 4.3 Client

The client is not a direct system user during the August 2026 phase.

Direct client interaction is outside the current scope.

## 5. Primary Use Case

The first use case operates on one VAPT finding at a time.

The system receives the content of a finding and returns a structured review result.

A finding may originate from different customers, report templates, assessment types, or document sections. Therefore, the system must not depend on:

- A fixed customer name.
- A fixed report filename.
- A fixed section number.
- A fixed section title.
- A specific vulnerability category.
- A specific application type.
- A single report template.

## 6. Supported Assessment Domains

The initial design must support findings from domains including:

- Web applications.
- APIs.
- Android applications.
- iOS applications.
- Networks.
- Cloud environments.
- Identity systems.
- Cryptography.
- Configuration reviews.
- Business logic assessments.

The first available company report contains web, mobile, and cryptography-related findings. However, the schemas and workflow must remain general.

## 7. Input

The initial input is one normalized VAPT finding.

The input may contain:

- Finding title.
- Reported severity.
- Affected target or component.
- Affected user roles.
- CWE identifier.
- CVSS version, score, and vector.
- Impact.
- Observation.
- Evidence.
- Reproduction or exploitation information.
- Recommendation.
- Retest information.
- Source traceability.
- Data-governance metadata.

A missing field must be represented explicitly using `null`, an empty list, or an appropriate validation issue.

The system must not invent missing values.

## 8. Review Tasks

The system must support the following review tasks:

1. Completeness review.
2. Evidence-sufficiency review.
3. Unsupported-claim detection.
4. Vulnerability-classification review.
5. Severity review.
6. CVSS consistency review.
7. CWE relevance review.
8. Impact review.
9. Observation and description review.
10. Reproduction review.
11. Recommendation review.
12. Internal-consistency review.
13. Retest review.
14. Writing-quality review.
15. Data-governance checks.

## 9. Output

The output must be structured and machine-readable.

The result must include:

- Review status.
- Vulnerability classification.
- Completeness results.
- Evidence-review results.
- Severity review.
- CVSS review.
- CWE review.
- Impact review.
- Recommendation review.
- Consistency issues.
- Retest review.
- Structured review comments.
- Confidence information when a validated confidence method is available.
- Human-escalation decision.
- Source and version traceability.

The initial review statuses are:

- `pass`
- `needs_revision`
- `human_review`

The initial classification labels are:

- `confirmed_vulnerability`
- `potential_issue`
- `informational`
- `false_positive`
- `undetermined`

## 10. Non-Goals for August 2026

The August version will not:

- Automatically discover vulnerabilities in a live target.
- Automatically scan customer systems.
- Automatically exploit targets.
- Replace the company's human reviewer.
- Automatically approve High or Critical findings.
- Provide production access directly to clients.
- Implement production multi-tenancy.
- Implement a commercial service.
- Publish company reports or training data publicly.
- Treat scanner output alone as proof of a confirmed vulnerability.
- Generate confidence scores without an evaluated scoring method.

## 11. System Components

### 11.1 Fine-Tuned SLM

Fine-tuning teaches the model how to review findings, detect quality issues, follow the required output structure, and avoid unsupported conclusions.

Fine-tuning is not used to memorize individual customer reports.

### 11.2 EVVO Knowledge Base and RAG

The knowledge base stores current review rules, SOPs, severity guidance, validation requirements, writing guidance, remediation guidance, schemas, and taxonomy definitions.

RAG provides only the relevant rules for the current review task.

### 11.3 Rule-Based Validation

Deterministic rules handle checks such as:

- Required fields.
- Data types.
- Enum validation.
- JSON Schema validation.
- CVSS calculation and mapping.
- CWE identifier format.
- Placeholder detection.
- Simple cross-field consistency.
- Data-governance status.

### 11.4 Harness

The Harness controls the workflow:

1. Receive a finding.
2. Check data-usage status.
3. Validate the input schema.
4. Run deterministic checks.
5. Retrieve relevant EVVO rules.
6. Build a compact prompt.
7. Call the SLM.
8. Validate the SLM output.
9. Run consistency and evidence checks.
10. Determine human escalation.
11. Record traceability.
12. Return the structured review result.

### 11.5 Human Reviewer

The human reviewer retains final authority for:

- Finding approval.
- Severity changes.
- Disputed CVSS metrics.
- High and Critical findings.
- False-positive confirmation.
- Business-impact approval.
- Retest approval.
- Dataset gold labels.
- Release approval.

## 12. Core Safety and Quality Principles

1. Do not guess missing context.
2. Do not invent evidence.
3. Do not treat unknown as false.
4. Use `null` when a check has not been performed or information is unavailable.
5. Use `undetermined` when classification is not possible.
6. Preserve original reported values.
7. Store normalized values separately from original values.
8. Keep source traceability.
9. Do not mix data between customers.
10. Prevent train-test leakage.
11. Do not use unreviewed AI-generated content as training truth.
12. Escalate uncertain decisions to a human reviewer.

## 13. Initial Data Source

The first registered source document is:

- Document ID: `DOC-000001`
- Source type: Company-provided VAPT report
- Number of registered findings: 5
- Intended usage: Internal dataset preparation, SLM training, validation, testing, and demonstration
- Training environment: Google Colab
- Current processing stage: Registered, pending extraction and normalization

The source document and its findings must not be hardcoded into the system design. They are the first development dataset, not the only supported report format.

## 14. Initial End-to-End Demonstration

The first working demonstration should show:

1. Loading one normalized finding.
2. Validating its structure.
3. Detecting missing or inconsistent information.
4. Reviewing whether evidence supports the finding.
5. Producing structured JSON comments.
6. Returning `human_review` when the available evidence is insufficient.
7. Preserving source traceability.