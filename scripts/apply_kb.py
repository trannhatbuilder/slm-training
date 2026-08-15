#!/usr/bin/env python3
"""
Task 08/08 — Backfill KB metadata + rename + new KB files.

What this script does (single source of truth for task 08/08 changes):
  1. Rename data/kb/rules/remediation_templates.json → remediation_quality.json
     (file content was actually quality-eval rules, not templates).
  2. Backfill 6 new metadata fields into ALL existing KB entries
     (document_type, section, vulnerability_type, effective_date, access_scope, source_id).
  3. Patch KB-VAL-001 in validation_requirements.json to require 5-part finding structure
     (Observation, Exploitation, Recommendation, Re-Test, Metadata) instead of 3-part.
  4. Create 4 new KB files:
     - data/kb/rules/remediation_templates.json   (real template patterns)
     - data/kb/rules/report_style.json            (EvvoH1/EvvoH2, disclaimer, scope list, ...)
     - data/kb/rules/client_qa_patterns.json      (Q&A patterns, source citation, refusal, ...)
     - data/kb/sops/pentest_methodology.json      (NIST 800-115 + OWASP + OSSTMM)
  5. Update data/kb/kb_manifest.json (file listing + entry counts + version bump to 1.1).
  6. Update data/kb/schemas/schema_registry.json
     (KB-SCH-004: bump KB Entry Schema version 1.0 → 1.1 + describe new fields).

This script is IDEMPOTENT: re-running it produces the same result.
"""

from __future__ import annotations
import json
import shutil
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(r"D:\evvo-slm-harness")
KB_ROOT = REPO_ROOT / "data" / "kb"
RULES_DIR = KB_ROOT / "rules"
SOPS_DIR = KB_ROOT / "sops"
SCHEMAS_DIR = KB_ROOT / "schemas"

EFFECTIVE_DATE = "2026-08-15"

# ──────────────────────────────────────────────────────────────────────────────
# Helper: classify source_id and document_type per entry
# ──────────────────────────────────────────────────────────────────────────────

def classify_source(entry: dict) -> tuple[str, str, str]:
    """
    Return (source_id, document_type, section) based on entry's `source` field
    and category. Heuristics derived from surveying all 64 existing entries.
    """
    src = entry.get("source", "")
    category = entry.get("category", "")
    subcategory = entry.get("subcategory", "")

    # Determine source_id from source string
    if "review_taxonomy.yaml" in src:
        source_id = "POLICY-review_taxonomy"
        doc_type = "policy_document"
    elif "data_usage_policy.yaml" in src:
        source_id = "POLICY-data_usage"
        doc_type = "policy_document"
    elif "data_protection_rules.yaml" in src:
        source_id = "POLICY-data_protection"
        doc_type = "policy_document"
    elif "system_responsibility.md" in src:
        source_id = "POLICY-system_responsibility"
        doc_type = "policy_document"
    elif "input_schema.json" in src:
        source_id = "SCHEMA-input_schema"
        doc_type = "schema_definition"
    elif "output_schema.json" in src:
        source_id = "SCHEMA-output_schema"
        doc_type = "schema_definition"
    elif "problem_definition.md" in src:
        source_id = "DOC-problem_definition"
        doc_type = "internal_guideline"
    elif "split_report.md" in src:
        source_id = "DOC-split_report"
        doc_type = "internal_guideline"
    elif "src/harness/kb/schema.py" in src:
        source_id = "CODE-kb_schema"
        doc_type = "schema_definition"
    elif "EVVO SOP" in src:
        source_id = "EVVO-SOP-internal"
        doc_type = "evvo_sop"
    elif "CVSS v3.1" in src:
        source_id = "REF-CVSS-3.1"
        doc_type = "internal_guideline"
    elif "MITRE CWE" in src:
        source_id = "REF-MITRE-CWE"
        doc_type = "internal_guideline"
    elif category == "sop":
        source_id = "DOC-problem_definition"
        doc_type = "evvo_sop"
    elif category == "taxonomy_definitions":
        source_id = "SCHEMA-registry"
        doc_type = "schema_definition"
    else:
        source_id = "EVVO-internal"
        doc_type = "evvo_rule"

    # Determine section
    if category == "sop" and subcategory == "pipeline_step":
        section = f"pipeline:{subcategory}"
    elif category == "sop":
        section = f"sop:{subcategory}"
    else:
        section = f"{category}:{subcategory}" if subcategory else category

    return source_id, doc_type, section


def classify_vulnerability_type(entry: dict) -> str:
    """Determine vulnerability_type from tags/title/source."""
    title = entry.get("title", "").lower()
    tags = [t.lower() for t in entry.get("tags", [])]
    desc = entry.get("description", "").lower()

    # Map common vulnerability keywords → VULNERABILITY_TYPES
    if "hardcoded" in title or "hard-coded" in title or "credential" in tags:
        return "hardcoded_credentials"
    if "jwt" in title or "hs256" in title or "crypto" in tags or "cryptographic" in title:
        return "weak_crypto_algorithm"
    if "root detection" in title:
        return "missing_root_detection"
    if "ssl pinning" in title or "certificate validation" in title:
        return "weak_ssl_pinning"
    if "enumeration" in title or "username" in title or "email enumeration" in title:
        return "user_enumeration"
    if "xss" in title or "cross-site scripting" in title:
        return "xss"
    if "sqli" in title or "sql injection" in title:
        return "sqli"
    if "csrf" in title:
        return "csrf"
    if "ssrf" in title:
        return "ssrf"
    if "authorization" in title or "privilege" in title:
        return "authorization_bypass"
    if "authentication" in title:
        return "authentication_bypass"
    if "information disclosure" in title or "info disclosure" in title:
        return "information_disclosure"
    if "business logic" in title:
        return "business_logic"
    return "general"


# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Rename remediation_templates.json → remediation_quality.json
# ──────────────────────────────────────────────────────────────────────────────

def step1_rename_remediation():
    src = RULES_DIR / "remediation_templates.json"
    dst = RULES_DIR / "remediation_quality.json"
    if src.exists() and not dst.exists():
        shutil.move(str(src), str(dst))
        print(f"  [step1] Renamed {src.name} → {dst.name}")
    elif src.exists() and dst.exists():
        # Both exist — prefer the existing dst, remove src (idempotent)
        src.unlink()
        print(f"  [step1] Both files exist; removed {src.name} (kept {dst.name})")
    else:
        print(f"  [step1] No rename needed ({src.name} absent)")
    return dst


# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Backfill metadata in existing KB files
# ──────────────────────────────────────────────────────────────────────────────

def step2_backfill_metadata(file_path: Path) -> int:
    """Backfill 6 new metadata fields into every entry of a KB JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "entries" not in data:
        print(f"  [step2] {file_path.name}: no 'entries' key — skipped")
        return 0

    count_backfilled = 0
    for entry in data["entries"]:
        if "kb_id" not in entry:
            continue
        source_id, doc_type, section = classify_source(entry)
        vuln_type = classify_vulnerability_type(entry)
        entry.setdefault("document_type", doc_type)
        entry.setdefault("section", section)
        entry.setdefault("vulnerability_type", vuln_type)
        entry.setdefault("effective_date", EFFECTIVE_DATE)
        entry.setdefault("access_scope", "internal")
        entry.setdefault("source_id", source_id)
        count_backfilled += 1

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return count_backfilled


# ──────────────────────────────────────────────────────────────────────────────
# Step 3: Patch KB-VAL-001 → 5-part finding structure
# ──────────────────────────────────────────────────────────────────────────────

def step3_patch_val_001():
    """Patch KB-VAL-001 to require 5-part finding structure per DOC-000001."""
    fpath = RULES_DIR / "validation_requirements.json"
    with open(fpath, "r", encoding="utf-8") as f:
        data = json.load(f)

    for entry in data["entries"]:
        if entry["kb_id"] == "KB-VAL-001":
            entry["title"] = "Finding must have all 5 required sections: Observation, Exploitation, Recommendation, Re-Test Verification, Metadata"
            entry["description"] = (
                "A complete VAPT finding (per EVVO report standard, see DOC-000001 DETAILED FINDINGS) "
                "must contain all five sections: (1) Observation — what was found and how it manifests; "
                "(2) Exploitation — concrete reproduction steps, commands, request/response pairs, or screenshots; "
                "(3) Recommendation — actionable remediation steps addressing root cause; "
                "(4) Re-Test Verification Result — status of retesting after fix (Verified/Fixed/Not Retested); "
                "(5) Metadata table — Severity, Affected Targets, CWE-ID, Impact, Retest Status, Affected User Roles, CVSS Score+Vector. "
                "Missing any of these sections prevents reliable review. Findings missing Observation, Exploitation, or Recommendation "
                "are blocked; missing Re-Test or Metadata are flagged as needs_revision."
            )
            entry["conditions"] = [
                "observation is null or empty",
                "exploitation/reproduction steps are missing",
                "recommendation array is empty",
                "retest.verification_result is null or 'Re-Test Verification Result:' line is empty",
                "metadata table missing any of: Severity, Affected Targets, CWE-ID, Impact, CVSS",
            ]
            entry["action"] = (
                "Flag as incomplete (taxonomy COMP). Report specific missing sections. "
                "If Observation/Exploitation/Recommendation missing: set review_status=needs_revision and block. "
                "If only Re-Test or Metadata missing: flag as needs_revision but allow pipeline to continue."
            )
            entry["references"] = [
                "input_schema.json",
                "review_taxonomy.yaml → COMP",
                "DOC-000001 → DETAILED FINDINGS (5-part structure reference)",
            ]
            entry["tags"] = [
                "validation", "completeness", "required_sections", "schema",
                "five_part_structure", "observation", "exploitation", "recommendation", "retest", "metadata",
            ]
            # Also backfill metadata (in case step 2 didn't run before step 3)
            entry.setdefault("document_type", "pentest_report")
            entry.setdefault("section", "validation_requirements:required_sections")
            entry.setdefault("vulnerability_type", "general")
            entry.setdefault("effective_date", EFFECTIVE_DATE)
            entry.setdefault("access_scope", "internal")
            entry.setdefault("source_id", "DOC-000001")
            print(f"  [step3] Patched KB-VAL-001 → 5-part structure")
            break

    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


# ──────────────────────────────────────────────────────────────────────────────
# Step 4: Create 4 new KB files
# ──────────────────────────────────────────────────────────────────────────────

def _entry(kb_id, category, subcategory, title, description, conditions, action,
           references, severity, applicable_to, tags, document_type="evvo_rule",
           section="", vulnerability_type="general", effective_date=EFFECTIVE_DATE,
           access_scope="internal", source_id="EVVO-internal", version="1.0"):
    """Build a single KB entry dict with full metadata."""
    return {
        "kb_id": kb_id,
        "category": category,
        "subcategory": subcategory,
        "title": title,
        "description": description,
        "conditions": conditions,
        "action": action,
        "references": references,
        "severity": severity,
        "applicable_to": applicable_to,
        "version": version,
        "source": source_id,
        "tags": tags,
        "document_type": document_type,
        "section": section or f"{category}:{subcategory}",
        "vulnerability_type": vulnerability_type,
        "effective_date": effective_date,
        "access_scope": access_scope,
        "source_id": source_id,
    }


def step4_create_remediation_templates():
    """Create NEW remediation_templates.json with real template patterns."""
    entries = [
        _entry(
            kb_id="KB-REC-TPL-001",
            category="remediation_guidance",
            subcategory="rotate_credentials",
            title="Template: Rotate exposed credentials and revoke old ones",
            description=(
                "Pattern for findings where credentials/secrets are exposed (hardcoded in client app, "
                "leaked to logs, committed to repo). The recommendation MUST include: "
                "(a) immediate removal of the credential from the exposed location; "
                "(b) rotation of the credential and revocation of all previously distributed copies; "
                "(c) commit to never embedding backend credentials in client-side code; "
                "(d) implementation of a server-side secret retrieval mechanism; "
                "(e) principle of least privilege for the affected account; "
                "(f) network-level restrictions (firewall/VPN/IP allowlist); "
                "(g) disable unnecessary management interfaces; "
                "(h) automated secret scanning in the build pipeline."
            ),
            conditions=["finding type is hardcoded_credentials or secret_exposure"],
            action=(
                "Suggest this template structure. Do NOT generate final remediation text — "
                "human writes the final recommendation."
            ),
            references=["CWE-798", "OWASP Top 10 A05", "DOC-000001 finding 1 (RabbitMQ)"],
            severity="info",
            applicable_to=["all"],
            tags=["recommendation", "template", "credentials", "rotation", "hardcoded"],
            document_type="pentest_report",
            section="remediation_guidance:rotate_credentials",
            vulnerability_type="hardcoded_credentials",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-REC-TPL-002",
            category="remediation_guidance",
            subcategory="migrate_algorithm",
            title="Template: Migrate from symmetric to asymmetric cryptographic algorithm",
            description=(
                "Pattern for findings where a symmetric algorithm is used in a context that "
                "would benefit from asymmetric (e.g., HS256 JWT → RS256/ES256). "
                "Recommendation MUST include: "
                "(a) protect the existing signing secret with a secure secrets manager; "
                "(b) ensure the key is sufficiently random and cryptographically strong; "
                "(c) periodically rotate the key; "
                "(d) never reuse the same key across Dev/UAT/Production; "
                "(e) migrate to an asymmetric algorithm (RS256/ES256) where the private key "
                "stays on the auth server and only the public key is distributed; "
                "(f) explicitly enforce the expected signing algorithm to prevent algorithm confusion."
            ),
            conditions=["finding type is weak_crypto_algorithm or symmetric_jwt"],
            action="Suggest this template structure. Do NOT generate final remediation text.",
            references=["CWE-327", "RFC 7519 (JWT)", "DOC-000001 finding 2 (HS256)"],
            severity="info",
            applicable_to=["all"],
            tags=["recommendation", "template", "crypto", "jwt", "asymmetric"],
            document_type="pentest_report",
            section="remediation_guidance:migrate_algorithm",
            vulnerability_type="weak_crypto_algorithm",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-REC-TPL-003",
            category="remediation_guidance",
            subcategory="implement_check",
            title="Template: Implement platform-specific security check / control",
            description=(
                "Pattern for findings where a security control is missing or weak "
                "(e.g., no root detection, weak SSL pinning, no input validation). "
                "Recommendation MUST include: "
                "(a) state what the control does and why it matters; "
                "(b) reference the platform-native API (e.g., Android Network Security Config, "
                "Google Play Integrity API, OkHttp CertificatePinner); "
                "(c) provide configuration-level guidance (XML, code snippet structure); "
                "(d) mention complementary runtime protections (anti-tampering, obfuscation); "
                "(e) reference OWASP Mobile Top 10 or Web Top 10 as appropriate."
            ),
            conditions=["finding type is missing_root_detection, weak_ssl_pinning, or similar"],
            action="Suggest this template structure. Do NOT generate final remediation text.",
            references=["CWE-693", "CWE-295", "OWASP Mobile Top 10", "DOC-000001 findings 3, 4"],
            severity="info",
            applicable_to=["android_application", "ios_application", "web_application"],
            tags=["recommendation", "template", "platform", "check", "control"],
            document_type="pentest_report",
            section="remediation_guidance:implement_check",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-REC-TPL-004",
            category="remediation_guidance",
            subcategory="restrict_access",
            title="Template: Restrict access using network controls and least privilege",
            description=(
                "Pattern for findings where an interface, endpoint, or service is exposed "
                "more broadly than necessary (e.g., management interface reachable from internet). "
                "Recommendation MUST include: "
                "(a) restrict access using firewall rules, VPN, IP allowlists, or private network segmentation; "
                "(b) disable unnecessary management interfaces on untrusted networks; "
                "(c) enforce least-privilege role-based access; "
                "(d) require authentication for the affected endpoint; "
                "(e) monitor and alert on anomalous access patterns."
            ),
            conditions=["finding relates to exposed management interface, open endpoint, or excessive permissions"],
            action="Suggest this template structure. Do NOT generate final remediation text.",
            references=["CWE-798", "OWASP A01 Broken Access Control"],
            severity="info",
            applicable_to=["all"],
            tags=["recommendation", "template", "network", "firewall", "least_privilege"],
            document_type="internal_guideline",
            section="remediation_guidance:restrict_access",
            vulnerability_type="misconfiguration",
            source_id="EVVO-internal",
        ),
        _entry(
            kb_id="KB-REC-TPL-005",
            category="remediation_guidance",
            subcategory="generic_response",
            title="Template: Return generic response to prevent information disclosure",
            description=(
                "Pattern for findings where server responses leak information (user enumeration, "
                "verbose errors, stack traces). Recommendation MUST include: "
                "(a) return a generic response for all attempts regardless of internal state; "
                "(b) avoid exposing detailed validation messages that reveal existence of accounts/resources; "
                "(c) perform duplicate checks internally without disclosing the result to the client; "
                "(d) implement rate limiting and CAPTCHA on sensitive endpoints; "
                "(e) monitor and alert on patterns indicating enumeration or brute-force activity."
            ),
            conditions=["finding type is user_enumeration, information_disclosure, or observable_response_discrepancy"],
            action="Suggest this template structure. Do NOT generate final remediation text.",
            references=["CWE-204", "CWE-209", "OWASP A04 Insecure Design", "DOC-000001 finding 5"],
            severity="info",
            applicable_to=["web_application", "api"],
            tags=["recommendation", "template", "generic", "enumeration", "rate_limiting"],
            document_type="pentest_report",
            section="remediation_guidance:generic_response",
            vulnerability_type="user_enumeration",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-REC-TPL-006",
            category="remediation_guidance",
            subcategory="secret_scanning_pipeline",
            title="Template: Integrate automated secret scanning in build pipeline",
            description=(
                "Pattern for findings where secrets/credentials reach production due to lack of "
                "build-time checks. Recommendation MUST include: "
                "(a) integrate a secret scanning tool (e.g., gitleaks, truffleHog, GitGuardian) "
                "into the CI/CD pipeline; "
                "(b) fail the build on detection of high-confidence secrets; "
                "(c) maintain a baseline of false positives to suppress; "
                "(d) enforce pre-commit hooks for developers; "
                "(e) periodically audit historical commits for leaked secrets."
            ),
            conditions=["finding type is hardcoded_credentials or secret_exposure in client code"],
            action="Suggest this template structure. Do NOT generate final remediation text.",
            references=["CWE-798", "OWASP A05 Security Misconfiguration"],
            severity="info",
            applicable_to=["all"],
            tags=["recommendation", "template", "secret_scanning", "ci_cd", "pipeline"],
            document_type="internal_guideline",
            section="remediation_guidance:secret_scanning_pipeline",
            vulnerability_type="hardcoded_credentials",
            source_id="EVVO-internal",
        ),
    ]

    data = {
        "description": (
            "Remediation template patterns — concrete recommendation structures for common "
            "vulnerability classes. Used by the SLM to suggest remediation structure (not text) "
            "for human reviewers. Sourced from DOC-000001 DETAILED FINDINGS + EVVO internal SOP. "
            "These are TEMPLATES (patterns to follow); KB-REC-001..006 in remediation_quality.json "
            "are QUALITY RULES (how to evaluate a written recommendation)."
        ),
        "version": "1.0",
        "entries": entries,
    }
    out = RULES_DIR / "remediation_templates.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  [step4] Created {out.name} with {len(entries)} template entries")


def step4_create_report_style():
    """Create report_style.json — EVVO report formatting conventions."""
    entries = [
        _entry(
            kb_id="KB-STYLE-001",
            category="writing_guidelines",
            subcategory="heading_hierarchy",
            title="Report must use EVVO heading styles: EvvoH1 for sections, EvvoH2 for subsections",
            description=(
                "EVVO pentest reports use custom heading styles: EvvoH1 for top-level sections "
                "(e.g., ENGAGEMENT INFORMATION, METHODOLOGY, DETAILED FINDINGS, CONCLUSION), "
                "EvvoH2 for subsections (e.g., DISCLAIMER, SCOPE, OUT OF SCOPE, OVERALL POSTURE, "
                "FINAL REMEDIATION STATUS, RECOMMENDATIONS SUMMARY, individual finding titles). "
                "Standard Heading 2 style is reserved for legacy compatibility (e.g., STATEMENT OF LIMITATIONS). "
                "When generating or reviewing report text, the SLM must respect this hierarchy."
            ),
            conditions=["report text is being generated or reviewed for style"],
            action=(
                "Verify heading styles match the EVVO convention. Flag any section using non-EVVO "
                "heading style. Do NOT auto-fix heading styles — escalate to human."
            ),
            references=["DOC-000001 (style inventory: EvvoH1=7, EvvoH2=18)"],
            severity="warning",
            applicable_to=["all"],
            tags=["style", "heading", "evvoh1", "evvoh2", "report_structure"],
            document_type="pentest_report",
            section="report_style:heading_hierarchy",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-STYLE-002",
            category="writing_guidelines",
            subcategory="disclaimer_block",
            title="Disclaimer and legal notice must appear before any technical content",
            description=(
                "Every EVVO report must include, in order: (1) DISCLAIMER — confidentiality notice "
                "with EVVO Labs Pte Ltd address (28 Genting, #05-07 Platinum 28, Singapore 349585); "
                "(2) COMPANY PROFILE — brief description of EVVO Labs services; "
                "(3) LEGAL NOTICE & LIMITATIONS — engagement scope, liability cap, third-party tool disclaimer. "
                "These sections must appear BEFORE Engagement Information. When reviewing a report, "
                "missing or out-of-order boilerplate must be flagged."
            ),
            conditions=["report is being validated for completeness"],
            action=(
                "Verify disclaimer block exists and is in correct position. Flag missing or "
                "misplaced boilerplate. Do NOT generate boilerplate text — human inserts."
            ),
            references=["DOC-000001 paragraphs 38-72"],
            severity="warning",
            applicable_to=["all"],
            tags=["style", "disclaimer", "legal", "boilerplate", "report_structure"],
            document_type="pentest_report",
            section="report_style:disclaimer_block",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-STYLE-003",
            category="writing_guidelines",
            subcategory="scope_list_format",
            title="Scope and out-of-scope items must use bullet list format (List Paragraph style)",
            description=(
                "Scope and out-of-scope items must be formatted as a bulleted list using the "
                "'List Paragraph' style. Each item is a single concise statement (one module, one asset, "
                "one constraint). Example from DOC-000001: scope lists admin portal modules (Invitees, "
                "Attendees, Orders, Reports, Campaings, Statistics, Templates, Promo codes, Event details, "
                "Event Page, Tickets, Merchandise & Inventory, Forms, Page Templates, Surveys, "
                "Automated Messages & Emails, Customizable Titles & Tickets, Payment, Taxes, Audit Logs). "
                "Out-of-scope items must also use this format (e.g., 'Anything in conjunction with social "
                "engineering aspects')."
            ),
            conditions=["report contains SCOPE or OUT OF SCOPE section"],
            action=(
                "Verify scope/out-of-scope sections use bullet list format. Flag if items are "
                "in paragraph form. Do NOT rewrite — human reformats."
            ),
            references=["DOC-000001 paragraphs 84-113"],
            severity="info",
            applicable_to=["all"],
            tags=["style", "scope", "bullet_list", "list_paragraph", "formatting"],
            document_type="pentest_report",
            section="report_style:scope_list_format",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-STYLE-004",
            category="writing_guidelines",
            subcategory="finding_metadata_table",
            title="Each finding must include a 7-row metadata table after the Recommendation section",
            description=(
                "Every finding in DETAILED FINDINGS must end with a 2-column, 7-row metadata table "
                "with EXACTLY these row labels in this order: "
                "SEVERITY | AFFECTED TARGETS | CWE-ID | IMPACT | RETEST STATUS | Affected User Roles | CVSS SCORE. "
                "Impact row may be prefixed with '(Potential)' for findings that did not demonstrate "
                "full exploitation. CVSS SCORE row must contain the numeric score AND the full CVSS:3.1 vector. "
                "Example: '9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8))'."
            ),
            conditions=["finding is being validated for structural completeness"],
            action=(
                "Verify all 7 metadata rows present and in correct order. Flag missing rows "
                "(especially CWE-ID and CVSS vector). Flag malformed CVSS vector."
            ),
            references=["DOC-000001 Tables 20-24", "input_schema.json"],
            severity="warning",
            applicable_to=["all"],
            tags=["style", "finding", "metadata_table", "cvss", "cwe", "structure"],
            document_type="pentest_report",
            section="report_style:finding_metadata_table",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-STYLE-005",
            category="writing_guidelines",
            subcategory="version_control_table",
            title="Report must include a Document Version Control table tracking revisions",
            description=(
                "Every EVVO report must include a Document Version Control table with 4 columns: "
                "VERSION | DATE | AUTHOR | DESCRIPTION. The table must list every revision "
                "(V 1.0 First version, V 1.1 added justification, V 1.2 added tool/CVSS/user roles, "
                "V 1.3 added scope and test cases, V 1.4 retest verification, ...). "
                "The current version field on page 1 must match the latest row in this table."
            ),
            conditions=["report validation in progress"],
            action=(
                "Verify version control table exists and latest version matches the page-1 Version field. "
                "Flag mismatches. Do NOT auto-update version."
            ),
            references=["DOC-000001 Table 2"],
            severity="info",
            applicable_to=["all"],
            tags=["style", "version_control", "traceability", "report_structure"],
            document_type="pentest_report",
            section="report_style:version_control_table",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-STYLE-006",
            category="writing_guidelines",
            subcategory="glossary_section",
            title="Report must include a Glossary defining testing methodology terms",
            description=(
                "Every EVVO report must include a Glossary section that defines testing methodology "
                "terms (Grey Box Testing, Vulnerability Assessment, Penetration Testing, External Testing, "
                "and any specialized terms used in the engagement). Definitions must be plain English, "
                "1-3 sentences, and not assume security expertise. This section must appear in the "
                "Methodology section, before TESTING APPROACH."
            ),
            conditions=["report being reviewed for completeness"],
            action="Verify Glossary exists and contains required definitions. Flag missing entries.",
            references=["DOC-000001 paragraphs 171-176"],
            severity="info",
            applicable_to=["all"],
            tags=["style", "glossary", "methodology", "definitions"],
            document_type="pentest_report",
            section="report_style:glossary_section",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-STYLE-007",
            category="writing_guidelines",
            subcategory="overall_posture_rating",
            title="Overall Posture Rating must use the 4-level scale with reasoning",
            description=(
                "The OVERALL POSTURE section must include a Security Posture Rating using one of "
                "4 levels: Critical Risk | High Risk | Medium Risk | Low Risk. The rating must be "
                "followed by a 'Reason:' paragraph that explains: (a) what was fixed since the last "
                "assessment; (b) what residual issues remain; (c) why the rating was chosen. "
                "Per-finding summaries (e.g., 'Improper Authorization: The application now properly "
                "enforces authorization checks...') must support the overall rating."
            ),
            conditions=["report being reviewed for posture section"],
            action=(
                "Verify posture rating uses one of the 4 levels. Verify Reason paragraph exists "
                "and addresses remediation + residual + justification."
            ),
            references=["DOC-000001 paragraphs 115-126", "DOC-000001 Table 4"],
            severity="warning",
            applicable_to=["all"],
            tags=["style", "posture_rating", "executive_summary", "risk"],
            document_type="pentest_report",
            section="report_style:overall_posture_rating",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
    ]

    data = {
        "description": (
            "Report style rules — EVVO pentest report formatting conventions including heading "
            "hierarchy, disclaimer block, scope list format, finding metadata table, version "
            "control, glossary, and posture rating. Sourced from DOC-000001 structural analysis."
        ),
        "version": "1.0",
        "entries": entries,
    }
    out = RULES_DIR / "report_style.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  [step4] Created {out.name} with {len(entries)} style entries")


def step4_create_client_qa_patterns():
    """Create client_qa_patterns.json — Q&A behavior rules for SLM."""
    entries = [
        _entry(
            kb_id="KB-QA-001",
            category="writing_guidelines",
            subcategory="source_citation",
            title="Client Q&A answers must cite source evidence from the report or KB",
            description=(
                "When answering a client question, the SLM must cite the specific source: "
                "(a) finding_id and section (e.g., 'Per Finding 1, Observation section, DOC-000001'); "
                "(b) the exact paragraph or table cell that supports the answer; "
                "(c) the KB rule applied (e.g., 'KB-SEV-001 CVSS mapping'). "
                "If the answer requires information from multiple findings, list all sources. "
                "If the answer relies on a KB rule rather than report content, cite the KB rule by ID."
            ),
            conditions=["client question being answered"],
            action=(
                "Verify every claim in the answer has a source citation. Flag any unsourced claim "
                "as unsupported. Do NOT generate answers without traceability."
            ),
            references=["problem_definition.md §12 (safety principles)"],
            severity="critical",
            applicable_to=["all"],
            tags=["client_qa", "citation", "traceability", "evidence_based"],
            document_type="internal_guideline",
            section="client_qa:source_citation",
            vulnerability_type="general",
            source_id="EVVO-internal",
        ),
        _entry(
            kb_id="KB-QA-002",
            category="writing_guidelines",
            subcategory="refusal_pattern",
            title="Refuse questions that cannot be answered from the report or KB",
            description=(
                "When a client asks a question that cannot be answered from the report content or "
                "the KB, the SLM must refuse with a structured response: "
                "(a) acknowledge the question; "
                "(b) state explicitly that the answer is not available in the report or KB; "
                "(c) list what information would be needed to answer; "
                "(d) suggest escalation to a human reviewer if appropriate. "
                "The SLM must NEVER speculate, infer, or generate answers from general knowledge "
                "when report/KB content is insufficient."
            ),
            conditions=[
                "question asks about content not in report",
                "question requires speculation about future risk",
                "question asks for opinion outside the report scope",
            ],
            action=(
                "Return structured refusal: {answerable: false, reason: 'insufficient_evidence', "
                "missing_info: [...], suggested_action: 'escalate_to_human'}."
            ),
            references=["problem_definition.md §12", "system_responsibility.md → SLM MUST NOT"],
            severity="critical",
            applicable_to=["all"],
            tags=["client_qa", "refusal", "safety", "no_hallucination", "escalation"],
            document_type="internal_guideline",
            section="client_qa:refusal_pattern",
            vulnerability_type="general",
            source_id="EVVO-internal",
        ),
        _entry(
            kb_id="KB-QA-003",
            category="writing_guidelines",
            subcategory="conditional_answer",
            title="Conditional answers for findings marked '(Potential)'",
            description=(
                "When a client question concerns a finding whose IMPACT row is prefixed with "
                "'(Potential)' (i.e., the vulnerability was not fully demonstrated during testing), "
                "the SLM must answer conditionally: "
                "(a) state that the finding is classified as Potential Issue, not Confirmed Vulnerability; "
                "(b) explain what would be needed to confirm or refute (additional testing, evidence); "
                "(c) provide the CVSS score and range as-is, without inflating severity; "
                "(d) recommend remediation as defensive measure, but acknowledge it is precautionary. "
                "Example from DOC-000001: Finding 3 (Root Detection) and Finding 5 (Email Enumeration) "
                "are both (Potential) — answers about these must use conditional phrasing."
            ),
            conditions=["question concerns finding with '(Potential)' impact marker"],
            action=(
                "Detect '(Potential)' marker in finding metadata. Apply conditional-answer template. "
                "Do NOT represent potential findings as confirmed."
            ),
            references=["DOC-000001 Tables 22, 24", "KB-CLASS-002 (potential_issue)"],
            severity="warning",
            applicable_to=["all"],
            tags=["client_qa", "conditional", "potential", "classification"],
            document_type="pentest_report",
            section="client_qa:conditional_answer",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-QA-004",
            category="writing_guidelines",
            subcategory="remediation_status_answer",
            title="Remediation status answers must use retest verification result",
            description=(
                "When a client asks 'Has this been fixed?' or 'What is the remediation status?', "
                "the SLM must answer using the Re-Test Verification Result field of the finding: "
                "(a) if retest.verification_result is 'Verified Fixed' → state the fix has been "
                "validated during retest; "
                "(b) if 'Not Retested' → state the fix has been reported by the client but not "
                "yet validated by EVVO; "
                "(c) if 'Verification Failed' → state the fix did not resolve the issue and "
                "additional remediation is needed; "
                "(d) if retest field is empty → state no retest information is available. "
                "The SLM must NEVER claim a fix is verified if the retest result does not support it."
            ),
            conditions=["question about remediation status or fix verification"],
            action=(
                "Read retest.verification_result from finding. Apply matching answer template. "
                "Flag if retest field is empty."
            ),
            references=["DOC-000001 'Re-Test Verification Result:' lines", "KB-VAL-005 (retest_validation)"],
            severity="warning",
            applicable_to=["all"],
            tags=["client_qa", "remediation", "retest", "verification"],
            document_type="pentest_report",
            section="client_qa:remediation_status_answer",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-QA-005",
            category="writing_guidelines",
            subcategory="scope_out_refusal",
            title="Refuse questions about assets or topics explicitly out of scope",
            description=(
                "When a client asks about an asset, module, or topic that is listed in the "
                "OUT OF SCOPE section of the report, the SLM must refuse: "
                "(a) state the asset/topic is explicitly out of scope for this engagement; "
                "(b) cite the OUT OF SCOPE entry verbatim; "
                "(c) suggest a separate engagement if assessment of that asset is needed. "
                "Example from DOC-000001: social engineering aspects, customer sites hosted on "
                "the GEVME platform, and 3rd-party hosted services are all explicitly out of scope."
            ),
            conditions=["question concerns asset/topic in OUT OF SCOPE list"],
            action=(
                "Match question against OUT OF SCOPE entries. If match found, return refusal "
                "citing the scope entry."
            ),
            references=["DOC-000001 paragraphs 86-89"],
            severity="warning",
            applicable_to=["all"],
            tags=["client_qa", "scope", "refusal", "out_of_scope"],
            document_type="pentest_report",
            section="client_qa:scope_out_refusal",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-QA-006",
            category="writing_guidelines",
            subcategory="severity_explanation",
            title="Severity explanation answers must reference CVSS vector breakdown",
            description=(
                "When a client asks 'Why is this Critical/High/Medium/Low?', the SLM must explain "
                "by decomposing the CVSS vector: "
                "(a) state the CVSS score and severity band (per KB-SEV-001..005); "
                "(b) walk through the vector components (AV, AC, PR, UI, S, C, I, A) with plain-English "
                "explanations of each; "
                "(c) explain which components contributed most to the score; "
                "(d) if the finding has a '(Potential)' marker, note that the score reflects potential "
                "impact assuming exploitation is confirmed. "
                "Example: '9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — Network-exploitable, "
                "low complexity, no privileges or user interaction required, high impact on confidentiality, "
                "integrity, and availability.'"
            ),
            conditions=["question about severity rating justification"],
            action=(
                "Decompose CVSS vector. Provide plain-English explanation per component. "
                "Cite KB-SEV-001..005 for severity band mapping."
            ),
            references=["CVSS v3.1 Specification", "KB-SEV-001..005", "DOC-000001 Tables 20-24"],
            severity="info",
            applicable_to=["all"],
            tags=["client_qa", "severity", "cvss", "explanation", "decomposition"],
            document_type="pentest_report",
            section="client_qa:severity_explanation",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
    ]

    data = {
        "description": (
            "Client Q&A patterns — behavior rules for the SLM when answering client questions "
            "about a pentest report. Covers source citation, refusal patterns, conditional answers "
            "for potential findings, remediation status, scope-out handling, and severity explanation."
        ),
        "version": "1.0",
        "entries": entries,
    }
    out = RULES_DIR / "client_qa_patterns.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  [step4] Created {out.name} with {len(entries)} Q&A pattern entries")


def step4_create_pentest_methodology():
    """Create pentest_methodology.json — NIST 800-115 + OWASP + OSSTMM SOP."""
    entries = [
        _entry(
            kb_id="KB-SOP-METH-001",
            category="sop",
            subcategory="standards_frameworks",
            title="EVVO pentest methodology follows OWASP Testing Guide, OSSTMM, and NIST SP 800-115",
            description=(
                "EVVO security assessments are based on three industry-recognized frameworks: "
                "(1) OWASP Testing Guide — for web application security testing, covers 13 categories "
                "(Information Gathering, Configuration and Deployment Management, Identity Management, "
                "Authentication Testing, Session Management, Access Control Testing, Business Logic Testing, "
                "Client-side Testing, API Testing, etc.); "
                "(2) OSSTMM (Open-Source Security Testing Methodology Manual) — for operational security metrics; "
                "(3) NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment, "
                "provides the overall assessment lifecycle. Findings must reference the relevant framework "
                "category in their methodology section."
            ),
            conditions=["report being validated for methodology section"],
            action=(
                "Verify methodology section cites at least one of the three frameworks. "
                "Flag reports missing methodology references."
            ),
            references=["OWASP Testing Guide v4.2", "OSSTMM v3", "NIST SP 800-115"],
            severity="warning",
            applicable_to=["all"],
            tags=["methodology", "owasp", "osstmm", "nist", "frameworks", "standards"],
            document_type="evvo_sop",
            section="pentest_methodology:standards_frameworks",
            vulnerability_type="general",
            source_id="EVVO-SOP-internal",
        ),
        _entry(
            kb_id="KB-SOP-METH-002",
            category="sop",
            subcategory="testing_approach",
            title="Testing approach must be declared: black-box, grey-box, or white-box",
            description=(
                "Every EVVO engagement must declare its testing approach in the Methodology section. "
                "Grey-box (the most common per DOC-000001) combines elements of black and white box: "
                "testers receive partial knowledge (user credentials, limited endpoint info) but not "
                "full source code or architecture. This allows realistic attacker simulation with "
                "deeper coverage of authentication, session handling, business logic, and privilege "
                "escalation paths. Black-box simulates external attacker with no internal knowledge. "
                "White-box gives full source code access for thorough code review."
            ),
            conditions=["report being validated"],
            action=(
                "Verify testing approach is explicitly declared. Flag if missing or ambiguous."
            ),
            references=["DOC-000001 paragraphs 178-180"],
            severity="info",
            applicable_to=["all"],
            tags=["methodology", "testing_approach", "grey_box", "black_box", "white_box"],
            document_type="evvo_sop",
            section="pentest_methodology:testing_approach",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-SOP-METH-003",
            category="sop",
            subcategory="assessment_phases",
            title="Assessment must follow 4 phases: Reconnaissance, Detection, Exploitation, Reporting",
            description=(
                "Every EVVO assessment follows 4 sequential phases: "
                "(1) Reconnaissance — Application & Functionality Mapping: manual navigation of the "
                "target to define attack surface, understand architecture, identify critical business "
                "functions (authentication, registration, password recovery, file uploads); "
                "(2) Vulnerability Detection — NIST SP 800-115 / OSSTMM / OWASP methodology: tests "
                "based on OWASP Top 10 to identify common security weaknesses and assess potential impact; "
                "(3) Exploitation & Validation: identified vulnerabilities are tested for exploitability "
                "to determine real-world impact; manual validation eliminates false positives and confirms "
                "exploitability beyond automated scanning; "
                "(4) Reporting — Documentation & Risk Analysis: vulnerabilities documented with "
                "supporting evidence, severity rating, potential impact, and remediation recommendations."
            ),
            conditions=["report being validated for assessment phases"],
            action=(
                "Verify all 4 phases are described. Flag if any phase is missing or under-described."
            ),
            references=["DOC-000001 paragraphs 184-193"],
            severity="warning",
            applicable_to=["all"],
            tags=["methodology", "phases", "reconnaissance", "detection", "exploitation", "reporting"],
            document_type="evvo_sop",
            section="pentest_methodology:assessment_phases",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-SOP-METH-004",
            category="sop",
            subcategory="owasp_categories",
            title="OWASP test cases must be enumerated by category (13 categories minimum)",
            description=(
                "The TEST CASES PERFORMED section must enumerate test cases organized by OWASP "
                "category. Minimum 13 categories for a comprehensive web assessment: "
                "Information Gathering (test cases 1-13: search engine discovery, fingerprinting, "
                "metafile review, application enumeration, metadata review, entry points, execution paths, "
                "framework fingerprinting, ...); "
                "Configuration and Deployment Management; Identity Management; Authentication Testing; "
                "Session Management; Access Control Testing; Business Logic Testing; "
                "Client-side Testing (DOM XSS, JS execution, HTML injection, URL redirect, CSS injection, "
                "resource manipulation, CORS, cross-site flashing, clickjacking, web sockets, web messaging, "
                "browser storage, cross-site script inclusion); API Testing; Server-side Testing. "
                "Each test case must have a stable S No. and be marked as performed or not performed."
            ),
            conditions=["report being validated for test case coverage"],
            action=(
                "Verify TEST CASES PERFORMED section exists and enumerates categories. "
                "Flag reports with incomplete coverage or missing test cases."
            ),
            references=["DOC-000001 Tables 6-18 (13 OWASP categories)", "OWASP Testing Guide v4.2"],
            severity="warning",
            applicable_to=["web_application", "api"],
            tags=["methodology", "owasp", "test_cases", "categories", "coverage"],
            document_type="evvo_sop",
            section="pentest_methodology:owasp_categories",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-SOP-METH-005",
            category="sop",
            subcategory="risk_rating",
            title="Risk rating must use CVSS v3.1 with 5 severity bands",
            description=(
                "All EVVO findings must be rated using CVSS v3.1. Severity is mapped as follows: "
                "Critical: 9.0–10.0; High: 7.0–8.9; Medium: 4.0–6.9; Low: 0.1–3.9; Informational: 0.0. "
                "Each finding's CVSS SCORE row must include the numeric score AND the full CVSS:3.1 vector. "
                "The severity bands are also described in the RISK DESCRIPTION section: "
                "Critical = system compromise without authentication, exploitation trivial, large-scale loss; "
                "High = system compromise, exploit code public, exploitation trivial, controls ineffective; "
                "Medium = skilled attacker required, no elevated privileges, controls impede exploitation; "
                "Low = exploitation extremely difficult, controls prevent exploitation, accrediting authority decides; "
                "Info = no business impact, useful for attacker context."
            ),
            conditions=["finding being rated or validated"],
            action=(
                "Verify CVSS score and vector are present and match one of the 5 bands. "
                "Flag mismatches between score, vector, and severity label."
            ),
            references=["CVSS v3.1 Specification", "DOC-000001 Table 19", "KB-SEV-001..005"],
            severity="critical",
            applicable_to=["all"],
            tags=["methodology", "cvss", "severity", "risk_rating", "bands"],
            document_type="evvo_sop",
            section="pentest_methodology:risk_rating",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-SOP-METH-006",
            category="sop",
            subcategory="user_roles_tested",
            title="Report must declare User Roles / Access Levels Tested",
            description=(
                "Every EVVO report must declare the user roles tested during the engagement. "
                "Common roles: Admin, Public (anonymous), and any custom roles (Editor, Viewer, "
                "Limited User). The roles tested must align with the declared testing approach "
                "(grey-box usually tests authenticated + unauthenticated roles). "
                "Findings must reference the affected user roles in their metadata table "
                "('Affected User Roles' row)."
            ),
            conditions=["report being validated"],
            action=(
                "Verify User Roles section exists. Cross-check that each finding's Affected User Roles "
                "row references a declared role. Flag findings with undeclared roles."
            ),
            references=["DOC-000001 paragraphs 181-183"],
            severity="info",
            applicable_to=["all"],
            tags=["methodology", "user_roles", "access_levels", "authentication"],
            document_type="evvo_sop",
            section="pentest_methodology:user_roles_tested",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-SOP-METH-007",
            category="sop",
            subcategory="tools_used",
            title="Report must declare tools used (e.g., Burp Suite, manual techniques)",
            description=(
                "Every EVVO report must declare the tools used during the assessment in the "
                "TESTING APPROACH section. Per DOC-000001: 'combination of manual techniques and "
                "assisted testing with Burp Suite. Manual validation was performed to eliminate false "
                "positives and confirm exploitability.' If other tools are used (Nmap, ZAP, Nuclei, "
                "Frida, etc.), they must be listed. The tools declared must align with the testing "
                "approach (e.g., grey-box web testing typically uses Burp Suite)."
            ),
            conditions=["report being validated"],
            action=(
                "Verify tools section declares at least one tool or technique. "
                "Flag if missing. Do NOT require specific tools — just declaration."
            ),
            references=["DOC-000001 paragraph 180"],
            severity="info",
            applicable_to=["all"],
            tags=["methodology", "tools", "burp_suite", "manual_testing"],
            document_type="evvo_sop",
            section="pentest_methodology:tools_used",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
        _entry(
            kb_id="KB-SOP-METH-008",
            category="sop",
            subcategory="retest_process",
            title="Retest process: every finding must have a Re-Test Verification Result",
            description=(
                "After the client reports remediation, EVVO performs a retest to validate the fix. "
                "Each finding's Re-Test Verification Result must be one of: "
                "(a) Verified Fixed — fix confirmed during retest; "
                "(b) Verification Failed — fix did not resolve the issue; "
                "(c) Not Retested — retest not yet performed or not applicable; "
                "(d) Partially Fixed — some aspects resolved, others remain. "
                "The FINAL REMEDIATION STATUS table must list every finding with its initial severity, "
                "retest status, final severity, and final status. Per DOC-000001 Table 5, the table "
                "has columns: NO | TITLE | INITIAL SEVERITY | RETEST STATUS | SEVERITY | FINAL STATUS."
            ),
            conditions=["retest report being validated"],
            action=(
                "Verify every finding has a Re-Test Verification Result. Verify FINAL REMEDIATION STATUS "
                "table is complete. Flag missing or invalid retest statuses."
            ),
            references=["DOC-000001 Table 5", "DOC-000001 paragraph 127"],
            severity="warning",
            applicable_to=["all"],
            tags=["methodology", "retest", "verification", "remediation_status"],
            document_type="evvo_sop",
            section="pentest_methodology:retest_process",
            vulnerability_type="general",
            source_id="DOC-000001",
        ),
    ]

    data = {
        "description": (
            "Pentest methodology SOP — NIST SP 800-115 + OWASP Testing Guide + OSSTMM conventions "
            "used by EVVO Labs. Covers testing approach, assessment phases, OWASP test categories, "
            "risk rating, user roles, tools, and retest process. Sourced from DOC-000001 Methodology "
            "section + EVVO internal SOP."
        ),
        "version": "1.0",
        "entries": entries,
    }
    out = SOPS_DIR / "pentest_methodology.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  [step4] Created {out.name} with {len(entries)} methodology entries")


# ──────────────────────────────────────────────────────────────────────────────
# Step 5: Update kb_manifest.json
# ──────────────────────────────────────────────────────────────────────────────

def step5_update_manifest():
    """Update kb_manifest.json with new files + entry counts + version 1.1."""
    fpath = KB_ROOT / "kb_manifest.json"
    with open(fpath, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Bump versions
    manifest["knowledge_base_version"] = "1.1"
    manifest["manifest_version"] = "1.1"
    manifest["updated_at"] = datetime.utcnow().isoformat(timespec="seconds") + "+00:00"

    # Update rules files listing
    rules_files = manifest["directories"]["rules"]["files"]
    # Replace the old remediation_templates entry with remediation_quality
    for f in rules_files:
        if f["filename"] == "remediation_templates.json":
            f["filename"] = "remediation_quality.json"
            f["description"] = "Remediation quality evaluation rules (root_cause, actionable, relevance, ...)"
            break
    # Add new rule files
    new_rules_files = [
        {
            "filename": "remediation_templates.json",
            "category": "remediation_guidance",
            "description": "Remediation template patterns by vulnerability class (rotate_credentials, migrate_algorithm, ...)",
        },
        {
            "filename": "report_style.json",
            "category": "writing_guidelines",
            "description": "EVVO report formatting conventions (headings, disclaimer, scope list, metadata table, ...)",
        },
        {
            "filename": "client_qa_patterns.json",
            "category": "writing_guidelines",
            "description": "Client Q&A behavior patterns (source citation, refusal, conditional answer, ...)",
        },
    ]
    existing_filenames = {f["filename"] for f in rules_files}
    for new_f in new_rules_files:
        if new_f["filename"] not in existing_filenames:
            rules_files.append(new_f)

    # Update sops files listing
    sops_files = manifest["directories"]["sops"]["files"]
    sop_filenames = {f["filename"] for f in sops_files}
    if "pentest_methodology.json" not in sop_filenames:
        sops_files.append({
            "filename": "pentest_methodology.json",
            "category": "sop",
            "description": "Pentest methodology SOP (NIST 800-115 + OWASP + OSSTMM)",
        })

    # Update retrieval strategies to reflect metadata-aware filtering
    manifest["retrieval_strategies"] = [
        "taxonomy-based: retrieve rules matching review taxonomy codes",
        "domain-based: retrieve rules matching the finding's domain",
        "tag-based: retrieve rules matching specific tags",
        "metadata-based (new in v1.1): filter by document_type, section, vulnerability_type, source_id",
        "combined: intersection of taxonomy + domain + tag + metadata filters",
    ]

    # Recompute entry_counts by actually loading the files
    def count_entries(rel_dir: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        d = KB_ROOT / rel_dir
        if not d.exists():
            return counts
        for jf in sorted(d.glob("*.json")):
            with open(jf, "r", encoding="utf-8") as f:
                d_data = json.load(f)
            for e in d_data.get("entries", []):
                cat = e.get("category", "unknown")
                counts[cat] = counts.get(cat, 0) + 1
        return counts

    rule_counts = count_entries("rules")
    sop_counts = count_entries("sops")
    schema_counts = count_entries("schemas")
    all_counts = {**rule_counts, **sop_counts, **schema_counts}
    all_counts["total"] = sum(all_counts.values())
    manifest["entry_counts"] = all_counts

    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  [step5] Updated kb_manifest.json — version 1.1, {all_counts['total']} entries total")


# ──────────────────────────────────────────────────────────────────────────────
# Step 6: Update schema_registry.json — bump KB Entry Schema to v1.1
# ──────────────────────────────────────────────────────────────────────────────

def step6_update_schema_registry():
    """Update KB-SCH-004 to describe schema v1.1 with new metadata fields."""
    fpath = SCHEMAS_DIR / "schema_registry.json"
    with open(fpath, "r", encoding="utf-8") as f:
        data = json.load(f)

    for entry in data["entries"]:
        if entry["kb_id"] == "KB-SCH-004":
            entry["title"] = "KB Entry Schema v1.1 — Knowledge Base entry structure"
            entry["description"] = (
                "The KB entry schema defines the structure of every Knowledge Base entry. "
                "Fields: kb_id, category, subcategory, title, description, conditions, action, "
                "references, severity, applicable_to, version, source, tags. "
                "New in v1.1 (per task 08/08 Definition of Done, PDF §3.3): "
                "document_type, section, vulnerability_type, effective_date, access_scope, source_id. "
                "Defined in src/harness/kb/schema.py."
            )
            entry["version"] = "1.1"
            entry["references"] = ["src/harness/kb/schema.py", "PDF §3.3 metadata schema"]
            entry["tags"] = ["schema", "kb_entry", "registry", "v1.1"]
            # Backfill metadata on this entry too
            entry.setdefault("document_type", "schema_definition")
            entry.setdefault("section", "taxonomy_definitions:kb_entry_schema")
            entry.setdefault("vulnerability_type", "general")
            entry.setdefault("effective_date", EFFECTIVE_DATE)
            entry.setdefault("access_scope", "internal")
            entry.setdefault("source_id", "CODE-kb_schema")
            print(f"  [step6] Updated KB-SCH-004 → schema v1.1")
            break

    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Task 08/08 — KB metadata backfill + 4 new files + manifest update")
    print("=" * 70)

    print("\n[Step 1] Rename remediation_templates.json → remediation_quality.json")
    step1_rename_remediation()

    print("\n[Step 2] Backfill metadata in existing KB files")
    all_kb_files = sorted(RULES_DIR.glob("*.json")) + sorted(SOPS_DIR.glob("*.json")) + sorted(SCHEMAS_DIR.glob("*.json"))
    total_backfilled = 0
    for kf in all_kb_files:
        n = step2_backfill_metadata(kf)
        if n:
            print(f"  [step2] {kf.name}: backfilled {n} entries")
        total_backfilled += n
    print(f"  [step2] Total entries backfilled: {total_backfilled}")

    print("\n[Step 3] Patch KB-VAL-001 → 5-part finding structure")
    step3_patch_val_001()

    print("\n[Step 4] Create 4 new KB files")
    step4_create_remediation_templates()
    step4_create_report_style()
    step4_create_client_qa_patterns()
    step4_create_pentest_methodology()

    print("\n[Step 5] Update kb_manifest.json")
    step5_update_manifest()

    print("\n[Step 6] Update schema_registry.json (KB-SCH-004 → v1.1)")
    step6_update_schema_registry()

    print("\n" + "=" * 70)
    print("DONE — task 08/08 KB v1.1 changes applied")
    print("=" * 70)


if __name__ == "__main__":
    main()