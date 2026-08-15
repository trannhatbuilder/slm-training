#!/usr/bin/env python3
"""
Task 08/08 — Generate notebooks/04_retrieval.ipynb + data/kb/retrieval_eval.json.

This script:
  1. Defines 10 gold queries covering realistic pentest-report-review scenarios.
  2. Generates notebooks/04_retrieval.ipynb (executes the queries + writes eval JSON).
  3. When the notebook is executed, it writes data/kb/retrieval_eval.json with
     precision@5, recall, and per-query results.

The notebook is designed to be re-runnable: each execution regenerates the eval JSON
based on the current KB state (so adding new KB entries will be reflected).
"""

from __future__ import annotations
import json
from pathlib import Path

REPO_ROOT = Path(r"D:\evvo-slm-harness")
NOTEBOOK_OUT = REPO_ROOT / "notebooks" / "04_retrieval.ipynb"
EVAL_OUT = REPO_ROOT / "data" / "kb" / "retrieval_eval.json"

# ──────────────────────────────────────────────────────────────────────────────
# Gold queries — 10 scenarios covering all 6 KB coverage categories
# ──────────────────────────────────────────────────────────────────────────────
# Each query has:
#   - query_id, scenario (description), taxonomy_codes, domain, tags
#   - expected_kb_ids: minimum set of KB IDs that MUST be retrieved (for recall)
#   - relevant_kb_ids:  broader set considered "relevant" (for precision@5)

GOLD_QUERIES = [
    {
        "query_id": "Q001",
        "scenario": "Review a Critical-severity finding with CVSS 9.8 — needs severity + consistency rules",
        "taxonomy_codes": ["SEV", "CVSS", "CONS"],
        "domain": "all",
        "tags": None,
        "categories": None,
        "expected_kb_ids": ["KB-SEV-001", "KB-CONS-001"],  # Critical range + severity-CVSS consistency
        "relevant_kb_ids": ["KB-SEV-001", "KB-SEV-006", "KB-SEV-007", "KB-CONS-001", "KB-VAL-002"],
    },
    {
        "query_id": "Q002",
        "scenario": "Finding has only scanner output as evidence — classify as false positive or potential?",
        "taxonomy_codes": ["EVID", "CLASS"],
        "domain": "all",
        "tags": None,
        "categories": None,
        "expected_kb_ids": ["KB-EVID-004", "KB-CLASS-004"],  # scanner-only + false_positive
        "relevant_kb_ids": ["KB-EVID-001", "KB-EVID-004", "KB-CLASS-002", "KB-CLASS-004", "KB-VAL-001"],
    },
    {
        "query_id": "Q003",
        "scenario": "Finding has hardcoded credentials in mobile APK — needs remediation template",
        "taxonomy_codes": ["REC"],
        "domain": "android_application",
        "tags": None,
        "categories": None,
        "expected_kb_ids": ["KB-REC-TPL-001", "KB-REC-TPL-006"],  # rotate_credentials + secret_scanning
        "relevant_kb_ids": ["KB-REC-TPL-001", "KB-REC-TPL-004", "KB-REC-TPL-006", "KB-REC-005", "KB-REC-006"],
    },
    {
        "query_id": "Q004",
        "scenario": "Finding uses HS256 JWT — needs migration template + crypto guidance",
        "taxonomy_codes": ["REC", "SEV"],
        "domain": "all",
        "tags": None,
        "categories": None,
        "expected_kb_ids": ["KB-REC-TPL-002"],  # migrate_algorithm
        "relevant_kb_ids": ["KB-REC-TPL-002", "KB-SEV-003", "KB-CONS-001", "KB-REC-001", "KB-REC-002"],
    },
    {
        "query_id": "Q005",
        "scenario": "Review a finding's report style — check heading hierarchy and metadata table",
        "taxonomy_codes": None,
        "domain": "all",
        "tags": None,
        "categories": ["writing_guidelines"],  # STYLE entries live in writing_guidelines
        "expected_kb_ids": ["KB-STYLE-001", "KB-STYLE-004"],  # heading_hierarchy + finding_metadata_table
        "relevant_kb_ids": ["KB-STYLE-001", "KB-STYLE-002", "KB-STYLE-003", "KB-STYLE-004", "KB-STYLE-005"],
    },
    {
        "query_id": "Q006",
        "scenario": "Client asks about a finding marked (Potential) — answer conditionally",
        "taxonomy_codes": None,
        "domain": "all",
        "tags": None,
        "categories": ["writing_guidelines", "classification_criteria"],  # QA + CLASS entries
        "expected_kb_ids": ["KB-QA-003", "KB-CLASS-002"],  # conditional_answer + potential_issue
        "relevant_kb_ids": ["KB-QA-003", "KB-CLASS-002", "KB-QA-001", "KB-QA-002", "KB-VAL-001"],
    },
    {
        "query_id": "Q007",
        "scenario": "Client asks about scope-out asset — must refuse",
        "taxonomy_codes": None,
        "domain": "all",
        "tags": None,
        "categories": ["writing_guidelines"],
        "expected_kb_ids": ["KB-QA-005"],  # scope_out_refusal
        "relevant_kb_ids": ["KB-QA-005", "KB-QA-002", "KB-QA-003", "KB-STYLE-003"],
    },
    {
        "query_id": "Q008",
        "scenario": "Review a finding — needs full pentest methodology context (NIST/OWASP)",
        "taxonomy_codes": None,
        "domain": "all",
        "tags": None,
        "categories": ["sop"],  # METH entries live in sop category
        "expected_kb_ids": ["KB-SOP-METH-001", "KB-SOP-METH-003"],  # standards + phases
        "relevant_kb_ids": ["KB-SOP-METH-001", "KB-SOP-METH-002", "KB-SOP-METH-003", "KB-SOP-METH-004", "KB-SOP-METH-005"],
    },
    {
        "query_id": "Q009",
        "scenario": "Finding has severity High but evidence insufficient — escalate",
        "taxonomy_codes": ["CONF", "EVID", "SEV"],
        "domain": "all",
        "tags": None,
        "categories": None,
        "expected_kb_ids": ["KB-ESC-001", "KB-SEV-006"],  # automatic_escalation + severity_evidence_mismatch
        "relevant_kb_ids": ["KB-ESC-001", "KB-ESC-002", "KB-ESC-004", "KB-SEV-006", "KB-EVID-002"],
    },
    {
        "query_id": "Q010",
        "scenario": "Validate finding schema — check 5-part structure + CVSS + CWE format",
        "taxonomy_codes": ["COMP", "CVSS", "CWE"],
        "domain": "all",
        "tags": None,
        "categories": None,
        "expected_kb_ids": ["KB-VAL-001", "KB-VAL-002", "KB-VAL-003"],  # 5-part + cvss + cwe
        "relevant_kb_ids": ["KB-VAL-001", "KB-VAL-002", "KB-VAL-003", "KB-VAL-004", "KB-VAL-005", "KB-VAL-006"],
    },
]


def build_notebook_cells():
    """Build the list of notebook cells (nbformat v4)."""
    cells = []

    # ── Markdown: title ──
    cells.append({
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "# 04 — Knowledge Base Retrieval Evaluation\n",
            "\n",
            "**Task 08/08 deliverable** — Retrieval notebook + `retrieval_eval.json`.\n",
            "\n",
            "This notebook:\n",
            "1. Loads the EVVO Knowledge Base (KB v1.1, 91 entries across 11 categories).\n",
            "2. Runs 10 gold queries covering realistic pentest-report-review scenarios.\n",
            "3. Computes precision@5 and recall for each query.\n",
            "4. Writes results to `data/kb/retrieval_eval.json`.\n",
            "\n",
            "**Retrieval method**: metadata-based filtering (taxonomy_codes + domain + tags).\n",
            "Vector index (embeddings + FAISS) will be added in task 13/08.\n",
            "\n",
            "**Gold query categories covered** (per Definition of Done PDF §3.3):\n",
            "- severity_logic (Q001, Q009)\n",
            "- validation_rules (Q010)\n",
            "- remediation_patterns (Q003, Q004)\n",
            "- report_style (Q005)\n",
            "- sop_methodology (Q008)\n",
            "- client_qa_patterns (Q006, Q007)\n",
            "- evidence/classification (Q002)\n",
        ],
    })

    # ── Code: setup ──
    cells.append({
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "import sys, json\n",
            "from pathlib import Path\n",
            "from datetime import datetime, timezone\n",
            "\n",
            "# Repo setup — adjust paths if running outside the repo\n",
            "REPO_ROOT = Path(r'D:\evvo-slm-harness')\n",
            "sys.path.insert(0, str(REPO_ROOT / 'src'))\n",
            "\n",
            "from harness.kb.loader import KBLoader\n",
            "from harness.kb.retriever import KBRetriever\n",
            "\n",
            "KB_ROOT = REPO_ROOT / 'data' / 'kb'\n",
            "EVAL_OUT = KB_ROOT / 'retrieval_eval.json'\n",
            "\n",
            "print(f'Repo root: {REPO_ROOT}')\n",
            "print(f'KB root:   {KB_ROOT}')\n",
            "print(f'Eval out:  {EVAL_OUT}')",
        ],
    })

    # ── Code: load KB ──
    cells.append({
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "loader = KBLoader(kb_root=str(KB_ROOT))\n",
            "entries = loader.load_all()\n",
            "print(f'Loaded: {len(entries)} entries, {len(loader.load_errors)} errors')\n",
            "if loader.load_errors:\n",
            "    for e in loader.load_errors[:5]:\n",
            "        print(f'  ERROR: {e}')\n",
            "\n",
            "from collections import Counter\n",
            "cat_counts = Counter(e.category for e in entries)\n",
            "print('\\nEntries by category:')\n",
            "for cat, n in sorted(cat_counts.items()):\n",
            "    print(f'  {cat:30s} {n}')\n",
            "\n",
            "# Verify metadata fields are populated on a sample\n",
            "sample = entries[0]\n",
            "print(f'\\nSample metadata ({sample.kb_id}):')\n",
            "for f in ['document_type', 'section', 'vulnerability_type', 'effective_date', 'access_scope', 'source_id']:\n",
            "    print(f'  {f}: {getattr(sample, f)!r}')",
        ],
    })

    # ── Markdown: gold queries intro ──
    cells.append({
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## Gold Queries\n",
            "\n",
            "10 hand-crafted queries covering all 6 KB coverage categories.\n",
            "Each query specifies:\n",
            "- `taxonomy_codes`: taxonomy codes to retrieve (None = skip taxonomy filter)\n",
            "- `domain`: finding domain filter ('all' = no domain filter)\n",
            "- `tags`: tag filter (None = skip tag filter — mirrors production usage)\n",
            "- `categories`: direct category filter (used for STYLE/QA/METH queries where\n",
            "  no taxonomy code maps to the target category)\n",
            "- `expected_kb_ids`: minimum set that MUST be retrieved (recall check)\n",
            "- `relevant_kb_ids`: broader set considered relevant (precision@5 denominator)\n",
            "\n",
            "**Note on retrieval design**: production code (orchestrator.py) calls\n",
            "`retrieve_for_review(taxonomy_codes=[9 codes], domain=finding_domain)` — no tags.\n",
            "These gold queries mirror that pattern, only using `categories` for cases\n",
            "where the target KB entries live in a category not reachable via taxonomy codes\n",
            "(writing_guidelines, sop). This is a known v1 limitation — task 13/08 will\n",
            "introduce vector retrieval to bridge this gap.",
        ],
    })

    # ── Code: gold queries (embed as Python literal reconstructed from JSON) ──
    # We dump to JSON then immediately parse it back inside the notebook cell,
    # so the cell source is valid Python: GOLD_QUERIES = json.loads("""...""")
    gold_queries_json = json.dumps(GOLD_QUERIES, indent=2, ensure_ascii=False)
    # Use triple-quoted string with escaped triple quotes (none in our content)
    cells.append({
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "import json as _json\n",
            "GOLD_QUERIES = _json.loads(r'''",
            gold_queries_json,
            "''')\n",
            "\n",
            "print(f'Loaded {len(GOLD_QUERIES)} gold queries')\n",
            "for q in GOLD_QUERIES:\n",
            "    print(f\"  {q['query_id']}: {q['scenario'][:80]}\")",
        ],
    })

    # ── Markdown: run retrieval ──
    cells.append({
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## Run Retrieval + Compute Metrics\n",
            "\n",
            "For each query:\n",
            "1. Call `KBRetriever.retrieve_for_review()` with the query parameters.\n",
            "2. Compute **recall** = |retrieved ∩ expected| / |expected|.\n",
            "3. Compute **precision@5** = |top-5 retrieved ∩ relevant| / 5.\n",
            "4. Record per-query results.",
        ],
    })

    # ── Code: run retrieval + compute metrics ──
    cells.append({
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "retriever = KBRetriever(kb_root=str(KB_ROOT))\n",
            "\n",
            "def compute_metrics(retrieved_ids, expected_ids, relevant_ids, k=5):\n",
            "    retrieved_set = set(retrieved_ids)\n",
            "    expected_set = set(expected_ids)\n",
            "    relevant_set = set(relevant_ids)\n",
            "    \n",
            "    # Recall: did we retrieve all expected IDs?\n",
            "    if expected_set:\n",
            "        recall = len(retrieved_set & expected_set) / len(expected_set)\n",
            "    else:\n",
            "        recall = 1.0\n",
            "    \n",
            "    # Precision@k: of the top-k retrieved, how many are relevant?\n",
            "    top_k = retrieved_ids[:k]\n",
            "    if top_k:\n",
            "        precision_at_k = len(set(top_k) & relevant_set) / len(top_k)\n",
            "    else:\n",
            "        precision_at_k = 0.0\n",
            "    \n",
            "    missing = sorted(expected_set - retrieved_set)\n",
            "    return recall, precision_at_k, missing\n",
            "\n",
            "results = []\n",
            "for q in GOLD_QUERIES:\n",
            "    # Mirror production usage: skip None filters, treat 'all' domain as no filter\n",
            "    domain = q['domain'] if q['domain'] and q['domain'] != 'all' else None\n",
            "    tags = q.get('tags') or None\n",
            "    taxonomy_codes = q.get('taxonomy_codes') or None\n",
            "    categories = q.get('categories') or None\n",
            "    \n",
            "    res = retriever.retrieve_for_review(\n",
            "        taxonomy_codes=taxonomy_codes,\n",
            "        domain=domain,\n",
            "        tags=tags,\n",
            "        categories=categories,\n",
            "    )\n",
            "    retrieved_ids = [e.kb_id for e in res.entries]\n",
            "    recall, p_at_5, missing = compute_metrics(\n",
            "        retrieved_ids, q['expected_kb_ids'], q['relevant_kb_ids']\n",
            "    )\n",
            "    \n",
            "    # Collect which expected IDs were found vs missing\n",
            "    expected_found = [kid for kid in q['expected_kb_ids'] if kid in retrieved_ids]\n",
            "    \n",
            "    results.append({\n",
            "        'query_id': q['query_id'],\n",
            "        'scenario': q['scenario'],\n",
            "        'query_params': {\n",
            "            'taxonomy_codes': taxonomy_codes,\n",
            "            'domain': q['domain'],\n",
            "            'tags': tags,\n",
            "            'categories': categories,\n",
            "        },\n",
            "        'retrieved_count': len(retrieved_ids),\n",
            "        'retrieved_kb_ids': retrieved_ids,\n",
            "        'expected_kb_ids': q['expected_kb_ids'],\n",
            "        'expected_found': expected_found,\n",
            "        'expected_missing': missing,\n",
            "        'relevant_kb_ids': q['relevant_kb_ids'],\n",
            "        'recall': round(recall, 4),\n",
            "        'precision_at_5': round(p_at_5, 4),\n",
            "    })\n",
            "    \n",
            "    status = 'OK' if recall == 1.0 else 'FAIL'\n",
            "    print(f\"  [{status}] {q['query_id']}: recall={recall:.3f}, p@5={p_at_5:.3f}, retrieved={len(retrieved_ids)}\")\n",
            "    if missing:\n",
            "        print(f\"         MISSING: {missing}\")",
        ],
    })

    # ── Markdown: aggregate + write eval JSON ──
    cells.append({
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## Aggregate + Write `retrieval_eval.json`\n",
            "\n",
            "Compute aggregate metrics (mean recall, mean precision@5, pass rate) and write the eval JSON.",
        ],
    })

    # ── Code: write eval JSON ──
    cells.append({
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "n = len(results)\n",
            "mean_recall = sum(r['recall'] for r in results) / n if n else 0\n",
            "mean_p5 = sum(r['precision_at_5'] for r in results) / n if n else 0\n",
            "n_pass = sum(1 for r in results if r['recall'] == 1.0)\n",
            "n_fail = n - n_pass\n",
            "\n",
            "eval_output = {\n",
            "    'eval_version': '1.0',\n",
            "    'kb_version': '1.1',\n",
            "    'evaluated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),\n",
            "    'retrieval_method': 'metadata_filter (taxonomy + domain + tags) — vector index planned for task 13/08',\n",
            "    'total_queries': n,\n",
            "    'aggregate_metrics': {\n",
            "        'mean_recall': round(mean_recall, 4),\n",
            "        'mean_precision_at_5': round(mean_p5, 4),\n",
            "        'pass_rate': round(n_pass / n, 4) if n else 0,\n",
            "        'queries_passed': n_pass,\n",
            "        'queries_failed': n_fail,\n",
            "    },\n",
            "    'coverage_categories': {\n",
            "        'severity_logic': ['Q001', 'Q009'],\n",
            "        'validation_rules': ['Q010'],\n",
            "        'remediation_patterns': ['Q003', 'Q004'],\n",
            "        'report_style': ['Q005'],\n",
            "        'sop_methodology': ['Q008'],\n",
            "        'client_qa_patterns': ['Q006', 'Q007'],\n",
            "        'evidence_classification': ['Q002'],\n",
            "    },\n",
            "    'queries': results,\n",
            "}\n",
            "\n",
            "EVAL_OUT.parent.mkdir(parents=True, exist_ok=True)\n",
            "with open(EVAL_OUT, 'w', encoding='utf-8') as f:\n",
            "    json.dump(eval_output, f, indent=2, ensure_ascii=False)\n",
            "    f.write('\\n')\n",
            "\n",
            "print(f'Wrote {EVAL_OUT}')\n",
            "print(f'\\n=== Aggregate Metrics ===')\n",
            "print(f'  Mean recall:        {mean_recall:.4f}')\n",
            "print(f'  Mean precision@5:   {mean_p5:.4f}')\n",
            "print(f'  Pass rate:          {n_pass}/{n} ({n_pass/n*100:.1f}%)')\n",
            "print(f'  Queries failed:     {n_fail}')",
        ],
    })

    # ── Markdown: per-query details ──
    cells.append({
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## Per-Query Details\n",
            "\n",
            "Display each query's retrieved IDs vs expected IDs for manual inspection.",
        ],
    })

    # ── Code: print details ──
    cells.append({
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "for r in results:\n",
            "    print(f\"\\n{r['query_id']}: {r['scenario']}\")\n",
            "    print(f\"  Query:   tax={r['query_params']['taxonomy_codes']}, domain={r['query_params']['domain']}, tags={r['query_params']['tags']}\")\n",
            "    print(f\"  Recall:  {r['recall']}  (found {len(r['expected_found'])}/{len(r['expected_kb_ids'])} expected)\")\n",
            "    print(f\"  P@5:     {r['precision_at_5']}\")\n",
            "    print(f\"  Retrieved ({r['retrieved_count']}):\")\n",
            "    for kid in r['retrieved_kb_ids'][:10]:\n",
            "        marker = ' [EXPECTED]' if kid in r['expected_kb_ids'] else (' [RELEVANT]' if kid in r['relevant_kb_ids'] else '')\n",
            "        print(f\"    - {kid}{marker}\")\n",
            "    if len(r['retrieved_kb_ids']) > 10:\n",
            "        print(f\"    ... and {len(r['retrieved_kb_ids'])-10} more\")\n",
            "    if r['expected_missing']:\n",
            "        print(f\"  MISSING: {r['expected_missing']}\")",
        ],
    })

    # ── Markdown: summary ──
    cells.append({
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "## Summary\n",
            "\n",
            "This notebook is re-runnable. After any KB change (adding/removing entries),\n",
            "re-execute this notebook to regenerate `data/kb/retrieval_eval.json`.\n",
            "\n",
            "**Next step (task 13/08)**: upgrade the retriever to support vector embeddings\n",
            "(sentence-transformers + FAISS) and re-evaluate. Compare precision/recall before/after\n",
            "to measure the improvement from semantic retrieval.",
        ],
    })

    return cells


def write_notebook():
    """Write the .ipynb file."""
    cells = build_notebook_cells()
    notebook = {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {
                "name": "python",
                "version": "3.11",
            },
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(NOTEBOOK_OUT, "w", encoding="utf-8") as f:
        json.dump(notebook, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Wrote {NOTEBOOK_OUT} ({len(cells)} cells)")


def main():
    print("=" * 70)
    print("Task 08/08 — Generate retrieval notebook + eval JSON scaffold")
    print("=" * 70)
    write_notebook()
    print()
    print("Next: execute the notebook with jupyter nbconvert --to notebook --execute")
    print(f"      Output: {EVAL_OUT}")


if __name__ == "__main__":
    main()