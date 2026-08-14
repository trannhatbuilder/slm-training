"""
EVVO SLM Harness — Rule-Based Validation Engine v1

Day 07/08 deliverable: deterministic review pipeline that takes
a normalized VAPT finding (Input Schema v0.2) and produces
a structured review (Output Schema v0.1) without SLM.

Day 08/08 deliverable: Knowledge Base structure with loader,
retriever, and 60 KB entries across 10 categories.

Architecture:
    orchestrator.py    → main pipeline controller (12 steps)
    input_validator.py → schema + governance checks
    rule_checks.py     → 9 taxonomy-based checks
    consistency.py     → cross-field consistency
    confidence.py      → confidence scoring (taxonomy CONF)
    escalation.py      → human escalation decision
    output_assembler.py→ Output Schema v0.1 assembly
    config.py          → constants and configuration
    kb/
        schema.py      → KB entry schema and type definitions
        loader.py      → Load KB from JSON source files
        retriever.py   → Retrieve relevant rules (RAG for step 5)
"""

__version__ = "0.2.0"
__schema_input__ = "0.2"
__schema_output__ = "0.1"
__kb_version__ = "1.0"