"""
EVVO Knowledge Base — Structure and Retrieval Layer

Day 08/08 deliverable: Knowledge Base structure that stores review rules,
SOPs, severity guidance, validation requirements, writing guidance,
remediation guidance, schemas, and taxonomy definitions.

Provides the RAG retrieval interface for Harness step 5
("Retrieve relevant EVVO rules") from problem_definition §11.4.

Architecture:
    schema.py    → KB entry schema and type definitions
    loader.py    → Load KB from YAML/JSON source files
    retriever.py → Retrieve relevant rules for a review task
"""

__version__ = "1.0"