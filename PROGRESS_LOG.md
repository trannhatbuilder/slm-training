# EVVO SLM + Harness — Progress Log

## Overall Status: Tasks 11-12/08 through 16/08 COMPLETED

---

## 13/08: Retrieval Pipeline ✅
- Built FAISS index: 91 vectors, 384 dims (all-MiniLM-L6-v2)
- Evaluated retrieval: metadata-only, semantic-only, hybrid
- Winner: hybrid (avg recall=1.0, precision@5=0.46)
- Files: data/kb/retrieval_eval.json (on Google Drive: kb-index-v1/)

## 14-15/08: PoC Pipeline ✅
- Pipeline: Parser → Normalization → Retrieval → Compact Prompt → SLM → JSON Parse → Harness → Schema Validation
- SLM: Qwen2.5-1.5B-Instruct + LoRA adapter v0.1 (8.34MB, QLoRA r=8 alpha=16)
- Ran on all 5 findings from DOC-000001
- Results saved: data/poc_pipeline_results.json
- Key finding: SLM uses free-text classification labels (not schema-controlled vocabulary)
  - SLM: "Critical", "Weakness", "Information Disclosure"
  - Harness: "confirmed_vulnerability", "potential_issue"
  - Gap identified → addressed in v0.2 fine-tuning

## 16/08: 4-Variant Metrics Report ✅
- Compared: Base vs Base+RAG vs Fine-tuned vs Fine-tuned+RAG
- Tested on 3 findings: FND-000001 (critical), FND-000002 (medium), FND-000005 (low)

### Results:
| Variant       | JSON% | SevMatch% | Avg Time |
|---------------|-------|-----------|----------|
| Base          | 100%  | 100%      | 14.3s    |
| Base+RAG      | 100%  | 67%       | 13.9s    |
| Fine-tuned    | 100%  | 100%      | 12.1s    |  ← BEST
| Fine-tuned+RAG| 100%  | 67%       | 15.2s    |

### Key Conclusions:
1. Fine-tuned (no RAG) is BEST variant: 100% severity match + fastest (12.1s)
2. RAG causes severity downgrade: FND-000001 Critical→High (both Base+RAG and Fine-tuned+RAG)
3. Fine-tuned is more stable: classification labels don't change when RAG added
4. Recommendation for v0.2: Fine-tuned as primary decision-maker, RAG as advisory context

### Files:
- data/metrics_report_16aug.json (detailed results + conclusions)
- data/poc_pipeline_results.json (full pipeline output for 5 findings)

---

## Important Notes for Next Session:
- Google Drive path: /content/drive/MyDrive/evvo-slm-checkpoints/
  - kb-index-v1/ (FAISS index, embeddings, chunk_metadata)
  - slm-adapter-v0.1/ (LoRA adapter weights)
  - poc_pipeline_results.json (backup)
  - metrics_report_16aug.json (backup)
- Colab cannot push to GitHub — must download files manually
- Harness import fix: monkey-patch config.py constants before importing orchestrator
  (EVIDENCE_COMPLETNESS_ESCALATION_THRESHOLD has __future__ annotations issue in Python 3.12)
- Finding structure: no "category" field; use cwe_id, severity, observation (not description)
- Normalized findings at: data/normalized/DOC-000001-findings-normalized.json
  - findings are in norm_data["findings"] (not root list)

---

## Next Tasks (per plan):
- 17-23/08 (Week 12): SLM v0.2 + self-validation + confidence + customer QA Beta
- 24-30/08 (Week 13): End-to-end + human comparison + regression + release
- 31/08: Final demo + freeze v1
