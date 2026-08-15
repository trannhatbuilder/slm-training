# Training Log — SLM Fine-tuning

This document records each training run for reproducibility and post-mortem analysis.

Format: append a new section per run, newest at the bottom. Copy the template at the bottom of this file and fill in the values printed by `notebooks/06_finetune.ipynb` cell 17.

---

## Run: 2026-08-11 (SMOKE TEST — to be filled in after Colab run)

- **Model:** Qwen/Qwen2.5-1.5B-Instruct
- **Hardware:** Tesla T4 (15 GB VRAM, Google Colab)
- **Run type:** smoke
- **Cases:** 5 (first 5 of benchmark_v1.jsonl)
- **Epochs:** 1
- **Max steps:** 10
- **Final loss:** _TBD_
- **Initial loss:** _TBD_
- **Runtime:** _TBD_ min
- **Peak VRAM:** _TBD_ GB
- **Adapter size:** _TBD_ MB
- **Reload test:** _TBD_ (PASS / FAIL)

### Package versions

```
transformers: _TBD_
peft:         _TBD_
trl:          _TBD_
datasets:     _TBD_
torch:        _TBD_
accelerate:   _TBD_
CUDA:         _TBD_
```

### LoRA config

```
r: 8
alpha: 16
dropout: 0.05
target_modules: [q_proj, k_proj, v_proj, o_proj]
```

### Training config

```
batch_size: 2
grad_accum: 8 (effective batch = 16)
lr: 2e-4
lr_scheduler: cosine
warmup_ratio: 0.03
max_seq_length: 2048
fp16: true
seed: 42
```

### Loss curve

```
_TBD_ (paste from cell 17 output)
```

### Observations

- _TBD_ (smoke test verdict: pass/fail, why)
- _TBD_ (any OOM, instability, warnings)
- _TBD_ (decision: proceed to full run / fix issue first)

---

## Run: 2026-08-12 (FULL TRAINING — to be filled in after Colab run)

- **Model:** Qwen/Qwen2.5-1.5B-Instruct
- **Hardware:** Tesla T4 (15 GB VRAM, Google Colab)
- **Run type:** full
- **Cases:** 34 (all of benchmark_v1.jsonl)
- **Epochs:** 3
- **Final loss:** _TBD_
- **Initial loss:** _TBD_
- **Runtime:** _TBD_ min
- **Peak VRAM:** _TBD_ GB
- **Adapter size:** _TBD_ MB
- **Reload test:** _TBD_ (PASS / FAIL)

### Loss curve

```
_TBD_ (paste from cell 17 output)
```

### Observations

- _TBD_ (loss decreased steadily / diverged / plateaued)
- _TBD_ (compare to baseline pass rate 14.7% — needs eval on benchmark, see task 16/08)
- _TBD_ (any issues encountered)

### Post-mortem vs target metrics

Baseline (10/08) → Target (post-fine-tune, to be verified on 16/08):

| Metric | Baseline | Fine-tuned | Target |
|---|---|---|---|
| pass_rate | 14.7% | _TBD_ | > 60% |
| pass_rate (excl. remediation) | 0% | _TBD_ | > 50% |
| hard_negative_pass_rate | 0% | _TBD_ | > 30% |
| FMT-MISSING-FIELD count | 34 | _TBD_ | < 5 |
| latency avg | 4.55 s/case | _TBD_ | < 3 s/case |

### Adapter location

- **Google Drive:** `/content/drive/MyDrive/evvo-slm-checkpoints/slm-adapter-v0.1/`
- **Local repo (git):** `checkpoints/slm-adapter-v0.1/`
- **Adapter file:** `adapter_model.safetensors` (~10-20 MB expected for r=8 on 1.5B)

### Next steps

- Task 13/08: Build retrieval index (BM25 or embedding), test on severity/validation/remediation queries.
- Task 14-15/08: Wire up report-review PoC pipeline (parser → normalization → retrieval → compact prompt → SLM → JSON → schema validation).
- Task 16/08: Compare Base vs Base+RAG vs Fine-tuned vs Fine-tuned+RAG on benchmark_v1.

---

## Template (copy for new runs)

```markdown
## Run: YYYY-MM-DD (SMOKE / FULL)

- **Model:**
- **Hardware:**
- **Run type:**
- **Cases:**
- **Epochs:**
- **Final loss:**
- **Initial loss:**
- **Runtime:** min
- **Peak VRAM:** GB
- **Adapter size:** MB
- **Reload test:** (PASS / FAIL)

### Package versions

\`\`\`
(paste from cell 3 output)
\`\`\`

### Loss curve

\`\`\`
(paste from cell 17 output)
\`\`\`

### Observations

-
-
-
```