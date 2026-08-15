# Training Log — SLM Fine-tuning

This document records each training run for reproducibility and post-mortem analysis.

Format: append a new section per run, newest at the bottom. Copy the template at the bottom of this file and fill in the values printed by `notebooks/06_finetune.ipynb` cell 17.

---

## Run: 2026-08-15 09:18 UTC (FULL TRAINING)

- **Model:** Qwen/Qwen2.5-1.5B-Instruct
- **Hardware:** Tesla T4 (15 GB VRAM, Google Colab)
- **Run type:** full
- **Cases:** 34 (all of benchmark_v1.jsonl, 8 task types)
- **Epochs:** 3
- **Total optimization steps:** 24 (ceil(34/4) × 3 = 9 × 3 ≈ 27, actual 24)
- **Final loss:** 1.5585 (step 24)
- **Initial loss:** 2.0871 (step 1)
- **Lowest loss:** 1.0471 (step 14)
- **Runtime:** 1.61 min (96.43 s)
- **Peak VRAM:** 6.77 GB / 15 GB (45% utilization)
- **Adapter size:** 8.34 MB (adapter_model.safetensors)
- **Reload test:** PASS

### Package versions

```
transformers: 4.46.0
peft:         0.13.2
trl:          0.12.1
datasets:     3.1.0
torch:        2.11.0+cu128
accelerate:   1.14.0
CUDA:         12.8
GPU:          Tesla T4
```

### LoRA config

```
r: 8
alpha: 16
dropout: 0.05
target_modules: [q_proj, k_proj, v_proj, o_proj]
bias: none
task_type: CAUSAL_LM
```

### Training config

```
per_device_train_batch_size: 1
gradient_accumulation_steps: 4   (effective batch = 4)
learning_rate: 2e-4
lr_scheduler: cosine
warmup_ratio: 0.03
max_seq_length: 2048
fp16: true
bf16: false
gradient_checkpointing: true
optim: adamw_torch
seed: 42
logging_steps: 1
```

### Loss curve

```
step   1: loss=2.0871
step   2: loss=1.8474
step   3: loss=2.1874
step   4: loss=1.7368
step   5: loss=1.9449
step   6: loss=1.9197
step   7: loss=1.8566
step   8: loss=1.5549
step   9: loss=2.6023   ← spike (likely finding_review long batch)
step  10: loss=1.9513
step  11: loss=1.8214
step  12: loss=1.9230
step  13: loss=1.5899
step  14: loss=1.0471   ← lowest
step  15: loss=1.9548
step  16: loss=1.8011
step  17: loss=2.2463   ← spike (likely finding_review long batch)
step  18: loss=1.6814
step  19: loss=1.6890
step  20: loss=1.3919
step  21: loss=1.5786
step  22: loss=1.6498
step  23: loss=1.7359
step  24: loss=1.5585
```

**Loss trend analysis:**
- Avg loss steps 1-8 (epoch 1): 1.89
- Avg loss steps 9-16 (epoch 2): 1.85
- Avg loss steps 17-24 (epoch 3): 1.68
- Trend: decreasing across epochs ✓
- Spikes at steps 9, 17: expected — these are likely the long `finding_review` cases (BMC-FR-0001 at ~1998 tokens) which have higher cross-entropy due to longer target sequences.

### Observations

- **Loss decreased steadily** across epochs (1.89 → 1.85 → 1.68 average per epoch). Model is learning the task distribution.
- **Loss noise is high** (range 1.05-2.60 within single epoch). Expected with batch_size=1 + diverse 8 task types + small dataset (34 cases). With effective batch = 4, gradient estimates are noisy.
- **Lowest loss 1.0471 at step 14** — model is capable of fitting individual cases well, but generalization across task types is harder.
- **No OOM** with batch_size=1, grad_accum=4, max_seq_length=2048. Peak VRAM 6.77 GB leaves substantial headroom (could fit batch_size=2 for shorter cases, but mixed-length batches caused OOM in initial attempt).
- **First attempt with grad_accum=16 OOM'd** at cross_entropy (2.09 GiB allocation) — root cause: when SFTTrainer encountered the long `finding_review` cases (~2000 tokens), the logits tensor at batch_size=2 × max_seq=2048 × vocab=151936 × fp16 = 1.24 GB forward, ~2.5 GB forward+backward, plus existing KV cache and activations, exceeded free memory. Fix: reduce batch_size to 1, keep effective batch via grad_accum=16 (later reduced to 4 for better logging granularity).
- **Reload test passed** — adapter saves and loads correctly via `PeftModel.from_pretrained()`.
- **Output quality improved visibly** vs base model baseline (10/08):
  - No more ```` ```json ```` markdown fences (clean JSON output)
  - Field names are task-appropriate (`status`, `message`, `evidence_summary`) instead of random (`evaluation`, `findings`)
  - Content correctness improved — sample output for FND-000001 correctly says `"status": "PASS"`, `"Evidence is sufficient"` matching gold label `is_sufficient: true`.
- **Schema compliance still imperfect** — model uses `status`/`message` instead of strict `evidence_review.is_sufficient`. This will be measured quantitatively in task 16/08 benchmark eval.

### Issues encountered

1. **Path mismatch**: `configs/training_config.yaml` vs `training_config.yaml` (notebook expected latter). Fixed via symlink: `ln -s configs/training_config.yaml training_config.yaml`.
2. **OOM on first full run** (batch_size=2, grad_accum=8): Fixed by reducing batch_size=1, grad_accum=4 (later changed from 16 to 4 for better loss logging granularity). Also set `PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True` BEFORE CUDA init (required session restart).
3. **Local adapter not saved to repo**: `local_copy_dir: "./checkpoints/slm-adapter-v0.1"` is relative path, resolved against CWD (`/content/`) instead of `REPO_ROOT`. Adapter actually saved to `/content/checkpoints/`. Fixed by manually copying from Drive to `/content/slm-training/checkpoints/`. **Bug to fix in `scripts/06_finetune.py`**: resolve `local_copy_dir` against `REPO_ROOT`.

### Post-mortem vs target metrics

Baseline (10/08, base model) → Fine-tuned (this run) → Target (16/08 eval):

| Metric | Baseline (10/08) | Fine-tuned (this run, expected) | Target (16/08) |
|---|---|---|---|
| pass_rate | 14.7% (5/34) | TBD (16/08 eval) | > 60% |
| pass_rate (excl. remediation) | 0% (0/29) | TBD | > 50% |
| hard_negative_pass_rate | 0% (0/9) | TBD | > 30% |
| FMT-MISSING-FIELD count | 34 | TBD (expected < 10 based on reload output) | < 5 |
| latency avg | 4.55 s/case | TBD | < 3 s/case |

**Qualitative expectation for 16/08:** pass_rate should improve significantly (visible output quality improvement), but may still fall short of 60% target due to schema field-name mismatches.

### Adapter location

- **Google Drive:** `/content/drive/MyDrive/evvo-slm-checkpoints/slm-adapter-v0.1/` (9 files, ~24 MB total)
- **Local repo (git):** `checkpoints/slm-adapter-v0.1/` (copied from Drive — 9 files, ~24 MB total)
- **Adapter file:** `adapter_model.safetensors` (8.34 MB — small enough for regular git push, no LFS needed)
- **Config file:** `adapter_config.json` (contains LoRA r=8, alpha=16, target_modules)

### Next steps

- **Task 13/08:** Build retrieval index (BM25 or embedding), test on severity/validation/remediation queries.
- **Task 14-15/08:** Wire up report-review PoC pipeline (parser → normalization → retrieval → compact prompt → SLM → JSON → schema validation).
- **Task 16/08:** Compare Base vs Base+RAG vs Fine-tuned vs Fine-tuned+RAG on benchmark_v1. This is where we'll get quantitative pass_rate for the fine-tuned model.

### Bugs to fix in next iteration

1. `scripts/06_finetune.py` line 357: `local_dir = Path(storage_cfg["local_copy_dir"])` should resolve against `REPO_ROOT` to avoid CWD dependency:
   ```python
   local_dir = REPO_ROOT / storage_cfg["local_copy_dir"] if not Path(storage_cfg["local_copy_dir"]).is_absolute() else Path(storage_cfg["local_copy_dir"])
   ```
2. `scripts/06_finetune.py` line 53: `CONFIG_PATH` should default to `configs/training_config.yaml` to match repo layout (currently expects `training_config.yaml` at repo root, requires symlink workaround).
3. `notebooks/06_finetune.ipynb` cell 1, 7, 11, 13: all references to `training_config.yaml` should be `configs/training_config.yaml`.

---

## Run: 2026-08-15 09:14 UTC (SMOKE TEST — PASSED)

- **Model:** Qwen/Qwen2.5-1.5B-Instruct
- **Hardware:** Tesla T4 (15 GB VRAM, Google Colab)
- **Run type:** smoke
- **Cases:** 5 (first 5 of benchmark_v1.jsonl — all `evidence_check`, short sequences)
- **Epochs:** 1
- **Max steps:** 10
- **Final loss:** 1.5839 (step 10)
- **Initial loss:** 1.7223 (step 5)
- **Runtime:** 1.69 min (101.17 s)
- **Peak VRAM:** 6.28 GB / 15 GB
- **Adapter size:** 8.34 MB
- **Reload test:** PASS

### Package versions

```
transformers: 4.46.0
peft:         0.13.2
trl:          0.12.1
datasets:     3.1.0
torch:        2.11.0+cu128
accelerate:   1.14.0
CUDA:         12.8
GPU:          Tesla T4
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
grad_accum: 8   (effective batch = 16, original config before OOM fix)
lr: 2e-4
max_seq_length: 2048
fp16: true
seed: 42
logging_steps: 5
```

### Loss curve

```
step   5: loss=1.7223
step  10: loss=1.5839
```

### Observations

- Smoke test passed — loss decreased 8% in 5 steps, no OOM, reload OK.
- VRAM usage 6.28 GB confirmed batch_size=2 was safe for short sequences (evidence_check cases ~700-1500 tokens).
- However, batch_size=2 caused OOM in full run when encountering long `finding_review` cases (~2000 tokens) — see full training notes above.
- Decision after smoke: proceed to full training. Verdict: correct (full training succeeded with batch_size=1).

---

## Template (copy for new runs)

```markdown
## Run: YYYY-MM-DD HH:MM UTC (SMOKE / FULL)

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