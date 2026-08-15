#!/usr/bin/env python3
"""
Build notebooks/06_finetune.ipynb from scratch using nbformat.

This script is the source of truth for the notebook. Re-run it whenever
the notebook code is updated. It guarantees the .ipynb file has the
correct top-level JSON structure (`{cells, metadata, nbformat}`) instead
of accidentally wrapping the JSON inside a single code cell.

Usage:
    python scripts/build_notebook_06.py
"""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = REPO_ROOT / "notebooks" / "06_finetune.ipynb"


def md(source: str) -> dict:
    return nbf.v4.new_markdown_cell(source)


def code(source: str) -> dict:
    return nbf.v4.new_code_cell(source)


CELL_0_MD = """# 06 — SLM Fine-tuning (LoRA/SFT) on benchmark_v1

**Task 11-12/08 deliverable** — Fine-tune Qwen2.5-1.5B-Instruct with LoRA.

**Status:** Skeleton — actual training is deferred to Colab on 11-12/08.

This notebook:
1. Installs deps (`transformers`, `peft`, `trl`, `datasets`, `pyyaml`).
2. Mounts Google Drive for persistent checkpoint storage.
3. Loads `training_config.yaml` and `data/benchmark/benchmark_v1.jsonl`.
4. Builds chat-formatted training examples (Qwen2.5 chat template).
5. Runs **smoke test** first (5 samples, 1 epoch, 10 steps) — verifies loss decreases + no OOM.
6. Runs **full training** (34 samples, 3 epochs) after smoke passes.
7. Saves adapter to Google Drive + local repo copy.
8. Verifies reload (load base + adapter, generate 1 case).

**Decisions (confirmed 11/08):**
- LoRA r=8, alpha=16, dropout=0.05, target=q/k/v/o_proj
- No quantization, fp16
- 3 epochs (full), 1 epoch (smoke)
- Google Drive for persistent storage

**Colab principles (per plan page 7):**
- No session storage dependency — checkpoints go to Drive.
- Smoke test before full training.
- Record package versions, seed, and config for reproducibility.

**STOP-AFTER-EACH-STEP:** Run cells one at a time. After each `Step N` markdown cell, run the following code cell, then pause for verification before proceeding to Step N+1.
"""

CELL_1_CODE = r'''# ── Configuration ────────────────────────────────────────────────────
# Set RUN_TRAINING = True ONLY on Colab (or any GPU-equipped machine).
# The EVVO VPS is CPU-only — running training there is forbidden.
RUN_TRAINING = False

# Smoke test: 5 samples, 1 epoch, 10 steps. Set False for full run.
# ALWAYS run smoke test first on a fresh Colab session.
SMOKE_TEST = True

# Repo root — auto-resolved when running on Colab after git clone.
# Override below if your repo is at a different path.
import os
from pathlib import Path

# Try common Colab locations
REPO_ROOT = None
for candidate in [
    Path("/content/slm-training"),
    Path("/content/evvo-slm-harness"),
    Path.cwd(),
]:
    if (candidate / "training_config.yaml").exists():
        REPO_ROOT = candidate
        break

if REPO_ROOT is None:
    # Fallback: assume current dir IS the repo root
    REPO_ROOT = Path.cwd()

print(f"RUN_TRAINING = {RUN_TRAINING}")
print(f"SMOKE_TEST   = {SMOKE_TEST}")
print(f"REPO_ROOT    = {REPO_ROOT}")
print(f"Config exists: {(REPO_ROOT / 'training_config.yaml').exists()}")
'''

CELL_2_MD = """## Step 1 — Install dependencies

Install the fine-tuning stack. Run this cell once per Colab session.

**Packages:**
- `transformers` — model + tokenizer
- `peft` — LoRA adapter
- `trl` — SFTTrainer
- `datasets` — HF dataset wrapper
- `pyyaml` — config loader
- `accelerate` — device_map
- `bitsandbytes` — not needed for fp16, but harmless

**After install:** Colab will prompt "Restart session" — accept it, then continue to Step 2.

**STOP** after this cell. Verify all packages installed without error before proceeding.
"""

CELL_3_CODE = r'''# Install deps (run once per Colab session)
!pip install -q -U transformers==4.46.0 peft==0.13.2 trl==0.12.1 datasets==3.1.0 pyyaml accelerate

# Print versions for reproducibility (will be copied to training_log.md)
import transformers, peft, trl, datasets, torch, accelerate
print("=== Package versions ===")
print(f"transformers: {transformers.__version__}")
print(f"peft:         {peft.__version__}")
print(f"trl:          {trl.__version__}")
print(f"datasets:     {datasets.__version__}")
print(f"torch:        {torch.__version__}")
print(f"accelerate:   {accelerate.__version__}")
print(f"CUDA:         {torch.version.cuda}")
print(f"GPU:          {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'NONE'}")
'''

CELL_4_MD = """## Step 2 — Mount Google Drive

Per Colab principle: **no session storage dependency**. Checkpoints must survive session disconnect.

Mount Drive at `/content/drive`. After mount, the checkpoint directory will be:
`/content/drive/MyDrive/evvo-slm-checkpoints/slm-adapter-v0.1/`

**STOP** after this cell. Verify Drive is mounted (you should see "Mounted at /content/drive" and a "MyDrive" folder appear in the file browser).
"""

CELL_5_CODE = r'''# Mount Google Drive
from google.colab import drive
import os
from pathlib import Path

DRIVE_MOUNT = "/content/drive"
DRIVE_CHECKPOINT_DIR = Path("/content/drive/MyDrive/evvo-slm-checkpoints/slm-adapter-v0.1")

if not Path(DRIVE_MOUNT).exists():
    drive.mount(DRIVE_MOUNT)
else:
    print(f"Drive already mounted at {DRIVE_MOUNT}")

# Create checkpoint dir on Drive
DRIVE_CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
print(f"Drive checkpoint dir: {DRIVE_CHECKPOINT_DIR}")
print(f"Drive exists: {DRIVE_CHECKPOINT_DIR.exists()}")
'''

CELL_6_MD = """## Step 3 — Verify repo + load config

If running on Colab, the repo should be cloned from GitHub first:

```python
!git clone https://github.com/trannhatbuilder/slm-training.git /content/slm-training
%cd /content/slm-training
```

If you uploaded the repo folder instead, ensure `REPO_ROOT` (cell 1) points to it.

This cell loads `training_config.yaml` and prints the key parameters.

**STOP** after this cell. Verify:
- Config loaded without error
- `base_model_id` = `Qwen/Qwen2.5-1.5B-Instruct`
- LoRA r=8, alpha=16
- 3 epochs (or 1 if smoke)
"""

CELL_7_CODE = r'''import sys
import yaml
from pathlib import Path

# Add repo root to sys.path so we can import from scripts/
sys.path.insert(0, str(REPO_ROOT))

# Load config
config_path = REPO_ROOT / "training_config.yaml"
with config_path.open(encoding="utf-8") as f:
    config = yaml.safe_load(f)

print("=== Config loaded ===")
print(f"Model: {config['model']['base_model_id']}")
print(f"  dtype: {config['model']['torch_dtype']}")
print()
print(f"LoRA:")
print(f"  r: {config['lora']['r']}")
print(f"  alpha: {config['lora']['alpha']}")
print(f"  dropout: {config['lora']['dropout']}")
print(f"  target_modules: {config['lora']['target_modules']}")
print()
print(f"Training:")
print(f"  epochs: {config['training']['num_train_epochs']}")
print(f"  batch_size: {config['training']['per_device_train_batch_size']}")
print(f"  grad_accum: {config['training']['gradient_accumulation_steps']}")
print(f"  lr: {config['training']['learning_rate']}")
print(f"  max_seq_length: {config['training']['max_seq_length']}")
print(f"  fp16: {config['training']['fp16']}")
print(f"  seed: {config['training']['seed']}")
print()
print(f"Smoke test: {config['smoke_test']['enabled']}")
print(f"  max_samples: {config['smoke_test']['max_samples']}")
print(f"  max_steps: {config['smoke_test']['max_steps']}")
print()
print(f"Drive checkpoint: {config['persistent_storage']['checkpoint_dir']}")
'''

CELL_8_MD = """## Step 4 — Load benchmark + build training examples

Load `data/benchmark/benchmark_v1.jsonl` (34 cases, 8 task types).

Each case is converted to a chat-formatted training string using the Qwen2.5 chat template:
```
<|im_start|>user
{instruction + task_type + input}
<|im_end|>
<|im_start|>assistant
{json.dumps(gold_output)}
<|im_end|>
```

**STOP** after this cell. Verify:
- 34 examples built
- Each example is non-empty
- Sample length is reasonable (1000-5000 chars typical)
"""

CELL_9_CODE = r'''import json
import sys
from pathlib import Path

# Import build_training_examples from the .py mirror
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from importlib import import_module
mod = import_module("06_finetune")

# Load benchmark
benchmark_path = REPO_ROOT / "data" / "benchmark" / "benchmark_v1.jsonl"
cases = mod.load_benchmark(benchmark_path)
print(f"Loaded {len(cases)} cases")

# Task type breakdown
from collections import Counter
by_task = Counter(c["task_type"] for c in cases)
print(f"Task types ({len(by_task)}):")
for tt in sorted(by_task):
    print(f"  {tt:35} {by_task[tt]:3d}")

# Build training examples
examples = mod.build_training_examples(cases)
print(f"\nBuilt {len(examples)} training examples")
print(f"Sample length (chars): min={min(len(e) for e in examples)}, "
      f"max={max(len(e) for e in examples)}, "
      f"avg={sum(len(e) for e in examples)//len(examples)}")

# Preview first example (truncated)
print("\n=== First example (first 500 chars) ===")
print(examples[0][:500])
print("...")
'''

CELL_10_MD = """## Step 5 — Smoke test (run BEFORE full training)

Per Colab principle: **always run smoke test before full training**.

Smoke test:
- 5 samples (first 5 cases)
- 1 epoch
- Max 10 steps
- Verifies loss decreases + no OOM + adapter saves correctly

**Set `RUN_TRAINING = True` and `SMOKE_TEST = True` in cell 1 before running this cell.**

Expected runtime: ~2-3 min on T4.

**STOP** after this cell. Verify:
- Final loss < initial loss
- No OOM error
- Peak VRAM < 14 GB
- Adapter saved to both Drive and local
- Reload test passed
"""

CELL_11_CODE = r'''# Smoke test
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from importlib import import_module
mod = import_module("06_finetune")

# Override module-level flags
mod.RUN_TRAINING = True
mod.SMOKE_TEST = True

# Re-load cases + examples (in case cell 9 was re-run)
benchmark_path = REPO_ROOT / "data" / "benchmark" / "benchmark_v1.jsonl"
cases = mod.load_benchmark(benchmark_path)
examples = mod.build_training_examples(cases)

# Load config (already in `config` variable from cell 7)
# But re-load to ensure fresh state
import yaml
with (REPO_ROOT / "training_config.yaml").open(encoding="utf-8") as f:
    config = yaml.safe_load(f)

# Run training
metrics = mod.run_training(config, cases, examples)

print("\n=== Smoke test complete ===")
print(f"final_loss:    {metrics.get('final_loss')}")
print(f"runtime (s):   {metrics.get('runtime_seconds')}")
print(f"peak VRAM (GB):{metrics.get('peak_vram_gb')}")
print(f"reload passed: {metrics.get('reload_test_passed')}")
print(f"adapter (Drive): {metrics.get('adapter_path_drive')}")
print(f"adapter (local): {metrics.get('adapter_path_local')}")

# Save metrics to data/benchmark/training_metrics.json
metrics_path = REPO_ROOT / "data" / "benchmark" / "training_metrics.json"
metrics_path.parent.mkdir(parents=True, exist_ok=True)
with metrics_path.open("w", encoding="utf-8") as f:
    json.dump(metrics, f, indent=2, ensure_ascii=False)
print(f"\nWrote {metrics_path}")
'''

CELL_12_MD = """## Step 6 — Full training (run AFTER smoke test passes)

Once smoke test verifies the setup works, switch to full training:
- 34 samples (all cases)
- 3 epochs
- ~50 steps total (34 / 16 effective batch × 3 epochs ≈ 6.4 → ceil to 7 batches × 3 = 21 steps; actual may be more due to packing=False)

**Before running:** Set `SMOKE_TEST = False` in cell 1, then re-run cell 1.

Expected runtime: ~10-20 min on T4 (depending on sequence lengths).

**STOP** after this cell. Verify:
- Final loss significantly lower than initial (target: < 1.0)
- Loss curve shows steady decrease (no divergence)
- No OOM
- Peak VRAM < 14 GB
- Adapter saved to Drive
- Reload test passed
"""

CELL_13_CODE = r'''# Full training
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from importlib import import_module
mod = import_module("06_finetune")

# Override module-level flags — SMOKE_TEST = False for full run
mod.RUN_TRAINING = True
mod.SMOKE_TEST = False

# Re-load cases + examples
benchmark_path = REPO_ROOT / "data" / "benchmark" / "benchmark_v1.jsonl"
cases = mod.load_benchmark(benchmark_path)
examples = mod.build_training_examples(cases)

# Load config
import yaml
with (REPO_ROOT / "training_config.yaml").open(encoding="utf-8") as f:
    config = yaml.safe_load(f)

# Run training
metrics = mod.run_training(config, cases, examples)

print("\n=== Full training complete ===")
print(f"final_loss:    {metrics.get('final_loss')}")
print(f"runtime (s):   {metrics.get('runtime_seconds')}")
print(f"peak VRAM (GB):{metrics.get('peak_vram_gb')}")
print(f"reload passed: {metrics.get('reload_test_passed')}")
print(f"adapter (Drive): {metrics.get('adapter_path_drive')}")
print(f"adapter (local): {metrics.get('adapter_path_local')}")

# Save metrics
metrics_path = REPO_ROOT / "data" / "benchmark" / "training_metrics.json"
metrics_path.parent.mkdir(parents=True, exist_ok=True)
with metrics_path.open("w", encoding="utf-8") as f:
    json.dump(metrics, f, indent=2, ensure_ascii=False)
print(f"\nWrote {metrics_path}")

# Print loss history
print("\n=== Loss history ===")
for entry in metrics.get("loss_history", []):
    print(f"  step {entry['step']:3d}: loss={entry['loss']:.4f}")
'''

CELL_14_MD = """## Step 7 — Verify adapter on disk + download

Verify:
1. Adapter files exist on Drive
2. Adapter files exist locally (in `./checkpoints/slm-adapter-v0.1/`)
3. List file sizes (adapter_model.safetensors should be ~10-20 MB for r=8 on 1.5B model)

**For git push:** the local `./checkpoints/slm-adapter-v0.1/` directory will be pushed to GitHub. Verify it contains only the adapter (not the full model).

**STOP** after this cell. Verify:
- adapter_model.safetensors exists and is < 50 MB
- adapter_config.json exists
- Both Drive and local copies present
"""

CELL_15_CODE = r'''# Verify adapter on disk
from pathlib import Path
import os

print("=== Drive copy ===")
drive_dir = Path("/content/drive/MyDrive/evvo-slm-checkpoints/slm-adapter-v0.1")
if drive_dir.exists():
    for f in sorted(drive_dir.iterdir()):
        size_mb = f.stat().st_size / 1024 / 1024
        print(f"  {f.name:40} {size_mb:8.2f} MB")
else:
    print(f"  NOT FOUND: {drive_dir}")

print("\n=== Local copy (for git push) ===")
local_dir = REPO_ROOT / "checkpoints" / "slm-adapter-v0.1"
if local_dir.exists():
    for f in sorted(local_dir.iterdir()):
        size_mb = f.stat().st_size / 1024 / 1024
        print(f"  {f.name:40} {size_mb:8.2f} MB")
else:
    print(f"  NOT FOUND: {local_dir}")

# Sanity check: adapter_model.safetensors should be < 50 MB
adapter_file = local_dir / "adapter_model.safetensors"
if adapter_file.exists():
    size_mb = adapter_file.stat().st_size / 1024 / 1024
    print(f"\nAdapter size: {size_mb:.2f} MB")
    if size_mb > 50:
        print("  WARNING: adapter is > 50 MB — consider git-lfs")
    else:
        print("  OK: small enough for regular git push")
'''

CELL_16_MD = """## Step 8 — Final summary + training log

Print final summary. Manually copy this output to `docs/training_log.md`:

```markdown
## Run: YYYY-MM-DD HH:MM UTC

- **Model:** Qwen/Qwen2.5-1.5B-Instruct
- **Hardware:** Tesla T4 (15 GB VRAM)
- **Run type:** smoke | full
- **Cases:** N
- **Epochs:** N
- **Final loss:** X.XXX
- **Runtime:** X.X min
- **Peak VRAM:** X.XX GB
- **Adapter size:** X.X MB
- **Reload test:** PASS | FAIL
```

Also print the loss curve (paste into training_log.md as a code block).

**STOP** after this cell. Copy the summary to `docs/training_log.md` and commit.
"""

CELL_17_CODE = r'''# Final summary
import json
from pathlib import Path
from datetime import datetime

metrics_path = REPO_ROOT / "data" / "benchmark" / "training_metrics.json"
if metrics_path.exists():
    with metrics_path.open() as f:
        metrics = json.load(f)

    print("=" * 60)
    print("TRAINING RUN SUMMARY")
    print("=" * 60)
    print(f"Model:          {metrics.get('model_id')}")
    print(f"Run type:       {'smoke' if metrics.get('smoke_test') else 'full'}")
    print(f"Ran at:         {metrics.get('ran_at')}")
    print(f"Cases:          {metrics.get('case_count')}")
    print(f"Epochs:         {metrics.get('epochs')}")
    print(f"Final loss:     {metrics.get('final_loss')}")
    print(f"Runtime (min):  {metrics.get('runtime_seconds', 0) / 60:.2f}")
    print(f"Peak VRAM (GB): {metrics.get('peak_vram_gb')}")
    print(f"Reload passed:  {metrics.get('reload_test_passed')}")
    print()
    print("LoRA config:")
    for k, v in metrics.get('lora_config', {}).items():
        print(f"  {k}: {v}")
    print()
    print("Training config:")
    for k, v in metrics.get('training_config', {}).items():
        print(f"  {k}: {v}")
    print()
    print("Loss curve:")
    for entry in metrics.get('loss_history', []):
        print(f"  step {entry['step']:3d}: loss={entry['loss']:.4f}")
    print()
    print(f"Adapter (Drive): {metrics.get('adapter_path_drive')}")
    print(f"Adapter (local): {metrics.get('adapter_path_local')}")
    print("=" * 60)
else:
    print(f"Metrics not found at {metrics_path}")
    print("Run cell 11 (smoke) or cell 13 (full) first.")
'''

CELL_18_MD = """## Next steps

After training completes:

1. **Copy summary** from cell 17 to `docs/training_log.md`.
2. **Commit + push** to GitHub:
   ```bash
   git add training_config.yaml scripts/06_finetune.py scripts/build_notebook_06.py \\
           notebooks/06_finetune.ipynb docs/training_log.md \\
           checkpoints/slm-adapter-v0.1/ data/benchmark/training_metrics.json
   git commit -m "task 11-12/08: SLM adapter v0.1 (LoRA r=8, 3 epochs)"
   git push
   ```
3. **Verify on local machine** (Windows):
   - `git pull`
   - Check `checkpoints/slm-adapter-v0.1/adapter_config.json` — should show r=8, alpha=16
4. **Proceed to task 13/08** — retrieval index + retrieval_eval.

**If reload test FAILED:** the adapter is corrupted. Re-run training from cell 13. Common causes:
- Drive write interrupted (check Drive quota)
- `gradient_checkpointing=True` + `use_cache=True` conflict (set `use_cache=False` — already done in script)
- OOM during reload (use `device_map='auto'` — already done)
"""


def build_notebook() -> nbf.NotebookNode:
    """Assemble all cells into a notebook."""
    nb = nbf.v4.new_notebook()
    nb.metadata = {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3",
        },
        "language_info": {
            "name": "python",
            "version": "3.10.0",
            "mimetype": "text/x-python",
            "file_extension": ".py",
            "pygments_lexer": "ipython3",
            "codemirror_mode": {"name": "ipython", "version": 3},
        },
    }
    nb.nbformat = 4
    nb.nbformat_minor = 5

    cells = [
        md(CELL_0_MD),
        code(CELL_1_CODE),
        md(CELL_2_MD),
        code(CELL_3_CODE),
        md(CELL_4_MD),
        code(CELL_5_CODE),
        md(CELL_6_MD),
        code(CELL_7_CODE),
        md(CELL_8_MD),
        code(CELL_9_CODE),
        md(CELL_10_MD),
        code(CELL_11_CODE),
        md(CELL_12_MD),
        code(CELL_13_CODE),
        md(CELL_14_MD),
        code(CELL_15_CODE),
        md(CELL_16_MD),
        code(CELL_17_CODE),
        md(CELL_18_MD),
    ]
    nb.cells = cells
    return nb


def main() -> int:
    print(f"Building {OUTPUT_PATH} ...")
    nb = build_notebook()

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        nbf.write(nb, f)

    # Verify
    import json
    with OUTPUT_PATH.open() as f:
        loaded = json.load(f)
    n_code = sum(1 for c in loaded["cells"] if c["cell_type"] == "code")
    n_md = sum(1 for c in loaded["cells"] if c["cell_type"] == "markdown")
    print(f"OK: {len(loaded['cells'])} cells ({n_code} code + {n_md} markdown)")
    print(f"nbformat: {loaded['nbformat']}.{loaded['nbformat_minor']}")

    # Syntax check all code cells (skip cells with IPython shell magic `!`)
    import ast
    errors = 0
    for i, c in enumerate(loaded["cells"]):
        if c["cell_type"] != "code":
            continue
        src = "".join(c["source"])
        # Strip lines starting with `!` (IPython shell magic, not valid Python)
        lines = [ln for ln in src.split("\n") if not ln.lstrip().startswith("!")]
        clean_src = "\n".join(lines)
        try:
            ast.parse(clean_src)
        except SyntaxError as e:
            print(f"  cell {i}: SYNTAX ERROR: {e}")
            errors += 1
    print(f"Syntax errors: {errors}")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())