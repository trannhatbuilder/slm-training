#!/usr/bin/env python3
"""
06 — SLM Fine-tuning (LoRA/SFT) on benchmark_v1
================================================

Task 11-12/08 deliverable — Fine-tune Qwen2.5-1.5B-Instruct with LoRA.

This is the .py mirror of `notebooks/06_finetune.ipynb`, provided so the
notebook's code can be run via `python` directly (without Jupyter).

Status: Skeleton — actual training is deferred to Colab on 11-12/08
(per Q2 = option a). The EVVO VPS is CPU-only and must not be used for
training.

Usage
-----
Local (stub, no torch needed):
    python scripts/06_finetune.py

Colab (real run, GPU needed):
    1. Set RUN_TRAINING = True below.
    2. Set SMOKE_TEST = True for smoke test, False for full run.
    3. Mount Google Drive (see notebook cell 3).
    4. Upload this script (or paste into a Colab cell) and run.

Outputs
-------
- `./checkpoints/slm-adapter-v0.1/` — local adapter copy
- `/content/drive/MyDrive/evvo-slm-checkpoints/slm-adapter-v0.1/` — Drive copy
- `docs/training_log.md` — append training metadata, loss curve, runtime
- `data/benchmark/training_metrics.json` — machine-readable training log
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ── Configuration ────────────────────────────────────────────────────
# Set RUN_TRAINING = True ONLY on Colab (or any GPU-equipped machine).
# The EVVO VPS is CPU-only — running training there is forbidden.
RUN_TRAINING: bool = False

# Smoke test: 5 samples, 1 epoch, 10 steps. Set False for full run.
SMOKE_TEST: bool = True

# Config path (loaded on Colab). Falls back to hardcoded defaults below
# if yaml is unavailable or the file is missing.
CONFIG_PATH: str = "training_config.yaml"

# Hardcoded defaults (mirror training_config.yaml — used when yaml missing)
DEFAULTS: dict = {
    "model": {
        "base_model_id": "Qwen/Qwen2.5-1.5B-Instruct",
        "torch_dtype": "float16",
        "device_map": "auto",
    },
    "lora": {
        "r": 8,
        "alpha": 16,
        "dropout": 0.05,
        "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj"],
        "bias": "none",
        "task_type": "CAUSAL_LM",
    },
    "training": {
        "output_dir": "./checkpoints/slm-adapter-v0.1",
        "num_train_epochs": 3,
        "per_device_train_batch_size": 2,
        "gradient_accumulation_steps": 8,
        "learning_rate": 2e-4,
        "lr_scheduler_type": "cosine",
        "warmup_ratio": 0.03,
        "max_seq_length": 2048,
        "logging_steps": 5,
        "save_steps": 25,
        "save_total_limit": 3,
        "fp16": True,
        "bf16": False,
        "gradient_checkpointing": True,
        "optim": "adamw_torch",
        "seed": 42,
        "report_to": "none",
    },
    "smoke_test": {
        "enabled": True,
        "max_samples": 5,
        "num_train_epochs": 1,
        "max_steps": 10,
    },
    "data": {
        "benchmark_path": "data/benchmark/benchmark_v1.jsonl",
        "train_split": 1.0,
    },
    "persistent_storage": {
        "type": "google_drive",
        "drive_mount": "/content/drive",
        "checkpoint_dir": "/content/drive/MyDrive/evvo-slm-checkpoints/slm-adapter-v0.1",
        "local_copy_dir": "./checkpoints/slm-adapter-v0.1",
    },
}

# ── Repo paths ──────────────────────────────────────────────────────
REPO_ROOT: Path = Path(__file__).resolve().parent.parent
BENCHMARK_PATH: Path = REPO_ROOT / "data" / "benchmark" / "benchmark_v1.jsonl"
METRICS_PATH: Path = REPO_ROOT / "data" / "benchmark" / "training_metrics.json"


def main() -> int:
    print(f"RUN_TRAINING = {RUN_TRAINING}")
    print(f"SMOKE_TEST   = {SMOKE_TEST}")
    print(f"Config       = {CONFIG_PATH}")
    print()

    # ── 1. Load config ──────────────────────────────────────────────
    config = load_config()
    print(f"Loaded config: model_id={config['model']['base_model_id']}")
    print(f"  LoRA: r={config['lora']['r']}, alpha={config['lora']['alpha']}, "
          f"target={config['lora']['target_modules']}")
    print(f"  Training: epochs={config['training']['num_train_epochs']}, "
          f"bs={config['training']['per_device_train_batch_size']}, "
          f"accum={config['training']['gradient_accumulation_steps']}")
    print(f"  Drive: {config['persistent_storage']['checkpoint_dir']}")
    print()

    # ── 2. Load dataset ─────────────────────────────────────────────
    cases = load_benchmark(BENCHMARK_PATH)
    print(f"Loaded {len(cases)} cases from {BENCHMARK_PATH.name}")
    by_task: dict[str, int] = {}
    for c in cases:
        by_task[c["task_type"]] = by_task.get(c["task_type"], 0) + 1
    print(f"  task types: {len(by_task)}")
    for tt in sorted(by_task):
        print(f"    {tt:35} {by_task[tt]:3d}")
    print()

    # ── 3. Build training examples ──────────────────────────────────
    examples = build_training_examples(cases)
    print(f"Built {len(examples)} training examples")
    if examples:
        ex = examples[0]
        print(f"  Sample length (chars): {len(ex)}")
        print(f"  Sample first 200 chars: {ex[:200]}...")
    print()

    # ── 4. Stub gate ────────────────────────────────────────────────
    if not RUN_TRAINING:
        print("[stub] RUN_TRAINING=False — would now:")
        print("  - Load model + tokenizer")
        print("  - Apply LoRA config")
        print("  - Initialize SFTTrainer")
        print("  - Run training (smoke or full)")
        print("  - Save adapter to Drive + local")
        print("  - Reload test (load base + adapter, generate 1 case)")
        print()
        print("To run for real on Colab:")
        print("  1. Set RUN_TRAINING = True")
        print("  2. Set SMOKE_TEST = True for smoke test, False for full run")
        print("  3. Mount Google Drive first")
        return 0

    # ── 5. Real training (Colab only) ──────────────────────────────
    metrics = run_training(config, cases, examples)
    print(f"\nTraining complete.")
    print(f"  final loss: {metrics.get('final_loss')}")
    print(f"  runtime (s): {metrics.get('runtime_seconds')}")
    print(f"  peak VRAM (GB): {metrics.get('peak_vram_gb')}")

    # Save metrics
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with METRICS_PATH.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"\nWrote {METRICS_PATH}")

    return 0


# ── Functions (module level — keeps them importable for tests) ──────


def load_config() -> dict:
    """Load config from yaml; fall back to DEFAULTS if unavailable."""
    try:
        import yaml
        config_path = REPO_ROOT / CONFIG_PATH
        if config_path.exists():
            with config_path.open(encoding="utf-8") as f:
                cfg = yaml.safe_load(f)
            print(f"[config] loaded from {config_path}")
            return cfg
        print(f"[config] {config_path} not found, using DEFAULTS")
        return DEFAULTS
    except ImportError:
        print("[config] PyYAML not installed, using DEFAULTS")
        return DEFAULTS


def load_benchmark(path: Path) -> list[dict]:
    """Load all cases from a JSONL benchmark file."""
    cases: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def build_training_examples(cases: list[dict]) -> list[str]:
    """Convert benchmark cases to chat-formatted training strings.

    Each example follows Qwen2.5 chat template:
        <|im_start|>user
        {instruction + task_type + input}
        <|im_end|>
        <|im_start|>assistant
        {json.dumps(gold_output)}
        <|im_end|>
    """
    examples: list[str] = []
    for case in cases:
        instruction = case.get("instruction", "")
        task_type = case.get("task_type", "")
        input_data = case.get("input", {})
        gold_output = case.get("gold_output", {})

        payload = json.dumps(input_data, ensure_ascii=False, indent=2)
        output_json = json.dumps(gold_output, ensure_ascii=False, indent=2)

        user_msg = (
            f"You are a pentest report reviewer. Complete the following task.\n\n"
            f"Task type: {task_type}\n"
            f"Instruction: {instruction}\n\n"
            f"Input:\n{payload}\n\n"
            f"Return ONLY valid JSON matching the output schema for this task type. "
            f"Do not include markdown fences or commentary."
        )
        assistant_msg = output_json

        text = (
            f"<|im_start|>user\n{user_msg}<|im_end|>\n"
            f"<|im_start|>assistant\n{assistant_msg}<|im_end|>"
        )
        examples.append(text)
    return examples


def run_training(config: dict, cases: list[dict], examples: list[str]) -> dict:
    """Run LoRA/SFT training. Returns metrics dict.

    Expected steps:
      1. Load model + tokenizer (fp16, device_map=auto)
      2. Tokenize examples (with max_seq_length truncation)
      3. Apply LoRA config via PEFT
      4. Init SFTTrainer with TrainingArguments
      5. trainer.train()
      6. Save adapter to Drive + local
      7. Reload test (load base + adapter, generate 1 case)
      8. Collect metrics (loss curve, runtime, peak VRAM)
    """
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import LoraConfig, get_peft_model, TaskType
    from trl import SFTTrainer, SFTConfig
    from datasets import Dataset

    t_start = datetime.now(timezone.utc)

    # ── 1. Apply smoke test overrides ───────────────────────────────
    if SMOKE_TEST:
        smoke = config.get("smoke_test", {})
        max_samples = smoke.get("max_samples", 5)
        examples = examples[:max_samples]
        cases = cases[:max_samples]
        print(f"[smoke] using {len(examples)} samples, 1 epoch, max 10 steps")

    # ── 2. Load model + tokenizer ──────────────────────────────────
    model_cfg = config["model"]
    model_id = model_cfg["base_model_id"]
    print(f"Loading {model_id} ...")
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=False)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=False,
    )
    model.config.use_cache = False  # required for gradient_checkpointing

    # ── 3. Apply LoRA ──────────────────────────────────────────────
    lora_cfg = config["lora"]
    peft_config = LoraConfig(
        r=lora_cfg["r"],
        lora_alpha=lora_cfg["alpha"],
        lora_dropout=lora_cfg["dropout"],
        target_modules=lora_cfg["target_modules"],
        bias=lora_cfg.get("bias", "none"),
        task_type=TaskType.CAUSAL_LM,
    )

    # ── 4. Build HF dataset ────────────────────────────────────────
    ds = Dataset.from_dict({"text": examples})

    # ── 5. Setup SFTTrainer ────────────────────────────────────────
    train_cfg = config["training"]
    sft_config = SFTConfig(
        output_dir=train_cfg["output_dir"],
        num_train_epochs=(
            config["smoke_test"]["num_train_epochs"] if SMOKE_TEST
            else train_cfg["num_train_epochs"]
        ),
        per_device_train_batch_size=train_cfg["per_device_train_batch_size"],
        gradient_accumulation_steps=train_cfg["gradient_accumulation_steps"],
        learning_rate=train_cfg["learning_rate"],
        lr_scheduler_type=train_cfg["lr_scheduler_type"],
        warmup_ratio=train_cfg["warmup_ratio"],
        max_seq_length=train_cfg["max_seq_length"],
        logging_steps=train_cfg["logging_steps"],
        save_steps=train_cfg["save_steps"],
        save_total_limit=train_cfg["save_total_limit"],
        fp16=train_cfg["fp16"],
        bf16=train_cfg["bf16"],
        gradient_checkpointing=train_cfg["gradient_checkpointing"],
        optim=train_cfg["optim"],
        seed=train_cfg["seed"],
        report_to=train_cfg["report_to"],
        max_steps=(
            config["smoke_test"]["max_steps"] if SMOKE_TEST else -1
        ),
        dataset_text_field="text",
        packing=False,
    )

    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=ds,
        peft_config=peft_config,
        processing_class=tokenizer,
    )

    # ── 6. Train ───────────────────────────────────────────────────
    print("Starting training...")
    train_result = trainer.train()
    print("Training complete.")

    # ── 7. Save adapter ────────────────────────────────────────────
    storage_cfg = config["persistent_storage"]
    drive_dir = Path(storage_cfg["checkpoint_dir"])
    local_dir = Path(storage_cfg["local_copy_dir"])

    # Drive (primary)
    try:
        drive_dir.mkdir(parents=True, exist_ok=True)
        trainer.model.save_pretrained(drive_dir)
        tokenizer.save_pretrained(drive_dir)
        print(f"[save] adapter saved to Drive: {drive_dir}")
    except Exception as e:
        print(f"[save] Drive save failed: {e}")

    # Local (for git push)
    local_dir.mkdir(parents=True, exist_ok=True)
    trainer.model.save_pretrained(local_dir)
    tokenizer.save_pretrained(local_dir)
    print(f"[save] adapter saved to local: {local_dir}")

    # ── 8. Reload test ─────────────────────────────────────────────
    reload_ok = reload_test(model_id, local_dir, cases[0])

    # ── 9. Collect metrics ─────────────────────────────────────────
    t_end = datetime.now(timezone.utc)
    runtime_seconds = (t_end - t_start).total_seconds()

    # Peak VRAM
    peak_vram_gb = 0.0
    if torch.cuda.is_available():
        peak_vram_gb = round(torch.cuda.max_memory_allocated() / 1e9, 2)

    # Loss history
    loss_history = [
        {"step": log["step"], "loss": log.get("loss")}
        for log in trainer.state.log_history
        if "loss" in log
    ]
    final_loss = loss_history[-1]["loss"] if loss_history else None

    return {
        "model_id": model_id,
        "smoke_test": SMOKE_TEST,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "environment": "google_colab",
        "case_count": len(cases),
        "epochs": (
            config["smoke_test"]["num_train_epochs"] if SMOKE_TEST
            else train_cfg["num_train_epochs"]
        ),
        "final_loss": final_loss,
        "loss_history": loss_history,
        "runtime_seconds": round(runtime_seconds, 2),
        "peak_vram_gb": peak_vram_gb,
        "adapter_path_drive": str(drive_dir),
        "adapter_path_local": str(local_dir),
        "reload_test_passed": reload_ok,
        "lora_config": {
            "r": lora_cfg["r"],
            "alpha": lora_cfg["alpha"],
            "dropout": lora_cfg["dropout"],
            "target_modules": lora_cfg["target_modules"],
        },
        "training_config": {
            "batch_size": train_cfg["per_device_train_batch_size"],
            "grad_accum": train_cfg["gradient_accumulation_steps"],
            "lr": train_cfg["learning_rate"],
            "max_seq_length": train_cfg["max_seq_length"],
            "fp16": train_cfg["fp16"],
            "seed": train_cfg["seed"],
        },
    }


def reload_test(model_id: str, adapter_path: Path, sample_case: dict) -> bool:
    """Verify adapter reloads: load base + adapter, generate 1 case."""
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForCausalLM
        from peft import PeftModel

        print(f"[reload] loading base {model_id} ...")
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        base_model = AutoModelForCausalLM.from_pretrained(
            model_id, torch_dtype=torch.float16, device_map="auto",
        )

        print(f"[reload] loading adapter from {adapter_path} ...")
        model = PeftModel.from_pretrained(base_model, str(adapter_path))
        model.eval()

        # Build prompt from sample case
        instruction = sample_case.get("instruction", "")
        task_type = sample_case.get("task_type", "")
        input_data = sample_case.get("input", {})
        payload = json.dumps(input_data, ensure_ascii=False, indent=2)
        prompt = (
            f"You are a pentest report reviewer. Complete the following task.\n\n"
            f"Task type: {task_type}\n"
            f"Instruction: {instruction}\n\n"
            f"Input:\n{payload}\n\n"
            f"Return ONLY valid JSON matching the output schema for this task type."
        )

        messages = [{"role": "user", "content": prompt}]
        inputs = tokenizer.apply_chat_template(
            messages, return_tensors="pt", add_generation_prompt=True,
        ).to(model.device)

        with torch.no_grad():
            output_ids = model.generate(
                inputs, max_new_tokens=512, do_sample=False, temperature=1.0,
            )
        generated = tokenizer.decode(
            output_ids[0][inputs.shape[1]:], skip_special_tokens=True,
        )
        print(f"[reload] generated {len(generated)} chars")
        print(f"[reload] preview: {generated[:200]}")
        return True
    except Exception as e:
        print(f"[reload] FAILED: {e}")
        return False


if __name__ == "__main__":
    sys.exit(main())