#!/usr/bin/env python3
"""
08 — Interactive Chat with SLM
==============================
Type a finding number (1-5) and a task type to get the model's response.
This lets you interact with the trained model conversationally.

Usage on VPS (CPU-only, 8GB RAM):
    cd slm-training
    source .venv/bin/activate
    python scripts/08_chat.py

Options:
    --no-adapter    Run with base model only (no LoRA)
    --max-tokens N  Max tokens to generate (default: 1024)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

# ── Repo paths ───────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_PATH = REPO_ROOT / "data" / "benchmark" / "benchmark_v1.jsonl"
ADAPTER_PATH = REPO_ROOT / "checkpoints" / "slm-adapter-v0.1"
BASE_MODEL_ID = "Qwen/Qwen2.5-1.5B-Instruct"

# ── Finding definitions ──────────────────────────────────────────────
# These are the 5 findings that were used in training.
FINDINGS = {
    "1": {"id": "FND-000001", "title": "Hardcoded RabbitMQ Credentials in Mobile Application"},
    "2": {"id": "FND-000002", "title": "Use of Symmetric JWT Signing Algorithm (HS256)"},
    "3": {"id": "FND-000003", "title": "Root Detection Not Implemented"},
    "4": {"id": "FND-000004", "title": "Weak SSL Pinning Implementation"},
    "5": {"id": "FND-000005", "title": "Email Enumeration Possible During User Registration"},
}

# Task types available per finding (from benchmark_v1.jsonl)
TASK_TYPES = [
    ("evidence_check",        "Check if exploitation evidence supports the vulnerability claim"),
    ("finding_review",       "Review the finding quality and completeness"),
    ("severity_review",      "Review if severity rating is appropriate"),
    ("remediation_review",   "Review if remediation advice is adequate"),
    ("false_positive_detection", "Detect if this is a false positive from scanner"),
]


def load_benchmark(path: Path) -> list[dict]:
    """Load benchmark cases from JSONL file."""
    cases = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def build_index(cases: list[dict]) -> dict[str, dict]:
    """Build a lookup index: (finding_id, task_type) -> case dict."""
    index = {}
    for case in cases:
        fid = case.get("input", {}).get("finding_id", "")
        tt = case.get("task_type", "")
        key = f"{fid}|{tt}"
        index[key] = case
    return index


def load_model_and_tokenizer(adapter_path: Path):
    """Load base model + LoRA adapter in float32 on CPU."""
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel

    print(f"[1/3] Loading tokenizer from {BASE_MODEL_ID} ...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, trust_remote_code=False)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print(f"[2/3] Loading base model in float32 on CPU (takes ~2 min) ...")
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        torch_dtype=torch.float32,
        device_map="cpu",
        trust_remote_code=False,
    )

    print(f"[3/3] Loading LoRA adapter from {adapter_path} ...")
    model = PeftModel.from_pretrained(base_model, str(adapter_path))
    model.eval()

    return model, tokenizer


def load_base_only():
    """Load base model WITHOUT LoRA adapter."""
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM

    print(f"[1/2] Loading tokenizer from {BASE_MODEL_ID} ...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, trust_remote_code=False)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print(f"[2/2] Loading base model in float32 on CPU (takes ~2 min) ...")
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        torch_dtype=torch.float32,
        device_map="cpu",
        trust_remote_code=False,
    )
    model.eval()
    return model, tokenizer


def generate_response(model, tokenizer, case: dict, max_new_tokens: int = 1024) -> str:
    """Generate model output for a single case. Returns the generated text."""
    import torch

    # Build prompt exactly like training format (06_finetune.py)
    instruction = case.get("instruction", "")
    task_type = case.get("task_type", "")
    input_data = case.get("input", {})
    payload = json.dumps(input_data, ensure_ascii=False, indent=2)

    user_msg = (
        f"You are a pentest report reviewer. Complete the following task.\n\n"
        f"Task type: {task_type}\n"
        f"Instruction: {instruction}\n\n"
        f"Input:\n{payload}\n\n"
        f"Return ONLY valid JSON matching the output schema for this task type. "
        f"Do not include markdown fences or commentary."
    )

    # Manual chat template (same as 07_inference_test.py)
    chat_text = (
        f"<|im_start|>user\n{user_msg}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )
    input_ids = tokenizer(chat_text, return_tensors="pt")["input_ids"]
    input_length = input_ids.shape[1]

    print(f"  Generating ... (input: {input_length} tokens)", end="", flush=True)
    t0 = time.time()

    with torch.no_grad():
        output_ids = model.generate(
            input_ids,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=1.0,
        )

    gen_time = time.time() - t0
    generated = tokenizer.decode(
        output_ids[0][input_length:], skip_special_tokens=True,
    )
    print(f" done ({gen_time:.1f}s, {len(generated)} chars)")
    return generated


def pretty_print_json(text: str) -> None:
    """Try to parse and pretty-print JSON. Falls back to raw text."""
    cleaned = text.strip()
    # Strip markdown fences if present
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(lines[1:])
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
        print(json.dumps(parsed, indent=2, ensure_ascii=False))
    except json.JSONDecodeError:
        print(text)


def print_menu() -> None:
    """Print the interactive menu."""
    print()
    print("=" * 60)
    print("  SLM Interactive Chat")
    print("=" * 60)
    print()
    print("  Findings (type number to select):")
    for num, info in FINDINGS.items():
        print(f"    [{num}] {info['id']} - {info['title']}")
    print()
    print("  Task types (type letter to select):")
    for i, (tt, desc) in enumerate(TASK_TYPES, 1):
        letter = chr(96 + i)  # a, b, c, d, e
        print(f"    [{letter}] {tt:35} - {desc}")
    print()
    print("  Commands:")
    print("    [1a]  = Finding 1 + evidence_check (quick combo)")
    print("    gold  = Show gold output for last query")
    print("    all   = Run all task types for a finding (e.g. 'all 1')")
    print("    quit  = Exit")
    print("    help  = Show this menu")
    print("=" * 60)


def main() -> int:
    parser = argparse.ArgumentParser(description="SLM Interactive Chat")
    parser.add_argument("--no-adapter", action="store_true", help="Use base model only (no LoRA)")
    parser.add_argument("--max-tokens", type=int, default=1024, help="Max tokens to generate")
    args = parser.parse_args()

    # Validate paths
    if not BENCHMARK_PATH.exists():
        print(f"ERROR: Benchmark file not found: {BENCHMARK_PATH}")
        return 1

    adapter_ok = ADAPTER_PATH.exists()
    if not args.no_adapter and not adapter_ok:
        print(f"ERROR: Adapter not found at {ADAPTER_PATH}")
        print(f"  Use --no-adapter to run with base model only.")
        return 1

    # Load benchmark and build index
    print(f"Loading benchmark from {BENCHMARK_PATH.name} ...")
    all_cases = load_benchmark(BENCHMARK_PATH)
    index = build_index(all_cases)
    print(f"Indexed {len(all_cases)} cases, {len(index)} unique (finding, task) pairs")

    # Load model
    print()
    if args.no_adapter:
        print("[--no-adapter] Loading BASE MODEL ONLY (no LoRA adapter)")
        model, tokenizer = load_base_only()
    else:
        model, tokenizer = load_model_and_tokenizer(ADAPTER_PATH)

    print("\nModel loaded successfully!\n")

    last_case = None  # Track last queried case for 'gold' command

    # ── Interactive loop ──
    print_menu()

    while True:
        try:
            user_input = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd in ("quit", "exit", "q"):
            print("Bye!")
            break

        if cmd == "help":
            print_menu()
            continue

        if cmd == "gold":
            if last_case is None:
                print("  No previous query. Run a finding first.")
                continue
            gold = last_case.get("gold_output", {})
            print(f"\n  Gold output for {last_case.get('input',{}).get('finding_id','?')} | {last_case.get('task_type','?')}:")
            print("  " + "-" * 50)
            print("  " + json.dumps(gold, indent=2, ensure_ascii=False).replace("\n", "\n  "))
            print("  " + "-" * 50)
            continue

        # Parse 'all N' command: run all task types for finding N
        if cmd.startswith("all "):
            finding_num = cmd.split()[-1].strip()
            if finding_num not in FINDINGS:
                print(f"  Invalid finding number. Choose 1-5.")
                continue
            fid = FINDINGS[finding_num]["id"]
            print(f"\n{'='*60}")
            print(f"  Running ALL task types for {FINDINGS[finding_num]['title']}")
            print(f"{'='*60}")
            for tt, desc in TASK_TYPES:
                key = f"{fid}|{tt}"
                case = index.get(key)
                if case is None:
                    print(f"  [SKIP] {tt:35} - not in benchmark")
                    continue
                print(f"\n  --- {tt} ---")
                print(f"  {desc}")
                generated = generate_response(model, tokenizer, case, args.max_tokens)
                print(f"  Model output:")
                print("  " + "-" * 50)
                for line in generated.split("\n"):
                    print(f"  {line}")
                print("  " + "-" * 50)
            last_case = case  # save last for 'gold' command
            continue

        # Parse combo input like '1a', '3c', '5b' (finding + task)
        # Or just a number to show finding info, or task letter
        if len(cmd) >= 2 and cmd[0] in FINDINGS and cmd[1] in "abcde":
            finding_num = cmd[0]
            task_letter = cmd[1]
            task_idx = ord(task_letter) - ord("a")
            if task_idx >= len(TASK_TYPES):
                print(f"  Invalid task letter. Choose a-e.")
                continue

            fid = FINDINGS[finding_num]["id"]
            tt = TASK_TYPES[task_idx][0]
            desc = TASK_TYPES[task_idx][1]

            key = f"{fid}|{tt}"
            case = index.get(key)
            if case is None:
                print(f"  No benchmark case found for {fid} + {tt}")
                print(f"  Available task types for this finding:")
                for k in index:
                    if k.startswith(fid + "|"):
                        print(f"    - {k.split('|')[1]}")
                continue

            print(f"\n{'='*60}")
            print(f"  {FINDINGS[finding_num]['id']}: {FINDINGS[finding_num]['title']}")
            print(f"  Task: {tt}")
            print(f"  {desc}")
            print(f"{'='*60}")

            generated = generate_response(model, tokenizer, case, args.max_tokens)

            print(f"\n  Model response:")
            print("  " + "-" * 50)
            pretty_print_json(generated)
            print("  " + "-" * 50)
            print(f"  (Type 'gold' to see the expected output)")

            last_case = case
            continue

        # Just a finding number: show info
        if cmd in FINDINGS:
            fid = FINDINGS[cmd]["id"]
            print(f"\n  {FINDINGS[cmd]['id']}: {FINDINGS[cmd]['title']}")
            print(f"  Available task types in benchmark:")
            for k in sorted(index.keys()):
                if k.startswith(fid + "|"):
                    tt_name = k.split("|")[1]
                    print(f"    {tt_name}")
            print(f"  Usage: type '{cmd}a' for evidence_check, '{cmd}b' for finding_review, etc.")
            print(f"  Or type 'all {cmd}' to run all task types.")
            continue

        # Just a task letter: show info
        if len(cmd) == 1 and cmd in "abcde":
            task_idx = ord(cmd) - ord("a")
            if task_idx < len(TASK_TYPES):
                tt, desc = TASK_TYPES[task_idx]
                print(f"\n  [{cmd}] {tt}: {desc}")
                print(f"  Usage: type '1{cmd}' for finding 1, '2{cmd}' for finding 2, etc.")
            continue

        print(f"  Unknown command: '{user_input}'")
        print(f"  Type 'help' to see available commands.")

    return 0


if __name__ == "__main__":
    sys.exit(main())