#!/usr/bin/env python3
"""
07 — SLM Inference Test
=======================
Prove that LoRA fine-tuning was successful by running the trained model
on benchmark cases and comparing outputs against gold labels.

Usage on VPS (CPU-only, 8GB RAM):
    cd slm-training
    source .venv/bin/activate
    python scripts/07_inference_test.py

Options:
    --cases N        Run only the first N cases (default: 5)
    --all            Run all benchmark cases
    --case-id ID     Run a specific case by ID (e.g. BMC-001)
    --verbose        Print full input/output JSON
    --no-model       Print what WOULD be run without loading the model
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


# ═══════════════════════════════════════════════════════════════════
#  Data loading
# ═══════════════════════════════════════════════════════════════════

def load_benchmark(path: Path) -> list[dict]:
    """Load benchmark cases from JSONL file."""
    cases = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def build_prompt(case: dict) -> str:
    """
    Build the user prompt exactly as used during training.

    This MUST match the format in build_training_examples() from
    06_finetune.py, otherwise the model will produce garbage.
    """
    instruction = case.get("instruction", "")
    task_type = case.get("task_type", "")
    input_data = case.get("input", {})
    payload = json.dumps(input_data, ensure_ascii=False, indent=2)

    prompt = (
        f"You are a pentest report reviewer. Complete the following task.\n\n"
        f"Task type: {task_type}\n"
        f"Instruction: {instruction}\n\n"
        f"Input:\n{payload}\n\n"
        f"Return ONLY valid JSON matching the output schema for this task type. "
        f"Do not include markdown fences or commentary."
    )
    return prompt


def build_messages(prompt: str) -> list[dict]:
    """Build chat messages for Qwen2.5 chat template."""
    return [{"role": "user", "content": prompt}]


# ═══════════════════════════════════════════════════════════════════
#  Model loading
# ═══════════════════════════════════════════════════════════════════

def load_model_and_tokenizer(adapter_path: Path):
    """
    Load base model + LoRA adapter for inference.

    On CPU, we MUST use float32 — not float16.
    CPU has no native fp16 arithmetic; PyTorch emulates it, which
    causes NaN/Inf logits and the model generates nothing (empty string).
    Qwen2.5-1.5B in fp32 ≈ 6GB weights + 1.5GB overhead ≈ 7.5GB total.
    Fits in 8GB RAM with some headroom.
    """
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel

    print(f"[1/3] Loading tokenizer from {BASE_MODEL_ID} ...")
    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL_ID,
        trust_remote_code=False,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    dtype = torch.float32
    print(f"[2/3] Loading base model ({BASE_MODEL_ID}) in {dtype} on CPU ...")
    print(f"       This may take a few minutes on first run (downloading weights)...")
    print(f"       NOTE: Using float32 on CPU (float16 causes NaN logits on CPU).")
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        torch_dtype=dtype,
        device_map="cpu",
        trust_remote_code=False,
    )

    print(f"[3/3] Loading LoRA adapter from {adapter_path} ...")
    model = PeftModel.from_pretrained(base_model, str(adapter_path))
    model.eval()

    return model, tokenizer


def load_base_only():
    """Load base model WITHOUT LoRA adapter (for comparison testing)."""
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM

    print(f"[1/2] Loading tokenizer from {BASE_MODEL_ID} ...")
    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL_ID, trust_remote_code=False,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print(f"[2/2] Loading base model ({BASE_MODEL_ID}) in float32 on CPU ...")
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        torch_dtype=torch.float32,
        device_map="cpu",
        trust_remote_code=False,
    )
    model.eval()
    return model, tokenizer


# ═══════════════════════════════════════════════════════════════════
#  Inference
# ═══════════════════════════════════════════════════════════════════

def generate(model, tokenizer, case: dict, max_new_tokens: int = 1024, debug: bool = False) -> str:
    """Generate model output for a single benchmark case."""
    import torch

    prompt = build_prompt(case)

    # Build the chat template manually — same format as training.
    # Training code (06_finetune.py build_training_examples) uses:
    #   f"<|im_start|>user\n{user_msg}<|im_end|>\n"
    #   f"<|im_start|>assistant\n{assistant_msg}<|im_end|>"
    # For inference we stop after the assistant header (no gold output):
    chat_text = (
        f"<|im_start|>user\n{prompt}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )
    input_ids = tokenizer(chat_text, return_tensors="pt")["input_ids"]
    input_length = input_ids.shape[1]

    if debug:
        print(f"  [DEBUG] input tokens:  {input_length}")
        # Print the last 5 input tokens to verify template format
        last5 = input_ids[0][-5:]
        print(f"  [DEBUG] last 5 input token IDs: {last5.tolist()}")
        for tid in last5.tolist():
            print(f"           token {tid} = {repr(tokenizer.decode([tid]))}")

    with torch.no_grad():
        output_ids = model.generate(
            input_ids,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=1.0,
        )

    new_token_count = output_ids.shape[1] - input_length
    if debug:
        print(f"  [DEBUG] output tokens: {output_ids.shape[1]}")
        print(f"  [DEBUG] new tokens:    {new_token_count}")
        if new_token_count > 0:
            gen_ids = output_ids[0][input_length:].tolist()
            print(f"  [DEBUG] first 10 gen token IDs: {gen_ids[:10]}")
            for tid in gen_ids[:10]:
                print(f"           token {tid} = {repr(tokenizer.decode([tid]))}")

    # Decode WITH special tokens for debugging
    raw_with_specials = tokenizer.decode(
        output_ids[0][input_length:], skip_special_tokens=False,
    )
    if debug:
        print(f"  [DEBUG] raw output (with special tokens):\n    {repr(raw_with_specials[:300])}")

    generated = tokenizer.decode(
        output_ids[0][input_length:],
        skip_special_tokens=True,
    )
    return generated


def generate_batch(model, tokenizer, cases: list[dict], max_new_tokens: int = 1024, debug: bool = False) -> list[dict]:
    """Generate outputs for multiple cases and collect results."""
    results = []
    total = len(cases)

    for i, case in enumerate(cases):
        case_id = case.get("case_id", f"case-{i}")
        task_type = case.get("task_type", "unknown")
        print(f"\n{'='*60}")
        print(f"  Case {i+1}/{total}: {case_id}  (task: {task_type})")
        print(f"{'='*60}")

        t0 = time.time()
        try:
            generated_text = generate(model, tokenizer, case, max_new_tokens, debug=debug)
            gen_time = time.time() - t0
            error = None
        except Exception as e:
            import traceback
            traceback.print_exc()  # Print full stack trace for diagnosis
            generated_text = ""
            gen_time = time.time() - t0
            error = f"{type(e).__name__}: {e}"

        # Try to parse generated text as JSON
        parsed_output = None
        if generated_text.strip():
            # Strip markdown fences if present
            cleaned = generated_text.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:])  # remove first line (```json)
                if cleaned.endswith("```"):
                    cleaned = cleaned[:-3]
                cleaned = cleaned.strip()
            try:
                parsed_output = json.loads(cleaned)
            except json.JSONDecodeError:
                parsed_output = None

        # Parse gold output
        gold_output = case.get("gold_output", {})

        # Evaluate
        eval_result = evaluate(generated_text, parsed_output, gold_output, task_type=task_type)

        result = {
            "case_id": case_id,
            "task_type": task_type,
            "generated_text": generated_text,
            "parsed_output": parsed_output,
            "gold_output": gold_output,
            "generation_time_sec": round(gen_time, 2),
            "error": error,
            "eval": eval_result,
        }
        results.append(result)

        # Print summary for this case
        print(f"  Time: {gen_time:.1f}s")
        if error:
            print(f"  ERROR: {error[:200]}")
        elif not generated_text.strip():
            print(f"  JSON valid: False")
            print(f"  Eval: FAIL — model generated empty output (0 chars)")
            print(f"  HINT: This usually means float16 on CPU (NaN logits).")
            print(f"        Make sure the script uses torch.float32.")
        else:
            print(f"  Output length:   {len(generated_text)} chars")
            print(f"  JSON valid: {parsed_output is not None}")
            print(f"  Eval: {eval_result['summary']}")
            if parsed_output is None:
                print(f"  Raw output (first 300 chars):\n    {generated_text[:300]}")

    return results


# ═══════════════════════════════════════════════════════════════════
#  Evaluation
# ═══════════════════════════════════════════════════════════════════

def evaluate(
    generated_text: str,
    parsed_output: dict | None,
    gold_output: dict,
    task_type: str = "",
) -> dict:
    """
    Compare generated output against gold output.

    Returns a dict with:
      - json_valid: bool
      - exact_match: bool
      - structure_match: float — fraction of gold top-level keys present in output
      - field_matches: dict — per-field match results (supports nested paths)
      - classification_match: bool | None
      - summary: str
    """
    # Check JSON validity
    json_valid = parsed_output is not None

    if not json_valid:
        return {
            "json_valid": False, "exact_match": False,
            "structure_match": 0.0, "field_matches": {},
            "classification_match": None,
            "summary": "FAIL — output is not valid JSON",
        }

    # Exact match
    exact = parsed_output == gold_output

    # Structure match: what fraction of gold top-level keys exist in output
    gold_keys = set(gold_output.keys())
    pred_keys = set(parsed_output.keys()) if isinstance(parsed_output, dict) else set()
    structure_match = len(gold_keys & pred_keys) / max(len(gold_keys), 1)

    # Field-level comparison with nested path support.
    # Each entry: (path_string, display_name)
    # We define important fields per task type.
    field_paths = _get_important_fields(task_type, gold_output, parsed_output)

    field_matches = {}
    for path_str, display_name in field_paths:
        gold_val = _get_nested(gold_output, path_str)
        pred_val = _get_nested(parsed_output, path_str)

        if gold_val is _SENTINEL:
            continue  # gold doesn't have this field, skip

        if pred_val is _SENTINEL:
            match = False
            pred_display = "<missing>"
        else:
            match = gold_val == pred_val
            pred_display = pred_val

        field_matches[display_name] = {
            "gold": gold_val,
            "pred": pred_display,
            "match": match,
        }

    # Classification match
    classification_match = None
    for key in ("classification", "label"):
        if key in field_matches:
            classification_match = field_matches[key]["match"]
            break
    # For evidence_check: treat is_sufficient as classification equivalent
    if classification_match is None and "evidence_review.is_sufficient" in field_matches:
        classification_match = field_matches["evidence_review.is_sufficient"]["match"]

    # Summary
    matched = sum(1 for v in field_matches.values() if v["match"])
    total_fields = len(field_matches)

    if exact:
        summary = "PASS — exact match with gold output"
    elif structure_match >= 0.8 and matched >= total_fields * 0.7:
        summary = f"GOOD — structure {structure_match:.0%}, {matched}/{total_fields} fields match"
    elif structure_match >= 0.5 or matched > 0:
        summary = f"PARTIAL — structure {structure_match:.0%}, {matched}/{total_fields} fields match"
    elif classification_match is False:
        # Find the actual classification field used
        pred_c, gold_c = "?", "?"
        for ck in ("classification", "label", "evidence_review.is_sufficient"):
            if ck in field_matches:
                pred_c = str(field_matches[ck]["pred"])[:40]
                gold_c = str(field_matches[ck]["gold"])[:40]
                break
        summary = f"MISMATCH — predicted '{pred_c}' vs gold '{gold_c}'"
    else:
        summary = f"WEAK — structure {structure_match:.0%}, {matched}/{total_fields} fields match"

    return {
        "json_valid": json_valid, "exact_match": exact,
        "structure_match": round(structure_match, 2),
        "field_matches": field_matches,
        "classification_match": classification_match,
        "summary": summary,
    }


_SENTINEL = object()


def _get_nested(d: dict, path: str):
    """Get a nested value using dot-notation path. Returns _SENTINEL if not found."""
    keys = path.split(".")
    current = d
    for k in keys:
        if isinstance(current, dict) and k in current:
            current = current[k]
        else:
            return _SENTINEL
    return current


def _get_important_fields(task_type: str, gold: dict, pred: dict) -> list[tuple[str, str]]:
    """Return list of (dot_path, display_name) for field comparison.

    Tries to pick the most relevant fields based on task type and
    what actually exists in the gold/pred outputs.
    """
    # Universal top-level fields
    paths = [
        ("classification", "classification"),
        ("label", "label"),
        ("severity", "severity"),
        ("suggested_severity", "suggested_severity"),
        ("review_status", "review_status"),
        ("rationale", "rationale"),
    ]

    # Evidence review nested fields
    evidence_paths = [
        ("evidence_review.is_sufficient", "evidence_review.is_sufficient"),
        ("evidence_review.supported_claims", "evidence_review.supported_claims"),
        ("evidence_review.unsupported_claims", "evidence_review.unsupported_claims"),
        ("evidence_review.missing_evidence", "evidence_review.missing_evidence"),
        ("confidence.overall_score", "confidence.overall_score"),
        ("confidence.level", "confidence.level"),
    ]

    # Severity check fields
    severity_paths = [
        ("suggested_severity", "suggested_severity"),
        ("suggested_cvss_score", "suggested_cvss_score"),
        ("suggested_cvss_vector", "suggested_cvss_vector"),
        ("rationale", "rationale"),
    ]

    # Add task-specific paths
    if "evidence" in task_type:
        paths.extend(evidence_paths)
    if "severity" in task_type or "cvss" in task_type:
        paths.extend(severity_paths)

    # Also add nested paths if gold has those top-level keys
    if "evidence_review" in gold and evidence_paths not in paths:
        paths.extend(evidence_paths)
    if "confidence" in gold:
        paths.extend([
            ("confidence.overall_score", "confidence.overall_score"),
            ("confidence.level", "confidence.level"),
        ])

    return paths


# ═══════════════════════════════════════════════════════════════════
#  Reporting
# ═══════════════════════════════════════════════════════════════════

def print_report(results: list[dict], verbose: bool = False) -> None:
    """Print a summary report of all inference results."""
    total = len(results)
    json_valid_count = sum(1 for r in results if r["eval"]["json_valid"])
    exact_count = sum(1 for r in results if r["eval"]["exact_match"])
    class_correct = sum(
        1 for r in results
        if r["eval"]["classification_match"] is True
    )
    class_total = sum(
        1 for r in results
        if r["eval"]["classification_match"] is not None
    )
    error_count = sum(1 for r in results if r["error"] is not None)
    avg_struct = sum(r["eval"]["structure_match"] for r in results) / max(total, 1)
    avg_time = sum(r["generation_time_sec"] for r in results) / max(total, 1)

    print(f"\n{'='*60}")
    print(f"  INFERENCE TEST REPORT")
    print(f"{'='*60}")
    print(f"  Total cases:      {total}")
    json_pct = f"{json_valid_count}/{total} ({100*json_valid_count/max(total,1):.0f}%)"
    exact_pct = f"{exact_count}/{total} ({100*exact_count/max(total,1):.0f}%)"
    class_pct = f"{class_correct}/{class_total} ({100*class_correct/max(class_total,1):.0f}%)"
    print(f"  JSON valid:       {json_pct}")
    print(f"  Exact match:      {exact_pct}")
    print(f"  Structure match:  {avg_struct:.0%} avg")
    print(f"  Classification:   {class_pct}")
    print(f"  Errors:           {error_count}")
    print(f"  Avg gen time:     {avg_time:.1f}s/case")
    print(f"{'='*60}")

    # Per-case results table
    print(f"\n  {'Case ID':<16} {'Task':<20} {'Struct':<8} {'Result':<36}")
    print(f"  {'-'*16} {'-'*20} {'-'*8} {'-'*36}")
    for r in results:
        case_id = r["case_id"]
        task = r["task_type"][:18]
        struct = f"{r['eval']['structure_match']:.0%}"
        summary = r["eval"]["summary"][:34]
        print(f"  {case_id:<16} {task:<20} {struct:<8} {summary:<36}")

    # Verbose: print full outputs for failed cases
    if verbose:
        for r in results:
            if not r["eval"]["json_valid"] or not r["eval"]["exact_match"]:
                print(f"\n{'─'*60}")
                print(f"  DETAILED — {r['case_id']}")
                print(f"{'─'*60}")
                print(f"  Gold output:")
                print(f"    {json.dumps(r['gold_output'], indent=4, ensure_ascii=False)[:500]}")
                print(f"  Generated:")
                print(f"    {r['generated_text'][:500]}")
                if r["eval"]["field_matches"]:
                    print(f"  Field comparison:")
                    for field, cmp in r["eval"]["field_matches"].items():
                        icon = "OK" if cmp["match"] else "!!"
                        print(f"    [{icon}] {field}: gold={cmp['gold']}  pred={cmp['pred']}")

    # Verdict
    print(f"\n{'='*60}")
    if json_valid_count == total and exact_count == total:
        print(f"  VERDICT: Training appears SUCCESSFUL")
        print(f"  All {total} cases produce exact match with gold output.")
    elif json_valid_count == total and avg_struct >= 0.7:
        print(f"  VERDICT: Training shows GOOD results")
        print(f"  All cases produce valid JSON with {avg_struct:.0%} avg structure match.")
        print(f"  Classification accuracy: {class_correct}/{class_total}.")
    elif json_valid_count > total * 0.5:
        print(f"  VERDICT: Training shows PARTIAL success")
        print(f"  Valid JSON on {json_valid_count}/{total} cases, {avg_struct:.0%} structure match.")
        print(f"  Classification accuracy: {class_correct}/{class_total}.")
    else:
        print(f"  VERDICT: Training may need investigation")
        print(f"  Only {json_valid_count}/{total} cases produced valid JSON.")
        print(f"  Possible causes: insufficient training, wrong adapter, or prompt mismatch.")
    print(f"{'='*60}")


# ═══════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(description="SLM Inference Test — prove training success")
    parser.add_argument("--cases", type=int, default=5, help="Number of cases to run (default: 5)")
    parser.add_argument("--all", action="store_true", help="Run all benchmark cases")
    parser.add_argument("--case-id", type=str, help="Run a specific case by ID")
    parser.add_argument("--verbose", action="store_true", help="Print full outputs for failed cases")
    parser.add_argument("--no-model", action="store_true", help="Dry run — show what would be run")
    parser.add_argument("--no-adapter", action="store_true", help="Load base model ONLY (skip LoRA adapter)")
    parser.add_argument("--debug", action="store_true", help="Print token-level debugging info")
    parser.add_argument("--max-tokens", type=int, default=1024, help="Max new tokens to generate (default: 1024)")
    args = parser.parse_args()

    # ── Validate paths ──
    if not BENCHMARK_PATH.exists():
        print(f"ERROR: Benchmark file not found: {BENCHMARK_PATH}")
        print(f"  Expected at: {BENCHMARK_PATH}")
        return 1

    if not ADAPTER_PATH.exists():
        print(f"ERROR: Adapter directory not found: {ADAPTER_PATH}")
        print(f"  Expected at: {ADAPTER_PATH}")
        return 1

    # ── Load benchmark ──
    print(f"Loading benchmark from {BENCHMARK_PATH.name} ...")
    all_cases = load_benchmark(BENCHMARK_PATH)
    print(f"Found {len(all_cases)} total cases")

    # ── Select cases ──
    if args.case_id:
        selected = [c for c in all_cases if c.get("case_id") == args.case_id]
        if not selected:
            print(f"ERROR: Case '{args.case_id}' not found in benchmark")
            print(f"  Available IDs: {[c.get('case_id') for c in all_cases[:10]]}...")
            return 1
    elif args.all:
        selected = all_cases
    else:
        selected = all_cases[:args.cases]

    print(f"Running {len(selected)} case(s)\n")

    # ── Dry run mode ──
    if args.no_model:
        print("[DRY RUN] Would load:")
        print(f"  Base model:  {BASE_MODEL_ID}")
        print(f"  Adapter:     {ADAPTER_PATH}")
        print(f"  Benchmark:   {BENCHMARK_PATH} ({len(all_cases)} cases)")
        print(f"  Selected:    {len(selected)} case(s)")
        print(f"\n[DRY RUN] Case list:")
        for c in selected:
            prompt = build_prompt(c)
            print(f"  {c.get('case_id', '?'):12} task={c.get('task_type', '?'):25} prompt_len={len(prompt)}")
        print(f"\n[DRY RUN] Adapter config:")
        cfg_path = ADAPTER_PATH / "adapter_config.json"
        if cfg_path.exists():
            with cfg_path.open() as f:
                cfg = json.load(f)
            print(f"  r={cfg.get('r')}, alpha={cfg.get('lora_alpha')}, "
                  f"target={cfg.get('target_modules')}")
            print(f"  base_model={cfg.get('base_model_name_or_path')}")
        return 0

    # ── Load model ──
    print()
    if args.no_adapter:
        print("[--no-adapter] Loading BASE MODEL ONLY (no LoRA adapter)")
        model, tokenizer = load_base_only()
    else:
        model, tokenizer = load_model_and_tokenizer(ADAPTER_PATH)

    # ── Run inference ──
    print(f"\nRunning inference on {len(selected)} case(s) ...")
    print(f"(First run includes model loading time in CPU memory allocation)\n")
    results = generate_batch(model, tokenizer, selected, max_new_tokens=args.max_tokens, debug=args.debug)

    # ── Print report ──
    print_report(results, verbose=args.verbose)

    # ── Save results ──
    output_path = REPO_ROOT / "data" / "benchmark" / "inference_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nResults saved to {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())