#!/usr/bin/env python3
"""
05 — Base Model Baseline on benchmark_v1
=========================================

Task 09/08 deliverable — Runnable baseline script (skeleton).

This is the .py mirror of `notebooks/05_baseline.ipynb`, provided so the
notebook's code can be run via `python` directly (without Jupyter).

Status: Skeleton — actual baseline run is deferred to Colab on 10/08
(per Q2 = option a). The EVVO VPS is CPU-only and must not be used for
inference/training.

Usage
-----
Local (stub, no torch needed):
    python scripts/05_baseline.py

Colab (real run, GPU needed):
    1. Set RUN_BASELINE = True below.
    2. Set MODEL_ID to the chosen Qwen2.5 model.
    3. Upload this script (or paste into a Colab cell) and run.

Outputs
-------
- `data/benchmark/baseline_result.json` — aggregated metrics + per-case errors.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ── Configuration ────────────────────────────────────────────────────
# Set RUN_BASELINE = True ONLY on Colab (or any GPU-equipped machine).
# The EVVO VPS is CPU-only — running inference there is forbidden.
RUN_BASELINE: bool = False

# HuggingFace model ID for the base SLM. Candidate models (decided 10/08):
#   - Qwen/Qwen2.5-0.5B-Instruct  (smallest, fastest, lowest quality)
#   - Qwen/Qwen2.5-1.5B-Instruct  (balanced)
#   - Qwen/Qwen2.5-7B-Instruct    (best quality, needs ~16GB VRAM in 4-bit)
MODEL_ID: str = "Qwen/Qwen2.5-0.5B-Instruct"

# ── Repo paths ──────────────────────────────────────────────────────
# Resolve repo root from script location so this file works on any machine
# (Linux/macOS/Windows) without hardcoding absolute paths.
REPO_ROOT: Path = Path(__file__).resolve().parent.parent
BENCHMARK_PATH: Path = REPO_ROOT / "data" / "benchmark" / "benchmark_v1.jsonl"
ERROR_CATEGORIES_PATH: Path = REPO_ROOT / "data" / "benchmark" / "error_categories.md"
BASELINE_RESULT_PATH: Path = REPO_ROOT / "data" / "benchmark" / "baseline_result.json"


def main() -> int:
    print(f"RUN_BASELINE = {RUN_BASELINE}")
    print(f"MODEL_ID     = {MODEL_ID}")
    print(f"Benchmark    = {BENCHMARK_PATH}")
    print()

    # ── 1. Load benchmark ────────────────────────────────────────────
    cases = load_benchmark(BENCHMARK_PATH)
    print(f"Loaded {len(cases)} cases from {BENCHMARK_PATH.name}")
    print()

    by_task = Counter(c["task_type"] for c in cases)
    by_diff = Counter(c["metadata"]["difficulty"] for c in cases)
    hard_neg = sum(1 for c in cases if c["metadata"].get("is_hard_negative"))

    print("By task type:")
    for tt in sorted(by_task):
        print(f"  {tt:35} {by_task[tt]:3d}")
    print(f"\nBy difficulty: {dict(sorted(by_diff.items()))}")
    print(f"Hard negatives: {hard_neg}")
    print()

    # ── 2. Load base model ──────────────────────────────────────────
    model = load_base_model(MODEL_ID)
    print(f"model loaded: {model is not None}")
    print()

    # ── 3. Prompt builder sanity check ──────────────────────────────
    sample_prompt = build_prompt(cases[0])
    print(f"Prompt length: {len(sample_prompt)} chars")
    print("First 500 chars:")
    print(sample_prompt[:500])
    print("...")
    print()

    # ── 4. Output parser sanity check ───────────────────────────────
    for t in ["```json\n{\"a\": 1}\n```", "Here is the answer: {\"a\": 1} thanks", "not json at all"]:
        parsed, err = parse_output(t)
        print(f"{t[:30]!r:35} -> parsed={parsed}, err={err}")
    print()

    # ── 5. Metric functions (defined at module level) ───────────────
    print("Metric functions defined.")
    print()

    # ── 6. Baseline run loop ────────────────────────────────────────
    print("Running baseline...")
    per_case = run_baseline(model, cases)
    print(f"\nDone. {len(per_case)} cases scored.")
    print()

    # ── 7. Aggregate and write baseline_result.json ────────────────
    result = aggregate(per_case, cases)
    print(f"pass_rate:              {result['pass_rate']}")
    print(f"error_rate:             {result['error_rate']}")
    print(f"hard_negative_pass_rate:{result['hard_negative_pass_rate']}")
    print("error_distribution:")
    for code, count in result["error_distribution"].items():
        if count:
            print(f"  {code:35} {count}")

    BASELINE_RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with BASELINE_RESULT_PATH.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\nWrote {BASELINE_RESULT_PATH}")
    print()

    # ── 8. Per-task-type breakdown ──────────────────────────────────
    per_task_stats: dict[str, dict] = defaultdict(lambda: {"total": 0, "pass": 0, "errors": []})
    for pc in per_case:
        tt = pc["task_type"]
        per_task_stats[tt]["total"] += 1
        if not pc["errors"]:
            per_task_stats[tt]["pass"] += 1
        per_task_stats[tt]["errors"].extend(pc["errors"])

    print(f"{'task_type':35} {'pass/total':12} {'pass_rate':10} top_errors")
    print("-" * 90)
    for tt in sorted(per_task_stats):
        s = per_task_stats[tt]
        rate = s["pass"] / s["total"] if s["total"] else 0
        err_counter = Counter(s["errors"])
        top = ", ".join(f"{c}({n})" for c, n in err_counter.most_common(3))
        print(f"{tt:35} {s['pass']:>4}/{s['total']:<7} {rate:>8.1%}  {top}")

    return 0


# ── Functions (module level — keeps them importable for tests) ──────


def load_benchmark(path: Path) -> list[dict]:
    """Load all cases from a JSONL benchmark file."""
    cases: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def load_base_model(model_id: str):
    """Load a base SLM for inference.

    Returns a callable `generate(prompt: str) -> str` on Colab, or None locally.

    On Colab, this function:
      1. Imports torch + transformers.
      2. Loads the model in 4-bit (BitsAndBytes) for 7B, or fp16 for 0.5B/1.5B.
      3. Wraps it in a `pipeline("text-generation", ...)`.
      4. Returns a closure that formats the prompt as a chat and returns the generated text.
    """
    if not RUN_BASELINE:
        print(f"[stub] RUN_BASELINE=False — would load {model_id} on Colab.")
        return None

    import torch
    from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM

    print(f"Loading {model_id} ...")
    tokenizer = AutoTokenizer.from_pretrained(model_id)

    # Use 4-bit quantization for 7B models, fp16 for smaller ones.
    if "7B" in model_id:
        from transformers import BitsAndBytesConfig

        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
        model = AutoModelForCausalLM.from_pretrained(
            model_id, quantization_config=bnb_config, device_map="auto",
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_id, torch_dtype=torch.float16, device_map="auto",
        )

    pipe = pipeline("text-generation", model=model, tokenizer=tokenizer, max_new_tokens=512)

    def generate(prompt: str) -> str:
        messages = [{"role": "user", "content": prompt}]
        out = pipe(messages, return_full_text=False)[0]["generated_text"]
        return out

    return generate


def build_prompt(case: dict) -> str:
    """Render a benchmark case as a chat prompt for the base SLM."""
    instruction = case["instruction"]
    task_type = case["task_type"]
    payload = json.dumps(case["input"], ensure_ascii=False, indent=2)
    return (
        f"You are a pentest report reviewer. Complete the following task.\n\n"
        f"Task type: {task_type}\n"
        f"Instruction: {instruction}\n\n"
        f"Input:\n{payload}\n\n"
        f"Return ONLY valid JSON matching the output schema for this task type. "
        f"Do not include markdown fences or commentary."
    )


FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def parse_output(raw: str) -> tuple[Optional[dict], Optional[str]]:
    """Parse model output into a dict. Returns (parsed, error_code)."""
    if not raw or not raw.strip():
        return None, "FMT-INVALID-JSON"

    text = raw.strip()

    # Try markdown fence extraction first
    m = FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()

    # Try to locate the outermost JSON object
    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None, "FMT-INVALID-JSON"
        text = text[start : end + 1]

    try:
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            return None, "FMT-INVALID-JSON"
        return parsed, None
    except json.JSONDecodeError:
        return None, "FMT-INVALID-JSON"


def _get(obj: dict, *path, default=None):
    cur = obj
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def metric_classification(predicted: dict, gold: dict, task_type: str) -> list[str]:
    errors: list[str] = []
    gold_label = _get(gold, "classification", "label")
    pred_label = _get(predicted, "classification", "label")
    if pred_label is None:
        errors.append("FMT-MISSING-FIELD")
    elif pred_label != gold_label:
        errors.append("CLASS-WRONG-LABEL")
        if pred_label == "confirmed_vulnerability" and gold_label in ("potential_issue", "false_positive"):
            errors.append("CLASS-HALLUCINATED-CONFIRM")
    return errors


def metric_evidence(predicted: dict, gold: dict) -> list[str]:
    errors: list[str] = []
    gold_suff = _get(gold, "evidence_review", "is_sufficient")
    pred_suff = _get(predicted, "evidence_review", "is_sufficient")
    if pred_suff is None:
        errors.append("FMT-MISSING-FIELD")
    elif pred_suff != gold_suff:
        errors.append("EVID-WRONG-SUFFICIENCY")
        if pred_suff is True and gold_suff is False:
            errors.append("EVID-HALLUCINATED")
    gold_unsupp = _get(gold, "evidence_review", "unsupported_claims", default=[]) or []
    pred_unsupp = _get(predicted, "evidence_review", "unsupported_claims", default=[]) or []
    if gold_unsupp and not pred_unsupp:
        errors.append("EVID-MISSED-UNSUPPORTED")
    return errors


def metric_severity(predicted: dict, gold: dict) -> list[str]:
    errors: list[str] = []
    gold_sugg = _get(gold, "severity_review", "suggested_severity")
    pred_sugg = _get(predicted, "severity_review", "suggested_severity")
    if pred_sugg is None:
        errors.append("FMT-MISSING-FIELD")
    elif pred_sugg != gold_sugg:
        errors.append("SEV-WRONG-SUGGESTION")
    gold_change = _get(gold, "severity_review", "change_recommended")
    pred_change = _get(predicted, "severity_review", "change_recommended")
    if gold_change is True and pred_change is False:
        errors.append("SEV-MISSED-MISMATCH")
    return errors


def metric_qa(predicted: dict, gold: dict) -> list[str]:
    errors: list[str] = []
    gold_refuses = _get(gold, "refuses", default=False)
    pred_refuses = _get(predicted, "refuses", default=None)
    if pred_refuses is None:
        errors.append("FMT-MISSING-FIELD")
    elif gold_refuses and not pred_refuses:
        errors.append("CLASS-FAILED-REFUSE")
    elif not gold_refuses and pred_refuses:
        errors.append("QA-REFUSED-IN-SCOPE")
    # Redaction leak check
    pred_answer = _get(predicted, "answer", default="") or ""
    if "[REDACTED_" in str(pred_answer) or "password" in str(pred_answer).lower():
        if gold_refuses:
            errors.append("QA-LEAKED-REDACTED")
    return errors


def score_case(predicted: Optional[dict], gold: dict, task_type: str, parse_error: Optional[str]) -> list[str]:
    """Return list of error codes for a single case."""
    if parse_error:
        return [parse_error]
    if predicted is None:
        return ["FMT-INVALID-JSON"]

    errors: list[str] = []
    if task_type in ("finding_review", "hard_negative_potential_issue", "false_positive_detection"):
        errors.extend(metric_classification(predicted, gold, task_type))
    if task_type in ("finding_review", "evidence_check", "hard_negative_potential_issue"):
        errors.extend(metric_evidence(predicted, gold))
    if task_type in ("finding_review", "severity_review"):
        errors.extend(metric_severity(predicted, gold))
    if task_type in ("client_qa", "unsupported_refusal"):
        errors.extend(metric_qa(predicted, gold))
    # remediation_review has no numeric metric in v0.1 — defer to 17/08 full taxonomy
    return errors


def run_baseline(model, cases: list[dict]) -> list[dict]:
    """Run the model over all cases. Returns per_case results."""
    per_case: list[dict] = []
    for i, case in enumerate(cases, start=1):
        case_id = case["case_id"]
        task_type = case["task_type"]
        gold = case["gold_output"]

        if model is None:
            per_case.append({
                "case_id": case_id,
                "task_type": task_type,
                "errors": ["FMT-INVALID-JSON"],  # placeholder — no model run
                "latency_ms": 0,
                "raw_output": None,
            })
            continue

        prompt = build_prompt(case)
        t0 = datetime.now(timezone.utc)
        try:
            raw = model(prompt)
        except Exception as e:
            raw = ""
            print(f"  [{i}/{len(cases)}] {case_id}: model error: {e}")
        t1 = datetime.now(timezone.utc)
        latency_ms = int((t1 - t0).total_seconds() * 1000)

        parsed, parse_err = parse_output(raw)
        errors = score_case(parsed, gold, task_type, parse_err)

        per_case.append({
            "case_id": case_id,
            "task_type": task_type,
            "errors": errors,
            "latency_ms": latency_ms,
            "raw_output": raw,
        })

        status = "PASS" if not errors else "FAIL: " + ",".join(errors)
        print(f"  [{i}/{len(cases)}] {case_id} ({task_type:30}) {latency_ms:5}ms  {status}")

    return per_case


def aggregate(per_case: list[dict], cases: list[dict]) -> dict:
    case_by_id = {c["case_id"]: c for c in cases}

    n_total = len(per_case)
    n_pass = sum(1 for pc in per_case if not pc["errors"])
    n_errors = sum(len(pc["errors"]) for pc in per_case)

    hard_neg_ids = {c["case_id"] for c in cases if c["metadata"].get("is_hard_negative")}
    hard_neg_per_case = [pc for pc in per_case if pc["case_id"] in hard_neg_ids]
    hard_neg_pass = sum(1 for pc in hard_neg_per_case if not pc["errors"])

    error_dist: Counter = Counter()
    for pc in per_case:
        for e in pc["errors"]:
            error_dist[e] += 1

    # Ensure all 13 error codes are present (fill 0 for missing)
    ALL_CODES = [
        "CLASS-WRONG-LABEL", "CLASS-HALLUCINATED-CONFIRM", "CLASS-FAILED-REFUSE",
        "EVID-WRONG-SUFFICIENCY", "EVID-HALLUCINATED", "EVID-MISSED-UNSUPPORTED",
        "SEV-WRONG-SUGGESTION", "SEV-MISSED-MISMATCH",
        "QA-LEAKED-REDACTED", "QA-REFUSED-IN-SCOPE",
        "FMT-INVALID-JSON", "FMT-SCHEMA-VIOLATION", "FMT-MISSING-FIELD",
    ]
    error_distribution = {code: error_dist.get(code, 0) for code in ALL_CODES}

    return {
        "benchmark_version": "1.0",
        "model_id": MODEL_ID if RUN_BASELINE else None,
        "ran_at": datetime.now(timezone.utc).isoformat() if RUN_BASELINE else None,
        "environment": "google_colab" if RUN_BASELINE else "local_stub",
        "case_count": n_total,
        "pass_rate": round(n_pass / n_total, 4) if n_total else 0.0,
        "error_rate": round(n_errors / n_total, 4) if n_total else 0.0,
        "hard_negative_pass_rate": (
            round(hard_neg_pass / len(hard_neg_ids), 4) if hard_neg_ids else 0.0
        ),
        "error_distribution": error_distribution,
        "per_case": [
            {k: v for k, v in pc.items() if k != "raw_output"}
            for pc in per_case
        ],
        "notes": [
            "Placeholder structure. Fill in by running scripts/05_baseline.py on Colab (10/08 task).",
            "All values are None/zero until the baseline is actually run.",
            "Per-case entries follow the shape documented in data/benchmark/error_categories.md section 6.",
        ] if not RUN_BASELINE else [
            f"Baseline run on {MODEL_ID} via Colab.",
            "Gold labels are rule-based — see data/benchmark/data_card.md section 4.3.",
        ],
    }


if __name__ == "__main__":
    sys.exit(main())