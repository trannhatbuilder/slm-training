#!/usr/bin/env python3
"""
Merge benchmark_v1.jsonl (34 cases) + hard_negatives_v11.jsonl (9 cases)
into benchmark_v11.jsonl (43 cases).
Also generates updated benchmark_manifest.json v1.1.

Usage:
    python scripts/merge_benchmark_v11.py
"""
import json, hashlib
from collections import Counter

def content_hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]

def cvss_band(score):
    if score >= 9.0: return 'critical'
    if score >= 7.0: return 'high'
    if score >= 4.0: return 'medium'
    if score >= 0.1: return 'low'
    return 'informational'

# ============================================================
# 1. LOAD
# ============================================================
with open('data/benchmark/benchmark_v1.jsonl') as f:
    v1_cases = [json.loads(line) for line in f if line.strip()]

with open('data/benchmark/hard_negatives_v11.jsonl') as f:
    hn_cases = [json.loads(line) for line in f if line.strip()]

print(f"Loaded: {len(v1_cases)} v1 cases + {len(hn_cases)} hard negatives")

# Verify no ID collision
v1_ids = {c['case_id'] for c in v1_cases}
hn_ids = {c['case_id'] for c in hn_cases}
overlap = v1_ids & hn_ids
assert not overlap, f"ID collision: {overlap}"

# Check content hash collision (dedup safety)
v1_hashes = {c['metadata'].get('content_hash','') for c in v1_cases}
hn_hashes = {c['metadata'].get('content_hash','') for c in hn_cases}
hash_overlap = v1_hashes & hn_hashes - {''}
if hash_overlap:
    print(f"WARNING: {len(hash_overlap)} content hash collisions (acceptable for swapped-evidence cases)")

# ============================================================
# 2. MERGE (v1 first, then HN)
# ============================================================
all_cases = v1_cases + hn_cases

# ============================================================
# 3. COMPUTE MANIFEST STATS
# ============================================================
task_counts = Counter(c['task_type'] for c in all_cases)
diff_counts = Counter(c['metadata'].get('difficulty', 'unknown') for c in all_cases)
hn_count = sum(1 for c in all_cases if c['metadata'].get('is_hard_negative'))

# Count by hard_negative_type
hn_type_counts = Counter()
for c in all_cases:
    if c['metadata'].get('is_hard_negative'):
        hn_type_counts[c['metadata'].get('hard_negative_type', 'unknown')] += 1

# Count expected_failure_modes
fm_counts = Counter()
for c in all_cases:
    for fm in c.get('expected_failure_modes', []):
        fm_counts[fm] += 1

# Check for duplicate cases (by content_hash)
dup_check = {}
duplicates = []
for c in all_cases:
    ch = c['metadata'].get('content_hash', '')
    if ch and ch in dup_check:
        duplicates.append({
            'case_a': dup_check[ch],
            'case_b': c['case_id'],
            'hash': ch
        })
    elif ch:
        dup_check[ch] = c['case_id']

# ============================================================
# 4. WRITE benchmark_v11.jsonl
# ============================================================
out_path = 'data/benchmark/benchmark_v11.jsonl'
with open(out_path, 'w', encoding='utf-8') as f:
    for c in all_cases:
        f.write(json.dumps(c, ensure_ascii=False) + '\n')

print(f"\nWritten: {out_path} ({len(all_cases)} cases)")

# ============================================================
# 5. WRITE benchmark_manifest.json v1.1
# ============================================================
manifest = {
    'benchmark_version': '1.1',
    'created_at': '2026-08-15',
    'last_updated': '2026-08-18',
    'source': {
        'findings_jsonl': 'data/normalized/DOC-000001-findings-normalized.jsonl',
        'engagement_id': 'DOC-000001',
        'n_findings': 5
    },
    'case_count': len(all_cases),
    'cases_by_task_type': dict(sorted(task_counts.items())),
    'cases_by_difficulty': dict(sorted(diff_counts.items())),
    'hard_negative_count': hn_count,
    'hard_negatives_by_type': dict(sorted(hn_type_counts.items())),
    'schema_contract': 'schemas/output_schema.json (v0.1)',
    'envelope_schema': {
        'case_id': 'string',
        'task_type': 'enum',
        'instruction': 'string',
        'input': 'object',
        'gold_output': 'object (shape depends on task_type)',
        'expected_failure_modes': 'string[]',
        'metadata': 'object'
    },
    'duplicates_detected': duplicates,
    'generation_strategy': 'cross_task_expansion + hand_crafted_hard_negatives + v11_hard_negative_expansion',
    'changelog': [
        {'version': '1.1', 'date': '2026-08-18', 'changes': [
            'Added 9 hard negative cases (4 types: scanner-only trap, unrelated evidence, wrong severity, unsupported question)',
            'Total: 34 -> 43 cases',
            'Hard negatives: 9 -> 18 (was 8, +1 scanner-only +3 unrelated evidence +3 wrong severity +2 unsupported question -1 existing FP overlap count correction)',
            'New case IDs: BMC-FP-0004, BMC-EV-0006..0008, BMC-SV-0006..0008, BMC-QA-0008..0009'
        ]},
        {'version': '1.0', 'date': '2026-08-15', 'changes': ['Initial 34 cases']}
    ],
    'failure_mode_counts': dict(sorted(fm_counts.items())),
    'notes': [
        'Gold labels are rule-based, not human-validated.',
        'Test set is NOT frozen — only 1 engagement available (see data/dataset/test_set_freeze.json).',
        'Regenerate v1 base with: python scripts/build_benchmark_v1.py',
        'Regenerate v1.1 HN with: python scripts/build_hard_negatives_v11.py',
        'Merge with: python scripts/merge_benchmark_v11.py'
    ]
}

manifest_path = 'data/benchmark/benchmark_manifest.json'
with open(manifest_path, 'w', encoding='utf-8') as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)

print(f"Updated: {manifest_path}")

# ============================================================
# 6. PRINT SUMMARY
# ============================================================
print(f"\n{'='*60}")
print(f"BENCHMARK v1.1 SUMMARY")
print(f"{'='*60}")
print(f"Total cases:    {len(all_cases)} (was 34)")
print(f"Hard negatives: {hn_count} (was 9)")
print(f"Duplicates:     {len(duplicates)}")
print()
print("By task type:")
for t, n in sorted(task_counts.items()):
    marker = ' (+' + str(n - (Counter(c['task_type'] for c in v1_cases).get(t,0))) + ')' if n > Counter(c['task_type'] for c in v1_cases).get(t,0) else ''
    print(f"  {t:35s}: {n:3d}{marker}")

print(f"\nBy difficulty:")
for d, n in sorted(diff_counts.items()):
    print(f"  {d:10s}: {n:3d}")

print(f"\nHard negatives by type:")
for t, n in sorted(hn_type_counts.items()):
    print(f"  {t:45s}: {n}")

print(f"\nTop expected_failure_modes:")
for fm, n in fm_counts.most_common(10):
    print(f"  {fm:45s}: {n}")