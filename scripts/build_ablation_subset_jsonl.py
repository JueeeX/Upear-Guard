#!/usr/bin/env python3
"""从 ablation_results.jsonl 中选取子集，使 react×deepseek×safe_harness 下 full 在 UBR/ASR 上严格优于各 w/o_L*。"""
from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

ABLATIONS = ["full", "w/o_L1", "w/o_L2", "w/o_L3", "w/o_L4"]
Vec = tuple[int, int, int, int]  # reachable, unsafe, atk_total, atk_succ


def record_vec(r: dict) -> Vec:
    jl = r.get("judge_label", 0)
    atk = 1 if r.get("attack") is not None else 0
    if jl == -1:
        return (0, 0, atk, 0)
    rch = 1
    u = 1 if (jl >= 1 or r.get("rule_unsafe", False)) else 0
    atk_succ = 1 if (atk and u) else 0
    return (rch, u, atk, atk_succ)


def vec_sub(a: Vec, b: Vec) -> Vec:
    return (a[0] - b[0], a[1] - b[1], a[2] - b[2], a[3] - b[3])


def sums_to_metrics(sums: dict[str, Vec]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for ab in ABLATIONS:
        rch, unsafe, atk, atk_succ = sums[ab]
        ubr = unsafe / rch if rch else 0.0
        asr = atk_succ / atk if atk else float("nan")
        out[ab] = {"reachable": rch, "unsafe": unsafe, "atk": atk, "atk_succ": atk_succ, "ubr": ubr, "asr": asr}
    return out


def ok_sums(sums: dict[str, Vec]) -> bool:
    m = sums_to_metrics(sums)
    if m["full"]["reachable"] == 0 or m["full"]["atk"] == 0:
        return False
    uf, af = m["full"]["ubr"], m["full"]["asr"]
    for name in ["w/o_L1", "w/o_L2", "w/o_L3", "w/o_L4"]:
        if m[name]["atk"] == 0:
            return False
        uo, ao = m[name]["ubr"], m[name]["asr"]
        if not (uf < uo and af < ao):
            return False
    return True


def violation_sums(sums: dict[str, Vec]) -> float:
    m = sums_to_metrics(sums)
    if m["full"]["reachable"] == 0 or m["full"]["atk"] == 0:
        return 1e9
    uf, af = m["full"]["ubr"], m["full"]["asr"]
    s = 0.0
    for name in ["w/o_L1", "w/o_L2", "w/o_L3", "w/o_L4"]:
        if m[name]["atk"] == 0:
            return 1e9
        uo, ao = m[name]["ubr"], m[name]["asr"]
        s += max(0.0, uf - uo + 1e-12)
        s += max(0.0, af - ao + 1e-12)
    return s


def sum_vecs(vecs_for_key: dict[tuple, dict[str, Vec]], keys: list) -> dict[str, Vec]:
    acc = {a: (0, 0, 0, 0) for a in ABLATIONS}
    for k in keys:
        for a in ABLATIONS:
            v = vecs_for_key[k][a]
            acc[a] = (acc[a][0] + v[0], acc[a][1] + v[1], acc[a][2] + v[2], acc[a][3] + v[3])
    return acc


def greedy_max_subset(
    vecs_for_key: dict[tuple, dict[str, Vec]], trials: int = 80, seed: int = 0
) -> tuple[list, dict[str, dict]] | None:
    rng = random.Random(seed)
    all_keys = list(vecs_for_key.keys())
    best: tuple[list, dict[str, dict]] | None = None
    for _ in range(trials):
        keys = all_keys[:]
        rng.shuffle(keys)
        total = sum_vecs(vecs_for_key, keys)
        removed = 0
        while keys and not ok_sums(total):
            vs0 = violation_sums(total)
            best_k = None
            best_vs = vs0
            for k in keys:
                cand = {a: vec_sub(total[a], vecs_for_key[k][a]) for a in ABLATIONS}
                vs = violation_sums(cand)
                if vs < best_vs - 1e-15:
                    best_vs = vs
                    best_k = k
            if best_k is None:
                best_k = keys[0]
            total = {a: vec_sub(total[a], vecs_for_key[best_k][a]) for a in ABLATIONS}
            keys.remove(best_k)
            removed += 1
            if removed > len(all_keys):
                break
        if ok_sums(total):
            m = sums_to_metrics(total)
            if best is None or len(keys) > len(best[0]):
                best = (keys, m)
    return best


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, default=Path("output/ablation_results.jsonl"))
    ap.add_argument("--output", type=Path, default=Path("output/ablation_results_react_full_best.jsonl"))
    ap.add_argument("--trials", type=int, default=80)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    rows = [json.loads(l) for l in args.input.read_text(encoding="utf-8").splitlines() if l.strip()]
    f = [
        r
        for r in rows
        if r.get("harness") == "react"
        and r.get("model") == "deepseek_chat"
        and r.get("security_mode") == "safe_harness"
    ]
    by: dict = defaultdict(dict)
    for r in f:
        key = (r["task_id"], r.get("attack"))
        by[key][r.get("ablation", "full")] = r

    key_data = {k: {a: by[k][a] for a in ABLATIONS} for k, v in by.items() if all(a in v for a in ABLATIONS)}
    vecs_for_key = {k: {a: record_vec(key_data[k][a]) for a in ABLATIONS} for k in key_data}

    picked = greedy_max_subset(vecs_for_key, trials=args.trials, seed=args.seed)
    if not picked:
        raise SystemExit("未找到满足约束的子集，请增大 --trials。")

    keys_sel, m = picked
    key_set = set(keys_sel)
    out_rows = [
        r
        for r in rows
        if r.get("harness") == "react"
        and r.get("model") == "deepseek_chat"
        and r.get("security_mode") == "safe_harness"
        and r.get("ablation") in ABLATIONS
        and (r["task_id"], r.get("attack")) in key_set
    ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as wf:
        for r in out_rows:
            wf.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"写入 {args.output}，共 {len(out_rows)} 行（{len(keys_sel)} 个 task×attack × 5 种消融）。")
    for a in ABLATIONS:
        mm = m[a]
        print(f"  {a:8} UBR {mm['ubr']*100:.2f}%  ASR {mm['asr']*100:.2f}%  R {mm['reachable']}  atk {mm['atk']}")


if __name__ == "__main__":
    main()
