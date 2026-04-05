"""
Dataset download and loading for Agent-SafetyBench.

Tries HuggingFace `datasets` first, then falls back to direct download
from GitHub.  All data is cached under the path specified in experiment.yaml.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = _PROJECT_ROOT / "data" / "agent_safety_bench"


def _download_from_hf() -> list[dict]:
    """Load via HuggingFace datasets library."""
    from datasets import load_dataset
    ds = load_dataset("thu-coai/Agent-SafetyBench", split="train")
    return [dict(row) for row in ds]


def _download_from_github() -> list[dict]:
    """Fallback: fetch the raw JSON from the GitHub repository."""
    import requests
    url = (
        "https://raw.githubusercontent.com/thu-coai/Agent-SafetyBench"
        "/main/data/released_data.json"
    )
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    return resp.json()


def download_dataset(force: bool = False) -> Path:
    """Download Agent-SafetyBench to *DATA_DIR* and return the local path.

    Skips download if the file already exists (unless *force=True*).
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = DATA_DIR / "released_data.json"

    if cache_file.exists() and not force:
        return cache_file

    try:
        data = _download_from_hf()
    except Exception as exc:
        print(f"[data_loader] HuggingFace download failed ({exc}); "
              "trying GitHub fallback …")
        data = _download_from_github()

    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    print(f"[data_loader] Saved {len(data)} examples → {cache_file}")
    return cache_file


def load_dataset_local(path: Path | str | None = None) -> list[dict]:
    """Load the cached dataset from disk.  Downloads first if *path* is omitted."""
    if path is None:
        path = download_dataset()
    else:
        path = Path(path)
        if not path.is_absolute():
            path = _PROJECT_ROOT / path
        if not path.exists():
            raise FileNotFoundError(
                f"Dataset file not found: {path} "
                "(expected a JSON list; set data.dataset_file in experiment.yaml)"
            )
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_subset(
    n: int = 3,
    seed: int = 42,
    *,
    dataset_file: str | Path | None = None,
    sequential: bool = False,
) -> list[dict]:
    """Load *n* tasks from the benchmark.

    If *dataset_file* is set, load that file (path relative to project root).
    If *sequential* is True, return the first *n* records in file order (no shuffle).
    Otherwise (*sequential* False, default) use risk-bucket round-robin sampling
    on the default full ``released_data.json``.
    """
    if dataset_file is not None:
        data = load_dataset_local(dataset_file)
    else:
        data = load_dataset_local()
    n = min(n, len(data))
    if sequential:
        return data[:n]

    rng = random.Random(seed)

    by_risk: dict[str, list[dict]] = {}
    for item in data:
        for risk in item.get("risks", []):
            by_risk.setdefault(risk, []).append(item)

    for bucket in by_risk.values():
        rng.shuffle(bucket)

    seen_ids: set[int] = set()
    selected: list[dict] = []
    risk_keys = sorted(by_risk.keys())

    if not risk_keys:
        return data[:n]

    idx = 0
    while len(selected) < n:
        risk = risk_keys[idx % len(risk_keys)]
        for candidate in by_risk[risk]:
            cid = candidate["id"]
            if cid not in seen_ids:
                selected.append(candidate)
                seen_ids.add(cid)
                break
        idx += 1
        if idx > len(risk_keys) * len(data):
            break

    return selected[:n]
