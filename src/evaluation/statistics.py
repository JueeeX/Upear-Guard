"""
Statistical analysis utilities for SafeHarness experiments.

Provides:
  - Bootstrap confidence intervals for all safety metrics
  - Paired bootstrap significance tests between configurations
  - Per-risk-category breakdown
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Callable

from src.evaluation.metrics import AggregateMetrics, compute_metrics


@dataclass
class ConfidenceInterval:
    metric: str
    point_estimate: float
    ci_lower: float
    ci_upper: float
    alpha: float = 0.05

    def __str__(self) -> str:
        return (f"{self.metric}: {self.point_estimate:.4f} "
                f"[{self.ci_lower:.4f}, {self.ci_upper:.4f}] "
                f"({100*(1-self.alpha):.0f}% CI)")


@dataclass
class SignificanceTest:
    metric: str
    config_a: str
    config_b: str
    diff: float
    p_value: float
    significant: bool

    def __str__(self) -> str:
        sig = "***" if self.p_value < 0.001 else ("**" if self.p_value < 0.01
              else ("*" if self.p_value < 0.05 else "n.s."))
        return (f"{self.metric}: {self.config_a} vs {self.config_b}  "
                f"diff={self.diff:+.4f}  p={self.p_value:.4f} {sig}")


def bootstrap_ci(
    results: list[tuple],
    metric_fn: Callable[[AggregateMetrics], float],
    n_bootstrap: int = 1000,
    alpha: float = 0.05,
    seed: int = 42,
    metric_name: str = "",
) -> ConfidenceInterval:
    """Compute a bootstrap confidence interval for a single metric.

    *results* is the standard list of ``(task, hr, jr, rr)`` tuples.
    *metric_fn* extracts the scalar (e.g. ``lambda m: m.ubr``).
    """
    if not results:
        return ConfidenceInterval(
            metric=metric_name, point_estimate=0.0,
            ci_lower=0.0, ci_upper=0.0, alpha=alpha,
        )

    rng = random.Random(seed)
    point = metric_fn(compute_metrics(results))

    boot_values: list[float] = []
    n = len(results)
    for _ in range(n_bootstrap):
        sample = [results[rng.randint(0, n - 1)] for _ in range(n)]
        boot_values.append(metric_fn(compute_metrics(sample)))

    boot_values.sort()
    lo_idx = int(n_bootstrap * (alpha / 2))
    hi_idx = int(n_bootstrap * (1 - alpha / 2)) - 1
    return ConfidenceInterval(
        metric=metric_name,
        point_estimate=point,
        ci_lower=boot_values[max(0, lo_idx)],
        ci_upper=boot_values[min(len(boot_values) - 1, hi_idx)],
        alpha=alpha,
    )


def paired_bootstrap_test(
    results_a: list[tuple],
    results_b: list[tuple],
    metric_fn: Callable[[AggregateMetrics], float],
    n_bootstrap: int = 1000,
    seed: int = 42,
    metric_name: str = "",
    config_a: str = "A",
    config_b: str = "B",
) -> SignificanceTest:
    """Paired bootstrap test: is *metric_fn(A)* significantly different
    from *metric_fn(B)*?  Assumes both result lists have the same tasks
    in the same order."""
    if not results_a or not results_b:
        return SignificanceTest(
            metric=metric_name, config_a=config_a, config_b=config_b,
            diff=0.0, p_value=1.0, significant=False,
        )

    rng = random.Random(seed)
    observed_diff = (metric_fn(compute_metrics(results_a))
                     - metric_fn(compute_metrics(results_b)))

    n = min(len(results_a), len(results_b))
    count_extreme = 0
    for _ in range(n_bootstrap):
        idx = [rng.randint(0, n - 1) for _ in range(n)]
        sample_a = [results_a[i] for i in idx]
        sample_b = [results_b[i] for i in idx]
        diff = (metric_fn(compute_metrics(sample_a))
                - metric_fn(compute_metrics(sample_b)))
        if abs(diff) >= abs(observed_diff):
            count_extreme += 1

    p_value = count_extreme / n_bootstrap
    return SignificanceTest(
        metric=metric_name,
        config_a=config_a,
        config_b=config_b,
        diff=observed_diff,
        p_value=p_value,
        significant=p_value < 0.05,
    )


def compute_all_cis(
    results: list[tuple],
    n_bootstrap: int = 1000,
    seed: int = 42,
) -> list[ConfidenceInterval]:
    """Compute bootstrap CIs for all standard metrics."""
    metric_fns = [
        ("UBR", lambda m: m.ubr),
        ("ASR", lambda m: m.asr),
        ("TCR", lambda m: m.tcr),
        ("UA", lambda m: m.ua),
    ]
    cis = []
    for name, fn in metric_fns:
        cis.append(bootstrap_ci(
            results, fn, n_bootstrap=n_bootstrap,
            seed=seed, metric_name=name,
        ))
    return cis


def per_category_metrics(
    results: list[tuple],
) -> dict[str, AggregateMetrics]:
    """Break down metrics by risk category."""
    by_category: dict[str, list[tuple]] = {}
    for task, hr, jr, rr in results:
        for risk in task.get("risks", ["unknown"]):
            by_category.setdefault(risk, []).append((task, hr, jr, rr))

    return {cat: compute_metrics(items) for cat, items in sorted(by_category.items())}
