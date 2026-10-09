from __future__ import annotations

import asyncio
import unittest

from tests.performance_budget import BUDGETS, run_benchmarks


class PerformanceBudgetTests(unittest.TestCase):
    def test_local_hot_paths_stay_within_absolute_p95_budgets(self) -> None:
        # IsolatedAsyncioTestCase enables asyncio debug mode, which measures its
        # scheduler instrumentation instead of production SDK overhead.
        results = asyncio.run(run_benchmarks(samples=500, warmup=50))
        for name, metrics in results.items():
            with self.subTest(name=name):
                self.assertLessEqual(
                    metrics["p95_overhead_ms"],
                    BUDGETS[name].p95_overhead_ms,
                )
                self.assertLessEqual(
                    metrics["p99_overhead_ms"],
                    BUDGETS[name].p99_overhead_ms,
                )


if __name__ == "__main__":
    unittest.main()
