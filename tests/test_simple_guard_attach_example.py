from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


class SimpleGuardAttachExampleTests(unittest.TestCase):
    def test_example_runs_in_production_mode_and_reports_enforcement(self) -> None:
        root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [sys.executable, "examples/simple_guard_attach.py"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        lines = completed.stdout.strip().splitlines()
        report = json.loads(lines[-1])
        self.assertEqual(report["security_mode"], "production")
        self.assertTrue(report["attachment_contract_satisfied"])
        self.assertEqual(report["capabilities"]["input_filter"], "enforce")


if __name__ == "__main__":
    unittest.main()
