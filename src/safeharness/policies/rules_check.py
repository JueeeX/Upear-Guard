"""Deploy-time validation for SafeHarness supplementary injection rules.

Run before pointing ``SAFEHARNESS_INFORM_RULES_DIR`` at a directory::

    python -m safeharness.policies.rules_check rules/

Exit code 0 = every directory parses and validates; 1 = at least one error
(duplicate names, invalid regex, unsupported action/severity, unreadable file).
"""

from __future__ import annotations

import argparse
import sys

from safeharness.policies.rules_loader import validate_rules_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safeharness.policies.rules_check",
        description="Validate supplementary SafeHarness injection rule directories.",
    )
    parser.add_argument("directories", nargs="+", help="rule directories to check")
    args = parser.parse_args(argv)

    failed = False
    for directory in args.directories:
        errors = validate_rules_dir(directory)
        if errors:
            failed = True
            print(f"[FAIL] {directory}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"[OK]   {directory}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
