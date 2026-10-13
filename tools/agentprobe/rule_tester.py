"""Rule-package regression: run supplementary rules against local attack suites.

The first piece of the policy-engineering toolchain (rule_tester in the
AgentGuard sense, rebuilt on this repo's own loader). Read-only: it never
touches the running platform or any database.

For every attack text in the suites it measures two verdicts:
- **baseline**  — the builtin default patterns only (the historic InformPolicy);
- **augmented** — builtin + the supplementary rules from ``--rules-dir``.

Report: per-suite and total ASR before/after, per-rule contribution (which
custom rules actually fired), dead-rule warnings (rules that never fired on
this corpus — either dead or covering attacks outside this suite), and the
escape list (attacks that still pass the augmented set).

Usage::

    python tools/agentprobe/rule_tester.py --rules-dir my-rules \
        [--suites tools/agentprobe/suites] [--json out.json]

Exit codes: 0 = report produced; 2 = rules directory or suites invalid
(fail-closed: a broken rule package must not produce a green report).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from safeharness.policies.inform import InformPolicy, _DEFAULT_PATTERNS  # noqa: E402
from safeharness.policies.rules_loader import (  # noqa: E402
    load_rules_from_dir,
    validate_rules_dir,
)


def _load_attacks(suites_dir: Path) -> list[dict]:
    attacks: list[dict] = []
    for path in sorted(suites_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] cannot read suite {path.name}: {exc}", file=sys.stderr)
            continue
        suite_name = str(data.get("name") or path.stem)
        for item in data.get("attacks") or []:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                attacks.append(
                    {
                        "suite": suite_name,
                        "id": str(item.get("id") or "?"),
                        "severity": str(item.get("severity") or "?"),
                        "text": item["text"],
                    }
                )
    return attacks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rule_tester",
        description="Regression for supplementary SafeHarness injection rules.",
    )
    parser.add_argument("--rules-dir", default="", help="supplementary rules directory (optional)")
    parser.add_argument(
        "--suites", default=str(_REPO_ROOT / "tools" / "agentprobe" / "suites"),
        help="directory containing attack-suite JSON files",
    )
    parser.add_argument("--json", dest="json_out", default="", help="write the report as JSON")
    args = parser.parse_args(argv)

    suites_dir = Path(args.suites)
    attacks = _load_attacks(suites_dir)
    if not attacks:
        print(f"[FAIL] no attacks found under {suites_dir}", file=sys.stderr)
        return 2

    custom_rules = []
    if args.rules_dir:
        errors = validate_rules_dir(args.rules_dir)
        if errors:
            print("[FAIL] invalid rule package:", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
            return 2
        custom_rules = list(load_rules_from_dir(args.rules_dir))

    baseline = InformPolicy()
    augmented = (
        InformPolicy(patterns=_DEFAULT_PATTERNS + tuple(rule.pattern for rule in custom_rules))
        if custom_rules
        else baseline
    )

    rule_names = [rule.name for rule in custom_rules]
    fired: dict[str, list[str]] = {name: [] for name in rule_names}
    rows = []
    escapes = []
    for attack in attacks:
        text_value = attack["text"]
        _, baseline_hit, _ = baseline._sanitize_value(text_value)
        _, augmented_hit, _ = augmented._sanitize_value(text_value)
        hit_rules = [
            rule.name
            for rule in custom_rules
            if re.search(rule.pattern, text_value, re.IGNORECASE)
        ]
        for name in hit_rules:
            fired[name].append(attack["id"])
        if not augmented_hit:
            escapes.append(f"{attack['suite']}/{attack['id']}")
        rows.append({**attack, "baseline": baseline_hit, "augmented": augmented_hit, "rules": hit_rules})

    total = len(rows)
    baseline_caught = sum(1 for row in rows if row["baseline"])
    augmented_caught = sum(1 for row in rows if row["augmented"])

    print(f"attacks: {total}  (suites under {suites_dir})")
    print(f"baseline ASR : {total - baseline_caught}/{total}  ({(total - baseline_caught) / total:.1%})")
    print(f"augmented ASR: {total - augmented_caught}/{total}  ({(total - augmented_caught) / total:.1%})")
    if custom_rules:
        print(f"rules: {len(custom_rules)} from {args.rules_dir}")
        for name in rule_names:
            mark = "" if fired[name] else "  [no hit on this corpus — dead rule?]"
            print(f"  {name}: fired on {len(fired[name])} attack(s){mark}")
            if fired[name]:
                print(f"    {', '.join(fired[name])}")
        if augmented_caught == baseline_caught:
            print("note: rules added no new catches on this corpus (baseline already covers it)")
    else:
        print("rules: none (baseline-only run)")
    if escapes:
        print(f"escapes ({len(escapes)}): {', '.join(escapes)}")

    if args.json_out:
        report = {
            "total": total,
            "baseline_caught": baseline_caught,
            "augmented_caught": augmented_caught,
            "escapes": escapes,
            "rules": [
                {"name": name, "fired": fired[name]} for name in rule_names
            ],
            "rows": rows,
        }
        Path(args.json_out).write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"json report: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
