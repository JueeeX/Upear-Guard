"""Optional file-based injection rules for :class:`InformPolicy` (additive).

Operators can drop YAML rule files into a directory and point
``SAFEHARNESS_INFORM_RULES_DIR`` at it; ``build_inform_policy()`` then returns
an InformPolicy whose patterns are the built-in defaults **plus** the file
rules. Design constraints (deliberate, do not relax):

- **Additive only**: the built-in default patterns always stay active; rule
  files can add patterns, never remove or weaken them.
- **Default-off**: with the env unset this module yields a plain
  ``InformPolicy()`` — identical to the historic construction sites.
- **Fail-closed**: a configured but unreadable/invalid rule directory raises
  :class:`RuleLoadError` instead of silently running with fewer rules.
- **Deny-only**: ``action`` accepts ``deny``; a per-rule allow path would
  loosen the baseline and is out of scope by design.
- **Process-cached**: the runtime loads a directory once per process, so rule
  changes apply after a restart — unless ``SAFEHARNESS_INFORM_RULES_WATCH`` is
  enabled, in which case each cache hit re-stats the directory (name + mtime +
  size fingerprint) and rescans on change, so edited rule files take effect on
  the next construction without a restart. The check adds a few stat calls
  per construction and no background thread; with the watch env unset the
  behaviour (including staleness) is byte-identical to the historic cache.
  ``validate_rules_dir`` is the pure per-run checker used by the CLI.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from safeharness.policies.inform import _DEFAULT_PATTERNS, InformPolicy

ENV_RULES_DIR = "SAFEHARNESS_INFORM_RULES_DIR"
ENV_RULES_WATCH = "SAFEHARNESS_INFORM_RULES_WATCH"

_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_ACTIONS = frozenset({"deny"})
_SUFFIXES = (".yaml", ".yml")
_MAX_CHAIN_TAGS = 16


class RuleLoadError(RuntimeError):
    """A configured rule file is unreadable or semantically invalid."""


@dataclass(frozen=True)
class LoadedRule:
    name: str
    pattern: str
    severity: str
    category: str
    reason: str
    source: str


@dataclass(frozen=True)
class LoadedChain:
    """Cross-tool chain rule (see safeharness.policies.trajectory).

    ``first``/``then`` carry the tool-name regexes; ``first_tags``/``then_tags``
    the optional descriptor-tag conditions. Each endpoint needs at least one
    of the two; both given = AND.
    """

    name: str
    first: str
    then: str
    max_gap: int
    severity: str
    category: str
    reason: str
    source: str
    first_tags: tuple[str, ...] = ()
    then_tags: tuple[str, ...] = ()


_CACHE: dict[
    str,
    tuple[tuple[LoadedRule, ...], tuple[LoadedChain, ...], tuple | None],
] = {}


def _extract_rules(document: Any, source: str) -> list[dict[str, Any]]:
    """Accept a bare list, a single mapping, or {"rules": [...]}."""
    if document is None:
        return []
    if isinstance(document, list):
        return [item for item in document if item is not None]
    if isinstance(document, dict):
        if "rules" in document:
            nested = document.get("rules")
            if not isinstance(nested, list):
                raise ValueError("'rules' must be a list")
            return [item for item in nested if item is not None]
        if "chain_rules" in document:
            return []  # chains are collected separately in _scan_rules
        return [document]
    raise ValueError("top-level document must be a list or a mapping")


def _check_enum_field(label: str, item: dict[str, Any], key: str, default: str, allowed: frozenset[str]) -> tuple[list[str], str]:
    value = str(item.get(key) or default).strip().lower()
    if value not in allowed:
        return [f"{label}: {key} {value!r} not supported (allowed: {sorted(allowed)})"], default
    return [], value


def _check_rule(
    item: Any, label: str, seen: dict[str, str], source: str
) -> tuple[list[str], LoadedRule | None]:
    """Field checks for one rule mapping; returns (errors, rule|None)."""
    if not isinstance(item, dict):
        return [f"{label}: rule must be a mapping"], None
    rule_name = str(item.get("name") or "").strip()
    if not rule_name:
        return [f"{label}: missing 'name'"], None
    qualified = f"{label}:{rule_name}"
    if rule_name in seen:
        return (
            [f"{qualified}: duplicate rule name (first defined in {seen[rule_name]})"],
            None,
        )
    pattern = item.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        return [f"{qualified}: missing 'pattern'"], None
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return [f"{qualified}: invalid regex ({exc})"], None
    errors, action = _check_enum_field(qualified, item, "action", "deny", _ACTIONS)
    if errors:
        return errors, None
    errors, severity = _check_enum_field(qualified, item, "severity", "high", _SEVERITIES)
    if errors:
        return errors, None
    seen[rule_name] = source
    return [], LoadedRule(
        name=rule_name,
        pattern=pattern,
        severity=severity,
        category=str(item.get("category") or "").strip(),
        reason=str(item.get("reason") or "").strip(),
        source=source,
    )


def _check_chain_tags(qualified: str, item: dict[str, Any], key: str) -> tuple[list[str], tuple[str, ...]]:
    """Validate one chain tag list: non-empty strings, deduped, capped."""
    raw = item.get(key)
    if raw is None:
        return [], ()
    if not isinstance(raw, (list, tuple)):
        return [f"{qualified}: {key} must be a list of strings"], ()
    tags: list[str] = []
    for entry in raw:
        if not isinstance(entry, str) or not entry.strip():
            return [f"{qualified}: {key} entries must be non-empty strings"], ()
        tags.append(entry.strip())
    if len(tags) > _MAX_CHAIN_TAGS:
        return [f"{qualified}: {key} accepts at most {_MAX_CHAIN_TAGS} tags"], ()
    return [], tuple(dict.fromkeys(tags))


def _check_chain(
    item: Any, label: str, seen: dict[str, str], source: str
) -> tuple[list[str], LoadedChain | None]:
    """Field checks for one chain mapping; returns (errors, chain|None)."""
    if not isinstance(item, dict):
        return [f"{label}: chain must be a mapping"], None
    chain_name = str(item.get("name") or "").strip()
    if not chain_name:
        return [f"{label}: missing 'name'"], None
    qualified = f"{label}:{chain_name}"
    if chain_name in seen:
        return (
            [f"{qualified}: duplicate chain name (first defined in {seen[chain_name]})"],
            None,
        )
    first = item.get("first")
    then = item.get("then")
    first = first.strip() if isinstance(first, str) else ""
    then = then.strip() if isinstance(then, str) else ""
    errors, first_tags = _check_chain_tags(qualified, item, "first_tags")
    if errors:
        return errors, None
    errors, then_tags = _check_chain_tags(qualified, item, "then_tags")
    if errors:
        return errors, None
    if not first and not first_tags:
        return [f"{qualified}: endpoint 'first' needs a regex or tags"], None
    if not then and not then_tags:
        return [f"{qualified}: endpoint 'then' needs a regex or tags"], None
    for endpoint, pattern in (("first", first), ("then", then)):
        if pattern:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                return [f"{qualified}: invalid {endpoint} regex ({exc})"], None
    try:
        max_gap = max(0, int(item.get("max_gap") or 0))
    except (TypeError, ValueError):
        return [f"{qualified}: max_gap must be an integer"], None
    errors, severity = _check_enum_field(qualified, item, "severity", "high", _SEVERITIES)
    if errors:
        return errors, None
    seen[chain_name] = source
    return [], LoadedChain(
        name=chain_name,
        first=first,
        then=then,
        max_gap=max_gap,
        severity=severity,
        category=str(item.get("category") or "trajectory_chain").strip(),
        reason=str(item.get("reason") or "").strip(),
        source=source,
        first_tags=first_tags,
        then_tags=then_tags,
    )


def _scan_rules(directory: str) -> tuple[list[str], list[LoadedRule], list[LoadedChain]]:
    """Read every rule file on disk; return (errors, rules, chains). Pure."""
    errors: list[str] = []
    loaded: list[LoadedRule] = []
    chains_loaded: list[LoadedChain] = []
    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        return [f"cannot read rules directory {directory!r}: {exc}"], [], []

    seen: dict[str, str] = {}
    seen_chains: dict[str, str] = {}
    for name in names:
        if not name.lower().endswith(_SUFFIXES):
            continue
        path = os.path.join(directory, name)
        try:
            import yaml

            with open(path, encoding="utf-8") as handle:
                documents = list(yaml.safe_load_all(handle))
        except OSError as exc:
            errors.append(f"{name}: unreadable ({exc})")
            continue
        except Exception as exc:  # yaml parse errors
            errors.append(f"{name}: invalid YAML ({exc})")
            continue
        for index, document in enumerate(documents):
            try:
                entries = _extract_rules(document, name)
            except ValueError as exc:
                errors.append(f"{name} (doc {index}): {exc}")
                continue
            for position, item in enumerate(entries):
                rule_errors, rule = _check_rule(
                    item, f"{name} (doc {index} rule {position})", seen, name
                )
                errors.extend(rule_errors)
                if rule is not None:
                    loaded.append(rule)
            if isinstance(document, dict) and "chain_rules" in document:
                nested = document.get("chain_rules")
                if not isinstance(nested, list):
                    errors.append(f"{name} (doc {index}): 'chain_rules' must be a list")
                    continue
                for position, item in enumerate(nested):
                    if item is None:
                        continue
                    chain_errors, chain = _check_chain(
                        item, f"{name} (doc {index} chain {position})", seen_chains, name
                    )
                    errors.extend(chain_errors)
                    if chain is not None:
                        chains_loaded.append(chain)
    return errors, loaded, chains_loaded


def validate_rules_dir(directory: str) -> list[str]:
    """Return every validation error in the directory (empty list = clean).

    Pure checker: never touches the runtime cache, never raises.
    """
    return _scan_rules(directory)[0]


def load_rules_from_dir(directory: str, *, refresh: bool = False) -> tuple[LoadedRule, ...]:
    """Runtime load: once per process unless ``refresh=True`` or the watch env
    detects a file change; raises :class:`RuleLoadError` on any validation
    error (fail-closed)."""
    rules, _chains = _load_dir_cached(directory, refresh=refresh)
    return rules


def load_chains_from_dir(directory: str, *, refresh: bool = False) -> tuple[LoadedChain, ...]:
    """Runtime load of ``chain_rules`` entries; same caching contract as
    :func:`load_rules_from_dir`."""
    _rules, chains = _load_dir_cached(directory, refresh=refresh)
    return chains


def _dir_fingerprint(directory: str) -> tuple | None:
    """Change marker for the watched directory: sorted (name, mtime_ns, size)
    of every rule file. ``None`` means "cannot stat — force a rescan" so a
    vanishing directory is never mistaken for "unchanged"."""
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return None
    entries = []
    for name in names:
        if not name.lower().endswith(_SUFFIXES):
            continue
        try:
            stat = os.stat(os.path.join(directory, name))
        except OSError:
            return None
        entries.append((name, stat.st_mtime_ns, stat.st_size))
    return tuple(entries)


def _watch_enabled() -> bool:
    return (os.environ.get(ENV_RULES_WATCH) or "").strip().lower() in ("1", "true", "yes")


def _load_dir_cached(
    directory: str, *, refresh: bool = False
) -> tuple[tuple[LoadedRule, ...], tuple[LoadedChain, ...]]:
    key = os.path.abspath(directory)
    cached = _CACHE.get(key)
    if cached is not None and not refresh:
        rules, chains, fingerprint = cached
        if not _watch_enabled():
            return rules, chains
        if _dir_fingerprint(directory) == fingerprint:
            return rules, chains
        # Changed (or unstatable): fall through to a fresh scan. A scan that
        # now fails raises RuleLoadError — the fail-closed contract matches a
        # restart with the same broken directory; a later clean scan self-heals.
    errors, rules, chains = _scan_rules(directory)
    if errors:
        raise RuleLoadError(
            "invalid SafeHarness supplementary rules:\n  - " + "\n  - ".join(errors)
        )
    fingerprint = _dir_fingerprint(directory) if _watch_enabled() else None
    _CACHE[key] = (tuple(rules), tuple(chains), fingerprint)
    return _CACHE[key][:2]


def build_inform_policy(environ: dict[str, str] | None = None) -> InformPolicy:
    """The platform construction point for InformPolicy.

    Pattern sources merge additively: built-in defaults (always) + file rules
    (``SAFEHARNESS_INFORM_RULES_DIR``, process-cached) + runtime rules (set
    via :func:`apply_runtime_rules`, hot-swappable). With no sources beyond
    the defaults this is exactly ``InformPolicy()``.
    """
    values = os.environ if environ is None else environ
    directory = (values.get(ENV_RULES_DIR) or "").strip()
    runtime = _RUNTIME_RULES
    if not directory and not runtime:
        return InformPolicy()
    patterns = _DEFAULT_PATTERNS
    if directory:
        patterns = patterns + tuple(
            rule.pattern for rule in load_rules_from_dir(directory)
        )
    if runtime:
        patterns = patterns + tuple(rule.pattern for rule in runtime)
    return InformPolicy(patterns=patterns)


# --- runtime rules (DB-backed, hot-swappable; see SUMC policy center) ------

_RUNTIME_RULES: tuple[LoadedRule, ...] = ()
_RUNTIME_CHAINS: tuple[LoadedChain, ...] = ()


def _check_rule_dicts(items: list[Any]) -> tuple[list[str], list[LoadedRule]]:
    seen: dict[str, str] = {}
    errors: list[str] = []
    loaded: list[LoadedRule] = []
    for position, item in enumerate(items):
        rule_errors, rule = _check_rule(item, f"rule[{position}]", seen, "<runtime>")
        errors.extend(rule_errors)
        if rule is not None:
            loaded.append(rule)
    return errors, loaded


def validate_rule_dicts(items: list[Any]) -> list[str]:
    """Pure validation for a list of rule mappings (no files, no cache)."""
    return _check_rule_dicts(items)[0]


def apply_runtime_rules(items: list[Any]) -> tuple[LoadedRule, ...]:
    """Atomically swap the runtime rule set; raises on any invalid rule.

    Takes effect immediately for every new :func:`build_inform_policy` call
    in this process (no restart).
    """
    global _RUNTIME_RULES
    errors, loaded = _check_rule_dicts(items)
    if errors:
        raise RuleLoadError(
            "invalid SafeHarness runtime rules:\n  - " + "\n  - ".join(errors)
        )
    _RUNTIME_RULES = tuple(loaded)
    return _RUNTIME_RULES


def clear_runtime_rules() -> None:
    global _RUNTIME_RULES
    _RUNTIME_RULES = ()


def runtime_rules() -> tuple[LoadedRule, ...]:
    return _RUNTIME_RULES


def validate_chain_dicts(items: list[Any]) -> list[str]:
    """Pure validation for a list of chain mappings (no files, no cache)."""
    seen: dict[str, str] = {}
    errors: list[str] = []
    for position, item in enumerate(items):
        chain_errors, _chain = _check_chain(item, f"chain[{position}]", seen, "<runtime>")
        errors.extend(chain_errors)
    return errors


def apply_runtime_chains(items: list[Any]) -> tuple[LoadedChain, ...]:
    """Atomically swap the runtime chain set; raises on any invalid chain."""
    global _RUNTIME_CHAINS
    seen: dict[str, str] = {}
    errors: list[str] = []
    loaded: list[LoadedChain] = []
    for position, item in enumerate(items):
        chain_errors, chain = _check_chain(item, f"chain[{position}]", seen, "<runtime>")
        errors.extend(chain_errors)
        if chain is not None:
            loaded.append(chain)
    if errors:
        raise RuleLoadError(
            "invalid SafeHarness runtime chains:\n  - " + "\n  - ".join(errors)
        )
    _RUNTIME_CHAINS = tuple(loaded)
    return _RUNTIME_CHAINS


def clear_runtime_chains() -> None:
    global _RUNTIME_CHAINS
    _RUNTIME_CHAINS = ()


def runtime_chains() -> tuple[LoadedChain, ...]:
    return _RUNTIME_CHAINS


__all__ = [
    "ENV_RULES_DIR",
    "LoadedChain",
    "LoadedRule",
    "RuleLoadError",
    "apply_runtime_chains",
    "apply_runtime_rules",
    "build_inform_policy",
    "clear_runtime_chains",
    "clear_runtime_rules",
    "load_chains_from_dir",
    "load_rules_from_dir",
    "runtime_chains",
    "runtime_rules",
    "validate_chain_dicts",
    "validate_rule_dicts",
    "validate_rules_dir",
]
