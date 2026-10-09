"""Reject placeholder, weak, duplicate, or URL-unsafe staging secrets."""

from __future__ import annotations

from collections.abc import Mapping
import os
import re


_MINIMUM_LENGTHS = {
    "SAFEHARNESS_POSTGRES_ADMIN_PASSWORD": 16,
    "SAFEHARNESS_POSTGRES_MIGRATOR_PASSWORD": 16,
    "SAFEHARNESS_POSTGRES_WRITER_PASSWORD": 16,
    "SAFEHARNESS_POSTGRES_READER_PASSWORD": 16,
    "SAFEHARNESS_POSTGRES_RETENTION_PASSWORD": 16,
    "SAFEHARNESS_REDIS_PASSWORD": 16,
    "SAFEHARNESS_REDIS_GATEWAY_PASSWORD": 16,
    "SAFEHARNESS_REDIS_COMMUNICATION_PASSWORD": 16,
    "SAFEHARNESS_GATEWAY_API_KEY": 32,
    "SAFEHARNESS_GATEWAY_SIGNING_KEY": 32,
    "SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY": 32,
    "GRAFANA_ADMIN_PASSWORD": 16,
}
_URL_SAFE = re.compile(r"[A-Za-z0-9._~-]+")


def configuration_errors(values: Mapping[str, str]) -> tuple[str, ...]:
    errors = []
    configured: dict[str, str] = {}
    for name, minimum_length in _MINIMUM_LENGTHS.items():
        value = values.get(name, "")
        configured[name] = value
        if value.lower().startswith("replace-"):
            errors.append(f"{name} still contains the example placeholder")
        elif len(value) < minimum_length:
            errors.append(f"{name} must contain at least {minimum_length} characters")
        elif _URL_SAFE.fullmatch(value) is None:
            errors.append(f"{name} must use URL-safe characters in this staging stack")

    by_value: dict[str, list[str]] = {}
    for name, value in configured.items():
        if value:
            by_value.setdefault(value, []).append(name)
    for names in by_value.values():
        if len(names) > 1:
            errors.append("separate secrets are required for " + ", ".join(names))
    return tuple(errors)


def main() -> int:
    errors = configuration_errors(os.environ)
    if errors:
        for error in errors:
            print(f"configuration error: {error}")
        return 1
    print("SafeHarness staging secret configuration passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
