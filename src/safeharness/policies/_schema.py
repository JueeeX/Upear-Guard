"""Dependency-free validation for the JSON Schema subset used by tool adapters."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def validate_arguments(arguments: Mapping[str, Any], schema: Mapping[str, Any]) -> list[str]:
    """Validate tool arguments against a deliberately small JSON Schema subset.

    Supported keywords are ``type``, ``properties``, ``required``, ``enum``,
    ``items``, and ``additionalProperties``. Deployments that require the full
    JSON Schema specification should validate inside their trusted ToolCatalog.
    """

    if not schema:
        return []
    return _validate(arguments, schema, path="$", root=True)


def _validate(value: Any, schema: Mapping[str, Any], *, path: str, root: bool = False) -> list[str]:
    errors: list[str] = []
    expected = schema.get("type", "object" if root else None)
    if expected is not None and not _matches_type(value, expected):
        return [f"{path} must be of type {expected}"]

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path} must be one of the declared enum values")

    if isinstance(value, Mapping):
        properties = schema.get("properties", {})
        required = schema.get("required", ())
        if not isinstance(properties, Mapping):
            return [f"{path} schema properties must be an object"]
        if not isinstance(required, Sequence) or isinstance(required, (str, bytes)):
            return [f"{path} schema required must be an array"]
        for name in required:
            if name not in value:
                errors.append(f"{path}.{name} is required")
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    errors.append(f"{path}.{name} is not an allowed property")
        for name, nested_schema in properties.items():
            if name in value:
                if not isinstance(nested_schema, Mapping):
                    errors.append(f"{path}.{name} schema must be an object")
                else:
                    errors.extend(
                        _validate(value[name], nested_schema, path=f"{path}.{name}")
                    )

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        item_schema = schema.get("items")
        if item_schema is not None:
            if not isinstance(item_schema, Mapping):
                errors.append(f"{path} schema items must be an object")
            else:
                for index, item in enumerate(value):
                    errors.extend(_validate(item, item_schema, path=f"{path}[{index}]"))
    return errors


def _matches_type(value: Any, expected: Any) -> bool:
    if isinstance(expected, Sequence) and not isinstance(expected, (str, bytes)):
        return any(_matches_type(value, item) for item in expected)
    checks = {
        "null": lambda item: item is None,
        "boolean": lambda item: isinstance(item, bool),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "string": lambda item: isinstance(item, str),
        "array": lambda item: isinstance(item, Sequence)
        and not isinstance(item, (str, bytes, bytearray)),
        "object": lambda item: isinstance(item, Mapping),
    }
    checker = checks.get(expected)
    return checker(value) if checker is not None else False
