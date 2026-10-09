"""Small helpers for defensively copying event and decision mappings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime
from enum import Enum
from types import MappingProxyType
from typing import Any


def frozen_mapping(value: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    """Return a recursively read-only copy of a mapping.

    Framework-native leaf objects are preserved in memory. Event serialization and
    audit minimization replace unknown objects without calling their potentially
    sensitive ``repr`` implementations.
    """

    return MappingProxyType(
        {str(key): _freeze(item) for key, item in (value or {}).items()}
    )


def plain_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a read-only mapping into a regular dictionary."""

    return dict(value)


def json_safe(value: Any) -> Any:
    """Convert framework-native values into a JSON-compatible structure.

    Unknown objects are represented only by their qualified type name. Their
    ``repr`` is deliberately excluded because it may contain credentials or
    private application state.
    """

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Enum):
        return json_safe(value.value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"type": "bytes", "length": len(value)}
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(item) for item in value]
    value_type = type(value)
    return {"type": f"{value_type.__module__}.{value_type.__qualname__}"}


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return frozen_mapping(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    return value
