"""Trusted user-intent records shared by policies and framework adapters."""

from __future__ import annotations

import hashlib


TRUSTED_USER_INTENT_STATE_KEY = "safeharness.trusted_user_intent"


def user_intent_digest(content: str) -> str:
    """Return a stable digest for the exact sanitized user intent."""

    if not isinstance(content, str):
        raise TypeError("trusted user intent must be a string")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
