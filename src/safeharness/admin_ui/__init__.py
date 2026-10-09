"""Small, dependency-free management console for SafeHarness."""

from typing import Any

__all__ = ["AdminUISettings", "create_admin_ui_server"]


def __getattr__(name: str) -> Any:
    if name == "AdminUISettings":
        from safeharness.admin_ui.server import AdminUISettings

        return AdminUISettings
    if name == "create_admin_ui_server":
        from safeharness.admin_ui.server import create_admin_ui_server

        return create_admin_ui_server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
