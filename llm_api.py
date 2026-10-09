"""Configurable OpenAI-compatible LLM client for SafeHarness examples.

The framework-independent ``safeharness`` runtime does not require an LLM SDK.
This module serves the paper-reproduction harnesses and examples. It loads a
repository-local ``config/llm.env`` file without overriding environment
variables already provided by the host process.
"""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Mapping

try:
    from openai import OpenAI
except ImportError:  # Keep the core package and mock-based tests dependency-free.
    OpenAI = None  # type: ignore[assignment,misc]


logger = logging.getLogger(__name__)

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_REPOSITORY_ROOT = Path(__file__).resolve().parent
_DEFAULT_ENV_PATH = _REPOSITORY_ROOT / "config" / "llm.env"
_MODEL_ALIASES = {
    "gpt4o": "deepseek-v4-flash",
    "gpt4omini": "deepseek-v4-flash",
    "gpt5.4": "gpt-5.4",
    "deepseek_chat": "deepseek-v4-flash",
    "deepseek_reasoner": "deepseek-v4-flash",
    "sonnet4.6": "claude-sonnet-4-6",
    "claude_sonnet": "claude-sonnet-4-5-20250929",
    "claude3haiku": "claude-sonnet-4-5-20250929",
}

HTTP_MAX_RETRIES = 5
EMPTY_RESPONSE_MAX_ATTEMPTS = 10
_EMPTY_RETRY_BASE_DELAY_SEC = 0.5


class InsufficientBalanceError(RuntimeError):
    """Raised when an upstream API reports HTTP 402 or insufficient balance."""


class LLMConfigurationError(RuntimeError):
    """Raised when the selected LLM endpoint is not configured."""


def _default_env_path() -> Path:
    configured_path = os.environ.get("SAFEHARNESS_ENV_FILE")
    if configured_path:
        return Path(configured_path).expanduser()
    return _DEFAULT_ENV_PATH


def load_env_file(
    path: str | Path | None = None, *, override: bool = False
) -> Path | None:
    """Load simple ``KEY=VALUE`` assignments from a dotenv file.

    Process-level environment values take precedence by default, which keeps
    container, CI, and secret-manager injection authoritative. Values may be
    enclosed in single or double quotes; the parser intentionally does not
    perform shell expansion or execute dotenv content.
    """

    if path is None:
        env_path = _default_env_path()
    else:
        env_path = Path(path).expanduser()

    if not env_path.exists():
        return None
    if not env_path.is_file():
        raise LLMConfigurationError(f"dotenv path is not a file: {env_path}")

    for line_number, raw_line in enumerate(
        env_path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or not _ENV_NAME.fullmatch(name):
            logger.warning(
                "Ignoring invalid dotenv assignment in %s at line %d.",
                env_path,
                line_number,
            )
            continue
        value = _parse_env_value(value.strip())
        if override or name not in os.environ:
            os.environ[name] = value
    return env_path


def _parse_env_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


try:
    load_env_file()
except (OSError, UnicodeError, LLMConfigurationError) as exc:
    logger.warning("Unable to load SafeHarness dotenv configuration: %s", exc)


def _nonempty_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return default


def _is_insufficient_balance(exc: BaseException) -> bool:
    if getattr(exc, "status_code", None) == 402:
        return True
    return "insufficient balance" in str(exc).lower()


def _sleep_before_empty_retry(attempt_index: int) -> None:
    time.sleep(_EMPTY_RETRY_BASE_DELAY_SEC * (2**attempt_index))


def configured_model(*, role: str = "agent") -> str:
    """Return the model configured for an Agent or LLM-as-Judge call."""

    if role not in {"agent", "judge"}:
        raise ValueError("role must be 'agent' or 'judge'")
    if role == "judge":
        model = _nonempty_env("SAFEHARNESS_JUDGE_MODEL", "SAFEHARNESS_LLM_MODEL")
    else:
        model = _nonempty_env("SAFEHARNESS_LLM_MODEL")
    if not model:
        raise LLMConfigurationError(
            "No model is configured. Set SAFEHARNESS_LLM_MODEL in config/llm.env."
        )
    return model


def resolve_model_name(model_name: str, *, role: str = "agent") -> str:
    """Resolve a legacy short name or ``env``/``judge`` to a concrete model ID."""

    if not isinstance(model_name, str) or not model_name.strip():
        raise ValueError("model_name must be a non-empty string")
    name = model_name.strip()
    if name in {"env", "default", "configured"}:
        return configured_model(role="agent")
    if name in {"judge", "configured_judge"}:
        return configured_model(role="judge")

    alias_override = _nonempty_env(
        f"SAFEHARNESS_MODEL_{name.upper().replace('.', '_').replace('-', '_')}"
    )
    if alias_override:
        return alias_override
    return _MODEL_ALIASES.get(name, name)


def _endpoint_settings() -> tuple[str, str]:
    """Return the endpoint and credential for an OpenAI-compatible gateway."""

    api_key = _nonempty_env(
        "SAFEHARNESS_LLM_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "ANTHROPIC_API_KEY",
    )
    base_url = _nonempty_env(
        "SAFEHARNESS_LLM_BASE_URL",
        "OPENAI_BASE_URL",
        "DEEPSEEK_BASE_URL",
        "ANTHROPIC_BASE_URL",
        default="https://api.openai.com/v1",
    )
    if not api_key or api_key in {"replace-with-your-api-key", "sk-..."}:
        raise LLMConfigurationError(
            "No API key is configured. Set SAFEHARNESS_LLM_API_KEY in config/llm.env."
        )
    return base_url, api_key


def _get_openai_client(timeout: int) -> Any:
    base_url, api_key = _endpoint_settings()
    if OpenAI is None:
        raise LLMConfigurationError(
            "The optional 'openai' package is required for live LLM calls. "
            "Install dependencies with: pip install -r requirements.txt"
        )
    return OpenAI(
        base_url=base_url,
        api_key=api_key,
        timeout=timeout,
        max_retries=HTTP_MAX_RETRIES,
    )


def call_llm(
    messages: list[Mapping[str, Any]],
    model_name: str,
    params: Mapping[str, Any] | None = None,
    timeout: int = 3600,
) -> str | None:
    """Call an OpenAI-compatible ``/chat/completions`` endpoint."""

    create_kw = dict(params or {})
    last_bad: str | None = None
    try:
        client = _get_openai_client(timeout)
    except LLMConfigurationError as exc:
        logger.error("LLM configuration error: %s", exc)
        return None
    except Exception as exc:
        if _is_insufficient_balance(exc):
            raise InsufficientBalanceError(str(exc)) from exc
        logger.warning("Error creating LLM client: %s", type(exc).__name__)
        return None

    for attempt in range(EMPTY_RESPONSE_MAX_ATTEMPTS):
        try:
            completion = client.chat.completions.create(
                model=model_name,
                messages=messages,
                **create_kw,
            )
            answer = completion.choices[0].message.content
        except Exception as exc:
            if _is_insufficient_balance(exc):
                raise InsufficientBalanceError(str(exc)) from exc
            logger.warning("Error calling LLM: %s", type(exc).__name__)
            return None

        if isinstance(answer, str) and answer:
            return answer

        last_bad = repr(answer)
        if attempt + 1 < EMPTY_RESPONSE_MAX_ATTEMPTS:
            logger.info(
                "LLM returned an empty response; retrying %d/%d (model=%r)",
                attempt + 1,
                EMPTY_RESPONSE_MAX_ATTEMPTS,
                model_name,
            )
            _sleep_before_empty_retry(attempt)

    logger.warning(
        "LLM returned empty responses after %d attempts (model=%r, last=%s)",
        EMPTY_RESPONSE_MAX_ATTEMPTS,
        model_name,
        last_bad,
    )
    return None


def call_anthropic(
    messages: list[Mapping[str, Any]],
    model_name: str,
    max_tokens: int = 4096,
    timeout: int = 3600,
) -> str | None:
    """Compatibility entry point for Claude models through a compatible gateway."""

    return call_llm(
        messages,
        model_name=model_name,
        params={"max_tokens": max_tokens},
        timeout=timeout,
    )


def call_by_name(
    model_short_name: str,
    messages: list[Mapping[str, Any]],
    *,
    params: Mapping[str, Any] | None = None,
    timeout: int = 3600,
    role: str = "agent",
) -> str | None:
    """Call a configured alias or a raw OpenAI-compatible model ID."""

    try:
        model_name = resolve_model_name(model_short_name, role=role)
    except (LLMConfigurationError, ValueError) as exc:
        logger.error("LLM model configuration error: %s", exc)
        return None
    return call_llm(messages, model_name=model_name, params=params, timeout=timeout)


def call_judge_model(
    messages: list[Mapping[str, Any]],
    model_name: str,
    *,
    timeout: int = 120,
) -> str | None:
    """Call a concrete judge model with deterministic, low-variance settings."""

    try:
        resolved = resolve_model_name(model_name, role="judge")
    except (LLMConfigurationError, ValueError) as exc:
        logger.error("LLM judge configuration error: %s", exc)
        return None
    return call_llm(
        messages,
        model_name=resolved,
        params={
            "temperature": 0,
            "max_tokens": 256,
            "response_format": {"type": "json_object"},
        },
        timeout=timeout,
    )


def _alias_caller(alias: str):
    def call(messages: list[Mapping[str, Any]]) -> str | None:
        return call_by_name(alias, messages)

    return call


def call_claude_sonnet(messages: list[Mapping[str, Any]]) -> str | None:
    return call_by_name("claude_sonnet", messages)


def call_claude_sonnet_4_6(messages: list[Mapping[str, Any]]) -> str | None:
    return call_by_name("sonnet4.6", messages)


def call_claude_3_haiku(messages: list[Mapping[str, Any]]) -> str | None:
    return call_by_name("claude3haiku", messages)


def call_gpt_5_4(messages: list[Mapping[str, Any]]) -> str | None:
    return call_by_name("gpt5.4", messages)


def call_gpt4o(messages: list[Mapping[str, Any]]) -> str | None:
    return call_by_name("gpt4o", messages)


def call_gpt_4o_mini(messages: list[Mapping[str, Any]]) -> str | None:
    return call_by_name("gpt4omini", messages)


def call_deepseek_chat(messages: list[Mapping[str, Any]]) -> str | None:
    return call_by_name("deepseek_chat", messages)


def call_deepseek_reasoner(messages: list[Mapping[str, Any]]) -> str | None:
    return call_by_name("deepseek_reasoner", messages)


MODEL_FUNC_MAP = {alias: _alias_caller(alias) for alias in _MODEL_ALIASES}
MODEL_FUNC_MAP["env"] = _alias_caller("env")
MODEL_FUNC_MAP["judge"] = _alias_caller("judge")
