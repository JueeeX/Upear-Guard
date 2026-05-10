"""
LLM client wrapper — imports call_llm / MODEL_FUNC_MAP from the local
llm_api.py so that base_url, api_key and model names are never
duplicated or hardcoded here.

Uses module-level access (``llm_api.call_llm``) rather than bare
imported names so that monkey-patching in tests works correctly.
"""

import sys
from pathlib import Path

_CODE_ROOT = str(Path(__file__).resolve().parents[1])
if _CODE_ROOT not in sys.path:
    sys.path.insert(0, _CODE_ROOT)

import llm_api  # noqa: E402

MODEL_FUNC_MAP_NAMES: dict[str, str] = {
    "gpt4o": "gpt-4o",
    "gpt4omini": "gpt-4o-mini-2024-07-18",
    "gpt5.4": "gpt-5.4-2026-03-05",
    "deepseek_chat": "deepseek-chat",
    "deepseek_reasoner": "deepseek-reasoner",
    "sonnet4.6": "claude-sonnet-4-6",
    "claude_sonnet": "claude-sonnet-4-5-20250929",
    "claude3haiku": "claude-3-haiku-20240307",
}


def available_models():
    """Return the list of model short-names that are currently enabled."""
    return list(llm_api.MODEL_FUNC_MAP.keys())


def call_model(model_name: str, messages: list[dict]) -> str | None:
    """Unified interface: call *model_name* with *messages*.

    *model_name* may be a MODEL_FUNC_MAP short name (e.g. ``gpt4o``) or a raw
    OpenAI-compatible gateway model id (e.g. ``gpt-5.4-2026-03-05``).
    """
    return llm_api.call_by_name(model_name, messages)


def call_judge(messages: list[dict], judge_model: str | None = None,
               temperature: float | None = None) -> str | None:
    """Call the LLM-as-Judge model.

    If *judge_model* is None, falls back to the first available model.
    When *temperature* is provided, it is forwarded to the underlying
    API call.
    """
    model = judge_model or available_models()[0]
    if temperature is not None:
        actual_model = MODEL_FUNC_MAP_NAMES.get(model, model)
        if actual_model.startswith("claude-"):
            return llm_api.call_anthropic(messages, actual_model)
        return llm_api.call_llm(messages, actual_model,
                                params={"temperature": temperature})
    return llm_api.call_by_name(model, messages)
