"""
LLM client wrapper — imports call_llm / MODEL_FUNC_MAP from the shared
llm_api_openai.py so that base_url, api_key and model names are never
duplicated or hardcoded here.
"""

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

try:
    from llm_api_openai import call_llm, call_by_name, MODEL_FUNC_MAP  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    # Backward-compatible fallback for older repo layouts.
    from llm_api import call_llm, call_by_name, MODEL_FUNC_MAP  # type: ignore


def available_models():
    """Return the list of model short-names that are currently enabled."""
    return list(MODEL_FUNC_MAP.keys())


def call_model(model_name: str, messages: list[dict]) -> str | None:
    """Unified interface: call *model_name* with *messages*.

    *model_name* must be a key in MODEL_FUNC_MAP (e.g. 'deepseek_v3_2').
    Returns the assistant reply string, or None on failure.
    """
    return call_by_name(model_name, messages)


def call_judge(messages: list[dict], judge_model: str | None = None) -> str | None:
    """Call the LLM-as-Judge model.

    If *judge_model* is None, falls back to the first available model.
    """
    model = judge_model or available_models()[0]
    return call_by_name(model, messages)
