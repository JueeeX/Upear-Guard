# -*- coding: UTF-8 -*-

import json

from openai import OpenAI
from anthropic import Anthropic

BASE_URL = "https://api.ai.cs.ac.cn/v1"
ANTHROPIC_BASE_URL = "https://api.ai.cs.ac.cn"
API_KEY = ""

def call_llm(messages, model_name, params=None, timeout=3600):
    """OpenAI-compatible API 调用（用于 GPT / DeepSeek 等）"""
    try:
        client = OpenAI(
            base_url=BASE_URL,
            api_key=API_KEY,
            timeout=timeout,
        )
        completion = client.chat.completions.create(
            model=model_name,
            messages=messages,
            **(params if params else {}),
        )
        answer = completion.choices[0].message.content

        assert isinstance(answer, str) and answer != ""
        return answer
    except Exception as e:
        print(f"Error occurred while calling LLM: {e}")
        return None


def call_anthropic(messages, model_name, max_tokens=4096, timeout=3600):
    """Anthropic native API 调用（用于 Claude 系列）"""
    try:
        client = Anthropic(
            base_url=ANTHROPIC_BASE_URL,
            api_key=API_KEY,
            timeout=timeout,
        )
        system_text = None
        user_messages = []
        for m in messages:
            if m["role"] == "system":
                system_text = m["content"]
            else:
                user_messages.append(m)

        kwargs = dict(
            model=model_name,
            max_tokens=max_tokens,
            messages=user_messages,
        )
        if system_text:
            kwargs["system"] = system_text

        message = client.messages.create(**kwargs)
        answer = message.content[0].text

        assert isinstance(answer, str) and answer != ""
        return answer
    except Exception as e:
        print(f"Error occurred while calling Anthropic: {e}")
        return None


# ── 便捷函数：每个模型对应一个带默认参数的调用 ──

def call_claude_sonnet(messages):
    return call_anthropic(messages, model_name="claude-sonnet-4-5-20250929")


def call_gpt4o(messages):
    return call_llm(messages, model_name="gpt-4o", timeout=3600)


def call_deepseek_chat(messages):
    return call_llm(messages, model_name="deepseek-chat", timeout=3600)


MODEL_FUNC_MAP = {
    # "claude_sonnet": call_claude_sonnet,
    "gpt4o": call_gpt4o,
    "deepseek_chat": call_deepseek_chat,
}


def call_by_name(model_short_name, messages):
    """通过简短的模型名调用，例如 call_by_name('deepseek_v3_2', messages)"""
    func = MODEL_FUNC_MAP.get(model_short_name)
    if func is None:
        raise ValueError(
            f"未知模型 '{model_short_name}'，可选: {list(MODEL_FUNC_MAP.keys())}"
        )
    return func(messages)


if __name__ == "__main__":
    test_messages = [
        {"role": "system", "content": "你是一个数学家，当用户询问你是谁，你要回答自己是一个数学家"},
        {"role": "user", "content": "你是谁"},
    ]

    for name, func in MODEL_FUNC_MAP.items():
        print(f"[{name}]", json.dumps(func(test_messages), ensure_ascii=False))
