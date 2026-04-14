#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证 api.ai.cs.ac.cn 上 deepseek-reasoner 的返回形态：

- 规范网关：思维链在 message.reasoning_content，最终回答在 message.content。
- 部分代理：二者都拼进 content，需要自行解析/截断。

用法（在仓库根目录）::

    python tests/verify_deepseek_reasoner_gateway.py

可选::

    python tests/verify_deepseek_reasoner_gateway.py --model deepseek-reasoner --max-tokens 4096

需要网络；鉴权与 base_url 来自项目根目录的 llm_api 模块。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from openai import OpenAI

_PROJECT = Path(__file__).resolve().parents[1]
if str(_PROJECT) not in sys.path:
    sys.path.insert(0, str(_PROJECT))

import llm_api  # noqa: E402

# 若 content 里出现这些模式，怀疑「思考」被混进正文（启发式，非绝对）
_MERGED_CONTENT_HINT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"</think>", re.I),
    re.compile(r"<think>", re.I),
    re.compile(r"【思考】|【推理】|思维链"),
    re.compile(r"</redacted_thinking>", re.I),
    re.compile(r"<redacted_thinking>", re.I),
)


def _preview(s: str | None, head: int = 400, tail: int = 200) -> str:
    if s is None:
        return "(None)"
    if not s:
        return "(empty string)"
    s = s.replace("\r\n", "\n")
    if len(s) <= head + tail + 20:
        return s
    return f"{s[:head]}\n\n... [{len(s) - head - tail} chars omitted] ...\n\n{s[-tail:]}"


def _message_to_dict(msg) -> dict:
    """尽量拿到 assistant message 的可序列化字段（含网关自定义键）。"""
    if hasattr(msg, "model_dump"):
        try:
            return msg.model_dump(mode="python")
        except Exception:
            pass
    if hasattr(msg, "dict"):
        try:
            return msg.dict()
        except Exception:
            pass
    out: dict = {"role": getattr(msg, "role", None), "content": getattr(msg, "content", None)}
    rc = getattr(msg, "reasoning_content", None)
    if rc is not None:
        out["reasoning_content"] = rc
    for name in ("refusal", "audio", "tool_calls", "function_call"):
        v = getattr(msg, name, None)
        if v is not None:
            out[name] = v
    return out


def _analyze(content: str | None, reasoning_content: str | None) -> list[str]:
    lines: list[str] = []
    rc_len = len(reasoning_content) if isinstance(reasoning_content, str) else 0
    c_len = len(content) if isinstance(content, str) else 0

    lines.append(f"reasoning_content 长度: {rc_len}")
    lines.append(f"content 长度: {c_len}")

    if rc_len > 0 and c_len > 0:
        lines.append(
            "判定: 字段分离 — 与 DeepSeek 官方一致，业务上应主要使用 content，"
            "勿把 reasoning_content 写回下一轮 messages。"
        )
    elif rc_len > 0 and c_len == 0:
        lines.append(
            "判定: 仅有 reasoning_content — 异常或网关差异，请检查网关是否把正文放在别处。"
        )
    elif rc_len == 0 and c_len > 0:
        hints = [p.pattern for p in _MERGED_CONTENT_HINT_PATTERNS if p.search(content or "")]
        if hints:
            lines.append(
                "判定: 怀疑合并进 content — content 命中常见「思考」标记: "
                + ", ".join(hints)
            )
        else:
            lines.append(
                "判定: 仅有 content、无 reasoning_content — 可能网关只暴露正文，"
                "也可能把思维链一并塞进 content 但未使用常见标记；请人工看下方预览。"
            )
    else:
        lines.append("判定: content 与 reasoning_content 均为空 — 请求或解析异常。")

    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="验证 deepseek-reasoner 网关响应字段")
    parser.add_argument("--model", default="deepseek-reasoner", help="模型 id")
    parser.add_argument("--max-tokens", type=int, default=4096, help="max_tokens")
    parser.add_argument("--timeout", type=int, default=600, help="请求超时秒数")
    parser.add_argument(
        "--dump-json",
        action="store_true",
        help="打印 message 的 model_dump（便于对照网关原始字段）",
    )
    args = parser.parse_args()

    client = OpenAI(
        base_url=llm_api.BASE_URL,
        api_key=llm_api.API_KEY,
        timeout=args.timeout,
        max_retries=2,
    )
    messages = [
        {
            "role": "user",
            "content": (
                "请心算：17×19 等于多少？先简短推理，最后一行只输出一行："
                "答案：<数字>（不要其它文字）"
            ),
        }
    ]

    print(f"BASE_URL={llm_api.BASE_URL!r} model={args.model!r}\n")

    try:
        completion = client.chat.completions.create(
            model=args.model,
            messages=messages,
            max_tokens=args.max_tokens,
        )
    except Exception as e:
        print(f"请求失败: {type(e).__name__}: {e}")
        return 1

    choice = completion.choices[0]
    msg = choice.message
    content = msg.content
    reasoning_content = getattr(msg, "reasoning_content", None)

    print("--- 分析 ---")
    for line in _analyze(content, reasoning_content):
        print(line)

    print("\n--- reasoning_content 预览 ---")
    print(_preview(reasoning_content))

    print("\n--- content 预览 ---")
    print(_preview(content))

    if args.dump_json:
        print("\n--- message model_dump ---")
        try:
            print(json.dumps(_message_to_dict(msg), ensure_ascii=False, indent=2, default=str))
        except Exception as e:
            print(f"(无法序列化: {e})")

    print("\n--- finish_reason ---")
    print(getattr(choice, "finish_reason", None))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
