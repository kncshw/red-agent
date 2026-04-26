"""Self-contained vLLM/OpenAI-compatible client with tool-calling support.

Stripped and adapted from OpenHarness openai_client.py (MIT License).
Handles Anthropic-style message types internally — no framework dependency.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx
from openai import AsyncOpenAI

log = logging.getLogger(__name__)

MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Message types (self-contained — no OpenHarness import)
# ---------------------------------------------------------------------------

@dataclass
class TextBlock:
    text: str


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class ToolResultBlock:
    tool_use_id: str
    content: str
    is_error: bool = False


ContentBlock = TextBlock | ToolUseBlock | ToolResultBlock


@dataclass
class Message:
    role: str  # "user" | "assistant"
    content: list[ContentBlock] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Format converters (Anthropic-style → OpenAI wire format)
# ---------------------------------------------------------------------------

def _tools_to_openai(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {}),
            },
        }
        for t in tools
    ]


def _messages_to_openai(
    messages: list[Message],
    system_prompt: str | None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if system_prompt:
        out.append({"role": "system", "content": system_prompt})

    for msg in messages:
        if msg.role == "assistant":
            text_parts = [b.text for b in msg.content if isinstance(b, TextBlock)]
            tool_uses = [b for b in msg.content if isinstance(b, ToolUseBlock)]
            openai_msg: dict[str, Any] = {
                "role": "assistant",
                "content": "".join(text_parts) or None,
            }
            if tool_uses:
                openai_msg["tool_calls"] = [
                    {
                        "id": tu.id,
                        "type": "function",
                        "function": {
                            "name": tu.name,
                            "arguments": json.dumps(tu.input),
                        },
                    }
                    for tu in tool_uses
                ]
            out.append(openai_msg)

        elif msg.role == "user":
            tool_results = [b for b in msg.content if isinstance(b, ToolResultBlock)]
            text_blocks = [b for b in msg.content if isinstance(b, TextBlock)]
            for tr in tool_results:
                out.append({
                    "role": "tool",
                    "tool_call_id": tr.tool_use_id,
                    "content": tr.content or "(no output)",
                })
            if text_blocks:
                text = "".join(b.text for b in text_blocks).strip()
                if text:
                    out.append({"role": "user", "content": text})

    return out


def _parse_response(response: Any) -> Message:
    choice = response.choices[0]
    msg = choice.message
    content: list[ContentBlock] = []
    if msg.content:
        content.append(TextBlock(text=msg.content))
    if msg.tool_calls:
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments)
            except (json.JSONDecodeError, TypeError):
                args = {}
            content.append(ToolUseBlock(id=tc.id, name=tc.function.name, input=args))
    return Message(role="assistant", content=content)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class LLMClient:
    """Thin async wrapper around an OpenAI-compatible vLLM endpoint."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "none",
        temperature: float = 0.2,
        verify_ssl: bool = False,
    ) -> None:
        self.model = model
        self.temperature = temperature
        http_client = httpx.AsyncClient(verify=verify_ssl)
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=http_client,
        )

    async def call(
        self,
        messages: list[Message],
        system_prompt: str,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
    ) -> Message:
        """Single non-streaming call. Returns the assistant Message."""
        openai_messages = _messages_to_openai(messages, system_prompt)
        openai_tools = _tools_to_openai(tools) if tools else None

        params: dict[str, Any] = {
            "model": self.model,
            "messages": openai_messages,
            "max_tokens": max_tokens,
            "temperature": self.temperature,
            "stream": False,
        }
        if openai_tools:
            params["tools"] = openai_tools

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                ">>> REQUEST TO GEMMA4:\n%s",
                json.dumps(
                    {k: v for k, v in params.items() if k != "tools"},
                    indent=2, default=str
                )
            )

        for attempt in range(MAX_RETRIES):
            try:
                response = await self._client.chat.completions.create(**params)
                result = _parse_response(response)

                if log.isEnabledFor(logging.DEBUG):
                    tool_uses = [b for b in result.content if isinstance(b, ToolUseBlock)]
                    text_blocks = [b for b in result.content if isinstance(b, TextBlock)]
                    log.debug(
                        "<<< RESPONSE FROM GEMMA4:\n%s",
                        json.dumps({
                            "finish_reason": response.choices[0].finish_reason,
                            "text": "".join(b.text for b in text_blocks) or None,
                            "tool_calls": [
                                {"name": tu.name, "arguments": tu.input}
                                for tu in tool_uses
                            ],
                        }, indent=2, default=str)
                    )

                return result
            except Exception as exc:
                if attempt == MAX_RETRIES - 1:
                    raise
                log.warning("LLM call failed (attempt %d/%d): %s", attempt + 1, MAX_RETRIES, exc)

        raise RuntimeError("LLM call failed after retries")
