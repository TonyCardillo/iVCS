"""LLMClient implementations.

LiteLLMClient is the production binding. It works against any provider
LiteLLM supports — including:

  - Local OpenAI-compatible endpoints (LM Studio, Ollama, vLLM, llama.cpp
    server) with a fake API key and an http://127.0.0.1 api_base.
  - Cloud providers (Anthropic, OpenAI) for testing/emulation. Setting
    model="anthropic/claude-haiku-4-5" + ANTHROPIC_API_KEY in env gives
    us a cheap stand-in for what a local-model run will look like, with
    the same OpenAI-shape tool-call surface that LiteLLM normalizes.

The adapter is *purely* a shape translator from LiteLLM's ModelResponse
to the dict the agent loop expects (the OpenAI tool-call shape). All
loop policy lives in src/agent_loop.py.
"""

from dataclasses import dataclass

from litellm import completion as litellm_completion


@dataclass
class LiteLLMClient:
    model: str
    api_base: str | None = None
    api_key: str = "sk-local"

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        kwargs = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "api_key": self.api_key,
        }
        if self.api_base is not None:
            kwargs["api_base"] = self.api_base

        response = litellm_completion(**kwargs)
        message = response.choices[0].message

        result: dict = {"role": "assistant", "content": getattr(message, "content", None)}

        tool_calls = getattr(message, "tool_calls", None) or []
        if tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in tool_calls
            ]

        return result
