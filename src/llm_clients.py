"""LiteLLM-backed LLMClient: pure shape translator from ModelResponse to
the OpenAI tool-call dict shape agent_loop_run expects.

Works against any provider LiteLLM supports — local OpenAI-compatible
servers (LM Studio, Ollama, vLLM) via api_base, or cloud providers like
Anthropic via api_key. Loop policy lives in src/agent_loop.py.
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
