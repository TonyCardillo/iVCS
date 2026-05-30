"""LiteLLM-backed LLMClient: pure shape translator from ModelResponse to
the OpenAI tool-call dict shape agent_loop_run expects.

Works against any provider LiteLLM supports — local OpenAI-compatible
servers (LM Studio, Ollama, vLLM) via api_base, or cloud providers like
Anthropic via api_key. Loop policy lives in src/agent_loop.py.
"""

import os
from dataclasses import dataclass

from litellm import completion as litellm_completion

_LM_STUDIO_API_BASE = "http://127.0.0.1:1234/v1"
_LM_STUDIO_MODEL = "qwen3-coder-30b"


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


def llm_client_for(model: str, *, api_key: str | None = None) -> LiteLLMClient:
	"""Build the LLM client for a run mode.

	`model == "local"` targets an OpenAI-compatible local server (LM Studio by
	default) via `IVCS_LLM_API_BASE` / `IVCS_LLM_MODEL`; anything else is a cloud
	Anthropic model and requires `ANTHROPIC_API_KEY` (or an explicit `api_key`).
	"""
	if model == "local":
		api_base = os.environ.get("IVCS_LLM_API_BASE", _LM_STUDIO_API_BASE)
		local_model = os.environ.get("IVCS_LLM_MODEL", _LM_STUDIO_MODEL)
		return LiteLLMClient(model=f"openai/{local_model}", api_base=api_base)

	key = api_key or os.environ.get("ANTHROPIC_API_KEY")
	if not key:
		raise RuntimeError("ANTHROPIC_API_KEY not set in environment")
	return LiteLLMClient(model=f"anthropic/{model}", api_key=key)
