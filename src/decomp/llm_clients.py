"""LiteLLM-backed LLMClient: pure shape translator from ModelResponse to
the OpenAI tool-call dict shape agent_loop_run expects.

Works against any provider LiteLLM supports; local OpenAI-compatible
servers (LM Studio, Ollama, vLLM) via api_base, or cloud providers like
Anthropic via api_key. Loop policy lives in src/agent_loop.py.
"""

import json
import os
import urllib.request
from dataclasses import dataclass

from litellm import completion as litellm_completion
from openai import APIConnectionError

from src.decomp.agent_loop import LLMClientError

# A model call that hasn't responded in this long is treated as a dead socket, not
# a slow think: long enough for a big reasoning response, short enough that a wedged
# endpoint can't park an unattended batch worker forever.
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 240.0

_LM_STUDIO_API_BASE = "http://127.0.0.1:1234/v1"
# Last-resort fallback name when no IVCS_LLM_MODEL is set AND the server can't be
# reached to report what's loaded. Deliberately NOT a real model id: an honest
# "we don't know" beats inventing a specific model the user never ran (which is
# how stale runs got mislabeled before detection worked).
_LM_STUDIO_MODEL = "local (unknown)"


def _lm_studio_api_base() -> str:
	return os.environ.get("IVCS_LLM_API_BASE", _LM_STUDIO_API_BASE)


def _lm_studio_detect_loaded_model() -> str | None:
	"""Ask the LM Studio server which model is actually loaded.

	Returns the first non-embedding model id from `/models`, or None if the
	server is unreachable; so we name the real AI rather than a guessed default.
	"""
	try:
		# noqa justified: always the http(s) LM Studio API base from env/default,
		# never a user-supplied or custom-scheme URL.
		url = f"{_lm_studio_api_base()}/models"
		with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310
			data = json.load(resp)
	except OSError, ValueError:
		return None
	for entry in data.get("data", []):
		mid = entry.get("id", "")
		if mid and "embed" not in mid.lower():
			return mid
	return None


def _local_model_name() -> str:
	"""The LM Studio model to use and record: an explicit IVCS_LLM_MODEL wins;
	otherwise the actually-loaded model; otherwise the built-in default."""
	return os.environ.get("IVCS_LLM_MODEL") or _lm_studio_detect_loaded_model() or _LM_STUDIO_MODEL


@dataclass
class LiteLLMClient:
	model: str
	api_base: str | None = None
	api_key: str = "sk-local"
	request_timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS

	def complete(self, messages: list[dict], tools: list[dict]) -> dict:
		kwargs = {
			"model": self.model,
			"messages": messages,
			"tools": tools,
			"api_key": self.api_key,
			"timeout": self.request_timeout_seconds,
		}
		if self.api_base is not None:
			kwargs["api_base"] = self.api_base

		try:
			response = litellm_completion(**kwargs)
		except APIConnectionError as exc:
			# Covers litellm.Timeout and APIConnectionError (both subclass openai's):
			# the endpoint hung or was unreachable. Re-raise as the loop's contract
			# type so it finalizes instead of unwinding the run.
			raise LLMClientError(f"LLM request failed: {exc}") from exc
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


def llm_recorded_model(model: str) -> str:
	"""The model name to record and display for a run mode.

	`"local"` resolves to the actual LM Studio model id (`IVCS_LLM_MODEL`, e.g.
	`qwen/qwen3.5-9b`) so reports name the real AI rather than the generic mode.
	Cloud models and `"ghidra"` pass through unchanged.
	"""
	if model == "local":
		return _local_model_name()
	return model


def llm_client_for(
	model: str,
	*,
	api_key: str | None = None,
	request_timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> LiteLLMClient:
	"""Build the LLM client for a run mode.

	`model == "local"` targets an OpenAI-compatible local server (LM Studio by
	default) via `IVCS_LLM_API_BASE` / `IVCS_LLM_MODEL`; anything else is a cloud
	Anthropic model and requires `ANTHROPIC_API_KEY` (or an explicit `api_key`).
	"""
	if model == "local":
		return LiteLLMClient(
			model=f"openai/{_local_model_name()}",
			api_base=_lm_studio_api_base(),
			request_timeout_seconds=request_timeout_seconds,
		)

	key = api_key or os.environ.get("ANTHROPIC_API_KEY")
	if not key:
		raise RuntimeError("ANTHROPIC_API_KEY not set in environment")
	return LiteLLMClient(
		model=f"anthropic/{model}", api_key=key, request_timeout_seconds=request_timeout_seconds
	)
