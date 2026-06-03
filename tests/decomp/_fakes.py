"""Test doubles for the agent loop.

A FakeLLMClient returns scripted assistant-message dicts in order (no
Wine / cl.exe / network), and the assistant_* builders construct those
dicts in the OpenAI tool-call shape the loop consumes.
"""

import json
from dataclasses import dataclass


@dataclass
class FakeLLMClient:
	"""Test double: returns scripted responses in order, raises when exhausted."""

	scripted: list[dict]
	_index: int = 0

	def complete(self, messages: list[dict], tools: list[dict]) -> dict:
		if self._index >= len(self.scripted):
			raise RuntimeError(
				f"FakeLLMClient exhausted after {self._index} calls (no more scripted responses)"
			)
		response = self.scripted[self._index]
		self._index += 1
		return response


def assistant_tool_call(tool_name: str, arguments: dict, tool_call_id: str = "call_1") -> dict:
	return {
		"role": "assistant",
		"content": None,
		"tool_calls": [
			{
				"id": tool_call_id,
				"type": "function",
				"function": {
					"name": tool_name,
					"arguments": json.dumps(arguments),
				},
			}
		],
	}


def assistant_text(text: str) -> dict:
	return {"role": "assistant", "content": text}
