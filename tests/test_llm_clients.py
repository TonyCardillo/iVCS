"""Tests for the LiteLLM-backed LLMClient adapter.

The adapter's job is purely to translate LiteLLM's ModelResponse shape
into the dict shape agent_loop_run expects. We mock litellm.completion
rather than calling a real model.
"""

from unittest.mock import MagicMock, patch

from src.llm_clients import LiteLLMClient


def _mock_response(content: str | None = None, tool_calls: list[dict] | None = None) -> MagicMock:
	"""Build a fake litellm ModelResponse with the choice/message structure."""
	msg = MagicMock()
	msg.content = content
	if tool_calls is None:
		msg.tool_calls = None
	else:
		tc_objects = []
		for tc in tool_calls:
			tc_obj = MagicMock()
			tc_obj.id = tc["id"]
			tc_obj.function.name = tc["name"]
			tc_obj.function.arguments = tc["arguments"]
			tc_objects.append(tc_obj)
		msg.tool_calls = tc_objects

	choice = MagicMock()
	choice.message = msg

	response = MagicMock()
	response.choices = [choice]
	return response


class TestNormalizeResponse:
	def test_text_only_response(self):
		client = LiteLLMClient(model="anthropic/claude-haiku-4-5")
		with patch("src.llm_clients.litellm_completion") as mock_completion:
			mock_completion.return_value = _mock_response(content="Just text.")
			result = client.complete(messages=[], tools=[])
		assert result == {"role": "assistant", "content": "Just text."}

	def test_tool_call_response(self):
		client = LiteLLMClient(model="anthropic/claude-haiku-4-5")
		with patch("src.llm_clients.litellm_completion") as mock_completion:
			mock_completion.return_value = _mock_response(
				content=None,
				tool_calls=[
					{
						"id": "call_abc",
						"name": "compile_and_view_assembly",
						"arguments": '{"c_code": "int foo(void) { return 0; }"}',
					}
				],
			)
			result = client.complete(messages=[], tools=[])
		assert result["role"] == "assistant"
		assert result["tool_calls"][0]["id"] == "call_abc"
		assert result["tool_calls"][0]["function"]["name"] == "compile_and_view_assembly"
		assert "int foo" in result["tool_calls"][0]["function"]["arguments"]

	def test_mixed_text_and_tool_call(self):
		client = LiteLLMClient(model="anthropic/claude-haiku-4-5")
		with patch("src.llm_clients.litellm_completion") as mock_completion:
			mock_completion.return_value = _mock_response(
				content="Trying this:",
				tool_calls=[{"id": "c1", "name": "compile_and_view_assembly", "arguments": "{}"}],
			)
			result = client.complete(messages=[], tools=[])
		assert result["content"] == "Trying this:"
		assert len(result["tool_calls"]) == 1


class TestCallPassthrough:
	def test_model_and_api_base_passed_through(self):
		client = LiteLLMClient(
			model="openai/qwen3-coder-30b",
			api_base="http://127.0.0.1:1234/v1",
			api_key="sk-local",
		)
		with patch("src.llm_clients.litellm_completion") as mock_completion:
			mock_completion.return_value = _mock_response(content="ok")
			client.complete(
				messages=[{"role": "user", "content": "hi"}], tools=[{"type": "function"}]
			)
		call_kwargs = mock_completion.call_args.kwargs
		assert call_kwargs["model"] == "openai/qwen3-coder-30b"
		assert call_kwargs["api_base"] == "http://127.0.0.1:1234/v1"
		assert call_kwargs["api_key"] == "sk-local"
		assert call_kwargs["messages"] == [{"role": "user", "content": "hi"}]
		assert call_kwargs["tools"] == [{"type": "function"}]

	def test_api_base_omitted_when_not_set(self):
		client = LiteLLMClient(model="anthropic/claude-haiku-4-5")
		with patch("src.llm_clients.litellm_completion") as mock_completion:
			mock_completion.return_value = _mock_response(content="ok")
			client.complete(messages=[], tools=[])
		call_kwargs = mock_completion.call_args.kwargs
		assert "api_base" not in call_kwargs
