"""Tests for the Gemma client wrapper and the PoC safety guard."""

import json

import pytest

from app.core.gemma_client import GemmaClient, GemmaResponse, extract_json_payload
from app.core.poc_guard import sanitize_poc


class TestExtractJsonPayload:
    def test_plain_json_object(self):
        assert extract_json_payload('{"a": 1}') == {"a": 1}

    def test_json_wrapped_in_fence(self):
        raw = '```json\n{"a": 1}\n```'
        assert extract_json_payload(raw) == {"a": 1}

    def test_json_with_leading_prose(self):
        raw = 'Here is the report:\n{"a": 1, "b": [2, 3]}\nHope this helps.'
        assert extract_json_payload(raw) == {"a": 1, "b": [2, 3]}

    def test_raises_on_non_json(self):
        with pytest.raises(ValueError):
            extract_json_payload("I cannot help with that.")


class TestGemmaClient:
    def test_construction_without_key_does_not_raise(self):
        client = GemmaClient(api_key="", model="gemma-4-31b-it")
        assert client.available is False

    def test_construction_with_key_is_available(self):
        client = GemmaClient(api_key="abc", model="gemma-4-31b-it")
        assert client.available is True

    def test_default_model_is_gemma_4_31b(self):
        client = GemmaClient(api_key="abc")
        assert client.model == "gemma-4-31b-it"

    def test_thinking_level_is_high_by_default(self):
        client = GemmaClient(api_key="abc")
        assert client.thinking_level == "high"

    def test_builds_thinking_config_with_high_level(self):
        from google.genai import types

        client = GemmaClient(api_key="abc", thinking_level="high")
        config = client.build_config(response_schema={"type": "object"})
        assert isinstance(config.thinking_config, types.ThinkingConfig)
        assert config.thinking_config.thinking_level == types.ThinkingLevel.HIGH
        assert config.response_mime_type == "application/json"

    def test_response_dataclass_carries_thoughts(self):
        resp = GemmaResponse(text="{}", thoughts="thinking...", usage={"input_tokens": 1})
        assert resp.thoughts == "thinking..."

    def test_parsers_extract_payload_from_provider_envelope(self):
        envelope = {
            "candidates": [
                {"content": {"parts": [{"text": '{"risk_index": 10}'}]}}
            ],
            "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 4},
        }
        parsed = GemmaClient.parse_provider_response(envelope)
        assert parsed.text == '{"risk_index": 10}'
        assert parsed.usage["input_tokens"] == 12
        assert parsed.usage["output_tokens"] == 4

    def test_parsers_handle_plain_text_envelope(self):
        envelope = {"text": '{"ok": true}'}
        parsed = GemmaClient.parse_provider_response(envelope)
        assert json.loads(parsed.text) == {"ok": True}
