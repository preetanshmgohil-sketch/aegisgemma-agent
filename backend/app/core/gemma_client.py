"""Gemma 4 client wrapper.

Primary path: the official `google-genai` SDK with `thinking_level="high"` and
a JSON structured-output schema, per the AegisGemma spec.

Fallback path: an OpenAI-compatible chat-completions endpoint (e.g. NVIDIA
NIM serving `google/gemma-4-31b-it`) for environments where the Gemini API
key is not available. The same JSON schema contract is enforced either way.

The client is deliberately provider-agnostic at the call site: callers ask
for JSON matching a schema and get back parsed JSON plus the model's
reasoning trace.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

DEFAULT_MODEL = "gemma-4-31b-it"
DEFAULT_THINKING_LEVEL = "high"


@dataclass
class GemmaResponse:
    """A single model response: the JSON payload, its reasoning, and usage."""

    text: str
    thoughts: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    model: str | None = None

    @property
    def json(self) -> dict[str, Any]:
        return extract_json_payload(self.text)


def extract_json_payload(raw: str) -> dict[str, Any]:
    """Pull a JSON object out of a model response, tolerating prose/fences."""
    if raw is None:
        raise ValueError("Empty model response")
    text = raw.strip()

    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # Fall back to the outermost balanced object in the text.
    start = text.find("{")
    if start == -1:
        raise ValueError(f"No JSON object found in model response: {raw[:200]!r}")
    depth = 0
    in_string = False
    escaped = False
    for idx in range(start, len(text)):
        char = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : idx + 1]
                data = json.loads(candidate)
                if isinstance(data, dict):
                    return data
    raise ValueError(f"Could not parse JSON from model response: {raw[:200]!r}")


class GemmaClient:
    """Thin async wrapper around the Gemma 4 reasoning API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        thinking_level: str | None = None,
        base_url: str | None = None,
        provider: str | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get(
            "GOOGLE_API_KEY"
        )
        self.model = model or os.environ.get("GEMMA_MODEL") or DEFAULT_MODEL
        self.thinking_level = (
            thinking_level or os.environ.get("GEMMA_THINKING_LEVEL") or DEFAULT_THINKING_LEVEL
        )
        self.base_url = (
            base_url
            or os.environ.get("GEMMA_BASE_URL")
            or os.environ.get("NVIDIA_BASE_URL")
            or "https://integrate.api.nvidia.com/v1"
        )
        self.provider = (
            provider or os.environ.get("GEMMA_PROVIDER") or ("google" if self.api_key else "nvidia")
        ).lower()
        self.timeout = timeout
        self._client = None

    # -- configuration ------------------------------------------------------

    @property
    def available(self) -> bool:
        if self.provider == "google":
            return bool(self.api_key)
        return bool(self.api_key or os.environ.get("NVIDIA_API_KEY"))

    def build_config(self, response_schema: dict[str, Any] | None = None):
        """Build the `google-genai` generation config for a JSON response."""
        from google.genai import types

        return types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            thinking_config=types.ThinkingConfig(thinking_level=self.thinking_level),
            response_mime_type="application/json",
            response_schema=response_schema,
            temperature=0.2,
            max_output_tokens=8192,
        )

    # -- provider calls -----------------------------------------------------

    async def complete_json(
        self,
        prompt: str,
        schema: dict[str, Any] | None = None,
        system_instruction: str | None = None,
    ) -> GemmaResponse:
        """Ask the model for JSON matching `schema`; return the raw response."""
        if not self.available:
            raise RuntimeError(
                "No AI provider configured: set GEMINI_API_KEY (Gemini API) or "
                "NVIDIA_API_KEY (OpenAI-compatible endpoint)."
            )
        if self.provider == "google":
            return await self._complete_google(prompt, schema, system_instruction)
        return await self._complete_openai_compatible(prompt, schema, system_instruction)

    async def _complete_google(
        self,
        prompt: str,
        schema: dict[str, Any] | None,
        system_instruction: str | None,
    ) -> GemmaResponse:
        from google import genai
        from google.genai import types

        if self._client is None:
            self._client = genai.Client(api_key=self.api_key)
        config = self.build_config(schema)
        if system_instruction:
            config.system_instruction = system_instruction

        response = await self._client.aio.models.generate_content(
            model=self.model,
            contents=prompt,
            config=config,
        )
        return self.parse_provider_response(response, model=self.model)

    async def _complete_openai_compatible(
        self,
        prompt: str,
        schema: dict[str, Any] | None,
        system_instruction: str | None,
    ) -> GemmaResponse:
        import httpx

        api_key = self.api_key or os.environ.get("NVIDIA_API_KEY")
        model = self.model
        if self.provider == "nvidia" and "/" not in model:
            model = f"google/{model}"
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": system_instruction or SYSTEM_INSTRUCTION,
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 8192,
            "response_format": {"type": "json_object"},
        }
        if schema:
            payload["response_format"] = {
                "type": "json_object",
                "schema": json.dumps(schema)[:18000],
            }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            http_response = await client.post(url, headers=headers, json=payload)
            http_response.raise_for_status()
            data = http_response.json()

        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        text = message.get("content") or ""
        thoughts = message.get("reasoning_content") or message.get("reasoning") or ""
        usage_raw = data.get("usage") or {}
        usage = {
            "input_tokens": int(usage_raw.get("prompt_tokens") or 0),
            "output_tokens": int(usage_raw.get("completion_tokens") or 0),
        }
        return GemmaResponse(text=text, thoughts=thoughts, usage=usage, model=model)

    # -- parsing ------------------------------------------------------------

    @staticmethod
    def parse_provider_response(response: Any, model: str | None = None) -> GemmaResponse:
        """Normalise a google-genai response object into a GemmaResponse."""
        if isinstance(response, dict):
            text = ""
            thoughts = ""
            usage: dict[str, int] = {}
            candidates = response.get("candidates") or []
            if candidates:
                content = candidates[0].get("content") or {}
                for part in content.get("parts") or []:
                    if part.get("thought"):
                        thoughts += part.get("text") or ""
                    else:
                        text += part.get("text") or ""
            if not text:
                text = response.get("text") or ""
            usage_raw = response.get("usageMetadata") or response.get("usage") or {}
            usage = {
                "input_tokens": int(
                    usage_raw.get("promptTokenCount")
                    or usage_raw.get("prompt_tokens")
                    or 0
                ),
                "output_tokens": int(
                    usage_raw.get("candidatesTokenCount")
                    or usage_raw.get("completion_tokens")
                    or 0
                ),
            }
            return GemmaResponse(text=text, thoughts=thoughts, usage=usage, model=model)

        text = getattr(response, "text", "") or ""
        thoughts = ""
        candidates = getattr(response, "candidates", None) or []
        if candidates:
            content = getattr(candidates[0], "content", None)
            parts = getattr(content, "parts", None) or []
            for part in parts:
                if getattr(part, "thought", False):
                    thoughts += getattr(part, "text", "") or ""
                else:
                    text += getattr(part, "text", "") or ""
        usage_raw = getattr(response, "usage_metadata", None)
        usage: dict[str, int] = {}
        if usage_raw is not None:
            usage = {
                "input_tokens": int(getattr(usage_raw, "prompt_token_count", 0) or 0),
                "output_tokens": int(getattr(usage_raw, "candidates_token_count", 0) or 0),
            }
        return GemmaResponse(text=text, thoughts=thoughts, usage=usage, model=model)


SYSTEM_INSTRUCTION = """
You are AegisGemma, a Principal Offensive Security Engineer and Code Auditor.
Analyze the provided input for critical vulnerabilities (OWASP Top 10, CWE top
categories). Perform multi-step threat modeling inside your internal thinking
buffer. Always answer with a single JSON object matching the requested schema.
""".strip()
