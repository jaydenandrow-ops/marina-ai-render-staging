"""Provider interfaces for local and future model backends."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator

import json
import os
import re
import httpx

class ProviderError(RuntimeError):
    pass


_DIAGNOSTIC_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _safe_diagnostic_code(value: object) -> str | None:
    if isinstance(value, str) and _DIAGNOSTIC_CODE_RE.fullmatch(value):
        return value
    return None


def _safe_request_id(value: object) -> str | None:
    if isinstance(value, str) and _REQUEST_ID_RE.fullmatch(value):
        return value
    return None


def _provider_error_fields(payload: object) -> tuple[str | None, str | None, str | None]:
    """Extract only bounded, identifier-shaped diagnostic fields from provider JSON."""
    if not isinstance(payload, dict):
        return None, None, None
    error = payload.get("error")
    if not isinstance(error, dict):
        return None, None, _safe_request_id(payload.get("request_id"))
    error_type = _safe_diagnostic_code(error.get("type"))
    error_code = _safe_diagnostic_code(error.get("code"))
    return error_type, error_code, _safe_request_id(payload.get("request_id"))


class AIProvider(ABC):
    @abstractmethod
    async def list_models(self) -> list[str]: ...

    @abstractmethod
    async def stream_chat(self, model: str, messages: list[dict[str, str]], *, response_length: str) -> AsyncIterator[str]: ...


class OllamaProvider(AIProvider):
    def __init__(self, base_url: str, *, connect_timeout: float = 5, read_timeout: float = 180):
        import httpx
        self.base_url = base_url.rstrip("/")
        self.timeout = httpx.Timeout(read_timeout, connect=connect_timeout)

    async def health(self) -> bool:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                response.raise_for_status()
            return True
        except httpx.HTTPError:
            return False

    async def list_models(self) -> list[str]:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                response.raise_for_status()
            return [m["name"] for m in response.json().get("models", []) if m.get("name")]
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise ProviderError("Ollama is unavailable. Start Ollama and try again.") from exc

    async def stream_chat(self, model: str, messages: list[dict[str, str]], *, response_length: str) -> AsyncIterator[str]:
        import httpx
        token_limits = {"short": 160, "balanced": 440, "detailed": 820}
        if response_length not in token_limits:
            raise ProviderError("Unsupported response length.")
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", f"{self.base_url}/api/chat", json={
                    "model": model, "messages": messages, "stream": True,
                    "keep_alive": 0,
                    "options": {"num_predict": token_limits[response_length]},
                }) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        try:
                            packet = __import__("json").loads(line)
                        except ValueError:
                            continue
                        if packet.get("error"):
                            raise ProviderError(str(packet["error"])[:250])
                        text = packet.get("message", {}).get("content", "")
                        if text:
                            yield text
        except httpx.HTTPError as exc:
            raise ProviderError(f"Generation failed: {str(exc)[:180]}") from exc


class MockProvider(AIProvider):
    """Predictable local provider for API and orchestration tests."""
    def __init__(self, response: str = "Mock response."):
        self.response = response

    async def list_models(self) -> list[str]:
        return ["mock"]

    async def stream_chat(self, model: str, messages: list[dict[str, str]], *, response_length: str) -> AsyncIterator[str]:
        for part in self.response.split(" "):
            yield part + " "


class OpenAIResponsesProvider(AIProvider):
    """Optional Responses adapter; transcript sharing is bounded by its caller and this adapter."""

    API_URL = "https://api.openai.com/v1/responses"
    RESPONSE_LIMITS = {"short": 96, "balanced": 256, "detailed": 512}

    def __init__(self, *, api_key: str | None = None, model: str | None = None,
                 enabled: bool | None = None, max_input_chars: int = 4000,
                 max_output_tokens: int = 256, max_context_tokens: int = 0,
                 timeout_seconds: float = 45, reasoning_effort: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.api_key = (api_key if api_key is not None else os.getenv("OPENAI_API_KEY", "")).strip()
        self.model = (model if model is not None else os.getenv("OPENAI_MODEL", "")).strip()
        enabled_env = os.getenv("CLOUD_PROVIDER_ENABLED", "0").strip().lower() in {"1", "true", "yes"}
        self.enabled = enabled_env if enabled is None else enabled
        self.max_input_chars = max_input_chars
        self.max_output_tokens = max_output_tokens
        self.max_context_tokens = max_context_tokens
        self.reasoning_effort = (reasoning_effort if reasoning_effort is not None
            else os.getenv("OPENAI_REASONING_EFFORT", "none")).strip().lower()
        self.timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 8))
        self.transport = transport
        # In-memory telemetry for the current response only. Callers may use it
        # for evaluation accounting; it is never persisted or logged.
        self.last_http_status: int | None = None
        self.last_actual_model: str | None = None
        self.last_usage: dict[str, int] | None = None
        self.last_terminal_event: str | None = None
        self.last_response_status: str | None = None
        self.last_incomplete_details: dict | None = None
        self.last_response_id: str | None = None
        self.last_request_id: str | None = None
        self.last_error_category: str | None = None
        self.last_error_code: str | None = None
        self.last_exception_type: str | None = None

    def reset_diagnostics(self) -> None:
        """Clear per-request telemetry so a local preflight error cannot reuse stale values."""
        self.last_http_status = None
        self.last_actual_model = None
        self.last_usage = None
        self.last_terminal_event = None
        self.last_response_status = None
        self.last_incomplete_details = None
        self.last_response_id = None
        self.last_request_id = None
        self.last_error_category = None
        self.last_error_code = None
        self.last_exception_type = None

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self.api_key.strip() and self.model.strip())

    async def list_models(self) -> list[str]:
        if not self.configured:
            raise ProviderError("Cloud provider is disabled or missing its local API key/model configuration.")
        return [self.model]

    async def stream_chat(self, model: str, messages: list[dict[str, str]], *, response_length: str) -> AsyncIterator[str]:
        self.reset_diagnostics()
        if not self.configured:
            raise ProviderError("Cloud provider is disabled or not configured.")
        if model != self.model:
            raise ProviderError("Choose the configured cloud model.")
        if response_length not in self.RESPONSE_LIMITS:
            raise ProviderError("Unsupported response length.")
        if model == "gpt-6-luna" and self.reasoning_effort not in {
            "none", "low", "medium", "high", "xhigh", "max"
        }:
            raise ProviderError("Unsupported GPT-6 Luna reasoning effort.")
        if len(messages) < 2 or messages[0].get("role") != "system" or messages[-1].get("role") != "user":
            raise ProviderError("Cloud requests require system instructions and a current user message.")
        instructions = messages[0].get("content", "")
        transcript = messages[1:]
        expected_role = "user"
        for item in transcript:
            if item.get("role") != expected_role or not isinstance(item.get("content"), str):
                raise ProviderError("Cloud conversation context has invalid message ordering or content.")
            expected_role = "assistant" if expected_role == "user" else "user"
        if expected_role != "assistant":
            raise ProviderError("Cloud conversation context must end with the current user message.")
        user_text = transcript[-1].get("content", "")
        if not user_text.strip() or len(user_text) > self.max_input_chars:
            raise ProviderError(f"Cloud input must contain 1 to {self.max_input_chars} characters.")
        context = transcript[:-1]
        context_upper_tokens = sum(len(item["content"].encode("utf-8")) + 8 for item in context)
        if context_upper_tokens > self.max_context_tokens:
            raise ProviderError("Cloud conversation context exceeds the configured token budget.")
        if len(instructions) + len(user_text) > self.max_input_chars + 5000:
            raise ProviderError("Cloud prompt exceeds the configured size limit.")

        payload = {
            "model": self.model,
            "instructions": instructions,
            "input": user_text if not context else [
                {"role": item["role"], "content": item["content"]} for item in transcript
            ],
            "stream": True,
            "store": False,
            "max_output_tokens": min(self.RESPONSE_LIMITS[response_length], self.max_output_tokens),
        }
        if model == "gpt-6-luna":
            payload["reasoning"] = {"effort": self.reasoning_effort}
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        received_text = False
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
                async with client.stream("POST", self.API_URL, headers=headers, json=payload) as response:
                    self.last_http_status = response.status_code
                    self.last_request_id = _safe_request_id(response.headers.get("x-request-id"))
                    if response.status_code == 401 or response.status_code == 403:
                        self.last_error_category = "authentication_or_access"
                        self._capture_http_error(response)
                        raise ProviderError("Cloud authentication failed; check OPENAI_API_KEY.")
                    if response.status_code == 429:
                        self.last_error_category = "rate_limit_or_billing"
                        self._capture_http_error(response)
                        raise ProviderError("Cloud rate limit or account spending limit reached.")
                    if response.status_code >= 500:
                        self.last_error_category = "provider_server_error"
                        self._capture_http_error(response)
                        raise ProviderError("Cloud provider is temporarily unavailable.")
                    if response.is_error:
                        self.last_error_category = "provider_request_rejected"
                        self._capture_http_error(response)
                        raise ProviderError("Cloud request was rejected; check OPENAI_MODEL and request limits.")
                    async for line in response.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if not data or data == "[DONE]":
                            continue
                        try:
                            event = json.loads(data)
                        except ValueError:
                            continue
                        event_type = event.get("type", "")
                        if event_type == "response.output_text.delta":
                            delta = event.get("delta", "")
                            if delta:
                                received_text = True
                                yield delta
                        elif event_type in {"response.completed", "response.incomplete", "response.failed"}:
                            self.last_terminal_event = event_type
                            completed = event.get("response")
                            if isinstance(completed, dict):
                                status_value = completed.get("status") or event_type.removeprefix("response.")
                                self.last_response_status = status_value if status_value in {
                                    "completed", "incomplete", "failed", "cancelled", "queued", "in_progress"
                                } else "unknown"
                                response_id = completed.get("id")
                                if isinstance(response_id, str):
                                    self.last_response_id = response_id
                                incomplete_details = completed.get("incomplete_details")
                                if isinstance(incomplete_details, dict):
                                    self.last_incomplete_details = incomplete_details
                                model_id = completed.get("model")
                                if isinstance(model_id, str):
                                    self.last_actual_model = model_id
                                provider_type, provider_code, event_request_id = _provider_error_fields(completed)
                                self.last_request_id = self.last_request_id or event_request_id
                                if event_type == "response.incomplete":
                                    reason = (incomplete_details or {}).get("reason") if isinstance(incomplete_details, dict) else None
                                    self.last_error_category = "incomplete_response"
                                    self.last_error_code = _safe_diagnostic_code(reason) or provider_code
                                elif event_type == "response.failed":
                                    self.last_error_category = "provider_response_failed"
                                    self.last_error_code = provider_code or provider_type
                                usage = completed.get("usage")
                                if isinstance(usage, dict):
                                    input_tokens = usage.get("input_tokens")
                                    output_tokens = usage.get("output_tokens")
                                    total_tokens = usage.get("total_tokens")
                                    if all(isinstance(v, int) and v >= 0 for v in
                                           (input_tokens, output_tokens, total_tokens)):
                                        input_details = usage.get("input_tokens_details")
                                        cached_tokens = (input_details.get("cached_tokens", 0)
                                            if isinstance(input_details, dict) else 0)
                                        if not isinstance(cached_tokens, int) or cached_tokens < 0:
                                            cached_tokens = 0
                                        self.last_usage = {
                                            "input_tokens": input_tokens,
                                            "output_tokens": output_tokens,
                                            "total_tokens": total_tokens,
                                            "cached_input_tokens": cached_tokens,
                                        }
                                if event_type == "response.completed" and self.last_usage is None:
                                    self.last_error_category = "missing_usage"
                            else:
                                self.last_response_status = event_type.removeprefix("response.")
                        elif event_type == "error":
                            error_type, error_code, event_request_id = _provider_error_fields(event)
                            self.last_error_category = "provider_stream_error"
                            self.last_error_code = error_code or error_type
                            self.last_request_id = self.last_request_id or event_request_id
                            raise ProviderError("Cloud generation failed. Check API access and try again.")
        except ProviderError:
            raise
        except httpx.TimeoutException as exc:
            self.last_error_category = "transport_timeout"
            self.last_exception_type = type(exc).__name__
            raise ProviderError("Cloud request timed out. No automatic retry was made.") from exc
        except httpx.HTTPError as exc:
            self.last_error_category = "transport_error"
            self.last_exception_type = type(exc).__name__
            raise ProviderError("Cloud connection failed. Check the network and try again.") from exc
        if self.last_terminal_event is None:
            self.last_error_category = "missing_terminal_event"
            raise ProviderError("Cloud stream ended before a terminal completion event; no retry was made.")
        if self.last_response_status != "completed":
            reason = (self.last_incomplete_details or {}).get("reason", "unspecified")
            if reason not in {"max_output_tokens", "content_filter", "other"}:
                reason = "unspecified"
            self.last_error_category = self.last_error_category or "incomplete_or_failed_response"
            self.last_error_code = self.last_error_code or _safe_diagnostic_code(reason)
            raise ProviderError(f"Cloud response did not complete (status={self.last_response_status}; reason={reason}). No retry was made.")
        if not received_text:
            self.last_error_category = "empty_response"
            raise ProviderError("Cloud provider completed without returning text.")

    def _capture_http_error(self, response: httpx.Response) -> None:
        """Record only safe provider type/code fields, never response message/body text."""
        try:
            error_type, error_code, event_request_id = _provider_error_fields(response.json())
        except (ValueError, json.JSONDecodeError):
            return
        self.last_error_code = error_code or error_type
        self.last_request_id = self.last_request_id or event_request_id


# Backward-compatible name used by older integrations.
CloudProvider = OpenAIResponsesProvider
