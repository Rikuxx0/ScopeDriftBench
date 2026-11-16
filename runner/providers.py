"""Pinned, host-side clients for local inference servers.

The model never chooses a URL.  Only the trusted orchestrator constructs these
clients; their requests cannot be redirected to another origin or path.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import socket
import time
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class ProviderError(RuntimeError):
    pass


MAX_JSON_RESPONSE_BYTES = 16 * 1024 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ProviderError("Provider redirected a request; redirects are disabled")


@dataclass(frozen=True)
class ModelInfo:
    model_id: str
    context_window: int | None = None
    tool_calling: bool | None = None
    quantization: str | None = None
    loaded: bool | None = None
    revision: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return vars(self).copy()


def validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Provider base_url must be an http(s) origin with no credentials")
    if parsed.path not in {"", "/", "/v1", "/v1/"} or parsed.query or parsed.fragment:
        raise ValueError("Provider base_url may only have the optional /v1 path")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid provider port")
    return f"{parsed.scheme}://{parsed.netloc}"


class LocalProvider:
    def __init__(self, kind: str, base_url: str, *, timeout: float = 120, retries: int = 1):
        if kind not in {"ollama", "lmstudio"}:
            raise ValueError(f"Unsupported local provider: {kind}")
        if not 0 < timeout <= 600 or not 0 <= retries <= 3:
            raise ValueError("Invalid provider timeout or retry count")
        self.kind = kind
        self.origin = validate_base_url(base_url)
        self.timeout = timeout
        self.retries = retries
        # Do not inherit HTTP_PROXY or follow redirects.  The path is selected
        # only from the fixed methods below, never from a model response.
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _request(self, method: str, path: str, data: dict | None = None, *, stream: bool = False):
        if path not in {"/api/tags", "/api/ps", "/api/show", "/api/v1/models",
                        "/v1/models", "/v1/chat/completions"}:
            raise ProviderError("Provider route is not allowlisted")
        body = None if data is None else json.dumps(data, ensure_ascii=False).encode("utf-8")
        request = Request(
            self.origin + path, data=body, method=method,
            headers={"Accept": "text/event-stream" if stream else "application/json",
                     "Content-Type": "application/json"},
        )
        # Only idempotent model discovery is retried.  A timed-out completion
        # may already have been processed by the model server.
        attempts = self.retries + 1 if method == "GET" else 1
        for attempt in range(attempts):
            try:
                return self._opener.open(request, timeout=self.timeout)
            except HTTPError as exc:
                raise ProviderError(f"{self.kind} returned HTTP {exc.code} for {path}") from exc
            except (URLError, TimeoutError, socket.timeout, OSError) as exc:
                if attempt + 1 == attempts:
                    raise ProviderError(
                        f"Cannot connect to {self.kind} at configured endpoint "
                        f"({type(exc).__name__}); check that the server is running and the address is correct"
                    ) from exc
                time.sleep(min(0.25 * 2 ** attempt, 1))
        raise AssertionError("unreachable")

    def _json(self, method: str, path: str, data: dict | None = None) -> Any:
        with self._request(method, path, data) as response:
            try:
                payload = response.read(MAX_JSON_RESPONSE_BYTES + 1)
                if len(payload) > MAX_JSON_RESPONSE_BYTES:
                    raise ProviderError(f"{self.kind} response exceeded size limit")
                result = json.loads(payload)
            except (ValueError, UnicodeError) as exc:
                raise ProviderError(f"{self.kind} returned invalid JSON from {path}") from exc
            except (TimeoutError, socket.timeout, OSError) as exc:
                raise ProviderError(f"{self.kind} response could not be read ({type(exc).__name__})") from exc
        if not isinstance(result, dict):
            raise ProviderError(f"{self.kind} returned an invalid response shape from {path}")
        return result

    def connect(self) -> None:
        self.list_models()

    def list_models(self) -> list[ModelInfo]:
        if self.kind == "ollama":
            data = self._json("GET", "/api/tags")
            entries = data.get("models")
            if not isinstance(entries, list):
                raise ProviderError("Ollama model list is malformed")
            result = []
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                    raise ProviderError("Ollama model entry is malformed")
                details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
                result.append(ModelInfo(
                    model_id=entry["name"],
                    quantization=details.get("quantization_level"),
                    revision=entry.get("digest"),
                ))
            try:
                active = self._json("GET", "/api/ps").get("models", [])
                running = {entry.get("name"): entry for entry in active if isinstance(entry, dict)} if isinstance(active, list) else {}
            except ProviderError:
                running = {}
            enriched = []
            for model in result:
                info = model
                active_info = running.get(model.model_id)
                if isinstance(active_info, dict):
                    context = active_info.get("context_length")
                    info = replace(info, loaded=True,
                                   context_window=context if isinstance(context, int) else None)
                try:
                    details = self._json("POST", "/api/show", {"model": model.model_id})
                    caps = details.get("capabilities")
                    model_data = details.get("model_info")
                    context = info.context_window
                    if context is None and isinstance(model_data, dict):
                        for key, value in model_data.items():
                            if key.endswith(".context_length") and isinstance(value, int):
                                context = value
                                break
                    info = replace(info, context_window=context,
                                   tool_calling=("tools" in caps) if isinstance(caps, list) else None)
                except ProviderError:
                    pass
                enriched.append(info)
            return enriched
        try:
            data = self._json("GET", "/api/v1/models")
        except ProviderError as exc:
            if "HTTP 404" not in str(exc):
                raise
            data = self._json("GET", "/v1/models")
        entries = data.get("models", data.get("data"))
        if not isinstance(entries, list):
            raise ProviderError("LM Studio model list is malformed")
        result = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ProviderError("LM Studio model entry is malformed")
            if entry.get("type", "llm") != "llm":
                continue
            model_id = entry.get("key", entry.get("id"))
            if not isinstance(model_id, str):
                raise ProviderError("LM Studio model ID is missing")
            capabilities = entry.get("capabilities")
            tool_calling = None
            if isinstance(capabilities, dict):
                for key in ("trained_for_tool_use", "tool_use"):
                    if isinstance(capabilities.get(key), bool):
                        tool_calling = capabilities[key]
                        break
            elif isinstance(capabilities, list):
                tool_calling = "tool_use" in capabilities or "tool_calling" in capabilities
            context = entry.get("max_context_length", entry.get("context_length"))
            instances = entry.get("loaded_instances")
            loaded = bool(instances) if isinstance(instances, list) else None
            if loaded and isinstance(instances[0], dict):
                active = instances[0].get("config")
                if isinstance(active, dict):
                    context = active.get("context_length", context)
            quantization = entry.get("quantization")
            if isinstance(quantization, dict):
                quantization = quantization.get("name")
            result.append(ModelInfo(
                model_id=model_id,
                context_window=context if isinstance(context, int) and context > 0 else None,
                tool_calling=tool_calling,
                quantization=quantization if isinstance(quantization, str) else None,
                loaded=loaded,
                revision=entry.get("model_revision"),
            ))
        return result

    def model_info(self, model_id: str) -> ModelInfo:
        for model in self.list_models():
            if model.model_id == model_id:
                return model
        raise ProviderError(f"Model {model_id!r} is not listed by {self.kind}")

    def select_model(self, model_id: str) -> ModelInfo:
        model = self.model_info(model_id)
        if self.kind == "lmstudio" and model.loaded is False:
            raise ProviderError(f"Model {model_id!r} is listed but not loaded in LM Studio")
        if model.tool_calling is False:
            raise ProviderError(f"Model {model_id!r} reports no tool calling support")
        return model

    def infer(self, model_id: str, messages: list[dict], tools: list[dict], *, temperature: float | None = None,
              max_output_tokens: int | None = None) -> dict:
        payload: dict[str, Any] = {"model": model_id, "messages": messages, "tools": tools, "stream": False}
        if temperature is not None:
            payload["temperature"] = temperature
        if max_output_tokens is not None:
            payload["max_tokens"] = max_output_tokens
        data = self._json("POST", "/v1/chat/completions", payload)
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ProviderError("Chat completion has no choices")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise ProviderError("Chat completion has no assistant message")
        calls = message.get("tool_calls", [])
        if not isinstance(calls, list):
            raise ProviderError("Chat completion tool_calls is malformed")
        return {"message": message, "finish_reason": choices[0].get("finish_reason"), "usage": data.get("usage")}

    def stream(self, model_id: str, messages: list[dict], tools: list[dict]) -> Iterator[dict]:
        payload = {"model": model_id, "messages": messages, "tools": tools, "stream": True}
        try:
            with self._request("POST", "/v1/chat/completions", payload, stream=True) as response:
                for line in response:
                    if len(line) > 1024 * 1024:
                        raise ProviderError("Provider stream event exceeded size limit")
                    if not line.startswith(b"data:"):
                        continue
                    data = line[5:].strip()
                    if data == b"[DONE]":
                        return
                    try:
                        event = json.loads(data)
                    except ValueError as exc:
                        raise ProviderError("Malformed provider stream event") from exc
                    if not isinstance(event, dict):
                        raise ProviderError("Malformed provider stream shape")
                    yield event
        except (TimeoutError, socket.timeout, OSError) as exc:
            raise ProviderError(f"{self.kind} stream closed ({type(exc).__name__})") from exc
