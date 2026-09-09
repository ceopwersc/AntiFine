"""Optional client for the local Ollama HTTP API.

This module is deliberately separate from the scanner and remediation
pipelines. Ollama is contacted only when an API caller explicitly requests
an AI operation.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_TIMEOUT = 30.0
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Load local development configuration once; explicit process environment
# variables remain authoritative because override is disabled.
load_dotenv(PROJECT_ROOT / ".env", override=False)


class OllamaError(RuntimeError):
    """Base exception for optional Ollama failures."""


class OllamaDisabledError(OllamaError):
    """Raised when AI support is disabled by configuration."""


class OllamaUnavailableError(OllamaError):
    """Raised when Ollama cannot be reached."""


class OllamaTimeoutError(OllamaUnavailableError):
    """Raised when Ollama does not respond before the configured timeout."""


class OllamaHTTPError(OllamaError):
    """Raised when Ollama returns a non-success HTTP status."""


class OllamaResponseError(OllamaError):
    """Raised when Ollama returns an unexpected JSON payload."""


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class OllamaConfig:
    """Runtime configuration loaded from environment variables."""

    enabled: bool = False
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls) -> "OllamaConfig":
        raw_timeout = os.getenv("OLLAMA_TIMEOUT", str(DEFAULT_TIMEOUT))
        try:
            timeout = float(raw_timeout)
        except ValueError:
            logger.warning("Invalid OLLAMA_TIMEOUT; using %.1f seconds", DEFAULT_TIMEOUT)
            timeout = DEFAULT_TIMEOUT
        return cls(
            enabled=_env_bool("OLLAMA_ENABLED"),
            base_url=os.getenv("OLLAMA_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            model=os.getenv("OLLAMA_MODEL", DEFAULT_MODEL),
            timeout=max(timeout, 0.1),
        )


class OllamaService:
    """Small, lazy HTTP abstraction around Ollama's local API."""

    def __init__(self, config: OllamaConfig | None = None) -> None:
        self.config = config or OllamaConfig.from_env()

    async def health_check(self) -> bool:
        """Return whether the configured Ollama API and model are available."""
        self._ensure_enabled()
        try:
            payload = await self._request_json("GET", "/api/tags")
        except OllamaError:
            raise
        models = payload.get("models")
        if not isinstance(models, list):
            raise OllamaResponseError("Ollama health response did not contain a models list")
        model_names = {
            item.get("name")
            for item in models
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        if self.config.model not in model_names:
            raise OllamaUnavailableError(
                f"Configured Ollama model is not available: {self.config.model}"
            )
        return True

    async def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        """Generate text from Ollama without logging prompt or response content."""
        self._ensure_enabled()
        if not prompt.strip():
            raise ValueError("Prompt must not be empty")

        request: dict[str, Any] = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt is not None and system_prompt.strip():
            request["system"] = system_prompt

        payload = await self._request_json("POST", "/api/generate", json=request)
        response = payload.get("response")
        if not isinstance(response, str):
            raise OllamaResponseError("Ollama response did not contain text")
        return response

    def _ensure_enabled(self) -> None:
        if not self.config.enabled:
            raise OllamaDisabledError("Ollama integration is disabled")

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.request(
                    method,
                    f"{self.config.base_url}{path}",
                    json=json,
                )
                response.raise_for_status()
                payload = response.json()
        except httpx.TimeoutException as exc:
            logger.warning("Ollama request timed out")
            raise OllamaTimeoutError("Ollama request timed out") from exc
        except httpx.HTTPStatusError as exc:
            logger.warning("Ollama returned HTTP status %s", exc.response.status_code)
            raise OllamaHTTPError(
                f"Ollama returned HTTP status {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            logger.warning("Ollama is not reachable: %s", exc.__class__.__name__)
            raise OllamaUnavailableError("Ollama is not reachable") from exc
        except ValueError as exc:
            logger.warning("Ollama returned malformed JSON")
            raise OllamaResponseError("Ollama returned malformed JSON") from exc

        if not isinstance(payload, dict):
            raise OllamaResponseError("Ollama response must be a JSON object")
        return payload
