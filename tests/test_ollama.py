from __future__ import annotations

import httpx
import anyio
import pytest
from fastapi.testclient import TestClient

from src.api.server import app
from src.services.ollama_service import (
    OllamaConfig,
    OllamaDisabledError,
    OllamaResponseError,
    OllamaService,
    OllamaTimeoutError,
    OllamaUnavailableError,
)


def test_disabled_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "false")
    service = OllamaService(OllamaConfig.from_env())

    with pytest.raises(OllamaDisabledError, match="disabled"):
        anyio.run(service.generate, "hello")


def test_successful_generation(httpx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "true")
    httpx_mock.add_response(
        method="POST",
        url="http://127.0.0.1:11434/api/generate",
        json={"response": "Terraform is infrastructure as code."},
    )

    result = anyio.run(
        OllamaService(OllamaConfig.from_env()).generate,
        "Explain Terraform.",
    )

    assert result == "Terraform is infrastructure as code."


def test_health_available(httpx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "true")
    httpx_mock.add_response(
        method="GET",
        url="http://127.0.0.1:11434/api/tags",
        json={"models": [{"name": "qwen2.5:7b"}]},
    )

    assert anyio.run(OllamaService(OllamaConfig.from_env()).health_check)


def test_unavailable_connection(httpx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "true")
    httpx_mock.add_exception(
        httpx.ConnectError("connection refused"),
        url="http://127.0.0.1:11434/api/generate",
    )

    with pytest.raises(OllamaUnavailableError, match="not reachable"):
        anyio.run(OllamaService(OllamaConfig.from_env()).generate, "hello")


def test_timeout(httpx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "true")
    httpx_mock.add_exception(
        httpx.ReadTimeout("timed out"),
        url="http://127.0.0.1:11434/api/generate",
    )

    with pytest.raises(OllamaTimeoutError, match="timed out"):
        anyio.run(OllamaService(OllamaConfig.from_env()).generate, "hello")


def test_malformed_response(httpx_mock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "true")
    httpx_mock.add_response(
        method="POST",
        url="http://127.0.0.1:11434/api/generate",
        json={"done": True},
    )

    with pytest.raises(OllamaResponseError, match="contain text"):
        anyio.run(OllamaService(OllamaConfig.from_env()).generate, "hello")


def test_ai_health_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "false")
    response = TestClient(app).get("/api/ai/health")

    assert response.status_code == 200
    assert response.json()["available"] is False
    assert response.json()["enabled"] is False


def test_ai_test_rejects_empty_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "true")
    response = TestClient(app).post("/api/ai/test", json={"prompt": "  "})

    assert response.status_code == 422
