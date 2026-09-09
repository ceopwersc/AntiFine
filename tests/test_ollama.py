from __future__ import annotations

import httpx
import anyio
import pytest
from fastapi.testclient import TestClient

from src.api.server import app
from src.models.finding import Finding
from src.services.ollama_service import (
    OllamaConfig,
    OllamaDisabledError,
    OllamaResponseError,
    OllamaService,
    OllamaTimeoutError,
    OllamaUnavailableError,
)
from src.services.ai_explanation import MAX_CODE_CONTEXT, build_explanation_prompt, sanitize_text


FINDING = {
    "rule_name": "Open Ingress Port (22-22) to 0.0.0.0/0 in main.tf",
    "severity": "CRITICAL",
    "filename": "main.tf",
    "frameworks": ["CIS AWS Foundations Benchmark 5.2"],
    "remediation": "Restrict ingress cidr_blocks to trusted CIDRs.",
    "description": "SSH is exposed to the public internet.",
}


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


def test_configuration_reads_ollama_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "true")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://ollama.local:11434/")
    monkeypatch.setenv("OLLAMA_MODEL", "custom-model")
    monkeypatch.setenv("OLLAMA_TIMEOUT", "12")

    config = OllamaConfig.from_env()

    assert config.enabled is True
    assert config.base_url == "http://ollama.local:11434"
    assert config.model == "custom-model"
    assert config.timeout == 12.0


def test_ai_test_rejects_empty_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_ENABLED", "true")
    response = TestClient(app).post("/api/ai/test", json={"prompt": "  "})

    assert response.status_code == 422


def test_secret_redaction_and_context_truncation() -> None:
    secret = "AKIA1234567890ABCDEF password=super-secret-value"
    sanitized = sanitize_text(secret)
    prompt = build_explanation_prompt(
        Finding(**FINDING),
        "x" * (MAX_CODE_CONTEXT + 1),
    )

    assert "AKIA1234567890ABCDEF" not in sanitized
    assert "super-secret-value" not in sanitized
    assert "[REDACTED" in sanitized
    assert "[TRUNCATED]" in prompt


def test_explain_finding_success(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    class FakeService:
        config = OllamaConfig(enabled=True, model="qwen2.5:7b")

        async def generate(self, prompt: str, system_prompt: str | None = None) -> str:
            captured["prompt"] = prompt
            captured["system_prompt"] = system_prompt or ""
            return "What was detected\nCRITICAL public SSH exposure."

    monkeypatch.setattr("src.api.server.OllamaService", FakeService)
    response = TestClient(app).post(
        "/api/ai/findings/explain",
        json={"finding": FINDING, "code_context": "cidr_blocks = [\"0.0.0.0/0\"]"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "ollama"
    assert body["model"] == "qwen2.5:7b"
    assert body["generated_locally"] is True
    assert "CRITICAL" in captured["prompt"]
    assert "CIS AWS Foundations Benchmark 5.2" in captured["prompt"]
    assert "AntiFine Security Assistant" in captured["system_prompt"]


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (OllamaDisabledError("Ollama integration is disabled"), 503),
        (OllamaUnavailableError("Ollama is not reachable"), 502),
        (OllamaResponseError("Ollama response did not contain text"), 502),
    ],
)
def test_explain_finding_errors(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status: int,
) -> None:
    class FakeService:
        config = OllamaConfig(enabled=True)

        async def generate(self, prompt: str, system_prompt: str | None = None) -> str:
            raise error

    monkeypatch.setattr("src.api.server.OllamaService", FakeService)
    response = TestClient(app).post(
        "/api/ai/findings/explain",
        json={"finding": FINDING},
    )

    assert response.status_code == status
