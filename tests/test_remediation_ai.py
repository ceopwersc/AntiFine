"""Offline tests for the advisory remediation explanation endpoint."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from src.api.server import RemediationExplanationRequest, explain_remediation
from src.models.finding import Finding
from src.services.ollama_service import OllamaDisabledError
from src.services.remediation_explanation import build_remediation_review_prompt


def request() -> RemediationExplanationRequest:
    return RemediationExplanationRequest(
        finding=Finding(
            rule_name="Publicly accessible database instance",
            severity="CRITICAL",
            filename="main.tf",
            frameworks=["CIS AWS 2.3.1", "PCI DSS 4.0"],
            remediation="Set publicly_accessible to false.",
            description="The database is publicly reachable.",
        ),
        before="publicly_accessible = true",
        after="publicly_accessible = false",
        diff="- publicly_accessible = true\n+ publicly_accessible = false",
        remediation="Set publicly_accessible to false.",
        frameworks=["CIS AWS 2.3.1", "PCI DSS 4.0"],
    )


class RemediationAITests(unittest.TestCase):
    def test_prompt_preserves_context_and_redacts_secrets(self) -> None:
        prompt = build_remediation_review_prompt(
            request().finding,
            "password = AKIA1234567890ABCDEF",
            request().after,
            request().diff,
            request().remediation,
            request().frameworks,
        )
        self.assertIn("publicly_accessible = false", prompt)
        self.assertIn("CIS AWS 2.3.1", prompt)
        self.assertNotIn("AKIA1234567890ABCDEF", prompt)
        self.assertIn("[REDACTED", prompt)

    def test_endpoint_returns_local_explanation(self) -> None:
        service = type("Service", (), {
            "config": type("Config", (), {"model": "qwen2.5:7b"})(),
            "generate": AsyncMock(return_value="### What changed\nThe flag is disabled."),
        })()
        with patch("src.api.server.OllamaService", return_value=service):
            response = asyncio.run(explain_remediation(request()))
        self.assertEqual(response["provider"], "ollama")
        self.assertTrue(response["generated_locally"])
        self.assertIn("publicly_accessible", service.generate.await_args.args[0])
        self.assertIn("CIS AWS 2.3.1", service.generate.await_args.args[0])

    def test_disabled_ollama_is_advisory_only(self) -> None:
        service = type("Service", (), {
            "generate": AsyncMock(side_effect=OllamaDisabledError("disabled")),
        })()
        with patch("src.api.server.OllamaService", return_value=service):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(explain_remediation(request()))
        self.assertEqual(raised.exception.status_code, 503)

    def test_malformed_or_empty_response_is_rejected(self) -> None:
        service = type("Service", (), {
            "generate": AsyncMock(return_value=""),
        })()
        with patch("src.api.server.OllamaService", return_value=service):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(explain_remediation(request()))
        self.assertEqual(raised.exception.status_code, 502)

    def test_oversized_diff_is_bounded(self) -> None:
        req = request()
        prompt = build_remediation_review_prompt(
            req.finding,
            "x" * 10000,
            "y" * 10000,
            "z" * 10000,
            req.remediation,
            req.frameworks,
        )
        self.assertLessEqual(len(prompt), 12000)
        self.assertIn("[TRUNCATED]", prompt)


if __name__ == "__main__":
    unittest.main()
