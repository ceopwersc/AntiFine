"""Offline tests for AntiFine's local retrieval-assisted AI layer."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from src.ai.context_builder import build_context
from src.ai.retriever import Retriever
from src.api.server import AIAskRequest, ask_ai
from src.services.ollama_service import OllamaDisabledError


class RagTests(unittest.TestCase):
    def test_exact_rule_is_ranked_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            retriever = Retriever(Path(directory) / "index.json")
            results = retriever.retrieve("terraform.open-ingress-sensitive-port SSH", top_k=3)
        self.assertEqual(results[0].rule_id, "terraform.open-ingress-sensitive-port")

    def test_semantic_terms_retrieve_secret_documentation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            results = Retriever(Path(directory) / "index.json").retrieve(
                "How does AntiFine detect high entropy secrets?", top_k=5
            )
        self.assertTrue(any("secrets" in result.source for result in results))

    def test_unknown_question_and_top_k(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            retriever = Retriever(Path(directory) / "index.json")
            self.assertEqual(retriever.retrieve("unrelated lunar quasar", top_k=5), [])
            self.assertEqual(len(retriever.retrieve("terraform", top_k=2)), 2)

    def test_source_metadata_and_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            retriever = Retriever(path)
            chunks = retriever.rebuild_index()
            self.assertTrue(path.is_file())
            self.assertTrue(any(chunk.source.startswith("docs/ai/") for chunk in chunks))

    def test_context_redacts_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            results = Retriever(Path(directory) / "index.json").retrieve("secret", top_k=2)
        context = build_context("Explain this token", results, code_context="TOKEN=AKIA1234567890ABCDEF")
        self.assertNotIn("AKIA1234567890ABCDEF", context)
        self.assertIn("REDACTED", context)

    def test_empty_index_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / "empty.json"
            index.write_text('{"version": 1, "chunks": []}', encoding="utf-8")
            self.assertEqual(Retriever(index).retrieve("anything"), [])

    def test_ollama_disabled_does_not_change_retrieval(self) -> None:
        service = type("Service", (), {
            "generate": AsyncMock(side_effect=OllamaDisabledError("disabled")),
        })()
        with patch("src.api.server.OllamaService", return_value=service):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(ask_ai(AIAskRequest(question="How does AntiFine detect secrets?")))
        self.assertEqual(getattr(raised.exception, "status_code", None), 503)

    def test_ask_endpoint_uses_local_sources_and_handles_ollama(self) -> None:
        service = type("Service", (), {
            "config": type("Config", (), {"model": "qwen2.5:7b"})(),
            "generate": AsyncMock(return_value="AntiFine uses entropy thresholds."),
        })()
        with patch("src.api.server.OllamaService", return_value=service):
            response = asyncio.run(ask_ai(AIAskRequest(question="How does AntiFine detect high entropy secrets?")))
        self.assertEqual(response["provider"], "ollama")
        self.assertTrue(response["sources"])
        service.generate.assert_awaited_once()
        prompt = service.generate.await_args.args[0]
        self.assertIn("AUTHORITATIVE ANTIFINE DATA", prompt)
        self.assertIn("secrets.entropy", prompt)


if __name__ == "__main__":
    unittest.main()
