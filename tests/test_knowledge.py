"""Focused checks for the deterministic AntiFine knowledge layer."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from src.ai.knowledge_service import KnowledgeService, find_rule_for_finding
from src.models.finding import Finding
from src.scanners.iac_audit import analyze_terraform
from src.services.ai_explanation import build_explanation_prompt


class KnowledgeServiceTests(unittest.TestCase):
    def test_known_rule_returns_actual_metadata(self) -> None:
        rule = KnowledgeService().get_rule("terraform.public-database")
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertEqual(rule.severity, "CRITICAL")
        self.assertIn("publicly_accessible", rule.description)

    def test_unknown_rule_is_safe(self) -> None:
        service = KnowledgeService()
        self.assertIsNone(service.get_rule("not-a-real-rule"))
        self.assertEqual(service.get_remediation("not-a-real-rule"), None)

    def test_dynamic_finding_matches_rule_context(self) -> None:
        finding = Finding(
            rule_name="Publicly Accessible Database (db) in main.tf",
            severity="CRITICAL",
            filename="main.tf",
        )
        rule = find_rule_for_finding(finding)
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertEqual(rule.rule_id, "terraform.public-database")

    def test_prompt_contains_rule_context_and_redacts_secret(self) -> None:
        finding = Finding(
            rule_name="Exact Vendor Match (AWS Access Key ID) in config.env [TOKEN]",
            severity="CRITICAL",
            filename="config.env",
            frameworks=["CWE-798"],
            remediation="Rotate the credential.",
        )
        prompt = build_explanation_prompt(
            finding,
            "TOKEN=AKIA1234567890ABCDEF",
            find_rule_for_finding(finding),
        )
        self.assertIn("AntiFine rule context:", prompt)
        self.assertIn("secrets.vendor-match", prompt)
        self.assertNotIn("AKIA1234567890ABCDEF", prompt)

    def test_prompt_without_rule_context_remains_valid(self) -> None:
        finding = Finding("Unknown local rule", "LOW", "main.tf")
        prompt = build_explanation_prompt(finding, None, None)
        self.assertIn("No matching AntiFine rule metadata supplied.", prompt)

    def test_ollama_prompt_path_does_not_require_knowledge_lookup(self) -> None:
        finding = Finding("Unknown local rule", "LOW", "main.tf")
        with patch("src.services.ollama_service.OllamaService.generate", new_callable=AsyncMock) as generate:
            generate.return_value = "explanation"
            # The prompt builder accepts no rule and remains independent of Ollama.
            self.assertTrue(build_explanation_prompt(finding, None, None))
            generate.assert_not_awaited()

    def test_terraform_scanner_remains_deterministic(self) -> None:
        findings = analyze_terraform(
            'resource "aws_db_instance" "db" {\n'
            '  publicly_accessible = true\n'
            '}\n',
            "main.tf",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("Publicly Accessible Database", findings[0].rule_name)


if __name__ == "__main__":
    unittest.main()
