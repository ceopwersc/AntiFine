import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from database.setup import initialize_database
from src.ai.context_builder import build_context
from src.models.finding import Finding
from src.reporting.generate import fetch_scan_results, render_report
from src.reporting.sarif_exporter import generate_sarif
from src.scanners.iac_audit import run_iac_audit


class ComplianceIntegrityTests(unittest.TestCase):
    def test_finding_preserves_single_multiple_and_missing_mappings(self):
        self.assertEqual(
            Finding("one", "HIGH", "x", frameworks=["CIS 1"]).compliance_frameworks,
            ["CIS 1"],
        )
        finding = Finding(
            "many", "HIGH", "x",
            frameworks=["CIS AWS Foundations Benchmark 5.2", "PCI-DSS 4.0 Requirement 1.3.1"],
        )
        self.assertEqual(finding.frameworks, finding.compliance_frameworks)
        self.assertEqual(Finding("none", "LOW", "x").frameworks, [])

    def test_legacy_primary_framework_migrates_as_one_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE scan_results (id INTEGER PRIMARY KEY, target_id INTEGER, "
                "vulnerability_type TEXT, severity TEXT, status TEXT, "
                "compliance_framework TEXT, timestamp TEXT)"
            )
            connection.execute(
                "INSERT INTO scan_results VALUES (1, 1, 'text', 'HIGH', 'OPEN', ?, 'now')",
                ("CIS AWS Foundations Benchmark 5.2",),
            )
            connection.commit()
            connection.close()
            initialize_database(path)
            records = fetch_scan_results(path)
            self.assertEqual(records[0].frameworks, ("CIS AWS Foundations Benchmark 5.2",))

    def test_report_sarif_and_ai_use_supplied_mappings(self):
        records = [
            type("Record", (), {
                "id": 1, "target_id": 1, "vulnerability_type": "finding",
                "severity": "HIGH", "status": "OPEN", "timestamp": "now",
                "frameworks": ("CIS AWS Foundations Benchmark 5.2",
                               "PCI-DSS 4.0 Requirement 1.3.1"),
                "normalized_severity": "HIGH", "port": None,
                "remediation": "Use a trusted network.",
            })()
        ]
        report = render_report(records)
        self.assertIn("PCI-DSS 4.0 Requirement 1.3.1", report)
        sarif = generate_sarif([{
            "vulnerability_type": "finding",
            "severity": "HIGH",
            "frameworks": list(records[0].frameworks),
        }])
        self.assertEqual(
            sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["frameworks"],
            list(records[0].frameworks),
        )
        self.assertEqual(
            sarif["runs"][0]["results"][0]["properties"]["frameworks"],
            list(records[0].frameworks),
        )
        context = build_context(
            "Does this affect PCI-DSS?",
            [],
            Finding("rule", "HIGH", "x", frameworks=["CIS AWS Foundations Benchmark 5.2"]),
        )
        self.assertIn("CIS AWS Foundations Benchmark 5.2", context)
        self.assertNotIn("PCI-DSS 4.0 Requirement", context)

    def test_tf_aws_004_mappings_survive_scanner_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.tf"
            source.write_text(
                'resource "aws_security_group" "web" {\n'
                '  ingress {\n'
                '    from_port = 22\n'
                '    to_port = 22\n'
                '    protocol = "tcp"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                '  }\n'
                '}\n',
                encoding="utf-8",
            )
            database = root / "antifine.db"
            findings = run_iac_audit(str(source), db_path=database, persist=True)
            self.assertEqual(len(findings), 1)
            record = fetch_scan_results(database)[0]
            self.assertEqual(
                record.frameworks,
                (
                    "CIS AWS Foundations Benchmark 5.2",
                    "PCI-DSS 4.0 Req 1.3.1",
                ),
            )


if __name__ == "__main__":
    unittest.main()
