"""Tests for the SARIF exporter."""

import json
from pathlib import Path
from src.reporting.sarif_exporter import export_to_sarif
from src.reporting.generate import ScanRecord

def test_export_sarif(tmp_path, monkeypatch):
    """Test that findings are properly exported to SARIF 2.1.0 format."""
    
    def mock_fetch_scan_results(db_path):
        return [
            ScanRecord(
                id=1,
                target_id=42,
                vulnerability_type="SSRF in metadata",
                severity="HIGH",
                status="OPEN",
                timestamp="2026-08-14 01:00:00"
            )
        ]
        
    monkeypatch.setattr("src.reporting.sarif_exporter.fetch_scan_results", mock_fetch_scan_results)
    
    out_file = tmp_path / "report.json"
    result_code = export_to_sarif(str(out_file), db_path=Path("dummy.db"))
    
    assert result_code == 0
    assert out_file.exists()
    
    data = json.loads(out_file.read_text())
    
    assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "AntiFine"
    assert len(run["results"]) == 1
    
    finding = run["results"][0]
    assert finding["ruleId"] == "AF-TARGET-42"
    assert finding["message"]["text"] == "SSRF in metadata"
    assert finding["level"] == "error"
