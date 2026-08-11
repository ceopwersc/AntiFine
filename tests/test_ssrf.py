"""Unit tests for the SSRF/web vulnerability scanner.

The network layer is mocked throughout via an injected ``fetcher`` callable:
these tests exercise payload injection, response analysis, and persistence
logic **without sending any real internet traffic**.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from src.scanners.ssrf_scanner import (
    DEFAULT_PAYLOADS,
    HttpResponse,
    Payload,
    SSRFScannerError,
    analyze_response,
    build_test_urls,
    record_findings,
    run_web_audit,
    scan_target,
)

TARGET = "http://target.local/api?url=test&id=5"

# A realistic AWS instance-metadata directory listing, of the kind a
# vulnerable server would return when coerced into fetching
# http://169.254.169.254/latest/meta-data/.
AWS_METADATA_BODY = (
    "ami-id\n"
    "ami-launch-index\n"
    "hostname\n"
    "instance-id\n"
    "instance-type\n"
    "local-hostname\n"
    "local-ipv4\n"
    "mac\n"
    "public-keys/\n"
    "reservation-id\n"
    "security-credentials/\n"
)

BENIGN_BODY = "<html><body>Hello, your input was: test</body></html>"


def make_fetcher(body_for_payload):
    """Build a fetcher that returns a mocked response based on the URL.

    Args:
        body_for_payload: Callable mapping a request URL to a response body
            string, or ``None`` to simulate a failed/refused request.

    Returns:
        A ``(url, timeout) -> HttpResponse | None`` callable with the same
        signature the scanner expects, plus a ``.calls`` list recording every
        URL requested so tests can assert no unexpected host was contacted.
    """
    calls: list[str] = []

    def fetcher(url: str, timeout: int) -> HttpResponse | None:
        calls.append(url)
        body = body_for_payload(url)
        if body is None:
            return None
        return HttpResponse(status=200, body=body, url=url)

    fetcher.calls = calls  # type: ignore[attr-defined]
    return fetcher


# --------------------------------------------------------------------------
# Payload injection
# --------------------------------------------------------------------------

def test_build_test_urls_injects_each_payload_into_each_param() -> None:
    tests = build_test_urls(TARGET)

    # Two parameters (url, id) x every default payload.
    assert len(tests) == 2 * len(DEFAULT_PAYLOADS)

    params_seen = {param for param, _payload, _url in tests}
    assert params_seen == {"url", "id"}

    # For the 'url' parameter injected with the AWS payload, the crafted URL
    # must carry the payload as that parameter's value while preserving 'id'.
    aws = next(p for p in DEFAULT_PAYLOADS if p.name == "aws-metadata-root")
    crafted = next(
        url for param, payload, url in tests
        if param == "url" and payload is aws
    )
    assert "169.254.169.254" in crafted
    assert "id=5" in crafted
    # The crafted request still targets the original host, never the payload.
    assert crafted.startswith("http://target.local/api?")


def test_build_test_urls_rejects_non_http_target() -> None:
    with pytest.raises(SSRFScannerError, match="http"):
        build_test_urls("ftp://target.local/x?a=1")


def test_build_test_urls_requires_a_host() -> None:
    with pytest.raises(SSRFScannerError, match="host"):
        build_test_urls("http:///api?a=1")


def test_build_test_urls_empty_when_no_query_params() -> None:
    assert build_test_urls("http://target.local/api") == []


# --------------------------------------------------------------------------
# Response analysis
# --------------------------------------------------------------------------

def test_analyze_response_matches_indicator_case_insensitively() -> None:
    aws = next(p for p in DEFAULT_PAYLOADS if p.name == "aws-metadata-root")

    assert analyze_response(AWS_METADATA_BODY, aws) is not None
    assert analyze_response("AMI-ID\nINSTANCE-ID\n", aws) is not None
    assert analyze_response(BENIGN_BODY, aws) is None
    assert analyze_response("", aws) is None


# --------------------------------------------------------------------------
# Core requirement: a mocked AWS metadata response is flagged as SSRF
# --------------------------------------------------------------------------

def test_mocked_aws_metadata_response_is_flagged_as_ssrf() -> None:
    """The headline test: coerced AWS metadata leak -> a HIGH SSRF finding."""

    def body_for(url: str):
        # Only the AWS metadata payload elicits the leak; everything else is
        # a benign echo. No real traffic: this fetcher never touches a socket.
        # The crafted URL carries the payload percent-encoded, so match on the
        # metadata host (which survives encoding) and exclude the IAM payload,
        # which is the only other probe pointed at the same host.
        if "169.254.169.254" in url and "iam" not in url:
            return AWS_METADATA_BODY
        return BENIGN_BODY

    fetcher = make_fetcher(body_for)

    findings = scan_target(TARGET, fetcher=fetcher)

    # At least one finding, and every finding must be a genuine SSRF hit.
    assert findings, "an exposed AWS metadata response must be flagged"
    aws_findings = [
        f for f in findings
        if f.payload.name == "aws-metadata-root"
    ]
    assert aws_findings, "the AWS metadata payload must produce a finding"

    finding = aws_findings[0]
    assert finding.severity == "HIGH"
    assert finding.parameter in {"url", "id"}
    assert "AWS instance metadata exposure" in finding.vulnerability_type
    assert "SSRF" in finding.vulnerability_type
    assert finding.matched_indicator.lower() in AWS_METADATA_BODY.lower()

    # Sanity: the scanner only ever contacted the target host.
    assert fetcher.calls  # type: ignore[attr-defined]
    assert all(
        url.startswith("http://target.local/")
        for url in fetcher.calls  # type: ignore[attr-defined]
    )


def test_benign_target_produces_no_findings() -> None:
    fetcher = make_fetcher(lambda url: BENIGN_BODY)

    assert scan_target(TARGET, fetcher=fetcher) == []


def test_failed_requests_are_skipped_not_fatal() -> None:
    # Every probe "fails" (connection refused / timeout simulated as None).
    fetcher = make_fetcher(lambda url: None)

    assert scan_target(TARGET, fetcher=fetcher) == []


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def test_run_web_audit_persists_high_severity_finding(tmp_path: Path) -> None:
    db_path = tmp_path / "antifine.db"

    def body_for(url: str):
        # The crafted URL carries the payload percent-encoded, so match on the
        # metadata host (which survives encoding) and exclude the IAM payload,
        # which is the only other probe pointed at the same host.
        if "169.254.169.254" in url and "iam" not in url:
            return AWS_METADATA_BODY
        return BENIGN_BODY

    findings = run_web_audit(
        TARGET,
        db_path=db_path,
        target_id=7,
        persist=True,
        fetcher=make_fetcher(body_for),
    )

    assert findings
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT target_id, vulnerability_type, severity, status, timestamp "
            "FROM scan_results"
        ).fetchall()

    assert len(rows) == len(findings)
    assert {row[0] for row in rows} == {7}
    assert {row[2] for row in rows} == {"HIGH"}
    assert all("SSRF" in row[1] for row in rows)
    assert {row[3] for row in rows} == {"OPEN"}
    # DEFAULT CURRENT_TIMESTAMP must populate without an explicit value.
    assert all(row[4] for row in rows)


def test_run_web_audit_dry_run_skips_persistence(tmp_path: Path) -> None:
    db_path = tmp_path / "antifine.db"

    def body_for(url: str):
        # The crafted URL carries the payload percent-encoded, so match on the
        # metadata host (which survives encoding) and exclude the IAM payload,
        # which is the only other probe pointed at the same host.
        if "169.254.169.254" in url and "iam" not in url:
            return AWS_METADATA_BODY
        return BENIGN_BODY

    findings = run_web_audit(
        TARGET,
        db_path=db_path,
        persist=False,
        fetcher=make_fetcher(body_for),
    )

    assert findings
    assert not db_path.exists()


def test_record_findings_with_no_findings_writes_nothing(tmp_path: Path) -> None:
    db_path = tmp_path / "antifine.db"

    assert record_findings([], db_path=db_path) == 0
    assert not db_path.exists()


def test_custom_payload_set_is_honoured() -> None:
    custom = (
        Payload(
            name="canary",
            value="http://127.0.0.1:9000/canary",
            category="Canary probe",
            indicators=("CANARY-HIT",),
        ),
    )

    def body_for(url: str):
        return "response: CANARY-HIT confirmed" if "canary" in url else BENIGN_BODY

    findings = scan_target(TARGET, payloads=custom, fetcher=make_fetcher(body_for))

    assert len(findings) == 2  # one per parameter
    assert all(f.payload.name == "canary" for f in findings)
    assert all(f.severity == "HIGH" for f in findings)
