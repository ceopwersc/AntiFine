"""Compliance framework mapping logic.

Translates raw vulnerability types into structured compliance metadata:
multi-framework cross-walks, human-readable descriptions, and actionable
remediation code snippets.
"""

from __future__ import annotations
from typing import TypedDict


class FindingMetadata(TypedDict):
    """Structured compliance metadata for a single finding."""
    primary_framework: str          # Used for DB storage (single string)
    frameworks: list[str]           # Full cross-walk list
    description: str                # Human-readable explanation
    remediation: str                # Actionable code diff / instruction


# ── Rule table ──────────────────────────────────────────────────────────────
# Each entry is (match_fn, metadata_dict).  match_fn receives the lower-cased
# vulnerability_type string and returns True when the rule applies.
# Rules are evaluated in order — first match wins.

_RULES: list[tuple] = [

    # ── USER root ─────────────────────────────────────────────────────────
    (
        lambda v: "user root" in v or "root user" in v,
        FindingMetadata(
            primary_framework="CIS Docker Benchmark 4.1",
            frameworks=[
                "CIS Docker Benchmark 4.1",
                "NIST SP 800-190 §3.3.1",
                "PCI-DSS 4.0 Req 2.2.4",
            ],
            description=(
                "Container is running as root. If the process is compromised, the attacker "
                "gains root privileges on the host. Containers must use a non-root user."
            ),
            remediation=(
                "# Create a dedicated non-root user and switch to it\n"
                "RUN groupadd -r appuser && useradd -r -g appuser appuser\n"
                "USER appuser"
            ),
        ),
    ),

    # ── Missing USER directive ────────────────────────────────────────────
    (
        lambda v: "missing user" in v,
        FindingMetadata(
            primary_framework="CIS Docker Benchmark 4.1",
            frameworks=[
                "CIS Docker Benchmark 4.1",
                "NIST SP 800-190 §3.3.1",
                "PCI-DSS 4.0 Req 2.2.4",
            ],
            description=(
                "No USER instruction found in Dockerfile. Docker defaults to running as root "
                "when no USER is specified, violating least-privilege principles."
            ),
            remediation=(
                "# Add before the ENTRYPOINT/CMD instruction\n"
                "RUN groupadd -r appuser && useradd -r -g appuser appuser\n"
                "USER appuser"
            ),
        ),
    ),

    # ── Missing HEALTHCHECK ───────────────────────────────────────────────
    (
        lambda v: "missing healthcheck" in v or ("healthcheck" in v and "missing" not in v),
        FindingMetadata(
            primary_framework="CIS Docker Benchmark 4.6",
            frameworks=[
                "CIS Docker Benchmark 4.6",
                "NIST SP 800-190 §3.3.4",
            ],
            description=(
                "No HEALTHCHECK instruction defined. Without a health check, the container "
                "orchestrator cannot detect hung or degraded processes and restart them."
            ),
            remediation=(
                "HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\\n"
                "  CMD curl -f http://localhost:8000/health || exit 1"
            ),
        ),
    ),

    # ── Hardcoded secrets (ENV with secret-like key names) ────────────────
    (
        lambda v: "hardcoded secret" in v or "hardcoded credential" in v or "secret" in v and "env" in v,
        FindingMetadata(
            primary_framework="CIS Docker Benchmark 4.7",
            frameworks=[
                "CIS Docker Benchmark 4.7",
                "CWE-798 (Use of Hard-coded Credentials)",
                "ISO 27001 A.8.24",
            ],
            description=(
                "A secret or credential appears to be baked into an ENV instruction. "
                "ENV values are stored in plain text in image layers and visible via "
                "'docker inspect'. Use runtime secret injection instead."
            ),
            remediation=(
                "# Remove the ENV secret entirely from the Dockerfile.\n"
                "# Option 1: Docker BuildKit secrets (build-time only, never stored in layer)\n"
                "# syntax=docker/dockerfile:1\n"
                "RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret\n\n"
                "# Option 2: Inject at runtime via environment variable\n"
                "# docker run -e MY_SECRET=$MY_SECRET myimage\n\n"
                "# Option 3: Use a secrets manager (Vault, AWS Secrets Manager)\n"
                "# and fetch in the entrypoint script."
            ),
        ),
    ),

    # ── Unpinned / latest image tag ───────────────────────────────────────
    (
        lambda v: "unpinned image" in v or "latest tag" in v or "untagged image" in v,
        FindingMetadata(
            primary_framework="CIS Docker Benchmark 4.3",
            frameworks=[
                "CIS Docker Benchmark 4.3",
                "NIST SP 800-190 §3.3.2",
            ],
            description=(
                "FROM uses ':latest' or no tag, making builds non-deterministic. "
                "A supply-chain compromise or upstream change can silently alter your image."
            ),
            remediation=(
                "# Pin to an exact digest for full supply-chain integrity\n"
                "FROM python:3.12.4-slim-bookworm@sha256:<digest>\n\n"
                "# At minimum, pin to a specific minor version\n"
                "FROM python:3.12.4-slim-bookworm"
            ),
        ),
    ),

    # ── Kubernetes: privileged container ─────────────────────────────────
    (
        lambda v: "privileged: true" in v or ("privileged" in v and "kubernetes" not in v and "resource" not in v),
        FindingMetadata(
            primary_framework="CIS Kubernetes Benchmark 5.2.1",
            frameworks=[
                "CIS Kubernetes Benchmark 5.2.1",
                "NIST SP 800-190 §3.4.4",
                "PCI-DSS 4.0 Req 2.2.4",
            ],
            description=(
                "Container is running in privileged mode, granting it near-host-level "
                "capabilities. This negates namespace isolation and enables container escape."
            ),
            remediation=(
                "# In your Pod spec, remove 'privileged: true' and apply least-privilege\n"
                "securityContext:\n"
                "  allowPrivilegeEscalation: false\n"
                "  runAsNonRoot: true\n"
                "  readOnlyRootFilesystem: true\n"
                "  capabilities:\n"
                "    drop:\n"
                "      - ALL"
            ),
        ),
    ),

    # ── Kubernetes: missing resource limits ───────────────────────────────
    (
        lambda v: "resource limits" in v or "missing resource" in v,
        FindingMetadata(
            primary_framework="CIS Kubernetes Benchmark 5.2.4",
            frameworks=[
                "CIS Kubernetes Benchmark 5.2.4",
                "NIST SP 800-190 §3.4.3",
            ],
            description=(
                "No CPU/memory resource limits defined. An unconstrained container can "
                "consume all node resources, causing a denial-of-service for co-located workloads."
            ),
            remediation=(
                "resources:\n"
                "  requests:\n"
                "    memory: \"128Mi\"\n"
                "    cpu: \"100m\"\n"
                "  limits:\n"
                "    memory: \"256Mi\"\n"
                "    cpu: \"500m\""
            ),
        ),
    ),

    # ── Terraform: public S3 ACL ──────────────────────────────────────────
    (
        lambda v: "s3" in v and ("public" in v or "acl" in v),
        FindingMetadata(
            primary_framework="CIS AWS Foundations Benchmark 2.1.5",
            frameworks=[
                "CIS AWS Foundations Benchmark 2.1.5",
                "ISO 27001 A.8.24",
                "PCI-DSS 4.0 Req 2.2",
            ],
            description=(
                "S3 bucket ACL is set to 'public-read' or 'public-read-write', "
                "exposing bucket contents to the public internet."
            ),
            remediation=(
                "# Remove the public ACL and enable Block Public Access\n"
                'resource "aws_s3_bucket_public_access_block" "example" {\n'
                '  bucket = aws_s3_bucket.example.id\n'
                "  block_public_acls       = true\n"
                "  block_public_policy     = true\n"
                "  ignore_public_acls      = true\n"
                "  restrict_public_buckets = true\n"
                "}"
            ),
        ),
    ),

    # ── Web: SSRF / Injection ─────────────────────────────────────────────
    (
        lambda v: "ssrf" in v or "injection" in v,
        FindingMetadata(
            primary_framework="OWASP Top 10, ISO 27001 Control A.14.2.5",
            frameworks=[
                "OWASP Top 10 A10:2021 – SSRF",
                "ISO 27001 A.14.2.5",
                "CWE-918",
            ],
            description=(
                "Server-Side Request Forgery (SSRF) vulnerability detected. "
                "An attacker can induce the server to make requests to internal services."
            ),
            remediation=(
                "# Validate and allowlist URLs before making outbound requests\n"
                "ALLOWED_HOSTS = {'api.example.com', 'internal.example.com'}\n"
                "from urllib.parse import urlparse\n"
                "def safe_request(url: str):\n"
                "    parsed = urlparse(url)\n"
                "    if parsed.hostname not in ALLOWED_HOSTS:\n"
                "        raise ValueError(f'Blocked request to {parsed.hostname}')\n"
                "    return requests.get(url, timeout=5)"
            ),
        ),
    ),

    # ── Plaintext / legacy services ───────────────────────────────────────
    (
        lambda v: "telnet" in v or "ftp" in v or "plaintext" in v,
        FindingMetadata(
            primary_framework="NIST SP 800-53 SC-8",
            frameworks=[
                "NIST SP 800-53 SC-8",
                "CIS Controls v8 – Control 3.10",
                "PCI-DSS 4.0 Req 4.2.1",
            ],
            description=(
                "A plaintext or legacy protocol service (Telnet, FTP) is exposed. "
                "These transmit credentials and data in clear text, enabling interception."
            ),
            remediation=(
                "# Replace Telnet with SSH\n"
                "# Replace FTP with SFTP or SCP\n"
                "# Disable legacy service:\n"
                "systemctl disable telnet && systemctl stop telnet\n"
                "# Install and configure SSH:\n"
                "apt-get install -y openssh-server && systemctl enable ssh"
            ),
        ),
    ),
]


def get_finding_metadata(vulnerability_type: str) -> FindingMetadata:
    """Return full compliance metadata (frameworks list + remediation) for a finding.

    Args:
        vulnerability_type: The raw vulnerability description string.

    Returns:
        A FindingMetadata dict.  Falls back to an 'Unmapped' entry if no rule matches.
    """
    v = vulnerability_type.lower()
    for match_fn, meta in _RULES:
        try:
            if match_fn(v):
                return meta
        except Exception:
            continue
    return FindingMetadata(
        primary_framework="Unmapped",
        frameworks=["Unmapped"],
        description=vulnerability_type,
        remediation="No automated remediation available. Review manually.",
    )


def map_finding_to_framework(vulnerability_type: str) -> str:
    """Legacy shim — returns the primary framework string for DB storage.

    Callers that only need a single string (e.g. SSRF handler) can keep using this.
    New callers should use get_finding_metadata() for the full cross-walk.
    """
    return get_finding_metadata(vulnerability_type)["primary_framework"]
