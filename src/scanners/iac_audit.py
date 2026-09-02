"""Infrastructure-as-Code (IaC) configuration auditor.

Parses Dockerfiles, Kubernetes YAML manifests, and Terraform files to detect
common configuration vulnerabilities.  Each finding is returned as a plain
(vulnerability_type, severity) tuple so that run_iac_audit() remains
backwards-compatible with existing callers.

New callers that want enriched dicts (frameworks, remediation, etc.) should
use run_iac_audit_enriched() and post-process through compliance_mapper.
"""

from __future__ import annotations

import math
import re
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database  # noqa: E402


class IaCScannerError(RuntimeError):
    """Raised when the IaC audit fails."""


# ── Shannon Entropy utilities ────────────────────────────────────────────────

ENTROPY_MIN_LENGTH: int = 16   # minimum token length to consider
ENTROPY_THRESHOLD: float = 3.8  # bits; tuned to catch base64/hex with low FP rate


def calculate_entropy(data: str) -> float:
    """Compute Shannon entropy of *data* in bits per character.

    Formula: H(X) = -Sigma P(x_i) * log2 P(x_i)

    Returns 0.0 for empty or single-character strings.
    """
    if len(data) < 2:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _scan_value_for_entropy(
    value: str,
    key_name: str,
    filename: str,
) -> tuple[str, str] | None:
    """Return a finding tuple if *value* looks like a high-entropy secret.

    Two-stage check:
    1. Keyword match on *key_name* (fast, low-cost).
    2. Entropy gate on *value* for obfuscated variable names.

    Only tokens whose stripped length is >= ENTROPY_MIN_LENGTH are considered
    for the entropy path, which keeps false-positive rates low on short values
    such as UUIDs or version strings.
    """
    stripped = value.strip('"\'  \t')
    if not stripped:
        return None

    h = calculate_entropy(stripped)

    if len(stripped) >= ENTROPY_MIN_LENGTH and h >= ENTROPY_THRESHOLD:
        return (
            f"High Entropy Credential Exposure (Shannon H >= {ENTROPY_THRESHOLD}) "
            f"in {filename} [{key_name}=... H={h:.2f}]",
            "HIGH",
        )
    return None


# ── Dockerfile analysis ──────────────────────────────────────────────────────

# Patterns for secret-like ENV key names (both `ENV KEY value` and `ENV KEY=value` forms)
_SECRET_ENV_PATTERN = re.compile(
    r"^ENV\s+(\w*(PASSWORD|SECRET|TOKEN|KEY|APIKEY|API_KEY|CREDENTIAL|AUTH)\w*)"
    r"(?:\s+\S+|=\S+)",
    re.IGNORECASE,
)

# Pattern for unpinned / latest-tagged FROM
_UNPINNED_FROM_PATTERN = re.compile(
    r"^FROM\s+(?P<image>[^\s:@]+)(?::(?P<tag>[^\s@]+))?(?:@sha256:\S+)?",
    re.IGNORECASE,
)

# Pattern to detect `FROM image AS stage_name` (the AS clause is optional)
_FROM_STAGE_PATTERN = re.compile(
    r"^FROM\s+"
    r"(?P<image>[^\s:@]+)"
    r"(?::(?P<tag>[^\s@]+))?"
    r"(?:@sha256:\S+)?"
    r"(?:\s+AS\s+(?P<alias>\S+))?",
    re.IGNORECASE,
)


class DockerfileStage:
    """Represents a single build stage within a multi-stage Dockerfile."""

    __slots__ = ("index", "alias", "is_final", "lines", "line_indices")

    def __init__(self, index: int, alias: str | None, is_final: bool) -> None:
        self.index = index          # 0-based stage number
        self.alias = alias          # e.g. "builder", or None for unnamed stages
        self.is_final = is_final    # True only for the last FROM block
        self.lines: list[str] = []          # raw stripped instruction lines
        self.line_indices: list[int] = []   # corresponding original line indices

    @property
    def label(self) -> str:
        if self.alias:
            return f"stage:{self.alias}"
        return f"stage:{self.index}"


def _parse_dockerfile_stages(lines: list[str]) -> list[DockerfileStage]:
    """Split a Dockerfile into its constituent build stages.

    Returns a list of DockerfileStage objects.  The *last* stage in the list
    has ``is_final=True``; all others are intermediate build stages.
    Empty files or files with no FROM produce a single unnamed stage.
    """
    stages: list[DockerfileStage] = []
    current: DockerfileStage | None = None

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.upper().startswith("FROM "):
            m = _FROM_STAGE_PATTERN.match(line)
            alias = m.group("alias") if m else None
            stage = DockerfileStage(
                index=len(stages),
                alias=alias,
                is_final=False,   # corrected after the loop
            )
            stages.append(stage)
            current = stage

        if current is not None:
            current.lines.append(line)
            current.line_indices.append(idx)

    if not stages:
        # Fallback: treat the whole file as one unnamed stage
        stage = DockerfileStage(index=0, alias=None, is_final=True)
        for idx, raw_line in enumerate(lines):
            line = raw_line.strip()
            if line and not line.startswith("#"):
                stage.lines.append(line)
                stage.line_indices.append(idx)
        return [stage]

    stages[-1].is_final = True
    return stages


def analyze_dockerfile(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan a Dockerfile for security misconfigurations with multi-stage awareness.

    Stage-specific enforcement rules:
    +-----------------------------+-------------------+---------------------+
    | Check                       | Intermediate stage| Final (runtime) stage|
    +-----------------------------+-------------------+---------------------+
    | USER root (explicit)        | INFORMATIONAL     | HIGH                |
    | Missing USER directive      | (not enforced)    | MEDIUM              |
    | Missing HEALTHCHECK         | (not enforced)    | LOW                 |
    | Hardcoded secret (keyword)  | CRITICAL          | CRITICAL            |
    | High-entropy value (entropy)| HIGH              | HIGH                |
    | Unpinned image tag          | MEDIUM            | MEDIUM              |
    +-----------------------------+-------------------+---------------------+

    Rationale for INFORMATIONAL on intermediate stages:
    - Build stages (compilers, package managers) legitimately need root access
      to install system packages, modify /etc, and set up toolchains.
    - The production/runtime image (final stage) must never run as root.
    - Secrets and entropy checks apply to ALL stages — a leaked credential
      baked into any layer is still a security exposure.
    """
    findings: list[tuple[str, str]] = []
    lines = content.splitlines()
    stages = _parse_dockerfile_stages(lines)

    multi_stage = len(stages) > 1

    for stage in stages:
        stage_label = stage.label
        has_user = False
        has_healthcheck = False
        # Track global line indices where a keyword match fired so
        # entropy scan doesn't double-report the same line.
        keyword_flagged: set[int] = set()

        for line, global_idx in zip(stage.lines, stage.line_indices):
            upper = line.upper()

            # ── USER directive ────────────────────────────────────────────
            if upper.startswith("USER "):
                has_user = True
                user = line.split(" ", 1)[1].strip().lower()
                if user in ("root", "0"):
                    if stage.is_final:
                        findings.append((
                            f"Insecure Configuration (USER root) in {filename}",
                            "HIGH",
                        ))
                    else:
                        # Root in a build/toolchain stage is common practice;
                        # downgrade to INFORMATIONAL so it's visible but not noisy.
                        findings.append((
                            f"Informational: USER root in intermediate build stage "
                            f"({stage_label}) in {filename} "
                            f"-- acceptable for toolchain/package-installation stages",
                            "INFORMATIONAL",
                        ))

            # ── HEALTHCHECK directive ─────────────────────────────────────
            elif upper.startswith("HEALTHCHECK "):
                has_healthcheck = True

            # ── ENV / ARG secret detection (keyword name + entropy) ───────
            elif upper.startswith("ENV ") or upper.startswith("ARG "):
                rest = line.split(" ", 1)[1] if " " in line else ""
                if "=" in rest:
                    key, _, val = rest.partition("=")
                else:
                    parts = rest.split(None, 1)
                    key = parts[0] if parts else ""
                    val = parts[1] if len(parts) > 1 else ""

                key = key.strip()
                val = val.strip()

                # Stage 1 -- keyword name match (CRITICAL, any stage)
                if _SECRET_ENV_PATTERN.match(line):
                    findings.append((
                        f"Hardcoded Secret in ENV Instruction in {filename}",
                        "CRITICAL",
                    ))
                    keyword_flagged.add(global_idx)

                # Stage 2 -- high-entropy value check (HIGH, any stage)
                if global_idx not in keyword_flagged and val:
                    ef = _scan_value_for_entropy(val, key, filename)
                    if ef:
                        findings.append(ef)

            # ── FROM unpinned image (applies to every stage) ──────────────
            elif upper.startswith("FROM "):
                m = _UNPINNED_FROM_PATTERN.match(line)
                if m:
                    tag = (m.group("tag") or "").lower()
                    image = m.group("image").lower()
                    if image not in ("scratch",) and not upper.startswith("FROM --"):
                        if tag in ("latest", ""):
                            stage_ctx = (
                                " [final stage]" if stage.is_final
                                else f" [{stage_label}]"
                            )
                            findings.append((
                                f"Unpinned Image Tag (latest or missing) in "
                                f"{filename}{stage_ctx}",
                                "MEDIUM",
                            ))

        # ── Post-stage checks ─────────────────────────────────────────────
        if stage.is_final:
            # Strict enforcement: the runtime image must specify a non-root user
            if not has_user:
                findings.append((
                    f"Insecure Configuration (Missing USER) in {filename}",
                    "MEDIUM",
                ))
            # Health checks only matter for the service that will run in production
            if not has_healthcheck:
                findings.append((
                    f"Insecure Configuration (Missing HEALTHCHECK) in {filename}",
                    "LOW",
                ))
        elif multi_stage and not has_user:
            # Informational only: intermediate stages default to root, which is fine
            findings.append((
                f"Informational: No USER directive in intermediate build stage "
                f"({stage_label}) in {filename} "
                f"-- defaults to root, acceptable for build/compilation stages",
                "INFORMATIONAL",
            ))

    return findings


# ── Kubernetes YAML analysis ─────────────────────────────────────────────────

def analyze_kubernetes(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan a Kubernetes YAML file for security misconfigurations."""
    findings: list[tuple[str, str]] = []

    if "privileged: true" in content:
        findings.append(
            (f"Insecure Configuration (privileged: true) in {filename}", "HIGH")
        )

    if "resources:" not in content or "limits:" not in content:
        findings.append(
            (f"Insecure Configuration (Missing resource limits) in {filename}", "MEDIUM")
        )

    # ── Entropy scan on YAML string values ───────────────────────────────
    # Matches "  key: value" lines; skips comments and block/flow indicators.
    _yaml_kv = re.compile(r'^\s*([\w.-]+):\s+"?([^"#{}\[\]|>]+)"?\s*$')
    for raw_line in content.splitlines():
        m = _yaml_kv.match(raw_line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        ef = _scan_value_for_entropy(val, key, filename)
        if ef:
            findings.append(ef)

    return findings


# ── Terraform analysis ───────────────────────────────────────────────────────

def analyze_terraform(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan a Terraform file for security misconfigurations."""
    findings: list[tuple[str, str]] = []

    # Match HCL assignment: key = "value" (unquoted key, quoted value)
    _tf_kv = re.compile(r'^\s*([\w_]+)\s*=\s*"([^"]+)"')

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("#") or line.startswith("//"):
            continue

        if re.search(r'acl\s*=\s*"(public-read|public-read-write)"', line):
            findings.append(
                (f"Insecure S3 Bucket ACL (Public) in {filename}", "HIGH")
            )

        # Entropy scan on string values
        m = _tf_kv.match(raw_line)
        if m:
            key, val = m.group(1), m.group(2)
            ef = _scan_value_for_entropy(val, key, filename)
            if ef:
                findings.append(ef)

    return findings


# ── File dispatcher ──────────────────────────────────────────────────────────

def scan_file(filepath: Path) -> list[tuple[str, str]]:
    """Scan a single file based on its name/extension."""
    try:
        content = filepath.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            content = filepath.read_text(encoding="utf-16")
        except UnicodeDecodeError:
            content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"[warning] Could not read {filepath}: {exc}", file=sys.stderr)
        return []

    filename = filepath.name
    if "Dockerfile" in filename:
        return analyze_dockerfile(content, filename)
    elif filename.endswith((".yaml", ".yml")):
        return analyze_kubernetes(content, filename)
    elif filename.endswith(".tf"):
        return analyze_terraform(content, filename)

    return []


# ── Public API ───────────────────────────────────────────────────────────────

def run_iac_audit(
    target_path: str,
    db_path: Path = DB_PATH,
    target_id: int = 1,
    persist: bool = True,
) -> list[tuple[str, str]]:
    """Run the IaC audit against a file or directory.

    Returns a list of (vulnerability_type, severity) tuples.
    This signature is preserved for backwards compatibility with existing callers.
    The server-side handler uses persist=False and enriches findings itself.
    """
    path = Path(target_path)
    if not path.exists():
        raise IaCScannerError(f"Target path does not exist: {target_path}")

    all_findings: list[tuple[str, str]] = []

    if path.is_file():
        all_findings.extend(scan_file(path))
    elif path.is_dir():
        for filepath in path.rglob("*"):
            if filepath.is_file() and (
                "Dockerfile" in filepath.name
                or filepath.name.endswith((".yaml", ".yml", ".tf"))
            ):
                all_findings.extend(scan_file(filepath))

    if persist and all_findings:
        rows = [
            (target_id, vuln_type, severity, "OPEN")
            for vuln_type, severity in all_findings
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
            raise IaCScannerError(
                f"Could not write findings to {db_path}: {exc}"
            ) from exc

    return all_findings
