"""Infrastructure-as-Code (IaC) configuration auditor.

Parses Dockerfiles, Kubernetes YAML manifests, Terraform files, and generic
configuration files to detect security misconfigurations.  Every scanner
returns a list[Finding] using the normalized Finding dataclass.
"""

from __future__ import annotations

import re
import sqlite3
import sys
import json
import yaml
from src.scanners.structures import yaml_documents, validate_graph, terraform_attribute
from src.services.filesystem import read_source, MAX_FILE_BYTES
from contextlib import closing
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database  # noqa: E402
from src.models.finding import Finding  # noqa: E402
from src.scanners.compliance_mapper import get_finding_metadata  # noqa: E402
from src.scanners.secret_scanner import scan_value_for_secrets  # noqa: E402
from src.services.secret_boundary import sanitize_path, sanitize_text  # noqa: E402


class IaCScannerError(RuntimeError):
    """Raised when the IaC audit fails."""


# ── Directories to skip during recursive scans ──────────────────────────────

_EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".tox", "dist", "build", ".eggs", ".mypy_cache", ".pytest_cache",
}

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


def analyze_dockerfile(content: str, filename: str) -> list[Finding]:
    """Scan a Dockerfile for security misconfigurations with multi-stage awareness."""
    findings: list[Finding] = []
    lines = content.splitlines()
    stages = _parse_dockerfile_stages(lines)

    multi_stage = len(stages) > 1

    for stage in stages:
        stage_label = stage.label
        has_user = False
        has_healthcheck = False
        user_lines = [i for text, i in zip(stage.lines, stage.line_indices) if text.upper().startswith("USER ")]

        for line, global_idx in zip(stage.lines, stage.line_indices):
            upper = line.upper()
            if upper.startswith("FROM "):
                has_healthcheck = False

            # ── USER directive ────────────────────────────────────────────
            if upper.startswith("USER "):
                has_user = True
                user = line.split(" ", 1)[1].strip().lower()
                if user.split(":", 1)[0] in ("root", "0") and global_idx == user_lines[-1]:
                    if stage.is_final:
                        findings.append(Finding(
                                            resource=f"docker/{stage.index}/{global_idx + 1}", line=global_idx + 1,
                                            rule_id='docker.root-user',
                            rule_name=f"Insecure Configuration (USER root) in {filename}",
                            severity="HIGH",
                            filename=filename,
                            frameworks=["CIS Docker Benchmark 4.1", "NIST SP 800-190 §3.3.1"],
                            remediation="RUN groupadd -r appuser && useradd -r -g appuser appuser\nUSER appuser",
                        ))
                    else:
                        findings.append(Finding(
                                            resource=f"docker/{stage.index}/{global_idx + 1}", line=global_idx + 1,
                                            rule_id='docker.builder-root',
                            rule_name=(
                                f"Informational: USER root in intermediate build stage "
                                f"({stage_label}) in {filename} "
                                f"-- acceptable for toolchain/package-installation stages"
                            ),
                            severity="INFORMATIONAL",
                            filename=filename,
                            frameworks=["CIS Docker Benchmark 4.1 (Informational)"],
                            remediation="No action required for intermediate build stages.",
                        ))

            # ── HEALTHCHECK directive ─────────────────────────────────────
            elif upper.startswith("HEALTHCHECK "):
                has_healthcheck = upper.split(None, 1)[1].strip() != "NONE"

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

                # Stage 1 -- Deep scan (Vendor exact match or Entropy)
                ef = scan_value_for_secrets(val, key, filename)
                if ef:
                    ef.resource = f"docker/{stage.index}/{global_idx}"
                    ef.line = global_idx + 1
                    findings.append(ef)
                # Stage 2 -- Fallback keyword name match (CRITICAL, any stage)
                elif _SECRET_ENV_PATTERN.match(line):
                    findings.append(Finding(
                                        resource=f"docker/{stage.index}/{global_idx + 1}", line=global_idx + 1,
                                        rule_id='secrets.docker-env',
                        rule_name=f"Hardcoded Secret in ENV Instruction in {filename}",
                        severity="CRITICAL",
                        filename=filename,
                        frameworks=["CIS Docker Benchmark 4.7", "CWE-798"],
                        remediation="Remove the ENV secret and use runtime secret injection.",
                    ))

            # ── FROM unpinned image (applies to every stage) ──────────────
            elif upper.startswith("FROM "):
                normalized_from = re.sub(r"^FROM\s+(?:--\S+\s+)*", "FROM ", line, flags=re.I)
                m = _UNPINNED_FROM_PATTERN.match(normalized_from)
                if m:
                    tag = (m.group("tag") or "").lower()
                    image = m.group("image").lower()
                    if image not in ("scratch",) and "@sha256:" not in line:
                        if tag in ("latest", ""):
                            stage_ctx = (
                                " [final stage]" if stage.is_final
                                else f" [{stage_label}]"
                            )
                            findings.append(Finding(
                                                resource=f"docker/{stage.index}/{global_idx + 1}", line=global_idx + 1,
                                                rule_id='docker.unpinned-image',
                                rule_name=(
                                    f"Unpinned Image Tag (latest or missing) in "
                                    f"{filename}{stage_ctx}"
                                ),
                                severity="MEDIUM",
                                filename=filename,
                                frameworks=["CIS Docker Benchmark 4.3", "NIST SP 800-190 §3.3.2"],
                                remediation="Pin to an exact digest or specific minor version.",
                            ))

        # ── Post-stage checks ─────────────────────────────────────────────
        if stage.is_final:
            if not has_user:
                findings.append(Finding(
                                    resource=f"docker/{stage.index}/{stage.line_indices[0] + 1}", line=stage.line_indices[0] + 1,
                                    rule_id='docker.missing-user',
                    rule_name=f"Insecure Configuration (Missing USER) in {filename}",
                    severity="MEDIUM",
                    filename=filename,
                    frameworks=["CIS Docker Benchmark 4.1", "NIST SP 800-190 §3.3.1"],
                    remediation="RUN groupadd -r appuser && useradd -r -g appuser appuser\nUSER appuser",
                ))
            if not has_healthcheck:
                findings.append(Finding(
                                    resource=f"docker/{stage.index}/{stage.line_indices[0] + 1}", line=stage.line_indices[0] + 1,
                                    rule_id='docker.missing-healthcheck',
                    rule_name=f"Insecure Configuration (Missing HEALTHCHECK) in {filename}",
                    severity="LOW",
                    filename=filename,
                    frameworks=["CIS Docker Benchmark 4.6", "NIST SP 800-190 §3.3.4"],
                    remediation="HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health || exit 1",
                ))
        elif multi_stage and not has_user:
            findings.append(Finding(
                                resource=f"docker/{stage.index}/{stage.line_indices[0] + 1}", line=stage.line_indices[0] + 1,
                                rule_id='docker.builder-default-root',
                rule_name=(
                    f"Informational: No USER directive in intermediate build stage "
                    f"({stage_label}) in {filename} "
                    f"-- defaults to root, acceptable for build/compilation stages"
                ),
                severity="INFORMATIONAL",
                filename=filename,
                frameworks=["CIS Docker Benchmark 4.1 (Informational)"],
                remediation="No action required for intermediate build stages.",
            ))

    return findings


# ── Kubernetes YAML analysis ─────────────────────────────────────────────────

# Dangerous capabilities that should never be added
_DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW", "SYS_MODULE", "DAC_OVERRIDE"}


def _walk_yaml_strings(obj: object, filename: str) -> list[Finding]:
    validate_graph(obj)
    findings = []
    seen = set()
    def visit(value, key="value", pointer="value"):
        if isinstance(value, (dict, list)):
            if id(value) in seen:
                return
            seen.add(id(value))
            if isinstance(value, dict):
                for index, (k, v) in enumerate(value.items()):
                    visit(v, str(k), f"{pointer}/{index}")
            else:
                for index, v in enumerate(value):
                    visit(v, key, f"{pointer}/{index}")
        elif isinstance(value, str):
            finding = scan_value_for_secrets(value, key, filename)
            if finding:
                finding.resource = pointer
                finding.resource_label = pointer
                findings.append(finding)
    visit(obj)
    return findings



def analyze_kubernetes(content: str, filename: str) -> list[Finding]:
    from src.scanners.kubernetes_rules import analyze
    return analyze(content, filename)



# ── Terraform analysis ───────────────────────────────────────────────────────

def analyze_terraform(content: str, filename: str) -> list[Finding]:
    from src.scanners.terraform_rules import analyze
    return analyze(content, filename)


# ── Generic Secrets analysis ──────────────────────────────────────────────────

def analyze_generic_secrets(content: str, filename: str) -> list[Finding]:
    if len(content.encode("utf-8")) > MAX_FILE_BYTES:
        raise IaCScannerError("Configuration exceeds size quota")
    if filename.lower().endswith(".json"):
        try:
            return _walk_yaml_strings(json.loads(content), filename)
        except (ValueError, RecursionError):
            return [Finding("JSON Parse Error", "CRITICAL", filename, frameworks=["Internal"], rule_id="parser.json")]
    findings = []
    assignment = re.compile(r"^\s*(?:export\s+)?([\w.-]+)\s*[:=]\s*(.*)$")
    for number, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        match = assignment.match(line)
        if match:
            key, value = match.groups()
            if value.startswith(('\"', "'")):
                quote = value[0]
                end = value.find(quote, 1)
                if end == -1:
                    return [Finding("Configuration Parse Error", "CRITICAL", filename, frameworks=["Internal"], rule_id="parser.config")]
                value = value[1:end]
            else:
                value = re.split(r"\s+(?:#|;|//)", value, maxsplit=1)[0].strip()
            finding = scan_value_for_secrets(value, key, filename)
            if finding:
                finding.line = number
                finding.resource = f"assignment/{number}"
                findings.append(finding)
    # Vendor detection also covers standalone tokens/private-key blocks.
    if not findings:
        from src.scanners.secret_scanner import vendor_findings
        findings.extend(vendor_findings(content, filename))
    return findings



# ── File dispatcher ──────────────────────────────────────────────────────────

def scan_file(filepath: Path) -> list[Finding]:
    """Scan a single file based on its name/extension."""
    data = read_source(filepath.parent, filepath)
    try:
        content = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise IaCScannerError("Source must be UTF-8 text") from None

    filename = sanitize_path(filepath.name)
    if "dockerfile" in filename.lower():
        return analyze_dockerfile(content, filename)
    elif filename.lower().endswith((".yaml", ".yml")):
        return analyze_kubernetes(content, filename)
    elif filename.lower().endswith(".tf"):
        return analyze_terraform(content, filename)
    elif filename.lower().endswith((".env", ".json", ".conf")) or filename.startswith(".env"):
        return analyze_generic_secrets(content, filename)

    return []


# ── Public API ───────────────────────────────────────────────────────────────

def run_iac_audit(target_path: str, db_path: Path = DB_PATH, target_id: int = 1, persist: bool = True, *, allow_unsupported: bool = False) -> list[Finding]:
    from src.services.scanning import scan_target, identity
    from src.services.scan_repository import ScanRepository
    path = Path(target_path).absolute()
    root = path if path.is_dir() else path.parent
    try:
        run, findings = scan_target(root, path, "cli-" + identity(str(root)), ScanRepository(db_path) if persist else None)
    except (ValueError, OSError) as exc:
        raise IaCScannerError("Target could not be evaluated safely") from exc
    explicit_supported_only = allow_unsupported and any(item['status'] == 'evaluated' for item in run['coverage']) and all(item['status'] in {'evaluated', 'unsupported'} for item in run['coverage']) and not run['listing_errors']
    if (run["status"] != "completed" and not explicit_supported_only) or not run["coverage"]:
        raise IaCScannerError("Scan incomplete or unsupported; no security-gate pass is available")
    return findings
