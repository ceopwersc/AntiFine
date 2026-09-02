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
from src.scanners.secret_scanner import scan_value_for_secrets  # noqa: E402


class IaCScannerError(RuntimeError):
    """Raised when the IaC audit fails."""



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

                # Stage 1 -- Deep scan (Vendor exact match or Entropy)
                ef = scan_value_for_secrets(val, key, filename)
                if ef:
                    findings.append(ef)
                # Stage 2 -- Fallback keyword name match (CRITICAL, any stage)
                elif _SECRET_ENV_PATTERN.match(line):
                    findings.append((
                        f"Hardcoded Secret in ENV Instruction in {filename}",
                        "CRITICAL",
                    ))

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

def _fallback_kubernetes_scan(content: str, filename: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []

    if "privileged: true" in content:
        findings.append(
            (f"Insecure Configuration (privileged: true) in {filename}", "CRITICAL")
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
        ef = scan_value_for_secrets(val, key, filename)
        if ef:
            findings.append(ef)

    return findings


def _evaluate_kubernetes_podspec(pod_spec: dict, filename: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    
    # 1. Host Namespace Access
    if pod_spec.get('hostPID') is True or pod_spec.get('hostIPC') is True or pod_spec.get('hostNetwork') is True:
        findings.append((f"Kubernetes PSS: Host namespace access enabled in {filename}", "CRITICAL"))

    containers = pod_spec.get('containers', [])
    init_containers = pod_spec.get('initContainers', [])
    if not isinstance(containers, list): containers = []
    if not isinstance(init_containers, list): init_containers = []
    all_containers = containers + init_containers

    for c in all_containers:
        if not isinstance(c, dict):
            continue
            
        name = c.get('name', 'unknown')
        
        # 2. Privileged Execution
        sec_ctx = c.get('securityContext', {})
        if isinstance(sec_ctx, dict):
            if sec_ctx.get('privileged') is True:
                findings.append((f"Kubernetes PSS: Privileged execution enabled (privileged: true) in {filename} [container: {name}]", "CRITICAL"))
                
            # 3. Read-Only Root Filesystem
            if not sec_ctx.get('readOnlyRootFilesystem', False):
                findings.append((f"Kubernetes PSS: Read-only root filesystem not enforced in {filename} [container: {name}]", "MEDIUM"))
                
            # 4. Linux Capabilities
            capabilities = sec_ctx.get('capabilities', {})
            if isinstance(capabilities, dict):
                drop = capabilities.get('drop', [])
                if not isinstance(drop, list): drop = []
                drop = [str(d).upper() for d in drop]
                
                if "ALL" not in drop:
                    findings.append((f"Kubernetes PSS: Linux capabilities do not drop ALL in {filename} [container: {name}]", "HIGH"))
                    
                add = capabilities.get('add', [])
                if not isinstance(add, list): add = []
                add = [str(a).upper() for a in add]
                
                if "CAP_SYS_ADMIN" in add or "CAP_NET_ADMIN" in add:
                    findings.append((f"Kubernetes PSS: Dangerous Linux capabilities added in {filename} [container: {name}]", "HIGH"))
        else:
            # If no securityContext exists, it's missing readOnlyRootFilesystem and drop ALL
            findings.append((f"Kubernetes PSS: Read-only root filesystem not enforced in {filename} [container: {name}]", "MEDIUM"))
            findings.append((f"Kubernetes PSS: Linux capabilities do not drop ALL in {filename} [container: {name}]", "HIGH"))

        # 5. Resource Limits
        resources = c.get('resources', {})
        if isinstance(resources, dict):
            limits = resources.get('limits', {})
            if not isinstance(limits, dict) or 'cpu' not in limits or 'memory' not in limits:
                findings.append((f"Kubernetes PSS: Missing resource limits in {filename} [container: {name}]", "MEDIUM"))
        else:
            findings.append((f"Kubernetes PSS: Missing resource limits in {filename} [container: {name}]", "MEDIUM"))
            
    return findings


def analyze_kubernetes(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan a Kubernetes YAML file for security misconfigurations."""
    try:
        import yaml
    except ImportError:
        return _fallback_kubernetes_scan(content, filename)

    findings: list[tuple[str, str]] = []
    
    try:
        # Load all documents
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        return _fallback_kubernetes_scan(content, filename)
        
    for doc in docs:
        if not isinstance(doc, dict):
            continue
            
        kind = doc.get('kind')
        if not kind:
            continue
            
        # Extract PodSpec depending on Kind
        pod_spec = None
        if kind == 'Pod':
            pod_spec = doc.get('spec')
        elif kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'ReplicaSet'):
            spec = doc.get('spec', {})
            if isinstance(spec, dict):
                template = spec.get('template', {})
                if isinstance(template, dict):
                    pod_spec = template.get('spec')
        elif kind == 'CronJob':
            spec = doc.get('spec', {})
            if isinstance(spec, dict):
                jobTemplate = spec.get('jobTemplate', {})
                if isinstance(jobTemplate, dict):
                    template_spec = jobTemplate.get('spec', {})
                    if isinstance(template_spec, dict):
                        template = template_spec.get('template', {})
                        if isinstance(template, dict):
                            pod_spec = template.get('spec')
                            
        if isinstance(pod_spec, dict):
            findings.extend(_evaluate_kubernetes_podspec(pod_spec, filename))

    # Also run the generic string secrets entropy check on the raw YAML
    _yaml_kv = re.compile(r'^\s*([\w.-]+):\s+"?([^"#{}\[\]|>]+)"?\s*$')
    for raw_line in content.splitlines():
        m = _yaml_kv.match(raw_line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            ef = scan_value_for_secrets(val, key, filename)
            if ef:
                findings.append(ef)

    # Deduplicate findings since multiple resources in one file might generate identical strings
    # but we usually keep them all. Wait, lists of tuples can be deduplicated easily.
    # However, keeping them all shows exactly how many violations there are.
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
            ef = scan_value_for_secrets(val, key, filename)
            if ef:
                findings.append(ef)

    return findings


# ── Generic Secrets analysis ──────────────────────────────────────────────────

def analyze_generic_secrets(content: str, filename: str) -> list[tuple[str, str]]:
    """Scan generic configuration files (.env, .json, .conf) for secrets."""
    findings: list[tuple[str, str]] = []

    # Match common KV structures: key=value, "key": "value", key: value
    _generic_kv = re.compile(r'^\s*["\']?([\w.-]+)["\']?\s*[:=]\s*["\']?([^"\']+)["\']?\s*,?$')

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "//")):
            continue

        m = _generic_kv.match(line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            ef = scan_value_for_secrets(val, key, filename)
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
    elif filename.endswith((".env", ".json", ".conf")) or filename.startswith(".env"):
        return analyze_generic_secrets(content, filename)

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
                or filepath.name.endswith((".yaml", ".yml", ".tf", ".env", ".json", ".conf"))
                or filepath.name.startswith(".env")
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
