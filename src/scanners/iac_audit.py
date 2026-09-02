"""Infrastructure-as-Code (IaC) configuration auditor.

Parses Dockerfiles, Kubernetes YAML manifests, Terraform files, and generic
configuration files to detect security misconfigurations.  Every scanner
returns a list[Finding] using the normalized Finding dataclass.
"""

from __future__ import annotations

import re
import sqlite3
import sys
import yaml
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.setup import DB_PATH, initialize_database  # noqa: E402
from src.models.finding import Finding  # noqa: E402
from src.scanners.secret_scanner import scan_value_for_secrets  # noqa: E402


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

        for line, global_idx in zip(stage.lines, stage.line_indices):
            upper = line.upper()

            # ── USER directive ────────────────────────────────────────────
            if upper.startswith("USER "):
                has_user = True
                user = line.split(" ", 1)[1].strip().lower()
                if user in ("root", "0"):
                    if stage.is_final:
                        findings.append(Finding(
                            rule_name=f"Insecure Configuration (USER root) in {filename}",
                            severity="HIGH",
                            filename=filename,
                            frameworks=["CIS Docker Benchmark 4.1", "NIST SP 800-190 §3.3.1"],
                            remediation="RUN groupadd -r appuser && useradd -r -g appuser appuser\nUSER appuser",
                        ))
                    else:
                        findings.append(Finding(
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
                    findings.append(Finding(
                        rule_name=f"Hardcoded Secret in ENV Instruction in {filename}",
                        severity="CRITICAL",
                        filename=filename,
                        frameworks=["CIS Docker Benchmark 4.7", "CWE-798"],
                        remediation="Remove the ENV secret and use runtime secret injection.",
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
                            findings.append(Finding(
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
                    rule_name=f"Insecure Configuration (Missing USER) in {filename}",
                    severity="MEDIUM",
                    filename=filename,
                    frameworks=["CIS Docker Benchmark 4.1", "NIST SP 800-190 §3.3.1"],
                    remediation="RUN groupadd -r appuser && useradd -r -g appuser appuser\nUSER appuser",
                ))
            if not has_healthcheck:
                findings.append(Finding(
                    rule_name=f"Insecure Configuration (Missing HEALTHCHECK) in {filename}",
                    severity="LOW",
                    filename=filename,
                    frameworks=["CIS Docker Benchmark 4.6", "NIST SP 800-190 §3.3.4"],
                    remediation="HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health || exit 1",
                ))
        elif multi_stage and not has_user:
            findings.append(Finding(
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
    """Recursively walk a parsed YAML structure and scan string values for secrets."""
    findings: list[Finding] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(val, str):
                ef = scan_value_for_secrets(val, str(key), filename)
                if ef:
                    findings.append(ef)
            else:
                findings.extend(_walk_yaml_strings(val, filename))
    elif isinstance(obj, list):
        for item in obj:
            findings.extend(_walk_yaml_strings(item, filename))
    return findings


def analyze_kubernetes(content: str, filename: str) -> list[Finding]:
    """Scan Kubernetes YAML manifests against Pod Security Standards (PSS Restricted) and CIS Benchmarks."""
    findings: list[Finding] = []

    try:
        documents = list(yaml.safe_load_all(content))
    except yaml.YAMLError as exc:
        findings.append(Finding(
            rule_name=f"YAML Parse Error in {filename}",
            severity="CRITICAL",
            filename=filename,
            frameworks=["Internal"],
            remediation="Fix the YAML syntax before scanning.",
            description=str(exc),
        ))
        return findings

    for doc in documents:
        if not isinstance(doc, dict):
            continue

        # Scan all string values in the document for embedded secrets
        findings.extend(_walk_yaml_strings(doc, filename))

        # Extract pod spec from standalone Pods or workload controllers
        spec = None
        if doc.get("kind") == "Pod":
            spec = doc.get("spec", {})
        elif "spec" in doc and isinstance(doc["spec"], dict):
            template = doc["spec"].get("template", {})
            if isinstance(template, dict):
                spec = template.get("spec", {})

        if not spec or not isinstance(spec, dict):
            continue

        # 1. Host Namespace Inspection (CRITICAL)
        host_flags = [k for k in ["hostPID", "hostIPC", "hostNetwork"] if spec.get(k) is True]
        if host_flags:
            findings.append(Finding(
                rule_name=f"Host Namespace Exposure ({', '.join(host_flags)}) in {filename}",
                severity="CRITICAL",
                filename=filename,
                frameworks=["CIS Kubernetes 5.2.2", "NIST SP 800-190 Section 3.3.1"],
                remediation="Remove hostPID, hostIPC, and hostNetwork flags from pod spec.",
            ))

        # Collect all container types for PSS checks
        all_containers: list[dict] = []
        for container_key in ("containers", "initContainers", "ephemeralContainers"):
            raw = spec.get(container_key, [])
            if isinstance(raw, list):
                all_containers.extend(c for c in raw if isinstance(c, dict))

        for container in all_containers:
            c_name = container.get("name", "unnamed")
            sec_ctx = container.get("securityContext") or {}

            # 2. Privileged Execution (CRITICAL)
            if sec_ctx.get("privileged") is True:
                findings.append(Finding(
                    rule_name=f"Privileged Container ({c_name}) in {filename}",
                    severity="CRITICAL",
                    filename=filename,
                    frameworks=["CIS Kubernetes 5.2.1", "PCI-DSS 4.0 Req 2.2.4"],
                    remediation="securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false",
                ))

            # 3. allowPrivilegeEscalation (HIGH)
            if sec_ctx.get("allowPrivilegeEscalation") is not False:
                findings.append(Finding(
                    rule_name=f"Privilege Escalation Allowed ({c_name}) in {filename}",
                    severity="HIGH",
                    filename=filename,
                    frameworks=["CIS Kubernetes 5.2.5", "PSS Restricted"],
                    remediation="securityContext:\n  allowPrivilegeEscalation: false",
                ))

            # 4. runAsNonRoot (HIGH)
            if sec_ctx.get("runAsNonRoot") is not True:
                findings.append(Finding(
                    rule_name=f"Container May Run As Root ({c_name}) in {filename}",
                    severity="HIGH",
                    filename=filename,
                    frameworks=["CIS Kubernetes 5.2.6", "PSS Restricted"],
                    remediation="securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
                ))

            # 5. Read-Only Root Filesystem (MEDIUM)
            if sec_ctx.get("readOnlyRootFilesystem") is not True:
                findings.append(Finding(
                    rule_name=f"Writable Root Filesystem ({c_name}) in {filename}",
                    severity="MEDIUM",
                    filename=filename,
                    frameworks=["CIS Kubernetes 5.2.6", "NIST SP 800-190 Section 3.3.4"],
                    remediation="securityContext:\n  readOnlyRootFilesystem: true",
                ))

            # 6. Capabilities Drop ALL (HIGH)
            caps = sec_ctx.get("capabilities") or {}
            dropped = caps.get("drop") or []
            if "ALL" not in [d.upper() for d in dropped if isinstance(d, str)]:
                findings.append(Finding(
                    rule_name=f"Insecure Capabilities (Missing drop ALL for {c_name}) in {filename}",
                    severity="HIGH",
                    filename=filename,
                    frameworks=["CIS Kubernetes 5.2.7", "PSS Restricted"],
                    remediation="securityContext:\n  capabilities:\n    drop:\n      - ALL",
                ))

            # 7. Dangerous capability additions (HIGH)
            added = caps.get("add") or []
            dangerous_added = [c.upper() for c in added if isinstance(c, str) and c.upper() in _DANGEROUS_CAPS]
            if dangerous_added:
                findings.append(Finding(
                    rule_name=f"Dangerous Capabilities Added ({', '.join(dangerous_added)} for {c_name}) in {filename}",
                    severity="HIGH",
                    filename=filename,
                    frameworks=["CIS Kubernetes 5.2.7", "PSS Restricted"],
                    remediation="Remove dangerous capabilities from securityContext.capabilities.add.",
                ))

            # 8. Seccomp Profile (MEDIUM)
            seccomp = sec_ctx.get("seccompProfile") or {}
            seccomp_type = seccomp.get("type", "")
            if seccomp_type not in ("RuntimeDefault", "Localhost"):
                findings.append(Finding(
                    rule_name=f"Missing Seccomp Profile ({c_name}) in {filename}",
                    severity="MEDIUM",
                    filename=filename,
                    frameworks=["PSS Restricted", "CIS Kubernetes 5.7.2"],
                    remediation="securityContext:\n  seccompProfile:\n    type: RuntimeDefault",
                ))

            # 9. Resource Limits (MEDIUM)
            resources = container.get("resources") or {}
            limits = resources.get("limits") or {}
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(Finding(
                    rule_name=f"Missing Resource Limits ({c_name}) in {filename}",
                    severity="MEDIUM",
                    filename=filename,
                    frameworks=["NIST SP 800-190 Section 3.3.4", "CIS Kubernetes 5.2.8"],
                    remediation="resources:\n  limits:\n    cpu: '500m'\n    memory: '512Mi'",
                ))

    return findings


# ── Terraform analysis ───────────────────────────────────────────────────────

def analyze_terraform(content: str, filename: str) -> list[Finding]:
    """Scan a Terraform file for security misconfigurations."""
    findings: list[Finding] = []

    import hcl2
    try:
        doc = hcl2.loads(content)
    except Exception as exc:
        findings.append(Finding(
            rule_name=f"HCL Parse Error in {filename}",
            severity="CRITICAL",
            filename=filename,
            frameworks=["Internal"],
            remediation="Fix the HCL syntax before scanning.",
            description=str(exc),
        ))
        return findings

    # Reuse the YAML string walker for entropy and embedded secrets
    findings.extend(_walk_yaml_strings(doc, filename))

    resources = doc.get("resource", [])
    
    s3_buckets = []
    sse_configs = []
    pab_configs = []
    
    for res_dict in resources:
        for res_type_raw, instances in res_dict.items():
            res_type = res_type_raw.strip('"\'')
            for res_name_raw, res_config in instances.items():
                res_name = res_name_raw.strip('"\'')
                
                if res_type == "aws_s3_bucket":
                    s3_buckets.append((res_name, res_config))
                elif res_type == "aws_s3_bucket_server_side_encryption_configuration":
                    sse_configs.append((res_name, res_config))
                elif res_type == "aws_s3_bucket_public_access_block":
                    pab_configs.append((res_name, res_config))
                
                # a) Open Ingress Ports (CRITICAL)
                if res_type in ("aws_security_group", "aws_security_group_rule"):
                    ingress_rules = []
                    if res_type == "aws_security_group_rule" and str(res_config.get("type", "")).strip('"\'') == "ingress":
                        ingress_rules.append(res_config)
                    elif res_type == "aws_security_group":
                        ig = res_config.get("ingress", [])
                        if isinstance(ig, list):
                            ingress_rules.extend(ig)
                        elif isinstance(ig, dict):
                            ingress_rules.append(ig)
                    
                    for rule in ingress_rules:
                        cidrs = rule.get("cidr_blocks", [])
                        cidrs_str = str(cidrs).replace('"', '').replace("'", "")
                        if "0.0.0.0/0" in cidrs_str or "::/0" in cidrs_str:
                            from_port = rule.get("from_port")
                            to_port = rule.get("to_port")
                            
                            try:
                                fp = int(from_port) if from_port is not None else None
                                tp = int(to_port) if to_port is not None else None
                            except (ValueError, TypeError):
                                continue
                                
                            if fp is not None and tp is not None:
                                if (fp <= 22 <= tp) or (fp <= 3389 <= tp):
                                    findings.append(Finding(
                                        rule_name=f"Open Ingress Port ({fp}-{tp}) to 0.0.0.0/0 in {filename}",
                                        severity="CRITICAL",
                                        filename=filename,
                                        frameworks=["CIS AWS Foundations Benchmark 5.2", "PCI-DSS 4.0 Req 1.3.1"],
                                        remediation="Restrict ingress cidr_blocks to specific trusted corporate CIDRs or bastion host."
                                    ))

                # c) Publicly Accessible Databases (CRITICAL)
                if res_type == "aws_db_instance":
                    if str(res_config.get("publicly_accessible", "")).lower() == "true":
                        findings.append(Finding(
                            rule_name=f"Publicly Accessible Database ({res_name}) in {filename}",
                            severity="CRITICAL",
                            filename=filename,
                            frameworks=["CIS AWS Foundations Benchmark 2.3.1", "PCI-DSS 4.0 Req 1.3.2"],
                            remediation="Set publicly_accessible = false and deploy the database inside private subnets."
                        ))

    # b) & d) Check S3 Buckets for SSE and PAB
    for b_name, b_config in s3_buckets:
        has_embedded_sse = "server_side_encryption_configuration" in b_config
        has_companion_sse = False
        for sse_name, sse_config in sse_configs:
            bucket_ref = str(sse_config.get("bucket", ""))
            if b_name in bucket_ref:
                has_companion_sse = True
                break
                
        if not (has_embedded_sse or has_companion_sse):
            findings.append(Finding(
                rule_name=f"Unencrypted S3 Storage ({b_name}) in {filename}",
                severity="HIGH",
                filename=filename,
                frameworks=["CIS AWS Foundations Benchmark 2.1.1", "NIST SP 800-190 Section 3.3.4"],
                remediation='resource "aws_s3_bucket_server_side_encryption_configuration" "example" {\n  bucket = aws_s3_bucket.example.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}'
            ))
            
        has_pab = False
        for pab_name, pab_config in pab_configs:
            bucket_ref = str(pab_config.get("bucket", ""))
            if b_name in bucket_ref:
                has_pab = True
                break
                
        if not has_pab:
            findings.append(Finding(
                rule_name=f"S3 Public Access Block Missing ({b_name}) in {filename}",
                severity="HIGH",
                filename=filename,
                frameworks=["CIS AWS Foundations Benchmark 2.1.5"],
                remediation='resource "aws_s3_bucket_public_access_block" "example" {\n  bucket = aws_s3_bucket.example.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}'
            ))

    return findings


# ── Generic Secrets analysis ──────────────────────────────────────────────────

def analyze_generic_secrets(content: str, filename: str) -> list[Finding]:
    """Scan generic configuration files (.env, .json, .conf) for secrets."""
    findings: list[Finding] = []

    # Match common KV structures: key=value, "key": "value", key: value
    _generic_kv = re.compile(r'^\s*["\']?([\w.-]+)["\']?\s*[:=]\s*["\']?([^"\']+ )["\']?\s*,?$')

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

def scan_file(filepath: Path) -> list[Finding]:
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
) -> list[Finding]:
    """Run the IaC audit against a file or directory.

    Returns a list of Finding objects.
    """
    path = Path(target_path)
    if not path.exists():
        raise IaCScannerError(f"Target path does not exist: {target_path}")

    all_findings: list[Finding] = []

    if path.is_file():
        all_findings.extend(scan_file(path))
    elif path.is_dir():
        for filepath in path.rglob("*"):
            # Skip excluded directories
            if any(part in _EXCLUDED_DIRS for part in filepath.parts):
                continue
            if filepath.is_file() and (
                "Dockerfile" in filepath.name
                or filepath.name.endswith((".yaml", ".yml", ".tf", ".env", ".json", ".conf"))
                or filepath.name.startswith(".env")
            ):
                all_findings.extend(scan_file(filepath))

    if persist and all_findings:
        rows = []
        for finding in all_findings:
            rows.append((
                target_id,
                finding.rule_name,
                finding.severity,
                "OPEN",
                finding.filename,
            ))

        try:
            initialize_database(db_path)
            with sqlite3.connect(db_path) as connection:
                connection.executemany(
                    "INSERT INTO scan_results "
                    "(target_id, vulnerability_type, severity, status, target_path) "
                    "VALUES (?, ?, ?, ?, ?)",
                    rows,
                )
                connection.commit()
        except (sqlite3.Error, OSError) as exc:
            raise IaCScannerError(
                f"Could not write findings to {db_path}: {exc}"
            ) from exc

    return all_findings
