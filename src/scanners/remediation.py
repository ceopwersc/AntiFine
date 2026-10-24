"""Exact allowlisted scalar changes; human-readable titles never authorize edits."""
from pathlib import Path
from src.models.finding import Finding
from src.scanners.structures import terraform_attribute, yaml_scalar

class RemediationError(ValueError):
    pass

def build_candidate(content: str, finding: Finding, suffix: str) -> tuple[str, str]:
    if finding.rule_id == "terraform.public-database" and suffix == ".tf":
        start, end, _ = terraform_attribute(content, finding.resource, "publicly_accessible")
        action = "Disable public access for the selected database"
    elif finding.rule_id in {"kubernetes.privileged", "kubernetes.privilege-escalation"} and suffix in {".yaml", ".yml"}:
        start, end, _ = yaml_scalar(content, finding.resource)
        action = "Disable the selected container security flag"
    else:
        raise RemediationError("No safe deterministic fix exists for this rule and file type")
    if content[start:end].lower() != "true":
        raise RemediationError("Source scalar is not the expected boolean true")
    updated = content[:start] + "false" + content[end:]
    from src.scanners.iac_audit import analyze_terraform, analyze_kubernetes
    remaining = (analyze_terraform if suffix == ".tf" else analyze_kubernetes)(updated, "candidate" + suffix)
    if any(f.rule_id.startswith("parser.") or (f.rule_id, f.resource) == (finding.rule_id, finding.resource) for f in remaining):
        raise RemediationError("Candidate failed deterministic validation")
    return updated, action

def preview_remediation(path: Path, rule_name: str):
    raise RemediationError("Title-based remediation retired; use finding_id and preview_id")

def remediate_file(path: Path, rule_name: str):
    raise RemediationError("Title-based remediation retired; use finding_id and preview_id")
