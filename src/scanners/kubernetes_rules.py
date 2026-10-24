"""Supported PodSpec checks; a partial policy evaluation, not PSS certification."""
import yaml

from src.models.finding import Finding
from src.scanners.structures import yaml_documents, yaml_node, yaml_scalar
from src.services.filesystem import MAX_FILE_BYTES

SPEC_PATHS = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
DANGEROUS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW", "SYS_MODULE", "DAC_OVERRIDE"}


def mapping(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("Expected a mapping in Kubernetes security fields")
    return value


def sequence(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("Expected an array in Kubernetes security fields")
    return value


def analyze(content, filename):
    from src.scanners.iac_audit import _walk_yaml_strings
    try:
        if len(content.encode()) > MAX_FILE_BYTES:
            raise ValueError("YAML byte quota exceeded")
        documents = yaml_documents(content)
        findings = []
        for doc_index, doc in enumerate(documents):
            if not isinstance(doc, dict):
                if doc is not None:
                    raise ValueError("Kubernetes document must be a mapping")
                continue
            findings.extend(_walk_yaml_strings(doc, filename))
            path = SPEC_PATHS.get(doc.get("kind"))
            if not path:
                continue
            spec = doc
            for key in path:
                spec = mapping(spec).get(key)
            spec = mapping(spec)
            base = f"yaml/{doc_index}/" + "/".join(path)
            pod_ctx = mapping(spec.get("securityContext"))
            for flag in ("hostPID", "hostIPC", "hostNetwork"):
                if flag in spec and not isinstance(spec[flag], bool):
                    raise ValueError("Host namespace flags must be booleans")
            if "runAsNonRoot" in pod_ctx and not isinstance(pod_ctx["runAsNonRoot"], bool):
                raise ValueError("Pod runAsNonRoot must be boolean")
            if not sequence(spec.get("containers")):
                raise ValueError("A supported PodSpec requires containers")

            def add(rule, title, severity, frameworks, advice, pointer, eligible=False):
                try:
                    line = yaml_node(content, pointer).start_mark.line + 1
                except (KeyError, IndexError, ValueError):
                    line = 1
                findings.append(Finding(title + f" in {filename}", severity, filename,
                    frameworks=frameworks, remediation=advice, rule_id=rule,
                    resource=pointer, line=line, remediation_eligible=eligible))

            flags = [key for key in ("hostPID", "hostIPC", "hostNetwork") if spec.get(key) is True]
            if flags:
                add("kubernetes.host-namespaces", f"Host Namespace Exposure ({', '.join(flags)})", "CRITICAL",
                    ["CIS Kubernetes 5.2.2", "NIST SP 800-190 Section 3.3.1"], "Remove host namespace flags.", base + "/" + flags[0])
            for group in ("containers", "initContainers", "ephemeralContainers"):
                for index, container in enumerate(sequence(spec.get(group))):
                    container = mapping(container)
                    name = container.get("name", "unnamed")
                    ctx = mapping(container.get("securityContext"))
                    caps = mapping(ctx.get("capabilities"))
                    drop, added = sequence(caps.get("drop")), sequence(caps.get("add"))
                    if any(not isinstance(c, str) for c in drop + added):
                        raise ValueError("Capabilities must contain strings")
                    prefix = f"{base}/{group}/{index}"
                    sec = prefix + "/securityContext"
                    for key in ("privileged", "allowPrivilegeEscalation", "runAsNonRoot", "readOnlyRootFilesystem"):
                        if key in ctx and not isinstance(ctx[key], bool):
                            raise ValueError("Security flags must be booleans")
                    if ctx.get("privileged") is True:
                        add("kubernetes.privileged", f"Privileged Container ({name})", "CRITICAL",
                            ["CIS Kubernetes 5.2.1", "PCI-DSS 4.0 Req 2.2.4"], "Set privileged: false.", sec + "/privileged", True)
                    if ctx.get("allowPrivilegeEscalation") is not False:
                        add("kubernetes.privilege-escalation", f"Privilege Escalation Allowed ({name})", "HIGH",
                            ["CIS Kubernetes 5.2.5", "PSS Restricted"], "Set allowPrivilegeEscalation: false.", sec + "/allowPrivilegeEscalation", ctx.get("allowPrivilegeEscalation") is True)
                    run_nonroot = ctx.get("runAsNonRoot", pod_ctx.get("runAsNonRoot"))
                    run_user = ctx.get("runAsUser", pod_ctx.get("runAsUser"))
                    if run_nonroot is not True or run_user == 0:
                        add("kubernetes.root", f"Container May Run As Root ({name})", "HIGH",
                            ["CIS Kubernetes 5.2.6", "PSS Restricted"], "Set runAsNonRoot: true and a nonzero runAsUser.", sec)
                    if ctx.get("readOnlyRootFilesystem") is not True:
                        add("kubernetes.writable-root", f"Writable Root Filesystem ({name})", "MEDIUM",
                            ["CIS Kubernetes 5.2.6", "NIST SP 800-190 Section 3.3.4"], "Set readOnlyRootFilesystem: true.", sec)
                    if "ALL" not in {v.upper() for v in drop}:
                        add("kubernetes.drop-capabilities", f"Insecure Capabilities (Missing drop ALL for {name})", "HIGH",
                            ["CIS Kubernetes 5.2.7", "PSS Restricted"], "Drop ALL capabilities.", sec)
                    dangerous = [v for v in added if v.upper() in DANGEROUS]
                    if dangerous:
                        add("kubernetes.dangerous-capabilities", f"Dangerous Capabilities Added ({', '.join(dangerous)} for {name})", "HIGH",
                            ["CIS Kubernetes 5.2.7", "PSS Restricted"], "Remove dangerous capabilities.", sec)
                    profile = mapping(ctx.get("seccompProfile", pod_ctx.get("seccompProfile")))
                    if profile.get("type") not in ("RuntimeDefault", "Localhost"):
                        add("kubernetes.seccomp", f"Missing Seccomp Profile ({name})", "MEDIUM",
                            ["PSS Restricted", "CIS Kubernetes 5.7.2"], "Set seccompProfile.type: RuntimeDefault.", sec)
                    resources = mapping(container.get("resources"))
                    limits = mapping(resources.get("limits"))
                    if not limits.get("cpu") or not limits.get("memory"):
                        add("kubernetes.resource-limits", f"Missing Resource Limits ({name})", "MEDIUM",
                            ["NIST SP 800-190 Section 3.3.4", "CIS Kubernetes 5.2.8"], "Define CPU and memory limits.", prefix)
        # Shared YAML anchors can point several containers at the same scalar.
        # Such an edit would affect more than the selected resource: manual-only.
        positions = {}
        for finding in findings:
            if finding.remediation_eligible:
                span = yaml_scalar(content, finding.resource)[:2]
                positions.setdefault(span, []).append(finding)
        for shared in positions.values():
            if len(shared) > 1:
                for finding in shared:
                    finding.remediation_eligible = False
        return findings
    except (yaml.YAMLError, ValueError, TypeError, RecursionError, KeyError, IndexError):
        return [Finding("YAML Parse Error or unsupported structure", "CRITICAL", filename,
            frameworks=["Internal"], remediation="Correct the YAML structure or reduce its complexity.", rule_id="parser.yaml")]
