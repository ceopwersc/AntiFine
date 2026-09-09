# Kubernetes rules

Kubernetes analysis is implemented in `analyze_kubernetes` in
`src/scanners/iac_audit.py`. It parses all YAML documents safely, scans string
values for secrets, and extracts Pod specs from Pods and workload templates.

| Rule ID | Finding | Severity | Detection |
| --- | --- | --- | --- |
| `kubernetes.host-namespace-exposure` | Host namespace exposure | CRITICAL | `hostPID`, `hostIPC`, or `hostNetwork` is true. |
| `kubernetes.privileged-container` | Privileged container | CRITICAL | A container security context has `privileged: true`. |
| `kubernetes.privilege-escalation` | Privilege escalation allowed | HIGH | `allowPrivilegeEscalation` is not false. |
| `kubernetes.run-as-root` | Container may run as root | HIGH | `runAsNonRoot` is not true. |
| `kubernetes.writable-root-filesystem` | Writable root filesystem | MEDIUM | `readOnlyRootFilesystem` is not true. |
| `kubernetes.capabilities` | Insecure capabilities | HIGH | `drop: ALL` is missing or a dangerous capability is added. |
| `kubernetes.seccomp-missing` | Missing Seccomp profile | MEDIUM | Profile type is not RuntimeDefault or Localhost. |
| `kubernetes.resource-limits` | Missing resource limits | MEDIUM | CPU or memory limits are missing. |

The deterministic remediation module can transform supported privileged and
privilege-escalation finding names. Other Kubernetes findings remain
explanation/reporting findings unless an explicit remediation branch exists.
