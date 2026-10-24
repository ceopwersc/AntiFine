---
name: kubernetes-security
description: Analyze AntiFine Kubernetes YAML rules, PodSpecs, and Pod Security Standards Restricted behavior.
---

# AntiFine Kubernetes security

Load this skill for Kubernetes manifest analysis or rule changes. Read `src/scanners/iac_audit.py`, `src/scanners/compliance_mapper.py`, `src/models/finding.py`, and tests before deciding.

- Parse YAML safely, including multi-document manifests, and inspect the actual workload PodSpec.
- Verify evidence for `privileged`, `hostPID`, `hostNetwork`, root execution, writable root filesystems, missing resource limits, capabilities, and PSS Restricted violations.
- Preserve deterministic severity, exact CIS Kubernetes/PSS mappings, and the distinction between absent, false, and true fields.
- Do not report fields from unrelated documents or infer risk from names alone.
- When changing rules, test valid, malformed, multi-document, negative, and false-positive cases.
- Keep remediation allowlisted and deterministic; AI may explain a finding but cannot decide, apply, or verify it.
