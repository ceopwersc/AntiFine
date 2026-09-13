---
name: iac-security
description: Analyze Terraform, Dockerfiles, and Kubernetes YAML with AntiFine's deterministic scanner and compliance rules. Load for IaC security review or rule changes.
---

# AntiFine IaC security

Use this skill only for Infrastructure-as-Code security work in AntiFine. AntiFine is deterministic first: scanner output, severity, evidence, compliance mappings, and remediation authority come from the repository code, not from an LLM guess.

## Required workflow

1. Read the real implementation under `src/scanners/`, the unified model in `src/models/finding.py`, and relevant tests before drawing conclusions.
2. Trace the exact rule and its evidence in the source file. If no matching rule or source evidence exists, say so; never manufacture a finding.
3. Preserve the scanner's exact severity and the mappings produced by `src/scanners/compliance_mapper.py`. Treat recommendations as recommendations, not observed facts.
4. Keep AI explanations advisory. Never use an LLM-generated decision as the authoritative security result, severity, compliance mapping, or remediation approval.
5. Do not modify files unless the user explicitly asks. Do not apply remediation, execute commands, or claim a fix without explicit authorization and deterministic verification.

## Rule coverage to inspect

### Terraform

Inspect HCL structurally through `src/scanners/iac_audit.py`. Check the implemented rules for:

- public SSH/RDP and dangerous `0.0.0.0/0` or `::/0` ingress
- overly permissive ingress
- `aws_db_instance.publicly_accessible = true`
- missing S3 server-side encryption
- missing or permissive S3 public-access blocks
- other public resource exposure

Report the exact rule name, resource/file evidence, affected ports or attributes, deterministic severity, and authoritative frameworks. Do not infer exposure from a variable name alone.

### Dockerfiles

Account for parser behavior and multi-stage builds. Check:

- final runtime containers running as root or missing `USER`
- `USER root` in intermediate builder stages, which may be informational rather than a final-image failure
- `:latest`, untagged, or otherwise unpinned `FROM` images
- missing `HEALTHCHECK` where the scanner requires it
- stage boundaries and final-stage behavior

Use the scanner's distinction between intermediate and final stages; do not turn normal builder setup into a critical finding.

### Kubernetes YAML

Use the scanner's safe multi-document YAML parsing and PodSpec traversal. Check:

- `privileged: true`
- `hostPID`, `hostNetwork` (and related host namespace access)
- containers that do not run as non-root
- writable root filesystems
- missing CPU/memory resource limits
- alignment with Pod Security Standards Restricted

Inspect the actual workload kind and container security context. Do not report a field that is absent from the parsed PodSpec as present.

## Rule changes

When explicitly asked to change a security rule:

- edit the smallest deterministic scanner/compliance/remediation surface;
- preserve `Finding` compatibility and existing severity/mapping semantics;
- add or update focused tests for positive, negative, malformed, and multi-stage/multi-document cases;
- verify false-positive behavior and backwards compatibility;
- keep remediation in `src/scanners/remediation.py` deterministic, allowlisted, backup-first, and followed by a rescan;
- run the relevant test suite and report failures plainly.

Reference files:

- `src/scanners/iac_audit.py`
- `src/scanners/compliance_mapper.py`
- `src/scanners/remediation.py`
- `src/models/finding.py`
- `tests/`

