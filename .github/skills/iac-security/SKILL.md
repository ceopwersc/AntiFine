---
name: iac-security
description: Analyze and safely evolve AntiFine's deterministic Terraform, Dockerfile, Kubernetes, secret, compliance, and remediation security logic.
---

# AntiFine IaC security

Load this skill for Infrastructure-as-Code security analysis, rule reviews, or scanner changes. AntiFine is a local-first deterministic scanner: its findings, evidence, severity, compliance mappings, and remediation verification are authoritative. AI/Copilot may explain and propose, but must never replace that logic.

## Source of truth

Before changing security behavior, inspect the actual implementation and tests. Do not assume a rule exists because it is documented.

- `src/scanners/iac_audit.py`
- `src/scanners/secret_scanner.py`
- `src/scanners/compliance_mapper.py`
- `src/scanners/remediation.py`
- `src/models/finding.py`
- `src/api/server.py`
- relevant files under `tests/`

Trace the real parser, rule name, evidence, severity, framework metadata, API response, and remediation path. Never claim a finding without source evidence.

## Terraform

Use AntiFine's existing structural HCL parser. Inspect security groups, ingress/egress, public exposure, S3 encryption and public-access blocks, databases, network configuration, supported IAM infrastructure, resource attributes, and secrets. Existing patterns include SSH/RDP exposed to `0.0.0.0/0`, public databases, unencrypted S3, and missing S3 public-access blocks.

For a new rule, define precise evidence, severity rationale, false-positive boundaries, authoritative mappings, and deterministic remediation where supported. Test malformed HCL, multiple resources, unknown/missing attributes, safe configurations, and edge cases. Never classify a resource from its name alone.

## Dockerfiles

Respect valid Dockerfile syntax and multi-stage semantics. Review root execution, missing final-stage `USER`, unpinned or `:latest` images, missing `HEALTHCHECK`, secrets in `ARG`/`ENV`, comments, and stage boundaries. Intermediate builder-stage root use may be informational or acceptable; do not report it as a final runtime failure when the final stage is secure.

## Kubernetes

Use the existing safe YAML parser and PodSpec traversal for `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, and `CronJob`. Inspect all containers and `initContainers` across multi-document manifests. Verify evidence for privileged containers, `hostPID`, `hostNetwork`, other host namespaces, root execution, writable root filesystems, missing resource limits, capabilities, and Pod Security Standards Restricted violations. Test malformed YAML, multiple documents, multiple containers, and negative cases. Never assume a single container.

## Secrets

Preserve both high-confidence vendor/token patterns and Shannon-entropy detection. Minimize false positives with realistic safe fixtures covering UUIDs, hashes, normal IDs, environment/config values, borderline entropy, and malformed input. Never log, return, persist, render, or send raw secrets to Ollama. Redaction must apply to logs, tests, API responses, frontend state, and AI prompts.

## Severity and compliance

Severity is deterministic and evidence-based: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`. Do not invent or let AI change it; document the rationale for rule changes.

Compliance metadata from `src/scanners/compliance_mapper.py` is authoritative. Supported mappings may include CIS AWS Foundations, CIS Docker, CIS Kubernetes, NIST SP 800-190, PCI-DSS 4.0, and PSS Restricted. Preserve exact framework/control identifiers. Never invent mappings, infer cross-framework equivalence, or turn general security advice into a compliance claim. If no mapping exists, represent that explicitly.

## Deterministic remediation

Read `src/scanners/remediation.py` before changing fixes. Remediation must remain allowlisted, exact-targeted, predictable, backup-first, and verified by an automatic rescan. It must not execute arbitrary shell commands or accept AI-generated patches. AI must never modify files, approve a fix, or establish remediation success.

## New-rule workflow

1. Inspect the scanner architecture, parser, model, mapper, remediation path, and tests.
2. Select the correct scanner and define observable positive, negative, boundary, and malformed-input behavior.
3. Add safe parser-based fixtures.
4. Implement the smallest deterministic detection change.
5. Preserve severity, finding shape, compliance mappings, and backwards compatibility.
6. Add deterministic remediation only when the existing allowlist can support it safely.
7. Add regression tests for false positives, multiple resources/documents, and parser edge cases.
8. Run focused tests, then the full relevant suite, and verify existing rules did not regress.

## Security review checklist

For every rule or scanner change, check:

- Can an attacker bypass the detection?
- Could legitimate configuration trigger a false positive?
- Is parser behavior understood and malformed input safe?
- Is severity justified by observed evidence?
- Is remediation deterministic and narrowly scoped?
- Is compliance mapping source-backed?
- Could secrets leak through output, logs, or AI?
- Could the rule introduce denial-of-service or scan-performance risk?

## AI boundary and output

AI may explain code, summarize behavior, analyze test failures, and suggest tests. It may not become the vulnerability source of truth, override severity or compliance, generate arbitrary remediation, or access secrets unnecessarily. Do not modify files while merely creating or reviewing this skill.

For a completed AntiFine security task, report what was inspected, what changed, why it is safe, false-positive considerations, tests added and run, and limitations. Keep changes minimal and repository-consistent.
