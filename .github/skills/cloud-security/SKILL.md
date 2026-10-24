---
name: cloud-security
description: Review AntiFine cloud and Terraform security analysis while preserving deterministic provider-specific rules and evidence.
---

# AntiFine cloud security

Load this skill for cloud/IaC security work, especially Terraform AWS rules. Inspect `src/scanners/iac_audit.py`, `src/scanners/compliance_mapper.py`, `src/models/finding.py`, remediation code, and tests.

- Use structural HCL parsing and real resource attributes; never infer exposure from variable names or general cloud knowledge.
- Verify evidence for public SSH/RDP, dangerous `0.0.0.0/0` or `::/0` ingress, public databases, S3 encryption, S3 public-access blocks, and public resource exposure.
- Preserve exact deterministic severity, rule names, compliance mappings, and affected ports/resources.
- Distinguish observed configuration from recommendation and from compliance status; a mapping is not proof of compliance.
- Test safe configurations, malformed HCL, missing/unknown attributes, multiple resources, and false-positive boundaries.
- Keep remediation backup-first, allowlisted, deterministic, and followed by a rescan. AI/Ollama is advisory and never authoritative.
