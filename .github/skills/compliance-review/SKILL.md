---
name: compliance-review
description: Review AntiFine compliance mappings and claims using deterministic rule metadata, exact controls, and evidence-based status.
---

# AntiFine compliance review

Load this skill for compliance analysis, mapping changes, or compliance-related AI behavior in AntiFine. Deterministic AntiFine mappings are authoritative; general security knowledge and retrieved framework documentation must not create a new finding mapping.

## Authoritative frameworks

AntiFine currently maps findings to:

- CIS AWS Foundations Benchmark
- CIS Docker Benchmark
- CIS Kubernetes Benchmark
- NIST SP 800-190
- PCI-DSS 4.0
- PSS Restricted

Verify the actual framework name and exact control identifier from the finding/rule metadata. Do not normalize away meaningful version, section, or requirement details.

## Required review method

1. Inspect `src/scanners/compliance_mapper.py` and the scanner rule that produces the finding.
2. Trace the real `Finding` data in `src/models/finding.py` and relevant API/AI context builders.
3. Confirm each reported framework and control is explicitly supplied by deterministic AntiFine metadata.
4. Distinguish evidence, mapping, and status:
   - **Mapped** means AntiFine attaches the framework/control to the finding.
   - **Compliant/passed** requires deterministic evidence that the applicable control is satisfied.
   - A security recommendation or general framework explanation is neither a mapping nor proof of compliance.
5. If a framework is absent, report that AntiFine has no supplied mapping. Do not invent control numbers, control names, equivalence, or framework-specific claims.

## Hard rules

- Never invent framework mappings.
- Never infer cross-framework equivalence.
- Never claim a control passed without evidence from the scanner or an authoritative verification result.
- Never turn general security guidance or retrieved compliance documents into a finding-specific mapping.
- Preserve exact identifiers, versions, and sections.
- For contextual AI questions, deterministic finding metadata is the allowlist for finding-specific compliance claims.
- Keep AI advisory. It may explain a supplied mapping, but it cannot alter severity, compliance state, or remediation state.

## Changing compliance logic

When explicitly asked to modify compliance behavior:

- make the smallest change in the deterministic mapper/rule metadata;
- preserve backwards compatibility and existing `Finding` contracts;
- update focused tests for unmapped frameworks, missing mappings, and findings with multiple framework mappings;
- test exact control identifiers and versioned names;
- test that generic documentation cannot create an unauthorized mapping;
- test malformed or incomplete metadata where relevant;
- run the relevant scanner, mapper, API, and AI compliance tests.

Reference files:

- `src/scanners/compliance_mapper.py`
- `src/scanners/iac_audit.py`
- `src/models/finding.py`
- `src/ai/context_builder.py`
- `src/ai/retriever.py`
- `tests/`

