---
name: compliance-review
description: Implement and review AntiFine compliance mappings with deterministic source data, exact controls, and evidence-based status.
---

# AntiFine compliance review

Load this skill for compliance mapping, compliance UI/reporting, compliance-related AI behavior, or tests. AntiFine is a deterministic security scanner. Existing finding metadata, deterministic scanner/rule definitions, `compliance_mapper.py`, scanner output, compliance tests, and approved AntiFine documentation are authoritative. AI suggestions are not.

## Keep these concepts separate

Never conflate:

1. **Framework mapped** — a framework is attached to a finding/rule.
2. **Control mapped** — an exact control or requirement is attached.
3. **Finding detected** — deterministic evidence triggered a finding.
4. **Compliance status** — a status explicitly produced by AntiFine.
5. **Remediation status** — whether a deterministic fix was applied and verified.

A finding mapped to CIS AWS Foundations Benchmark 5.2 with status `OPEN` does not prove that the entire framework is non-compliant. A mapping does not imply `PASS` or `FAIL` unless the repository explicitly defines that status.

## Source-of-truth workflow

Before changing behavior, inspect:

- `src/scanners/compliance_mapper.py`
- `src/scanners/iac_audit.py`
- `src/models/finding.py`
- compliance tests and rule definitions
- report and SARIF generation
- frontend representations and AI context builders where relevant

Trace the real finding metadata and scanner output. Do not assume a framework is supported or infer a mapping from general cybersecurity knowledge. Preserve actual repository semantics; do not invent `PASSED`, `FAILED`, or `UNKNOWN` statuses if they do not exist.

## Supported frameworks

AntiFine may include:

- CIS AWS Foundations Benchmark
- CIS Docker Benchmark
- CIS Kubernetes Benchmark
- NIST SP 800-190
- PCI-DSS 4.0
- PSS Restricted

Treat a framework as supported only when the repository provides evidence. Do not expand the list automatically.

## Mapping integrity

Where the implementation supports them, preserve the exact:

- framework name and version;
- control/requirement identifier;
- title and description;
- finding/rule association;
- remediation guidance;
- source/reference.

Never invent control IDs, silently drop mappings, rename frameworks inconsistently, normalize away meaningful identifiers, infer from text similarity, or create frontend-only mappings.

Never infer cross-framework equivalence. For example, CIS AWS 5.2 does not imply PCI-DSS 1.3.1, NIST, or ISO 27001 unless AntiFine explicitly defines that mapping. General security relevance is not evidence of an AntiFine mapping.

A real finding may legitimately contain multiple authoritative mappings, such as:

```text
CIS AWS Foundations Benchmark 5.2
PCI-DSS 4.0 Requirement 1.3.1
```

Preserve both when the actual rule metadata supplies both. Do not remove a valid mapping because a manually constructed test payload omitted it.

## AI and UI boundaries

Frontend compliance displays, dashboards, Finding Drawers, compliance views, SARIF, reports, and Ask AntiFine must derive from the same authoritative backend data. AI may explain supplied mappings, but must never add frameworks, controls, requirements, or compliance states.

If a finding has only `CIS AWS Foundations Benchmark 5.2` and the user asks whether it affects PCI-DSS, the assistant must say AntiFine has no supplied PCI-DSS mapping for that finding. It must not invent a PCI-DSS control. General PCI-DSS education is allowed only when clearly labeled as general guidance and not presented as an AntiFine mapping.

AntiFine must not claim “Compliant” or “Non-compliant” without deterministic evidence for that state. Prefer “Not mapped” or “Status unavailable” over guessing.

## Required change workflow

When explicitly changing compliance behavior:

1. Inspect existing mapping behavior and authoritative source.
2. Compare the proposed change with current semantics.
3. Verify every exact framework/control identifier.
4. Check missing, unknown, and false mappings.
5. Update the smallest implementation surface.
6. Preserve finding/status/remediation separation and backwards compatibility.
7. Update tests and relevant documentation, reports, SARIF, and frontend representations when applicable.
8. Run compliance tests, relevant scanner tests, report/SARIF checks, and frontend verification where affected.

## Required regression coverage

Test:

1. one framework mapping;
2. multiple framework mappings;
3. missing mapping;
4. unknown framework;
5. control-ID preservation;
6. framework-name/version preservation;
7. compliance-status preservation;
8. finding/status separation;
9. AI explanation of supplied mappings;
10. report output;
11. SARIF mapping;
12. generic security reasoning cannot create a new mapping.

Include the false-mapping regression:

```text
Finding: TF-AWS-004
Authoritative mapping: CIS AWS Foundations Benchmark 5.2
Question: "Does this affect PCI-DSS?"
Expected: no PCI-DSS mapping or control is generated.
```

Include a positive multi-mapping regression using a real rule whose metadata supplies both CIS AWS Foundations Benchmark 5.2 and PCI-DSS 4.0 Requirement 1.3.1; both must remain available for explanation and reporting.

## Output expectations

For a compliance task, report:

1. authoritative mapping source;
2. frameworks involved;
3. exact controls involved;
4. whether status is explicitly known;
5. code changed;
6. tests added;
7. tests run and results;
8. any ambiguity or unavailable evidence.

Never fill missing compliance information with a guess. The deterministic AntiFine implementation is always authoritative.
