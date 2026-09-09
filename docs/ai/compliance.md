# Compliance mappings

`src/scanners/compliance_mapper.py` contains an ordered, first-match-wins
mapping table. It maps raw vulnerability text to a primary framework, a full
framework cross-walk, a description, and remediation guidance. When no entry
matches, it returns `Unmapped`, preserves the input as the description, and
returns manual-review guidance.

Scanner findings also carry direct framework lists. The AI prompt must treat
those supplied finding frameworks as authoritative and discuss no framework
that AntiFine did not provide. Catalog framework values are supporting
metadata for a matched rule, not permission to invent a mapping for an
unmatched finding.

Known mapping families include Docker CIS/NIST/PCI controls, Kubernetes CIS,
PSS and NIST controls, AWS Foundations controls for Terraform, secret
handling controls, and OWASP/CWE mappings for the SSRF scanner.
