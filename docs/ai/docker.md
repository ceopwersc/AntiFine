# Docker rules

Docker analysis is implemented by `analyze_dockerfile` in
`src/scanners/iac_audit.py`. It tracks build stages and applies runtime checks
to the final stage. Intermediate-stage root use is informational rather than
treated as a runtime root finding.

| Rule ID | Finding | Severity | Detection |
| --- | --- | --- | --- |
| `docker.user-root` | `USER root` / `USER 0` in final stage | HIGH | A final-stage USER instruction selects root. |
| `docker.user-missing` | Missing USER | MEDIUM | The final stage has no USER instruction. |
| `docker.healthcheck-missing` | Missing HEALTHCHECK | LOW | The final stage has no HEALTHCHECK instruction. |
| `docker.unpinned-image` | Unpinned image tag | MEDIUM | A non-scratch FROM uses `latest` or no tag. |
| `secrets.vendor-match` | Hardcoded secret | CRITICAL | ENV or ARG values are checked for vendor signatures and keyword-based fallback. |

The scanner also checks high-entropy ENV and ARG values through
`src/scanners/secret_scanner.py`. Docker remediation supports narrowly scoped
USER and HEALTHCHECK transformations, with a backup, only when the finding
name matches an allowlisted branch.
