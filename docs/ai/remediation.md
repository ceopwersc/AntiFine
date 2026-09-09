# Remediation behavior

Deterministic remediation is implemented in
`src/scanners/remediation.py` and exposed by
`POST /api/scan/iac/remediate`. The API first resolves a project-relative
target under the backend project root, then applies one allowlisted
transformation and re-scans the file. Absolute paths and traversal outside
the project root are rejected.

Supported transformations are:

- Set `publicly_accessible = true` to false.
- Set Kubernetes `privileged: true` to false.
- Set `allowPrivilegeEscalation: true` to false.
- Replace final-stage Docker `USER root` or `USER 0` with `USER appuser`.
- Insert a final-stage non-root USER when the finding is missing USER.
- Add a Docker HEALTHCHECK when the finding is missing HEALTHCHECK.

Each successful change creates a sibling `.bak` backup and returns the action,
backup path, and post-remediation findings. Unsupported findings raise a
remediation error; Ollama never chooses, applies, or claims these changes.
