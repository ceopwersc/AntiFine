# AntiFine Copilot Instructions

Read `DESIGN.md` before modifying frontend UI.

AntiFine is a local-first security engineering product.

Architecture:

- FastAPI backend
- React/Vite frontend
- SQLite persistence
- deterministic security engine
- optional local Ollama AI

Rules:

1. Deterministic scanner results are authoritative.
2. AI is advisory only.
3. Never let AI modify files or execute commands.
4. Never invent security findings, severity, compliance mappings, or remediation results.
5. Never expose raw secrets to logs or Ollama.
6. Preserve existing API contracts unless a migration is explicitly required.
7. Run relevant tests after changes.
8. Use Playwright for UI functionality verification.
9. Follow `DESIGN.md` for all frontend design decisions.
10. Prefer small, testable changes over broad rewrites.

Read the relevant skill under `.github/skills/` before security, IaC, compliance, secret, Kubernetes, cloud, or browser E2E work. Inspect real source and tests before changing behavior. Preserve backwards compatibility and do not modify files unless explicitly asked.
