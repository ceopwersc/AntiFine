# AntiFine Agent Handoff & Rules

## Project State & Architecture
If you need to understand the codebase, the scanner logic (Dockerfile, Kubernetes, Secrets, Terraform), or the CI/CD gating CLI, please load and read the `antifine-architecture` skill. 

## Maintenance Rules
1. **Update Architecture Skill**: If you add new scanners, alter the core logic in `iac_audit.py`, change return types, or significantly modify the pipeline, you MUST update `.agents/skills/antifine-architecture/SKILL.md` to reflect these changes so future agents have up-to-date knowledge.
2. **Commit Behavior**: After successfully testing your changes, auto-commit them. Do NOT use `git add .` - only add the specific files you changed.
3. **No Unintentional Commits**: NEVER commit configuration files, `.env` files, or local database states unless explicitly authorized.

## Coding Standards
- Write modular, decoupled code. Scanners must not depend on the reporting engine.
- All Python code must include type hints and basic error handling.
- Focus strictly on defensive auditing: reading configurations, verifying access controls, and mapping open ports.

## Project History / Recent Updates
- **Phase 1**: Implemented `src/scanners/secret_scanner.py` with high-confidence vendor regexes (AWS, GitHub, Slack) and charset-adjusted Shannon entropy for FP reduction.
- **Phase 2 & 3**: Refactored `analyze_kubernetes` in `iac_audit.py` to use structured `PyYAML` parsing for multi-document manifests. Enforced Kubernetes PSS Restricted rules. Updated CLI gate and `run_iac_audit` to handle mixed-type findings cleanly.
