# AntiFine Agent Handoff & Rules

## Project State & Architecture
If you need to understand the codebase, the scanner logic (Dockerfile, Kubernetes, Secrets, Terraform), or the CI/CD gating CLI, please load and read the `antifine-architecture` skill. 

## Maintenance Rules
1. **Update CLAUDE.md**: After completing any task, ALWAYS update the `CLAUDE.md` file in the root directory to log the latest changes under the "Project History / Recent Updates" section.
2. **Update Architecture Skill**: If you add new scanners, alter the core logic in `iac_audit.py`, change return types, or significantly modify the pipeline, you MUST update `.agents/skills/antifine-architecture/SKILL.md` to reflect these changes so future agents have up-to-date knowledge.
3. **Commit Behavior**: After successfully testing your changes, auto-commit them. Do NOT use `git add .` - only add the specific files you changed. Do NOT commit configuration files, `.env` files, or local database states unless explicitly authorized.
