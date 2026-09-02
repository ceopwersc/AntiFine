# AntiFine: Automated Security & Compliance Framework
## Architecture
- **Core Orchestrator:** Python 3.
- **System Execution:** Bash scripts for raw environment queries.
- **Storage:** SQLite for localized audit logging and compliance tracking.
## Coding Standards
- Write modular, decoupled code. Scanners must not depend on the reporting engine.
- All Python code must include type hints and basic error handling.
- Focus strictly on defensive auditing: reading configurations, verifying access controls, and mapping open ports.
## Commands
- `run-tests`: `pytest tests/`
- `init-db`: `python3 database/setup.py`
## Version Control Rules
- After successfully completing a build step and ensuring all tests pass, commit your work automatically, but DO NOT use `git add .`.
- Only add the specific files you explicitly created or modified during that step (e.g., `git add src/main.py tests/test_main.py`).
- Use a descriptive commit message: `git commit -m "Auto-commit: [Specific description]"`
- Push to the repository: `git push origin main`
- NEVER commit configuration files, `.env` files, or local database states unless I explicitly authorize it.

## Project History / Recent Updates
- **Phase 1**: Implemented `src/scanners/secret_scanner.py` with high-confidence vendor regexes (AWS, GitHub, Slack) and charset-adjusted Shannon entropy for FP reduction. Integrated into `iac_audit.py`.
- **Phase 2 & 3**: Refactored `analyze_kubernetes` in `iac_audit.py` to use structured `PyYAML` parsing for multi-document manifests. Enforced Kubernetes PSS Restricted rules (Host Namespace, Privileged, Read-Only FS, Capabilities, Resource Limits). Updated CLI gate and `run_iac_audit` to handle mixed-type (tuple and dictionary) findings cleanly.
