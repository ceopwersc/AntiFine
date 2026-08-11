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
