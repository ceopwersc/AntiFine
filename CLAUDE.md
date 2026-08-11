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
- After successfully completing a build step or fixing a bug, and ensuring all tests pass, you MUST automatically commit and push the code to GitHub.
- Use the following commands:
  1. `git add .`
  2. `git commit -m "Auto-commit: [Brief description of what you just built]"`
  3. `git push origin main`
