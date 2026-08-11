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
