---
name: secret-security
description: Review AntiFine secret detection, redaction, logging, storage, and local AI data boundaries.
---

# AntiFine secret security

Load this skill for secret scanning or secret-handling work. Treat credentials, tokens, keys, private-key material, infrastructure values, and user-provided configuration as sensitive.

- Inspect `src/scanners/secret_scanner.py` and all callers before changing detection.
- Require evidence for a secret finding and preserve deterministic severity and scanner behavior.
- Test vendor patterns, credential assignments, private keys, entropy cases, benign UUIDs/hashes, malformed input, and false positives.
- Redact secrets before Ollama, logs, reports, browser output, tests, and error messages. Never persist or echo raw secrets.
- Prefer environment/runtime secret injection over baking values into images or files.
- Do not weaken patterns, suppress errors, or treat AI output as secret-detection authority.
- For fixes, preserve deterministic remediation and add regression coverage for both exposure and safe non-detection.
