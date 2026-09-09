# Secret detection

`src/scanners/secret_scanner.py` combines exact vendor signatures with
Shannon-entropy analysis. It scans Docker ENV/ARG values, YAML/HCL strings,
and generic key-value configuration values.

`secrets.vendor-match` is `CRITICAL` and covers AWS access keys and secret
keys, GitHub tokens, Slack tokens, and private-key markers. Its mapped
frameworks include CIS Docker Benchmark 4.7, CWE-798, ISO 27001 A.8.24, and
NIST SP 800-190 §3.3.1.

`secrets.entropy` is `HIGH`. Values must be at least 16 characters and meet a
charset-dependent Shannon threshold: 3.0 for pure hex and 4.2 otherwise.
UUIDs, 40/64-character pure hex hashes, and values containing both `/` and `.`
are allowlisted as likely non-secrets.

The explanation flow redacts vendor tokens, private key blocks, and common
credential assignments before sending context or finding text to Ollama.
Raw secret values are not loaded by the knowledge service.
