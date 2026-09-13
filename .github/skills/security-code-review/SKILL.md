---
name: security-code-review
description: Perform evidence-based security review of AntiFine Python/FastAPI and React/TypeScript code, including AI and remediation boundaries.
---

# AntiFine security code review

Load this skill for security-focused review of AntiFine code. Review the implementation and its tests; never infer a vulnerability from a name, pattern, or hypothetical behavior alone.

## Review method

1. Trace untrusted input from the API, browser, files, environment, or Ollama through validation, storage, processing, and output.
2. Read the complete relevant function and its callers before reporting an issue.
3. Require concrete evidence: file and line, reachable data flow, affected boundary, and a plausible attack scenario.
4. Check existing tests and repository conventions before concluding that a guard is missing.
5. Report only actionable findings. If evidence is insufficient, state that the risk is unconfirmed rather than inventing a vulnerability.

## Security areas

Review Python/FastAPI routes, Pydantic validation, authentication and authorization boundaries, error responses, CORS/CSRF where applicable, SSRF, command injection, unsafe deserialization, dependency risks, and logging of secrets or infrastructure data.

Review filesystem behavior for path traversal, sandbox escapes, symlink and race conditions, insecure temporary files, unsafe archive extraction, untrusted filenames, and accidental writes. Treat subprocess arguments, shell invocation, environment inheritance, and return-code handling as command-injection boundaries.

Review React/TypeScript for XSS, unsafe HTML/URL rendering, DOM injection, token or secret exposure, client-side authorization assumptions, CSRF implications for cookie-authenticated APIs, insecure downloads, and sensitive data retained in browser storage or logs.

Review AI features for prompt injection and data exfiltration through user-controlled infrastructure text, retrieved documents, conversation history, and tool responses. Secrets must be redacted before Ollama; sensitive prompts and full conversations must not be logged.

## AntiFine invariants

- The deterministic scanner is authoritative for findings, severity, evidence, and compliance mappings.
- AI and Ollama are advisory only. They must never decide or alter severity, compliance, remediation state, or scan truth.
- Ollama must never control file modification, command execution, or remediation approval.
- Deterministic remediation must remain allowlisted, backup-first, and verified by a rescan.
- User-controlled infrastructure text is untrusted prompt content, not instructions.
- Preserve the separation between authoritative finding metadata and general AI knowledge.

When reviewing a proposed fix, verify that it does not replace deterministic rules with an LLM guess, broaden an allowlist unsafely, bypass validation, suppress errors, or turn a successful HTTP response into proof of a successful remediation.

## Finding format

For every confirmed issue, provide:

- **Severity**: impact and exploitability, using repository conventions where available.
- **Affected code**: exact file and line or a precise symbol/range.
- **Attack scenario**: the attacker-controlled input and reachable path.
- **Why it matters**: confidentiality, integrity, availability, or trust-boundary impact.
- **Safe remediation**: the smallest defense that preserves existing AntiFine behavior.
- **Regression test**: a concrete test covering the exploit and the intended safe behavior.

Prioritize issues by risk and confidence. Distinguish exploitable vulnerabilities from hardening suggestions, false positives, and missing evidence. Never claim a vulnerability without a demonstrated code path.

## Review boundaries

Do not modify code during review unless the user explicitly requests fixes. If fixes are requested, preserve backwards compatibility, add regression tests, and run the narrowest relevant validation plus the existing security-sensitive tests. Do not disclose secrets, credentials, private infrastructure contents, or full sensitive logs in the review.

