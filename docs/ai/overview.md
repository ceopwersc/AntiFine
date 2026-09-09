# AntiFine AI knowledge

AntiFine is a deterministic, local-first Infrastructure-as-Code scanner. The
FastAPI application in `src/api/server.py` dispatches scans to
`src/scanners/iac_audit.py`, normalizes results as the `Finding` dataclass,
maps compliance metadata, persists scan results in SQLite, and can explicitly
invoke the optional Ollama explanation endpoint.

The scan dispatcher selects analyzers by file type:

- Dockerfiles are analyzed as multi-stage instruction streams.
- Terraform is parsed with `python-hcl2`.
- Kubernetes manifests are parsed with `yaml.safe_load_all`.
- Generic configuration values are checked for secrets.

Each finding contains `rule_name`, `severity`, `filename`, `frameworks`,
`remediation`, and an optional `description`. Severity values emitted by the
scanner are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFORMATIONAL`.

Ollama receives an existing finding, bounded sanitized code context, and the
matching catalog entry from `src/ai/knowledge/rules.json`. It does not scan,
create findings, change severity or frameworks, edit files, or apply
remediation. If no catalog entry matches, the prompt explicitly says that no
matching rule metadata was supplied.

The catalog is a deterministic source for prompt context, not a vector store,
embedding index, RAG framework, or autonomous agent.
