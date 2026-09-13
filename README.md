# AntiFine

**Local security engineering for infrastructure-as-code.**

AntiFine scans Terraform, Dockerfiles, and Kubernetes YAML before deployment, maps deterministic findings to supported compliance frameworks, and gives engineers a reviewable path from **finding → code → remediation → rescan**.

Everything important stays local:

```text
FastAPI · 127.0.0.1:8000    React/Vite · 127.0.0.1:5173    Ollama · optional
```

> AntiFine is deterministic first. The scanner decides what was found, its severity, and its compliance metadata. Local AI can explain an existing finding, but it cannot create findings, change severity, modify files, or approve a fix.

## What AntiFine does

| Surface | Coverage |
| --- | --- |
| **Terraform** | Public SSH/RDP and permissive ingress, public databases, S3 encryption, S3 public-access blocks, and public exposure |
| **Dockerfiles** | Root/final-stage user checks, image pinning, `HEALTHCHECK`, secrets in `ENV`, and multi-stage build awareness |
| **Kubernetes** | Privileged containers, host namespaces, non-root execution, writable root filesystems, resource limits, capabilities, and PSS Restricted |
| **Secrets** | High-confidence AWS, GitHub, Slack, private-key, credential, and entropy-based detection with redaction |
| **Compliance** | CIS AWS Foundations, CIS Docker, CIS Kubernetes, NIST SP 800-190, PCI-DSS 4.0, and PSS Restricted |
| **Remediation** | Small allowlisted Terraform, Dockerfile, and Kubernetes transformations with backup-first writes and deterministic rescan verification |
| **Delivery** | FastAPI endpoints, React workstation UI, CLI gating, SARIF export, reports, and optional webhooks |

## The engineering workflow

```text
Scan
  ↓
Finding
  ↓
Finding Drawer → Code / Rule / Compliance
  ↓
Review deterministic fix
  ↓
Diff → Apply → Backup → Rescan
  ↓
Verified only when no finding remains
```

The UI is intentionally dense: rule IDs, file paths, line numbers, code context, framework mappings, deterministic diffs, scan output, and operational state take priority over decorative analytics.

## Quick start

### Requirements

- Python 3.10+
- Node.js 18+
- Optional: [Ollama](https://ollama.com/) for local explanations and Ask AntiFine

### Install

```bash
git clone https://github.com/ceopwersc/AntiFine.git
cd AntiFine

python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt

cd frontend
npm install
cd ..
```

### Run the local workspace

Start the backend from the repository root:

```bash
python -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```bash
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

Open:

- UI: <http://127.0.0.1:5173>
- API docs: <http://127.0.0.1:8000/docs>
- AI health: <http://127.0.0.1:8000/api/ai/health>

The scanner API accepts a **server-local path**. A path must resolve inside AntiFine's backend project root; the API does not treat a browser upload as a remote file-write mechanism.

## Scan from the CLI

Use the headless gate in CI or pre-deployment checks:

```bash
python -m src.cli.gate --file path/to/target --fail-on HIGH
```

The gate exits non-zero when the configured severity threshold is met. Use the CLI against a file or directory supported by the deterministic IaC scanner.

## Scan through the API

Terraform, Dockerfile, and Kubernetes scanning uses the existing `/api/scan/iac` contract:

```bash
curl -X POST http://127.0.0.1:8000/api/scan/iac \
  -H "Content-Type: application/json" \
  -d '{"target_path":"path/to/infrastructure.tf"}'
```

The response contains the scan status, resolved target, finding count, normalized findings, frameworks, descriptions, and remediation guidance. Findings are persisted locally for the existing reporting and dashboard workflows.

## Deterministic remediation

The only file-writing path is the deterministic remediation engine:

```text
POST /api/scan/iac/remediate
```

It:

1. resolves and sandboxes the target path;
2. rejects unsupported rules or unsafe targets;
3. creates `<target>.bak` before writing;
4. applies a narrow allowlisted transformation;
5. rescans the target;
6. returns the backup path, action, remaining finding count, and remaining findings.

The frontend marks a finding **Fixed** only when the verification response reports `findings_count == 0`. A successful HTTP response by itself is not proof of remediation.

## Compliance model

AntiFine separates three concepts:

- **Observed evidence** — what the deterministic scanner found in the source.
- **Authoritative mapping** — frameworks and controls explicitly attached by AntiFine rule metadata.
- **Compliance status** — whether deterministic evidence supports a control as satisfied.

A framework mentioned by a user or found in general documentation does not create a finding mapping. If a requested framework is absent from the authoritative metadata, AntiFine reports that no supplied mapping is available rather than inventing a control or cross-framework equivalence.

## Optional local AI

Ollama is optional and is not part of scanning, compliance mapping, remediation, or CI gating.

Create a local `.env` from `.env.example`, or set process environment variables:

```bash
OLLAMA_ENABLED=true
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:7b
OLLAMA_TIMEOUT=30
```

Then:

```bash
ollama serve
ollama pull qwen2.5:7b
```

Check availability without exposing credentials:

```bash
curl http://127.0.0.1:8000/api/ai/health

curl -X POST http://127.0.0.1:8000/api/ai/test \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Explain Terraform in one sentence."}'
```

### Finding explanations

The finding explanation workflow accepts an existing deterministic finding. It does not detect new issues, change severity or compliance, edit files, or apply remediation. Secret-like values are redacted and code context is bounded before local generation.

The React finding drawer exposes this as **Explain with Local AI**. Results are advisory, session-scoped, and separate from the deterministic finding state.

### Ask AntiFine and local retrieval

Ask AntiFine uses bounded conversation history and deterministic lexical retrieval over the local rule catalog and `docs/ai/`. It does not use hosted RAG, a cloud API, embeddings, or a vector database.

```bash
curl -X POST http://127.0.0.1:8000/api/ai/ask \
  -H "Content-Type: application/json" \
  -d '{"question":"How does AntiFine detect high entropy secrets?"}'
```

Finding-aware questions can include structured context:

```json
{
  "question": "Why is this finding critical?",
  "context": {
    "source": "finding",
    "finding": {
      "rule_id": "TF-AWS-004",
      "title": "Security group exposes SSH to the internet",
      "severity": "CRITICAL",
      "technology": "terraform",
      "file": "main.tf",
      "line": 42,
      "frameworks": ["CIS AWS Foundations Benchmark 5.2"],
      "status": "open"
    }
  },
  "messages": [
    {
      "role": "user",
      "content": "Why is this finding critical?"
    },
    {
      "role": "assistant",
      "content": "The deterministic scanner found public SSH ingress..."
    }
  ]
}
```

Conversation history is request-supplied, bounded, and not persisted as permanent memory. Rebuild the local knowledge index after changing AI documentation:

```bash
python -m src.cli.ai rebuild-index
```

## Reports and integrations

- SARIF export for GitHub Code Scanning and CI ingestion
- Markdown report generation
- Local SQLite scan history
- Optional webhook dispatch for configured severity thresholds
- Optional CustomTkinter desktop entry point:

  ```bash
  pip install -r requirements-gui.txt
  python src/main.py --gui
  ```

## Development validation

Backend tests:

```bash
python -m pytest -q
```

Frontend build and lint:

```bash
cd frontend
npm run build
npm run lint
```

UI functionality is verified with Playwright against the running local services. Critical coverage includes:

```text
Scan → Finding → Drawer → Review Fix → Diff → Apply → Rescan → Verified
Finding → Ask AntiFine → Ollama → explanation
Compliance → related finding → remediation
```

Use temporary fixtures without real secrets. Collect console errors and failed network requests, and verify resulting state rather than only checking that controls render.

## Project boundaries

AntiFine intentionally does **not**:

- send infrastructure secrets to hosted services;
- let Ollama modify files or execute commands;
- use AI to decide findings, severity, compliance, or remediation success;
- claim compliance from general security relevance;
- persist permanent AI conversation memory;
- replace deterministic scanner rules with model guesses.

## Repository map

```text
src/api/                 FastAPI routes and API contracts
src/scanners/            Deterministic IaC, secret, and remediation logic
src/models/finding.py    Shared finding model
src/ai/                  Local retrieval and constrained prompt context
src/services/            Ollama and explanation services
src/cli/                 CI gate and knowledge-index commands
frontend/                React/Vite local security workstation
docs/ai/                 Local AntiFine knowledge documentation
tests/                   Focused backend and AI regression tests
.github/skills/          Project guidance for security and E2E work
```

## License

See the repository license file for terms.
