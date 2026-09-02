# AntiFine

**AntiFine** is a modern, automated Security, Compliance, and Infrastructure-as-Code (IaC) auditing framework. It acts as a defensive guardrail for development teams by statically analyzing infrastructure configurations, enforcing strict security postures, and preventing critical misconfigurations or secrets from ever reaching production.

It is designed to be deeply integrated into CI/CD pipelines (acting as an automated deployment gate) while also providing a rich API and dashboard for historical compliance tracking.

---

## Core Capabilities

### 1. Advanced Infrastructure Auditing
AntiFine includes highly specialized scanners tailored for modern cloud-native environments:
* **Kubernetes (PSS Enforcement)**: It structurally parses multi-document Kubernetes YAML manifests and strictly enforces the **Pod Security Standards (PSS) Restricted Profile**. It flags critical violations like containers running in privileged mode, host namespace sharing (`hostPID`/`hostNetwork`), missing read-only root filesystems, dangerous Linux capabilities (`CAP_SYS_ADMIN`), missing `runAsNonRoot`, and privilege escalation.
* **Docker / Container Security**: It features **multi-stage build awareness**. It understands the difference between build-time compilation environments and the final runtime image—intelligently allowing `USER root` for package installations in early stages, but strictly forbidding it in the final production container layer. It also enforces health checks and image pinning.
* **Secret Detection Engine**: It scans configuration files (`.env`, `.json`, `.conf`, and Kubernetes YAMLs) for hardcoded credentials. It combines high-confidence vendor regexes (AWS, GitHub, Slack) with a highly tuned, character-set adjusted **Shannon Entropy filter** to drastically reduce false positives (intelligently ignoring things like Git SHAs or UUIDs).
* **Terraform Security**: Scans Terraform (`.tf`) for insecure AWS configurations (e.g. public S3 bucket ACLs) and embedded secrets.
* **SSRF Auditing**: Capable of auditing web targets for Server-Side Request Forgery vulnerabilities.

### 2. Automated CI/CD Gating & Integration
* **Headless CLI Gate**: AntiFine is built to run headlessly in CI/CD environments (like GitHub Actions). By running a command like `python -m src.cli.gate --fail-on HIGH`, AntiFine acts as a strict deployment gate, instantly breaking the build if any configuration violates the required severity threshold.
* **SARIF Export**: It natively translates findings into the **OASIS SARIF v2.1.0** standard, allowing immediate and seamless integration with native GitHub Security Code Scanning alerts.
* **SOC Dispatching**: It supports webhook integrations to instantly dispatch critical security alerts to a Security Operations Center (SOC) or incident response channel.

### 3. Compliance Mapping & Remediation
AntiFine doesn't just throw errors—it contextualizes them.
* Every finding is automatically mapped against industry-standard frameworks such as the **CIS Benchmarks** and **NIST SP 800-190**.
* It acts as a knowledge base, attaching direct, actionable **remediation guidance** to every alert so developers know exactly how to fix the issue without needing to become security experts.

### 4. System Architecture
* **The Engine**: A heavily decoupled Python 3 backend using FastAPI to expose scanning, analytics, and reporting capabilities via a REST API.
* **The Interface**: A modern React/Vite frontend for visualizing compliance score gauges, historical severity trends, and managing integrations.
* **The Storage**: A localized SQLite database for fast, private, and persistent audit logging and historical trend analysis.

---

## Installation

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** (for frontend UI)

### Backend Setup
```bash
# Clone the repository
git clone https://github.com/ceopwersc/AntiFine.git
cd AntiFine

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Frontend Setup
```bash
cd frontend
npm install
```

---

## Usage

### Headless CI/CD Gate
To scan a specific file or directory and block a build pipeline:
```bash
python -m src.cli.gate --file path/to/target --fail-on HIGH
```
You can also supply a `--min-score` to fail the build if the weighted compliance score drops below a certain threshold.

### Running the API Server
Start the FastAPI backend to use the UI or API endpoints:
```bash
python src/api/server.py
```
The API will be available at `http://localhost:8000/docs`.

### Running the Frontend UI
To start the React dashboard in development mode:
```bash
cd frontend
npm run dev
```
Visit `http://localhost:5173` to see compliance dashboards, run scans, and generate reports.

### GUI Testing
To run the Desktop CustomTkinter interface (Optional):
```bash
pip install -r requirements-gui.txt
python src/main.py --gui
```

---

## Running Tests
Run the test suite using pytest:
```bash
python -m pytest tests/ -v
```
