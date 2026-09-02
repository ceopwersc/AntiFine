"""Tests for the IaC auditor."""

from pathlib import Path
from src.scanners.iac_audit import analyze_dockerfile, analyze_kubernetes, run_iac_audit

def test_analyze_dockerfile_missing_user():
    content = """FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
CMD ["curl", "-h"]"""
    findings = analyze_dockerfile(content, "Dockerfile")
    assert any("Missing USER" in f.rule_name for f in findings)
    assert any(f.severity == "MEDIUM" for f in findings)
    assert any("Missing HEALTHCHECK" in f.rule_name for f in findings)
    
def test_analyze_dockerfile_user_root():
    content = """FROM ubuntu:latest
USER root
CMD ["bash"]"""
    findings = analyze_dockerfile(content, "Dockerfile")
    assert any("USER root" in f.rule_name for f in findings)
    assert any(f.severity == "HIGH" for f in findings)
    
def test_analyze_kubernetes_privileged():
    content = """apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: myapp
    image: myapp:latest
    securityContext:
      privileged: true"""
    findings = analyze_kubernetes(content, "pod.yaml")
    assert any("Privileged Container" in f.rule_name for f in findings)
    assert any(f.severity == "CRITICAL" for f in findings)
    
def test_analyze_kubernetes_missing_resources():
    content = """apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: myapp
    image: myapp:latest"""
    findings = analyze_kubernetes(content, "pod.yaml")
    assert any("Missing Resource Limits" in f.rule_name for f in findings)
    assert any(f.severity == "MEDIUM" for f in findings)

def test_analyze_kubernetes_malformed_yaml():
    """Malformed YAML must return a CRITICAL parse error, not silently pass."""
    content = """apiVersion: v1
kind: Pod
  name: broken  # bad indentation
    - invalid: ["""
    findings = analyze_kubernetes(content, "bad.yaml")
    assert len(findings) > 0
    assert any("YAML Parse Error" in f.rule_name for f in findings)
    assert any(f.severity == "CRITICAL" for f in findings)

def test_analyze_kubernetes_privilege_escalation():
    """allowPrivilegeEscalation must be explicitly false."""
    content = """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: myapp
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: true"""
    findings = analyze_kubernetes(content, "pod.yaml")
    assert any("Privilege Escalation" in f.rule_name for f in findings)

def test_analyze_kubernetes_run_as_non_root():
    """runAsNonRoot must be true."""
    content = """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: myapp
    image: myapp:latest
    securityContext:
      runAsNonRoot: false"""
    findings = analyze_kubernetes(content, "pod.yaml")
    assert any("May Run As Root" in f.rule_name for f in findings)

def test_analyze_kubernetes_dangerous_capabilities():
    """Adding SYS_ADMIN must be flagged."""
    content = """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: myapp
    image: myapp:latest
    securityContext:
      capabilities:
        add:
        - SYS_ADMIN
        - NET_ADMIN"""
    findings = analyze_kubernetes(content, "pod.yaml")
    assert any("Dangerous Capabilities" in f.rule_name for f in findings)

def test_analyze_kubernetes_init_containers():
    """initContainers must be scanned too."""
    content = """apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  initContainers:
  - name: init
    image: busybox:latest
    securityContext:
      privileged: true
  containers:
  - name: myapp
    image: myapp:latest"""
    findings = analyze_kubernetes(content, "pod.yaml")
    assert any("Privileged Container" in f.rule_name and "init" in f.rule_name for f in findings)

def test_run_iac_audit_dry_run(tmp_path):
    target_dir = tmp_path / "iac_test"
    target_dir.mkdir()
    
    dockerfile = target_dir / "Dockerfile"
    dockerfile.write_text("FROM alpine:latest\n")
    
    findings = run_iac_audit(str(target_dir), persist=False)
    
    assert len(findings) > 0
    assert any("Missing USER" in f.rule_name for f in findings)

def test_run_iac_audit_excludes_venv(tmp_path):
    """Files inside excluded directories like .venv must be skipped."""
    target_dir = tmp_path / "project"
    target_dir.mkdir()
    venv_dir = target_dir / ".venv" / "lib"
    venv_dir.mkdir(parents=True)
    
    # Put a Dockerfile in .venv — it should be ignored
    (venv_dir / "Dockerfile").write_text("FROM ubuntu:latest\nUSER root\n")
    
    # Put a clean Dockerfile at the project root
    (target_dir / "Dockerfile").write_text("FROM alpine:3.18\nUSER nobody\nHEALTHCHECK CMD true\n")
    
    findings = run_iac_audit(str(target_dir), persist=False)
    # Should NOT contain any USER root finding from the .venv Dockerfile
    assert not any("USER root" in f.rule_name and f.severity == "HIGH" for f in findings)
