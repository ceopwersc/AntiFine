"""Tests for the IaC auditor."""

from pathlib import Path
from src.scanners.iac_audit import analyze_dockerfile, analyze_kubernetes, run_iac_audit

def test_analyze_dockerfile_missing_user():
    content = """FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
CMD ["curl", "-h"]"""
    findings = analyze_dockerfile(content, "Dockerfile")
    assert any("Missing USER" in f[0] for f in findings)
    assert any(f[1] == "MEDIUM" for f in findings)
    assert any("Missing HEALTHCHECK" in f[0] for f in findings)
    
def test_analyze_dockerfile_user_root():
    content = """FROM ubuntu:latest
USER root
CMD ["bash"]"""
    findings = analyze_dockerfile(content, "Dockerfile")
    assert any("USER root" in f[0] for f in findings)
    assert any(f[1] == "MEDIUM" for f in findings)
    
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
    assert any("privileged: true" in f[0] for f in findings)
    assert any(f[1] == "HIGH" for f in findings)
    
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
    assert any("Missing resource limits" in f[0] for f in findings)
    assert any(f[1] == "MEDIUM" for f in findings)

def test_run_iac_audit_dry_run(tmp_path):
    target_dir = tmp_path / "iac_test"
    target_dir.mkdir()
    
    dockerfile = target_dir / "Dockerfile"
    dockerfile.write_text("FROM alpine:latest\n")
    
    findings = run_iac_audit(str(target_dir), persist=False)
    
    assert len(findings) > 0
    assert any("Missing USER" in f[0] for f in findings)
