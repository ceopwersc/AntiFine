"""Tests for Terraform IaC auditor."""

from src.scanners.iac_audit import analyze_terraform

def test_analyze_terraform_public_acl():
    content = """resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "public-read"
}"""
    findings = analyze_terraform(content, "s3.tf")
    assert len(findings) == 1
    assert "Insecure S3 Bucket ACL (Public)" in findings[0].rule_name
    assert findings[0].severity == "HIGH"
    
def test_analyze_terraform_public_read_write_acl():
    content = """resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "public-read-write"
}"""
    findings = analyze_terraform(content, "s3.tf")
    assert len(findings) == 1
    assert "Insecure S3 Bucket ACL (Public)" in findings[0].rule_name
    assert findings[0].severity == "HIGH"

def test_analyze_terraform_private_acl():
    content = """resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"
}"""
    findings = analyze_terraform(content, "s3.tf")
    assert len(findings) == 0
