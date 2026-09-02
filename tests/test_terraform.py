"""Tests for Terraform IaC auditor."""

from src.scanners.iac_audit import analyze_terraform

def test_analyze_terraform_open_ingress():
    content = """
resource "aws_security_group" "bad_sg" {
  name = "bad_sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
    findings = analyze_terraform(content, "sg.tf")
    assert len(findings) == 1
    assert "Open Ingress Port (22-22) to 0.0.0.0/0" in findings[0].rule_name
    assert findings[0].severity == "CRITICAL"
    
def test_analyze_terraform_open_ingress_rule():
    content = """
resource "aws_security_group_rule" "bad_rule" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = ["::/0"]
  security_group_id = "sg-12345"
}
"""
    findings = analyze_terraform(content, "sg_rule.tf")
    assert len(findings) == 1
    assert "Open Ingress Port" in findings[0].rule_name
    assert findings[0].severity == "CRITICAL"

def test_analyze_terraform_db_publicly_accessible():
    content = """
resource "aws_db_instance" "default" {
  allocated_storage    = 10
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  publicly_accessible  = true
}
"""
    findings = analyze_terraform(content, "db.tf")
    assert len(findings) == 1
    assert "Publicly Accessible Database" in findings[0].rule_name
    assert findings[0].severity == "CRITICAL"

def test_analyze_terraform_s3_encryption_and_pab_missing():
    content = """
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-tf-test-bucket"
}
"""
    findings = analyze_terraform(content, "s3.tf")
    assert len(findings) == 2
    rule_names = [f.rule_name for f in findings]
    assert any("Unencrypted S3 Storage" in r for r in rule_names)
    assert any("S3 Public Access Block Missing" in r for r in rule_names)

def test_analyze_terraform_s3_encryption_and_pab_present():
    content = """
resource "aws_s3_bucket" "good_bucket" {
  bucket = "my-tf-test-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "good_sse" {
  bucket = aws_s3_bucket.good_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "good_pab" {
  bucket = aws_s3_bucket.good_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""
    findings = analyze_terraform(content, "s3_good.tf")
    assert len(findings) == 0

def test_analyze_terraform_s3_embedded_encryption():
    content = """
resource "aws_s3_bucket" "good_bucket" {
  bucket = "my-tf-test-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
"""
    findings = analyze_terraform(content, "s3_good.tf")
    # Missing PAB, but has embedded SSE
    assert len(findings) == 1
    assert "S3 Public Access Block Missing" in findings[0].rule_name

def test_analyze_terraform_hcl_error():
    content = """
resource "aws_s3_bucket" "bad_syntax" {
  bucket = "my-tf-test-bucket"
  this is invalid hcl
}
"""
    findings = analyze_terraform(content, "bad.tf")
    assert len(findings) == 1
    assert "HCL Parse Error" in findings[0].rule_name
    assert findings[0].severity == "CRITICAL"
