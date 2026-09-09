# Terraform rules

Terraform analysis is implemented in `src/scanners/iac_audit.py` using
`hcl2.loads`. HCL parse errors produce a `CRITICAL` finding with the `Internal`
framework. Parsed Terraform string values are also passed through the secret
scanner.

| Rule ID | Finding | Severity | Detection |
| --- | --- | --- | --- |
| `terraform.open-ingress-sensitive-port` | Open ingress port | CRITICAL | An `aws_security_group` or ingress `aws_security_group_rule` contains `0.0.0.0/0` or `::/0` and its range includes port 22 or 3389. |
| `terraform.public-database` | Publicly accessible database | CRITICAL | An `aws_db_instance` has `publicly_accessible` equal to `true`. |
| `terraform.s3-encryption-missing` | Unencrypted S3 storage | HIGH | An `aws_s3_bucket` lacks embedded or companion server-side encryption configuration. |
| `terraform.s3-public-access-block-missing` | S3 public access block missing | HIGH | An `aws_s3_bucket` lacks a companion public access block resource. |

Mappings and remediation guidance are emitted directly in each scanner
finding. Terraform remediation currently has no dedicated branch in
`src/scanners/remediation.py`; the API therefore does not claim to apply
these Terraform fixes automatically.
