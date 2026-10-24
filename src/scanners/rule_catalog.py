"""Deterministic explanatory metadata; never an AI or compliance mapping source."""

DETAILS = {
    'terraform.public-database': ('A publicly accessible database can expose its network endpoint beyond private application infrastructure.', 'publicly_accessible = true'),
    'terraform.open-ingress': ('Unrestricted ingress permits public access to administrative services or all protocols.', 'Unrestricted IPv4/IPv6 ingress matches the implemented protocol/port check.'),
    'terraform.s3-encryption': ('This source does not declare a recognized encryption configuration for the bucket.', 'Recognized bucket encryption configuration is absent.'),
    'terraform.s3-public-access': ('This source does not declare a public-access-block resource for the bucket.', 'Recognized bucket public-access-block configuration is absent.'),
    'kubernetes.privileged': ('Privileged containers can access host capabilities outside normal container isolation.', 'privileged: true'),
    'kubernetes.privilege-escalation': ('Allowing privilege escalation can permit a container process to gain additional privileges.', 'allowPrivilegeEscalation is not explicitly false.'),
    'secrets.vendor-match': ('A supported credential signature was detected. Revoke exposed credentials and move them to a secret manager.', 'Credential signature matched; value withheld.'),
    'secrets.entropy': ('A value matched the implemented entropy heuristic. Review locally without disclosing the value.', 'Entropy heuristic matched; value withheld.'),
}


def family(rule_id: str) -> str:
    prefix = rule_id.split('.', 1)[0]
    return prefix if prefix in {'terraform', 'docker', 'kubernetes', 'secrets', 'parser', 'network'} else 'unknown'


def details(rule_id: str) -> tuple[str, str]:
    return DETAILS.get(rule_id, (
        'The deterministic rule matched the recorded source. Review its location and remediation guidance; coverage is limited to implemented checks.',
        'Deterministic rule matched at the recorded source location; sensitive values are withheld.',
    ))
