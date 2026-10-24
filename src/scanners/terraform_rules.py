"""Terraform source checks with exact structural pointers and stable resource keys."""
import hashlib

import hcl2

from src.models.finding import Finding
from src.scanners.structures import terraform_attribute, terraform_blocks


def analyze(content: str, filename: str) -> list[Finding]:
    from src.scanners.iac_audit import _walk_yaml_strings
    try:
        document = hcl2.loads(content)
        blocks = terraform_blocks(content)
        findings = _walk_yaml_strings(document, filename)
        buckets, encryption, public_blocks = [], [], []
        addresses = set()
        index = -1
        for resource in document.get('resource', []):
            for raw_type, instances in resource.items():
                resource_type = raw_type.strip('"\'')
                for raw_name, config in instances.items():
                    index += 1
                    name = raw_name.strip('"\'')
                    address = f'{resource_type}.{name}'
                    if address in addresses or not isinstance(config, dict):
                        raise ValueError('Ambiguous or unsupported resource declaration')
                    addresses.add(address)
                    block = blocks[index]

                    def location(suffix: str = '', *, resource_index: int = index, resource_address: str = address, source_block=block) -> dict:
                        return dict(resource=f'terraform/{resource_index}' + suffix,
                            resource_key=hashlib.sha256((resource_address + suffix).encode()).hexdigest(),
                            resource_label=resource_address, line=source_block.meta.line,
                            end_line=source_block.meta.end_line)

                    if resource_type == 'aws_s3_bucket':
                        buckets.append((name, config, location()))
                    elif resource_type == 'aws_s3_bucket_server_side_encryption_configuration':
                        encryption.append(config)
                    elif resource_type == 'aws_s3_bucket_public_access_block':
                        public_blocks.append(config)

                    if resource_type in ('aws_security_group', 'aws_security_group_rule'):
                        rules = []
                        if resource_type == 'aws_security_group_rule' and str(config.get('type', '')).strip('"\'') == 'ingress':
                            rules = [config]
                        elif resource_type == 'aws_security_group':
                            rules = config.get('ingress', [])
                            if isinstance(rules, dict):
                                rules = [rules]
                        if not isinstance(rules, list):
                            raise ValueError('Unsupported ingress structure')
                        for rule_index, rule in enumerate(rules):
                            if not isinstance(rule, dict):
                                raise ValueError('Unsupported ingress rule')
                            ipv4, ipv6 = rule.get('cidr_blocks', []), rule.get('ipv6_cidr_blocks', [])
                            if not isinstance(ipv4, list) or not isinstance(ipv6, list):
                                raise ValueError('CIDR lists must be statically enumerable')
                            if not any(isinstance(cidr, str) and cidr.strip('"\'') in ('0.0.0.0/0', '::/0') for cidr in ipv4 + ipv6):
                                continue
                            protocol = str(rule.get('protocol', 'tcp')).strip('"\'').lower()
                            exposed = protocol in ('-1', 'all')
                            if protocol in ('tcp', '6'):
                                first, last = int(rule['from_port']), int(rule['to_port'])
                                exposed = first <= 22 <= last or first <= 3389 <= last
                            if exposed:
                                findings.append(Finding('Unrestricted Administrative Ingress in ' + filename, 'CRITICAL', filename,
                                    frameworks=['CIS AWS Foundations Benchmark 5.2', 'PCI-DSS 4.0 Req 1.3.1'],
                                    remediation='Restrict ingress to specific trusted CIDRs or a bastion host.',
                                    rule_id='terraform.open-ingress', **location(f'/ingress/{rule_index}')))

                    if resource_type == 'aws_db_instance' and str(config.get('publicly_accessible', '')).lower() == 'true':
                        position = location()
                        position['line'] = terraform_attribute(content, position['resource'], 'publicly_accessible', blocks=blocks)[2]
                        findings.append(Finding(f'Publicly Accessible Database ({name}) in {filename}', 'CRITICAL', filename,
                            frameworks=['CIS AWS Foundations Benchmark 2.3.1', 'PCI-DSS 4.0 Req 1.3.2'],
                            remediation='Set publicly_accessible = false and deploy the database inside private subnets.',
                            rule_id='terraform.public-database', remediation_eligible=True,
                            evidence='publicly_accessible = true', **position))

        for name, config, position in buckets:
            references = {f'${{aws_s3_bucket.{name}.id}}', f'${{aws_s3_bucket.{name}.bucket}}', f'aws_s3_bucket.{name}.id', f'aws_s3_bucket.{name}.bucket'}
            if 'server_side_encryption_configuration' not in config and not any(str(item.get('bucket', '')).strip('"') in references for item in encryption):
                findings.append(Finding(f'Unencrypted S3 Storage ({name}) in {filename}', 'HIGH', filename,
                    frameworks=['CIS AWS Foundations Benchmark 2.1.1', 'NIST SP 800-190 Section 3.3.4'],
                    remediation='Declare an aws_s3_bucket_server_side_encryption_configuration referencing this bucket.',
                    rule_id='terraform.s3-encryption', **position))
            if not any(str(item.get('bucket', '')).strip('"') in references for item in public_blocks):
                findings.append(Finding(f'S3 Public Access Block Missing ({name}) in {filename}', 'HIGH', filename,
                    frameworks=['CIS AWS Foundations Benchmark 2.1.5'],
                    remediation='Declare an aws_s3_bucket_public_access_block referencing this bucket and enable its public-access protections.',
                    rule_id='terraform.s3-public-access', **position))
        return findings
    except Exception:
        # Parser/source errors are evidence, never a clean security decision.
        return [Finding('HCL Parse Error or unsupported structure', 'CRITICAL', filename,
            frameworks=['Internal'], remediation='Correct the HCL syntax/structure before rescanning.',
            description='Terraform could not be parsed or its structure is unsupported. No security pass is available.', rule_id='parser.hcl')]
