import json
import time

import pytest

from src.scanners.iac_audit import analyze_generic_secrets, analyze_kubernetes, analyze_terraform, analyze_dockerfile


TOKEN = "ghp_" + "a" * 36


@pytest.mark.parametrize("source", [f'TOKEN={TOKEN}', f'export TOKEN = "{TOKEN}" # fake', f"token: '{TOKEN}'\r\n", f'TOKEN={TOKEN} # comment'])
def test_assignment_secret_variants(source):
    findings = analyze_generic_secrets(source, "sample.env")
    assert findings and all(TOKEN not in repr(f) for f in findings)


def test_nested_json_arrays_and_false_positives():
    assert analyze_generic_secrets(json.dumps({'nested': [{'value': TOKEN}]}), 'nested.json')
    assert not analyze_generic_secrets('ID=550e8400-e29b-41d4-a716-446655440000\nHASH=' + 'a' * 64 + '\nname=ordinary', 'safe.env')
    assert analyze_generic_secrets('{bad', 'bad.json')[0].rule_id == 'parser.json'


@pytest.mark.parametrize('source', ['node: &node\n  child: *node', 'kind: Pod\nspec:\n  containers:\n  - securityContext: invalid', 'x: ' + '[' * 70 + '0' + ']' * 70])
def test_hostile_yaml_controlled(source):
    start = time.monotonic()
    findings = analyze_kubernetes(source, 'hostile.yaml')
    assert findings and findings[0].rule_id == 'parser.yaml'
    assert time.monotonic() - start < 2


def test_alias_dag_linear_and_document_quota():
    source = 'n0: &n0 {v: ordinary}\n' + ''.join(f'n{i}: &n{i} {{a: *n{i-1}, b: *n{i-1}, c: *n{i-1}}}\n' for i in range(1,17))
    start = time.monotonic(); analyze_kubernetes(source, 'dag.yaml')
    assert time.monotonic() - start < 2
    assert analyze_kubernetes(('---\nkind: ConfigMap\n' * 65), 'many.yaml')[0].rule_id == 'parser.yaml'


@pytest.mark.parametrize('cidr,protocol,ports', [('ipv6_cidr_blocks = ["::/0"]', 'tcp', (22,22)), ('cidr_blocks = ["0.0.0.0/0"]', '-1', (0,0))])
def test_terraform_open_network_bypasses(cidr, protocol, ports):
    source=f'resource "aws_security_group" "audit" {{\n ingress {{\n from_port = {ports[0]}\n to_port = {ports[1]}\n protocol = "{protocol}"\n {cidr}\n }}\n}}'
    assert any(f.rule_id == 'terraform.open-ingress' for f in analyze_terraform(source, 'audit.tf'))
    assert not any(f.rule_id == 'terraform.open-ingress' for f in analyze_terraform(source.replace('0.0.0.0/0','10.0.0.0/8').replace('::/0','fd00::/8'), 'audit.tf'))


def test_docker_root_group_disabled_healthcheck_and_builder_information():
    source='FROM alpine:3.20 AS builder\nUSER root:root\nFROM alpine:3.20\nUSER 0:1000\nHEALTHCHECK NONE\n'
    findings=analyze_dockerfile(source, 'Dockerfile')
    assert any(f.rule_id == 'docker.root-user' and f.severity == 'HIGH' for f in findings)
    assert any(f.rule_id == 'docker.missing-healthcheck' for f in findings)
    assert any(f.severity == 'INFORMATIONAL' for f in findings)


def test_privileged_cronjob_and_pod_inheritance():
    import yaml
    spec={'securityContext': {'runAsNonRoot': True, 'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': [{'name':'a','image':'nginx:1.27','securityContext':{'privileged': True,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'resources':{'limits':{'cpu':'100m','memory':'128Mi'}}}]}
    doc={'kind':'CronJob','spec':{'jobTemplate':{'spec':{'template':{'spec':spec}}}}}
    findings=analyze_kubernetes(yaml.safe_dump(doc), 'cron.yaml')
    assert [f.rule_id for f in findings] == ['kubernetes.privileged']
    assert findings[0].remediation_eligible
    assert findings[0].line > 1


def test_shared_yaml_security_context_is_manual_only():
    source='''kind: Pod
spec:
  containers:
  - name: one
    securityContext: &context
      privileged: true
  - name: two
    securityContext: *context
'''
    findings=analyze_kubernetes(source,'shared.yaml')
    selected=[f for f in findings if f.rule_id=='kubernetes.privileged']
    assert len(selected)==2 and all(not f.remediation_eligible for f in selected)
