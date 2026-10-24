import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.services.settings import workspace_root, data_root
from src.services.advisory_guard import constrain


@pytest.mark.parametrize('text', ['Severity is LOW. I applied the fix and verified the file.', 'The finding was resolved.', 'Verification completed.'])
def test_ai_action_and_severity_claims_withheld(text):
    result=constrain(text,'CRITICAL')
    assert text not in result and 'withheld' in result


def test_ai_endpoint_rejects_contradictory_mock(client):
    (workspace_root()/'ai.tf').write_text('resource \"aws_db_instance\" \"audit\" {\n publicly_accessible = true\n}\n')
    finding=client.post('/api/scan/iac',json={'target_path':'ai.tf'}).json()['findings'][0]
    request={'finding':dict(finding, severity='LOW',filename=finding['file'])}
    with patch('src.services.ollama_service.OllamaService.generate',new=AsyncMock(return_value='Severity is LOW. I applied the fix.')):
        r=client.post('/api/ai/findings/explain',json=request)
    assert r.status_code==200 and 'withheld' in r.json()['explanation']


def test_ai_review_uses_backend_preview_and_rejects_forgery(client):
    (workspace_root()/'review.tf').write_text('resource "aws_db_instance" "audit" {\n publicly_accessible = true\n}\n')
    finding=client.post('/api/scan/iac',json={'target_path':'review.tf'}).json()['findings'][0]
    preview=client.post('/api/scan/iac/remediation/preview',json={'finding_id':finding['id']}).json()
    request={'finding':dict(finding,filename=finding['file'],severity='LOW'), 'preview_id':preview['preview_id'],
        'before':'fabricated before','after':'fabricated after','diff':'fabricated diff'}
    with patch('src.services.ollama_service.OllamaService.generate',new=AsyncMock(return_value='The proposed flag disables public access.')) as generate:
        r=client.post('/api/ai/remediation/explain',json=request)
    assert r.status_code==200
    prompt=generate.await_args.args[0]
    assert 'CRITICAL' in prompt and 'fabricated' not in prompt
    assert r.json()['finding_id']==finding['id']
    request['preview_id']='0'*64
    assert client.post('/api/ai/remediation/explain',json=request).status_code==422


def test_ask_finding_context_is_canonical(client):
    (workspace_root()/'ask.tf').write_text('resource "aws_db_instance" "audit" {\n publicly_accessible = true\n}\n')
    finding=client.post('/api/scan/iac',json={'target_path':'ask.tf'}).json()['findings'][0]
    request={'question':'Explain this finding.', 'context':{'source':'finding','finding':{'finding_id':finding['id'],'severity':'LOW','frameworks':['fabricated control']}}}
    with patch('src.services.ollama_service.OllamaService.generate',new=AsyncMock(return_value='Severity is LOW.')) as generate:
        result=client.post('/api/ai/ask',json=request)
    assert result.status_code==200 and 'withheld' in result.json()['answer']
    prompt=generate.await_args.args[0]
    assert 'CRITICAL' in prompt and 'fabricated control' not in prompt
    request['context']['finding']['finding_id']='fabricated'
    assert client.post('/api/ai/ask',json=request).status_code==422


def test_network_scan_compatibility_uses_canonical_storage(client):
    from types import SimpleNamespace
    observation=SimpleNamespace(vulnerability_type='SSRF synthetic observation',severity='HIGH')
    with patch('src.api.server.run_web_audit',return_value=[observation]):
        response=client.post('/api/scan/ssrf',json={'target_url':'https://audit.invalid/?url=synthetic'})
    assert response.status_code==200 and response.json()['status']=='partial'
    assert response.json()['findings'][0]['rule_id']=='network.ssrf'
    assert any(f['rule_id']=='network.ssrf' for f in client.get('/api/findings').json()['findings'])


def test_sarif_schema_markdown_coverage_and_redaction(client):
    import jsonschema
    token='ghp_'+'a'*36
    (workspace_root()/'source.tf').write_text('resource "aws_db_instance" "audit" {\n publicly_accessible = true\n}\nlocals {\n token = "'+token+'"\n}\n')
    scan=client.post('/api/scan/iac',json={'target_path':'source.tf'})
    assert scan.status_code==200
    response=client.get('/api/scan/iac/export/sarif')
    schema=json.loads((Path(__file__).parent/'schemas/sarif-schema-2.1.0.json').read_text(encoding='utf-8'))
    jsonschema.Draft7Validator(schema,format_checker=jsonschema.FormatChecker()).validate(response.json())
    database_result=next(r for r in response.json()['runs'][0]['results'] if r['ruleId']=='terraform.public-database')
    assert database_result['locations'][0]['physicalLocation']['region']['startLine']>1
    report=client.post('/api/report/generate')
    assert report.status_code==200
    name=report.json()['results']['markdown']['file']
    content=client.get('/api/reports/'+name)
    assert content.status_code==200 and scan.json()['scan_id'] in content.text
    for value in (scan.text,response.text,content.text,client.get('/api/findings').text,client.get('/api/findings/secrets').text):
        assert token not in value
    assert client.get('/api/reports/../../source.tf').status_code==404


def test_informational_and_no_compliance_inference(client):
    (workspace_root()/'Dockerfile').write_text('FROM alpine:3.20 AS build\nUSER root\nFROM alpine:3.20\nUSER 1000\nHEALTHCHECK CMD true\n')
    response=client.post('/api/scan/iac',json={'target_path':'Dockerfile'})
    assert any(f['severity']=='INFORMATIONAL' for f in response.json()['findings'])
    assert client.get('/api/dashboard').json()['counts']['INFORMATIONAL']>=1
    assert client.get('/api/analytics/dashboard').json()['overall_compliance_score'] is None
    (workspace_root()/'unsupported.txt').write_text('ordinary')
    unsupported=client.post('/api/scan/iac',json={'target_path':'unsupported.txt'}).json()
    assert unsupported['status']=='error' and unsupported['coverage'][0]['status']=='unsupported'
    assert 'compliant' not in unsupported['summary'].lower()


def test_actual_worker_deadline(tmp_path):
    from src.services.scan_worker import isolated_file
    (tmp_path/'x.tf').write_text('# synthetic')
    with patch('src.services.scan_worker.SCAN_TIMEOUT',0.001):
        with pytest.raises(ValueError,match='deadline'):
            isolated_file(tmp_path/'x.tf',tmp_path)


def test_compliance_labels_preserve_unicode_identifiers():
    from src.scanners.iac_audit import analyze_dockerfile
    from src.scanners.secret_scanner import scan_value_for_secrets

    docker = analyze_dockerfile('FROM alpine:3.20\nUSER root\nHEALTHCHECK NONE\n', 'Dockerfile')
    root = next(finding for finding in docker if finding.rule_id == 'docker.root-user')
    secret = scan_value_for_secrets('token', 'ghp_' + 'a' * 36, 'synthetic.env')
    assert secret is not None
    for finding in (root, secret):
        assert 'NIST SP 800-190 §3.3.1' in finding.frameworks
        assert not any('Â' in label for label in finding.frameworks)
