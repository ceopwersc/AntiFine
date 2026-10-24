import json
from pathlib import Path
from unittest.mock import patch

from src.services.settings import workspace_root, data_root

TF='resource "aws_db_instance" "first" {\n publicly_accessible = true\n}\n'


def start(client, text=TF):
    (workspace_root()/'main.tf').write_text(text)
    r=client.post('/api/scan/iac',json={'target_path':'main.tf'})
    assert r.status_code == 200, r.text
    return r.json()['findings']


def test_exact_second_resource_and_immutable_backups(client):
    original=TF+TF.replace('first','second')
    findings=start(client,original)
    second=findings[1]
    preview=client.post('/api/scan/iac/remediation/preview',json={'finding_id':second['id']})
    assert preview.status_code==200, preview.text
    r=client.post('/api/scan/iac/remediate',json={'approved':True,'finding_id':second['id'],'preview_id':preview.json()['preview_id']})
    assert r.status_code==200, r.text
    assert r.json()['verified'] is False
    text=(workspace_root()/'main.tf').read_text()
    assert text.split('resource')[1].count('true')==1
    assert text.split('resource')[2].count('false')==1
    backup1=data_root()/'backups'/(r.json()['backup_id']+'.bak')
    assert backup1.read_text()==original
    remaining=r.json()['findings'][0]
    p=client.post('/api/scan/iac/remediation/preview',json={'finding_id':remaining['id']}).json()
    fixed=client.post('/api/scan/iac/remediate',json={'approved':True,'finding_id':remaining['id'],'preview_id':p['preview_id']})
    assert fixed.status_code==200 and fixed.json()['verified'] is True, fixed.text
    assert fixed.json()['backup_id'] != r.json()['backup_id']
    assert backup1.read_text()==original
    assert not [f for f in client.get('/api/findings').json()['findings'] if f['status']=='OPEN']


def test_stale_preview_forged_title_and_unsupported_file(client):
    f=start(client)[0]
    p=client.post('/api/scan/iac/remediation/preview',json={'finding_id':f['id']}).json()
    target=workspace_root()/'main.tf';target.write_text(TF+'# concurrent edit\n')
    assert client.post('/api/scan/iac/remediate',json={'approved':True,'finding_id':f['id'],'preview_id':p['preview_id']}).status_code==409
    assert target.read_text().endswith('# concurrent edit\n')
    assert client.post('/api/scan/iac/remediate',json={'target_path':'main.tf','rule_name':'Publicly Accessible Database'}).status_code==422
    assert client.post('/api/scan/iac/remediation/preview',json={'finding_id':'fabricated'}).status_code==422
    (workspace_root()/'wrong.txt').write_text('publicly_accessible = true')
    assert client.post('/api/scan/iac/remediate',json={'target_path':'wrong.txt','rule_name':'Publicly Accessible Database'}).status_code==422


def test_import_nested_file_and_secret_boundaries(client):
    sentinel='ghp_'+'a'*36
    source=TF+'locals {\n token = "'+sentinel+'"\n}\n'
    uploaded=client.post('/api/scan/upload',files=[('files',('main.tf',source))],data={'relative_paths':json.dumps(['nested/main.tf'])}).json()
    scan=client.post('/api/scan/iac',json={'target_path':uploaded['target_path']})
    assert sentinel not in scan.text
    f=next(f for f in scan.json()['findings'] if f['rule_id']=='terraform.public-database')
    assert f['file']=='nested/main.tf'
    p=client.post('/api/scan/iac/remediation/preview',json={'finding_id':f['id']})
    assert p.status_code==200 and sentinel not in p.text
    r=client.post('/api/scan/iac/remediate',json={'approved':True,'finding_id':f['id'],'preview_id':p.json()['preview_id']})
    assert r.status_code==200 and sentinel not in r.text and r.json()['verified'] is False
    assert sentinel not in Path(__import__('os').environ['ANTIFINE_DB_PATH']).read_bytes().decode('latin1')


def test_docker_manual_only_and_multiple_stages(client):
    (workspace_root()/'Dockerfile').write_text('FROM alpine:3.20 AS build\nUSER root\nFROM alpine:3.20\nUSER root:root\nHEALTHCHECK NONE\n')
    r=client.post('/api/scan/iac',json={'target_path':'Dockerfile'}).json()
    assert any(f['severity']=='INFORMATIONAL' for f in r['findings'])
    assert all(not f['remediation_eligible'] for f in r['findings'])
    for f in r['findings']:
        assert client.post('/api/scan/iac/remediation/preview',json={'finding_id':f['id']}).status_code==422


def test_failed_verification_restores_original(client):
    from src.services import remediation_apply
    f=start(client)[0];p=client.post('/api/scan/iac/remediation/preview',json={'finding_id':f['id']}).json()
    with patch.object(remediation_apply,'scan_target',side_effect=ValueError('synthetic failure')):
        r=client.post('/api/scan/iac/remediate',json={'approved':True,'finding_id':f['id'],'preview_id':p['preview_id']})
    assert r.status_code==409
    assert (workspace_root()/'main.tf').read_text()==TF


def test_health_responsive_during_scan(client):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from src.services import scanning
    from src.scanners.iac_audit import scan_file
    start_event=threading.Event();release=threading.Event()
    (workspace_root()/'main.tf').write_text(TF)
    def slow(path,root):
        start_event.set();release.wait(3);return scan_file(path)
    with patch.object(scanning,'isolated_file',side_effect=slow), ThreadPoolExecutor() as pool:
        pending=pool.submit(client.post,'/api/scan/iac',json={'target_path':'main.tf'})
        assert start_event.wait(2)
        try: assert client.get('/api/health').status_code==200
        finally: release.set()
        assert pending.result().status_code==200
