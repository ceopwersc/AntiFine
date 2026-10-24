import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest
from starlette.datastructures import UploadFile
from src.services.scan_repository import ScanRepository
from src.services.secret_boundary import sanitize_text
from src.services.settings import workspace_root, data_root
from src.services.workspaces import store_uploads, import_root


def test_first_start_concurrent_migrations(tmp_path):
    path=tmp_path/'fresh.db'
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(lambda _: ScanRepository(path).history(), range(16))) == [[]]*16


@pytest.mark.parametrize('sentinel', ['0123456789abcdef','AbCdEfGhIjKlMnOpQrStUvWx'])
def test_entropy_detection_redaction_threshold_alignment(sentinel):
    from src.scanners.secret_scanner import scan_value_for_secrets
    assert scan_value_for_secrets(sentinel,'id','synthetic.env')
    assert sentinel not in sanitize_text('id='+sentinel)


def test_legacy_privacy_migration_does_not_reconstruct_mappings(tmp_path):
    from database.setup import initialize_database
    path=tmp_path/'legacy.db';initialize_database(path)
    sentinel='ghp_'+'a'*36
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO scan_results(vulnerability_type,severity,status,compliance_framework) VALUES(?,?,?,?)",('Secret '+sentinel,'HIGH','OPEN','CIS 1'))
        db.execute('INSERT INTO webhooks(url) VALUES(?)',('https://hooks.invalid/'+sentinel+'?token='+sentinel,))
    repo=ScanRepository(path);values=repo.findings()
    assert values[0]['frameworks']==['CIS 1']
    assert sentinel not in path.read_bytes().decode('latin1')


def test_aggregate_upload_quota_and_duplicate_path_cleanup(client):
    before=set(import_root().iterdir())
    with patch('src.services.workspaces.MAX_WORKSPACE_BYTES',4):
        with pytest.raises(ValueError):
            store_uploads([UploadFile(filename='a.tf',file=BytesIO(b'123')),UploadFile(filename='b.tf',file=BytesIO(b'123'))],'[]')
    assert set(import_root().iterdir())==before
    r=client.post('/api/scan/upload',files=[('files',('x.tf',b'#a')),('files',('x.tf',b'#b'))])
    assert r.status_code==400 and set(import_root().iterdir())==before


def test_webhook_mixed_dns_pinned_address_and_no_redirect(monkeypatch):
    from src.integrations.webhook_policy import validate_destination, deliver
    monkeypatch.setenv('ANTIFINE_WEBHOOK_ALLOWLIST','hooks.example.com')
    mixed=[(2,1,6,'',('1.1.1.1',443)),(10,1,6,'',('::1',443,0,0))]
    with patch('socket.getaddrinfo',return_value=mixed):
        with pytest.raises(ValueError):validate_destination('https://hooks.example.com/hook')
    with patch('socket.getaddrinfo',return_value=mixed[:1]), patch('src.integrations.webhook_policy.PinnedHTTPSConnection') as connection:
        connection.return_value.getresponse.return_value.status=302
        with pytest.raises(ValueError):deliver('https://hooks.example.com/hook',{'safe':'synthetic'})
        assert connection.call_args.args[0].address=='1.1.1.1'
        assert connection.return_value.request.call_count==1


def test_os_worker_memory_limit_rejects_oversized_allocation():
    import subprocess,sys
    code='from src.services.worker_limits import enforce; enforce();\ntry:\n x=bytearray(600*1024*1024)\nexcept MemoryError:\n raise SystemExit(0)\nraise SystemExit(1)'
    result=subprocess.run([sys.executable,'-c',code],capture_output=True,timeout=10)
    assert result.returncode==0


def test_raw_request_access_log_is_suppressed(client):
    import logging
    record=logging.LogRecord('uvicorn.access',logging.INFO,'synthetic',1,'%s',('ghp_'+'a'*36,),None)
    assert not logging.getLogger('uvicorn.access').filter(record)
