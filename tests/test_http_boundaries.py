from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import UploadFile

from src.services.filesystem import BoundaryError, contained, relative_target
from src.services.settings import workspace_root
from src.services.workspaces import import_root, store_uploads


def test_prefix_sibling_and_parent_rejected(tmp_path):
    root = tmp_path / "AntiFine-1"; root.mkdir()
    sibling = tmp_path / "AntiFine-1-other"; sibling.mkdir()
    (sibling / "main.tf").write_text("# synthetic")
    with pytest.raises(BoundaryError):
        relative_target(root, "../AntiFine-1-other/main.tf")
    with pytest.raises(BoundaryError):
        contained(root, sibling / "main.tf")
    (root / "valid.tf").write_text("# valid")
    assert relative_target(root, "valid.tf").is_file()


def test_symlink_rejected(tmp_path):
    (tmp_path / "real.tf").write_text("# synthetic")
    try:
        (tmp_path / "link.tf").symlink_to(tmp_path / "real.tf")
    except OSError:
        # Windows junctions are exercised independently without symlink privilege.
        if __import__('os').name != 'nt':
            raise
        pytest.skip("Windows symbolic links require a privilege unavailable here; the junction test covers reparse-point rejection")
    with pytest.raises(BoundaryError):
        contained(tmp_path, tmp_path / "link.tf")


def test_windows_junction_rejected(tmp_path):
    import os
    import subprocess
    if os.name != 'nt':
        pytest.skip("Windows junction behavior is tested on Windows")
    target=tmp_path/'real';target.mkdir()
    (target/'source.tf').write_text('# synthetic')
    link=tmp_path/'junction'
    subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],check=True,capture_output=True)
    try:
        with pytest.raises(BoundaryError):contained(tmp_path,link/'source.tf')
    finally:
        os.rmdir(link)


def test_http_auth_host_origin_no_side_effects(client):
    from src.api.server import app
    with TestClient(app) as anonymous:
        assert anonymous.get("/api/dashboard").status_code == 401
        assert anonymous.get("/api/health").status_code == 200
    before = set(import_root().iterdir())
    assert client.post("/api/scan/upload", headers={"Origin": "https://attacker.invalid"}, files={"files": ("x.tf", b"# fake")}).status_code == 403
    assert client.get("/api/dashboard", headers={"Host": "attacker.invalid"}).status_code == 400
    assert set(import_root().iterdir()) == before


def test_session_cookie_is_http_only(client):
    r = client.post("/api/session", headers={"Origin": "http://127.0.0.1:5173", "X-AntiFine-Request": "1"})
    assert r.status_code == 200
    assert "HttpOnly" in r.headers["set-cookie"] and "SameSite=strict" in r.headers["set-cookie"]
    assert "synthetic-test-capability" not in r.text


def test_remote_peer_cannot_bootstrap_or_use_capability():
    from src.api.server import app
    from src.api.security import CAPABILITY
    with TestClient(app, client=('203.0.113.10',12345), headers={'X-AntiFine-Token':CAPABILITY}) as remote:
        assert remote.get('/api/dashboard').status_code==403
        assert remote.post('/api/session',headers={'Origin':'http://127.0.0.1:5173','X-AntiFine-Request':'1'}).status_code==403


def test_upload_private_quotas_and_cleanup(client):
    before = set(import_root().iterdir())
    r = client.post("/api/scan/upload", files={"files": ("nested.tf", b"# safe")})
    assert r.status_code == 200
    assert r.json()["target_path"].startswith("workspace_")
    assert not import_root().is_relative_to(Path(__file__).resolve().parents[1])
    with patch("src.services.workspaces.MAX_FILE_BYTES", 3):
        with pytest.raises(BoundaryError):
            store_uploads([UploadFile(filename="x.tf", file=BytesIO(b"1234"))], "[]")
    assert len(set(import_root().iterdir()) - before) == 1


@pytest.mark.parametrize('filename',['NUL.tf','sub/CON','bad.tf:stream','bad.tf.','bad?.tf'])
def test_windows_special_upload_names_rejected(client,filename):
    before=set(import_root().iterdir())
    response=client.post('/api/scan/upload',files={'files':('safe.tf',b'# synthetic')},data={'relative_paths':__import__('json').dumps([filename])})
    assert response.status_code==400
    assert set(import_root().iterdir())==before


def test_validation_never_echoes_values(client):
    token = "ghp_" + "a" * 36
    r = client.post("/api/scan/iac", json={"target_path": {"token": token}})
    assert r.status_code == 422
    assert token not in r.text


def test_webhook_private_dns_and_allowlist(monkeypatch):
    from src.integrations.webhook_policy import validate_destination
    monkeypatch.setenv("ANTIFINE_WEBHOOK_ALLOWLIST", "hooks.example.com")
    with patch("socket.getaddrinfo", return_value=[(2,1,6,'',('127.0.0.1',443))]):
        with pytest.raises(ValueError): validate_destination("https://hooks.example.com/hook")
    with pytest.raises(ValueError): validate_destination("https://localhost/hook")
    with pytest.raises(ValueError): validate_destination("https://hooks.example.com/hook?token=fake")
