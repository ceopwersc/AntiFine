import pytest
from fastapi.testclient import TestClient
from src.api.server import app

from src.api.security import CAPABILITY
client = TestClient(app, headers={"X-AntiFine-Token": CAPABILITY})

def test_upload_scan_target_multiple_files():
    # Test uploading multiple files safely
    files = [
        ("files", ("main.tf", b"resource 'aws_s3_bucket' 'b' {}")),
        ("files", ("variables.tf", b"variable 'foo' {}")),
    ]
    response = client.post("/api/scan/upload", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "target_path" in data
    assert data["target_path"].startswith("workspace_")

def test_upload_scan_target_with_relative_paths():
    # Test uploading files with relative paths inside a folder
    files = [
        ("files", ("main.tf", b"resource 'aws_s3_bucket' 'b' {}")),
        ("files", ("variables.tf", b"variable 'foo' {}")),
    ]
    data = {"relative_paths": '["my_folder/main.tf", "my_folder/variables.tf"]'}
    response = client.post("/api/scan/upload", data=data, files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "target_path" in data
    assert data["target_path"].startswith("workspace_")

def test_upload_scan_target_path_traversal():
    response = client.post("/api/scan/upload", data={"relative_paths": '["../../../etc/passwd"]'}, files=[("files", ("evil.tf", b"synthetic"))])
    assert response.status_code == 400

def test_upload_scan_target_too_many_files():
    # Test upload limit
    files = [("files", (f"file{i}.tf", b"content")) for i in range(101)]
    response = client.post("/api/scan/upload", files=files)
    assert response.status_code == 400
    assert "Too many files" in response.json()["detail"]
