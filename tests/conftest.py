"""All application tests use synthetic storage before importing any app module."""
import os
import tempfile
from pathlib import Path

import pytest

_sandbox = tempfile.TemporaryDirectory(prefix="antifine-tests-")
_root = Path(_sandbox.name)
(_root / "workspace").mkdir()
os.environ.update({
    "ANTIFINE_TESTING": "1",
    "ANTIFINE_DATA_DIR": str(_root / "private"),
    "ANTIFINE_WORKSPACE_ROOT": str(_root / "workspace"),
    "ANTIFINE_DB_PATH": str(_root / "tests.db"),
    "ANTIFINE_API_TOKEN": "synthetic-test-capability",
    "OLLAMA_ENABLED": "false",
})


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from src.api.server import app
    from src.api.security import CAPABILITY
    (tmp_path / "workspace").mkdir()
    monkeypatch.setenv("ANTIFINE_DATA_DIR", str(tmp_path / "private"))
    monkeypatch.setenv("ANTIFINE_DB_PATH", str(tmp_path / "tests.db"))
    monkeypatch.setenv("ANTIFINE_WORKSPACE_ROOT", str(tmp_path / "workspace"))
    with TestClient(app, headers={"X-AntiFine-Token": CAPABILITY}) as result:
        yield result


def pytest_sessionfinish(session, exitstatus):
    _sandbox.cleanup()
