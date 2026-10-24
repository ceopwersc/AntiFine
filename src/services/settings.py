"""Trusted process configuration. Never derive storage roots from HTTP input."""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def workspace_root() -> Path:
    return Path(os.getenv("ANTIFINE_WORKSPACE_ROOT", str(PROJECT_ROOT))).resolve()


def data_root() -> Path:
    base = Path(os.getenv("LOCALAPPDATA", str(Path.home() / ".local" / "share")))
    root = Path(os.getenv("ANTIFINE_DATA_DIR", str(base / "AntiFine"))).resolve()
    if root.is_relative_to(PROJECT_ROOT):
        raise ValueError("Private AntiFine storage must be outside the source checkout")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    from src.services.private_permissions import restrict
    restrict(root)
    return root


def database_path() -> Path:
    return Path(os.getenv("ANTIFINE_DB_PATH", str(PROJECT_ROOT / "antifine.db"))).resolve()
