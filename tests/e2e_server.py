"""Isolated real API process for Playwright. Never opens the developer DB."""
import os
from pathlib import Path
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix="antifine-e2e-") as directory:
        root = Path(directory)
        (root / "workspace").mkdir()
        os.environ.update({
            "ANTIFINE_DATA_DIR": str(root / "private"),
            "ANTIFINE_DB_PATH": str(root / "test.db"),
            "ANTIFINE_WORKSPACE_ROOT": str(root / "workspace"),
            "OLLAMA_ENABLED": "false",
            "ANTIFINE_WEBHOOK_ALLOWLIST": "",
        })
        if os.environ.get("ANTIFINE_E2E_MANIFEST"):
            import json
            Path(os.environ["ANTIFINE_E2E_MANIFEST"]).write_text(json.dumps({"root": str(root), "data_dir": str(root / "private"), "workspace": str(root / "workspace"), "database": str(root / "test.db")}), encoding="utf-8")
        import uvicorn
        uvicorn.run("src.api.server:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
