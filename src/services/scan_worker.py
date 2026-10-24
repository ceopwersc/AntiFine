"""Killable, bounded scanner isolation. Child never touches the application DB."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

from src.models.finding import Finding

_slots = threading.BoundedSemaphore(2)
SCAN_TIMEOUT = 10


def isolated_file(path: Path, root: Path) -> list[Finding]:
    from src.services.filesystem import contained
    contained(root, path)
    if not _slots.acquire(timeout=0.1):
        raise ValueError("Scanner capacity reached; retry shortly")
    try:
        result = subprocess.run([sys.executable, "-m", "src.services.scan_worker", str(path), str(root)],
            cwd=Path(__file__).resolve().parents[2], capture_output=True, timeout=SCAN_TIMEOUT,
            env={**os.environ, "OLLAMA_ENABLED": "false"})
        if result.returncode != 0 or len(result.stdout) > 4 * 1024 * 1024:
            raise ValueError("Scanner could not evaluate this file")
        return [Finding(**value) for value in json.loads(result.stdout)]
    except subprocess.TimeoutExpired:
        raise ValueError("Scanner processing deadline exceeded") from None
    finally:
        _slots.release()


if __name__ == "__main__":
    from src.services.worker_limits import enforce
    enforce()
    from dataclasses import asdict
    from src.scanners.iac_audit import scan_file
    from src.services.filesystem import contained
    try:
        root = Path(sys.argv[2])
        path = contained(root, Path(sys.argv[1]))
        findings = scan_file(path)
        if len(findings) > 1000:
            raise ValueError("Finding quota exceeded")
        print(json.dumps([asdict(f) for f in findings], ensure_ascii=True))
    except Exception:
        raise SystemExit(2)
