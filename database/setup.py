"""Database bootstrap for the AntiFine auditing framework.

Creates a local SQLite database used for audit target tracking and
compliance result logging. Safe to run repeatedly: all DDL is guarded
with IF NOT EXISTS.
"""

from __future__ import annotations

import sqlite3
import sys
import os
from contextlib import closing
from pathlib import Path

# Project root, so the database lands in a predictable place no matter
# which working directory the script is invoked from.
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
DB_PATH: Path = Path(os.getenv("ANTIFINE_DB_PATH", str(PROJECT_ROOT / "antifine.db")))

AUDIT_TARGETS_DDL: str = """
CREATE TABLE IF NOT EXISTS audit_targets (
    id INTEGER PRIMARY KEY,
    ip_address TEXT,
    hostname TEXT
)
"""

SCAN_RESULTS_DDL: str = """
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY,
    target_id INTEGER,
    vulnerability_type TEXT,
    severity TEXT,
    status TEXT,
    compliance_framework TEXT,
    compliance_frameworks TEXT,
    description TEXT,
    remediation TEXT,
    target_path TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""

WEBHOOKS_DDL: str = """
CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    min_severity TEXT DEFAULT 'HIGH'
)
"""

def initialize_database(db_path: Path = DB_PATH) -> Path:
    """Additive, serialized legacy migration; unexpected DDL errors are never hidden."""
    import json
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path, timeout=10)) as connection:
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(AUDIT_TARGETS_DDL)
        connection.execute(SCAN_RESULTS_DDL)
        connection.execute(WEBHOOKS_DDL)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_results)")}
        for column in ("compliance_framework", "compliance_frameworks", "description", "remediation", "target_path"):
            if column not in columns:
                connection.execute(f"ALTER TABLE scan_results ADD COLUMN {column} TEXT")
        legacy = connection.execute("SELECT id,compliance_framework FROM scan_results WHERE (compliance_frameworks IS NULL OR compliance_frameworks='') AND compliance_framework IS NOT NULL AND compliance_framework!=''").fetchall()
        connection.executemany("UPDATE scan_results SET compliance_frameworks=? WHERE id=?", [(json.dumps([framework]), row_id) for row_id,framework in legacy])
        connection.commit()
    return db_path



def main() -> int:
    """Entry point for running this module directly."""
    try:
        path = initialize_database()
    except (sqlite3.Error, OSError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    print(f"[ok] Database ready at {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
