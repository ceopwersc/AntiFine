"""Database bootstrap for the AntiFine auditing framework.

Creates a local SQLite database used for audit target tracking and
compliance result logging. Safe to run repeatedly: all DDL is guarded
with IF NOT EXISTS.
"""

from __future__ import annotations

import sqlite3
import sys
from contextlib import closing
from pathlib import Path

# Project root, so the database lands in a predictable place no matter
# which working directory the script is invoked from.
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
DB_PATH: Path = PROJECT_ROOT / "antifine.db"

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
    """Create the AntiFine database and its tables if they do not exist.

    Args:
        db_path: Location of the SQLite database file.

    Returns:
        The path to the initialized database.

    Raises:
        sqlite3.Error: If the database cannot be created or written to.
    """
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(db_path)) as connection:
            cursor = connection.cursor()
            cursor.execute(AUDIT_TARGETS_DDL)
            cursor.execute(SCAN_RESULTS_DDL)
            cursor.execute(WEBHOOKS_DDL)
            
            # Add compliance_framework column to existing databases
            try:
                cursor.execute("ALTER TABLE scan_results ADD COLUMN compliance_framework TEXT")
            except sqlite3.OperationalError:
                # Column might already exist, which is fine
                pass

            # JSON array of authoritative mappings.  Keep the legacy
            # compliance_framework column for old clients and migration.
            try:
                cursor.execute("ALTER TABLE scan_results ADD COLUMN compliance_frameworks TEXT")
            except sqlite3.OperationalError:
                pass
            for column in ("description", "remediation"):
                try:
                    cursor.execute(f"ALTER TABLE scan_results ADD COLUMN {column} TEXT")
                except sqlite3.OperationalError:
                    pass

            # A legacy row has exactly one authoritative mapping: its old
            # primary framework.  Do not reconstruct mappings from text.
            import json
            legacy_rows = cursor.execute(
                "SELECT id, compliance_framework FROM scan_results "
                "WHERE (compliance_frameworks IS NULL OR compliance_frameworks = '') "
                "AND compliance_framework IS NOT NULL AND compliance_framework != ''"
            ).fetchall()
            cursor.executemany(
                "UPDATE scan_results SET compliance_frameworks = ? WHERE id = ?",
                [(json.dumps([framework]), row_id) for row_id, framework in legacy_rows],
            )

            # Add target_path column to existing databases
            try:
                cursor.execute("ALTER TABLE scan_results ADD COLUMN target_path TEXT")
            except sqlite3.OperationalError:
                pass
                
            connection.commit()
    except sqlite3.Error as exc:
        raise sqlite3.Error(f"Failed to initialize database at {db_path}: {exc}") from exc
    except OSError as exc:
        raise OSError(f"Cannot access database location {db_path}: {exc}") from exc

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
