"""Transactional findings, scan coverage and immutable remediation evidence (v4)."""
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3

from database.setup import initialize_database
from src.models.finding import Finding
from src.services.secret_boundary import sanitize_path, sanitize_text

EXTRA_COLUMNS = {
    "finding_id": "TEXT", "rule_id": "TEXT", "file_id": "TEXT", "workspace_id": "TEXT",
    "resource": "TEXT", "source_line": "INTEGER", "source_column": "INTEGER", "end_line": "INTEGER",
    "source_digest": "TEXT", "scan_id": "TEXT", "remediation_eligible": "INTEGER DEFAULT 0",
    'family': 'TEXT', 'resource_key': 'TEXT', 'resource_label': 'TEXT', 'evidence': 'TEXT',
}


class ScanRepository:
    def __init__(self, path: Path):
        self.path = Path(path)

    def connect(self):
        initialize_database(self.path)
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA secure_delete=ON")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("BEGIN IMMEDIATE")
        version = db.execute('PRAGMA user_version').fetchone()[0]
        if version > 4:
            db.close()
            raise ValueError('Database schema is newer than this AntiFine release')
        columns = {r[1] for r in db.execute("PRAGMA table_info(scan_results)")}
        for name, sql_type in EXTRA_COLUMNS.items():
            if name not in columns:
                db.execute(f"ALTER TABLE scan_results ADD COLUMN {name} {sql_type}")
        db.executescript("""
            CREATE UNIQUE INDEX IF NOT EXISTS finding_identity ON scan_results(finding_id) WHERE finding_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS scan_runs (
                id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, scope_id TEXT NOT NULL,
                target TEXT NOT NULL, status TEXT NOT NULL, coverage TEXT NOT NULL,
                findings_count INTEGER NOT NULL, timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                scan_type TEXT NOT NULL DEFAULT 'IaC Config Audit');
            CREATE TABLE IF NOT EXISTS scan_evidence (
                scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, evidence TEXT NOT NULL,
                PRIMARY KEY(scan_id, finding_id), FOREIGN KEY(scan_id) REFERENCES scan_runs(id));
            CREATE TABLE IF NOT EXISTS remediation_runs (
                id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, details TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE INDEX IF NOT EXISTS remediation_finding ON remediation_runs(finding_id);
        """)
        db.execute("BEGIN IMMEDIATE")
        run_columns = {row[1] for row in db.execute('PRAGMA table_info(scan_runs)')}
        if 'enumeration_complete' not in run_columns:
            db.execute('ALTER TABLE scan_runs ADD COLUMN enumeration_complete INTEGER NOT NULL DEFAULT 0')
            db.execute("UPDATE scan_runs SET enumeration_complete=1 WHERE status='completed'")
        if version < 3:
            # A one-time privacy migration preserves evidence and mappings while
            # removing credential material from legacy display fields. Existing
            # webhook credentials are deliberately retired, never copied elsewhere.
            for row in db.execute("SELECT id,vulnerability_type,description,remediation,target_path,compliance_framework,compliance_frameworks FROM scan_results").fetchall():
                safe = [sanitize_text(value) if value is not None else None for value in row[1:]]
                db.execute("UPDATE scan_results SET vulnerability_type=?,description=?,remediation=?,target_path=?,compliance_framework=?,compliance_frameworks=? WHERE id=?", (*safe,row[0]))
            from urllib.parse import urlsplit
            for row in db.execute("SELECT id,url FROM webhooks").fetchall():
                parts = urlsplit(row[1])
                if parts.username or parts.password or parts.query or sanitize_text(row[1]) != row[1]:
                    db.execute("UPDATE webhooks SET url=? WHERE id=?", (f"disabled-legacy-destination-{row[0]}",row[0]))
        db.execute("PRAGMA user_version=4")
        db.commit()
        return db

    def save_run(self, run: dict, findings: list[Finding], *, remediation: dict | None = None) -> None:
        db = self.connect()
        try:
            with db:
                previous = db.execute("SELECT coverage FROM scan_runs WHERE workspace_id=? AND scope_id=? AND enumeration_complete=1 ORDER BY rowid DESC LIMIT 1",
                    (run["workspace_id"], run["scope_id"])).fetchone()
                evaluated = {f["file_id"] for f in run["coverage"] if f["status"] == "evaluated"}
                removed = set()
                enumerated = run.get('enumeration_complete', run['status'] == 'completed')
                if enumerated and previous:
                    removed = {f["file_id"] for f in json.loads(previous[0])} - {f["file_id"] for f in run["coverage"]}
                # Close only successfully evaluated files or files proven removed by a complete listing.
                for file_id in evaluated | removed:
                    db.execute("UPDATE scan_results SET status='RESOLVED' WHERE workspace_id=? AND file_id=? AND status='OPEN'",
                        (run["workspace_id"], file_id))
                db.execute("INSERT INTO scan_runs(id,workspace_id,scope_id,target,status,coverage,findings_count,enumeration_complete) VALUES(?,?,?,?,?,?,?,?)",
                    (run["id"], run["workspace_id"], run["scope_id"], sanitize_path(run["target"]), run["status"], json.dumps(run["coverage"]), len(findings), int(enumerated)))
                for f in findings:
                    data = asdict(f)
                    # Errors remain evidence, but never replace a prior evaluated file's findings.
                    row = (f.id, f.rule_name, f.severity, 'OPEN', f.frameworks[0] if f.frameworks else None,
                        json.dumps(f.frameworks), f.description, f.remediation, f.filename, f.rule_id, f.file_id,
                        run["workspace_id"], f.resource, f.line, f.column, f.end_line, f.source_digest, run["id"], int(f.remediation_eligible),
                        f.family, f.resource_key, f.resource_label, f.evidence)
                    db.execute("""INSERT INTO scan_results (finding_id,vulnerability_type,severity,status,compliance_framework,
                        compliance_frameworks,description,remediation,target_path,rule_id,file_id,workspace_id,resource,
                        source_line,source_column,end_line,source_digest,scan_id,remediation_eligible,family,resource_key,resource_label,evidence)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(finding_id) WHERE finding_id IS NOT NULL DO UPDATE SET
                        vulnerability_type=excluded.vulnerability_type,severity=excluded.severity,status='OPEN',
                        compliance_framework=excluded.compliance_framework,compliance_frameworks=excluded.compliance_frameworks,
                        description=excluded.description,remediation=excluded.remediation,target_path=excluded.target_path,
                        source_line=excluded.source_line,source_column=excluded.source_column,end_line=excluded.end_line,
                        source_digest=excluded.source_digest,scan_id=excluded.scan_id,remediation_eligible=excluded.remediation_eligible,
                        resource=excluded.resource,family=excluded.family,resource_key=excluded.resource_key,
                        resource_label=excluded.resource_label,evidence=excluded.evidence""", row)
                    db.execute("INSERT INTO scan_evidence VALUES(?,?,?)", (run["id"], f.id, json.dumps(data)))
                if remediation is not None:
                    self._insert_remediation(db, remediation)
        finally:
            db.close()

    def findings(self, *, open_only=False) -> list[dict]:
        db = self.connect()
        try:
            rows = db.execute("SELECT * FROM scan_results" + (" WHERE status='OPEN' OR status='Open'" if open_only else "") + " ORDER BY id").fetchall()
            latest = {row[0]: json.loads(row[1]) | {'recorded_at': row[2]} for row in db.execute('''
                SELECT finding_id,details,created_at FROM remediation_runs e
                WHERE e.rowid=(SELECT MAX(x.rowid) FROM remediation_runs x WHERE x.finding_id=e.finding_id)''')}
            return [self.dto(row, latest.get(row['finding_id'])) for row in rows]
        finally:
            db.close()

    @staticmethod
    def dto(row, verification=None) -> dict:
        from src.scanners.rule_catalog import details, family
        verification = dict(verification or {})
        state = verification.get('status', 'resolved_by_scan' if str(row['status'] or '').upper() == 'RESOLVED' else 'not_requested')
        if str(row['status'] or '').upper() == 'OPEN' and state in {'verified_resolved', 'resolved_with_findings'}:
            state = 'reopened'
        verification['state'] = state
        try:
            frameworks = json.loads(row["compliance_frameworks"] or "[]")
        except (ValueError, TypeError):
            frameworks = []
        if not isinstance(frameworks, list):
            frameworks = []
        if not frameworks and row["compliance_framework"]:
            frameworks = [row["compliance_framework"]]
        return {
            "id": row["finding_id"] or f"legacy-{row['id']}", "rule_id": row["rule_id"] or "legacy.unknown",
            "rule_name": sanitize_text(row["vulnerability_type"]), "severity": row["severity"],
            "filename": sanitize_path(row["target_path"] or "unknown"), "file": sanitize_path(row["target_path"] or "unknown"),
            "file_id": row["file_id"] or "", "workspace_id": row["workspace_id"] or "legacy",
            "frameworks": [sanitize_text(v) for v in frameworks], "compliance_framework": frameworks[0] if frameworks else "",
            "description": sanitize_text(row["description"]), "remediation": sanitize_text(row["remediation"]),
            "resource": row["resource"] or "unknown", "line": row["source_line"] or 1,
            "column": row["source_column"] or 1, "end_line": row["end_line"] or 1,
            "source_digest": row["source_digest"] or "", "scan_id": row["scan_id"] or "",
            "remediation_eligible": bool(row["remediation_eligible"]), "status": row["status"],
            "detected": row["timestamp"],
            'family': row['family'] or family(row['rule_id'] or 'legacy.unknown'),
            'resource_key': row['resource_key'] or '', 'resource_label': sanitize_text(row['resource_label'] or row['resource'] or 'unknown'),
            'evidence': sanitize_text(row['evidence'] or details(row['rule_id'] or 'legacy.unknown')[1]),
            'verification': verification,
        }

    @staticmethod
    def _insert_remediation(db, event: dict) -> None:
        safe = {key: sanitize_text(value, limit=2000) if isinstance(value, str) else value for key, value in event.items()}
        db.execute('INSERT INTO remediation_runs(id,finding_id,details) VALUES(?,?,?)',
            (safe['id'], safe['finding_id'], json.dumps(safe)))

    def record_remediation(self, event: dict) -> None:
        db = self.connect()
        try:
            with db:
                self._insert_remediation(db, event)
        finally:
            db.close()

    def remediations(self) -> list[dict]:
        db = self.connect()
        try:
            return [json.loads(row[0]) | {'recorded_at': row[1]} for row in db.execute('SELECT details,created_at FROM remediation_runs ORDER BY rowid DESC LIMIT 100')]
        finally:
            db.close()

    def get(self, finding_id: str) -> dict:
        values = [f for f in self.findings(open_only=True) if f["id"] == finding_id]
        if len(values) != 1:
            raise ValueError("Finding is not an open deterministic finding")
        return values[0]

    def history(self) -> list[dict]:
        db = self.connect()
        try:
            return [{**dict(r), "coverage": json.loads(r["coverage"]), "findings": r["findings_count"],
                "type": r["scan_type"], "time": r["timestamp"], "duration": "Recorded run"}
                for r in db.execute("SELECT * FROM scan_runs ORDER BY rowid DESC LIMIT 100")]
        finally:
            db.close()
