import sqlite3

from src.services.scan_repository import ScanRepository
from src.services.scanning import scan_target

TF = 'resource "aws_db_instance" "audit" {\n publicly_accessible = true\n}\n'


def test_same_basename_clean_scan_and_history(tmp_path):
    root=tmp_path/'work';root.mkdir()
    repo=ScanRepository(tmp_path/'db.sqlite')
    for directory in ('a','b'):
        (root/directory).mkdir();(root/directory/'main.tf').write_text(TF)
    run, first=scan_target(root,root,'local',repo,isolated=False)
    assert len(repo.findings(open_only=True)) == 2
    assert len({f.id for f in first}) == 2 and len({f.file_id for f in first}) == 2
    (root/'a/main.tf').write_text(TF.replace('true','false'))
    scan_target(root,root/'a/main.tf','local',repo,isolated=False)
    active=repo.findings(open_only=True)
    assert len(active)==1 and active[0]['file']=='b/main.tf'
    assert len(repo.history()) == 2
    assert repo.history()[0]['findings']==0
    with sqlite3.connect(repo.path) as db:
        assert db.execute('SELECT COUNT(*) FROM scan_evidence').fetchone()[0] == 2


def test_partial_scan_retains_previous_evidence_and_removed_files(tmp_path):
    root=tmp_path/'work';root.mkdir();repo=ScanRepository(tmp_path/'db.sqlite')
    (root/'one.tf').write_text(TF);(root/'two.tf').write_text(TF)
    scan_target(root,root,'local',repo,isolated=False)
    (root/'one.tf').write_text('resource {')
    (root/'two.tf').write_text(TF.replace('true','false'))
    run,_=scan_target(root,root,'local',repo,isolated=False)
    assert run['status']=='partial'
    assert any(f['rule_id']=='terraform.public-database' and f['file']=='one.tf' for f in repo.findings(open_only=True))
    assert not any(f['file']=='two.tf' for f in repo.findings(open_only=True))
    (root/'one.tf').unlink()
    scan_target(root,root,'local',repo,isolated=False)
    assert not repo.findings(open_only=True)


def test_legacy_migration_preserves_history(tmp_path):
    from database.setup import initialize_database
    path=tmp_path/'legacy.db';initialize_database(path)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO scan_results(vulnerability_type,severity,status,compliance_framework) VALUES('legacy','HIGH','OPEN','CIS 1')")
    repo=ScanRepository(path)
    assert repo.findings()[0]['frameworks']==['CIS 1']
    assert repo.findings()[0]['remediation_eligible'] is False
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==5
        assert db.execute('SELECT COUNT(*) FROM remediation_runs').fetchone()[0] == 0


def test_unsupported_input_cannot_pass_gate(tmp_path):
    import pytest
    from src.scanners.iac_audit import run_iac_audit,IaCScannerError
    path=tmp_path/'note.txt';path.write_text('not infrastructure')
    with pytest.raises(IaCScannerError):run_iac_audit(str(path),persist=False)
