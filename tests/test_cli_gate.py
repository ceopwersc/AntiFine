import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize('content,suffix,expected', [
    ('resource "aws_db_instance" "audit" {\n publicly_accessible = true\n}\n','.tf',1),
    ('resource "aws_db_instance" "audit" {\n publicly_accessible = false\n}\n','.tf',0),
    ('not infrastructure','.txt',1),
])
def test_cli_exit_policy(tmp_path,content,suffix,expected):
    source=tmp_path/('fixture'+suffix);source.write_text(content)
    process=subprocess.run([sys.executable,'-m','src.cli.gate','--file',str(source),'--fail-on','CRITICAL'],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=15)
    assert process.returncode==expected
    assert 'appears compliant' not in process.stdout
