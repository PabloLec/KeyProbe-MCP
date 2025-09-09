# tests/test_path_utils.py
import os
import pathlib
import pytest
from keyprobe.path_utils import validate_and_resolve, parse_file_uri, PathOutsideSandbox

def test_validate_in_allowlist(tmp_path):
    allow = [str(tmp_path)]
    target = tmp_path / "file.txt"
    target.write_text("ok")
    resolved = validate_and_resolve(str(target), allow)
    assert resolved == target.resolve()

def test_block_outside_allowlist(tmp_path):
    allow = [str(tmp_path)]
    outside = pathlib.Path(os.getcwd()) / "outside.txt"
    with pytest.raises(PathOutsideSandbox):
        validate_and_resolve(str(outside), allow)

def test_parse_file_uri(tmp_path):
    p = tmp_path / "a.txt"
    # existence non exigée pour la résolution ; on vérifie juste le parsing
    uri = f"file://{p}"
    got = parse_file_uri(uri)
    assert got == p
