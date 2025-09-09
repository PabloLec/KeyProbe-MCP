import pathlib
from keyprobe.path_utils import resolve_path, parse_file_uri

def test_resolve_path_basic(tmp_path):
    p = tmp_path / "file.txt"
    p.write_text("ok")
    r = resolve_path(str(p))
    assert r == p.resolve()

def test_parse_file_uri(tmp_path):
    p = tmp_path / "a.txt"
    uri = f"file://{p}"
    got = parse_file_uri(uri)
    assert got == p
