"""shield patch: correct prepared-statement diffs for the simple cases, honest manual items for the rest."""
import subprocess
from pathlib import Path

import pytest

from palmerah_shield.patch import _prepared, generate

PHP = Path(__file__).resolve().parents[2] / "benteng-platform" / ".tools" / "php84" / "php.exe"
DEMO = Path(__file__).resolve().parents[2] / "benteng-platform" / "targets" / "php-react-demo" / "public"


def test_like_suffix_moves_into_the_bound_value():
    out = "".join(_prepared("""$res = mysqli_query($db, "SELECT id FROM t WHERE nama LIKE '" . $q . "%' LIMIT " . $limit);\n"""))
    assert "LIKE ?" in out and "'?" not in out and "?%" not in out
    assert "$p1 = $q . '%';" in out and 'bind_param($st, "si", $p1, $limit)' in out    # by reference: variables only


def test_quoted_and_unquoted_parameters():
    out = "".join(_prepared("""$r = mysqli_query($db, "SELECT * FROM t WHERE a = '" . $a . "' AND id = " . $id);\n"""))
    assert '"SELECT * FROM t WHERE a = ? AND id = ?"' in out and 'bind_param($st, "si", $a, $id)' in out


def test_interpolated_or_unbalanced_sql_is_left_to_a_human():
    assert _prepared("""$r = mysqli_query($db, "SELECT * FROM t WHERE a = '$a'");\n""") is None
    assert _prepared("""$r = mysqli_query($db, "SELECT * FROM t WHERE a = '" . $a);\n""") is None


def test_generate_writes_guide_and_marks_review(tmp_path):
    r = generate("b", None, tmp_path)
    assert r["needs_human_review"] and (tmp_path / "patches" / "b" / "01-login-least-privilege.md").exists()


@pytest.mark.skipif(not DEMO.exists(), reason="php-react-demo target not present")
def test_against_the_php_demo_target(tmp_path):
    r = generate("a", DEMO, tmp_path)
    issues = {(f["file"], f["issue"].split(" (")[0].split(" lalu")[0]) for f in r["code_findings"]}
    assert ("api/member.php", "SQL dirangkai dari variabel") in issues and ("api/search.php", "SQL dirangkai dari variabel") in issues
    assert ("api/login.php", "SQL dirangkai dari variabel") in issues and ("api/login.php", "hash sandi md5/sha1") in issues
    assert any("login.php" in m for m in r["manual"])                     # split build/execute: not patched automatically
    work = tmp_path / "src"
    subprocess.run(["git", "init", "-q", str(work)], check=True)
    import shutil
    shutil.copytree(DEMO / "api", work / "api")
    subprocess.run(["git", "apply", "-p1", str(tmp_path / "patches" / "a" / "02-prepared-statements.diff")], cwd=work, check=True)
    if PHP.exists():
        for f in ("member.php", "search.php"):
            assert "No syntax errors" in subprocess.run([str(PHP), "-l", str(work / "api" / f)], capture_output=True, text=True).stdout
