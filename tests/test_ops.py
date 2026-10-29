"""One operation at a time across processes (CLI + console), re-entrant inside one, and progress events."""
import subprocess
import sys
import textwrap

import pytest

from palmerah_shield import ops


@pytest.fixture(autouse=True)
def tmp_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(ops, "LOCK_FILE", tmp_path / "op.lock")
    monkeypatch.setattr(ops, "INFO_FILE", tmp_path / "op.json")
    return tmp_path


def test_reentrant_and_released():
    with ops.exclusive("plan"):
        with ops.exclusive("scan"):              # plan may call scan
            assert ops.current()["op"] == "plan"
    assert ops.current() is None
    with ops.exclusive("apply"):
        pass


def test_second_process_is_refused_while_held(tmp_lock):
    code = textwrap.dedent(f"""
        import pathlib, sys
        from palmerah_shield import ops
        ops.LOCK_FILE = pathlib.Path({str(tmp_lock / 'op.lock')!r})
        ops.INFO_FILE = pathlib.Path({str(tmp_lock / 'op.json')!r})
        try:
            with ops.exclusive("rollback"):
                print("got")
        except ops.Busy:
            print("busy")
    """)
    with ops.exclusive("apply"):
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
        assert out == "busy"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "got"


def test_other_thread_is_refused():
    import threading
    seen = []
    with ops.exclusive("apply"):
        def other():
            try:
                with ops.exclusive("reset"):
                    seen.append("got")
            except ops.Busy:
                seen.append("busy")
        t = threading.Thread(target=other)
        t.start()
        t.join()
    assert seen == ["busy"]


def test_stale_info_is_not_a_holder(tmp_lock):
    (tmp_lock / "op.json").write_text('{"op": "apply", "pid": 1}', encoding="utf-8")   # crashed holder
    assert ops.current() is None


def test_progress_only_reaches_the_listener():
    ops.step("ignored")                          # no listener: no-op
    got = []
    with ops.listening(got.append):
        ops.step("backup", database="web_modern")
    ops.step("after")
    assert got == [{"step": "backup", "database": "web_modern"}]
