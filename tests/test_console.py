"""Console API: login, CSRF, Host check, security headers, confirmation, one job at a time, SSE, audit, out/ reads."""
import json
import shutil
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from palmerah_shield import ops
from palmerah_shield.console import server

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "out"
TOKEN = "t0ken-for-tests"


@pytest.fixture
def env(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    for f in EXAMPLES.glob("*_[ab].json"):
        shutil.copy(f, out / f.name)
    monkeypatch.setattr(ops, "LOCK_FILE", tmp_path / "op.lock")
    monkeypatch.setattr(ops, "INFO_FILE", tmp_path / "op.json")
    monkeypatch.setattr(server, "AUDIT_FILE", tmp_path / "audit.log")
    monkeypatch.setattr(server, "services", lambda: {"mysql": False})
    gate = threading.Event()
    calls = []

    def fake_run(op, target, out_dir):
        calls.append((op, target))
        ops.step("backup", database="x")
        gate.wait(5)
        return {"ok": True}

    app = server.create_app(TOKEN, out_dir=out, runner=server.Runner(out, run=fake_run), dist=tmp_path / "no-dist")
    return {"client": TestClient(app, base_url="https://localhost"), "out": out, "gate": gate, "calls": calls, "tmp": tmp_path}


def login(c: TestClient) -> dict:
    r = c.post("/api/session", json={"token": TOKEN})
    assert r.status_code == 200
    return {"X-CSRF-Token": r.json()["csrf"]}


def test_login_required_and_cookie_flags(env):
    c = env["client"]
    assert c.get("/api/status").status_code == 401
    assert c.post("/api/session", json={"token": "wrong"}).status_code == 401
    r = c.post("/api/session", json={"token": TOKEN})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie
    assert c.get("/api/status").status_code == 200


def test_login_is_closed_after_repeated_failures(env):
    c = env["client"]
    for _ in range(server.LOGIN_FAILURES_MAX):
        c.post("/api/session", json={"token": "wrong"})
    assert c.post("/api/session", json={"token": TOKEN}).status_code == 429


def test_foreign_host_refused(env):
    r = env["client"].get("/api/status", headers={"Host": "evil.example:8700"})
    assert r.status_code == 421


def test_security_headers(env):
    h = env["client"].get("/api/status").headers
    assert "default-src 'self'" in h["content-security-policy"] and "'unsafe-inline'" not in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff" and h["cache-control"] == "no-store"


def test_changes_need_csrf_header(env):
    c = env["client"]
    login(c)
    assert c.post("/api/jobs", json={"op": "scan", "target": "a"}).status_code == 403


def test_status_reads_out_files(env):
    c = env["client"]
    login(c)
    s = c.get("/api/status").json()
    a = next(t for t in s["targets"] if t["target"] == "a")
    assert a["files"]["inventory"] and a["summary"]["pii_columns"] > 0 and a["mode"] == "vuln" and a["next_step"] == "apply"
    assert s["redcheck"] == {"available": False, "results": []}


def test_redcheck_scoreboard_is_read_not_invented(env):
    c = env["client"]
    login(c)
    (env["out"] / "redcheck_vuln.json").write_text(json.dumps({
        "target": "http://localhost:3000", "mode": "vuln", "scoreboard": {"nik": 734, "rekening": 734, "note": "x"},
        "findings": [{"id": "F1", "status": "fail"}, {"id": "F2", "status": "pass"}]}), encoding="utf-8")
    (env["out"] / "redcheck_broken.json").write_text("{", encoding="utf-8")
    r = c.get("/api/redcheck").json()
    good = next(x for x in r["results"] if x["file"] == "redcheck_vuln.json")
    assert r["available"] and good["scoreboard"] == {"nik": 734, "rekening": 734} and good["failed"] == 1
    assert next(x for x in r["results"] if x["file"] == "redcheck_broken.json")["valid"] is False


def test_out_files_whitelisted(env):
    c = env["client"]
    login(c)
    assert c.get("/api/out/inventory_b").json()["target"] == "b"
    assert c.get("/api/out/..%2F..%2F.env").status_code == 404
    assert c.get("/api/out/credentials").status_code == 404


def test_apply_needs_typed_target_name(env):
    c = env["client"]
    h = login(c)
    assert c.post("/api/jobs", json={"op": "apply", "target": "b", "confirm": "b"}, headers=h).status_code == 422
    assert c.post("/api/jobs", json={"op": "reset", "confirm": "web-modern"}, headers=h).status_code == 422
    assert env["calls"] == []


def test_one_job_at_a_time_with_progress_and_audit(env):
    c = env["client"]
    h = login(c)
    r = c.post("/api/jobs", json={"op": "apply", "target": "b", "confirm": "web-modern"}, headers=h)
    assert r.status_code == 202
    job = r.json()["id"]
    assert c.post("/api/jobs", json={"op": "scan", "target": "a"}, headers=h).status_code == 409
    assert c.get("/api/status").json()["operation"]["op"] == "apply"
    env["gate"].set()
    with c.stream("GET", f"/api/jobs/{job}/events") as s:
        events = [json.loads(line[6:]) for line in s.iter_lines() if line.startswith("data: ")]
    assert [e["step"] for e in events] == ["backup", "end"] and events[-1]["state"] == "done"
    assert c.get(f"/api/jobs/{job}").json()["result"] == {"ok": True}
    log = [json.loads(x)["action"] for x in (env["tmp"] / "audit.log").read_text(encoding="utf-8").splitlines()]
    assert log == ["login", "apply:start", "apply:done"]


def test_job_refused_while_cli_holds_the_lock(env):
    import subprocess
    import sys
    import textwrap
    c = env["client"]
    h = login(c)
    code = textwrap.dedent(f"""
        import pathlib, sys, time
        from palmerah_shield import ops
        ops.LOCK_FILE = pathlib.Path({str(env['tmp'] / 'op.lock')!r})
        ops.INFO_FILE = pathlib.Path({str(env['tmp'] / 'op.json')!r})
        with ops.exclusive("apply"):
            print("held", flush=True)
            sys.stdin.readline()
    """)
    p = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout.readline().strip() == "held"
        r = c.post("/api/jobs", json={"op": "scan", "target": "a"}, headers=h)
        assert r.status_code == 409 and "CLI" in r.json()["detail"]
    finally:
        p.communicate("\n")


def test_ui_not_built_message(env):
    r = env["client"].get("/")
    assert r.status_code == 503
