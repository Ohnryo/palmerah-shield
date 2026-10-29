"""Palmerah Shield Console API (FastAPI). Second door to the same core as the CLI: every operation calls the same
functions and writes the same out/*.json files.

Security (docs/PLAN.md, "Keamanan konsol"):
* 127.0.0.1 only, HTTPS TLS 1.3 with the test CA; requests whose Host is not localhost/127.0.0.1 are refused
  (DNS rebinding).
* Login with the random token printed at start -> session cookie HttpOnly; Secure; SameSite=Strict. Every request that
  changes something also needs the X-CSRF-Token header returned at login.
* CSP 'self', no inline script or style; the UI renders data as text. The API only serves out/ files, which hold
  masked samples, never raw PII.
* apply / rollback / reset need the target name typed again (`confirm`) and every action is written to the console
  audit log (.local/console/audit.log).
* One operation at a time: the job runner takes the same OS lock as the CLI (ops.exclusive), so the two doors never
  run at once.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hmac
import json
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from .. import access, ops
from ..config import LOCAL, OUT, ROOT, settings

SESSION_COOKIE = "palmerah_session"
SESSION_TTL_S = 12 * 3600
LOGIN_FAILURES_MAX = 10              # then login is closed for LOGIN_LOCK_S
LOGIN_LOCK_S = 60
AUDIT_FILE = LOCAL / "console" / "audit.log"
DIST = ROOT / "web" / "dist"
TARGETS = {"a": {"name": "web-legacy", "db": "MySQL :3306 (web_legacy)", "url": "http://localhost:8080", "proxy": "https://localhost:8443"},
           "b": {"name": "web-modern", "db": "PostgreSQL :5432 (web_modern)", "url": "http://localhost:3000", "proxy": "https://localhost:8444"}}
# out/ files the UI may read (all written by Shield with masked samples only)
OUT_FILES = {f"{kind}_{t}": f"{kind}_{t}.json" for kind in ("inventory", "plan", "apply_report", "rollback") for t in TARGETS}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _mode(target: str) -> str:
    f = settings().mode_file.parent / f"MODE_{target}"
    try:
        return f.read_text(encoding="ascii").strip().split("=", 1)[1]
    except (OSError, IndexError):
        return "vuln"


# ---------- RedCheck results (Teman 2) ----------
def redcheck(out_dir: Path) -> dict:
    """Leak scoreboards from out/redcheck_<mode>.json (contract) or out/redcheck_<target>_<mode>.json (proposed, so
    A and B do not overwrite each other). Nothing is invented: missing files are reported as missing."""
    results = []
    for f in sorted(out_dir.glob("redcheck_*.json")):
        r = _read_json(f)
        if not isinstance(r, dict) or not isinstance(r.get("scoreboard"), dict):
            results.append({"file": f.name, "valid": False})
            continue
        findings = r.get("findings") if isinstance(r.get("findings"), list) else []
        results.append({
            "file": f.name, "valid": True, "target": str(r.get("target", "")), "mode": str(r.get("mode", "")),
            "scoreboard": {str(k): v for k, v in r["scoreboard"].items() if isinstance(v, (int, float))},
            "findings": len(findings),
            "failed": sum(1 for x in findings if isinstance(x, dict) and x.get("status") == "fail"),
            "modified_at": dt.datetime.fromtimestamp(f.stat().st_mtime, dt.timezone.utc).isoformat(timespec="seconds"),
        })
    return {"available": any(r["valid"] for r in results), "results": results}


# ---------- status ----------
def target_status(t: str, out_dir: Path) -> dict:
    files = {}
    for kind in ("inventory", "plan", "apply_report"):
        f = out_dir / f"{kind}_{t}.json"
        files[kind] = dt.datetime.fromtimestamp(f.stat().st_mtime, dt.timezone.utc).isoformat(timespec="seconds") if f.exists() else None
    inv, rep = _read_json(out_dir / f"inventory_{t}.json"), _read_json(out_dir / f"apply_report_{t}.json")
    summary: dict = {}
    if inv:
        summary["pii_columns"] = sum(1 for x in inv.get("findings", []) if x.get("detected_class") not in ("NON_PII", "PUBLIK"))
        summary["columns"] = len(inv.get("findings", []))
        m = inv.get("metrics", {}).get("content_only", {}).get("protect")
        if m:
            summary["recall_content_only"], summary["precision_content_only"] = m["recall"], m["precision"]
    mode = _mode(t)
    if rep and mode == "hardened":
        v = rep.get("rerun", {}).get("verification") or rep.get("verification", {})
        dump = v.get("dump_without_keys", {})
        summary["dump_found"], summary["dump_sampled"] = dump.get("found_in_dump"), dump.get("sample_values")
        summary["controls_tested"] = sum(1 for c in rep.get("controls", []) if c.get("status") == "[TESTED]")
        summary["controls_total"] = len(rep.get("controls", []))
    steps = ["scan", "plan", "apply"]
    done = {"scan": bool(files["inventory"]), "plan": bool(files["plan"]), "apply": mode == "hardened"}
    nxt = next((s for s in steps if not done[s]), None)
    return {"target": t, **TARGETS[t], "mode": mode, "files": files, "summary": summary, "next_step": nxt}


def services() -> dict:
    from ..devenv import port_open
    s = settings()
    kms_port = int(s.kms_url.rsplit(":", 1)[1])
    return {"mysql": port_open(s.mysql_port), "postgres": port_open(s.pg_port), "kms": port_open(kms_port),
            "web_a": port_open(8080), "web_b": port_open(3000), "proxy_a": port_open(8443), "proxy_b": port_open(8444)}


# ---------- jobs (one at a time; same lock as the CLI) ----------
class JobRequest(BaseModel):
    op: Literal["scan", "plan", "apply", "rollback", "reset"]
    target: Literal["a", "b"] | None = None
    confirm: str | None = None


class Login(BaseModel):
    token: str


class MatrixUpdate(BaseModel):
    fields: dict[str, dict[str, Literal["full", "masked", "none", "self"]]]


CONFIRM_NEEDED = {"apply", "rollback", "reset"}


def confirm_word(op: str, target: str | None) -> str:
    return "reset" if op == "reset" else TARGETS[target]["name"]


def _run_op(op: str, target: str | None, out_dir: Path) -> dict:
    if op == "scan":
        from ..scan import scan
        r = scan(target=target, out_dir=out_dir)
        return {"findings": len(r["findings"])}
    if op == "plan":
        from ..plan import plan
        r = plan(target, out_dir=out_dir)
        return {"by_control": {k: len(v) for k, v in r["by_control"].items()}, "needs_human_review": len(r["needs_human_review"])}
    if op == "apply":
        from ..apply import apply
        r = apply(target, out_dir=out_dir)
        return {"controls": [f"{c['status']} {c['control']}" for c in r["controls"]]}
    if op == "rollback":
        from ..apply import rollback
        return rollback(target, out_dir=out_dir)
    from ..reset import reset
    return reset()


class Runner:
    def __init__(self, out_dir: Path, run=_run_op):
        self.out_dir, self.run = out_dir, run
        self.jobs: dict[str, dict] = {}
        self.lock = threading.Lock()

    def active(self) -> dict | None:
        with self.lock:
            return next((j for j in self.jobs.values() if j["state"] == "running"), None)

    def start(self, req: JobRequest, who: str) -> dict:
        with self.lock:
            if any(j["state"] == "running" for j in self.jobs.values()):
                raise ops.Busy("operasi lain sedang berjalan di konsol")
            holder = ops.current()
            if holder:
                raise ops.Busy(f"operasi '{holder.get('op')}' sedang berjalan (CLI)")
            job = {"id": uuid.uuid4().hex[:12], "op": req.op, "target": req.target, "state": "running", "started_at": _now(),
                   "events": [], "result": None, "error": None}
            self.jobs[job["id"]] = job
        threading.Thread(target=self._work, args=(job, who), daemon=True).start()
        return job

    def _work(self, job: dict, who: str) -> None:
        def emit(e: dict) -> None:
            job["events"].append({"t": round(time.time(), 3), **e})
        audit(who, f"{job['op']}:start", job["target"])
        try:
            with ops.listening(emit):
                job["result"] = self.run(job["op"], job["target"], self.out_dir)
            job["state"] = "done"
        except ops.Busy as e:
            job["state"], job["error"] = "failed", str(e)
        except Exception as e:                     # error type + message from our own code; never request data
            job["state"], job["error"] = "failed", f"{type(e).__name__}: {str(e)[:300]}"
        job["finished_at"] = _now()
        emit({"step": "end", "state": job["state"]})
        audit(who, f"{job['op']}:{job['state']}", job["target"], job["error"])


def audit(who: str, action: str, target: str | None, detail: str | None = None) -> None:
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": _now(), "session": who, "action": action, "target": target, "detail": detail}) + "\n")


def _public(job: dict) -> dict:
    return {k: job[k] for k in ("id", "op", "target", "state", "started_at", "result", "error")} | {
        "finished_at": job.get("finished_at"), "events": job["events"]}


# ---------- app ----------
def create_app(token: str, out_dir: Path = OUT, runner: Runner | None = None, dist: Path = DIST) -> FastAPI:
    app = FastAPI(title="Palmerah Shield Console", docs_url=None, redoc_url=None, openapi_url=None)
    sessions: dict[str, dict] = {}
    failures = {"n": 0, "until": 0.0}
    runner = runner or Runner(out_dir)
    app.state.runner = runner

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = (request.headers.get("host") or "").rsplit(":", 1)[0]
        if host not in ("localhost", "127.0.0.1"):
            return JSONResponse({"error": "host tidak diizinkan"}, status_code=421)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def session(request: Request) -> dict:
        sid = request.cookies.get(SESSION_COOKIE, "")
        s = sessions.get(sid)
        if not s or s["expires"] < time.time():
            sessions.pop(sid, None)
            raise HTTPException(401, "belum login")
        if request.method not in ("GET", "HEAD") and not hmac.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"]):
            raise HTTPException(403, "token CSRF salah")
        return s

    @app.post("/api/session")
    def login(body: Login, response: Response):
        if failures["until"] > time.time():
            raise HTTPException(429, "terlalu banyak percobaan; tunggu sebentar")
        if not hmac.compare_digest(body.token.strip().encode(), token.encode()):
            failures["n"] += 1
            if failures["n"] >= LOGIN_FAILURES_MAX:
                failures.update(n=0, until=time.time() + LOGIN_LOCK_S)
            audit("-", "login:failed", None)
            raise HTTPException(401, "token salah")
        failures["n"] = 0
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        sessions[sid] = {"id": sid[:8], "csrf": csrf, "expires": time.time() + SESSION_TTL_S}
        response.set_cookie(SESSION_COOKIE, sid, max_age=SESSION_TTL_S, httponly=True, secure=True, samesite="strict", path="/")
        audit(sid[:8], "login", None)
        return {"csrf": csrf}

    @app.get("/api/session")
    def whoami(s: dict = Depends(session)):
        return {"authenticated": True, "csrf": s["csrf"]}

    @app.delete("/api/session")
    def logout(response: Response, request: Request, s: dict = Depends(session)):
        sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
        response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        audit(s["id"], "logout", None)
        return {"ok": True}

    @app.get("/api/status")
    def status(s: dict = Depends(session)):
        job = runner.active()
        return {"targets": [target_status(t, out_dir) for t in TARGETS], "services": services(),
                "operation": ({"op": job["op"], "target": job["target"], "source": "console", "id": job["id"]} if job
                              else ops.current()),
                "redcheck": redcheck(out_dir), "generated_at": _now()}

    @app.get("/api/redcheck")
    def scoreboard(s: dict = Depends(session)):
        return redcheck(out_dir)

    @app.get("/api/out/{name}")
    def out_file(name: str, s: dict = Depends(session)):
        if name not in OUT_FILES:
            raise HTTPException(404, "berkas tidak dikenal")
        r = _read_json(out_dir / OUT_FILES[name])
        if r is None:
            raise HTTPException(404, "belum ada: jalankan langkahnya dulu")
        return r

    @app.get("/api/matrix")
    def get_matrix(s: dict = Depends(session)):
        m, _ = access.ensure_matrix(access.MATRIX_FILE)
        return {"roles": m["roles"], "levels": m["levels"], "fields": m["fields"], "problems": access.validate(m)}

    @app.put("/api/matrix")
    def put_matrix(body: MatrixUpdate, s: dict = Depends(session)):
        """Change levels of existing fields only; a changed matrix takes effect after `plan` + `apply` again (VIEWs)."""
        if runner.active() or ops.current():
            raise HTTPException(409, "operasi sedang berjalan; tunggu selesai sebelum mengubah matriks")
        m, _ = access.ensure_matrix(access.MATRIX_FILE)
        unknown = sorted(set(body.fields) - set(m["fields"]))
        if unknown:
            raise HTTPException(422, f"field tidak dikenal: {unknown}")
        changed = []
        for f, row in body.fields.items():
            if set(row) != set(access.ROLES):
                raise HTTPException(422, f"{f}: semua peran harus diisi")
            new = {**m["fields"][f], **row}
            if new != m["fields"][f]:
                changed.append(f)
            m["fields"][f] = new
        problems = access.validate(m)
        if problems:
            raise HTTPException(422, "; ".join(problems[:3]))
        if changed:
            access.MATRIX_FILE.write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            audit(s["id"], "matrix:update", None, ",".join(changed)[:300])
        return {"changed": changed, "needs": "jalankan plan + apply ulang agar VIEW per peran mengikuti matriks"}

    @app.post("/api/jobs", status_code=202)
    def start_job(req: JobRequest, s: dict = Depends(session)):
        if req.op != "reset" and not req.target:
            raise HTTPException(422, "target wajib (a atau b)")
        if req.op in CONFIRM_NEEDED and (req.confirm or "").strip() != confirm_word(req.op, req.target):
            raise HTTPException(422, f"ketik '{confirm_word(req.op, req.target)}' untuk konfirmasi")
        try:
            return _public(runner.start(req, s["id"]))
        except ops.Busy as e:
            raise HTTPException(409, str(e)) from None

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str, s: dict = Depends(session)):
        job = runner.jobs.get(job_id)
        if not job:
            raise HTTPException(404, "tidak ada")
        return _public(job)

    @app.get("/api/jobs/{job_id}/events")
    async def job_events(job_id: str, request: Request, s: dict = Depends(session)):
        job = runner.jobs.get(job_id)
        if not job:
            raise HTTPException(404, "tidak ada")

        async def stream():
            sent = 0
            while True:
                while sent < len(job["events"]):
                    yield f"data: {json.dumps(job['events'][sent])}\n\n"
                    sent += 1
                if job["state"] != "running" and sent >= len(job["events"]):
                    return
                if await request.is_disconnected():
                    return
                await asyncio.sleep(0.25)
        return StreamingResponse(stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})

    # ---------- built UI (web/dist), single origin so CSP 'self' and SameSite=Strict just work ----------
    @app.get("/{path:path}", include_in_schema=False)
    def ui(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "tidak ada")
        if not dist.is_dir():
            return JSONResponse({"error": "UI belum di-build: cd web && npm ci && npm run build"}, status_code=503)
        f = (dist / path).resolve()
        if path and f.is_file() and f.is_relative_to(dist.resolve()):
            return FileResponse(f)
        return FileResponse(dist / "index.html", headers={"Cache-Control": "no-store"})

    return app


def serve(port: int = 8700) -> None:
    """HTTPS on 127.0.0.1 only, TLS 1.3, test CA certificate from `shield dev init`."""
    import ssl

    import uvicorn

    from ..devenv import CERTS, ensure_certs, ensure_env
    ensure_env()
    ensure_certs()
    token = secrets.token_urlsafe(24)
    config = uvicorn.Config(create_app(token), host="127.0.0.1", port=port, log_level="warning", access_log=False,
                            ssl_certfile=str(CERTS / "server.crt"), ssl_keyfile=str(CERTS / "server.key"))
    config.load()
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    print(f"Palmerah Shield Console: https://localhost:{port}\n"
          f"Token login (berlaku sampai proses ini berhenti): {token}\n"
          f"Browser perlu mempercayai CA uji: {CERTS / 'ca.crt'}", flush=True)
    uvicorn.Server(config).run()
