"""Mini KMS: a separate process (container in Docker) that holds the KEK and the token vault. Internal only.

The KEK never leaves this process. Shield and the proxy ask it to create and unwrap per-column data keys (DEKs) and to
tokenise / detokenise nik and account_no. Every unwrap and detokenise is written to an audit log, and a burst of
detokenisations by one caller raises an alert line (mass-dump detection).

HTTP API (Authorization: Bearer <KMS_TOKEN>; X-Caller names the client for the audit log):
  GET  /v1/health
  POST /v1/datakey    {"name": "web_modern:member_contacts.email:aead"}  -> {"key_id", "wrapped"}
  POST /v1/unwrap     {"key_id", "name", "wrapped"}                      -> {"dek"}
  POST /v1/tokenize   {"domain": "nik", "values": [...]}                 -> {"tokens": [...]}
  POST /v1/detokenize {"domain": "nik", "tokens": [...]}                 -> {"values": [...]}
  POST /v1/admin/wipe {}                                                 -> vault + audit emptied (demo reset)
  GET  /v1/status   (auth)  -> kek_id, tokens per domain, audit line/alert counts   (never key material)
  GET  /v1/audit?limit=N (auth) -> last N audit lines (caller, op, subject, count; never values)
"""
from __future__ import annotations

import base64
import datetime as dt
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import LOCAL, settings

STATE = LOCAL / "kms"
ALERT_WINDOW_S = 60
ALERT_VALUES = 5000          # detokenised values per caller per minute before an alert is written


def _subkey(kek: bytes, label: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label.encode()).derive(kek)


class Vault:
    """Format-preserving tokens: same length, same character class; stable per (domain, value); originals encrypted."""

    def __init__(self, path: Path, kek: bytes):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS tokens (domain TEXT, lookup TEXT, token TEXT, value_enc BLOB, "
                        "PRIMARY KEY (domain, lookup), UNIQUE (domain, token))")
        self.lookup_key, self.enc = _subkey(kek, "vault-lookup"), AESGCM(_subkey(kek, "vault-enc"))
        self.lock = threading.Lock()

    def _new_token(self, domain: str, value: str) -> str:
        while True:
            tok = "".join(secrets.choice("0123456789") if ch.isdigit() else
                          secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") if ch.isupper() else
                          secrets.choice("abcdefghijklmnopqrstuvwxyz") if ch.islower() else ch for ch in value)
            if tok != value and not self.db.execute("SELECT 1 FROM tokens WHERE domain=? AND token=?", (domain, tok)).fetchone():
                return tok

    def tokenize(self, domain: str, values: list[str]) -> list[str]:
        out = []
        with self.lock, self.db:
            for v in values:
                lk = hmac.new(self.lookup_key, f"{domain}\x00{v}".encode(), "sha256").hexdigest()
                row = self.db.execute("SELECT token FROM tokens WHERE domain=? AND lookup=?", (domain, lk)).fetchone()
                if row:
                    out.append(row[0])
                    continue
                tok = self._new_token(domain, v)
                nonce = os.urandom(12)
                self.db.execute("INSERT INTO tokens VALUES (?,?,?,?)",
                                (domain, lk, tok, nonce + self.enc.encrypt(nonce, v.encode(), f"{domain}:{tok}".encode())))
                out.append(tok)
        return out

    def detokenize(self, domain: str, tokens: list[str]) -> list[str | None]:
        out = []
        for t in tokens:
            row = self.db.execute("SELECT value_enc FROM tokens WHERE domain=? AND token=?", (domain, t)).fetchone()
            out.append(self.enc.decrypt(row[0][:12], row[0][12:], f"{domain}:{t}".encode()).decode() if row else None)
        return out

    def wipe(self) -> None:
        with self.lock, self.db:
            self.db.execute("DELETE FROM tokens")

    def counts(self) -> dict[str, int]:
        return dict(self.db.execute("SELECT domain, COUNT(*) FROM tokens GROUP BY domain").fetchall())


class KMS:
    def __init__(self, state: Path = STATE):
        state.mkdir(parents=True, exist_ok=True)
        kek_file = state / "kek.bin"
        if not kek_file.exists():
            kek_file.write_bytes(os.urandom(32))
            try:
                os.chmod(kek_file, 0o600)
            except OSError:
                pass
        kek = kek_file.read_bytes()
        self.kek_id = hmac.new(kek, b"kek-id", "sha256").hexdigest()[:12]
        self.wrap = AESGCM(_subkey(kek, "dek-wrap"))
        self.vault = Vault(state / "vault.db", kek)
        self.audit_file = state / "audit.log"
        self.recent: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def audit(self, caller: str, op: str, subject: str, count: int) -> None:
        now = time.time()
        line = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "caller": caller, "op": op,
                "subject": subject, "count": count}
        with self.lock:
            q = self.recent[caller]
            if op == "detokenize":
                q.append((now, count))
            while q and now - q[0][0] > ALERT_WINDOW_S:
                q.popleft()
            burst = sum(c for _, c in q)
            if burst > ALERT_VALUES:
                line["alert"] = f"pembacaan massal: {burst} nilai didetokenisasi dalam {ALERT_WINDOW_S} detik"
            with open(self.audit_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(line) + "\n")

    def audit_tail(self, limit: int) -> list[dict]:
        try:
            lines = self.audit_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        return [json.loads(x) for x in lines[-limit:] if x.strip()]

    def status(self) -> dict:
        try:
            lines = self.audit_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        return {"kek_id": self.kek_id, "tokens": self.vault.counts(), "audit_lines": len(lines),
                "alerts": sum('"alert"' in x for x in lines)}

    def datakey(self, name: str) -> dict:
        dek, nonce = os.urandom(32), os.urandom(12)
        key_id = secrets.token_hex(6)
        wrapped = nonce + self.wrap.encrypt(nonce, dek, f"{key_id}:{name}".encode())
        return {"key_id": key_id, "wrapped": base64.b64encode(wrapped).decode()}

    def unwrap(self, key_id: str, name: str, wrapped: str) -> dict:
        raw = base64.b64decode(wrapped)
        return {"dek": base64.b64encode(self.wrap.decrypt(raw[:12], raw[12:], f"{key_id}:{name}".encode())).decode()}


def serve(port: int | None = None) -> None:
    s = settings()
    if not s.kms_token:
        raise SystemExit("KMS_TOKEN missing in .env (run: shield dev init)")
    kms = KMS()
    token = s.kms_token.encode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):            # no request logging to stdout: payloads may hold identifiers
            pass

        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorised(self) -> bool:
            got = self.headers.get("Authorization", "").removeprefix("Bearer ").encode()
            return hmac.compare_digest(got, token)

        def do_GET(self):
            if self.path == "/v1/health":
                return self._send(200, {"ok": True, "kek_id": kms.kek_id})
            if not self._authorised():
                return self._send(401, {"error": "unauthorised"})
            if self.path == "/v1/status":
                return self._send(200, kms.status())
            if self.path.startswith("/v1/audit"):
                try:
                    limit = max(1, min(500, int(self.path.partition("limit=")[2] or 100)))
                except ValueError:
                    limit = 100
                return self._send(200, {"lines": kms.audit_tail(limit)})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._authorised():
                return self._send(401, {"error": "unauthorised"})
            caller = self.headers.get("X-Caller", "unknown")[:40]
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n > 8_000_000:
                    return self._send(413, {"error": "too large"})
                req = json.loads(self.rfile.read(n) or b"{}")
                if self.path == "/v1/datakey":
                    r = kms.datakey(req["name"])
                    kms.audit(caller, "datakey", req["name"], 1)
                elif self.path == "/v1/unwrap":
                    r = kms.unwrap(req["key_id"], req["name"], req["wrapped"])
                    kms.audit(caller, "unwrap", req["name"], 1)
                elif self.path == "/v1/tokenize":
                    r = {"tokens": kms.vault.tokenize(req["domain"], req["values"])}
                    kms.audit(caller, "tokenize", req["domain"], len(req["values"]))
                elif self.path == "/v1/detokenize":
                    r = {"values": kms.vault.detokenize(req["domain"], req["tokens"])}
                    kms.audit(caller, "detokenize", req["domain"], len(req["tokens"]))
                elif self.path == "/v1/admin/wipe":
                    kms.vault.wipe()
                    kms.audit_file.write_text("", encoding="utf-8")
                    r = {"wiped": True}
                else:
                    return self._send(404, {"error": "not found"})
                self._send(200, r)
            except Exception as e:                       # error type only: never echo request values
                self._send(400, {"error": type(e).__name__})

    ThreadingHTTPServer(("127.0.0.1", port or int(s.kms_url.rsplit(":", 1)[1])), Handler).serve_forever()


class Client:
    def __init__(self, caller: str = "shield"):
        s = settings()
        self.url, self.token, self.caller = s.kms_url.rstrip("/"), s.kms_token, caller

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {self.token}", "X-Caller": self.caller,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    def health(self) -> dict:
        with urllib.request.urlopen(self.url + "/v1/health", timeout=5) as r:
            return json.loads(r.read())

    def datakey(self, name: str) -> dict:
        return self._post("/v1/datakey", {"name": name})

    def unwrap(self, key_id: str, name: str, wrapped: str) -> bytes:
        return base64.b64decode(self._post("/v1/unwrap", {"key_id": key_id, "name": name, "wrapped": wrapped})["dek"])

    def tokenize(self, domain: str, values: list[str]) -> list[str]:
        out: list[str] = []
        for i in range(0, len(values), 5000):
            out += self._post("/v1/tokenize", {"domain": domain, "values": values[i:i + 5000]})["tokens"]
        return out

    def detokenize(self, domain: str, tokens: list[str]) -> list[str | None]:
        return self._post("/v1/detokenize", {"domain": domain, "tokens": tokens})["values"]

    def wipe(self) -> None:
        self._post("/v1/admin/wipe", {})

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(self.url + path, headers={"Authorization": f"Bearer {self.token}", "X-Caller": self.caller})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def status(self) -> dict:
        return self._get("/v1/status")

    def audit(self, limit: int = 100) -> list[dict]:
        return self._get(f"/v1/audit?limit={int(limit)}")["lines"]
