"""Palmerah Shield reverse proxy (S4): https://localhost:8443 -> web-legacy :8080, https://localhost:8444 -> web-modern :3000.

What it does to every response (docs/ASUMSI.md A5, A14):
* TLS 1.3 only, security headers added, Server / X-Powered-By removed.
* The caller's role comes from the website's RESPONSE header `X-Palmerah-Role` (set from its own authenticated session);
  `X-Palmerah-Member` names the member for role `anggota`. Both are removed before the response leaves the proxy, and the
  same headers sent by a client are dropped, so a browser can never choose its role. No role header = `public`.
* JSON bodies are filtered field by field with access_matrix.json: none -> removed, masked -> masked,
  full -> decrypted (AES-256-GCM envelope) or detokenised (vault) through the KMS, self -> full only on the member's own
  record. The website therefore never needs crypto code or keys. Keys: wrapped DEKs from `shield_keys`, unwrapped by the
  KMS (audited there); DEKs live only in this process's memory.
* An envelope or token under a key the matrix does not know is removed (fail closed). HTML is passed through unchanged:
  structural filtering needs JSON (limitation, written in the report).
* Audit: one line per response that revealed protected values (role, path, counts, never values) in
  .local/proxy/audit-<t>.log, plus an alert when one role decrypts more than ALERT_VALUES values per minute.
"""
from __future__ import annotations

import datetime as dt
import http.client
import json
import ssl
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import crypto
from .access import ROLES, ensure_matrix, field_for
from .apply import mask_value
from .config import LOCAL

PORTS = {"a": 8443, "b": 8444}
UPSTREAMS = {"a": "http://127.0.0.1:8080", "b": "http://127.0.0.1:3000"}
TABLE_HINT = {"a": "anggota", "b": None}         # website A: one wide table, so JSON keys are anggota columns
TOKEN_DOMAIN = {"nik": "nik", "account_no": "account_no", "ref_code": "nik"}
ROLE_HEADER, MEMBER_HEADER = "X-Palmerah-Role", "X-Palmerah-Member"
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}
DROP_RESPONSE = HOP | {"server", "x-powered-by", "content-length", ROLE_HEADER.lower(), MEMBER_HEADER.lower()}
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
}
ALERT_WINDOW_S, ALERT_VALUES = 60, 2000
MAX_BODY = 50_000_000


# ---------- policy ----------
class Policy:
    """JSON key -> canonical field -> level for a role (access_matrix.json)."""

    def __init__(self, matrix: dict, target: str):
        self.fields: dict[str, dict] = matrix["fields"]
        self.table = TABLE_HINT[target]

    def field(self, key: str) -> str | None:
        f = field_for(self.table, key) if self.table else key
        return f if f in self.fields else None

    def level(self, field: str, role: str) -> str:
        return self.fields.get(field, {}).get(role, "none")


# ---------- keys ----------
class Keys:
    """Envelope decryption and detokenisation through the KMS. `loader` returns [(key_id, name, wrapped)]."""

    def __init__(self, kms, loader):
        self.kms, self.loader = kms, loader
        self.wrapped: dict[str, tuple[str, str]] = {}
        self.deks: dict[str, bytes] = {}
        self.lock = threading.Lock()
        self.last_load = 0.0

    def _row(self, key_id: str) -> tuple[str, str] | None:
        with self.lock:
            if key_id not in self.wrapped and time.time() - self.last_load > 5:   # re-apply creates new keys
                self.wrapped = {k: (n, w) for k, n, w in self.loader()}
                self.last_load = time.time()
            return self.wrapped.get(key_id)

    def decrypt(self, envelope: str, pk_candidates: list) -> str | None:
        key_id, _ = crypto.parse(envelope)
        row = self._row(key_id)
        if not row:
            return None
        name, wrapped = row
        if key_id not in self.deks:
            self.deks[key_id] = self.kms.unwrap(key_id, name, wrapped)
        db, rest = name.split(":", 1)
        table, column = rest.rsplit(":", 1)[0].split(".", 1)
        for pk in pk_candidates:              # the AEAD tag proves which one is right; a wrong guess just fails
            try:
                return crypto.decrypt(self.deks[key_id], envelope, crypto.aad_for(db, table, column, pk))
            except Exception:
                continue
        return None

    def detokenize(self, domain: str, tokens: list[str]) -> list[str | None]:
        return self.kms.detokenize(domain, tokens) if tokens else []


# ---------- filtering ----------
def _member_of(obj: dict):
    return obj.get("member_id", obj.get("id"))


def filter_json(doc, role: str, member: str | None, policy: Policy, keys: Keys | None) -> tuple[object, dict]:
    """Return (filtered document, stats). Never raises on unknown shapes: unknown keys pass, unknown secrets go."""
    stats = {"removed": 0, "masked": 0, "decrypted": 0, "detokenized": 0, "failed": 0}
    pending: dict[str, list[tuple[dict, str, str]]] = defaultdict(list)    # domain -> [(obj, key, level)]

    def reveal(obj: dict, key: str, value, level: str):
        if crypto.is_envelope(value):
            plain = keys.decrypt(value, [p for p in (obj.get("member_id"), obj.get("id")) if p is not None]) if keys else None
            if plain is None:
                stats["failed"] += 1
                del obj[key]
                return
            stats["decrypted"] += 1
            if level == "masked":
                stats["masked"] += 1
                plain = mask_value(plain)
            obj[key] = plain
        elif level == "masked" and value is not None and "*" not in str(value):
            stats["masked"] += 1
            obj[key] = mask_value(value)

    def walk(node):
        if isinstance(node, list):
            for x in node:
                walk(x)
            return
        if not isinstance(node, dict):
            return
        for key in list(node):
            value = node[key]
            if isinstance(value, (dict, list)):
                walk(value)
                continue
            field = policy.field(key)
            if field is None:
                if crypto.is_envelope(value):          # a secret under a name the matrix does not know: fail closed
                    del node[key]
                    stats["removed"] += 1
                continue
            level = policy.level(field, role)
            if level == "self":
                level = "full" if member is not None and str(_member_of(node)) == str(member) else "none"
            if level == "none":
                del node[key]
                stats["removed"] += 1
                continue
            if field in TOKEN_DOMAIN and value is not None and not crypto.is_envelope(value) and "*" not in str(value):
                pending[TOKEN_DOMAIN[field]].append((node, key, level))
                continue
            reveal(node, key, value, level)

    walk(doc)
    for domain, items in pending.items():          # one KMS call per domain per response
        values = keys.detokenize(domain, [str(o[k]) for o, k, _ in items]) if keys else [None] * len(items)
        for (obj, key, level), plain in zip(items, values):
            if plain is None:                         # not a token (e.g. before apply): keep only if allowed in clear
                if level == "masked":
                    stats["masked"] += 1
                    obj[key] = mask_value(obj[key])
                continue
            stats["detokenized"] += 1
            if level == "masked":
                stats["masked"] += 1
                plain = mask_value(plain)
            obj[key] = plain
    return doc, stats


# ---------- audit ----------
class Audit:
    def __init__(self, path: Path):
        self.path = path
        self.recent: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def write(self, role: str, method: str, path: str, status: int, stats: dict) -> None:
        revealed = stats.get("decrypted", 0) + stats.get("detokenized", 0)
        if not revealed and not stats.get("failed") and not stats.get("removed"):
            return
        now = time.time()
        line = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "role": role, "method": method,
                "path": path.split("?", 1)[0], "status": status, **stats}
        with self.lock:
            q = self.recent[role]
            q.append((now, revealed))
            while q and now - q[0][0] > ALERT_WINDOW_S:
                q.popleft()
            burst = sum(n for _, n in q)
            if burst > ALERT_VALUES:
                line["alert"] = f"pembacaan massal: peran {role} membuka {burst} nilai dalam {ALERT_WINDOW_S} detik"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(line) + "\n")


# ---------- HTTP ----------
def make_handler(upstream: str, policy_fn, keys: Keys | None, audit: Audit):
    up = urlsplit(upstream)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "palmerah"
        sys_version = ""

        def log_message(self, *a):            # no request logging: URLs may carry identifiers
            pass

        def _proxy(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._error(413, "terlalu besar")
            body = self.rfile.read(n) if n else None
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in HOP and k.lower() not in (ROLE_HEADER.lower(), MEMBER_HEADER.lower(), "host", "accept-encoding")}
            headers.update({"Host": up.netloc, "Accept-Encoding": "identity", "X-Forwarded-Proto": "https",
                            "X-Forwarded-For": self.client_address[0]})
            try:
                conn = http.client.HTTPConnection(up.hostname, up.port or 80, timeout=60)
                conn.request(self.command, self.path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read(MAX_BODY + 1)
            except OSError:
                return self._error(502, "website tidak dapat dihubungi")
            role = resp.getheader(ROLE_HEADER, "public").strip().lower()
            if role not in ROLES:
                role = "public"
            member = resp.getheader(MEMBER_HEADER)
            ctype = (resp.getheader("Content-Type") or "").lower()
            stats: dict = {}
            if "json" in ctype and data:
                try:
                    doc, stats = filter_json(json.loads(data), role, member, policy_fn(), keys)
                    data = json.dumps(doc, ensure_ascii=False).encode("utf-8")
                except ValueError:
                    pass                          # not valid JSON: passed as is
                except Exception:
                    return self._error(502, "filter gagal: respons ditahan")   # fail closed
            audit.write(role, self.command, self.path, resp.status, stats)
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in DROP_RESPONSE:
                    self.send_header(k, v)
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _error(self, code: int, msg: str):
            body = json.dumps({"error": msg}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _proxy

    return Handler


def build(target: str, upstream: str | None = None, port: int | None = None, keys: Keys | None = None,
          policy_fn=None, tls: bool = True, audit_path: Path | None = None) -> ThreadingHTTPServer:
    if policy_fn is None:
        def policy_fn():          # re-read per request: a saved matrix applies at once, no restart
            return Policy(ensure_matrix()[0], target)
    if keys is None:
        from .apply import DIALECTS
        from .kms import Client
        d = DIALECTS[target]()

        def loader():
            with d.connect() as conn:
                cur = conn.cursor()
                try:
                    cur.execute("SELECT key_id, name, wrapped FROM shield_keys WHERE purpose = 'aead'")
                    return cur.fetchall()
                except Exception:
                    return []             # not applied yet: nothing to decrypt
        keys = Keys(Client(f"proxy-{target}"), loader)
    audit = Audit(audit_path or LOCAL / "proxy" / f"audit-{target}.log")
    srv = ThreadingHTTPServer(("127.0.0.1", port or PORTS[target]), make_handler(upstream or UPSTREAMS[target], policy_fn, keys, audit))
    if tls:
        from .devenv import CERTS
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(CERTS / "server.crt", CERTS / "server.key")
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)   # handshake in the handler thread
    return srv


def serve(target: str, upstream: str | None = None) -> None:
    from .devenv import ensure_certs, ensure_env
    ensure_env()
    ensure_certs()
    srv = build(target, upstream)
    print(f"Palmerah proxy {target.upper()}: https://localhost:{srv.server_address[1]} -> {upstream or UPSTREAMS[target]}", flush=True)
    srv.serve_forever()
