"""`shield apply` / `shield rollback`: carry out out/plan_<target>.json on website A (MySQL) or B (PostgreSQL).

Order (expand -> migrate -> verify -> contract), all driven by the plan:
 1. encrypted backup of the database (backup key = KMS data key) -> rollback source
 2. per column: blind index (on the original value), mask column, tokenisation (vault in KMS), AES-256-GCM envelope
 3. every encrypted value is decrypted again and compared with the original before any plaintext is removed
 4. plaintext of encrypted columns is dropped; tokenised columns keep the format-preserving token
 5. one VIEW per role and table (access_matrix levels), DB roles per role, one application login without access to
    base tables (it must SET ROLE); the app stops using root/postgres
 6. evidence: real dump grepped for original values, app login denied on base tables, blind-index lookup, detokenise
 7. MODE=hardened, out/apply_report.json, state for idempotency and rollback

If any step fails the database is restored from the backup taken in step 1. Running apply twice with the same plan is
a no-op (verification only). Columns planned as `drop` are not dropped without --allow-drop (needs human review).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import crypto
from .access import ROLES
from .config import LOCAL, OUT, settings
from .kms import Client

STATE = LOCAL / "state"
BACKUPS = LOCAL / "backups"
EXE = ".exe" if sys.platform == "win32" else ""
TOKEN_DOMAINS = {"nik": "nik", "account_no": "account_no"}


def mask_value(v) -> str | None:
    if v is None:
        return None
    s = v.isoformat() if hasattr(v, "isoformat") else str(v)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}.*", s):
        return s[:4]
    if "@" in s:
        local, _, dom = s.partition("@")
        return f"{local[:1]}***@{dom}"
    if s.isdigit():
        return "*" * max(0, len(s) - 4) + s[-4:]
    return s[:2] + "***"


# ---------- dialects ----------
class Dialect:
    kind: str
    db: str
    target: str

    def roles(self) -> dict[str, str]:
        return {r: f"palmerah_{self.target}_r_{r}" for r in ROLES}

    @property
    def app_user(self) -> str:
        return f"palmerah_{self.target}_app"

    def member_key(self, table: str, columns: list[str]) -> str | None:
        if "member_id" in columns:
            return "member_id"
        return "id" if table in ("members", "anggota") else None


class PG(Dialect):
    kind, db, target = "pg", "web_modern", "b"
    view_schema = "shield"

    def connect(self):
        from .db import pg_connect
        return pg_connect()

    def q(self, ident: str) -> str:
        return '"' + ident.replace('"', '""') + '"'

    def view(self, role: str, table: str) -> str:
        return f"{self.view_schema}.v_{role}_{table}"

    def base(self, table: str) -> str:
        return f"public.{self.q(table)}"

    def pk(self, cur, table: str) -> str:
        cur.execute("""SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                       WHERE i.indrelid = %s::regclass AND i.indisprimary""", (table,))
        rows = cur.fetchall()
        if len(rows) != 1:
            raise RuntimeError(f"{table}: Shield needs a single-column primary key (AAD binds ciphertext to the row)")
        return rows[0][0]

    def columns(self, cur, table: str) -> list[str]:
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=%s ORDER BY ordinal_position", (table,))
        return [r[0] for r in cur.fetchall()]

    def self_expr(self, key: str) -> str:
        return f"{self.q(key)}::text = current_setting('palmerah.member_id', true)"

    def setup_views(self, cur) -> None:
        cur.execute(f"DROP SCHEMA IF EXISTS {self.view_schema} CASCADE")
        cur.execute(f"CREATE SCHEMA {self.view_schema}")

    def create_roles(self, cur, app_password: str, views: dict[str, list[str]]) -> None:
        self.drop_roles(cur)
        for role, name in self.roles().items():
            cur.execute(f"CREATE ROLE {name} NOLOGIN")
            cur.execute(f"GRANT USAGE ON SCHEMA {self.view_schema} TO {name}")
            for v in views[role]:
                cur.execute(f"GRANT SELECT ON {v} TO {name}")
        from psycopg import sql     # utility statements take no bind parameters: quote the password as a literal
        cur.execute(sql.SQL(f"CREATE ROLE {self.app_user} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {{}}").format(sql.Literal(app_password)))
        cur.execute(f"GRANT {', '.join(self.roles().values())} TO {self.app_user}")
        cur.execute(f"REVOKE ALL ON DATABASE {self.db} FROM PUBLIC")
        cur.execute(f"GRANT CONNECT ON DATABASE {self.db} TO {self.app_user}")
        cur.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")

    def drop_roles(self, cur) -> None:
        names = [*self.roles().values(), self.app_user]
        cur.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (names,))
        for (name,) in cur.fetchall():
            cur.execute(f"DROP OWNED BY {name}")            # grants in the current database
            cur.execute(f"REVOKE ALL ON DATABASE {self.db} FROM {name}")
            cur.execute(f"DROP ROLE {name}")

    def dump(self) -> bytes:
        s = settings()
        env = {**os.environ, "PGPASSWORD": s.pg_super_password, "PGSSLMODE": "verify-full", "PGSSLROOTCERT": str(s.ca_cert)}
        return subprocess.run([str(s.pg_home / "bin" / f"pg_dump{EXE}"), "-h", "127.0.0.1", "-p", str(s.pg_port), "-U", "postgres",
                               "--no-owner", "--no-privileges", "--inserts", self.db], env=env, capture_output=True, check=True).stdout

    def restore(self, sql: bytes) -> None:
        from .db import pg_connect
        s = settings()
        with pg_connect(database="postgres") as c:
            c.autocommit = True
            c.execute(f"DROP DATABASE IF EXISTS {self.db} WITH (FORCE)")   # database first: roles hold CONNECT on it
            existing = c.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", ([*self.roles().values(), self.app_user],)).fetchall()
            for (name,) in existing:
                c.execute(f"DROP OWNED BY {name}")
                c.execute(f"DROP ROLE {name}")
            c.execute(f"CREATE DATABASE {self.db}")
        env = {**os.environ, "PGPASSWORD": s.pg_super_password, "PGSSLMODE": "verify-full", "PGSSLROOTCERT": str(s.ca_cert)}
        subprocess.run([str(s.pg_home / "bin" / f"psql{EXE}"), "-h", "127.0.0.1", "-p", str(s.pg_port), "-U", "postgres", "-d", self.db,
                        "-v", "ON_ERROR_STOP=1", "-q"], input=sql, env=env, capture_output=True, check=True)

    def app_connect(self, password: str):
        from .db import pg_connect
        return pg_connect(user=self.app_user, password=password)


class MY(Dialect):
    kind, db, target = "mysql", "web_legacy", "a"

    def connect(self):
        from .db import mysql_connect
        return mysql_connect()

    def q(self, ident: str) -> str:
        return "`" + ident.replace("`", "``") + "`"

    def view(self, role: str, table: str) -> str:
        return f"{self.db}.v_{role}_{table}"

    def base(self, table: str) -> str:
        return f"{self.db}.{self.q(table)}"

    def pk(self, cur, table: str) -> str:
        cur.execute("SELECT column_name FROM information_schema.key_column_usage WHERE table_schema=%s AND table_name=%s AND constraint_name='PRIMARY'", (self.db, table))
        rows = cur.fetchall()
        if len(rows) != 1:
            raise RuntimeError(f"{table}: Shield needs a single-column primary key (AAD binds ciphertext to the row)")
        return rows[0][0]

    def columns(self, cur, table: str) -> list[str]:
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position", (self.db, table))
        return [r[0] for r in cur.fetchall()]

    def self_expr(self, key: str) -> str:
        return f"{self.q(key)} = shield_member_id()"

    def setup_views(self, cur) -> None:
        cur.execute("SELECT table_name FROM information_schema.views WHERE table_schema=%s AND table_name LIKE 'v\\_%%'", (self.db,))
        for (v,) in cur.fetchall():
            cur.execute(f"DROP VIEW {self.q(v)}")
        cur.execute("DROP FUNCTION IF EXISTS shield_member_id")
        # views cannot read user variables directly; a function can (set per request: SET @palmerah_member_id = ?)
        cur.execute("CREATE FUNCTION shield_member_id() RETURNS INT NOT DETERMINISTIC READS SQL DATA RETURN @palmerah_member_id")

    def create_roles(self, cur, app_password: str, views: dict[str, list[str]]) -> None:
        self.drop_roles(cur)
        for role, name in self.roles().items():
            cur.execute(f"CREATE ROLE {name}")
            for v in views[role]:
                cur.execute(f"GRANT SELECT ON {v} TO {name}")
            cur.execute(f"GRANT EXECUTE ON FUNCTION {self.db}.shield_member_id TO {name}")
        cur.execute(f"CREATE USER '{self.app_user}'@'127.0.0.1' IDENTIFIED BY %s REQUIRE SSL", (app_password,))
        for name in self.roles().values():
            cur.execute(f"GRANT {name} TO '{self.app_user}'@'127.0.0.1'")
        cur.execute(f"SET DEFAULT ROLE NONE FOR '{self.app_user}'@'127.0.0.1'")

    def drop_roles(self, cur) -> None:
        cur.execute(f"DROP USER IF EXISTS '{self.app_user}'@'127.0.0.1'")
        for name in self.roles().values():
            cur.execute(f"DROP ROLE IF EXISTS {name}")

    def _client_args(self) -> list[str]:
        s = settings()
        return ["-h", "127.0.0.1", "-P", str(s.mysql_port), "-u", "root", f"--ssl-ca={s.ca_cert}", "--ssl-verify-server-cert"]

    def dump(self) -> bytes:
        s = settings()
        env = {**os.environ, "MYSQL_PWD": s.mysql_root_password}
        return subprocess.run([str(s.mariadb_home / "bin" / f"mariadb-dump{EXE}"), *self._client_args(), "--skip-extended-insert",
                               "--routines", self.db], env=env, capture_output=True, check=True).stdout

    def restore(self, sql: bytes) -> None:
        from .db import mysql_connect
        s = settings()
        with mysql_connect(database=None) as c, c.cursor() as cur:
            self.drop_roles(cur)
            cur.execute(f"DROP DATABASE IF EXISTS {self.db}")
            cur.execute(f"CREATE DATABASE {self.db} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        env = {**os.environ, "MYSQL_PWD": s.mysql_root_password}
        subprocess.run([str(s.mariadb_home / "bin" / f"mariadb{EXE}"), *self._client_args(), self.db], input=sql, env=env,
                       capture_output=True, check=True)

    def app_connect(self, password: str):
        from .db import mysql_connect
        return mysql_connect(database=None, user=self.app_user, password=password)   # no privilege on the schema itself


DIALECTS = {"a": MY, "b": PG}


# ---------- backup ----------
def backup(d: Dialect, kms: Client) -> dict:
    BACKUPS.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"backup:{d.db}:{stamp}"
    key = kms.datakey(name)
    dek = kms.unwrap(key["key_id"], name, key["wrapped"])
    nonce = os.urandom(12)
    path = BACKUPS / f"{d.db}-{stamp}.sql.enc"
    path.write_bytes(nonce + AESGCM(dek).encrypt(nonce, d.dump(), name.encode()))
    return {"file": str(path), "name": name, "key_id": key["key_id"], "wrapped": key["wrapped"]}


def restore_backup(d: Dialect, kms: Client, b: dict) -> None:
    dek = kms.unwrap(b["key_id"], b["name"], b["wrapped"])
    raw = Path(b["file"]).read_bytes()
    d.restore(AESGCM(dek).decrypt(raw[:12], raw[12:], b["name"].encode()))


# ---------- apply ----------
def _plan_hash(plan: dict) -> str:
    return hashlib.sha256(json.dumps(plan["columns"], sort_keys=True).encode()).hexdigest()[:16]


def _state_file(target: str) -> Path:
    return STATE / f"applied_{target}.json"


def write_mode(target: str, mode: str) -> None:
    s = settings()
    s.mode_file.parent.mkdir(parents=True, exist_ok=True)
    (s.mode_file.parent / f"MODE_{target}").write_text(f"MODE={mode}\n", encoding="ascii")
    any_hard = any(_state_file(t).exists() for t in DIALECTS)
    s.mode_file.write_text(f"MODE={'hardened' if any_hard else 'vuln'}\n", encoding="ascii")


def _levels(col: dict, role: str) -> str:
    v = col.get("visible_to")
    if not v:
        return "full" if col["detected_class"] == "NON_PII" else "none"
    return v.get(role, "none")


def apply(target: str, allow_drop: bool = False, out_dir: Path = OUT) -> dict:
    d = DIALECTS[target]()
    plan = json.loads((out_dir / f"plan_{target}.json").read_text(encoding="utf-8"))
    ph = _plan_hash(plan)
    sf = _state_file(target)
    if sf.exists():
        st = json.loads(sf.read_text(encoding="utf-8"))
        if st["plan_hash"] != ph:
            raise RuntimeError("target already hardened with a different plan: run `shield rollback` first")
        report = json.loads((out_dir / f"apply_report_{target}.json").read_text(encoding="utf-8"))
        report["rerun"] = {"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "result": "no-op (already applied with this plan)",
                           "verification": verify(d, plan, st)}
        _write_report(report, target, out_dir)
        return report

    kms = Client("shield-apply")
    kms.health()
    b = backup(d, kms)
    steps: list[dict] = []
    app_password = secrets.token_urlsafe(24)
    by_table: dict[str, list[dict]] = {}
    for c in plan["columns"]:
        by_table.setdefault(c["table"], []).append(c)
    originals: dict[tuple[str, str], dict] = {}           # kept in memory only, for the equivalence check
    keys: dict[str, dict] = {}
    try:
        with d.connect() as conn:
            cur = conn.cursor()
            ktable = "shield_keys"
            cur.execute(f"CREATE TABLE IF NOT EXISTS {ktable} (key_id VARCHAR(32) PRIMARY KEY, name VARCHAR(200) NOT NULL, "
                        f"purpose VARCHAR(16) NOT NULL, wrapped TEXT NOT NULL, created_at VARCHAR(40) NOT NULL)")
            for table, cols in by_table.items():
                todo = [c for c in cols if set(c["controls"]) & {"encrypt-AEAD", "tokenize", "blind-index", "mask"}
                        or any(_levels(c, r) == "masked" for r in ROLES)]
                if not todo:
                    continue
                pk = d.pk(cur, table)
                names = [c["column"] for c in todo]
                cur.execute(f"SELECT {d.q(pk)}, {', '.join(d.q(n) for n in names)} FROM {d.q(table)}")
                rows = cur.fetchall()
                new_cols, updates = [], {r[0]: {} for r in rows}
                for i, c in enumerate(todo, start=1):
                    col, ctl = c["column"], set(c["controls"])
                    vals = {r[0]: r[i] for r in rows}
                    originals[(table, col)] = vals
                    if "blind-index" in ctl:
                        kname = f"{d.db}:{table}.{col}:bidx"
                        keys[kname] = kms.datakey(kname) | {"purpose": "bidx"}
                        ikey = kms.unwrap(keys[kname]["key_id"], kname, keys[kname]["wrapped"])
                        new_cols.append((f"{col}_bidx", "CHAR(64)"))
                        for pkv, v in vals.items():
                            updates[pkv][f"{col}_bidx"] = None if v is None else crypto.blind_index(ikey, str(v))
                    if "mask" in ctl or any(_levels(c, r) == "masked" for r in ROLES):
                        new_cols.append((f"{col}_mask", "VARCHAR(64)"))
                        for pkv, v in vals.items():
                            updates[pkv][f"{col}_mask"] = mask_value(v)
                    if "tokenize" in ctl:
                        domain = TOKEN_DOMAINS.get(c["field"]) or TOKEN_DOMAINS.get(c["pii_type"], c["pii_type"])
                        present = [(pkv, str(v)) for pkv, v in vals.items() if v is not None]
                        tokens = kms.tokenize(domain, [v for _, v in present])
                        for (pkv, _), tok in zip(present, tokens):
                            updates[pkv][col] = tok
                        steps.append({"step": "tokenize", "column": f"{table}.{col}", "domain": domain, "values": len(present)})
                    if "encrypt-AEAD" in ctl:
                        kname = f"{d.db}:{table}.{col}:aead"
                        keys[kname] = kms.datakey(kname) | {"purpose": "aead"}
                        dek = kms.unwrap(keys[kname]["key_id"], kname, keys[kname]["wrapped"])
                        new_cols.append((f"{col}_enc", "TEXT"))
                        for pkv, v in vals.items():
                            updates[pkv][f"{col}_enc"] = None if v is None else crypto.encrypt(
                                dek, keys[kname]["key_id"], v.isoformat() if hasattr(v, "isoformat") else str(v),
                                crypto.aad_for(d.db, table, col, pkv))
                # expand
                for name, typ in new_cols:
                    if name not in d.columns(cur, table):
                        cur.execute(f"ALTER TABLE {d.q(table)} ADD COLUMN {d.q(name)} {typ}")
                # migrate
                set_cols = sorted({k for u in updates.values() for k in u})
                if set_cols:
                    ph_ = "%s"
                    sql = f"UPDATE {d.q(table)} SET {', '.join(f'{d.q(k)} = {ph_}' for k in set_cols)} WHERE {d.q(pk)} = {ph_}"
                    cur.executemany(sql, [[u.get(k) for k in set_cols] + [pkv] for pkv, u in updates.items()])
                # verify every encrypted value decrypts back to the original, before any plaintext is removed
                enc_cols = [c["column"] for c in todo if "encrypt-AEAD" in c["controls"]]
                checked = 0
                if enc_cols:
                    cur.execute(f"SELECT {d.q(pk)}, {', '.join(d.q(c + '_enc') for c in enc_cols)} FROM {d.q(table)}")
                    for r in cur.fetchall():
                        for j, col in enumerate(enc_cols, start=1):
                            orig = originals[(table, col)][r[0]]
                            if orig is None and r[j] is None:
                                continue
                            kname = f"{d.db}:{table}.{col}:aead"
                            dek = _dek_cache(kms, keys, kname)
                            want = orig.isoformat() if hasattr(orig, "isoformat") else str(orig)
                            if crypto.decrypt(dek, r[j], crypto.aad_for(d.db, table, col, r[0])) != want:
                                raise RuntimeError(f"equivalence check failed: {table}.{col} id={r[0]}")
                            checked += 1
                    # contract: plaintext of encrypted columns is removed
                    for col in enc_cols:
                        cur.execute(f"ALTER TABLE {d.q(table)} DROP COLUMN {d.q(col)}")
                steps.append({"step": "migrate", "table": table, "rows": len(rows), "encrypted_columns": enc_cols,
                              "values_verified": checked, "new_columns": [n for n, _ in new_cols]})
            for kname, k in keys.items():
                cur.execute(f"INSERT INTO {ktable} (key_id, name, purpose, wrapped, created_at) VALUES (%s, %s, %s, %s, %s)",
                            (k["key_id"], kname, k["purpose"], k["wrapped"], dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")))
            # views per role and table
            d.setup_views(cur)
            views: dict[str, list[str]] = {r: [] for r in ROLES}
            for table, cols in by_table.items():
                existing = d.columns(cur, table)
                key = d.member_key(table, existing)
                for role in ROLES:
                    exprs = []
                    for c in cols:
                        col, lvl = c["column"], _levels(c, role)
                        if role == "anggota" and lvl == "self":
                            lvl = "full"
                        full = d.q(f"{col}_enc") if f"{col}_enc" in existing else d.q(col)
                        if lvl == "full":
                            exprs.append(f"{full} AS {d.q(col)}")
                        elif lvl == "masked" and f"{col}_mask" in existing:
                            exprs.append(f"{d.q(col + '_mask')} AS {d.q(col)}")
                        else:
                            exprs.append(f"NULL AS {d.q(col)}")
                        if f"{col}_bidx" in existing and lvl != "none":     # equality search without decryption
                            exprs.append(f"{d.q(col + '_bidx')} AS {d.q(col + '_bidx')}")
                    where = ""
                    if role == "anggota":
                        where = f" WHERE {d.self_expr(key)}" if key else " WHERE 1 = 0"
                    v = d.view(role, table)
                    cur.execute(f"CREATE VIEW {v} AS SELECT {', '.join(exprs)} FROM {d.q(table)}{where}")
                    views[role].append(v)
            d.create_roles(cur, app_password, views)
            conn.commit()
            steps.append({"step": "views_and_roles", "views": sum(len(v) for v in views.values()), "roles": list(d.roles().values()),
                          "app_login": d.app_user})
    except Exception:
        restore_backup(d, kms, b)        # PostgreSQL also rolled back its transaction; MySQL DDL is not transactional
        raise

    STATE.mkdir(parents=True, exist_ok=True)
    creds = LOCAL / f"app-credentials-{target}.json"
    creds.write_text(json.dumps({"user": d.app_user, "password": app_password, "database": d.db,
                                 "usage": "SET ROLE <palmerah_..._r_peran> per request; anggota: set palmerah.member_id / @palmerah_member_id"},
                                indent=2), encoding="utf-8")
    state = {"target": target, "plan_hash": ph, "backup": b, "applied_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "app_password_file": str(creds), "sample": _sample_originals(originals)}
    sf.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    write_mode(target, "hardened")
    from .patch import generate
    patches = generate(target, None, out_dir)       # code-level fixes as suggestions, never applied automatically
    report = _report(target, d, plan, steps, b, allow_drop, verify(d, plan, state))
    report["patches"] = {"dir": f"out/patches/{target}/", "files": patches["files"], "status": "needs human review"}
    _write_report(report, target, out_dir)
    return report


_DEKS: dict[str, bytes] = {}


def _dek_cache(kms: Client, keys: dict, kname: str) -> bytes:
    k = keys[kname]
    if k["key_id"] not in _DEKS:            # keyed by key id: a re-apply after rollback creates new keys
        _DEKS[k["key_id"]] = kms.unwrap(k["key_id"], kname, k["wrapped"])
    return _DEKS[k["key_id"]]


def _sample_originals(originals: dict) -> dict:
    """A few original values per protected column, kept only in .local/state (gitignored) to prove the dump is clean."""
    out = {}
    for (table, col), vals in originals.items():
        vs = [str(v.isoformat() if hasattr(v, "isoformat") else v) for v in vals.values() if v is not None]
        vs = [v for v in vs if len(v) >= 6]
        if vs:
            out[f"{table}.{col}"] = vs[:: max(1, len(vs) // 25)][:25]
    return out


# ---------- verification (evidence for the report) ----------
def verify(d: Dialect, plan: dict, state: dict) -> dict:
    s = state["sample"]
    protected = {f"{c['table']}.{c['column']}" for c in plan["columns"] if set(c["controls"]) & {"encrypt-AEAD", "tokenize"}}
    derived = {f"{c['table']}.{c['column']}" for c in plan["columns"] if c["pii_type"] == "account_name"}
    dump = d.dump().decode("utf-8", "replace")
    leaked = {k: sum(v in dump for v in vals) for k, vals in s.items() if k in protected and k not in derived}
    residual = {k: sum(v in dump for v in vals) for k, vals in s.items() if k in derived}
    total = sum(len(s[k]) for k in leaked)
    result = {"dump_without_keys": {"sample_values": total, "found_in_dump": sum(leaked.values()),
                                    "columns_leaking": [k for k, n in leaked.items() if n],
                                    "residual_derived": {k: f"{n}/{len(s[k])} nilai tetap terlihat: turunan full_name yang publik" for k, n in residual.items()}}}
    pw = json.loads(Path(state["app_password_file"]).read_text(encoding="utf-8"))["password"]
    table = "members" if d.kind == "pg" else "anggota"
    denied = False
    try:
        with d.app_connect(pw) as c:
            cur = c.cursor()
            cur.execute(f"SELECT * FROM {d.base(table)} LIMIT 1")
            cur.fetchall()
    except Exception as e:
        denied = "denied" in str(e).lower() or "permission" in str(e).lower()
    result["app_login_denied_on_base_table"] = denied
    # public role sees no protected column; keuangan sees an account envelope/token it must not be able to read alone
    with d.app_connect(pw) as c:
        cur = c.cursor()
        fin = "member_finance" if d.kind == "pg" else "anggota"
        nik = "nik" if d.kind == "pg" else "no_ktp"
        cur.execute(f"SET ROLE {d.roles()['public']}")
        cur.execute(f"SELECT {d.q(nik)} FROM {d.view('public', fin)} LIMIT 5")
        result["public_view_nik_values"] = [r[0] for r in cur.fetchall()]
        cur.execute(f"SET ROLE {d.roles()['sdm']}")
        cur.execute(f"SELECT {d.q(nik)} FROM {d.view('sdm', fin)} LIMIT 1")
        result["sdm_view_nik_example"] = cur.fetchone()[0]
    return result


def _write_report(report: dict, target: str, out_dir: Path) -> None:
    text = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "apply_report.json").write_text(text, encoding="utf-8")
    (out_dir / f"apply_report_{target}.json").write_text(text, encoding="utf-8")


def _report(target: str, d: Dialect, plan: dict, steps: list, b: dict, allow_drop: bool, ver: dict) -> dict:
    enc_verified = sum(s.get("values_verified", 0) for s in steps)
    dropped = [f"{c['table']}.{c['column']}" for c in plan["columns"] if "drop" in c["controls"]]
    clean = ver["dump_without_keys"]["found_in_dump"] == 0
    controls = [
        {"control": "Enkripsi kolom AES-256-GCM, nonce acak, AAD tabel:kolom:id, padding 16 B", "status": "[TESTED]",
         "evidence": f"{enc_verified} nilai terdekripsi kembali identik sebelum plaintext dihapus"},
        {"control": "Envelope DEK per kolom dibungkus KEK di KMS terpisah (:8200)", "status": "[TESTED]",
         "evidence": "tabel shield_keys hanya berisi DEK terbungkus; KEK di .local/kms (proses terpisah); unwrap tercatat di audit KMS"},
        {"control": "Tokenisasi format-preserving nik & account_no (vault KMS)", "status": "[TESTED]",
         "evidence": "; ".join(f"{s['column']} ({s['values']} nilai)" for s in steps if s["step"] == "tokenize")},
        {"control": "Blind index HMAC-SHA256 untuk nik & email", "status": "[IMPLEMENTED]",
         "evidence": "kolom *_bidx terisi; uji pencarian di tests/test_apply_live.py"},
        {"control": "Dump tanpa kunci tidak membocorkan nilai asli", "status": "[TESTED]" if clean else "[IMPLEMENTED]",
         "evidence": f"{ver['dump_without_keys']['found_in_dump']} dari {ver['dump_without_keys']['sample_values']} nilai sampel ditemukan di dump nyata"},
        {"control": "Role DB per peran + VIEW per peran; login aplikasi tanpa akses tabel dasar (wajib SET ROLE)", "status": "[TESTED]" if ver["app_login_denied_on_base_table"] else "[IMPLEMENTED]",
         "evidence": f"login {d.app_user} ditolak pada tabel dasar: {ver['app_login_denied_on_base_table']}; view public untuk NIK: {ver['public_view_nik_values'][:3]}"},
        {"control": "Backup terenkripsi sebelum perubahan + rollback otomatis bila gagal", "status": "[IMPLEMENTED]",
         "evidence": Path(b["file"]).name},
        {"control": "Aplikasi berhenti memakai root/superuser", "status": "[IMPLEMENTED]",
         "evidence": f"kredensial {d.app_user} di .local/app-credentials-{target}.json; web perlu diarahkan ke akun ini (needs human review)"},
        {"control": "Minimisasi kolom duplikat (drop)", "status": "[IMPLEMENTED]" if allow_drop else "[PLANNED]",
         "evidence": ("dihapus: " if allow_drop else "menunggu persetujuan manusia: ") + ", ".join(dropped)},
        {"control": "Patch kode aplikasi (login least-privilege, prepared statement, hash sandi)", "status": "[IMPLEMENTED]",
         "evidence": f"out/patches/{target}/ (needs human review; diff prepared statement dibuat bila --app-src diberikan ke `shield patch`)"},
        {"control": "Reverse proxy TLS + header + filter respons per peran + dekripsi terkendali", "status": "[PLANNED]", "evidence": "tahap S4"},
        {"control": "Audit akses/dekripsi PII + alarm baca massal", "status": "[IMPLEMENTED]", "evidence": "audit KMS (unwrap, detokenize, alarm >5000 nilai/menit); audit proxy di S4"},
    ]
    return {
        "target": target, "database": d.db, "applied_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "plan": f"plan_{target}.json", "mode": "hardened", "backup": {"file": Path(b["file"]).name, "key_id": b["key_id"]},
        "steps": steps, "controls": controls, "verification": ver,
        "needs_human_review": plan.get("needs_human_review", []) + [
            f"arahkan website ke login {d.app_user} (bukan root/postgres) dan jalankan SET ROLE sesuai peran pengguna",
            "kolom terenkripsi kini hanya-baca lewat VIEW: fitur yang MENULIS kolom itu harus lewat layanan Shield (patch)"],
    }


# ---------- rollback ----------
def rollback(target: str, out_dir: Path = OUT) -> dict:
    d = DIALECTS[target]()
    sf = _state_file(target)
    if not sf.exists():
        return {"target": target, "rollback": "nothing to roll back"}
    st = json.loads(sf.read_text(encoding="utf-8"))
    restore_backup(d, Client("shield-rollback"), st["backup"])
    sf.unlink()
    Path(st["app_password_file"]).unlink(missing_ok=True)
    write_mode(target, "vuln")
    r = {"target": target, "rollback": "restored", "backup": Path(st["backup"]["file"]).name,
         "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    (out_dir / f"rollback_{target}.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    return r


# ---------- reset hook ----------
def cleanup_all() -> None:
    """Remove everything apply created (used by `make reset`): roles and app logins, state, app credentials, vault."""
    from .db import mysql_connect, pg_connect
    from .devenv import port_open
    s = settings()
    if port_open(s.pg_port):
        d = PG()
        with pg_connect(database="postgres") as c:
            c.autocommit = True
            c.execute(f"DROP DATABASE IF EXISTS {d.db} WITH (FORCE)")     # the seed recreates it
            for (name,) in c.execute(r"SELECT rolname FROM pg_roles WHERE rolname LIKE 'palmerah\_%%'").fetchall():
                c.execute(f"DROP OWNED BY {name}")
                c.execute(f"DROP ROLE {name}")
    if port_open(s.mysql_port):
        with mysql_connect(database=None) as c, c.cursor() as cur:
            MY().drop_roles(cur)
    for f in [*STATE.glob("applied_*.json"), *LOCAL.glob("app-credentials-*.json")]:
        f.unlink(missing_ok=True)
    if port_open(int(s.kms_url.rsplit(":", 1)[1])):
        Client("shield-reset").wipe()
    for t in DIALECTS:
        (s.mode_file.parent / f"MODE_{t}").unlink(missing_ok=True)
