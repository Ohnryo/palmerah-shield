"""Local fixture services for development without Docker: a test CA, MariaDB on :3306 and PostgreSQL on :5432,
both listening on 127.0.0.1 only and refusing connections without TLS. In Docker the same roles are played by
the compose services (see compose.yaml); the ports and database names are the contract's."""
from __future__ import annotations

import datetime as dt
import ipaddress
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import LOCAL, ROOT, read_env_file, settings, write_env_value

CERTS = LOCAL / "certs"
MYSQL_DATA = LOCAL / "mysql"
PG_DATA = LOCAL / "pg"
DETACHED = (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP) if sys.platform == "win32" else 0
EXE = ".exe" if sys.platform == "win32" else ""


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _wait(port: int, up: bool, seconds: float = 20) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if port_open(port) == up:
            return True
        time.sleep(0.25)
    return False


# ---------- secrets and certificates ----------
def ensure_env() -> None:
    """Create .env from .env.example and fill empty secrets with random values (never printed)."""
    env = ROOT / ".env"
    if not env.exists():
        shutil.copyfile(ROOT / ".env.example", env)
    current = read_env_file(env)
    for key in ("MYSQL_ROOT_PASSWORD", "PG_SUPER_PASSWORD", "KMS_TOKEN"):
        if not current.get(key):
            write_env_value(key, secrets.token_urlsafe(24), env)


def ensure_certs(days: int = 90) -> None:
    """Private test CA + a server certificate for localhost/127.0.0.1 (test-only material, gitignored)."""
    CERTS.mkdir(parents=True, exist_ok=True)
    if (CERTS / "server.crt").exists():
        return
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Palmerah Test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=days))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    srv = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
           .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
           .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
           .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    nokey = serialization.NoEncryption()
    (CERTS / "ca.crt").write_bytes(ca.public_bytes(pem))
    (CERTS / "ca.key").write_bytes(ca_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, nokey))
    (CERTS / "server.crt").write_bytes(srv.public_bytes(pem))
    (CERTS / "server.key").write_bytes(key.private_bytes(pem, serialization.PrivateFormat.TraditionalOpenSSL, nokey))


# ---------- MariaDB (MySQL protocol) ----------
def _mysql_ini(port: int) -> str:
    d, c = MYSQL_DATA.as_posix(), CERTS.as_posix()
    return f"""[mysqld]
datadir = {d}
port = {port}
bind-address = 127.0.0.1
skip-name-resolve
local_infile = 0
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
ssl_ca = {c}/ca.crt
ssl_cert = {c}/server.crt
ssl_key = {c}/server.key
tls_version = TLSv1.3
require_secure_transport = ON
log_error = {d}/mariadb.err
"""


def mysql_init() -> None:
    s = settings()
    if (MYSQL_DATA / "mysql").exists():
        return
    MYSQL_DATA.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(s.mariadb_home / "bin" / f"mariadb-install-db{EXE}"), f"--datadir={MYSQL_DATA}",
                    f"--password={s.mysql_root_password}"], check=True, capture_output=True)
    (MYSQL_DATA / "my.ini").write_text(_mysql_ini(s.mysql_port), encoding="ascii")


def mysql_start() -> None:
    s = settings()
    if port_open(s.mysql_port):
        return
    log = open(MYSQL_DATA / "stdout.log", "ab")
    subprocess.Popen([str(s.mariadb_home / "bin" / f"mariadbd{EXE}"), f"--defaults-file={MYSQL_DATA / 'my.ini'}"],
                     stdout=log, stderr=log, stdin=subprocess.DEVNULL, creationflags=DETACHED, close_fds=True)
    if not _wait(s.mysql_port, True):
        raise RuntimeError(f"MariaDB did not start; see {MYSQL_DATA / 'mariadb.err'}")
    from .db import mysql_connect
    with mysql_connect(database=None) as c, c.cursor() as cur:   # same intent as mysql_secure_installation
        cur.execute("DROP DATABASE IF EXISTS test")
        cur.execute("DELETE FROM mysql.global_priv WHERE User='' OR (User='root' AND Host NOT IN ('localhost','127.0.0.1'))")
        cur.execute("FLUSH PRIVILEGES")


def mysql_stop() -> None:
    s = settings()
    if not port_open(s.mysql_port):
        return
    from .db import mysql_connect
    with mysql_connect(database=None) as c, c.cursor() as cur:
        cur.execute("SHUTDOWN")
    _wait(s.mysql_port, False)


# ---------- PostgreSQL ----------
def pg_init() -> None:
    s = settings()
    if (PG_DATA / "PG_VERSION").exists():
        return
    pw = LOCAL / "pgpass.tmp"
    pw.write_text(s.pg_super_password, encoding="ascii")
    try:
        subprocess.run([str(s.pg_home / "bin" / f"initdb{EXE}"), "-D", str(PG_DATA), "-U", "postgres", "--auth=scram-sha-256",
                        f"--pwfile={pw}", "--encoding=UTF8", "--locale=C"], check=True, capture_output=True)
    finally:
        pw.unlink(missing_ok=True)
    with open(PG_DATA / "postgresql.conf", "a", encoding="utf-8") as f:
        f.write(f"""
# --- palmerah fixture ---
port = {s.pg_port}
listen_addresses = '127.0.0.1'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_min_protocol_version = 'TLSv1.3'
password_encryption = 'scram-sha-256'
log_statement = 'none'
""")
    (PG_DATA / "pg_hba.conf").write_text(
        "# TLS + SCRAM only, loopback only\nhostssl all all 127.0.0.1/32 scram-sha-256\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n",
        encoding="ascii")


def _pg_ctl(*args: str) -> subprocess.CompletedProcess:
    s = settings()
    return subprocess.run([str(s.pg_home / "bin" / f"pg_ctl{EXE}"), "-D", str(PG_DATA), *args],
                          capture_output=True, stdin=subprocess.DEVNULL, creationflags=DETACHED)


def pg_start() -> None:
    s = settings()
    if port_open(s.pg_port):
        return
    # PostgreSQL reads its certificate from the data directory; copy the current one on every start
    shutil.copyfile(CERTS / "server.crt", PG_DATA / "server.crt")
    shutil.copyfile(CERTS / "server.key", PG_DATA / "server.key")
    log = LOCAL / "pg-server.log"   # outside the data directory: crash recovery fsyncs every file in it
    if sys.platform == "win32":
        # a postmaster started from a console process receives that console's Ctrl+C when the caller exits
        # (exit 0xC000013A); Start-Process gives it no console at all
        exe = s.pg_home / "bin" / "pg_ctl.exe"
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"Start-Process -FilePath '{exe}' -ArgumentList '-D','\"{PG_DATA}\"','-l','\"{log}\"','start' -WindowStyle Hidden"],
                       check=True, capture_output=True)
    else:
        _pg_ctl("-l", str(log), "start")
    ready = [str(s.pg_home / "bin" / f"pg_isready{EXE}"), "-h", "127.0.0.1", "-p", str(s.pg_port)]
    end = time.time() + 30
    while subprocess.run(ready, capture_output=True).returncode != 0:   # the port opens before recovery ends
        if time.time() > end:
            raise RuntimeError(f"PostgreSQL did not start; see {LOCAL / 'pg-server.log'}")
        time.sleep(0.25)


def pg_stop() -> None:
    if port_open(settings().pg_port):
        _pg_ctl("stop", "-m", "fast")


# ---------- KMS (separate process; a separate container under Docker) ----------
KMS_DIR = LOCAL / "kms"


def _kms_port() -> int:
    return int(settings().kms_url.rsplit(":", 1)[1])


def kms_start() -> None:
    if port_open(_kms_port()):
        return
    KMS_DIR.mkdir(parents=True, exist_ok=True)
    log = open(KMS_DIR / "kms.out", "ab")
    p = subprocess.Popen([sys.executable, "-m", "palmerah_shield", "kms", "serve"], cwd=ROOT, stdout=log, stderr=log,
                         stdin=subprocess.DEVNULL, creationflags=DETACHED, close_fds=True)
    (KMS_DIR / "kms.pid").write_text(str(p.pid), encoding="ascii")
    if not _wait(_kms_port(), True):
        raise RuntimeError(f"KMS did not start; see {KMS_DIR / 'kms.out'}")


def kms_stop() -> None:
    pid_file = KMS_DIR / "kms.pid"
    if pid_file.exists() and port_open(_kms_port()):
        pid = pid_file.read_text().strip()
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", pid, "/F"], capture_output=True)
        else:
            import os
            import signal
            os.kill(int(pid), signal.SIGTERM)
        _wait(_kms_port(), False)
    pid_file.unlink(missing_ok=True)


# ---------- all ----------
def init() -> None:
    ensure_env()
    ensure_certs()
    mysql_init()
    pg_init()


def start() -> None:
    mysql_start()
    pg_start()
    kms_start()


def stop() -> None:
    kms_stop()
    mysql_stop()
    pg_stop()


def status() -> dict[str, bool]:
    s = settings()
    return {f"mysql :{s.mysql_port}": port_open(s.mysql_port), f"postgres :{s.pg_port}": port_open(s.pg_port),
            f"kms :{_kms_port()}": port_open(_kms_port())}
