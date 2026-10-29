"""Database connections. TLS with server-certificate verification is always on: the fixture servers refuse
plaintext, and Shield never sends credentials or data over an unverified channel."""
from __future__ import annotations

import ssl
from urllib.parse import unquote, urlparse

import psycopg
import pymysql

from .config import settings

MYSQL_DB = "web_legacy"     # website A (contract: PHP/MySQL, one wide table `anggota`)
PG_DB = "web_modern"        # website B (contract: Node/PG, normalised English schema)


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(settings().ca_cert))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def mysql_connect(database: str | None = MYSQL_DB, user: str = "root", password: str | None = None) -> pymysql.Connection:
    s = settings()
    return pymysql.connect(host="127.0.0.1", port=s.mysql_port, user=user,
                           password=s.mysql_root_password if password is None else password,
                           database=database, ssl=_tls_context(), charset="utf8mb4", autocommit=False)


def pg_connect(database: str = PG_DB, user: str = "postgres", password: str | None = None) -> psycopg.Connection:
    s = settings()
    return psycopg.connect(host="127.0.0.1", port=s.pg_port, dbname=database, user=user,
                           password=s.pg_super_password if password is None else password,
                           sslmode="verify-full", sslrootcert=str(s.ca_cert))


def connect_dsn(dsn: str):
    """mysql://user:pass@host:port/db or postgresql://user:pass@host:port/db -> (kind, connection)."""
    u = urlparse(dsn)
    user, pw, db = unquote(u.username or ""), unquote(u.password or ""), u.path.lstrip("/")
    if u.scheme in ("mysql", "mariadb"):
        return "mysql", pymysql.connect(host=u.hostname, port=u.port or 3306, user=user, password=pw, database=db,
                                        ssl=_tls_context(), charset="utf8mb4")
    if u.scheme in ("postgres", "postgresql"):
        return "pg", psycopg.connect(host=u.hostname, port=u.port or 5432, dbname=db, user=user, password=pw,
                                     sslmode="verify-full", sslrootcert=str(settings().ca_cert))
    raise ValueError(f"unsupported DSN scheme: {u.scheme}")
