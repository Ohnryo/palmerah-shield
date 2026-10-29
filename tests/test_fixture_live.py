"""Live fixture checks: reset is fast and idempotent, both servers refuse plaintext, data lands as the contract says."""
import json
import ssl

import psycopg
import pymysql
import pytest

from palmerah_shield import devenv
from palmerah_shield.config import LOCAL, settings
from palmerah_shield.db import mysql_connect, pg_connect
from palmerah_shield.reset import reset

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def first_reset():
    return reset()


def test_reset_is_fast_and_idempotent(first_reset):
    second = reset()
    assert first_reset["rows"] == second["rows"]
    assert second["seconds"] < 30
    assert settings().mode_file.read_text().strip() == "MODE=vuln"


def test_counts(first_reset):
    assert first_reset["rows"]["website_a"]["anggota"] == 734
    b = first_reset["rows"]["website_b"]
    assert all(b[t] == 734 for t in ("members", "member_contacts", "member_finance", "member_family", "member_health"))
    assert b["users"] == 6


def test_servers_refuse_plaintext(first_reset):
    s = settings()
    with pytest.raises(pymysql.err.OperationalError):
        pymysql.connect(host="127.0.0.1", port=s.mysql_port, user="root", password=s.mysql_root_password, ssl_disabled=True)
    with pytest.raises(psycopg.OperationalError, match="no encryption"):
        psycopg.connect(host="127.0.0.1", port=s.pg_port, dbname="postgres", user="postgres",
                        password=s.pg_super_password, sslmode="disable", connect_timeout=5)


def test_servers_reject_an_unknown_ca(first_reset):
    s = settings()
    wrong = ssl.create_default_context()          # system CAs only: the test CA is not trusted
    with pytest.raises(pymysql.err.OperationalError):
        pymysql.connect(host="127.0.0.1", port=s.mysql_port, user="root", password=s.mysql_root_password, ssl=wrong)


def test_loaded_data_matches(first_reset):
    with mysql_connect() as c, c.cursor() as cur:
        cur.execute("SELECT no_ktp FROM anggota WHERE id = 1")
        a_nik = cur.fetchone()[0]
    with pg_connect() as c:
        b_nik = c.execute("SELECT nik FROM member_finance WHERE member_id = 1").fetchone()[0]
        trap = c.execute("SELECT count(*) FROM member_activities a JOIN member_finance f USING (member_id) WHERE a.ref_code = f.nik").fetchone()[0]
        roles = sorted(r[0] for r in c.execute("SELECT role FROM users"))
    assert a_nik == b_nik
    assert trap > 734
    assert roles == sorted(["humas", "keuangan", "sdm", "medis", "admin", "anggota"])
    creds = json.loads((LOCAL / "credentials.json").read_text())
    assert set(creds) == {f"{r}1" for r in roles}
