"""shield apply / rollback on the live fixtures (website A on MySQL, B on PostgreSQL) with the KMS running."""
import hashlib
import json

import pytest

from palmerah_shield import crypto
from palmerah_shield.apply import DIALECTS, apply, rollback
from palmerah_shield.config import LOCAL, settings
from palmerah_shield.db import mysql_connect, pg_connect
from palmerah_shield.kms import Client
from palmerah_shield.plan import plan
from palmerah_shield.reset import reset
from palmerah_shield.scan import scan

pytestmark = pytest.mark.live
TABLES = {"a": ["anggota"], "b": ["members", "member_contacts", "member_finance", "member_family", "member_health", "member_activities", "users"]}


def fingerprint(t):
    if t == "b":
        with pg_connect() as c:
            return {x: hashlib.sha256(repr(c.execute(f"SELECT * FROM {x} ORDER BY 1").fetchall()).encode()).hexdigest() for x in TABLES[t]}
    with mysql_connect() as c, c.cursor() as cur:
        cur.execute("SELECT * FROM anggota ORDER BY 1")
        return {"anggota": hashlib.sha256(repr(cur.fetchall()).encode()).hexdigest()}


@pytest.fixture(scope="module")
def applied():
    reset()
    before, reports = {}, {}
    for t in ("a", "b"):
        scan(target=t)
        plan(t)
        before[t] = fingerprint(t)
        reports[t] = apply(t)
    yield before, reports
    reset()


def app(t):
    d = DIALECTS[t]()
    pw = json.loads((LOCAL / f"app-credentials-{t}.json").read_text())["password"]
    return d, d.app_connect(pw)


@pytest.mark.parametrize("t", ["a", "b"])
def test_dump_without_keys_has_no_original_values(applied, t):
    v = applied[1][t]["verification"]["dump_without_keys"]
    assert v["sample_values"] >= 300 and v["found_in_dump"] == 0, v
    statuses = {c["control"]: c["status"] for c in applied[1][t]["controls"]}
    assert all(s in ("[TESTED]", "[IMPLEMENTED]", "[PLANNED]") for s in statuses.values())
    assert any("Dump tanpa kunci" in k and s == "[TESTED]" for k, s in statuses.items())


@pytest.mark.parametrize("t", ["a", "b"])
def test_every_encrypted_value_was_verified(applied, t):
    assert sum(s.get("values_verified", 0) for s in applied[1][t]["steps"]) > 10_000


def test_plaintext_columns_are_gone_from_base_tables(applied):
    with pg_connect() as c:
        cols = {r[0] for r in c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='members'")}
    assert "religion" not in cols and "religion_enc" in cols
    with mysql_connect() as c, c.cursor() as cur:
        cur.execute("SELECT agama_enc, no_ktp FROM anggota WHERE id = 1")
        enc, tok = cur.fetchone()
    assert crypto.is_envelope(enc) and len(tok) == 14 and tok.isdigit()


@pytest.mark.parametrize("t", ["a", "b"])
def test_app_login_is_least_privilege(applied, t):
    d, c = app(t)
    with c:
        cur = c.cursor()
        with pytest.raises(Exception, match="(?i)denied|permission"):
            cur.execute(f"SELECT * FROM {d.base(TABLES[t][0])}")
    d, c = app(t)
    with c:
        cur = c.cursor()
        with pytest.raises(Exception, match="(?i)denied|permission"):          # no role set yet: views closed too
            cur.execute(f"SELECT * FROM {d.view('sdm', TABLES[t][0])}")


def test_views_follow_the_access_matrix_and_tokens_round_trip(applied):
    d, c = app("b")
    with c:
        cur = c.cursor()
        cur.execute(f"SET ROLE {d.roles()['public']}")
        cur.execute(f"SELECT nik, account_no FROM {d.view('public', 'member_finance')}")
        assert all(r == (None, None) for r in cur.fetchall())
        cur.execute(f"SET ROLE {d.roles()['keuangan']}")
        cur.execute(f"SELECT member_id, account_no, npwp FROM {d.view('keuangan', 'member_finance')} WHERE member_id = 1")
        mid, tok, npwp = cur.fetchone()
    from palmerah_shield.seed import dump_rows
    cols, rows = dump_rows()
    original = dict(zip(cols, rows[0]))
    assert tok != original["rekening"] and len(tok) == len(original["rekening"])
    assert Client("test").detokenize("account_no", [tok]) == [original["rekening"]]       # only through the KMS vault
    assert crypto.is_envelope(npwp)                                                    # keuangan gets the envelope; S4 decrypts it


def test_blind_index_search_without_decryption(applied):
    from palmerah_shield.seed import dump_rows
    cols, rows = dump_rows()
    email = dict(zip(cols, rows[9]))["email"]
    with pg_connect() as c:
        key_id, wrapped = c.execute("SELECT key_id, wrapped FROM shield_keys WHERE name = 'web_modern:member_contacts.email:bidx'").fetchone()
    ikey = Client("test").unwrap(key_id, "web_modern:member_contacts.email:bidx", wrapped)
    d, c = app("b")
    with c:
        cur = c.cursor()
        cur.execute(f"SET ROLE {d.roles()['sdm']}")
        cur.execute(f"SELECT member_id FROM {d.view('sdm', 'member_contacts')} WHERE email_bidx = %s", (crypto.blind_index(ikey, email.upper()),))
        assert cur.fetchall() == [(10,)]


@pytest.mark.parametrize("t", ["a", "b"])
def test_anggota_sees_only_own_record(applied, t):
    d, c = app(t)
    table = "members" if t == "b" else "anggota"
    with c:
        cur = c.cursor()
        cur.execute(f"SET ROLE {d.roles()['anggota']}")
        if t == "b":
            cur.execute("SELECT set_config('palmerah.member_id', '5', false)")
        else:
            cur.execute("SET @palmerah_member_id = 5")
        cur.execute(f"SELECT id FROM {d.view('anggota', table)}")
        assert list(cur.fetchall()) == [(5,)]


@pytest.mark.parametrize("t", ["a", "b"])
def test_reapply_is_a_noop_and_rollback_restores_everything(applied, t):
    before, _ = applied
    assert apply(t)["rerun"]["result"].startswith("no-op")
    assert rollback(t)["rollback"] == "restored"
    assert fingerprint(t) == before[t]
    assert settings().mode_file.parent.joinpath(f"MODE_{t}").read_text().strip() == "MODE=vuln"
    with pg_connect(database="postgres") as c:
        left = c.execute("SELECT count(*) FROM pg_roles WHERE rolname LIKE %s", (f"palmerah_{t}%",)).fetchone()[0]
    assert t == "a" or left == 0
