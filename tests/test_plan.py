"""shield plan obeys the contract: crypto choices, nothing sensitive left plain, access matrix rules."""
import json

import pytest

from palmerah_shield.access import ROLES, default_matrix, ensure_matrix, validate
from palmerah_shield.plan import plan
from palmerah_shield.reference import PROTECT
from palmerah_shield.scan import classify
from palmerah_shield.seed import dump_rows, to_canonical
from palmerah_shield.sqldump import read_dump
from palmerah_shield.config import settings


def _inventory(tables, path):
    path.write_text(json.dumps({"findings": classify(tables)}), encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def plans(tmp_path_factory):
    d = tmp_path_factory.mktemp("plan")
    cols, rows = dump_rows()
    b = {t: {"columns": list(r[0]), "rows": [list(x.values()) for x in r]} for t, r in to_canonical(cols, rows).items()}
    from palmerah_shield.seed import ROLES as APP_ROLES, _pbkdf2
    b["users"] = {"columns": ["id", "username", "password_hash", "role", "member_id"],   # as loaded into website B
                  "rows": [[i, f"{r}1", _pbkdf2("x"), r, 1 if r == "anggota" else None] for i, r in enumerate(APP_ROLES, 1)]}
    a = {"anggota": read_dump(settings().seed_dump)["anggota"]}
    return {"a": plan("a", _inventory(a, d / "inv_a.json"), d), "b": plan("b", _inventory(b, d / "inv_b.json"), d)}


@pytest.mark.parametrize("t", ["a", "b"])
def test_contract_crypto_choices(plans, t):
    for c in plans[t]["columns"]:
        if "blind-index" in c["controls"]:
            assert c["field"] in ("nik", "email"), c                         # blind index: nik & email only
        if "tokenize" in c["controls"]:
            assert c["field"] in ("nik", "account_no") or c["pii_type"] == "nik", c   # tokenisation: nik & account_no
    fields = {c["field"]: c["controls"] for c in plans[t]["columns"]}
    assert "tokenize" in fields["nik"] and "blind-index" in fields["nik"]
    assert "tokenize" in fields["account_no"]
    assert "blind-index" in fields["email"]


@pytest.mark.parametrize("t", ["a", "b"])
def test_nothing_sensitive_stays_plain(plans, t):
    for c in plans[t]["columns"]:
        if c["detected_class"] in PROTECT:
            assert {"encrypt-AEAD", "tokenize"} & set(c["controls"]), c
            assert c["reason"] and c["limitations"], c


def test_trap_column_is_tokenised_without_blind_index(plans):
    ref = next(c for c in plans["b"]["columns"] if c["column"] == "ref_code")
    assert ref["controls"] == ["tokenize"] and "jebakan" in ref["reason"]


def test_duplicates_and_derived_columns_go_to_human_review(plans):
    review = "\n".join(plans["a"]["needs_human_review"])
    assert "nama_lengkap" in review and "nama_tanpa_gelar" in review and "nama_rekening" in review
    assert any(c["controls"] == ["drop"] for c in plans["a"]["columns"] if c["column"] == "nama_lengkap")


def test_credentials_never_visible(plans):
    pw = next(c for c in plans["b"]["columns"] if c["column"] == "password_hash")
    assert all(v == "none" for v in pw["visible_to"].values())


def test_matrix_rules():
    m = default_matrix()
    assert validate(m) == []
    public = sorted(f for f, row in m["fields"].items() if row["public"] != "none")
    assert public == ["display_name", "full_name", "room_code"]
    for f in ("nik", "npwp", "account_no", "religion", "allergy_note", "condition_note"):
        assert m["fields"][f]["anggota"] == "self" and m["fields"][f]["public"] == "none"
    assert set(ROLES) == set(m["fields"]["nik"])


def test_matrix_is_never_overwritten(tmp_path):
    p = tmp_path / "access_matrix.json"
    p.write_text(json.dumps({"fields": {"nik": {"public": "none"}}}), encoding="utf-8")
    m, created = ensure_matrix(p)
    assert not created and m == {"fields": {"nik": {"public": "none"}}}
    _, created = ensure_matrix(tmp_path / "new.json")
    assert created and validate(json.loads((tmp_path / "new.json").read_text(encoding="utf-8"))) == []
