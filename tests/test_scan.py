"""shield scan: content-based detection against the contract's reference, traps, masking, dump reader."""
import json
import re
from pathlib import Path

import pytest

from palmerah_shield.config import LOCAL, settings
from palmerah_shield.scan import classify, mask, metrics, reference_for
from palmerah_shield.seed import dump_rows, to_canonical
from palmerah_shield.sqldump import read_dump


def _tables_b():
    cols, rows = dump_rows()
    data = to_canonical(cols, rows)
    return {t: {"columns": list(r[0]), "rows": [list(x.values()) for x in r]} for t, r in data.items()}


@pytest.fixture(scope="module")
def tables_a():
    return read_dump(settings().seed_dump)        # website A straight from the official dump file


@pytest.mark.parametrize("use_names", [True, False])
def test_dump_a_matches_contract_reference(tables_a, use_names):
    tables = {"anggota": tables_a["anggota"]}
    ref_name, ref = reference_for(tables)
    m = metrics(classify(tables, use_names=use_names), {k: v for k, v in ref.items() if k[1] != "id"})
    assert m["protect"]["precision"] == 1.0 and m["protect"]["recall"] == 1.0, m["mismatches"]
    assert m["class_accuracy"] == 1.0, m["mismatches"]


@pytest.mark.parametrize("use_names", [True, False])
def test_website_b_and_traps(use_names):
    tables = _tables_b()
    _, ref = reference_for(tables)
    m = metrics(classify(tables, use_names=use_names), ref)
    assert m["protect"]["recall"] == 1.0 and m["protect"]["precision"] == 1.0, m["mismatches"]
    assert m["traps_caught"] == {"member_activities.ref_code": True, "member_activities.notes": True}


def test_trap_reasons_are_content_based():
    found = {(f["table"], f["column"]): f for f in classify(_tables_b(), use_names=False)}
    ref = found[("member_activities", "ref_code")]
    assert ref["detected_class"] == "SANGAT_TINGGI" and ref["pii_type"] == "nik"
    assert any("member_finance.nik" in w for w in ref["why"])          # same values as the real NIK column
    notes = found[("member_activities", "notes")]
    assert any("phone tertanam" in w for w in notes["why"]) and any("address tertanam" in w for w in notes["why"])


def test_mask_never_returns_the_value():
    for v in ["00000648505443", "smn.s.ekoaw.wds.ilil,734@example.com", "Jl. Contoh No. 435, Jakarta", "AB"]:
        assert mask(v) != v
    assert mask("00000648505443").endswith("5443") and mask("00000648505443").startswith("*")


def test_inventory_contains_no_raw_identifier(tmp_path):
    from palmerah_shield.scan import scan
    r = scan(dump=settings().seed_dump, target="a-dump", out_dir=tmp_path)
    text = (tmp_path / "inventory.json").read_text(encoding="utf-8")
    assert not re.search(r"\d{14,18}", text)                          # no NIK/NPWP/account number in clear
    assert {"table", "column", "detected_class", "confidence", "why", "sample_masked"} <= set(r["findings"][0])


def test_pg_dump_without_column_list(tmp_path):
    p = tmp_path / "d.sql"
    p.write_text("CREATE TABLE s.t (\n    id integer NOT NULL,\n    note text,\n    CONSTRAINT t_pk PRIMARY KEY (id)\n);\n"
                 "INSERT INTO s.t VALUES (1, 'a''b');\nINSERT INTO s.t VALUES (2, E'x\\ny');\n", encoding="utf-8")
    t = read_dump(p)["t"]
    assert t["columns"] == ["id", "note"] and t["rows"] == [[1, "a'b"], [2, "x\ny"]]


@pytest.mark.skipif(not (LOCAL / "holdout" / "holdout.sql").exists(), reason="holdout dump not generated")
def test_holdout_after_fix_is_reported_honestly():
    from palmerah_shield.holdout import evaluate
    r = evaluate(LOCAL / "holdout" / "holdout.sql", LOCAL / "holdout" / "ground_truth.csv")
    assert r["content_only"]["precision"] == 1.0 and r["content_only"]["recall"] >= 0.9
    # the one remaining difference is a taxonomy disagreement: the contract classes birth date as QUASI-ID
    assert [(m["table"], m["column"]) for m in r["content_only"]["misses"]] == [("pegawai", "tgl_lhr")]
