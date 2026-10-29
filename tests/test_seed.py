"""The fixture must match the shared contract: dump mapping facts, canonical schema, detector traps."""
import re

import pytest

from palmerah_shield.seed import dump_rows, to_canonical

cols, rows = dump_rows()
A = [dict(zip(cols, r)) for r in rows]
B = to_canonical(cols, rows)


def test_dump_shape():
    assert len(rows) == 734 and len(cols) == 29


def test_contract_mapping_facts():
    assert all(a["nama"] == a["nama_lengkap"] == a["nama_tanpa_gelar"] for a in A)
    assert all(a["nama_rekening"] == a["nama"][:20] for a in A)
    assert all(a["jumlah_jiwa"] == a["jumlah_tanggungan"] + 1 for a in A)
    for col, width in [("no_ktp", 14), ("npwp", 15), ("rekening", 16), ("nip_kppn", 18), ("kode_bank", 3)]:
        assert all(len(a[col]) == width and a[col].isdigit() for a in A), col


def test_kawin_rule_is_partial():
    # the contract marks "jumlah_tanggungan = jumlah_anak + 1" with (K): it holds only for married members
    married = [a for a in A if a["status_kawin"].startswith("K")]
    assert married and all(a["jumlah_tanggungan"] == a["jumlah_anak"] + 1 for a in married)


def test_canonical_tables_and_columns():
    expect = {
        "members": ["id", "full_name", "display_name", "gender", "birth_place", "birth_date", "job", "religion",
                    "marital_status", "marriage_date", "room_code", "created_at"],
        "member_contacts": ["member_id", "address_jakarta", "phone_jakarta", "address_region", "phone_region", "mobile", "email"],
        "member_finance": ["member_id", "nik", "npwp", "account_no", "account_name", "bank_name", "bank_code", "kppn_name", "kppn_nip"],
        "member_family": ["member_id", "num_children", "num_dependents", "num_souls"],
        "member_health": ["member_id", "blood_type", "allergy_note", "condition_note"],
        "member_activities": ["member_id", "title", "ref_code", "notes", "created_at"],
    }
    for table, columns in expect.items():
        assert list(B[table][0]) == columns, table
    assert all(len(B[t]) == 734 for t in expect if t != "member_activities")


def test_detector_traps():
    nik = {f["member_id"]: f["nik"] for f in B["member_finance"]}
    acts = B["member_activities"]
    assert all(x["ref_code"] == nik[x["member_id"]] for x in acts)                    # misleading name, NIK inside
    phone = re.compile(r"\b0\d{9,12}\b")
    assert sum(bool(phone.search(x["notes"])) for x in acts) > len(acts) // 4          # phone numbers in free text
    assert sum("Jl. " in x["notes"] for x in acts) > len(acts) // 5                    # addresses in free text
    assert any(not phone.search(x["notes"]) and "Jl. " not in x["notes"] for x in acts)  # and clean notes too


def test_synthetic_data_is_deterministic():
    assert to_canonical(cols, rows) == B
