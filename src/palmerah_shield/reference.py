"""Reference classification transcribed from the shared contract ("Klasifikasi PII acuan"), for both websites.

Contract classes are kept verbatim. Columns the contract does not name get an explicit class here and are listed in
docs/ASUMSI.md: identifiers/timestamps/roles -> NON_PII, password hashes -> KREDENSIAL, room_code -> PUBLIK (A6).
"""
from __future__ import annotations

SANGAT_TINGGI = "SANGAT_TINGGI"
TINGGI_KONTAK = "TINGGI_KONTAK"          # kontak/lokasi
TINGGI_SOSIAL = "TINGGI_SOSIAL"          # keluarga/sosial (+ kesehatan)
QUASI_ID = "QUASI_ID"
INTERNAL = "INTERNAL"
PUBLIK = "PUBLIK"
KREDENSIAL = "KREDENSIAL"
NON_PII = "NON_PII"

CLASSES = [SANGAT_TINGGI, TINGGI_KONTAK, TINGGI_SOSIAL, QUASI_ID, INTERNAL, PUBLIK, KREDENSIAL, NON_PII]
# columns that must be protected at rest (scored for precision/recall)
PROTECT = {SANGAT_TINGGI, TINGGI_KONTAK, TINGGI_SOSIAL}

_CANONICAL = {   # canonical field -> class (contract wording)
    "nik": SANGAT_TINGGI, "npwp": SANGAT_TINGGI, "account_no": SANGAT_TINGGI, "account_name": SANGAT_TINGGI,
    "address_jakarta": TINGGI_KONTAK, "address_region": TINGGI_KONTAK, "mobile": TINGGI_KONTAK,
    "phone_jakarta": TINGGI_KONTAK, "phone_region": TINGGI_KONTAK, "email": TINGGI_KONTAK,
    "marital_status": TINGGI_SOSIAL, "marriage_date": TINGGI_SOSIAL, "num_children": TINGGI_SOSIAL,
    "num_dependents": TINGGI_SOSIAL, "num_souls": TINGGI_SOSIAL, "religion": TINGGI_SOSIAL,
    "blood_type": TINGGI_SOSIAL, "allergy_note": TINGGI_SOSIAL, "condition_note": TINGGI_SOSIAL,
    "birth_date": QUASI_ID, "birth_place": QUASI_ID, "gender": QUASI_ID, "job": QUASI_ID,
    "kppn_nip": INTERNAL, "kppn_name": INTERNAL, "bank_name": INTERNAL, "bank_code": INTERNAL, "username": INTERNAL,
    "full_name": PUBLIK, "display_name": PUBLIK, "room_code": PUBLIK,
}

# website A column -> canonical field (contract mapping dump -> canonical)
A_TO_CANONICAL = {
    "nama": "full_name", "nama_lengkap": "full_name", "nama_tanpa_gelar": "full_name", "jenis_kelamin": "gender",
    "tempat_lahir": "birth_place", "tanggal_lahir": "birth_date", "tanggal_pernikahan": "marriage_date",
    "no_ktp": "nik", "pekerjaan_terakhir": "job", "alamat_jakarta": "address_jakarta", "telpon_jakarta": "phone_jakarta",
    "alamat_daerah": "address_region", "telpon_daerah": "phone_region", "handphone": "mobile", "email": "email",
    "ruangan": "room_code", "status_kawin": "marital_status", "jumlah_anak": "num_children",
    "jumlah_tanggungan": "num_dependents", "jumlah_jiwa": "num_souls", "rekening": "account_no",
    "nama_rekening": "account_name", "npwp": "npwp", "nama_kppn": "kppn_name", "nip_kppn": "kppn_nip",
    "nama_bank": "bank_name", "kode_bank": "bank_code", "pengguna": "username", "agama": "religion",
}


def reference_a() -> dict[tuple[str, str], str]:
    ref = {("anggota", c): _CANONICAL[f] for c, f in A_TO_CANONICAL.items()}
    ref[("anggota", "id")] = NON_PII
    return ref


def reference_b() -> dict[tuple[str, str], str]:
    tables = {
        "members": ["full_name", "display_name", "gender", "birth_place", "birth_date", "job", "religion",
                    "marital_status", "marriage_date", "room_code"],
        "member_contacts": ["address_jakarta", "phone_jakarta", "address_region", "phone_region", "mobile", "email"],
        "member_finance": ["nik", "npwp", "account_no", "account_name", "bank_name", "bank_code", "kppn_name", "kppn_nip"],
        "member_family": ["num_children", "num_dependents", "num_souls"],
        "member_health": ["blood_type", "allergy_note", "condition_note"],
    }
    ref = {(t, c): _CANONICAL[c] for t, cols in tables.items() for c in cols}
    for t in ("member_contacts", "member_finance", "member_family", "member_health", "member_activities"):
        ref[(t, "member_id")] = NON_PII
    ref.update({
        ("members", "id"): NON_PII, ("members", "created_at"): NON_PII,
        # detector traps (contract): misleading names, sensitive content
        ("member_activities", "ref_code"): SANGAT_TINGGI,
        ("member_activities", "notes"): TINGGI_KONTAK,
        ("member_activities", "id"): NON_PII, ("member_activities", "title"): NON_PII, ("member_activities", "created_at"): NON_PII,
        ("users", "id"): NON_PII, ("users", "username"): INTERNAL, ("users", "password_hash"): KREDENSIAL,
        ("users", "role"): NON_PII, ("users", "member_id"): NON_PII,
    })
    return ref


TRAPS = {("member_activities", "ref_code"), ("member_activities", "notes")}
