"""access_matrix.json: the one shared file (contract) that says which role may see which field, and how.

Levels: full = value as stored; masked = partially hidden (e.g. last 4 digits, year only); none = never sent;
self = full on the member's own record only, none on others (role `anggota`). Fields use the contract's canonical
names; website A columns are mapped through reference.A_TO_CANONICAL. The file is created once and then owned by the
team: Shield never overwrites an existing matrix.
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import ROOT
from .reference import A_TO_CANONICAL

MATRIX_FILE = ROOT / "access_matrix.json"
ROLES = ["public", "humas", "keuangan", "sdm", "medis", "admin", "anggota"]
LEVELS = ("full", "masked", "none", "self")

ROLE_PURPOSE = {
    "public": "pengunjung tanpa login: direktori anggota",
    "humas": "hubungan masyarakat: profil publik dan kegiatan",
    "keuangan": "pembayaran: rekening, NPWP, KPPN",
    "sdm": "kepegawaian: identitas, kontak, keluarga",
    "medis": "layanan kesehatan: data kesehatan dan kontak darurat",
    "admin": "administrasi sistem: akun, bukan pemilik data pribadi",
    "anggota": "anggota Dewan: hanya data dirinya sendiri",
}


def _row(public="none", humas="none", keuangan="none", sdm="none", medis="none", admin="none", anggota="self") -> dict:
    return {"public": public, "humas": humas, "keuangan": keuangan, "sdm": sdm, "medis": medis, "admin": admin, "anggota": anggota}


ALL_FULL = _row(*["full"] * 6, anggota="full")

DEFAULT_FIELDS: dict[str, dict] = {
    # PUBLIK
    "full_name": ALL_FULL, "display_name": ALL_FULL, "room_code": ALL_FULL,
    # SANGAT TINGGI
    "nik": _row(keuangan="masked", sdm="masked"),
    "npwp": _row(keuangan="full"),
    "account_no": _row(keuangan="full"),
    "account_name": _row(keuangan="full"),
    # TINGGI kontak/lokasi
    "address_jakarta": _row(sdm="full"), "address_region": _row(sdm="full"),
    "phone_jakarta": _row(sdm="full"), "phone_region": _row(sdm="full"),
    "mobile": _row(sdm="full", medis="masked"), "email": _row(humas="masked", sdm="full", admin="masked"),
    # TINGGI keluarga/sosial (+ kesehatan)
    "marital_status": _row(sdm="full"), "marriage_date": _row(sdm="full"),
    "num_children": _row(sdm="full"), "num_dependents": _row(sdm="full", keuangan="full"), "num_souls": _row(sdm="full"),
    "religion": _row(),
    "blood_type": _row(medis="full"), "allergy_note": _row(medis="full"), "condition_note": _row(medis="full"),
    # QUASI-ID
    "birth_date": _row(sdm="full", medis="full", humas="masked"),
    "birth_place": _row(humas="full", sdm="full"), "gender": _row(humas="full", sdm="full", medis="full"),
    "job": _row(humas="full", sdm="full"),
    # INTERNAL
    "kppn_nip": _row(keuangan="full"), "kppn_name": _row(keuangan="full"), "bank_name": _row(keuangan="full"),
    "bank_code": _row(keuangan="full"), "username": _row(admin="full", sdm="full"),
    # activities (title is not personal; ref_code and notes hide identifiers)
    "title": _row(humas="full", sdm="full", admin="full"),
    "ref_code": _row(),
    "notes": _row(sdm="full"),
    # credentials are never sent to anyone
    "password_hash": _row(anggota="none"),
}


def default_matrix() -> dict:
    return {
        "_comment": "Matriks akses peran x field (kontrak Palmerah). Dipakai Shield untuk VIEW per peran dan filter respons. "
                    "Diubah oleh tim; Shield tidak menimpa berkas yang sudah ada.",
        "version": 1,
        "levels": {"full": "nilai utuh", "masked": "sebagian disamarkan", "none": "tidak pernah dikirim",
                   "self": "utuh hanya untuk record milik sendiri"},
        "roles": ROLE_PURPOSE,
        "website_a_columns": A_TO_CANONICAL,
        "fields": DEFAULT_FIELDS,
    }


def ensure_matrix(path: Path = MATRIX_FILE) -> tuple[dict, bool]:
    """(matrix, created). Creates the default file only when none exists."""
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8")), False
    m = default_matrix()
    path.write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return m, True


def field_for(table: str, column: str) -> str:
    """Canonical field name of a column (website A columns are translated; B already uses canonical names)."""
    return A_TO_CANONICAL.get(column, column) if table == "anggota" else column


def validate(matrix: dict) -> list[str]:
    problems = []
    for f, row in matrix.get("fields", {}).items():
        missing = [r for r in ROLES if r not in row]
        bad = [f"{r}={v}" for r, v in row.items() if v not in LEVELS]
        if missing:
            problems.append(f"{f}: peran tanpa level {missing}")
        if bad:
            problems.append(f"{f}: level tidak dikenal {bad}")
        if row.get("public") not in (None, "none", "full"):
            problems.append(f"{f}: public hanya boleh full atau none")
    return problems
