"""`shield plan`: map every scanned column to controls (encrypt-AEAD | tokenize | blind-index | mask | view-only | drop),
with the reason and the honest limits of each choice, and attach who may see the column (access_matrix.json).

Crypto choices follow the contract exactly: AES-256-GCM with a random nonce for every protected value, tokenisation for
nik and account_no only, blind index for nik and email only. Nothing is applied here; `shield apply` reads out/plan.json.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .access import ensure_matrix, field_for, validate
from .config import OUT
from .reference import INTERNAL, KREDENSIAL, NON_PII, PUBLIK, QUASI_ID, SANGAT_TINGGI, TINGGI_KONTAK, TINGGI_SOSIAL

CONTROLS = {
    "encrypt-AEAD": {
        "what": "AES-256-GCM, nonce acak 96-bit per nilai, AAD = tabel:kolom:id; DEK per kolom dibungkus KEK di KMS terpisah",
        "limits": ["kolom tidak bisa dicari/diurutkan di database", "panjang ciphertext bisa membocorkan panjang nilai (diberi padding 16 byte)",
                   "tidak melindungi bila aplikasi dan akses KMS dikuasai sekaligus"],
    },
    "tokenize": {
        "what": "nilai diganti token format-preserving (panjang dan jenis karakter sama); nilai asli + pemetaan disimpan di vault KMS",
        "limits": ["detokenisasi butuh KMS online", "token konsisten per nilai: kesetaraan antar-baris tetap terlihat",
                   "aplikasi yang memvalidasi checksum nilai asli bisa menolak token"],
    },
    "blind-index": {
        "what": "HMAC-SHA256(normalize(nilai), index_key) di kolom terpisah untuk pencarian kesetaraan",
        "limits": ["membocorkan kesetaraan nilai", "hanya untuk pencarian persis, bukan awalan/LIKE",
                   "bila index_key bocor, nilai berentropi rendah dapat ditebak (kamus)"],
    },
    "mask": {
        "what": "VIEW per peran menampilkan sebagian (4 digit akhir, tahun saja, email tersamar)",
        "limits": ["hanya membatasi tampilan; data tersimpan tetap dilindungi kontrol lain"],
    },
    "view-only": {
        "what": "tabel dasar tertutup untuk akun aplikasi; kolom hanya terlihat lewat VIEW peran yang diizinkan matriks",
        "limits": ["nilai tetap plaintext di disk, backup, dan dump: hanya kontrol akses"],
    },
    "drop": {
        "what": "kolom tidak disimpan lagi; VIEW kompatibilitas menurunkannya dari kolom sumber",
        "limits": ["fitur yang MENULIS kolom ini harus diubah", "tidak dapat dibatalkan setelah backup lama dimusnahkan"],
    },
}


def decide(f: dict, field: str) -> dict:
    cls, t = f["detected_class"], f["pii_type"]
    rel = f.get("relations", [])
    controls: list[str] = []
    reason, review = "", None
    if any(r.startswith("identik dengan") for r in rel) and cls in (PUBLIK, QUASI_ID, INTERNAL):
        controls, reason = ["drop"], f"duplikat kolom lain ({rel[0]}): minimisasi data, tidak menambah informasi"
        review = "pastikan tidak ada kode yang menulis kolom ini; VIEW kompatibilitas tetap menyediakannya untuk dibaca"
    elif t == "nik" or field == "nik":
        if field == "nik":
            controls, reason = ["tokenize", "blind-index"], "NIK: tokenisasi (kontrak) + blind index untuk pencarian kesetaraan (kontrak)"
        else:
            controls = ["tokenize"]
            reason = f"berisi NIK walau namanya '{f['column']}' (jebakan): ditokenisasi dengan vault yang sama, jadi relasi antar-tabel tetap terjaga; tanpa blind index karena kontrak membatasinya untuk nik & email"
    elif field == "account_no" or t == "account_no":
        controls, reason = ["tokenize"], "nomor rekening: tokenisasi format-preserving (kontrak)"
    elif field == "email" or t == "email":
        controls, reason = ["encrypt-AEAD", "blind-index"], "email: AEAD + blind index untuk login/pencarian persis (kontrak)"
    elif t == "account_name":
        controls, reason = ["encrypt-AEAD"], "nama rekening: SANGAT TINGGI menurut kontrak"
        review = "kolom ini = 20 karakter pertama full_name (PUBLIK); enkripsi tidak menambah kerahasiaan nyata. Usulan: drop dan turunkan dari full_name"
    elif t == "free_text_pii":
        controls, reason = ["encrypt-AEAD"], "teks bebas berisi PII (" + "; ".join(f["why"][:2]) + ")"
        review = "teks bebas tidak bisa disamarkan per bagian; pertimbangkan redaksi saat input di aplikasi"
    elif cls in (SANGAT_TINGGI, TINGGI_KONTAK):
        controls, reason = ["encrypt-AEAD"], f"{cls}: harus tak terbaca dari dump tanpa kunci"
    elif cls == TINGGI_SOSIAL:
        controls, reason = ["encrypt-AEAD"], "TINGGI keluarga/sosial/kesehatan: harus tak terbaca dari dump tanpa kunci"
        if t in ("religion", "marital_status", "blood_type", "family_count", "health_context"):
            reason += "; domain nilai kecil, jadi padding panjang ciphertext wajib (agar panjang tidak membocorkan nilai)"
    elif cls == QUASI_ID:
        if t in ("birth_date", "date"):
            controls, reason = ["encrypt-AEAD", "mask"], "tanggal lahir: AEAD; peran yang tidak butuh tanggal lengkap hanya melihat tahun"
        else:
            controls, reason = ["view-only"], "kuasi-identifier: dibatasi lewat VIEW per peran (kombinasinya bisa mengidentifikasi orang)"
    elif cls == INTERNAL:
        controls, reason = ["view-only"], "data internal: hanya peran yang membutuhkan (matriks)"
    elif cls == KREDENSIAL:
        controls, reason = ["view-only"], "hash sandi: tidak pernah dikirim ke peran mana pun"
        review = "periksa algoritma hash; MD5/SHA-1 tanpa salt harus diganti argon2id/bcrypt di kode aplikasi (patch)"
    elif cls == PUBLIK:
        reason = "data publik menurut kontrak: tidak dienkripsi"
    else:
        reason = "bukan data pribadi"
    limits = [l for c in controls for l in CONTROLS[c]["limits"]]
    return {"controls": controls, "reason": reason, "limitations": limits, "needs_human_review": review is not None, "review_note": review}


def plan(target: str, inventory: Path | None = None, out_dir: Path = OUT) -> dict:
    inv_path = inventory or out_dir / f"inventory_{target}.json"
    if not inv_path.exists():
        from .scan import scan
        scan(target=target, out_dir=out_dir)
    inv = json.loads(inv_path.read_text(encoding="utf-8"))
    matrix, created = ensure_matrix()
    problems = validate(matrix)
    columns = []
    for f in inv["findings"]:
        field = field_for(f["table"], f["column"])
        d = decide(f, field)
        visible = matrix["fields"].get(field)
        if visible is None and d["controls"]:
            d["needs_human_review"] = True
            d["review_note"] = ((d["review_note"] or "") + f" field '{field}' belum ada di access_matrix.json: default tidak terlihat oleh peran mana pun").strip()
            visible = {r: "none" for r in ("public", "humas", "keuangan", "sdm", "medis", "admin", "anggota")}
        columns.append({"table": f["table"], "column": f["column"], "field": field, "detected_class": f["detected_class"],
                        "pii_type": f["pii_type"], **d, "visible_to": visible})
    by_control: dict[str, list[str]] = {c: [] for c in CONTROLS}
    for c in columns:
        for k in c["controls"]:
            by_control[k].append(f"{c['table']}.{c['column']}")
    roles = {}
    for role in ("public", "humas", "keuangan", "sdm", "medis", "admin", "anggota"):
        roles[role] = sorted(f"{c['table']}.{c['column']}:{c['visible_to'][role]}" for c in columns
                             if c["visible_to"] and c["visible_to"].get(role, "none") != "none")
    report = {
        "target": target, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "from_inventory": inv_path.name, "access_matrix": {"file": "access_matrix.json", "created_now": created, "problems": problems},
        "controls_catalog": CONTROLS, "columns": columns, "by_control": by_control, "role_views": roles,
        "needs_human_review": [f"{c['table']}.{c['column']}: {c['review_note']}" for c in columns if c["needs_human_review"]],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    (out_dir / "plan.json").write_text(text, encoding="utf-8")
    (out_dir / f"plan_{target}.json").write_text(text, encoding="utf-8")
    return report
