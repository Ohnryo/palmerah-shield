"""Content-based PII detection. The column NAME is only a tie-breaker (and can be switched off): every class is first
decided from the values themselves — fixed-length digit identifiers, phone/email/address shapes, dates, small
categorical domains, dictionaries, cross-column relations, and identifiers hidden inside free text.

Each detector returns (pii_type, contract_class, confidence, reasons). The highest confidence wins; a column no rule
claims is reported as NON_PII with low confidence and the reason "no evidence" (it is listed, never silently dropped).
"""
from __future__ import annotations

import datetime as dt
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from .reference import INTERNAL, KREDENSIAL, NON_PII, PUBLIK, QUASI_ID, SANGAT_TINGGI, TINGGI_KONTAK, TINGGI_SOSIAL

RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
RE_PHONE = re.compile(r"^(\+62|62|0)[1-9]\d{7,11}$")             # leading 0 then a non-zero digit: not a padded ID
RE_ADDRESS = re.compile(r"\b(Jl\.|Jalan|Gg\.|Gang)\s.+\bNo\.?\s*\d+", re.I)
RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RE_ROOM = re.compile(r"^[A-Z]{2,}-\d{2,}$")
RE_HASH = re.compile(r"^(pbkdf2_sha\d+\$|\$2[aby]\$|\$argon2|[0-9a-f]{32}$|[0-9a-f]{40}$|[0-9a-f]{64}$)")
RE_USERNAME = re.compile(r"^[a-z0-9_.,\-]{3,64}$")
# inside free text
RE_T_IDNUM = re.compile(r"(?<!\d)\d{14,16}(?!\d)")
RE_T_PHONE = re.compile(r"(?<![\d+])(\+62|0)[1-9]\d{7,11}(?!\d)")
RE_T_EMAIL = re.compile(r"[^@\s;,]+@[^@\s;,]+\.[A-Za-z]{2,}")
RE_T_ADDRESS = re.compile(r"\b(Jl\.|Jalan)\s[^,;]+No\.?\s*\d+", re.I)

RELIGIONS = {"islam", "kristen", "protestan", "katolik", "hindu", "buddha", "budha", "konghucu", "khonghucu", "lain-lain", "kepercayaan"}
CITIES = {"jakarta", "bandung", "surabaya", "semarang", "yogyakarta", "medan", "makassar", "palembang", "denpasar", "malang",
          "bogor", "depok", "tangerang", "bekasi", "padang", "pekanbaru", "manado", "balikpapan", "pontianak", "banjarmasin",
          "solo", "surakarta", "cirebon", "kupang", "jayapura", "ambon", "mataram", "aceh", "banda aceh", "jambi", "bengkulu"}
JOBS = {"pegawai negeri", "pns", "wiraswasta", "pensiunan", "guru", "dokter", "akuntan", "pengusaha", "petani", "nelayan",
        "dosen", "advokat", "pengacara", "tni", "polri", "karyawan swasta", "ibu rumah tangga", "pedagang", "buruh"}
MARITAL = {"k", "tk", "k0", "k1", "k2", "k3", "tk0", "tk1", "tk2", "tk3", "kawin", "belum kawin", "cerai hidup", "cerai mati"}
BLOOD = {"a", "b", "ab", "o", "a+", "a-", "b+", "b-", "ab+", "ab-", "o+", "o-"}
HEALTH_TERMS = ("alergi", "hipertensi", "diabetes", "asma", "operasi", "kolesterol", "keluhan", "jantung", "stroke", "obat",
                "penyakit", "kanker", "ginjal", "pasca")
ORG_PREFIX = ("kppn ", "bank ", "pt ", "cv ", "kantor ", "dinas ")
ROLES = {"public", "humas", "keuangan", "sdm", "medis", "admin", "anggota", "auditor", "operator", "user"}

NAME_HINTS = [  # optional tie-breakers only
    (re.compile(r"(ktp|nik)"), "nik"), (re.compile(r"npwp"), "npwp"), (re.compile(r"(rekening|account_no)"), "account_no"),
    (re.compile(r"(jumlah|num_)"), "family_count"), (re.compile(r"(nip)"), "nip"),
]

ID_LENGTH = {14: ("nik", SANGAT_TINGGI), 16: ("account_no", SANGAT_TINGGI), 15: ("npwp", SANGAT_TINGGI), 18: ("nip", INTERNAL)}


@dataclass
class Finding:
    pii_type: str
    cls: str
    confidence: float
    why: list[str] = field(default_factory=list)


def _frac(values: list, pred) -> float:
    return sum(1 for v in values if pred(v)) / len(values) if values else 0.0


def _s(v) -> str:
    return v.isoformat() if isinstance(v, (dt.date, dt.datetime)) else str(v)


def entropy(values: list[str]) -> float:
    """Average Shannon entropy per character (bits); high for random identifiers, low for codes and words."""
    text = "".join(values)
    if not text:
        return 0.0
    c = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in c.values())


def detect_column(table: str, column: str, values: list, context: dict, use_names: bool = True) -> Finding:
    """values: sample of the column (may contain None). context: {"name_prefixes": set[str]} built across the scan."""
    present = [v for v in values if v is not None and _s(v).strip() != ""]
    n = len(values)
    if not present:
        return Finding("empty", NON_PII, 0.2, ["kolom kosong pada sampel"])
    strs = [_s(v).strip() for v in present]
    distinct = len(set(strs))
    uniq = distinct / len(strs)
    null_ratio = 1 - len(present) / n if n else 0.0
    lens = Counter(len(s) for s in strs)
    top_len, top_len_n = lens.most_common(1)[0]
    lower = [s.lower() for s in strs]
    cands: list[Finding] = []

    # --- identifiers and credentials ---
    if all(isinstance(v, int) and not isinstance(v, bool) for v in present):
        ints = sorted(set(present))
        if uniq > 0.98 and ints[-1] - ints[0] + 1 <= len(ints) * 1.05:
            cands.append(Finding("surrogate_key", NON_PII, 0.9, [f"bilangan bulat unik dan berurutan ({distinct} nilai)"]))
        elif max(ints) <= 20 and min(ints) >= 0 and distinct <= 12:
            cands.append(Finding("family_count", TINGGI_SOSIAL, 0.6, [f"bilangan kecil 0..{max(ints)} dengan {distinct} nilai: jumlah anggota keluarga/tanggungan"]))
        else:
            cands.append(Finding("reference_id", NON_PII, 0.7, [f"bilangan bulat berulang ({distinct} nilai): rujukan ke tabel lain"]))
    textual = all(isinstance(v, str) for v in present)   # digit-string identifiers; numeric columns were handled above
    digit_frac = _frac(strs, str.isdigit)
    high_card = uniq > 0.95 or distinct >= 100      # identifiers may repeat when other rows refer to the same person
    if textual and digit_frac > 0.98 and top_len_n / len(strs) > 0.98:
        if top_len in ID_LENGTH and high_card:
            t, c = ID_LENGTH[top_len]
            why = [f"100% digit, panjang tetap {top_len}, {distinct} nilai berbeda (unik {uniq:.0%})",
                   f"entropi {entropy(strs):.2f} bit/karakter", f"pola panjang {top_len} digit = format {t}"]
            for (ot, oc), vals in context.get("id_values", {}).items():
                if (ot, oc) != (table, column) and _frac(strs, lambda s, vs=vals: s in vs) > 0.95:
                    why.append(f"nilainya sama dengan kolom {ot}.{oc}: data identitas yang sama di tempat lain")
                    break
            cands.append(Finding(t, c, 0.92, why))
        elif top_len >= 12 and high_card:
            cands.append(Finding("id_number", SANGAT_TINGGI, 0.75, [f"100% digit, panjang tetap {top_len}, unik {uniq:.0%}: nomor identitas"]))
        elif top_len <= 6:
            cands.append(Finding("code", INTERNAL, 0.7, [f"kode numerik pendek ({top_len} digit, {distinct} nilai)"]))
        elif 8 <= top_len <= 13 and high_card and _frac(strs, lambda s: s.startswith("0")) < 0.5:
            # not phone-shaped (phones start with 0): a fixed-length account/card number
            cands.append(Finding("account_no", SANGAT_TINGGI, 0.75, [f"100% digit, panjang tetap {top_len}, {distinct} nilai berbeda, tidak berawalan 0: nomor rekening"]))
    elif textual and digit_frac > 0.98 and high_card and min(lens) >= 8:
        # account and card numbers vary in length between banks; long, high-cardinality digit strings are identifiers
        cands.append(Finding("account_no", SANGAT_TINGGI, 0.75, [f"100% digit, panjang {min(lens)}-{max(lens)}, {distinct} nilai berbeda: nomor rekening/identitas"]))
    money = lambda v: (isinstance(v, float) or (isinstance(v, str) and bool(re.fullmatch(r"\d{4,}\.\d{2}", v))))
    if _frac(present, money) > 0.95 and distinct > 20 and min(float(v) for v in present) >= 1000:
        cands.append(Finding("money_amount", SANGAT_TINGGI, 0.8, ["nominal uang (desimal 2 angka, ribuan ke atas): data keuangan pribadi"]))
    if _frac(strs, lambda s: bool(RE_HASH.match(s))) > 0.95:
        cands.append(Finding("password_hash", KREDENSIAL, 0.95, ["format hash sandi (pbkdf2/bcrypt/argon2/hex digest)"]))

    # --- contact and location ---
    f = _frac(strs, lambda s: bool(RE_EMAIL.match(s)))
    if f > 0.9:
        cands.append(Finding("email", TINGGI_KONTAK, 0.95, [f"{f:.0%} nilai berformat email"]))
    f = _frac(strs, lambda s: bool(RE_PHONE.match(s.replace(" ", "").replace("-", ""))))
    phone_shape = _frac(strs, lambda s: s.isdigit() and s.startswith("0") and 10 <= len(s) <= 13)
    if f > 0.9 or (f >= 0.8 and phone_shape > 0.98):
        mobile = _frac(strs, lambda s: s.startswith(("08", "+628", "628")))
        why = [f"{f:.0%} nilai berbentuk nomor telepon Indonesia"]
        if f <= 0.9:
            why.append(f"sisanya tetap berbentuk nomor telepon (10-13 digit berawalan 0) dengan kode area tidak valid: data sintetis")
        cands.append(Finding("mobile" if mobile > 0.5 else "phone", TINGGI_KONTAK, 0.92 if f > 0.9 else 0.8, why))
    f = _frac(strs, lambda s: bool(RE_ADDRESS.search(s)))
    if f > 0.8:
        cands.append(Finding("address", TINGGI_KONTAK, 0.9, [f"{f:.0%} nilai berpola alamat (Jl. ... No.)"]))

    # --- dates ---
    is_date = lambda v: isinstance(v, (dt.date, dt.datetime)) or bool(RE_DATE.match(_s(v)))
    if _frac(present, is_date) > 0.98:
        has_time = _frac(present, lambda v: isinstance(v, dt.datetime) and (v.hour or v.minute))
        years = [int(_s(v)[:4]) for v in present]
        span = max(years) - min(years)
        if has_time > 0.5 or (max(years) - min(years) <= 3 and min(years) >= dt.date.today().year - 5):
            cands.append(Finding("event_timestamp", NON_PII, 0.75, ["waktu kejadian/pencatatan (rentang pendek, berjam)"]))
        elif null_ratio > 0.2:
            cands.append(Finding("marriage_date", TINGGI_SOSIAL, 0.7, [f"tanggal, {null_ratio:.0%} kosong: peristiwa keluarga yang tidak dimiliki semua orang"]))
        elif span > 20 and max(years) <= dt.date.today().year - 17:
            cands.append(Finding("birth_date", QUASI_ID, 0.85, [f"tanggal lengkap rentang {span} tahun, semua ≥17 tahun lalu: tanggal lahir"]))
        else:
            cands.append(Finding("date", QUASI_ID, 0.5, ["tanggal pribadi"]))

    # --- small categorical domains ---
    dom = set(lower)
    if dom <= {"l", "p", "m", "f"}:
        cands.append(Finding("gender", QUASI_ID, 0.9, [f"domain {sorted(dom)}: jenis kelamin"]))
    if len(dom) <= 12 and _frac(lower, lambda s: s in RELIGIONS) > 0.9:
        cands.append(Finding("religion", TINGGI_SOSIAL, 0.95, ["nilai dari kamus agama (data spesifik UU PDP)"]))
    if len(dom) <= 12 and _frac(lower, lambda s: s in MARITAL) > 0.95:
        cands.append(Finding("marital_status", TINGGI_SOSIAL, 0.85, [f"kode status kawin {sorted(dom)}"]))
    if len(dom) <= 12 and _frac(lower, lambda s: s in BLOOD) > 0.95:
        cands.append(Finding("blood_type", TINGGI_SOSIAL, 0.9, ["golongan darah: data kesehatan"]))
    if len(dom) <= 20 and _frac(lower, lambda s: s in ROLES) > 0.95:
        cands.append(Finding("role", NON_PII, 0.8, ["nama peran aplikasi"]))
    if _frac(lower, lambda s: any(t in s for t in HEALTH_TERMS)) > 0.4:
        cands.append(Finding("health_note", TINGGI_SOSIAL, 0.85, ["kosakata medis (alergi/penyakit/operasi): data kesehatan"]))
    if _frac(lower, lambda s: s.startswith(ORG_PREFIX)) > 0.95:
        cands.append(Finding("organisation", INTERNAL, 0.85, ["nama institusi (KPPN/Bank/...)"]))
    if len(dom) <= 40 and _frac(lower, lambda s: s in CITIES) > 0.9:
        cands.append(Finding("birth_place", QUASI_ID, 0.85, ["nama kota dari kamus: tempat lahir/asal"]))
    if len(dom) <= 40 and _frac(lower, lambda s: s in JOBS) > 0.9:
        cands.append(Finding("job", QUASI_ID, 0.85, ["nilai dari kamus pekerjaan"]))
    if _frac(strs, lambda s: bool(RE_ROOM.match(s))) > 0.95:
        cands.append(Finding("room_code", PUBLIK, 0.8, ["kode ruangan berpola HURUF-ANGKA"]))

    # --- names and identifiers derived from names ---
    letters = _frac(strs, lambda s: sum(ch.isalpha() for ch in s) >= max(3, len(s) * 0.5) and " " in s.strip())
    truncated_of = None
    if max(lens) <= 20:   # a copy cut at 20 characters of a longer name column = name printed on the bank account
        for (ot, oc), vals in context.get("name_values", {}).items():
            if (ot, oc) != (table, column) and max(map(len, vals)) > 20:
                cut = {v[:20].strip() for v in vals}       # values are compared stripped on both sides
                if _frac(strs, lambda s: s in cut) > 0.95:
                    truncated_of = f"{ot}.{oc}"
                    break
    if truncated_of:
        cands.append(Finding("account_name", SANGAT_TINGGI, 0.88, [f"salinan 20 karakter pertama {truncated_of}: nama pemilik rekening"]))
    elif letters > 0.9 and uniq > 0.9 and top_len > 8:
        cands.append(Finding("person_name", PUBLIK, 0.7, [f"teks bernama orang, unik {uniq:.0%} (nama pejabat publik menurut kontrak)"]))
    if uniq > 0.9 and _frac(strs, lambda s: bool(RE_USERNAME.match(s)) and not RE_EMAIL.match(s) and not s.isdigit()) > 0.95:
        cands.append(Finding("username", INTERNAL, 0.7, ["pengenal akun: huruf kecil tanpa spasi, unik"]))

    # --- identifiers hidden in free text (only when the whole value is not itself an address/email/phone) ---
    structured = any(c.pii_type in ("address", "email", "phone", "mobile") for c in cands)
    if (top_len > 25 or len(lens) > 10) and not structured:
        hits = {"nik": _frac(strs, lambda s: bool(RE_T_IDNUM.search(s))), "phone": _frac(strs, lambda s: bool(RE_T_PHONE.search(s))),
                "email": _frac(strs, lambda s: bool(RE_T_EMAIL.search(s))), "address": _frac(strs, lambda s: bool(RE_T_ADDRESS.search(s)))}
        found = {k: v for k, v in hits.items() if v >= 0.05}
        if found:
            cls = SANGAT_TINGGI if "nik" in found else TINGGI_KONTAK
            why = [f"teks bebas: {k} tertanam di {v:.0%} baris" for k, v in found.items()]
            cands.append(Finding("free_text_pii", cls, min(0.95, 0.6 + max(found.values())), why))
        elif not cands:
            cands.append(Finding("free_text", NON_PII, 0.5, ["teks bebas tanpa pola PII pada sampel"]))

    # table context: in a table that holds health data, dates are medical events and short categories are clinical facts
    if context.get("health_tables") and table in context["health_tables"]:
        for c in cands:
            if c.cls in (NON_PII, QUASI_ID) and c.pii_type in ("event_timestamp", "date", "birth_date", "categorical", "free_text"):
                c.cls, c.confidence = TINGGI_SOSIAL, max(c.confidence, 0.7)
                c.why.append(f"tabel {table} berisi data kesehatan: {c.pii_type} di sini adalah fakta medis")
        if not cands and distinct <= 40:
            cands.append(Finding("health_context", TINGGI_SOSIAL, 0.6, [f"kategori pendek di tabel kesehatan {table}"]))

    if use_names:   # tie-breaker: a matching name hint nudges a candidate of the same family
        for rx, hint in NAME_HINTS:
            if rx.search(column.lower()):
                for c in cands:
                    if c.pii_type == hint or (hint in ("nik", "account_no") and c.pii_type in ("nik", "account_no", "id_number")):
                        c.confidence = min(0.99, c.confidence + 0.05)
                        c.why.append(f"nama kolom '{column}' mendukung")

    if not cands:
        low_card = distinct <= 20 and len(strs) >= 50
        return Finding("categorical" if low_card else "unknown", NON_PII, 0.3,
                       [f"tidak ada bukti PII ({distinct} nilai berbeda); perlu tinjauan manusia"])
    best = max(cands, key=lambda c: c.confidence)
    others = [f"{c.pii_type} ({c.confidence:.2f})" for c in cands if c is not best]
    if others:
        best.why.append("kandidat lain: " + ", ".join(others))
    return best
