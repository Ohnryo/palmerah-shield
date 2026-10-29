"""`shield evidence`: live proof for the three leak scenarios of the demo, written to out/evidence_<target>.json.

(a) dump without keys   what a stolen dump shows for the protected columns of one row, next to the (masked) original
(b) dump + keys         the wrapped DEKs stored in the database do not decrypt anything without the KMS: tried with the
                        wrapped bytes as key, with a wrong KMS token, and (the legitimate path) with the KMS
(c) legitimate users    each role reads through the application login (SET ROLE) and sees only what access_matrix.json allows

Nothing here prints a raw PII value: original values are masked, stored values are tokens/envelopes/masked columns, and a
value that equals a known original is reported as PLAINTEXT without being shown. The measurements are made at evidence
time against the real database and KMS; the "residual risk" list is written text, labelled as such.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import urllib.error
import urllib.request
from pathlib import Path

from . import crypto, ops
from .access import ROLES
from .apply import DIALECTS, STATE, mask_value
from .config import OUT, settings
from .kms import Client

# canonical fields shown (when the target has them); ref_code is the detector trap holding NIK
FIELDS = ["nik", "npwp", "account_no", "mobile", "email", "ref_code", "condition_note"]
TOKENISED = {"nik", "account_no", "ref_code"}
SHOW = 44


def kind_of(field: str, value, originals: set[str]) -> str:
    """none | PLAINTEXT | envelope | masked | token | other: what a stored/visible value is."""
    if value is None:
        return "none"
    s = str(value)
    if s in originals:
        return "PLAINTEXT"
    if crypto.is_envelope(s):
        return "envelope"
    if "*" in s:
        return "masked"
    if field in TOKENISED:
        return "token"
    return "other"


def shown(value, kind: str) -> str | None:
    """Display text: never a plaintext; long envelopes are cut."""
    if value is None:
        return None
    if kind == "PLAINTEXT":
        return "(nilai asli terbaca; tidak ditampilkan)"
    s = str(value)
    return s if len(s) <= SHOW else s[:SHOW] + f"… ({len(s)} karakter)"


def _targets(plan: dict) -> list[dict]:
    """[{field, table, column}] for the FIELDS this target has, in FIELDS order."""
    by_field = {c["field"]: c for c in plan["columns"] if c["field"] in FIELDS and c["controls"]}
    return [{"field": f, "table": by_field[f]["table"], "column": by_field[f]["column"]} for f in FIELDS if f in by_field]


def _wrong_token_status() -> int:
    s = settings()
    req = urllib.request.Request(s.kms_url.rstrip("/") + "/v1/unwrap", data=b"{}", method="POST",
                                 headers={"Authorization": "Bearer not-the-real-token", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


@ops.locked("evidence")
def evidence(target: str, out_dir: Path = OUT) -> dict:
    d = DIALECTS[target]()
    sf = STATE / f"applied_{target}.json"
    if not sf.exists():
        raise RuntimeError("target belum diterapkan (MODE=vuln): jalankan apply dulu")
    state = json.loads(sf.read_text(encoding="utf-8"))
    plan = json.loads((out_dir / f"plan_{target}.json").read_text(encoding="utf-8"))
    sample = state["sample"]
    cols = _targets(plan)
    originals = {t["field"]: set(sample.get(f"{t['table']}.{t['column']}", [])) for t in cols}
    kms = Client("shield-evidence")

    # ---------- (a) + (b): the database as a thief sees it ----------
    ops.step("dump_view")
    attacker, first_member, keys_rows = [], None, []
    stored_env: dict | None = None
    with d.connect() as conn:
        cur = conn.cursor()
        for t in cols:
            pk = d.pk(cur, t["table"])
            existing = d.columns(cur, t["table"])
            stored = f"{t['column']}_enc" if f"{t['column']}_enc" in existing else t["column"]
            cur.execute(f"SELECT {d.q(pk)}, {d.q(stored)} FROM {d.base(t['table'])} ORDER BY {d.q(pk)} LIMIT 1")
            row = cur.fetchone()
            if row is None:
                continue
            if first_member is None:
                first_member = row[0]
            k = kind_of(t["field"], row[1], originals[t["field"]])
            samp = sample.get(f"{t['table']}.{t['column']}", [])
            attacker.append({
                **t, "stored_column": stored, "row_id": row[0], "kind": k, "stored": shown(row[1], k), "leak": k == "PLAINTEXT",
                "original_masked": mask_value(samp[0]) if samp else None,
            })
            if k == "envelope" and stored_env is None:
                stored_env = {**t, "pk": row[0], "envelope": row[1]}
        cur.execute("SELECT key_id, name, purpose, wrapped FROM shield_keys ORDER BY name")
        keys_rows = cur.fetchall()

    ops.step("keys")
    with_key: dict = {"shield_keys_rows": len(keys_rows),
                      "sample": [{"key_id": r[0], "name": r[1], "purpose": r[2], "wrapped": r[3][:24] + "…"} for r in keys_rows[:3]]}
    if stored_env:
        env, aad = stored_env["envelope"], crypto.aad_for(d.db, stored_env["table"], stored_env["column"], stored_env["pk"])
        kname = f"{d.db}:{stored_env['table']}.{stored_env['column']}:aead"
        krow = next((r for r in keys_rows if r[1] == kname), None)
        attempt = {"column": f"{stored_env['table']}.{stored_env['column']}"}
        if krow:
            try:                           # the thief has the wrapped DEK and uses its bytes as if they were the key
                crypto.decrypt(base64.b64decode(krow[3])[:32], env, aad)
                attempt["wrapped_dek_as_key"] = "BERHASIL (bocor!)"
            except Exception as e:
                attempt["wrapped_dek_as_key"] = f"gagal ({type(e).__name__})"
            code = _wrong_token_status()
            attempt["kms_with_wrong_token"] = f"HTTP {code}" + (" (ditolak)" if code == 401 else " (TIDAK ditolak!)")
            try:                           # legitimate path: authorised KMS client, audited by the KMS
                dek = kms.unwrap(krow[0], kname, krow[3])
                crypto.decrypt(dek, env, aad)
                attempt["kms_authorised"] = "berhasil didekripsi (nilai tidak ditampilkan); tercatat di audit KMS"
            except Exception as e:
                attempt["kms_authorised"] = f"gagal ({type(e).__name__})"
        else:
            attempt["error"] = f"DEK {kname} tidak ada di shield_keys"
        with_key["attempt"] = attempt
    with_key["residual_risk_written"] = [
        "bila penyerang menguasai KMS (KEK + vault) atau proses yang berhak memanggil KMS, semua kolom dapat dibuka",
        "token konsisten per nilai: kesetaraan antar-baris tetap terlihat",
        "kuasi-identifier dan kolom turunan nama (mis. account_name) tetap memungkinkan re-identifikasi sebagian",
        "mitigasi: pisahkan host/kustodian KMS, batasi klien KMS, rotasi DEK/KEK, pantau audit",
    ]

    # ---------- (c): each role through the application login ----------
    ops.step("roles")
    creds = json.loads(Path(state["app_password_file"]).read_text(encoding="utf-8"))
    roles: dict[str, dict] = {r: {"cells": {}} for r in ROLES}
    pk_of: dict[str, str] = {}
    with d.connect() as conn:
        cur = conn.cursor()
        for t in cols:
            pk_of[t["table"]] = d.pk(cur, t["table"])
    with d.app_connect(creds["password"]) as c:
        cur = c.cursor()
        for role in ROLES:
            if d.kind == "pg":
                cur.execute("RESET ROLE")
                cur.execute(f"SET ROLE {d.roles()[role]}")
                cur.execute("SELECT set_config('palmerah.member_id', %s, false)", (str(first_member),))
            else:
                cur.execute("SET ROLE NONE")
                cur.execute(f"SET ROLE {d.roles()[role]}")
                cur.execute("SET @palmerah_member_id = %s", (first_member,))
            for t in cols:
                try:
                    cur.execute(f"SELECT {d.q(t['column'])} FROM {d.view(role, t['table'])} ORDER BY {d.q(pk_of[t['table']])} LIMIT 1")
                    row = cur.fetchone()
                except Exception as e:                      # a role without access to the view: report, never hide
                    if d.kind == "pg":
                        c.rollback()
                    roles[role]["cells"][t["field"]] = {"kind": "error", "value": type(e).__name__}
                    continue
                if row is None:
                    roles[role]["cells"][t["field"]] = {"kind": "no-row", "value": None}
                    continue
                k = kind_of(t["field"], row[0], originals[t["field"]])
                roles[role]["cells"][t["field"]] = {"kind": k, "value": shown(row[0], k)}
        if d.kind == "pg":
            cur.execute("RESET ROLE")
    for r in roles.values():
        kinds = [x["kind"] for x in r["cells"].values()]
        r["readable"] = sum(1 for k in kinds if k not in ("none", "error", "no-row"))
        r["plaintext_cells"] = kinds.count("PLAINTEXT")

    leaks = sum(a["leak"] for a in attacker) + sum(r["plaintext_cells"] for r in roles.values())
    report = {
        "target": target, "database": d.db, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "fields": [t["field"] for t in cols],
        "a_dump_without_keys": {"label": "[TESTED]", "row": "baris pertama tiap tabel, dibaca sebagai superuser (isi dump)",
                                "columns": attacker, "apply_report_sample": {
                                    k: v for k, v in (json.loads((out_dir / f"apply_report_{target}.json").read_text(encoding="utf-8"))
                                                      .get("verification", {}).get("dump_without_keys", {})).items()
                                    if k in ("sample_values", "found_in_dump")}},
        "b_dump_with_keys": {"label": "[TESTED]", **with_key},
        "c_legitimate_users": {"label": "[TESTED] level database; lewat proxy: lihat `shield proxy` (butuh web yang mengirim X-Palmerah-Role)",
                               "via": f"login {d.app_user} + SET ROLE (tanpa akses tabel dasar)",
                               "roles": roles, "member_id_for_self_role": first_member},
        "plaintext_cells_total": leaks,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"evidence_{target}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return report
