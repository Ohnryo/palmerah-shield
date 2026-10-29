"""Patches for fixes that need application code changes. Shield never edits application code: it writes suggested
diffs and guides to out/patches/<target>/, every one marked "needs human review".

* Always: switch the website from root/postgres to the least-privilege login + SET ROLE per request, and route writes
  of encrypted columns through Shield.
* With --app-src: PHP files are searched for SQL built by string concatenation passed to mysqli_query()/->query();
  the simple cases (one statement, variables concatenated into the SQL string) get a prepared-statement diff,
  the rest are listed for manual work. Password checks with md5()/sha1() are listed.
"""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path

from .config import OUT

_CALL = re.compile(r"^(?P<indent>\s*)(?P<lhs>\$\w+\s*=\s*)?mysqli_query\(\s*(?P<db>\$\w+)\s*,\s*(?P<sql>.+)\);\s*$")
_WEAK_HASH = re.compile(r"\b(md5|sha1)\s*\(\s*\$\w*pass", re.I)
# a SQL string literal concatenated with a variable: "SELECT ... '" . $x
_SQL_BUILD = re.compile(r"(\"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\"|'\s*(SELECT|INSERT|UPDATE|DELETE)\b[^']*')\s*\.\s*\$\w+", re.I)


def _split_concat(expr: str) -> list[tuple[str, str]] | None:
    """Split a PHP concatenation into ('str', text) / ('expr', code) parts; None if it is not a simple one."""
    parts, i, n = [], 0, len(expr)
    while i < n:
        while i < n and expr[i] in " \t.":
            i += 1
        if i >= n:
            break
        if expr[i] in "\"'":
            q, j, buf = expr[i], i + 1, []
            while j < n and expr[j] != q:
                if expr[j] == "\\" and j + 1 < n:
                    buf.append(expr[j:j + 2])
                    j += 2
                    continue
                buf.append(expr[j])
                j += 1
            if j >= n:
                return None
            text = "".join(buf)
            if q == '"' and re.search(r"\$\w", text):       # interpolated variables: not handled automatically
                return None
            parts.append(("str", text))
            i = j + 1
        else:
            depth, j = 0, i
            while j < n and not (depth == 0 and expr[j] == "."):
                depth += expr[j] in "([" and 1 or (expr[j] in ")]" and -1 or 0)
                j += 1
            parts.append(("expr", expr[i:j].strip()))
            i = j
    return parts


def _prepared(line: str) -> list[str] | None:
    m = _CALL.match(line)
    if not m:
        return None
    parts = _split_concat(m["sql"])
    if not parts or not any(k == "expr" for k, _ in parts):
        return None
    sql, binds, types = "", [], ""
    for idx, (kind, val) in enumerate(parts):
        if kind == "str":
            sql += val
            continue
        nxt = parts[idx + 1][1] if idx + 1 < len(parts) and parts[idx + 1][0] == "str" else None
        if sql.endswith("'") and nxt is not None and "'" in nxt:
            # '" . $x . "suffix'  ->  ?  with the literal suffix moved into the bound value (LIKE '...%')
            k = nxt.index("'")
            suffix = nxt[:k]
            if "?" in suffix or "'" in suffix:
                return None
            sql = sql[:-1] + "?"
            parts[idx + 1] = ("str", nxt[k + 1:])
            val = f"{val} . '{suffix}'" if suffix else val
            types += "s"
        elif sql.endswith("'"):
            return None                              # unbalanced quoting: leave for a human
        else:
            sql += "?"
            types += "i" if re.search(r"\(int\)|intval", val) or sql.rstrip("?").rstrip().upper().endswith(("=", "LIMIT", "OFFSET")) else "s"
        binds.append(val)
    ind, lhs, db = m["indent"], (m["lhs"] or ""), m["db"]
    sql_lit = '"' + sql.replace('"', '\\"') + '"'
    out, names = [], []
    for k, b in enumerate(binds, start=1):           # bind_param takes variables by reference, never expressions
        if re.fullmatch(r"\$\w+", b):
            names.append(b)
        else:
            out.append(f"{ind}$p{k} = {b};\n")
            names.append(f"$p{k}")
    out += [f"{ind}$st = mysqli_prepare({db}, {sql_lit});\n",
            f"{ind}mysqli_stmt_bind_param($st, \"{types}\", {', '.join(names)});\n",
            f"{ind}mysqli_stmt_execute($st);\n"]
    if lhs:
        out.append(f"{ind}{lhs}mysqli_stmt_get_result($st);\n")
    return out


def php_findings(src: Path) -> tuple[list[dict], list[str]]:
    findings, diffs = [], []
    for f in sorted(src.rglob("*.php")):
        rel = f.relative_to(src).as_posix()
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        new, changed = [], False
        for no, line in enumerate(lines, start=1):
            if _WEAK_HASH.search(line):
                findings.append({"file": rel, "line": no, "issue": "hash sandi md5/sha1",
                                 "fix": "password_hash()/password_verify() (argon2id/bcrypt) + migrasi hash saat login berikutnya", "auto_diff": False})
            if _SQL_BUILD.search(line) and "mysqli_query" not in line:
                findings.append({"file": rel, "line": no, "issue": "SQL dirangkai dari variabel lalu dijalankan di baris lain (SQL injection)",
                                 "fix": "prepared statement (perlu ditulis manual: query dan eksekusinya terpisah)", "auto_diff": False})
            if "mysqli_query" in line and "." in line.split("mysqli_query", 1)[1]:
                rep = _prepared(line)
                findings.append({"file": rel, "line": no, "issue": "SQL dirangkai dari variabel (SQL injection)",
                                 "fix": "prepared statement" + ("" if rep else " (perlu ditulis manual)"), "auto_diff": bool(rep)})
                if rep:
                    new.extend(rep)
                    changed = True
                    continue
            new.append(line)
        if changed:
            diffs.append("".join(difflib.unified_diff(lines, new, f"a/{rel}", f"b/{rel}")))
    return findings, diffs


def generate(target: str, app_src: Path | None = None, out_dir: Path = OUT) -> dict:
    d = out_dir / "patches" / target
    d.mkdir(parents=True, exist_ok=True)
    app_user = f"palmerah_{target}_app"
    stack = "PHP/MySQL" if target == "a" else "Node/PostgreSQL"
    guide = [f"# Patch website {target.upper()} ({stack}) — NEEDS HUMAN REVIEW", "",
             "Shield sudah mengubah database. Bagian di bawah butuh perubahan kode aplikasi; tinjau dan terapkan oleh pemilik web.", "",
             "## 1. Berhenti memakai root/superuser",
             f"Login database: `{app_user}` (sandi di `.local/app-credentials-{target}.json`, jangan di-commit).",
             "Login ini tidak bisa membaca tabel dasar; setiap request memilih peran pengguna yang sudah diautentikasi:", ""]
    if target == "a":
        guide += ["```php", "$db = mysqli_init();", "mysqli_ssl_set($db, null, null, $CA_FILE, null, null);",
                  f"mysqli_real_connect($db, '127.0.0.1', '{app_user}', getenv('DB_PASS'), null, 3306, null, MYSQLI_CLIENT_SSL);",
                  "mysqli_query($db, 'SET ROLE palmerah_a_r_' . $role);          // $role dari sesi server, bukan dari request",
                  "if ($role === 'anggota') { $st = mysqli_prepare($db, 'SET @palmerah_member_id = ?'); mysqli_stmt_bind_param($st, 'i', $memberId); mysqli_stmt_execute($st); }",
                  "$res = mysqli_query($db, \"SELECT * FROM web_legacy.v_{$role}_anggota\");", "```"]
    else:
        guide += ["```js", f"const client = await pool.connect();   // user: '{app_user}', ssl: {{ ca, rejectUnauthorized: true }}",
                  "await client.query(`SET ROLE ${pgFormat.ident('palmerah_b_r_' + role)}`);   // role dari sesi server",
                  "if (role === 'anggota') await client.query(\"SELECT set_config('palmerah.member_id', $1, false)\", [String(memberId)]);",
                  "const { rows } = await client.query(`SELECT * FROM shield.v_${role}_members WHERE id = $1`, [id]);",
                  "await client.query('RESET ROLE'); client.release();", "```"]
    guide += ["", "## 2. Kolom terenkripsi kini hanya-baca lewat VIEW",
              "Fitur yang MENULIS kolom terenkripsi/ditokenisasi (mis. ubah alamat, email) harus memanggil layanan Shield yang "
              "mengenkripsi dengan DEK kolom itu (rencana S4); jangan menulis plaintext ke tabel dasar.", "",
              "## 3. Nilai `pal1:...` di respons",
              "Untuk peran berlevel full, VIEW mengembalikan envelope `pal1:...`; reverse proxy Shield (S4) mendekripsi field yang "
              "diizinkan matriks untuk peran itu. Jangan mendekripsi di browser."]
    (d / "01-login-least-privilege.md").write_text("\n".join(guide) + "\n", encoding="utf-8")
    result = {"target": target, "needs_human_review": True, "files": ["01-login-least-privilege.md"], "code_findings": []}
    if app_src:
        findings, diffs = php_findings(app_src)
        result["code_findings"] = findings
        if diffs:
            with open(d / "02-prepared-statements.diff", "w", encoding="utf-8", newline="") as f:   # keep the source line endings
                f.write("".join(diffs))
            result["files"].append("02-prepared-statements.diff")
            result["behaviour_change"] = ("prepared statement (mysqlnd) mengembalikan angka sebagai int, query teks sebagai string: "
                                          "JSON berubah dari \"id\":\"17\" menjadi \"id\":17. Periksa kode frontend yang membandingkan dengan ===. "
                                          "Diuji pada target php-react-demo: isi data identik, hanya tipe yang berubah.")
        manual = [f for f in findings if not f["auto_diff"]]
        if manual:
            result["manual"] = [f"{f['file']}:{f['line']} {f['issue']} -> {f['fix']}" for f in manual]
    (d / "patches.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result
