"""`shield scan`: read a sample of every column (from a .sql dump or a live MySQL/PostgreSQL connection), classify it
by content (detect.py), compare with the contract's reference classification, and write out/inventory.json.

Sample values never leave this module unmasked: the inventory carries `sample_masked` only.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path

from . import ops
from .config import OUT
from .detect import HEALTH_TERMS, detect_column
from .reference import CLASSES, PROTECT, TRAPS, reference_a, reference_b
from .sqldump import read_dump

SAMPLE_ROWS = 20_000


# ---------- readers: {table: {"columns": [...], "rows": [[...]]}} ----------
def read_live(kind: str, conn) -> dict[str, dict]:
    tables: dict[str, dict] = {}
    if kind == "mysql":
        with conn.cursor() as cur:
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY 1")
            names = [r[0] for r in cur.fetchall()]
            for t in names:
                cur.execute(f"SELECT * FROM `{t}` LIMIT {SAMPLE_ROWS}")
                tables[t] = {"columns": [d[0] for d in cur.description], "rows": [list(r) for r in cur.fetchall()]}
    else:
        names = [r[0] for r in conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1")]
        for t in names:
            cur = conn.execute(f'SELECT * FROM "{t}" LIMIT {SAMPLE_ROWS}')
            tables[t] = {"columns": [d.name for d in cur.description], "rows": [list(r) for r in cur.fetchall()]}
    return tables


def read_target(target: str) -> tuple[dict[str, dict], str]:
    from .db import MYSQL_DB, PG_DB, mysql_connect, pg_connect
    if target == "a":
        with mysql_connect() as c:
            return read_live("mysql", c), f"mysql://127.0.0.1:3306/{MYSQL_DB}"
    if target == "b":
        with pg_connect() as c:
            return read_live("pg", c), f"postgresql://127.0.0.1:5432/{PG_DB}"
    raise ValueError("target must be 'a' or 'b'")


# ---------- masking ----------
def mask(v) -> str | None:
    if v is None:
        return None
    s = v.isoformat() if isinstance(v, (dt.date, dt.datetime)) else str(v)
    if "@" in s and re.match(r"^[^@\s]+@", s):
        local, _, domain = s.partition("@")
        return f"{local[:1]}***@{domain}"
    if s.isdigit():
        return "*" * max(0, len(s) - 4) + s[-4:] if len(s) > 4 else "*" * len(s)
    if len(s) <= 4:
        return "*" * len(s)
    return f"{s[:2]}***({len(s)} karakter)"


# ---------- scan ----------
def _context(tables: dict[str, dict]) -> dict:
    """Cross-column evidence: person-name columns (for truncated copies) and fixed-length identifier columns."""
    name_values, id_values, health_tables = {}, {}, set()
    for t, d in tables.items():
        for i, _ in enumerate(d["columns"]):   # a table holding medical vocabulary in any column is a health table
            texts = [r[i].lower() for r in d["rows"] if isinstance(r[i], str)]
            if texts and sum(any(w in s for w in HEALTH_TERMS) for s in texts) / len(texts) > 0.4:
                health_tables.add(t)
        for i, c in enumerate(d["columns"]):
            vals = [r[i] for r in d["rows"] if isinstance(r[i], str) and r[i].strip()]
            if len(vals) < 20:
                continue
            uniq = len(set(vals)) / len(vals)
            if uniq > 0.9 and sum(" " in v and sum(ch.isalpha() for ch in v) >= len(v) * 0.5 for v in vals) / len(vals) > 0.9:
                name_values[(t, c)] = vals
            if all(v.isdigit() for v in vals) and len({len(v) for v in vals}) == 1 and 12 <= len(vals[0]) <= 18 and uniq > 0.95:
                id_values[(t, c)] = set(vals)
    return {"name_values": name_values, "id_values": id_values, "health_tables": health_tables}


def _relations(columns: list[str], rows: list[list]) -> dict[str, list[str]]:
    """Columns whose values equal an earlier column in every sampled row: copies that add no information."""
    rel: dict[str, list[str]] = {}
    if not rows:
        return rel
    for j, c in enumerate(columns):
        for i in range(j):
            if all(r[i] == r[j] for r in rows) and any(r[j] is not None for r in rows):
                rel[c] = [f"identik dengan {columns[i]} di {len(rows)}/{len(rows)} baris"]
                break
    return rel


def classify(tables: dict[str, dict], use_names: bool = True) -> list[dict]:
    ctx = _context(tables)
    out = []
    for t, d in tables.items():
        rel = _relations(d["columns"], d["rows"])
        for i, c in enumerate(d["columns"]):
            vals = [r[i] for r in d["rows"]]
            f = detect_column(t, c, vals, ctx, use_names=use_names)
            sample = next((v for v in vals if v is not None), None)
            relations = rel.get(c, []) + [w for w in f.why if w.startswith("salinan 20 karakter")]
            out.append({"table": t, "column": c, "detected_class": f.cls, "pii_type": f.pii_type,
                        "confidence": round(f.confidence, 2), "why": f.why, "sample_masked": mask(sample),
                        "relations": relations})
    return out


def reference_for(tables: dict[str, dict]) -> tuple[str | None, dict]:
    if "anggota" in tables:
        return "website A (kontrak)", reference_a()
    if "members" in tables:
        return "website B (kontrak)", reference_b()
    return None, {}


def metrics(findings: list[dict], ref: dict) -> dict:
    """Precision/recall for 'must be protected' (contract classes SANGAT_TINGGI + TINGGI_*), exact-class accuracy,
    a confusion matrix, and whether the detector traps were caught."""
    scored = [f for f in findings if (f["table"], f["column"]) in ref]
    tp = sum(1 for f in scored if f["detected_class"] in PROTECT and ref[(f["table"], f["column"])] in PROTECT)
    fp = sum(1 for f in scored if f["detected_class"] in PROTECT and ref[(f["table"], f["column"])] not in PROTECT)
    fn = sum(1 for f in scored if f["detected_class"] not in PROTECT and ref[(f["table"], f["column"])] in PROTECT)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    exact = sum(1 for f in scored if f["detected_class"] == ref[(f["table"], f["column"])])
    confusion = Counter((ref[(f["table"], f["column"])], f["detected_class"]) for f in scored)
    wrong = [{"table": f["table"], "column": f["column"], "reference": ref[(f["table"], f["column"])], "detected": f["detected_class"]}
             for f in scored if f["detected_class"] != ref[(f["table"], f["column"])]]
    traps = {f"{t}.{c}": next((x["detected_class"] in PROTECT for x in scored if (x["table"], x["column"]) == (t, c)), None)
             for t, c in TRAPS if (t, c) in ref}
    return {
        "columns_scored": len(scored),
        "protect": {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3),
                    "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0},
        "class_accuracy": round(exact / len(scored), 3) if scored else 0.0,
        "confusion": {a: {b: confusion[(a, b)] for b in CLASSES if confusion[(a, b)]} for a in CLASSES if any(confusion[(a, b)] for b in CLASSES)},
        "mismatches": wrong,
        "traps_caught": traps,
    }


@ops.locked("scan")
def scan(target: str | None = None, dump: Path | None = None, dsn: str | None = None, out_dir: Path = OUT) -> dict:
    if dump:
        tables, source = read_dump(dump), f"dump:{dump.name}"
        name = target or dump.stem
    elif dsn:
        from .db import connect_dsn
        kind, conn = connect_dsn(dsn)
        with conn:
            tables = read_live(kind, conn)
        source, name = re.sub(r"//[^@]*@", "//***@", dsn), target or "dsn"     # never write credentials
    else:
        tables, source = read_target(target or "a")
        name = target or "a"
    ops.step("classify", tables=len(tables))
    findings = classify(tables)
    ref_name, ref = reference_for(tables)
    report = {
        "target": name, "source": source, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "rows_sampled": {t: len(d["rows"]) for t, d in tables.items()},
        "findings": findings,
    }
    if ref:
        content_only = classify(tables, use_names=False)
        report["metrics"] = {"reference": ref_name, "with_column_names": metrics(findings, ref),
                             "content_only": metrics(content_only, ref)}
        report["notes"] = ["room_code tercantum di INTERNAL dan PUBLIK pada kontrak; acuan memakai PUBLIK (docs/ASUMSI.md A6)",
                           "content_only = nama kolom diabaikan seluruhnya; membuktikan deteksi berbasis isi"]
    out_dir.mkdir(parents=True, exist_ok=True)
    text = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    (out_dir / "inventory.json").write_text(text, encoding="utf-8")
    (out_dir / f"inventory_{name}.json").write_text(text, encoding="utf-8")
    return report
