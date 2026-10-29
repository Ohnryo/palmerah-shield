"""`shield benchmark`: cost of the protections, before vs after, on enlarged synthetic data -> out/benchmark_<t>.json.

For each size: load n plaintext members (seed.scale_rows) -> measure "before" (the vulnerable app as root) -> apply
(timed per step) -> measure "after" (application login + SET ROLE + per-role VIEW, plus the proxy's decryption) ->
rollback. At the end the target is reloaded from the seed (734 rows, MODE=vuln), i.e. the demo starting point.
DESTRUCTIVE for the target's current data: never run it during the demo.

Workload per phase (same random members both times):
* lookup  : one member's contact row by id                (after: VIEW v_sdm_* + proxy filter = decrypt)
* search  : find a member by NIK equality                 (after: blind index HMAC on the VIEW, indexed)
Reported: p50 / p95 / mean (ms), throughput (queries/s), errors; database size; dump (backup) time and size;
restore time; client CPU seconds and peak RSS of this process (database server CPU is not measured here).
"""
from __future__ import annotations

import datetime as dt
import json
import platform
import random
import shutil
import statistics
import sys
import time
from pathlib import Path

from . import crypto, ops, seed
from .apply import DIALECTS, apply, rollback, write_mode
from .config import LOCAL, OUT
from .kms import Client

DEFAULT_SIZES = [10_000, 100_000]
QUERIES = 300

try:
    import resource
except ImportError:                    # Windows: no getrusage
    resource = None


def _usage() -> dict:
    if resource is None:
        return {"cpu_s": None, "peak_rss_mb": None}
    u = resource.getrusage(resource.RUSAGE_SELF)
    rss = u.ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)
    return {"cpu_s": u.ru_utime + u.ru_stime, "peak_rss_mb": round(rss, 1)}


def _stats(lat: list[float], errors: int, wall: float) -> dict:
    if not lat:
        return {"n": 0, "errors": errors}
    q = statistics.quantiles(lat, n=20) if len(lat) >= 20 else [max(lat)] * 19
    return {"n": len(lat), "errors": errors, "p50_ms": round(statistics.median(lat) * 1000, 3),
            "p95_ms": round(q[18] * 1000, 3), "mean_ms": round(statistics.fmean(lat) * 1000, 3),
            "qps": round(len(lat) / wall, 1) if wall else None}


def _run(fn, args: list) -> dict:
    lat, errors = [], 0
    t0 = time.perf_counter()
    for a in args:
        s = time.perf_counter()
        try:
            fn(a)
            lat.append(time.perf_counter() - s)
        except Exception:
            errors += 1
    return _stats(lat, errors, time.perf_counter() - t0)


# ---------- per-dialect bits ----------
SQL = {
    "b": {"lookup_table": "member_contacts", "key": "member_id", "search_table": "member_finance", "nik": "nik",
          "size": "SELECT pg_database_size(current_database())"},
    "a": {"lookup_table": "anggota", "key": "id", "search_table": "anggota", "nik": "no_ktp",
          "size": "SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = DATABASE()"},
}


def _size(d, cur) -> int:
    cur.execute(SQL[d.target]["size"])
    return int(cur.fetchone()[0] or 0)


def _before(d, sample: list[tuple]) -> dict:
    s = SQL[d.target]
    with d.connect() as conn:
        cur = conn.cursor()
        size = _size(d, cur)

        def lookup(a):
            cur.execute(f"SELECT * FROM {d.q(s['lookup_table'])} WHERE {d.q(s['key'])} = %s", (a[0],))
            cur.fetchall()

        def search(a):
            cur.execute(f"SELECT {d.q(s['key'])} FROM {d.q(s['search_table'])} WHERE {d.q(s['nik'])} = %s", (a[1],))
            if not cur.fetchall():
                raise LookupError
        u0 = _usage()
        res = {"lookup": _run(lookup, sample), "search": _run(search, sample)}
        u1 = _usage()
    return {**res, "db_bytes": size, "client_cpu_s": _delta(u0, u1), "peak_rss_mb": u1["peak_rss_mb"]}


def _after(d, sample: list[tuple]) -> dict:
    from .access import ensure_matrix
    from .proxy import Keys, Policy, filter_json
    s = SQL[d.target]
    state = json.loads((LOCAL / "state" / f"applied_{d.target}.json").read_text(encoding="utf-8"))
    pw = json.loads(Path(state["app_password_file"]).read_text(encoding="utf-8"))["password"]
    kms = Client("benchmark")
    with d.connect() as conn:
        cur = conn.cursor()
        size = _size(d, cur)
        cur.execute("SELECT key_id, name, wrapped FROM shield_keys")
        rows = cur.fetchall()
    bname = f"{d.db}:{s['search_table']}.{s['nik']}:bidx"
    brow = next(r for r in rows if r[1] == bname)
    ikey = kms.unwrap(brow[0], brow[1], brow[2])
    keys = Keys(kms, lambda: [r for r in rows if r[1].endswith(":aead")])
    policy = Policy(ensure_matrix()[0], d.target)
    with d.app_connect(pw) as c:
        cur = c.cursor()
        cur.execute(f"SET ROLE {d.roles()['sdm']}")
        def lookup(a):
            cur.execute(f"SELECT * FROM {d.view('sdm', s['lookup_table'])} WHERE {d.q(s['key'])} = %s", (a[0],))
            names = [x[0] for x in cur.description]
            doc = [dict(zip(names, r)) for r in cur.fetchall()]
            filter_json(doc, "sdm", None, policy, keys)          # what the proxy does before the browser sees it

        def search(a):
            cur.execute(f"SELECT {d.q(s['key'])} FROM {d.view('sdm', s['search_table'])} WHERE {d.q(s['nik'] + '_bidx')} = %s",
                        (crypto.blind_index(ikey, a[1]),))
            if not cur.fetchall():
                raise LookupError
        lookup(sample[0])                                          # warm the DEK cache (one unwrap per column)
        u0 = _usage()
        res = {"lookup": _run(lookup, sample), "search": _run(search, sample)}
        u1 = _usage()
    return {**res, "db_bytes": size, "client_cpu_s": _delta(u0, u1), "peak_rss_mb": u1["peak_rss_mb"]}


def _delta(u0: dict, u1: dict):
    return None if u0["cpu_s"] is None else round(u1["cpu_s"] - u0["cpu_s"], 3)


def _backup_restore(d) -> dict:
    t0 = time.perf_counter()
    dump = d.dump()
    t1 = time.perf_counter()
    return {"dump_s": round(t1 - t0, 2), "dump_bytes": len(dump), "_dump": dump}


@ops.locked("benchmark")
def benchmark(target: str, sizes: list[int] | None = None, out_dir: Path = OUT) -> dict:
    d = DIALECTS[target]()
    sizes = sizes or DEFAULT_SIZES
    plan_file = out_dir / f"plan_{target}.json"
    if not plan_file.exists():
        raise RuntimeError(f"belum ada {plan_file.name}: jalankan scan + plan dulu (benchmark memakai rencana yang sama)")
    if (LOCAL / "state" / f"applied_{target}.json").exists():
        raise RuntimeError("target sedang hardened: rollback dulu (benchmark memuat ulang data target)")
    work = out_dir / f"bench_{target}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    shutil.copy(plan_file, work / plan_file.name)
    cols, base = seed.dump_rows()
    s = SQL[target]
    results = []
    try:
        for n in sizes:
            ops.step("load", rows=n)
            t0 = time.perf_counter()
            seed.load_target(target, cols, seed.scale_rows(cols, base, n))
            load_s = time.perf_counter() - t0
            with d.connect() as conn:                  # sample of real (member, nik) pairs, kept in memory only
                cur = conn.cursor()
                cur.execute(f"SELECT {d.q(s['key'])}, {d.q(s['nik'])} FROM {d.q(s['search_table'])}")
                pairs = cur.fetchall()
            sample = random.Random(n).sample(pairs, min(QUERIES, len(pairs)))
            ops.step("measure_before", rows=n)
            before = _before(d, sample)
            br = _backup_restore(d)
            t0 = time.perf_counter()
            d.restore(br.pop("_dump"))
            before.update(br, restore_s=round(time.perf_counter() - t0, 2))

            ops.step("apply", rows=n)
            marks: list[tuple[str, float]] = []
            t0 = time.perf_counter()
            with ops.listening(lambda e: marks.append((e["step"], time.perf_counter()))):
                apply(target, out_dir=work)
            apply_s = time.perf_counter() - t0
            steps = [{"step": a, "seconds": round((marks[i + 1][1] if i + 1 < len(marks) else t0 + apply_s) - ts, 2)}
                     for i, (a, ts) in enumerate(marks)]
            merged: dict[str, float] = {}
            for x in steps:
                merged[x["step"]] = round(merged.get(x["step"], 0) + x["seconds"], 2)

            ops.step("measure_after", rows=n)
            after = _after(d, sample)
            br = _backup_restore(d)
            after.update({k: v for k, v in br.items() if k != "_dump"})

            ops.step("rollback", rows=n)
            t0 = time.perf_counter()
            rollback(target, out_dir=work)
            rollback_s = time.perf_counter() - t0
            results.append({"members": n, "load_s": round(load_s, 2), "before": before, "after": after,
                            "apply": {"seconds": round(apply_s, 2), "members_per_s": round(n / apply_s, 1), "steps": merged},
                            "rollback_s": round(rollback_s, 2)})
    finally:
        ops.step("reload_seed")
        if (LOCAL / "state" / f"applied_{target}.json").exists():
            rollback(target, out_dir=work)
        seed.load_target(target)
        write_mode(target, "vuln")
        shutil.rmtree(work, ignore_errors=True)
    report = {
        "target": target, "database": d.db, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "queries_per_workload": QUERIES, "role_after": "sdm",
        "machine": {"platform": platform.platform(), "python": platform.python_version(), "cpus": __import__("os").cpu_count()},
        "sizes": results,
        "notes": [
            "data sintetis hasil seed.scale_rows (identitas unik baru per baris); bukan data nyata",
            "before = aplikasi rentan sebagai root/postgres pada tabel dasar; after = login aplikasi + SET ROLE sdm + VIEW, "
            "lookup termasuk dekripsi oleh filter proxy, search memakai blind index (berindeks)",
            "search: kolom nik pada skema rentan tidak berindeks, nik_bidx sesudah apply berindeks; selisih search karena indeks, "
            "bukan karena enkripsi",
            "CPU/RAM = proses benchmark (klien + kripto proxy); RSS puncak didominasi apply yang memuat seluruh tabel ke memori; "
            "CPU server database tidak diukur",
            "dump after lebih besar karena ciphertext + kolom bidx/mask; restore after tidak diukur (rollback memulihkan backup)",
        ],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"benchmark_{target}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
