"""Held-out evaluation: a schema the detector was never tuned on (the hackathon "holdout" schema: staff, medical
records, internal activities, emergency contacts; different language style, FKs, health data, free text).

Its ground truth uses tiers (0..3) instead of contract classes, so only the protect decision is scored:
tier >= 2 must be protected. The first run is recorded as the frozen result; later runs after any rule change are
reported separately and are no longer held-out.
"""
from __future__ import annotations

import csv
from pathlib import Path

from .reference import PROTECT
from .scan import classify
from .sqldump import read_dump


def evaluate(dump: Path, truth_csv: Path) -> dict:
    tables = read_dump(dump)
    truth = {(r["table"], r["column"]): int(r["tier"]) for r in csv.DictReader(truth_csv.open(encoding="utf-8"))}
    out = {}
    for mode, use_names in (("with_column_names", True), ("content_only", False)):
        found = {(f["table"], f["column"]): f for f in classify(tables, use_names=use_names)}
        tp = fp = fn = 0
        rows = []
        for key, tier in sorted(truth.items()):
            f = found.get(key)
            pred = bool(f and f["detected_class"] in PROTECT)
            want = tier >= 2
            tp += pred and want
            fp += pred and not want
            fn += want and not pred
            rows.append({"table": key[0], "column": key[1], "tier": tier, "detected": f["detected_class"] if f else None,
                         "pii_type": f["pii_type"] if f else None, "ok": pred == want})
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        out[mode] = {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3),
                     "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0,
                     "misses": [x for x in rows if not x["ok"]]}
    return out
