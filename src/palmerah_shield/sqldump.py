"""Read rows out of a .sql dump without a database: INSERT statements (MySQL and PostgreSQL --inserts style)
and PostgreSQL COPY ... FROM stdin blocks. Values come back as Python str/int/float/None."""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

_INSERT = re.compile(r"INSERT\s+INTO\s+([`\"\w.]+)\s*(\(([^)]*)\))?\s*VALUES\s*", re.I)
_CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`\"\w.]+)\s*\((.*?)\n\)", re.I | re.S)
_NOT_COLUMN = re.compile(r"^(CONSTRAINT|PRIMARY|UNIQUE|KEY|INDEX|FOREIGN|CHECK|FULLTEXT|SPATIAL)\b", re.I)
_COPY = re.compile(r"^COPY\s+([\"\w.]+)\s*\(([^)]*)\)\s+FROM\s+stdin;\s*$", re.I | re.M)
_NUM = re.compile(r"-?\d+(\.\d+)?([eE][-+]?\d+)?$")
_ESC = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "Z": "\x1a"}


def _ident(s: str) -> str:
    return s.strip().strip("`\"").split(".")[-1].strip("`\"")


def _parse_values(text: str, i: int, mysql_escapes: bool):
    """Parse `(v, v, ...), (...)` starting at text[i]; returns (rows, index after the statement)."""
    rows: list[list] = []
    n = len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n,":
            i += 1
        if i >= n or text[i] == ";":
            return rows, i + 1
        if text[i] != "(":
            raise ValueError(f"unexpected {text[i]!r} at {i}")
        i += 1
        row: list = []
        while True:
            while text[i] in " \t\r\n":
                i += 1
            backslash = mysql_escapes
            if text[i] in "Ee" and text[i + 1] == "'":   # PostgreSQL E'...' string: backslash escapes apply
                backslash = True
                i += 1
            if text[i] == "'":                      # quoted string: '' or \x escapes
                i += 1
                buf = []
                while True:
                    c = text[i]
                    if c == "\\" and backslash:
                        nxt = text[i + 1]
                        buf.append(_ESC.get(nxt, nxt))
                        i += 2
                    elif c == "'":
                        if i + 1 < n and text[i + 1] == "'":
                            buf.append("'")
                            i += 2
                        else:
                            i += 1
                            break
                    else:
                        buf.append(c)
                        i += 1
                row.append("".join(buf))
            else:                                   # bare token: NULL, number, true/false
                j = i
                while text[j] not in ",)":
                    j += 1
                tok = text[i:j].strip()
                i = j
                if tok.upper() == "NULL":
                    row.append(None)
                elif _NUM.match(tok):
                    row.append(float(tok) if any(ch in tok for ch in ".eE") else int(tok))
                else:
                    row.append(tok)
            while text[i] in " \t\r\n":
                i += 1
            if text[i] == ",":
                i += 1
                continue
            if text[i] == ")":
                i += 1
                rows.append(row)
                break
            raise ValueError(f"unexpected {text[i]!r} at {i}")
    return rows, i


def _copy_value(v: str):
    if v == r"\N":
        return None
    return re.sub(r"\\(.)", lambda m: _ESC.get(m.group(1), m.group(1)), v)


def read_dump(path: Path) -> dict[str, dict]:
    """{table: {"columns": [...], "rows": [[...], ...]}} for every table that has data in the dump."""
    text = path.read_text(encoding="utf-8", errors="replace")
    mysql_escapes = "`" in text[:20000] or "ENGINE=" in text[:50000]
    tables: dict[str, dict] = defaultdict(lambda: {"columns": [], "rows": []})
    declared: dict[str, list[str]] = {}             # INSERTs without a column list (pg_dump --inserts) use these
    for m in _CREATE.finditer(text):
        cols = []
        for line in m.group(2).split("\n"):
            line = line.strip().rstrip(",")
            if line and not _NOT_COLUMN.match(line) and not line.startswith("--"):
                cols.append(_ident(line.split()[0]))
        declared[_ident(m.group(1))] = cols
    pos = 0
    while (m := _INSERT.search(text, pos)):
        name = _ident(m.group(1))
        cols = [_ident(c) for c in m.group(3).split(",")] if m.group(3) else declared.get(name, [])
        rows, pos = _parse_values(text, m.end(), mysql_escapes)
        t = tables[name]
        if cols and not t["columns"]:
            t["columns"] = cols
        t["rows"].extend(rows)
    for m in _COPY.finditer(text):
        name = _ident(m.group(1))
        cols = [_ident(c) for c in m.group(2).split(",")]
        end = text.index("\n\\.", m.end())
        t = tables[name]
        t["columns"] = t["columns"] or cols
        for line in text[m.end():end].splitlines():
            if line:
                t["rows"].append([_copy_value(v) for v in line.split("\t")])
    return dict(tables)
