"""Settings come from .env (and the process environment, which wins). Nothing secret lives in the repo."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / ".local"          # databases, certificates, KMS state: gitignored
OUT = ROOT / "out"               # tool output (JSON + scoreboards): gitignored


def read_env_file(path: Path = ROOT / ".env") -> dict[str, str]:
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()
    return values


def write_env_value(key: str, value: str, path: Path = ROOT / ".env") -> None:
    """Set one key in .env, keeping every other line as it is."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key:
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _resolve(p: str) -> Path:
    q = Path(p)
    return q if q.is_absolute() else (ROOT / q).resolve()


@dataclass(frozen=True)
class Settings:
    seed_dump: Path
    mariadb_home: Path
    pg_home: Path
    mysql_port: int
    mysql_root_password: str
    pg_port: int
    pg_super_password: str
    kms_url: str
    kms_token: str
    mode_file: Path

    @property
    def ca_cert(self) -> Path:
        return LOCAL / "certs" / "ca.crt"


def settings() -> Settings:
    e = {**read_env_file(), **{k: v for k, v in os.environ.items() if k.isupper()}}
    return Settings(
        seed_dump=_resolve(e.get("SEED_DUMP", "../hackathon_dprri-main/anggota_dummy.sql")),
        mariadb_home=_resolve(e.get("MARIADB_HOME", "../benteng-platform/.tools/mariadb")),
        pg_home=_resolve(e.get("PG_HOME", "../hackathon_dprri-main/.tools/pg16/pgsql")),
        mysql_port=int(e.get("MYSQL_PORT", "3306")),
        mysql_root_password=e.get("MYSQL_ROOT_PASSWORD", ""),
        pg_port=int(e.get("PG_PORT", "5432")),
        pg_super_password=e.get("PG_SUPER_PASSWORD", ""),
        kms_url=e.get("KMS_URL", "http://127.0.0.1:8200"),
        kms_token=e.get("KMS_TOKEN", ""),
        mode_file=_resolve(e.get("MODE_FILE", "out/MODE")),
    )
