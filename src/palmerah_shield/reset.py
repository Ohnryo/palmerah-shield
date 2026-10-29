"""`make reset`: back to the vulnerable starting point, idempotently and in well under 30 s.

Rebuilds both fixture databases from the seed, removes everything `shield apply` creates, and records MODE=vuln.
Later stages register their own cleanup in RESET_HOOKS (roles, views, KMS keys, proxy state)."""
from __future__ import annotations

import time
from typing import Callable

from . import devenv, seed
from .config import settings

RESET_HOOKS: list[Callable[[], None]] = []


def write_mode(mode: str) -> None:
    if mode not in ("vuln", "hardened"):
        raise ValueError(mode)
    f = settings().mode_file
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(f"MODE={mode}\n", encoding="ascii")


def reset() -> dict[str, object]:
    t0 = time.perf_counter()
    devenv.init()
    devenv.start()
    from .apply import cleanup_all
    cleanup_all()                       # roles, app logins, apply state, token vault
    for hook in RESET_HOOKS:
        hook()
    counts = seed.load_all()
    write_mode("vuln")
    return {"mode": "vuln", "rows": counts, "seconds": round(time.perf_counter() - t0, 2)}
