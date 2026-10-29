"""One operation at a time, and progress for whoever is watching.

* `exclusive(name)`: an OS file lock on .local/state/op.lock, shared by the CLI and the web console, so `apply` from
  one door and `rollback` from the other can never run on the same databases at once. The OS releases the lock when
  the process dies, so a crash never leaves a stale lock. Re-entrant within one thread (plan may call scan).
* `step(...)`: progress events. The CLI ignores them; the console runner installs a listener and streams them (SSE).
  Events carry step names and counts only, never data values.
"""
from __future__ import annotations

import contextvars
import functools
import json
import os
import sys
import threading
import time
from contextlib import contextmanager
from typing import Callable, Iterator

from .config import LOCAL

LOCK_FILE = LOCAL / "state" / "op.lock"
INFO_FILE = LOCAL / "state" / "op.json"        # who holds the lock (informational; the lock itself is the OS lock)

_listener: contextvars.ContextVar[Callable[[dict], None] | None] = contextvars.ContextVar("palmerah_progress", default=None)
_held = threading.local()


class Busy(RuntimeError):
    """Another Shield operation holds the lock."""


def current() -> dict | None:
    """The operation that holds the lock, if any (read from the lock file; no lock taken)."""
    try:
        raw = INFO_FILE.read_text(encoding="utf-8").strip()
        info = json.loads(raw) if raw else None
    except (OSError, ValueError):
        return None
    if not info:
        return None
    if getattr(_held, "depth", 0):
        return info
    try:                         # holder gone: the OS released the lock; the info file is just left over
        with _os_lock():
            return None
    except Busy:
        return info


@contextmanager
def _os_lock() -> Iterator[None]:
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if sys.platform == "win32":
            import msvcrt
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise Busy("operasi lain sedang berjalan") from None
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy("operasi lain sedang berjalan") from None
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextmanager
def exclusive(name: str) -> Iterator[None]:
    depth = getattr(_held, "depth", 0)
    if depth:
        _held.depth = depth + 1
        try:
            yield
        finally:
            _held.depth -= 1
        return
    with _os_lock():
        INFO_FILE.write_text(json.dumps({"op": name, "pid": os.getpid(), "since": time.strftime("%Y-%m-%dT%H:%M:%S")}),
                             encoding="utf-8")
        _held.depth = 1
        try:
            yield
        finally:
            _held.depth = 0
            INFO_FILE.write_text("", encoding="utf-8")


def locked(name: str):
    """Decorator form of `exclusive`."""
    def wrap(fn):
        @functools.wraps(fn)
        def inner(*a, **kw):
            with exclusive(name):
                return fn(*a, **kw)
        return inner
    return wrap


def step(name: str, **info) -> None:
    fn = _listener.get()
    if fn is not None:
        fn({"step": name, **info})


@contextmanager
def listening(fn: Callable[[dict], None]) -> Iterator[None]:
    tok = _listener.set(fn)
    try:
        yield
    finally:
        _listener.reset(tok)
