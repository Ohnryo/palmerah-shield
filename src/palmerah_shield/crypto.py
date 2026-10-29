"""Field crypto as agreed in the contract.

* AES-256-GCM, a fresh random 96-bit nonce for every value (never deterministic). AAD binds the ciphertext to its
  place: "<db>:<table>:<column>:<primary key>", so a ciphertext copied to another row or column fails to decrypt.
* Plaintext is padded to a multiple of 16 bytes (ISO/IEC 7816-4) so ciphertext length does not reveal short values
  (a religion or blood type would otherwise be guessable from its length).
* Envelope text stored in the database: "pal1:<key_id>:<base64(nonce || ciphertext+tag)>".
* Blind index: HMAC-SHA256(normalize(value), index_key), hex, for equality search on nik and email only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "pal1"
BLOCK = 16


def pad(data: bytes) -> bytes:
    n = BLOCK - (len(data) + 1) % BLOCK
    return data + b"\x80" + b"\x00" * (n % BLOCK)


def unpad(data: bytes) -> bytes:
    i = data.rstrip(b"\x00")
    if not i.endswith(b"\x80"):
        raise ValueError("bad padding")
    return i[:-1]


def aad_for(db: str, table: str, column: str, pk) -> bytes:
    return f"{db}:{table}:{column}:{pk}".encode()


def encrypt(dek: bytes, key_id: str, value: str, aad: bytes) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(dek).encrypt(nonce, pad(value.encode("utf-8")), aad)
    return f"{PREFIX}:{key_id}:{base64.b64encode(nonce + ct).decode('ascii')}"


def parse(envelope: str) -> tuple[str, bytes]:
    prefix, key_id, body = envelope.split(":", 2)
    if prefix != PREFIX:
        raise ValueError("not a Shield envelope")
    return key_id, base64.b64decode(body)


def decrypt(dek: bytes, envelope: str, aad: bytes) -> str:
    _, raw = parse(envelope)
    return unpad(AESGCM(dek).decrypt(raw[:12], raw[12:], aad)).decode("utf-8")


def normalize(value: str) -> str:
    v = value.strip().lower()
    return "".join(ch for ch in v if ch not in " -.") if v.replace(" ", "").replace("-", "").isdigit() else v


def blind_index(index_key: bytes, value: str) -> str:
    return hmac.new(index_key, normalize(value).encode("utf-8"), hashlib.sha256).hexdigest()


def is_envelope(v) -> bool:
    return isinstance(v, str) and v.startswith(PREFIX + ":")
