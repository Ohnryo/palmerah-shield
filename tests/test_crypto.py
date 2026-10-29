"""Field crypto: AEAD binding, random nonce, padding, blind index normalisation."""
import os

import pytest
from cryptography.exceptions import InvalidTag

from palmerah_shield import crypto

DEK = os.urandom(32)


def test_roundtrip_and_aad_binding():
    e = crypto.encrypt(DEK, "k1", "00000648505443", crypto.aad_for("db", "t", "nik", 1))
    assert crypto.decrypt(DEK, e, crypto.aad_for("db", "t", "nik", 1)) == "00000648505443"
    with pytest.raises(InvalidTag):                       # copied to another row
        crypto.decrypt(DEK, e, crypto.aad_for("db", "t", "nik", 2))
    with pytest.raises(InvalidTag):                       # copied to another column
        crypto.decrypt(DEK, e, crypto.aad_for("db", "t", "npwp", 1))


def test_nonce_is_random_never_deterministic():
    aad = crypto.aad_for("db", "t", "c", 1)
    assert crypto.encrypt(DEK, "k", "Islam", aad) != crypto.encrypt(DEK, "k", "Islam", aad)


def test_padding_hides_short_value_lengths():
    lengths = {len(crypto.encrypt(DEK, "k", v, b"a")) for v in ["Islam", "Hindu", "Buddha", "Konghucu", "Lain-lain", "O+", "AB-"]}
    assert len(lengths) == 1
    for v in ["", "x", "y" * 15, "z" * 16, "\x00tail\x00"]:
        assert crypto.unpad(crypto.pad(v.encode())) == v.encode()


def test_blind_index_normalises_and_is_keyed():
    k = os.urandom(32)
    assert crypto.blind_index(k, " 0000-0648-505443 ") == crypto.blind_index(k, "00000648505443")
    assert crypto.blind_index(k, "A@Example.com") == crypto.blind_index(k, "a@example.com")
    assert crypto.blind_index(os.urandom(32), "a@example.com") != crypto.blind_index(k, "a@example.com")
