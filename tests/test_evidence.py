"""Evidence helpers that need no database: classification of what a value is, and that plaintext is never displayed."""
from palmerah_shield import crypto
from palmerah_shield.evidence import FIELDS, kind_of, shown, _targets


def test_kinds():
    orig = {"00000648505443"}
    assert kind_of("nik", None, orig) == "none"
    assert kind_of("nik", "00000648505443", orig) == "PLAINTEXT"          # equals a known original
    assert kind_of("npwp", "pal1:abc:ZGF0YQ==", orig) == "envelope"
    assert kind_of("nik", "**********5443", orig) == "masked"
    assert kind_of("nik", "91175523842877", orig) == "token"              # tokenised field, not an original
    assert kind_of("mobile", "081234", set()) == "other"                  # unknown: reported, not assumed safe


def test_plaintext_is_never_shown_and_long_values_are_cut():
    assert "0000" not in shown("00000648505443", "PLAINTEXT")
    long = crypto.PREFIX + ":k:" + "A" * 200
    assert len(shown(long, "envelope")) < 80 and shown(None, "none") is None


def test_targets_follow_the_plan():
    plan = {"columns": [{"field": "nik", "table": "anggota", "column": "no_ktp", "controls": ["tokenize"]},
                        {"field": "email", "table": "anggota", "column": "email", "controls": []},
                        {"field": "zzz", "table": "t", "column": "c", "controls": ["encrypt-AEAD"]}]}
    assert _targets(plan) == [{"field": "nik", "table": "anggota", "column": "no_ktp"}]
    assert "ref_code" in FIELDS
