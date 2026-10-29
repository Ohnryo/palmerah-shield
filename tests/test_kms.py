"""KMS read-only status/audit: counts and audit lines, never key material or values."""
import json

from palmerah_shield.kms import KMS


def test_status_and_audit_tail(tmp_path):
    k = KMS(tmp_path)
    toks = k.vault.tokenize("nik", ["00000648505443", "00000648505444"])
    k.audit("shield-apply", "tokenize", "nik", 2)
    k.audit("proxy-b", "detokenize", "nik", 6000)          # over the mass-read threshold
    s = k.status()
    assert s["tokens"] == {"nik": 2} and s["audit_lines"] == 2 and s["alerts"] == 1 and len(s["kek_id"]) == 12
    tail = k.audit_tail(1)
    assert tail[0]["caller"] == "proxy-b" and "alert" in tail[0]
    dumped = json.dumps([s, k.audit_tail(10)])
    assert "00000648505443" not in dumped and not any(t in dumped for t in toks)
    assert (tmp_path / "kek.bin").read_bytes().hex() not in dumped
