"""Proxy: per-role JSON filtering with real AES-GCM envelopes and a fake KMS, and the HTTP path end to end (stub website)."""
import json
import os
import ssl
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from palmerah_shield import crypto
from palmerah_shield.access import default_matrix
from palmerah_shield.proxy import Keys, Policy, build, filter_json

DEK = os.urandom(32)
NAME = "web_modern:member_contacts.mobile:aead"


class FakeKMS:
    def __init__(self):
        self.unwraps, self.detok = 0, []

    def unwrap(self, key_id, name, wrapped):
        assert (key_id, name, wrapped) == ("k1", NAME, "W")
        self.unwraps += 1
        return DEK

    def detokenize(self, domain, tokens):
        self.detok.append((domain, len(tokens)))
        return ["00000648505443" if t == "91175523842877" else None for t in tokens]


def env(value, member_id):
    return crypto.encrypt(DEK, "k1", value, crypto.aad_for("web_modern", "member_contacts", "mobile", member_id))


@pytest.fixture
def keys():
    return Keys(FakeKMS(), lambda: [("k1", NAME, "W")])


def doc():
    return [{"member_id": 1, "full_name": "Budi", "mobile": env("081234567890", 1), "email": "x", "nik": "91175523842877",
             "nik_bidx": "ab" * 32, "mystery": env("rahasia", 1)},
            {"member_id": 2, "full_name": "Siti", "mobile": env("081200000002", 2), "nik": "91175523842877"}]


def run(role, keys, member=None):
    return filter_json(doc(), role, member, Policy(default_matrix(), "b"), keys)


def test_public_sees_only_public_fields(keys):
    out, s = run("public", keys)
    assert out[0] == {"member_id": 1, "full_name": "Budi", "nik_bidx": "ab" * 32}
    assert s["decrypted"] == 0 and keys.kms.unwraps == 0 and keys.kms.detok == []     # nothing revealed, KMS untouched


def test_sdm_gets_decrypted_contact_and_masked_nik(keys):
    out, s = run("sdm", keys)
    assert out[0]["mobile"] == "081234567890" and out[1]["mobile"] == "081200000002"
    assert out[0]["nik"] == "**********5443"                           # masked after detokenising
    assert "mystery" not in out[0]                                     # envelope under an unknown key: removed
    assert s["decrypted"] == 2 and keys.kms.unwraps == 1 and keys.kms.detok == [("nik", 2)]   # one batch per domain


def test_medis_gets_masked_mobile(keys):
    out, _ = run("medis", keys)
    assert out[0]["mobile"] == "********7890" and "nik" not in out[0]


def test_anggota_sees_only_own_record(keys):
    out, _ = run("anggota", keys, member="1")
    assert out[0]["mobile"] == "081234567890" and out[0]["nik"] == "00000648505443"
    assert "mobile" not in out[1] and "nik" not in out[1]


def test_ciphertext_moved_to_another_row_does_not_decrypt(keys):
    d = [{"member_id": 2, "mobile": env("081234567890", 1)}]          # AAD binds row 1
    out, s = filter_json(d, "sdm", None, Policy(default_matrix(), "b"), keys)
    assert "mobile" not in out[0] and s["failed"] == 1


def test_website_a_column_names_are_mapped(keys):
    out, _ = filter_json([{"id": 1, "nama": "Budi", "no_ktp": "91175523842877", "agama": "Islam"}], "humas", None,
                         Policy(default_matrix(), "a"), keys)
    assert out == [{"id": 1, "nama": "Budi"}]


# ---------- HTTP ----------
class Stub(BaseHTTPRequestHandler):
    """Stands in for a website: role from its own 'session' (?as=), JSON body, headers to be stripped."""
    seen_role_header = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Stub.seen_role_header.append(self.headers.get("X-Palmerah-Role"))
        role = self.path.split("as=")[-1] if "as=" in self.path else None
        body = json.dumps(doc()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/5.6")
        if role:
            self.send_header("X-Palmerah-Role", role)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def proxy(tmp_path, keys):
    up = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    px = build("b", upstream=f"http://127.0.0.1:{up.server_address[1]}", port=0, keys=keys,
               policy_fn=lambda: Policy(default_matrix(), "b"), tls=False, audit_path=tmp_path / "audit.log")
    threading.Thread(target=px.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{px.server_address[1]}", tmp_path / "audit.log"
    px.shutdown()
    up.shutdown()


def get(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {})) as r:
        return json.loads(r.read()), dict(r.headers)


def test_http_role_from_website_and_headers(proxy):
    base, audit = proxy
    body, h = get(base + "/api/members?as=sdm")
    assert body[0]["mobile"] == "081234567890"
    assert "X-Palmerah-Role" not in h and "X-Powered-By" not in h and h["X-Content-Type-Options"] == "nosniff"
    line = json.loads(audit.read_text().splitlines()[-1])
    assert line["role"] == "sdm" and line["decrypted"] == 2 and "0812" not in audit.read_text()   # counts, never values


def test_http_client_cannot_choose_its_role(proxy):
    base, _ = proxy
    Stub.seen_role_header.clear()
    body, _ = get(base + "/api/members", headers={"X-Palmerah-Role": "admin"})   # no website session -> public
    assert "mobile" not in body[0] and Stub.seen_role_header == [None]


def test_tls13_only(tmp_path, keys):
    from palmerah_shield.devenv import CERTS, ensure_certs
    ensure_certs()
    px = build("b", upstream="http://127.0.0.1:9", port=0, keys=keys, policy_fn=lambda: Policy(default_matrix(), "b"),
               audit_path=tmp_path / "a.log")
    threading.Thread(target=px.serve_forever, daemon=True).start()
    port = px.server_address[1]
    try:
        ctx = ssl.create_default_context(cafile=str(CERTS / "ca.crt"))
        with urllib.request.urlopen(f"https://localhost:{port}/", context=ctx) as r:
            pytest.fail("upstream is down: expected 502")
    except urllib.error.HTTPError as e:
        assert e.code == 502                                          # TLS 1.3 worked; website unreachable reported
    old = ssl.create_default_context(cafile=str(CERTS / "ca.crt"))
    old.maximum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises((ssl.SSLError, urllib.error.URLError)):
        urllib.request.urlopen(f"https://localhost:{port}/", context=old)
    px.shutdown()
