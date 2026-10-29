"""Generator for the benchmark: size, unique identifiers with the contract's widths, contract rules kept."""
from palmerah_shield.seed import scale_rows

COLS = ["nama", "no_ktp", "npwp", "rekening", "handphone", "email", "pengguna", "jumlah_anak", "jumlah_tanggungan", "jumlah_jiwa"]
BASE = [["Budi", "00000000000001", "000000000000001", "0000000000000001", "081", "budi@example.com", "budi", 2, 3, 4],
        ["Siti", "00000000000002", "000000000000002", "0000000000000002", "082", "siti@example.com", "siti", 0, 1, 2]]


def test_scale_rows():
    rows = scale_rows(COLS, BASE, 5000)
    assert len(rows) == 5000
    for i, w in ((1, 14), (2, 15), (3, 16)):
        vals = [r[i] for r in rows]
        assert len(set(vals)) == 5000 and all(len(v) == w and v.isdigit() for v in vals)
    assert len({r[5] for r in rows}) == 5000 and len({r[6] for r in rows}) == 5000
    assert all(r[9] == r[8] + 1 for r in rows)                    # jumlah_jiwa = jumlah_tanggungan + 1 kept
    assert not {r[1] for r in rows} & {b[1] for b in BASE}        # seed identifiers are not reused
    assert scale_rows(COLS, BASE, 50) == scale_rows(COLS, BASE, 50)   # deterministic
