# Palmerah Shield

Komponen **Shield** dari proyek Palmerah (Final Hackathon DPR RI 2026, "Database Bocor"): CLI yang mengubah website
dummy yang rentan menjadi terlindungi — `scan` → `plan` → `apply` (+ `rollback`, `benchmark`).

* Sumber kebenaran: [docs/KONTRAK.md](docs/KONTRAK.md). Integrasi website A/B dengan proxy: [docs/INTEGRASI_WEB.md](docs/INTEGRASI_WEB.md). Asumsi dan hal yang perlu disepakati tim: [docs/ASUMSI.md](docs/ASUMSI.md).
* Semua data **sintetis**; semua layanan hanya di `127.0.0.1` (atau jaringan Docker terisolasi). Tidak ada rahasia di repo.

## Status

| Tahap | Isi | Status |
|---|---|---|
| S0 | Kerangka CLI, fixture website A (MySQL :3306) dan B (PostgreSQL :5432) sesuai skema kontrak, `make reset` | [TESTED] 11 uji |
| S1 | `shield scan` (dump `.sql` MySQL/PG atau `--dsn` live) + presisi/recall vs klasifikasi kontrak → `out/inventory.json` | [TESTED] 9 uji |
| U0 | Konsol web `shield console` (https://localhost:8700): login token, CSRF, TLS 1.3, runner + SSE, kunci operasi bersama CLI, Beranda | [TESTED] 17 uji + uji browser |
| U1–U2 | Halaman Scan, Rencana (+ editor `access_matrix.json`), Terapkan (konfirmasi nama target, progres live, rollback) | [TESTED] 18 uji API + uji browser alur penuh dengan runner palsu; belum dengan database nyata |
| U3 | `shield evidence -t a|b` + halaman Bukti: (a) isi dump tanpa kunci, (b) dump + kunci terbungkus (DEK terbungkus, token KMS salah, jalur sah), (c) bacaan per peran lewat login aplikasi → `out/evidence_<t>.json` | [TESTED] live pada website B (PostgreSQL) dengan dump pengganti sintetis: 0 sel plaintext; website A belum diuji live |
| – | Unggah dump `.sql` lewat konsol (lihat docs/PLAN.md) | [PLANNED] |
| S2 | `shield plan` + `access_matrix.json` (7 peran × field) → `out/plan.json`: kontrol per kolom + alasan + batas + daftar *needs human review* | [TESTED] 9 uji |
| S3 | KMS terpisah :8200, `shield apply` / `rollback` / `patch` → `out/apply_report.json`, `MODE=hardened` | [TESTED] 22 uji (A & B live) |
| S4 | `shield proxy -t a|b`: TLS 1.3 :8443/:8444, peran dari header respons web `X-Palmerah-Role` (header klien dibuang), filter JSON per field sesuai `access_matrix.json`, dekripsi/detokenisasi lewat KMS, audit + alarm baca massal | [TESTED] 9 uji + live pada website B (PostgreSQL) dengan web B tiruan; menunggu web A/B asli |
| S5 + U4 | Generator data (`seed.scale_rows`), `shield benchmark -t a|b --rows N` → `out/benchmark_<t>.json`, halaman Kinerja; indeks pada kolom blind index | [TESTED] website B 10 rb + 100 rb anggota (lihat Hasil benchmark); 1 jt belum dijalankan |
| U5 | Kunci & Audit, Patch di konsol, Dockerfile/compose | [PLANNED] |

## Mulai (mesin dev Windows, tanpa Docker)

Prasyarat: Python ≥ 3.11, MariaDB 11.x dan PostgreSQL 16 portable (lokasi diatur di `.env`: `MARIADB_HOME`, `PG_HOME`),
dan dump resmi `anggota_dummy.sql` (`SEED_DUMP`, tidak di-commit).

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m palmerah_shield dev init     # .env berisi rahasia acak, CA uji, direktori data
.venv/Scripts/python -m palmerah_shield reset        # = make reset: fixture A & B dari seed, MODE=vuln (~3 dtk)
.venv/Scripts/python -m pytest -q
```

### Konsol web

```bash
cd web && npm ci && npm run build && cd ..
.venv/Scripts/python -m palmerah_shield console     # cetak URL + token login sekali pakai
```

Buka `https://localhost:8700` (browser perlu mempercayai `.local/certs/ca.crt`). Konsol memanggil inti yang sama dan
menulis `out/` yang sama dengan CLI; selama satu operasi berjalan (dari CLI atau konsol), operasi lain ditolak.

`make` tidak tersedia di Windows tanpa instalasi tambahan; `Makefile` berisi perintah yang sama untuk Linux/Docker.

## Hasil `shield scan` (contoh: `examples/out/`)

| Data | Presisi | Recall | F1 | Akurasi kelas | Catatan |
|---|---|---|---|---|---|
| Website A (dump resmi), nama kolom dipakai / **diabaikan** | 1,00 / 1,00 | 1,00 / 1,00 | 1,00 | 1,00 | aturan disetel pada data ini |
| Website B (+ jebakan), nama kolom dipakai / **diabaikan** | 1,00 / 1,00 | 1,00 / 1,00 | 1,00 | 1,00 | `ref_code` (NIK) dan `notes` (HP/alamat) tertangkap |
| **Holdout beku** (skema asing, belum pernah dilihat) | **1,00** | **0,62** | **0,76** | – | ukuran generalisasi yang jujur: `out/holdout_FROZEN.json` |
| Holdout sesudah 3 aturan umum (BUKAN held-out) | 1,00 | 0,92 | 0,96 | – | sisa 1 beda taksonomi: kontrak menggolongkan tanggal lahir QUASI-ID |

Presisi/recall dihitung untuk keputusan "harus dilindungi" (kelas SANGAT TINGGI + TINGGI kontrak). Mode "nama kolom
diabaikan" membuktikan deteksi berbasis isi. Setiap temuan berisi `why` (sinyal yang dipakai) dan `sample_masked`;
nilai asli tidak pernah ditulis ke `out/`.

## Hasil `shield plan` (contoh: `examples/out/plan_*.json`)

| Kontrol | Website A | Website B | Aturan kontrak |
|---|---|---|---|
| encrypt-AEAD (AES-256-GCM, nonce acak) | 15 kolom | 19 kolom | semua SANGAT TINGGI/TINGGI yang tidak ditokenisasi |
| tokenize | `no_ktp`, `rekening` | `nik`, `account_no`, `ref_code` (jebakan berisi NIK) | hanya nik & account_no |
| blind-index | `no_ktp`, `email` | `nik`, `email` | hanya nik & email |
| mask | `tanggal_lahir` (tahun saja) | `birth_date` | — |
| view-only | 8 | 9 | kuasi-identifier, internal, hash sandi |
| drop (needs human review) | `nama_lengkap`, `nama_tanpa_gelar` (identik dengan `nama`) | `display_name` | minimisasi |

`access_matrix.json` (dibuat bila belum ada, tidak pernah ditimpa): 7 peran × field kanonik; `public` hanya melihat
`full_name` dan `room_code`; `anggota` hanya record miliknya; hash sandi tidak terlihat oleh siapa pun. Setiap kolom
di `plan.json` membawa `reason`, `limitations`, dan `visible_to` per peran; keputusan yang butuh perubahan kode atau
penilaian manusia masuk `needs_human_review` (mis. `nama_rekening` = 20 karakter pertama nama: enkripsi tidak
menambah kerahasiaan, usulan drop).

## Hasil `shield apply` (contoh: `examples/out/apply_report_*.json`)

| Bukti otomatis di setiap apply | Website A (MySQL) | Website B (PostgreSQL) |
|---|---|---|
| Nilai terenkripsi yang didekripsi ulang identik sebelum plaintext dihapus | 10.643 | 15.036 |
| Nilai asli sampel yang ditemukan di dump nyata (`mariadb-dump` / `pg_dump`) | **0 / 300** | **0 / 400** |
| Login aplikasi membaca tabel dasar | ditolak | ditolak |
| Peran `public` melihat NIK | `NULL` | `NULL` |
| Apply ulang dengan rencana yang sama | no-op | no-op |
| Rollback dari backup terenkripsi | data identik dengan sebelum apply | data identik dengan sebelum apply |

### Skenario bocor (a): dump tanpa kunci
Satu baris `member_finance` dari `pg_dump` sesudah apply:

```
INSERT INTO public.member_finance VALUES (702, '91175523842877', '1338218446986106', 'Bank BCA', '120', 'KPPN Yogyakarta',
  '000000000227370327', '7e32890b1caa…f6312', '**********7421', 'pal1:f43e78222fa2:MVYh0WD/…', 'pal1:d9470ed5982b:4NLRM7UO…');
```

* `nik` dan `account_no` berisi **token** berformat sama (14 dan 16 digit) — tanpa vault KMS tidak bermakna.
* `npwp` dan `account_name` berisi **envelope AES-256-GCM** (`pal1:<key_id>:…`); kolom plaintext-nya sudah dihapus.
* `nik_bidx` = HMAC-SHA256 (tidak dapat dibalik), `nik_mask` = 4 digit akhir untuk peran berlevel *masked*.
* Tetap terbaca (sesuai kontrak, bukan kebocoran tak terduga): nama, `room_code`, kolom INTERNAL (`kppn_nip`, bank, KPPN),
  kuasi-identifier (jenis kelamin, tempat lahir, pekerjaan), jumlah baris, dan `account_name` yang merupakan potongan `full_name` publik.

### Skenario bocor (b): dump + kunci
Yang dimaksud "kunci" di sini: isi tabel `shield_keys` (DEK **terbungkus**) ikut bocor bersama dump.
* DEK terbungkus tidak berguna tanpa **KEK**, yang hanya ada di proses KMS terpisah (`.local/kms/kek.bin`; di Docker: container sendiri).
* Token tidak dapat dibalik tanpa **vault** KMS; blind index tidak dapat dibalik sama sekali (HMAC), hanya dapat dicocokkan dengan tebakan bila `index_key` juga bocor.
* Setiap unwrap dan detokenisasi tercatat di audit KMS; detokenisasi > 5.000 nilai/menit oleh satu klien memicu alarm pembacaan massal.
* **Sisa risiko (jujur):** bila penyerang menguasai KMS (KEK + vault) **atau** proses yang berhak memanggil KMS, semua kolom dapat dibuka
  — enkripsi memindahkan rahasia ke kunci, tidak menghapusnya. Mitigasi: pisahkan host/kustodian KMS, batasi klien KMS, rotasi DEK/KEK,
  pantau audit. Nilai turunan (`account_name` = 20 karakter nama) dan kuasi-identifier tetap memungkinkan re-identifikasi sebagian.

### Patch kode (needs human review)
`shield patch -t a --app-src <kode web>` menulis `out/patches/a/`: panduan login least-privilege + `SET ROLE`, dan diff prepared
statement untuk SQL yang dirangkai dari variabel. Diuji pada target PHP `benteng-platform/targets/php-react-demo`: diff dapat
diterapkan, lolos `php -l`, dan hasil query identik — kecuali tipe JSON angka (`"17"` → `17`), dicatat sebagai perubahan perilaku.
Query yang dirangkai dan dijalankan di baris berbeda (`login.php`) serta hash MD5 hanya dilaporkan untuk dikerjakan manusia.

## Fixture

| Website | Database | Isi |
|---|---|---|
| A (legacy) | MySQL/MariaDB `127.0.0.1:3306`, `web_legacy.anggota` | 734 baris, 29 kolom persis dump + `id` |
| B (modern) | PostgreSQL `127.0.0.1:5432`, `web_modern` | 7 tabel kanonik kontrak; `member_health` dan `member_activities` sintetis (seed tetap), termasuk jebakan detektor: `ref_code` berisi NIK, `notes` berisi HP/alamat |

Kedua server menolak koneksi tanpa TLS 1.3 dan menolak klien yang tidak memverifikasi CA uji. Sandi login enam peran
dibuat acak setiap reset (`.local/credentials.json`).
