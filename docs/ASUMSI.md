# Asumsi dan pertanyaan terbuka terhadap Kontrak Bersama v1

Kontrak (`docs/KONTRAK.md`) adalah sumber kebenaran. Hal di bawah tidak diatur kontrak atau perlu disepakati;
Shield memakai asumsi berikut sampai tim memutuskan lain. Status: **[USULAN]** = perlu persetujuan tim.

| # | Topik | Asumsi Shield | Perlu disepakati dengan |
|---|---|---|---|
| A1 | Nama database | MySQL `web_legacy` (website A), PostgreSQL `web_modern` (website B) | Arfa |
| A2 | Primary key website A | Dump tidak punya PK; fixture menambah `id INT AUTO_INCREMENT`. Enkripsi kolom mengikat ciphertext ke baris (AAD), jadi tabel tanpa PK tidak dapat dimigrasi dengan aman | Arfa |
| A3 | Akun login website A | Kontrak hanya menyebut satu tabel `anggota`; fixture A belum punya tabel pengguna. Uji peran di A menunggu desain web A | Arfa |
| A4 | Lokasi `MODE` | `shield apply` menulis `MODE=hardened` ke `out/MODE` (atur lewat `MODE_FILE`); web membaca berkas itu atau variabel lingkungan dari sana | Arfa, Teman 2 |
| A5 | Filter respons per peran **[USULAN]** | Web mengirim header respons `X-Palmerah-Role: <peran>` (dari sesi yang sudah diautentikasi). Proxy Shield memakai header itu untuk memilih whitelist field di `access_matrix.json`, lalu **menghapus** header sebelum respons sampai ke browser. Peran tidak pernah diambil dari permintaan klien | Arfa |
| A6 | `room_code` | Kontrak menaruhnya di INTERNAL sekaligus PUBLIK. Shield memperlakukannya sebagai PUBLIK (boleh tampil di direktori), dan mencatat ketidakkonsistenan ini di inventaris | Tim |
| A7 | Data sintetis tambahan | `member_health` dan `member_activities` dibuat fixture Shield dengan seed tetap (`seed.py`). Bila loader Arfa membuat versinya sendiri, ground truth tetap mengikuti kelas di kontrak, bukan isi tertentu | Arfa |
| A8 | Generator pembesaran data | Kontrak menaruhnya di Arfa; spesifikasi Shield juga meminta generator untuk `shield benchmark`. Shield memakai generator sendiri untuk benchmark dan siap memakai milik Arfa bila tersedia | Arfa |
| A9 | Python | Kode kompatibel 3.11 (Dockerfile `python:3.11-slim` direncanakan di S5, belum ada); di mesin dev diuji dengan 3.14 karena 3.11 tidak terpasang | — |
| A10 | Docker | Mesin dev tanpa Docker: fixture memakai MariaDB 11.8 dan PostgreSQL 16 portable pada port kontrak. `compose.yaml` untuk mesin dengan Docker **[PLANNED]** (S5, belum ada di repo) | — |
| A11 | Hash sandi fixture B | `pbkdf2_sha256` (200.000 iterasi). Mode rentan web B yang asli boleh berbeda; Shield menilai hash yang ditemukan, bukan mengasumsikan | Arfa |
| A12 | Kolom di luar daftar kontrak | `id`, `member_id`, `created_at`, `users.role`, `member_activities.title` → NON_PII; `users.password_hash` → KREDENSIAL (bukan PII, tetapi rahasia). Dipakai sebagai acuan `shield scan` (`reference.py`) | Tim |
| A13 | Evaluasi generalisasi | Skema holdout dari repo hackathon (pegawai, rekam medis, kegiatan, kontak darurat) dipakai sebagai data yang belum pernah dilihat detektor. Ground truth-nya bertier (≥2 = harus dilindungi), bukan kelas kontrak; tanggal lahir bertier 2 di sana tetapi QUASI-ID di kontrak | — |
| A14 | Dekripsi untuk pengguna sah **[USULAN]** | Kunci tidak boleh ada di database, jadi VIEW tidak mendekripsi: kolom berlevel full tampil sebagai envelope `pal1:…` (atau token). Proxy Shield (S4) memegang akses KMS dan mendekripsi/detokenisasi hanya field yang diizinkan `access_matrix.json` untuk peran pemanggil, lalu mencatatnya di audit. Web tidak perlu kode kripto | Arfa, Teman 2 |
| A15 | Akses database web sesudah apply | Web memakai login `palmerah_<a/b>_app` (bukan root/postgres) dan menjalankan `SET ROLE palmerah_<a/b>_r_<peran>` per request; peran `anggota` juga mengisi `palmerah.member_id` (PG) atau `@palmerah_member_id` (MySQL). Data dibaca dari `shield.v_<peran>_<tabel>` (B) atau `web_legacy.v_<peran>_anggota` (A). Panduan di `out/patches/<t>/` | Arfa |
| A16 | Penulisan kolom terenkripsi | Sesudah apply, kolom terenkripsi/ditokenisasi hanya-baca lewat VIEW. Fitur web yang mengubah data sensitif perlu jalur tulis lewat Shield (rencana S4) | Arfa |
| A17 | Bukti (c) | `shield evidence` membaca lewat login `palmerah_<t>_app` + `SET ROLE` per peran: bukti level database. Kolom berlevel full tampil sebagai envelope/token (A14); jalur web/proxy menunggu S4 | Arfa |
