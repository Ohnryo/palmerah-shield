# Naskah demo Palmerah (15 menit)

Mengikuti "Alur demo final" di `KONTRAK.md`. Perintah ditulis untuk **Windows PowerShell** dari folder repo
(`.venv\Scripts\python -m palmerah_shield ...`, disingkat `shield ...` di bawah). Semua layanan hanya di `127.0.0.1`.

Status bagian yang bergantung pada tim, cek sebelum hari H:

| Bagian | Pemilik | Wajib untuk | Bila belum siap |
|---|---|---|---|
| Web A :8080 dan B :3000 dengan data dummy | Arfa | langkah 2 dan 5c lewat web | lihat Rencana cadangan C1 |
| Web memakai login aplikasi + `SET ROLE` + header `X-Palmerah-Role` sesudah apply (`docs/INTEGRASI_WEB.md`) | Arfa | langkah 5c lewat proxy | C1 |
| RedCheck menulis `out/redcheck_<mode>.json` (usulan: `redcheck_<target>_<mode>.json`) | Teman 2 | scoreboard langkah 3 dan 5 | C2 |

---

## A. Persiapan H-1 (sekali, ±30 menit)

1. Ambil kode terbaru dan pasang dependensi:
   ```powershell
   git pull origin claude/admiring-cerf-vh7ebm
   .venv\Scripts\python -m pip install -e ".[dev]"
   cd web
   npm ci
   npm run build
   cd ..
   ```
2. Pastikan `.env` benar (`SEED_DUMP`, `MARIADB_HOME`, `PG_HOME`), lalu siapkan fixture:
   ```powershell
   .venv\Scripts\python -m palmerah_shield dev init
   .venv\Scripts\python -m palmerah_shield reset
   .venv\Scripts\python -m pytest -q
   ```
   `reset` harus selesai < 30 detik; `pytest` harus lulus semua. Jangan demo bila ada yang gagal: kirim keluarannya.
3. Gladi penuh sekali (bagian C di bawah) untuk A **dan** B, termasuk `apply`, `evidence`, `rollback`.
4. Isi halaman Kinerja (butuh beberapa menit per target, menghapus data target lalu kembali ke seed):
   ```powershell
   .venv\Scripts\python -m palmerah_shield benchmark -t b
   .venv\Scripts\python -m palmerah_shield benchmark -t a
   ```
5. Percayakan CA uji di browser (hapus lagi sesudah acara, lihat bagian E):
   ```powershell
   certutil -user -addstore Root .local\certs\ca.crt
   ```
6. Integrasi dengan Arfa: web A/B sesudah apply membaca `out\MODE_a` / `out\MODE_b`; bila `MODE=hardened`, web login
   dengan `.local\app-credentials-<a|b>.json` (sandi baru setiap apply) dan mengirim `X-Palmerah-Role`. Uji sekali
   lewat proxy (langkah C5).

## B. Persiapan T-30 menit (setiap kali demo)

1. Kondisi awal rentan:
   ```powershell
   .venv\Scripts\python -m palmerah_shield reset
   ```
2. Buka terminal terpisah (biarkan berjalan):

   | Terminal | Perintah | Untuk |
   |---|---|---|
   | T1 | `.venv\Scripts\python -m palmerah_shield console` | konsol https://localhost:8700 (catat token) |
   | T2 | `.venv\Scripts\python -m palmerah_shield proxy -t a` | https://localhost:8443 → web A |
   | T3 | `.venv\Scripts\python -m palmerah_shield proxy -t b` | https://localhost:8444 → web B |
   | T4 | (Arfa) web A :8080 dan web B :3000 | data dummy |
   | T5 | (Teman 2) RedCheck | uji-bobol |
   | T6 | cadangan CLI | bila konsol bermasalah |

3. Browser: tab konsol (login token dari T1, nyalakan **Mode Presentasi**), tab web A, tab web B.
4. Cek di **Beranda**: kedua kartu `MODE=VULN`, layanan MySQL/PostgreSQL/KMS/Web A/Web B/Proxy aktif.
5. Opsional untuk menghemat waktu: jalankan Scan + Rencana untuk A dan B sekarang (bisa diulang langsung saat demo).

## C. Demo (15 menit)

| Waktu | Langkah kontrak | Yang ditunjukkan | Aksi |
|---|---|---|---|
| 0:00–2:00 | 1. Risiko + arsitektur | Beranda: kedua web `MODE=VULN`, data at rest **plaintext** | Jelaskan: dump bocor = semua NIK, rekening, alamat terbaca. Arsitektur: Shield (scan → plan → apply), KMS terpisah :8200, proxy :8443/:8444, RedCheck sebagai penguji |
| 2:00–3:30 | 2. Dua web dummy | Tab web A (PHP/MySQL) dan web B (Node/PG) | Tunjukkan data dummy, sebut 734 baris sintetis |
| 3:30–5:30 | 3. Uji-bobol web rentan | RedCheck (T5) pada `http://localhost:8080` dan `:3000`, `MODE=vuln` | Beranda → **Leak scoreboard** kolom VULN merah (nik, rekening, alamat ...) |
| 5:30–7:00 | 4a. Scan | Halaman **Scan**, target B | Klik *Scan ulang*; sorot **Jebakan detektor**: `ref_code` berisi NIK, `notes` berisi HP/alamat, tertangkap **tanpa nama kolom**; presisi/recall vs acuan kontrak |
| 7:00–8:00 | 4b. Rencana | Halaman **Rencana** | Ringkasan kontrol (AES-256-GCM, tokenisasi NIK/rekening, blind index NIK/email, mask); buka 1 baris untuk alasan + batas; tunjukkan matriks akses 7 peran |
| 8:00–10:00 | 4c. Terapkan | Halaman **Terapkan**, B lalu A | Ketik `web-modern`, klik Terapkan: progres live (backup terenkripsi → migrasi → VIEW/role → verifikasi). Laporan: **0 / 400** nilai asli di dump, login aplikasi ditolak di tabel dasar, `public` → NIK `NULL`. Ulangi untuk A (`web-legacy`) |
| 10:00–12:00 | 5. Uji-bobol ulang | RedCheck yang sama, `MODE=hardened`, `BASE_URL` proxy `https://localhost:8443` / `:8444` | Beranda/Bukti → scoreboard **VULN vs HARDENED** berdampingan |
| 12:00–13:30 | 5a + 5b | Halaman **Bukti** → *Jalankan pembuktian* (B, lalu A) | (a) isi dump: token/envelope, bukan nilai asli. (b) dump + kunci: DEK terbungkus → `InvalidTag`, token KMS salah → 401, hanya jalur sah lewat KMS yang berhasil (tercatat audit). Sebut sisa risiko dengan jujur |
| 13:30–14:30 | 5c. Pengguna sah tetap jalan | Bukti (c) + web lewat proxy | Tabel peran: `public` tidak dapat apa pun, `keuangan` dapat rekening/NPWP, `sdm` kontak, `anggota` hanya dirinya. Login web sebagai sdm via `https://localhost:8444` → kontak terbaca normal |
| 14:30–15:00 | Penutup | **Kinerja** (lookup p95 < 1 ms, biaya penyimpanan ±3,7×) dan **Kunci & Audit** | Satu kalimat: "klaim tanpa bukti tidak dihitung, semua angka ini dari `out/*.json` yang diukur saat ini" |

Kalimat kunci untuk juri:
* Enkripsi memindahkan rahasia ke kunci; kunci ada di proses KMS terpisah, bukan di database.
* Token berformat sama (aplikasi tidak rusak), tetapi tanpa vault tidak bermakna.
* Label `[TESTED]` = diukur otomatis saat apply/evidence; `[IMPLEMENTED]` = ada tetapi belum diukur; `[PLANNED]` = belum.

## D. Rencana cadangan

| Kode | Masalah | Lakukan |
|---|---|---|
| C1 | Web A/B belum ada / belum terintegrasi | Lewati tab web; langkah 5c pakai **Bukti (c)** (bukti level database lewat login aplikasi + `SET ROLE`, berlabel `[TESTED] level database`); katakan jalur proxy siap dan diuji dengan web tiruan |
| C2 | RedCheck belum ada | Beranda menulis "Belum ada data RedCheck" (tidak ada angka karangan). Ganti dengan Bukti (a): `0 / 400` nilai asli di dump nyata + `0` sel plaintext |
| C3 | Konsol bermasalah | CLI di T6: `shield scan -t b`, `shield plan -t b`, `shield apply -t b`, `shield evidence -t b`; tunjukkan `out\apply_report_b.json` dan `out\evidence_b.json` |
| C4 | Apply gagal di tengah | Shield memulihkan database dari backup terenkripsi otomatis; jalankan `shield reset` (< 30 detik) dan ulangi |
| C5 | Proxy menolak/502 | Web tidak terjangkau dari proxy: cek T4 aktif di :8080/:3000; sementara tunjukkan Bukti (c) |
| C6 | Browser memperingatkan sertifikat | CA belum dipercaya: `certutil` di A5, atau lanjutkan melewati peringatan (hanya localhost) |
| C7 | Tombol tidak aktif, ada pesan "Operasi ... sedang berjalan" | Satu operasi per waktu (CLI dan konsol berbagi kunci); tunggu atau hentikan perintah CLI di terminal lain |

## E. Sesudah demo

```powershell
.venv\Scripts\python -m palmerah_shield reset
.venv\Scripts\python -m palmerah_shield dev stop
certutil -user -delstore Root "Palmerah Test CA"
```
Tutup T1–T3 dengan Ctrl+C. Simpan `out\*.json` bila juri meminta bukti mentah (tidak berisi nilai PII mentah).

## F. Pertanyaan yang mungkin muncul

| Pertanyaan | Jawaban singkat | Bukti |
|---|---|---|
| Bagaimana kalau kunci ikut bocor? | Yang di database hanya DEK **terbungkus**; KEK di proses KMS terpisah. Dicoba langsung: `InvalidTag`, token salah 401 | Bukti (b) |
| Kalau KMS-nya yang dibobol? | Semua bisa dibuka: itu sisa risiko. Mitigasi: host/kustodian terpisah, batasi klien, rotasi, audit + alarm baca massal | Bukti (b) sisa risiko, Kunci & Audit |
| Apakah pencarian NIK masih bisa? | Ya, lewat blind index HMAC berindeks, tanpa mendekripsi | Kinerja (search) |
| Seberapa lambat? | Lookup p95 tetap < 1 ms; biaya utama penyimpanan ±3,7× | Kinerja, `out\benchmark_<t>.json` |
| Bagaimana pengguna sah membaca data terenkripsi? | Proxy mendekripsi hanya field yang diizinkan matriks untuk perannya, tercatat di audit | Bukti (c), Kunci & Audit |
| Kenapa ada kolom "needs human review"? | Keputusan yang butuh perubahan kode atau penilaian manusia tidak dijalankan otomatis (mis. drop kolom duplikat) | Rencana, Patch |
| Data asli? | Tidak ada: semua sintetis, semua layanan di localhost | `KONTRAK.md` |
