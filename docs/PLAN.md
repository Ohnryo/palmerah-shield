# Rencana Palmerah Shield v2 (CLI + aplikasi web)

Revisi 29 Oktober 2026 (malam). Sumber kebenaran tetap `KONTRAK.md`; spesifikasi tugas Shield (Teman 1) tidak berubah.
Selain CLI, ada konsol web di atas **inti yang sama**.

## 1. Arsitektur
```
                 ┌──────────── Palmerah Shield Console (web, https://localhost:8700) ────────────┐
Operator ──────► │ React UI  ──►  API FastAPI  ──►  INTI shield (Python)  ◄──  CLI `shield` (Typer) │
                 └───────────────────────────────────┬───────────────────────────────────────────┘
                                                     │  menulis out/*.json (format kontrak, tidak berubah)
          ┌──────────────┬───────────────────────────┼──────────────────────┬─────────────────────┐
     KMS :8200      MySQL :3306 (web A)       PG :5432 (web B)      Proxy :8443/:8444      RedCheck (Teman 2)
   (proses terpisah)                                               (TLS + header + filter)  membaca BASE_URL+MODE
```
* **Satu inti, dua pintu.** CLI dan web memanggil fungsi yang sama dan menulis berkas `out/` yang sama.
* **Satu operasi per waktu, lintas pintu.** Inti memegang kunci OS (`ops.exclusive`, `.local/state/op.lock`) untuk
  scan/plan/apply/rollback/reset; CLI dan konsol tidak pernah berjalan bersamaan. Inti mengirim event progres
  (`ops.step`) yang dialirkan konsol lewat SSE.
* **Port konsol 8700**, tidak bentrok dengan port kontrak (8080, 3000, 8200, 8443, 8444, 3306, 5432).

## 2. Stack
| Lapisan | Pilihan | Alasan |
|---|---|---|
| Inti + CLI | Python 3.11, Typer (sudah ada) | Sesuai spesifikasi |
| API | FastAPI + uvicorn (HTTPS TLS 1.3 dengan CA uji), Server-Sent Events untuk progres | Bahasa yang sama dengan inti |
| UI | React 19 + Vite + TypeScript, Tailwind CSS v4, Recharts, React Router, TanStack Query, lucide | Build lokal tanpa CDN; disajikan oleh API dari origin yang sama, jadi CSP `'self'` dan cookie `SameSite=Strict` berlaku |
| Pekerjaan panjang | Runner di proses API + kunci OS di inti + SSE | Satu operator, sederhana |
| Proxy | Caddy (TLS, header) + filter respons per peran (Python) | Sesuai spesifikasi |

## 3. Halaman UI (urut alur demo)
| # | Halaman | Isi | Momen demo |
|---|---|---|---|
| 1 | Beranda | Kartu web A/B: `MODE`, langkah scan → rencana → terapkan, ringkasan angka, langkah berikutnya; leak scoreboard dari `out/redcheck_*.json`; status layanan | 2–3 |
| 2 | Scan | Target A/B/unggah dump `.sql`; temuan PII (kelas, confidence, alasan, sampel tersamar); presisi/recall + confusion matrix; sorotan jebakan | 4 |
| 3 | Rencana | Kontrol per kolom + alasan dan batas; editor `access_matrix.json` (7 peran × field) | 4 |
| 4 | Terapkan | Pratinjau → ketik nama target → progres live → laporan berlabel → Rollback | 4 |
| 5 | Bukti | (a) dump tanpa kunci, (b) dump + kunci, (c) pengguna sah; scoreboard sebelum vs sesudah | 5 |
| 6 | Kinerja | p50/p95, throughput, error, CPU/RAM, ukuran, backup/restore (100 rb / 1 jt baris) | Tanya jawab |
| 7 | Kunci & Audit | Status KMS (tanpa materi kunci), log akses/dekripsi PII, alarm pembacaan massal | Tanya jawab |
| 8 | Patch | Diff *needs human review* | Tanya jawab |

Desain: tema gelap/terang, kartu besar untuk proyektor, warna status tetap (merah = bocor, hijau = terlindungi,
kuning = perlu tindakan, biru-abu = [PLANNED]), mode Presentasi (huruf 125%).

## 4. Keamanan konsol
* `127.0.0.1` saja, HTTPS TLS 1.3 (TLS 1.2 ditolak), CA uji; Host selain `localhost`/`127.0.0.1` ditolak (DNS rebinding).
* Token acak dicetak saat start → cookie sesi `HttpOnly; Secure; SameSite=Strict` (12 jam) + header `X-CSRF-Token`
  untuk setiap perubahan; login ditutup 60 detik sesudah 10 kali gagal.
* CSP `'self'` tanpa `unsafe-inline`; data dirender sebagai teks; API hanya membaca berkas `out/` yang sudah
  tersamar (daftar putih), tidak pernah PII mentah.
* apply/rollback/reset wajib mengetik nama target (`web-legacy`/`web-modern`/`reset`); setiap aksi tercatat di
  `.local/console/audit.log`.

## 5. Fase dan status
Presentasi 31 Oktober. Urutan: inti dulu, lalu UI, dengan garis potong yang jelas.

| Fase | Isi | Estimasi sisa | Prioritas | Status |
|---|---|---|---|---|
| S0 | Fixture A/B + reset | — | WAJIB | selesai [TESTED] |
| S1 | `scan` + presisi/recall → `inventory.json` | — | WAJIB | selesai [TESTED] |
| S2 | `plan` + `access_matrix.json` | — | WAJIB | selesai [TESTED] |
| S3 | KMS :8200, `apply`/`rollback`/`patch` | — | WAJIB | selesai [TESTED] |
| U0 | API FastAPI + auth + runner/SSE + kunci operasi di inti + shell React + design system + Beranda | — | WAJIB | selesai [TESTED] |
| U1 | Halaman Scan dan Rencana (+ editor matriks; unggah dump `.sql` belum) | — | WAJIB | selesai [TESTED] (kecuali unggah dump: [PLANNED]) |
| U2 | Halaman Terapkan (pratinjau, konfirmasi nama target, progres SSE, laporan berlabel, rollback) | — | WAJIB | selesai [TESTED] |
| U3 | `shield evidence` + halaman Bukti (a)(b)(c) level DB; scoreboard sebelum/sesudah dari RedCheck | — | WAJIB untuk demo | selesai [TESTED] pada website B; (c) lewat web/proxy [PLANNED] (S4) |
| S4 | Proxy :8443/:8444 + filter respons + dekripsi terkendali + audit | 3–4 j | WAJIB untuk demo | [PLANNED] |
| S5 + U4 | Generator 100 rb/1 jt + `benchmark` + halaman Kinerja | 3–4 j | penting | [PLANNED] |
| U5 | Kunci & Audit (perlu endpoint baca-saja KMS), Patch, Dockerfile/compose, README akhir | 2–3 j | **garis potong** | [PLANNED] |

Sisa ±8–11 jam. Fase setelah garis potong yang tidak sempat dikerjakan tetap ditandai [PLANNED], tidak diklaim.

## 6. Catatan teknis untuk fase berikutnya
* **Kunci & Audit (U5):** konsol tidak membaca `.local/kms/` langsung (KMS proses terpisah); tambahkan
  `GET /v1/status` dan `GET /v1/audit` baca-saja di KMS, tanpa materi kunci.
* **Editor `access_matrix.json` (U1, selesai):** hanya mengubah level field yang sudah ada (divalidasi: `public` hanya
  full/none), ditolak saat operasi berjalan, dicatat di audit konsol; berlaku sesudah `plan` + `apply` ulang.
* **Unggah dump (U1, belum dikerjakan):** batas ukuran, berkas sementara di luar `out/`, nilai asli tidak pernah dikirim ke UI.
* **Bukti (a) (U3):** baris "sebelum" ditampilkan tersamar (`apply.mask_value`).
* **Bukti (c) (U3):** hasil per peran di level DB sudah dibuktikan `apply` (public → NIK `NULL`, sdm → tersamar,
  login aplikasi ditolak di tabel dasar); jalur web/proxy menyusul S4.
* **Nama berkas RedCheck:** kontrak menetapkan `out/redcheck_<mode>.json` tanpa target, sehingga hasil A dan B saling
  menimpa. Usulan ke Teman 2: `redcheck_<target>_<mode>.json` (konsol sudah membaca keduanya; `target` diambil dari isi).
* **Kinerja (S5):** yang dapat diukur tanpa web/proxy: query lewat VIEW, waktu `apply`, ukuran data, backup/restore.

## 7. Paket
* Python: `fastapi`, `uvicorn` (dependensi utama), `httpx` (uji).
* npm (versi dipatok di `web/package.json`): `react`, `react-dom`, `react-router`, `@tanstack/react-query`,
  `lucide-react`, `vite`, `@vitejs/plugin-react`, `typescript`, `tailwindcss`, `@tailwindcss/vite`; `recharts` saat
  halaman Kinerja dibuat.
* Caddy: sudah diizinkan.

## 8. Risiko
* **Waktu sangat sempit.** Web hanya bernilai bila inti benar-benar jalan; juri menilai bukti, bukan tampilan.
* **Web A/B milik Arfa belum ada.** Bukti (c) lewat web dan filter respons bergantung pada web mereka dan header
  `X-Palmerah-Role` (ASUMSI A5).
* **Scoreboard sebelum/sesudah** bergantung pada RedCheck (Teman 2). Tanpa berkasnya, konsol menampilkan
  "Belum ada data RedCheck", tanpa angka karangan.
