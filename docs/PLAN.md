# Rencana Palmerah Shield v2 (CLI + aplikasi web)

Disetujui 29 Oktober 2026. Sumber kebenaran tetap `KONTRAK.md`; spesifikasi tugas Shield (Teman 1) tidak berubah.
Perbedaan dari v1 hanya bentuk: selain CLI, ada konsol web di atas **inti yang sama**.

## Prinsip
* **Satu inti, dua pintu.** CLI `shield` (Typer, kontrak) dan API web memanggil fungsi inti yang sama dan menulis berkas
  `out/*.json` yang sama, dengan format kontrak yang tidak berubah. RedCheck (Teman 2) tidak terpengaruh.
* Bukti lebih penting dari tampilan: inti dikerjakan dulu, UI di atasnya.
* Setiap kontrol berlabel `[IMPLEMENTED]` / `[TESTED]` / `[PLANNED]`; yang belum selesai ditulis `[PLANNED]`, tidak diklaim.

## Arsitektur
```
Operator -> React UI -> API FastAPI -> INTI shield (Python) <- CLI `shield` (Typer)
                                          | menulis out/*.json (format kontrak)
   KMS :8200 (terpisah) | MySQL :3306 (web A) | PG :5432 (web B) | Proxy :8443/:8444 (TLS, header, filter) | RedCheck
```
Konsol web: `https://localhost:8700` (tidak bentrok dengan port kontrak).

## Stack
| Lapisan | Pilihan |
|---|---|
| Inti + CLI | Python 3.11 (diuji 3.14 di mesin dev), Typer |
| API | FastAPI + uvicorn (HTTPS, CA uji), Server-Sent Events untuk progres |
| UI | React 19 + Vite + TypeScript, Tailwind CSS v4, Recharts, React Router, TanStack Query, lucide |
| Proxy | Caddy (TLS + header) + filter respons per peran (Python) |
| Kunci | KMS mini terpisah :8200, kunci di luar repo |

## Halaman UI
1. Beranda — status MODE web A/B, langkah berikutnya, leak scoreboard dari `out/redcheck_<mode>.json`.
2. Scan — target A/B/unggah dump; temuan PII, presisi/recall, confusion matrix, sorotan jebakan.
3. Rencana — kontrol per kolom + alasan/batas; editor `access_matrix.json` (7 peran × kolom).
4. Terapkan — pratinjau, konfirmasi nama target, progres live, laporan berlabel, Rollback.
5. Bukti — (a) dump tanpa kunci, (b) dump + kunci, (c) pengguna sah; scoreboard sebelum vs sesudah.
6. Kinerja — hasil `shield benchmark`.
7. Kunci & Audit — status KMS (tanpa materi kunci), log akses/dekripsi PII, alarm baca massal.
8. Patch — diff *needs human review*.

## Keamanan konsol
`127.0.0.1` saja, HTTPS TLS 1.3; token acak saat start → cookie `HttpOnly; Secure; SameSite=Strict` + header anti-CSRF;
CSP `'self'`; data dirender sebagai teks; PII hanya tersamar; apply/rollback wajib konfirmasi nama target dan tercatat.

## Fase
| Fase | Isi | Estimasi | Prioritas |
|---|---|---|---|
| S0 | Fixture A/B + reset | — | selesai |
| S1 | Inti `scan` + CLI + presisi/recall → `out/inventory.json` | 3–4 j | WAJIB |
| U0 | Kerangka web: API + auth + shell React + design system + Beranda | 3–4 j | WAJIB |
| S2 + U1 | `plan` + `access_matrix.json` + halaman Scan, Rencana | 3–4 j | WAJIB |
| S3 + U2 | KMS :8200, `apply`/`rollback` (AEAD, tokenisasi, blind index, role + view), **pembuatan patch** + halaman Terapkan | 5–6 j | WAJIB |
| S4 | Proxy :8443/:8444 + filter respons + audit | 3–4 j | WAJIB |
| U3 | Halaman Bukti | 2–3 j | WAJIB |
| S5 | `benchmark` + generator 100 rb/1 jt + grafik, Dockerfile/compose, README dua skenario bocor | 4–5 j | WAJIB |
| U4 | Halaman Kinerja, Kunci & Audit, Patch | 2–3 j | dapat dipotong (fitur intinya tetap ada di CLI) |

## Risiko
* Waktu sempit sampai presentasi 31 Oktober.
* Web A/B (Arfa) belum ada: skenario "pengguna sah" dan filter respons bergantung pada web mereka dan ASUMSI A5.
* Scoreboard sebelum/sesudah bergantung pada keluaran RedCheck; tanpa itu UI menampilkan "belum ada data", bukan angka karangan.
