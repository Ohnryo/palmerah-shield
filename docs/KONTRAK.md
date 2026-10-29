# PALMERAH — KONTRAK BERSAMA (v1)

Salinan kontrak bersama tim, sumber kebenaran untuk port, skema, klasifikasi, dan kripto. Jangan diubah di sini
tanpa kesepakatan tim; asumsi dan pertanyaan terbuka ada di `ASUMSI.md`.

Proyek: Final Hackathon DPR RI 2026 "Keamanan Data dan Informasi".
Tema: "Database Bocor — seberapa jauh data pribadi tetap terlindungi."
Semua data SINTETIS. Semua layanan berjalan HANYA di localhost / jaringan Docker terisolasi. Tidak ada target nyata,
tidak ada deploy publik.

## Alur demo final (15 menit)
1. Jelaskan risiko dari temuan data + arsitektur pertahanan.
2. Tunjukkan 2 web dummy (A legacy, B modern) berisi data dummy.
3. Uji-bobol web yang RENTAN -> tampilkan "leak scoreboard".
4. Jalankan Palmerah Shield: scan -> klasifikasi PII -> apply pertahanan.
5. Uji-bobol ULANG dengan harness yang sama -> bandingkan scoreboard.
   Buktikan: (a) dump tanpa kunci, (b) dump + kunci, (c) pengguna sah tetap jalan.

## Tiga komponen & pemilik
- Website dummy (A & B) + data loader + generator pembesaran data -> Arfa
- Palmerah Shield (aplikator pertahanan) -> Teman 1
- Palmerah RedCheck (harness validasi/uji-bobol) -> Teman 2

## Repo & port (tetap, jangan diubah)
- web-legacy (PHP/MySQL): http://localhost:8080 db: mysql :3306
- web-modern (Node/PG): http://localhost:3000 db: pg :5432
- kms (key service): http://localhost:8200 (internal only)
- reverse proxy (sesudah apply): https://localhost:8443 (web-legacy), https://localhost:8444 (web-modern)
- Mode VULN vs HARDENED dipilih lewat env `MODE=vuln|hardened`.
- Skrip reset ke kondisi rentan: `make reset` (wajib ada, idempotent, < 30 dtk).

## Model data kanonik (seed dari anggota_dummy.sql, 734 baris, 29 kolom)
Entitas: member. Web A = 1 tabel lebar `anggota` (nama kolom Indonesia persis dump).
Web B = ternormalisasi (nama Inggris):
- members(id, full_name, display_name, gender, birth_place, birth_date, job, religion, marital_status, marriage_date, room_code, created_at)
- member_contacts(member_id, address_jakarta, phone_jakarta, address_region, phone_region, mobile, email)
- member_finance(member_id, nik, npwp, account_no, account_name, bank_name, bank_code, kppn_name, kppn_nip)
- member_family(member_id, num_children, num_dependents, num_souls)
- member_health(member_id, blood_type, allergy_note, condition_note)   # sintetis tambahan
- member_activities(id, member_id, title, ref_code, notes, created_at) # free-text + nama kolom menyesatkan
- users(id, username, password_hash, role, member_id)

Mapping dump -> kanonik (734 baris):
- nama/nama_lengkap/nama_tanpa_gelar -> full_name (identik di 734/734)
- nama_rekening = full_name[:20]; email & pengguna = turunan full_name (734/734)
- jumlah_jiwa = jumlah_tanggungan + 1; (K) jumlah_tanggungan = jumlah_anak + 1
- no_ktp 14 char pad-0, npwp 15, rekening 16, nip_kppn 18, kode_bank 3 (acak, bukan kode bank asli)

## Peran (untuk uji otorisasi & "pengguna sah tetap terlayani")
public | humas | keuangan | sdm | medis | admin | anggota(self-only)
Matriks akses kolom dipegang satu file bersama: `access_matrix.json` (lihat Shield).

## Klasifikasi PII acuan (ground truth untuk uji detektor)
- SANGAT TINGGI: nik, npwp, account_no, account_name
- TINGGI (kontak/lokasi): address_*, mobile, phone_*, email
- TINGGI (keluarga/sosial): marital_status, marriage_date, num_*, religion, health.*
- QUASI-ID: birth_date, birth_place, gender, job
- INTERNAL: kppn_nip, kppn_name, bank_name, bank_code, username, room_code
- PUBLIK: full_name, room_code
- JEBAKAN DETEKTOR (nama kolom menyesatkan, isi sensitif):
  - member_activities.ref_code -> berisi NIK
  - member_activities.notes -> berisi nomor HP / alamat di teks bebas

## Kriptografi (disepakati)
- Enkripsi kolom: AES-256-GCM, nonce acak per nilai (JANGAN deterministik).
- Envelope: DEK per-kolom dibungkus KEK di KMS container terpisah.
- Pencarian: blind index = HMAC-SHA256(normalize(value), index_key) utk nik & email saja.
- Tokenisasi: nik & account_no -> token format-preserving di vault; mapping di KMS.
- JANGAN simpan kunci di repo. .env.example berisi placeholder saja.

## Aturan bukti (dinilai juri: "klaim tanpa bukti tidak dihitung")
Setiap kontrol ditandai: [IMPLEMENTED] / [TESTED] / [PLANNED].
Semua tool keluarkan JSON mentah ke ./out/ + ringkasan "scoreboard".

## Kontrak antar-tool (WAJIB stabil)
- Shield membaca dump/live-schema, menulis: out/inventory.json (temuan PII), out/apply_report.json (apa yang diubah),
  dan menyalakan MODE=hardened.
- RedCheck membaca: BASE_URL + MODE, menulis out/redcheck_<mode>.json dgn skema:
  { target, mode, findings:[{id,category,severity,endpoint,leaked_fields,rows_exposed,evidence_snippet,status:pass|fail}], scoreboard:{nik,rekening,alamat,...} }
- "Leak scoreboard" dihitung dari field PII mentah yang berhasil dibaca penyerang.
