# Patch website B (Node/PostgreSQL) — NEEDS HUMAN REVIEW

Shield sudah mengubah database. Bagian di bawah butuh perubahan kode aplikasi; tinjau dan terapkan oleh pemilik web.

## 1. Berhenti memakai root/superuser
Login database: `palmerah_b_app` (sandi di `.local/app-credentials-b.json`, jangan di-commit).
Login ini tidak bisa membaca tabel dasar; setiap request memilih peran pengguna yang sudah diautentikasi:

```js
const client = await pool.connect();   // user: 'palmerah_b_app', ssl: { ca, rejectUnauthorized: true }
await client.query(`SET ROLE ${pgFormat.ident('palmerah_b_r_' + role)}`);   // role dari sesi server
if (role === 'anggota') await client.query("SELECT set_config('palmerah.member_id', $1, false)", [String(memberId)]);
const { rows } = await client.query(`SELECT * FROM shield.v_${role}_members WHERE id = $1`, [id]);
await client.query('RESET ROLE'); client.release();
```

## 2. Kolom terenkripsi kini hanya-baca lewat VIEW
Fitur yang MENULIS kolom terenkripsi/ditokenisasi (mis. ubah alamat, email) harus memanggil layanan Shield yang mengenkripsi dengan DEK kolom itu (rencana S4); jangan menulis plaintext ke tabel dasar.

## 3. Nilai `pal1:...` di respons
Untuk peran berlevel full, VIEW mengembalikan envelope `pal1:...`; reverse proxy Shield (S4) mendekripsi field yang diizinkan matriks untuk peran itu. Jangan mendekripsi di browser.
