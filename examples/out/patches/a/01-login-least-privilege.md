# Patch website A (PHP/MySQL) — NEEDS HUMAN REVIEW

Shield sudah mengubah database. Bagian di bawah butuh perubahan kode aplikasi; tinjau dan terapkan oleh pemilik web.

## 1. Berhenti memakai root/superuser
Login database: `palmerah_a_app` (sandi di `.local/app-credentials-a.json`, jangan di-commit).
Login ini tidak bisa membaca tabel dasar; setiap request memilih peran pengguna yang sudah diautentikasi:

```php
$db = mysqli_init();
mysqli_ssl_set($db, null, null, $CA_FILE, null, null);
mysqli_real_connect($db, '127.0.0.1', 'palmerah_a_app', getenv('DB_PASS'), null, 3306, null, MYSQLI_CLIENT_SSL);
mysqli_query($db, 'SET ROLE palmerah_a_r_' . $role);          // $role dari sesi server, bukan dari request
if ($role === 'anggota') { $st = mysqli_prepare($db, 'SET @palmerah_member_id = ?'); mysqli_stmt_bind_param($st, 'i', $memberId); mysqli_stmt_execute($st); }
$res = mysqli_query($db, "SELECT * FROM web_legacy.v_{$role}_anggota");
```

## 2. Kolom terenkripsi kini hanya-baca lewat VIEW
Fitur yang MENULIS kolom terenkripsi/ditokenisasi (mis. ubah alamat, email) harus memanggil layanan Shield yang mengenkripsi dengan DEK kolom itu (rencana S4); jangan menulis plaintext ke tabel dasar.

## 3. Nilai `pal1:...` di respons
Untuk peran berlevel full, VIEW mengembalikan envelope `pal1:...`; reverse proxy Shield (S4) mendekripsi field yang diizinkan matriks untuk peran itu. Jangan mendekripsi di browser.
