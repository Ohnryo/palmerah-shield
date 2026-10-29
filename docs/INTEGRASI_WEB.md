# Integrasi website A/B dengan Palmerah Shield (untuk Arfa)

Berlaku setelah `shield apply` (MODE=hardened). Usulan ini masih menunggu persetujuan tim (ASUMSI A5, A14, A15).
Proxy dan VIEW sudah diuji dengan web tiruan; web asli cukup memenuhi empat hal di bawah.

## 1. Pakai login aplikasi, bukan root/postgres
Kredensial dibuat oleh `apply` di `.local/app-credentials-<a|b>.json` (`palmerah_a_app` / `palmerah_b_app`).
Login ini tidak punya akses ke tabel dasar; ia hanya bisa `SET ROLE` ke salah satu dari 7 peran.

## 2. Per permintaan: `SET ROLE` sesuai sesi pengguna, lalu baca VIEW
| | Website A (MySQL) | Website B (PostgreSQL) |
|---|---|---|
| Peran | `SET ROLE palmerah_a_r_<peran>` | `SET ROLE palmerah_b_r_<peran>` |
| Peran `anggota` | `SET @palmerah_member_id = <id>` | `SELECT set_config('palmerah.member_id', '<id>', false)` |
| Data | `web_legacy.v_<peran>_anggota` | `shield.v_<peran>_<tabel>` |

Peran: `public`, `humas`, `keuangan`, `sdm`, `medis`, `admin`, `anggota`. Kolom yang tidak boleh dilihat peran itu
bernilai `NULL`; kolom berlevel penuh berisi envelope `pal1:…` atau token (VIEW tidak mendekripsi: kunci tidak ada di
database).

## 3. Kirim data sebagai JSON dengan nama kolom asli, dan umumkan peran di header respons
```
Content-Type: application/json
X-Palmerah-Role: sdm          # dari sesi yang sudah diautentikasi; tanpa header = public
X-Palmerah-Member: 17         # hanya untuk peran anggota
```
Proxy (`shield proxy -t a|b`, https://localhost:8443 / :8444) menghapus kedua header itu sebelum respons sampai ke
browser, membuang header yang sama bila dikirim klien, menghapus field yang tidak boleh dilihat, menyamarkan field
berlevel *masked*, serta mendekripsi/detokenisasi field berlevel *full* lewat KMS. Web tidak perlu kode kripto.
Respons HTML diteruskan apa adanya (filter per field butuh JSON).

## 4. Fitur yang menulis kolom terenkripsi
Sesudah apply, kolom terenkripsi/ditokenisasi hanya-baca lewat VIEW. Fitur yang mengubahnya perlu jalur tulis lewat
Shield (belum ada; ASUMSI A16).

## Contoh minimal
PHP (PDO, website A):
```php
$db = new PDO('mysql:host=127.0.0.1;port=3306;charset=utf8mb4', 'palmerah_a_app', $pw,
              [PDO::MYSQL_ATTR_SSL_CA => $ca, PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => true]);
$role = $_SESSION['role'] ?? 'public';                          // dari login web, bukan dari input pengguna
$db->exec("SET ROLE palmerah_a_r_" . preg_replace('/[^a-z]/', '', $role));
if ($role === 'anggota') { $db->prepare('SET @palmerah_member_id = ?')->execute([$_SESSION['member_id']]); }
$rows = $db->query("SELECT * FROM web_legacy.v_{$role}_anggota")->fetchAll(PDO::FETCH_ASSOC);
header('Content-Type: application/json');
header('X-Palmerah-Role: ' . $role);
echo json_encode($rows);
```
Node (pg, website B):
```js
const c = await pool.connect();                                  // user palmerah_b_app, ssl: { ca }
try {
  await c.query(`SET ROLE palmerah_b_r_${role}`);                // role dari sesi; whitelist 7 nilai
  if (role === "anggota") await c.query("SELECT set_config('palmerah.member_id', $1, false)", [String(memberId)]);
  const { rows } = await c.query(`SELECT * FROM shield.v_${role}_member_contacts`);
  res.set("X-Palmerah-Role", role).json(rows);
} finally { await c.query("RESET ROLE"); c.release(); }
```
